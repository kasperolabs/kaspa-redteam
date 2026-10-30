//! Covenant families: transactions that spend coins of several programs of a
//! project together (a bridge and its token's mint authority), and create
//! coins of a third (the token cells).
//!
//! The draft is built from the sources (which state field holds the other
//! program's covenant id, which arguments are template parts, what a journal
//! record looks like), then repaired from the scripts themselves: when an
//! input rejects the draft, the engine's execution log shows the comparison
//! that failed and the value it expected, often a whole output script. The
//! tool puts that value in and runs again. What the scripts ask for, the draft
//! gets; nothing about any one contract is built in.

use crate::baseline::{Baseline, PathStatus};
use crate::contract::Contract;
use crate::sandbox::{
    ArgRecipe, BASE_FEE, Dest, FailedCheck, InputSpec, Judge, OutputSpec, RawInput, SpendPlan, StateValues, UTXO_DAA,
    Verdict, trace_failure,
};
use crate::wallets::KeyRef;
use kaspa_consensus_core::tx::{CovenantBinding, ScriptPublicKey, UtxoEntry};
use kaspa_hashes::Hash;
use kaspa_txscript::pay_to_script_hash_script;
use silverscript_abi::{ArtifactValue, TypeArtifact};
use std::collections::BTreeMap;

/// Another program of the project, as it is spent or created next to the one
/// under test.
pub struct Program {
    pub file: String,
    pub contract: Contract,
    pub cov_id: [u8; 32],
}

pub fn family_id(file: &str) -> [u8; 32] {
    let mut b = [0u8; 32];
    b.copy_from_slice(blake2b_simd::Params::new().hash_length(32).hash(format!("kaspa-redteam/family/{file}").as_bytes()).as_bytes());
    b
}

fn norm(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_lowercase()
}

/// State fields the source passes to covenant-id opcodes: `OpCovInputCount(prev_state.token)`.
pub fn cov_fields(c: &Contract) -> Vec<String> {
    let al = aliases(&c.source);
    c.state_fields
        .iter()
        .filter(|(name, ty)| {
            // The field itself, or a helper's parameter it is passed as
            // (`require_owner_authorized(owner, ...)` checking `OpCovInputCount(gen__glob_owner)`).
            let names: Vec<&str> =
                std::iter::once(name.as_str()).chain(al.iter().filter(|(_, f)| *f == name).map(|(p, _)| p.as_str())).collect();
            matches!(ty, TypeArtifact::FixedBytes { len: 32 })
                && c.source.lines().any(|l| {
                    l.contains("OpCov")
                        && names.iter().any(|n| {
                            l.contains(&format!("(prev_state.{n}")) || l.contains(&format!("({n})")) || l.contains(&format!("({n},"))
                        })
                })
        })
        .map(|(n, _)| n.clone())
        .collect()
}

/// Helper parameters bound to state fields: for `function f(T a, T b)` called
/// as `f(owner, owner_scheme)`, a -> owner, b -> owner_scheme. One level deep.
pub fn aliases(source: &str) -> BTreeMap<String, String> {
    let mut defs: Vec<(String, Vec<String>)> = Vec::new();
    for l in source.lines() {
        let t = l.trim();
        let Some(rest) = t.strip_prefix("function ") else { continue };
        let Some((name, after)) = rest.split_once('(') else { continue };
        let Some((plist, _)) = after.split_once(')') else { continue };
        let params: Vec<String> = plist.split(',').filter_map(|p| p.split_whitespace().last().map(str::to_string)).collect();
        defs.push((name.trim().to_string(), params));
    }
    let ident = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    let mut out = BTreeMap::new();
    for (name, params) in &defs {
        let pat = format!("{name}(");
        for l in source.lines() {
            let t = l.trim();
            if t.starts_with("function ") {
                continue;
            }
            let mut from = 0;
            while let Some(at) = t[from..].find(&pat) {
                let start = from + at + pat.len();
                let before = t[..from + at].chars().last();
                from = start;
                if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
                    continue;
                }
                let Some(close) = t[start..].find(')') else { continue };
                let args: Vec<&str> = t[start..start + close].split(',').map(str::trim).collect();
                for (p, a) in params.iter().zip(args) {
                    if ident(a) {
                        out.entry(p.clone()).or_insert_with(|| a.to_string());
                    }
                }
            }
        }
    }
    out
}

/// The program's bytes before and after its state window.
pub fn template_parts(c: &Contract) -> Option<(Vec<u8>, Vec<u8>)> {
    let span = c.artifact.as_ref()?.contracts.values().next()?.compiled.state_span;
    Some((c.bytecode[..span.offset].to_vec(), c.bytecode[span.offset + span.len..].to_vec()))
}

/// Decodes a redeem script of `p` (its prefix and suffix around a state).
pub fn decode_state(p: &Contract, redeem: &[u8]) -> Option<StateValues> {
    let (pre, suf) = template_parts(p)?;
    if !redeem.starts_with(&pre) || !redeem.ends_with(&suf) || redeem.len() < pre.len() + suf.len() {
        return None;
    }
    let abi = p.artifact.as_ref()?;
    let c = abi.contracts.values().next()?;
    silverscript_abi::decode_runtime_state_script(abi, &c.runtime_state, &redeem[pre.len()..redeem.len() - suf.len()]).ok()
}

fn encode_state(p: &Contract, state: &StateValues) -> Option<Vec<u8>> {
    p.script_for(Some(state)).ok()
}

/// A journal with one record, for entries that loop over records:
/// `int off = FIXED + LEN * i;`, `int nonce = be64(journal, off);`,
/// `int(byte[1](journal.slice(off + 16, off + 17)))`, a count read from two
/// bytes, and checks like `nonce > prev_state.cursor`, `amount > 0`,
/// `version == 0 || version == 8`. Fixed-position checks are filled as the
/// one-shot journal builder does (see `zk::journal_from_source`).
pub fn journal_with_record(
    body: &str,
    source: &str,
    param: &str,
    bytes_of: &dyn Fn(&str) -> Option<Vec<u8>>,
    int_of: &dyn Fn(&str) -> Option<i64>,
    owner: &[u8],
) -> Option<Vec<u8>> {
    let base = crate::zk::journal_from_source(body, param, bytes_of)?;
    let consts: BTreeMap<String, i64> = source
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            let rest = l.strip_prefix("int constant ")?;
            let (n, v) = rest.split_once('=')?;
            Some((n.trim().to_string(), v.trim().trim_end_matches(';').trim().parse().ok()?))
        })
        .collect();
    let val = |s: &str| -> Option<i64> {
        let s = s.trim();
        s.replace('_', "").parse().ok().or_else(|| consts.get(s).copied()).or_else(|| int_of(s.rsplit('.').next().unwrap_or(s)))
    };
    // `int off = A + B * i;`
    let (fixed, len) = body.lines().find_map(|l| {
        let l = l.trim();
        let rest = l.strip_prefix("int ")?;
        let (_, expr) = rest.split_once('=')?;
        let expr = expr.trim().trim_end_matches(';');
        let (a, b) = expr.split_once('+')?;
        let (b, i) = b.split_once('*')?;
        (i.trim().len() <= 2).then_some(())?;
        Some((val(a)?, val(b)?))
    })?;
    let (fixed, len) = (fixed as usize, len as usize);
    let mut j = base;
    j.resize(fixed + len, 0);
    // The count: `int(byte[2](journal.slice(269, 270) + journal.slice(268, 269)))`,
    // little-endian over the listed slices: the first one gets the 1.
    for l in body.lines() {
        if l.contains("int(byte[") && l.matches(&format!("{param}.slice(")).count() >= 2 && !l.contains("off") {
            let first = l.split(&format!("{param}.slice(")).nth(1)?;
            let a: usize = first.split(',').next()?.trim().parse().ok()?;
            if a < j.len() {
                j[a] = 1;
            }
        }
    }
    // Record fields and their checks.
    let mut fields: BTreeMap<String, (usize, usize)> = BTreeMap::new(); // name -> (offset in record, width)
    for l in body.lines() {
        let l = l.trim();
        let Some(rest) = l.strip_prefix("int ") else { continue };
        let Some((name, expr)) = rest.split_once('=') else { continue };
        let name = name.trim().to_string();
        let expr = expr.trim();
        let rel = |e: &str| -> Option<usize> {
            let at = e.find("off")?;
            let tail = &e[at + 3..];
            let tail = tail.trim_start();
            if let Some(t) = tail.strip_prefix('+') {
                t.trim().split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
            } else {
                Some(0)
            }
        };
        if expr.starts_with("be64(") && expr.contains("off") {
            if let Some(r) = rel(expr) {
                fields.insert(name, (r, 8));
            }
        } else if expr.starts_with("int(byte[1](") && expr.contains("off") {
            if let Some(r) = rel(expr) {
                fields.insert(name, (r, 1));
            }
        }
    }
    let put = |j: &mut Vec<u8>, at: usize, width: usize, v: i64| {
        let bytes = (v as u64).to_be_bytes();
        if at + width <= j.len() {
            j[at..at + width].copy_from_slice(&bytes[8 - width..]);
        }
    };
    for (name, (rel, width)) in &fields {
        let mut value: Option<i64> = None;
        for l in body.lines() {
            let l = l.trim();
            if !l.starts_with("require(") && !l.starts_with("if (") {
                continue;
            }
            let inner = l.trim_start_matches("require(").trim_start_matches("if (");
            if !inner.starts_with(name.as_str()) || inner[name.len()..].starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_') {
                continue;
            }
            let rest = inner[name.len()..].trim_start();
            if let Some(r) = rest.strip_prefix('>') {
                let r = r.trim_start_matches('=');
                let term = r.split(|c| c == ')' || c == '&' || c == '|').next().unwrap_or("");
                if let Some(v) = val(term) {
                    value = Some(if name.contains("amount") { v.max(0) + 100_000_000 } else { v + 1 });
                }
            } else if let Some(r) = rest.strip_prefix("==") {
                let term = r.split(|c| c == ')' || c == '&' || c == '|').next().unwrap_or("");
                if let Some(v) = val(term) {
                    value = value.or(Some(v));
                }
            }
        }
        if let Some(v) = value {
            put(&mut j, fixed + rel, *width, v);
        }
    }
    // A 32-byte slice of the record that becomes an owner: a key the tool holds.
    for l in body.lines() {
        if !l.contains("owner") || !l.contains(&format!("{param}.slice(off")) {
            continue;
        }
        let s = l.split(&format!("{param}.slice(")).nth(1).unwrap_or("");
        let (a, b) = s.split_once(',').unwrap_or(("", ""));
        let num = |t: &str| t.trim().trim_start_matches("off").trim().trim_start_matches('+').trim().split(|c: char| !c.is_ascii_digit()).next()?.parse::<usize>().ok();
        let (Some(a), Some(b)) = (num(a), num(b.split(')').next().unwrap_or(""))) else { continue };
        if b > a && b - a == owner.len() && fixed + b <= j.len() {
            j[fixed + a..fixed + b].copy_from_slice(owner);
        }
    }
    Some(j)
}

/// One co-spend attempt's moving parts.
struct Draft {
    plan: SpendPlan,
    /// Index of the sibling input, its entry and arguments (rebuilt on every run).
    sib: usize,
    sib_entry: String,
    sib_args: Vec<ArtifactValue>,
    /// Redeem scripts learned for outputs (index -> script), from the log.
    redeems: BTreeMap<usize, Vec<u8>>,
    repaired: std::collections::BTreeSet<usize>,
    /// The state of the coin spent alongside, when the scripts' checks may change it.
    sib_state: Option<StateValues>,
    /// A second coin of the other program, owned by an honest key and spent
    /// with it (a seller's tokens, merged into the first coin).
    delegate: Option<Delegate>,
    /// The key that owns the coin spent alongside, when a key owns it (a seller
    /// filling an order): its witness is that key's signature, made again
    /// after every change.
    sib_key: Option<secp256k1::Keypair>,
    /// The output whose script was put in last: with two outputs carrying the
    /// same script, the next fix goes to the other one.
    last_fix: Option<usize>,
    /// Fields of the other coin the repairs may not move (its borrow settings
    /// and amount when the test is about them).
    frozen: Vec<String>,
}

/// How the coin spent alongside is set up: as found, with borrowing turned on,
/// or after a stranger borrowed it once (one token unit more, fixed).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Borrow {
    No,
    On,
    OnPlusOne,
}

#[derive(Clone)]
struct Delegate {
    input: usize,
    entry: String,
    state: StateValues,
    key: secp256k1::Keypair,
}

fn spk_bytes(spk: &ScriptPublicKey) -> Vec<u8> {
    let mut v = spk.version().to_le_bytes().to_vec();
    v.extend_from_slice(spk.script());
    v
}

fn spk_from(bytes: &[u8]) -> Option<ScriptPublicKey> {
    if bytes.len() < 3 {
        return None;
    }
    let version = u16::from_le_bytes([bytes[0], bytes[1]]);
    Some(ScriptPublicKey::new(version, bytes[2..].to_vec().into()))
}

/// Applies what a failed check expected. Returns false when nothing could be learned.
fn repair(d: &mut Draft, built: &crate::sandbox::Built, f: &FailedCheck, main: &Contract) -> bool {
    // An output script: put in the one the script computed. When several
    // outputs carry the compared script, the latest one not repaired before
    // (continuations come first, created coins after).
    let mut matches: Vec<(usize, Vec<u8>)> = built
        .tx
        .outputs
        .iter()
        .enumerate()
        .filter_map(|(k, out)| {
            let have = spk_bytes(&out.script_public_key);
            if have == f.a {
                Some((k, f.b.clone()))
            } else if have == f.b {
                Some((k, f.a.clone()))
            } else {
                None
            }
        })
        .collect();
    matches.sort_by_key(|(k, _)| (!d.repaired.contains(k), *k));
    if matches.len() > 1 && matches.last().map(|m| m.0) == d.last_fix {
        let last = matches.pop();
        matches.insert(0, last.unwrap());
    }
    if let Some((k, want)) = matches.pop() {
        d.last_fix = Some(k);
        let out = &built.tx.outputs[k];
        let Some(spk) = spk_from(&want) else { return false };
        if spk == out.script_public_key {
            return false;
        }
        // Its redeem script, if the run computed one (`OP_BLAKE2B <hash> OP_EQUAL`).
        if spk.script().len() == 35 && spk.script()[0] == 0xaa {
            let h = &spk.script()[2..34];
            if let Some(r) = f.seen.iter().find(|r| blake2b_simd::Params::new().hash_length(32).hash(r).as_bytes() == h) {
                d.redeems.insert(k, r.clone());
            }
        }
        // A key's script (a payout) is no covenant coin.
        let binding = if spk.script().first() == Some(&0xaa) { out.covenant } else { None };
        d.plan.outputs[k].to = Dest::Raw(spk);
        d.plan.outputs[k].covenant = binding;
        d.repaired.insert(k);
        return true;
    }
    // A number the coin under test's next state carries, compared to the one the
    // script computed (`newState.amount == amount - minted`): put that one in.
    let num = |v: &[u8]| -> Option<i64> {
        if v.len() > 8 {
            return None;
        }
        if v.is_empty() {
            return Some(0);
        }
        let mut n: i64 = 0;
        for (i, b) in v.iter().enumerate() {
            n |= ((*b as i64) & if i == v.len() - 1 { 0x7f } else { 0xff }) << (8 * i);
        }
        Some(if v[v.len() - 1] & 0x80 != 0 { -n } else { n })
    };
    // A field of the coin spent alongside, as the input under test reads it
    // (`require(cell.owner_scheme == OWNER_COVENANT_ID)`, `cell.amount == SUPPLY - sold`).
    // An output the script asks to be in the other program's family
    // (`OpOutputCovenantId(out) == tokenCovId`): a coin of that program that
    // carries no covenant id yet gets the one of the coin spent alongside.
    if f.recent.iter().any(|r| r == "OpOutputCovenantId") {
        let sib_id = match d.plan.inputs.get(d.sib) {
            Some(InputSpec::Raw(r)) => r.entry.covenant_id,
            _ => None,
        };
        if let Some(id) = sib_id {
            if f.a.as_slice() == id.as_bytes().as_slice() || f.b.as_slice() == id.as_bytes().as_slice() {
                let k = d.redeems.keys().copied().find(|k| d.plan.outputs.get(*k).is_some_and(|o| o.covenant.is_none()));
                if let Some(k) = k {
                    d.plan.outputs[k].covenant = Some(CovenantBinding::new(d.sib as u16, id));
                    return true;
                }
                // The output whose script was just put in carries the wrong
                // family (a delivery at the slot drafted for a continuation).
                if let Some(k) = d.last_fix {
                    let wrong = d.plan.outputs.get(k).and_then(|o| o.covenant).is_some_and(|c| c.covenant_id != id);
                    if wrong && d.redeems.contains_key(&k) {
                        d.plan.outputs[k].covenant = Some(CovenantBinding::new(d.sib as u16, id));
                        return true;
                    }
                }
            }
        }
    }
    // A lock time the input under test asks for (a refund after expiry).
    if f.op == "OpCheckLockTimeVerify" {
        if let Some(want) = num(&f.b) {
            if want > 0 && (d.plan.lock_time as i64) < want {
                d.plan.lock_time = want as u64;
                return true;
            }
        }
    }
    // The left side of the comparison is what was read; when a state-shaped
    // argument holds it, that argument is what is wrong, not the coin.
    let in_args = f.input == 0
        && d.sib_state.is_some()
        && matches!(d.plan.inputs.first(), Some(InputSpec::Covenant { args, .. }) if args.iter().any(|a| matches!(a,
            ArgRecipe::Value(ArtifactValue::Object(m)) if m.values().any(|v| match v {
                ArtifactValue::Byte(x) => f.a.len() == 1 && f.a[0] == *x,
                ArtifactValue::Bytes(b) => b.len() >= 2 && *b == f.a,
                ArtifactValue::Int(x) => !f.a.is_empty() && num(&f.a) == Some(*x),
                _ => false,
            }))));
    if !in_args && (f.input == 0 || f.input == d.sib) && matches!(f.op.as_str(), "OpEqual" | "OpEqualVerify" | "OpNumEqual" | "OpNumEqualVerify") {
        if let Some(st) = d.sib_state.as_mut() {
            for (from, to) in [(&f.a, &f.b), (&f.b, &f.a)] {
                let frozen = d.frozen.clone();
                let hit = st.iter_mut().filter(|(n, _)| !frozen.contains(n)).find(|(_, v)| match v {
                    ArtifactValue::Byte(x) => from.len() == 1 && from[0] == *x,
                    ArtifactValue::Int(x) => num(from) == Some(*x) && !from.is_empty(),
                    ArtifactValue::Bytes(b) => b.len() == from.len() && b.len() >= 2 && b == from,
                    _ => false,
                });
                if let Some((_, v)) = hit {
                    let new = match v {
                        ArtifactValue::Byte(_) => ArtifactValue::Byte(to.first().copied().unwrap_or(0)),
                        ArtifactValue::Int(_) => ArtifactValue::Int(num(to).unwrap_or(0)),
                        _ => ArtifactValue::Bytes(to.clone()),
                    };
                    if *v != new {
                        *v = new;
                        return true;
                    }
                }
            }
        }
    }
    // A field of a state-shaped argument of the input under test
    // (`require(rest.ownerScheme == OWNER_P2SH)`, `rest.amount >= locked`).
    // Not for the minter shape, whose typed arguments come from the source.
    if f.input == 0 && d.sib_state.is_some() {
        let eq = matches!(f.op.as_str(), "OpEqual" | "OpEqualVerify" | "OpNumEqual" | "OpNumEqualVerify");
        let ge = matches!(f.op.as_str(), "OpGreaterThanOrEqual" | "OpGreaterThan");
        if let Some(InputSpec::Covenant { args, .. }) = d.plan.inputs.get_mut(0) {
            for a in args.iter_mut() {
                let ArgRecipe::Value(ArtifactValue::Object(m)) = a else { continue };
                for (from, to) in [(&f.a, &f.b), (&f.b, &f.a)] {
                    if !eq && !(ge && std::ptr::eq(from, &f.a)) {
                        continue;
                    }
                    let hit = m.iter_mut().find(|(_, v)| match v {
                        ArtifactValue::Byte(x) => from.len() == 1 && from[0] == *x,
                        ArtifactValue::Int(x) => num(from) == Some(*x) && (!from.is_empty() || ge),
                        ArtifactValue::Bytes(b) => b.len() == from.len() && b.len() >= 2 && b == from,
                        _ => false,
                    });
                    if let Some((_, v)) = hit {
                        let new = match v {
                            ArtifactValue::Byte(_) => ArtifactValue::Byte(to.first().copied().unwrap_or(0)),
                            ArtifactValue::Int(_) => {
                                ArtifactValue::Int(num(to).unwrap_or(0) + if f.op == "OpGreaterThan" { 1 } else { 0 })
                            }
                            _ => ArtifactValue::Bytes(to.clone()),
                        };
                        if *v != new {
                            *v = new;
                            return true;
                        }
                    }
                }
            }
        }
    }
    // A number argument of the input under test (`require(m > 0)`): the value
    // the comparison asks for.
    if f.input == 0 && matches!(f.op.as_str(), "OpGreaterThanOrEqual" | "OpGreaterThan" | "OpNumEqual" | "OpLessThan" | "OpLessThanOrEqual") {
        if let (Some(na), Some(nb)) = (num(&f.a), num(&f.b)) {
            let want = match f.op.as_str() {
                "OpGreaterThan" => nb + 1,
                "OpLessThan" => nb - 1,
                _ => nb,
            };
            // Arguments that index inputs or outputs are not amounts.
            let index_args: Vec<String> = match d.plan.inputs.first() {
                Some(InputSpec::Covenant { entry, .. }) => {
                    let flat: String = crate::tune::entry_body(&main.source, entry).unwrap_or("").split_whitespace().collect();
                    main.entry(entry)
                        .map(|e| {
                            e.params
                                .iter()
                                .filter(|p| {
                                    let q = &p.name;
                                    [format!("CovenantId({q})"), format!("tx.inputs[{q}]"), format!("tx.outputs[{q}]"), format!("ScriptSigLen({q})"), format!("WithTemplate({q},"), format!("readInputState({q})")]
                                        .iter()
                                        .any(|x| flat.contains(x.as_str()))
                                })
                                .map(|p| p.name.clone())
                                .collect()
                        })
                        .unwrap_or_default()
                }
                _ => vec![],
            };
            let params: Vec<String> = match d.plan.inputs.first() {
                Some(InputSpec::Covenant { entry, .. }) => main.entry(entry).map(|e| e.params.iter().map(|p| p.name.clone()).collect()).unwrap_or_default(),
                _ => vec![],
            };
            if let Some(InputSpec::Covenant { args, .. }) = d.plan.inputs.get_mut(0) {
                // A number passed as fixed bytes and converted in the script
                // (`byte[8] nb`, `int n = int(nb)`): the exact bytes compared,
                // re-encoded. Exact bytes are the stronger match, so first.
                for a in args.iter_mut() {
                    if let ArgRecipe::Value(ArtifactValue::Bytes(v)) = a {
                        if v.len() == 8 && *v == f.a && na != want && want >= 0 {
                            *v = (want as u64).to_le_bytes().to_vec();
                            return true;
                        }
                    }
                }
                for (i, a) in args.iter_mut().enumerate() {
                    if params.get(i).is_some_and(|n| index_args.contains(n)) {
                        continue;
                    }
                    if let ArgRecipe::Value(ArtifactValue::Int(x)) = a {
                        if *x == na && na != want {
                            *x = want;
                            return true;
                        }
                    }
                }
            }
        }
    }
    // A number of the state the coin under test is in (`require(m <= sold)` with
    // nothing sold yet): a later state where the comparison holds.
    if f.input == 0 && matches!(f.op.as_str(), "OpLessThanOrEqual" | "OpLessThan" | "OpGreaterThanOrEqual" | "OpGreaterThan") {
        if let (Some(na), Some(nb)) = (num(&f.a), num(&f.b)) {
            // The right side moves to the left one, or the left to the right.
            let fix = |to: i64, other: bool| -> i64 {
                match (f.op.as_str(), other) {
                    ("OpLessThan", false) => to + 1,
                    ("OpGreaterThan", false) => to - 1,
                    ("OpLessThan", true) => to - 1,
                    ("OpGreaterThan", true) => to + 1,
                    _ => to,
                }
            };
            if let Some(InputSpec::Covenant { state: Some(st), .. }) = d.plan.inputs.get_mut(0) {
                for (from, to) in [(nb, fix(na, false)), (na, fix(nb, true))] {
                    if let Some((_, v)) = st.iter_mut().find(|(_, v)| **v == ArtifactValue::Int(from)) {
                        if to >= 0 && from != to {
                            *v = ArtifactValue::Int(to);
                            return true;
                        }
                    }
                }
            }
        }
    }
    // An output's value the script compared (`successor value >= in + cost`):
    // the value it asked for, paid by the funding coin.
    if matches!(f.op.as_str(), "OpGreaterThanOrEqual" | "OpGreaterThan" | "OpNumEqual" | "OpNumEqualVerify") {
        if let (Some(na), Some(nb)) = (num(&f.a), num(&f.b)) {
            let want = if f.op == "OpGreaterThan" { nb + 1 } else { nb };
            if want > 0 && na != want {
                // The output itself, or the output plus a constant of the
                // contract (`tx.outputs[self].value + refundTip >= carriers`).
                let consts: Vec<i64> = main
                    .args
                    .iter()
                    .filter_map(|a| match a.value {
                        ArtifactValue::Int(x) => Some(x),
                        _ => None,
                    })
                    .collect();
                let hit = d.plan.outputs.iter().position(|o| o.value as i64 == na).or_else(|| {
                    d.plan.outputs.iter().position(|o| o.to != Dest::Key(KeyRef::Attacker) && consts.contains(&(na - o.value as i64)))
                });
                if let Some(k) = hit {
                    let (na, want) = (d.plan.outputs[k].value as i64, d.plan.outputs[k].value as i64 + want - na);
                    let delta = want - na;
                    d.plan.outputs[k].value = want as u64;
                    if delta > 0 {
                        if let Some(InputSpec::P2pk { value, .. }) = d.plan.inputs.iter_mut().find(|i| matches!(i, InputSpec::P2pk { .. })) {
                            *value += delta as u64;
                        }
                    }
                    return true;
                }
            }
        }
    }
    if f.input == 0 && f.op.starts_with("OpNum") {
        if let (Some(na), Some(nb)) = (num(&f.a), num(&f.b)) {
            for o in d.plan.outputs.iter_mut() {
                if let Dest::Successor(st) = &mut o.to {
                    for (from, to) in [(na, nb), (nb, na)] {
                        if let Some((_, v)) = st.iter_mut().find(|(_, v)| **v == ArtifactValue::Int(from)) {
                            *v = ArtifactValue::Int(to);
                            return true;
                        }
                    }
                }
            }
        }
    }
    // An argument of the input under test: swap the bytes it carried.
    if f.input == 0 {
        if let Some(InputSpec::Covenant { args, .. }) = d.plan.inputs.get_mut(0) {
            for a in args.iter_mut() {
                if let ArgRecipe::Value(ArtifactValue::Bytes(v)) = a {
                    for (from, to) in [(&f.a, &f.b), (&f.b, &f.a)] {
                        if from.len() == to.len() && from.len() >= 4 {
                            if let Some(at) = v.windows(from.len()).position(|w| w == from.as_slice()) {
                                v[at..at + from.len()].copy_from_slice(to);
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    let _ = main;
    false
}

fn struct_obj(fields: &[(String, TypeArtifact)], from: &StateValues) -> ArtifactValue {
    let mut m = BTreeMap::new();
    for (n, ty) in fields {
        m.insert(n.clone(), from.get(n).cloned().unwrap_or_else(|| crate::sandbox::zero_value(ty)));
    }
    ArtifactValue::Object(m)
}

/// Sibling arguments: state-shaped arrays from the cells this transaction
/// creates (decoded with whichever program they are), template parts by name.
fn sibling_args(sib: &Program, entry: &str, programs: &[Program], d: &Draft) -> Option<Vec<ArtifactValue>> {
    let e = sib.contract.entry(entry)?;
    let mut out = Vec::new();
    for p in &e.params {
        let n = norm(&p.name);
        out.push(match &p.ty {
            TypeArtifact::DynamicArray { item } | TypeArtifact::FixedArray { item, .. } => {
                let TypeArtifact::Struct { name } = item.as_ref() else { return None };
                let fields = sib.contract.struct_fields(name)?;
                let mut items = Vec::new();
                let sib_id = Hash::from_bytes(sib.cov_id);
                for (k, r) in &d.redeems {
                    // The new coins of the other program's family (never the coin
                    // under test's own continuation).
                    let bound = d.plan.outputs.get(*k).and_then(|o| o.covenant).map(|c| c.covenant_id);
                    if bound != Some(sib_id) {
                        continue;
                    }
                    if let Some(s) = programs.iter().find_map(|pr| decode_state(&pr.contract, r)) {
                        items.push(struct_obj(&fields, &s));
                    }
                }
                ArtifactValue::Array(items)
            }
            TypeArtifact::Bytes if n.contains("prefix") || n.contains("suffix") => {
                let core = n.replace("prefix", "").replace("suffix", "").replace("gen", "");
                let prog = programs.iter().find(|pr| norm(&pr.contract.contract_name) == core || norm(&pr.file).trim_end_matches("sil") == core)?;
                let (pre, suf) = template_parts(&prog.contract)?;
                ArtifactValue::Bytes(if n.contains("prefix") { pre } else { suf })
            }
            // A coin owned by a covenant id authorizes with no signature: the
            // witness is the path byte alone (normal path).
            // Owned by a script hash (owner scheme P2SH): the path byte, then
            // the index of the input that carries that script (the coin under test).
            TypeArtifact::Bytes if n.contains("witness") && p2sh_owned(sib, d) => ArtifactValue::Bytes(vec![0x00, 0x00]),
            TypeArtifact::Bytes if n.contains("witness") => ArtifactValue::Bytes(vec![0x00]),
            TypeArtifact::Sig => ArtifactValue::Bytes(vec![0; 65]),
            ty => crate::sandbox::zero_value(ty),
        });
    }
    Some(out)
}

fn rebuild_sibling(d: &mut Draft, sib: &Program, sib_state: &StateValues) -> Option<()> {
    let artifact = sib.contract.artifact.as_ref()?;
    let marker = vec![0xa5u8; 65];
    let mut args = d.sib_args.clone();
    if d.sib_key.is_some() {
        // The normal path byte, then the owner's signature.
        let e = sib.contract.entry(&d.sib_entry)?;
        for (p, a) in e.params.iter().zip(args.iter_mut()) {
            if norm(&p.name).contains("witness") {
                let mut w = vec![0x00];
                w.extend(&marker);
                *a = ArtifactValue::Bytes(w);
            }
        }
    }
    let mut s = silverscript_abi::encode_contract_entry_sig_script(artifact, &sib.contract.contract_name, &d.sib_entry, &args).ok()?;
    let sig_at = d.sib_key.and_then(|k| s.windows(65).position(|w| w == marker.as_slice()).map(|at| (k, at)));
    let state = d.sib_state.clone().unwrap_or_else(|| sib_state.clone());
    let redeem = encode_state(&sib.contract, &state)?;
    s.extend(crate::sandbox::push_data(&redeem).ok()?);
    if let InputSpec::Raw(r) = &mut d.plan.inputs[d.sib] {
        r.signature_script = s;
        // The coin's address follows its state.
        r.entry = UtxoEntry::new(r.entry.amount, pay_to_script_hash_script(&redeem), r.entry.block_daa_score, false, r.entry.covenant_id);
        r.resign = sig_at.map(|(keypair, at)| crate::sandbox::Resign { keypair, at });
        if r.resign.is_some() {
            r.sig_op_count = 1;
        }
    }
    if let Some(del) = d.delegate.clone() {
        // Its witness is the owner's signature, made again after every change.
        let marker = vec![0xa5u8; 65];
        let e = sib.contract.entry(&del.entry)?;
        let args: Vec<ArtifactValue> = e
            .params
            .iter()
            .map(|p| if norm(&p.name).contains("witness") { ArtifactValue::Bytes(marker.clone()) } else { crate::sandbox::zero_value(&p.ty) })
            .collect();
        let mut s = silverscript_abi::encode_contract_entry_sig_script(artifact, &sib.contract.contract_name, &del.entry, &args).ok()?;
        let at = s.windows(65).position(|w| w == marker.as_slice())?;
        // The first coin's state, with the follower's own owner and amount.
        let mut st = state.clone();
        st.extend(del.state.clone());
        let redeem = encode_state(&sib.contract, &st)?;
        s.extend(crate::sandbox::push_data(&redeem).ok()?);
        if let InputSpec::Raw(r) = &mut d.plan.inputs[del.input] {
            r.signature_script = s;
            r.entry = UtxoEntry::new(r.entry.amount, pay_to_script_hash_script(&redeem), r.entry.block_daa_score, false, r.entry.covenant_id);
            r.resign = Some(crate::sandbox::Resign { keypair: del.key, at });
        }
    }
    Some(())
}

/// The other program keeps its books (`output_total == input_total`) and the
/// new coins carry less than the coins spent: the spender takes the rest as a
/// coin of its own (a buyer's tokens).
fn rest_to_spender(d: &mut Draft, f: &FailedCheck, sib: &Program, main: &Contract) -> bool {
    if f.input != d.sib || f.a.len() > 8 || f.b.len() > 8 {
        return false;
    }
    // More new coins of the other program than it has states for
    // (`next_states.length == OpAuthOutputCount(...)`): the drafted ones
    // nothing asked for (no script learned for them) go.
    let sib_id = Hash::from_bytes(sib.cov_id);
    let bound = d.plan.outputs.iter().filter(|o| o.covenant.map(|c| c.covenant_id) == Some(sib_id)).count();
    let small = |v: &[u8]| v.len() <= 1;
    let (fa, fb) = (f.a.first().copied().unwrap_or(0) as usize, f.b.first().copied().unwrap_or(0) as usize);
    if f.op.starts_with("OpNumEqual") && small(&f.a) && small(&f.b) && fa < fb && fb == bound {
        let idle: Vec<usize> = d
            .plan
            .outputs
            .iter()
            .enumerate()
            .filter(|(k, o)| o.covenant.map(|c| c.covenant_id) == Some(sib_id) && !d.redeems.contains_key(k))
            .map(|(k, _)| k)
            .collect();
        if !idle.is_empty() && d.redeems.keys().any(|k| d.plan.outputs.get(*k).and_then(|o| o.covenant).map(|c| c.covenant_id) == Some(sib_id)) {
            for k in idle.iter().rev() {
                let gone = d.plan.outputs[*k].value;
                d.plan.outputs.remove(*k);
                if let Some(InputSpec::P2pk { value, .. }) = d.plan.inputs.iter_mut().find(|i| matches!(i, InputSpec::P2pk { .. })) {
                    *value = value.saturating_sub(gone).max(BASE_FEE * 2);
                }
                d.redeems = std::mem::take(&mut d.redeems).into_iter().map(|(j, r)| (if j > *k { j - 1 } else { j }, r)).collect();
                d.repaired = d.repaired.iter().filter(|j| *j != k).map(|j| if *j > *k { j - 1 } else { *j }).collect();
                d.last_fix = None;
            }
            return true;
        }
    }
    // Too few new coins for the other program (`OpAuthOutputCount(...) >= 1`):
    // the spender takes all that is not accounted for.
    let too_few = f.op.starts_with("OpGreaterThan") && f.recent.iter().any(|r| r == "OpAuthOutputCount");
    if !f.op.starts_with("OpNumEqual") && !too_few {
        return false;
    }
    let num = |v: &[u8]| -> i64 {
        let mut n: i64 = 0;
        for (i, b) in v.iter().enumerate() {
            n |= ((*b as i64) & if i == v.len() - 1 { 0x7f } else { 0xff }) << (8 * i);
        }
        if v.last().is_some_and(|b| b & 0x80 != 0) { -n } else { n }
    };
    let Some(st) = d.sib_state.clone() else { return false };
    // More out than in: a new coin of exactly the excess, drafted but not asked
    // for by the coin under test (a second copy), goes.
    if !too_few && f.op.starts_with("OpNumEqual") {
        let (o, i) = (num(&f.a), num(&f.b));
        if o > i {
            let excess = o - i;
            let k = d
                .redeems
                .iter()
                .filter(|(k, _)| d.plan.outputs.get(**k).and_then(|x| x.covenant).map(|c| c.covenant_id) == Some(sib_id))
                .filter(|(_, r)| decode_state(&sib.contract, r).is_some_and(|x| x.get("amount") == Some(&ArtifactValue::Int(excess))))
                .map(|(k, _)| *k)
                .max();
            if let (Some(k), true) = (k, d.redeems.len() > 1) {
                let gone = d.plan.outputs[k].value;
                d.plan.outputs.remove(k);
                if let Some(InputSpec::P2pk { value, .. }) = d.plan.inputs.iter_mut().find(|i| matches!(i, InputSpec::P2pk { .. })) {
                    *value = value.saturating_sub(gone).max(BASE_FEE * 2);
                }
                d.redeems = std::mem::take(&mut d.redeems).into_iter().filter(|(j, _)| *j != k).map(|(j, r)| (if j > k { j - 1 } else { j }, r)).collect();
                d.repaired = d.repaired.iter().filter(|j| **j != k).map(|j| if *j > k { j - 1 } else { *j }).collect();
                d.last_fix = None;
                return true;
            }
        }
    }
    let (out_total, in_total) = if too_few {
        let sib_id = Hash::from_bytes(sib.cov_id);
        let have: i64 = d
            .redeems
            .iter()
            .filter(|(k, _)| d.plan.outputs.get(**k).and_then(|o| o.covenant).map(|c| c.covenant_id) == Some(sib_id))
            .filter_map(|(_, r)| decode_state(&sib.contract, r))
            .filter_map(|x| match x.get("amount") {
                Some(ArtifactValue::Int(n)) => Some(*n),
                _ => None,
            })
            .sum();
        match st.get("amount") {
            Some(ArtifactValue::Int(n)) => (have, *n),
            _ => return false,
        }
    } else {
        (num(&f.a), num(&f.b))
    };
    if st.get("amount") != Some(&ArtifactValue::Int(in_total)) || out_total >= in_total || d.redeems.len() > 4 {
        return false;
    }
    let mut mine = st;
    mine.insert("amount".into(), ArtifactValue::Int(in_total - out_total));
    let attacker = main.wallets.attacker.xonly().to_vec();
    for fld in cov_fields(&sib.contract) {
        mine.insert(fld, ArtifactValue::Bytes(attacker.clone()));
    }
    if let Some((sel, _)) = cov_branch(&sib.contract) {
        let p2pk = source_consts(&sib.contract.source)
            .into_iter()
            .find(|(n, _)| n.contains("P2PK") && !n.contains("P2PKH"))
            .map(|(_, v)| v)
            .unwrap_or(ArtifactValue::Byte(0));
        mine.insert(sel, p2pk);
    }
    let Some(redeem) = encode_state(&sib.contract, &mine) else { return false };
    let value = 100_000_000u64;
    let k = d.plan.outputs.len();
    d.plan.outputs.push(OutputSpec {
        value,
        to: Dest::Raw(pay_to_script_hash_script(&redeem)),
        covenant: Some(CovenantBinding::new(d.sib as u16, Hash::from_bytes(sib.cov_id))),
        own: true,
    });
    d.redeems.insert(k, redeem);
    if let Some(InputSpec::P2pk { value: v, .. }) = d.plan.inputs.iter_mut().find(|i| matches!(i, InputSpec::P2pk { .. })) {
        *v += value;
    }
    true
}

/// The coin under test asks for one more coin of the other program than the
/// draft spends (`OpCovInputCount(token) == 2`): a second one, owned by an
/// honest key, spent with the other program's follower entry. Or for fewer
/// new coins of it (`OpCovOutputCount(token) == 1`): the last ones go.
fn add_or_drop_coins(d: &mut Draft, f: &FailedCheck, sib: &Program, key: &secp256k1::Keypair) -> bool {
    if !matches!(f.op.as_str(), "OpNumEqual" | "OpNumEqualVerify" | "OpGreaterThanOrEqual") || f.a.len() > 1 || f.b.len() > 1 {
        return false;
    }
    let (na, nb) = (f.a.first().copied().unwrap_or(0) as usize, f.b.first().copied().unwrap_or(0) as usize);
    let id = Hash::from_bytes(sib.cov_id);
    let ins = d.plan.inputs.iter().filter(|i| matches!(i, InputSpec::Raw(r) if r.entry.covenant_id == Some(id))).count();
    let outs: Vec<usize> =
        d.plan.outputs.iter().enumerate().filter(|(_, o)| o.covenant.map(|c| c.covenant_id) == Some(id)).map(|(k, _)| k).collect();
    let counted = |op: &str| f.recent.iter().any(|r| r == op);
    if d.delegate.is_none() && na == ins && nb == ins + 1 && counted("OpCovInputCount") {
        let Some(sib_state) = d.sib_state.clone() else { return false };
        // The follower: an entry that only takes a witness and is not the leader.
        let Some(entry) = sib.contract.entries.iter().find(|e| {
            e.name != d.sib_entry
                && !e.params.is_empty()
                && e.params.iter().all(|p| norm(&p.name).contains("witness"))
                && crate::tune::entry_body(&sib.contract.source, &e.name).is_some_and(|b| b.contains("!= this.activeInputIndex"))
        }) else {
            return false;
        };
        let mut state = StateValues::new();
        if let Some(v) = sib_state.get("amount") {
            state.insert("amount".into(), v.clone());
        }
        for f in cov_fields(&sib.contract) {
            state.insert(f, ArtifactValue::Bytes(key.x_only_public_key().0.serialize().to_vec()));
        }
        if let Some((sel, _)) = cov_branch(&sib.contract) {
            let consts = source_consts(&sib.contract.source);
            let p2pk = consts
                .iter()
                .find(|(n, _)| n.contains("P2PK") && !n.contains("P2PKH"))
                .map(|(_, v)| v.clone())
                .unwrap_or(ArtifactValue::Byte(0));
            state.insert(sel, p2pk);
        }
        if let Some(ArtifactValue::Int(a)) = state.get_mut("amount") {
            *a = 1;
        }
        let at = d.sib + 1;
        let value = 100_000_000u64;
        d.plan.inputs.insert(
            at,
            InputSpec::Raw(RawInput {
                outpoint: None,
                signature_script: vec![],
                sequence: 0,
                sig_op_count: 1,
                compute_budget: 2_000,
                entry: UtxoEntry::new(value, ScriptPublicKey::default(), UTXO_DAA, false, Some(id)),
                target: false,
                signed: false,
                resign: None,
            }),
        );
        // Its KAS goes back to its owner, who signs this spend (the tool signs
        // again after every change, so taking from it takes from the signer).
        d.plan.outputs.push(OutputSpec { value: value - BASE_FEE, own: true, to: Dest::Raw(kaspa_txscript::pay_to_address_script(&kaspa_addresses::Address::new(kaspa_addresses::Prefix::Testnet, kaspa_addresses::Version::PubKey, &key.x_only_public_key().0.serialize()))), covenant: None });
        d.delegate = Some(Delegate { input: at, entry: entry.name.clone(), state, key: *key });
        return true;
    }
    // The coin under test asked not to continue (`OpCovOutputCount(self) == 0`,
    // a refund or a sold-out order): its continuation goes.
    let mine: Vec<usize> = d
        .plan
        .outputs
        .iter()
        .enumerate()
        .filter(|(_, o)| matches!(o.to, Dest::SelfCovenant | Dest::Successor(_)))
        .map(|(k, _)| k)
        .collect();
    // The coin under test asked to continue (`OpCovOutputCount(self) == 1`) and
    // no output does: a continuation of its own, with its value.
    if f.op.starts_with("OpNumEqual") && na == 0 && nb == 1 && mine.is_empty() && counted("OpCovOutputCount") && outs.len() != 0 {
        let value = match d.plan.inputs.first() {
            Some(InputSpec::Covenant { value, .. }) => *value,
            _ => return false,
        };
        let state = match d.plan.inputs.first() {
            Some(InputSpec::Covenant { state: Some(st), .. }) => Some(st.clone()),
            _ => None,
        };
        let to = match state {
            Some(st) => Dest::Successor(st),
            None => Dest::SelfCovenant,
        };
        let at = d.plan.outputs.iter().position(|o| o.to == Dest::Key(KeyRef::Attacker)).unwrap_or(d.plan.outputs.len());
        d.plan.outputs.insert(at, OutputSpec::new(value, to));
        // Indexes after `at` move up by one.
        let moved: BTreeMap<usize, Vec<u8>> = std::mem::take(&mut d.redeems).into_iter().map(|(k, r)| (if k >= at { k + 1 } else { k }, r)).collect();
        d.redeems = moved;
        d.repaired = d.repaired.iter().map(|k| if *k >= at { k + 1 } else { *k }).collect();
        d.last_fix = d.last_fix.map(|k| if k >= at { k + 1 } else { k });
        if let Some(InputSpec::P2pk { value: v, .. }) = d.plan.inputs.iter_mut().find(|i| matches!(i, InputSpec::P2pk { .. })) {
            *v += value;
        }
        return true;
    }
    if f.op.starts_with("OpNumEqual") && nb == 0 && na == mine.len() && na > 0 && counted("OpCovOutputCount") {
        for k in mine.iter().rev() {
            let gone = d.plan.outputs[*k].value;
            d.plan.outputs.remove(*k);
            d.redeems.remove(k);
            d.repaired.remove(k);
            // Its KAS goes to whoever spends.
            if let Some(o) = d.plan.outputs.iter_mut().find(|o| o.to == Dest::Key(KeyRef::Attacker)) {
                o.value += gone;
            }
        }
        return true;
    }
    if f.op != "OpGreaterThanOrEqual" && na == outs.len() && nb < na && nb > 0 && counted("OpCovOutputCount") {
        for k in outs[nb..].iter().rev() {
            // Its KAS came from the funding coin: that coin shrinks with it.
            let gone = d.plan.outputs[*k].value;
            if let Some(InputSpec::P2pk { value, .. }) = d.plan.inputs.iter_mut().find(|i| matches!(i, InputSpec::P2pk { .. })) {
                *value = value.saturating_sub(gone).max(BASE_FEE * 2);
            }
            d.plan.outputs.remove(*k);
            d.redeems.remove(k);
            d.repaired.remove(k);
        }
        return true;
    }
    false
}

/// Tries to spend `entry` of `main` together with a coin of another program of
/// the project, creating coins of a third. Returns the accepted spend.
pub fn explore(main: &Contract, entry: &str, programs: &[Program], judge: &Judge) -> Option<(PathStatus, Vec<String>)> {
    explore_seeded(main, entry, programs, judge, None, 1, Borrow::No)
}

/// The other branches of an entry that switches on a number argument
/// (`if (n == 0) { refund } else { fill }`): each tried as its own path,
/// `settle+transfer[n>0]`.
pub fn explore_branches(main: &Contract, entry: &str, programs: &[Program], judge: &Judge) -> Vec<(PathStatus, Vec<String>)> {
    let Some(body) = crate::tune::entry_body(&main.source, entry) else { return vec![] };
    let Some(me) = main.entry(entry) else { return vec![] };
    let flat: String = body.split_whitespace().collect();
    let mut out = Vec::new();
    for p in me.params.iter().filter(|p| matches!(p.ty, TypeArtifact::Int | TypeArtifact::FixedBytes { len: 8 })) {
        // The number itself, or a local read from it (`int n = int(nb);`).
        let local = body.lines().find_map(|l| {
            let (lhs, rhs) = l.split_once('=')?;
            let rhs: String = rhs.split_whitespace().collect();
            if !rhs.starts_with(&format!("int({})", p.name)) {
                return None;
            }
            let mut w = lhs.split_whitespace();
            (w.next() == Some("int")).then(|| w.next().map(str::to_string)).flatten()
        });
        let tested = |v: &str| flat.contains(&format!("if({v}==0)"));
        if std::env::var_os("REDTEAM_DEBUG").is_some() {
            eprintln!("branches {entry}: param {} {:?} local {:?} tested {}", p.name, p.ty, local, local.as_deref().is_some_and(tested) || tested(&p.name));
        }
        if tested(&p.name) || local.as_deref().is_some_and(tested) {
            let Some((mut st, notes)) = explore_seeded(main, entry, programs, judge, Some((p.name.clone(), 1)), 1, Borrow::No) else { continue };
            st.entry = format!("{}[{}>0]", st.entry, p.name);
            let shape = |s: &PathStatus| s.baseline.as_ref().map(|b| b.plan.outputs.len());
            let first = shape(&st);
            out.push((st, notes));
            // The other coin holding more than the trade takes (an order that
            // keeps a remainder and continues): a path of its own when the
            // spend comes out different.
            if let Some((mut st2, notes2)) = explore_seeded(main, entry, programs, judge, Some((p.name.clone(), 1)), 3, Borrow::No) {
                if shape(&st2) != first {
                    st2.entry = format!("{}[{}>0,rest kept]", st2.entry, p.name);
                    out.push((st2, notes2));
                }
            }
        }
    }
    out
}

fn explore_seeded(
    main: &Contract,
    entry: &str,
    programs: &[Program],
    judge: &Judge,
    seed: Option<(String, i64)>,
    scale: i64,
    borrow: Borrow,
) -> Option<(PathStatus, Vec<String>)> {
    let body = crate::tune::entry_body(&main.source, entry)?;
    let main_cov = cov_fields(main);
    // Two ways to name the other family: a state field (a bridge's `token`),
    // or a constructor value the project linked to it (an order's `tokenCovId`).
    let in_state = main.initial_state.is_some() && !main_cov.is_empty() && main_cov.iter().any(|f| body.contains(f.as_str()));
    let by_arg = |p: &Program| {
        main.args.iter().any(|a| a.value == ArtifactValue::Bytes(p.cov_id.to_vec()) && body.contains(a.name.as_str()))
    };
    if !in_state && !programs.iter().any(by_arg) {
        return None;
    }
    let init = main.initial_state.clone().unwrap_or_default();
    let (pov_daa, block_time) = crate::baseline::pov(main);
    let main_id = crate::sandbox::sandbox_covenant_id();
    for sib in programs
        .iter()
        .filter(|p| p.contract.is_stateful() && !cov_fields(&p.contract).is_empty() && (in_state || by_arg(p)))
    {
        // Each side's covenant-id fields name the other.
        let mut state = init.clone();
        for f in &main_cov {
            state.insert(f.clone(), ArtifactValue::Bytes(sib.cov_id.to_vec()));
        }
        let mut sib_state = sib.contract.initial_state.clone()?;
        // One value under one name across the project (`extension_commitment`
        // in both): the coin under test's value, so both sides agree.
        let core = |n: &str| norm(n).replace("init", "").replace("gen", "");
        for (field, v) in sib_state.iter_mut() {
            let c = core(field);
            if let Some(a) = main.args.iter().find(|a| core(&a.name) == c && a.ty == "byte[32]") {
                *v = a.value.clone();
            } else if let Some(x) = state.iter().find(|(n, _)| core(n) == c).map(|(_, x)| x.clone()) {
                *v = x;
            }
        }
        for f in cov_fields(&sib.contract) {
            sib_state.insert(f, ArtifactValue::Bytes(main_id.as_bytes().to_vec()));
        }
        // On the branch that checks ownership by covenant id (owner_scheme 4).
        if let Some((sel, v)) = cov_branch(&sib.contract) {
            sib_state.insert(sel, v);
        }
        // A coin the coin under test does not read (an order filled with
        // someone's tokens) belongs to whoever brings it: the attacker, who
        // signs for it.
        if scale > 1 {
            if let Some(ArtifactValue::Int(a)) = sib_state.get_mut("amount") {
                *a = a.saturating_mul(scale);
            }
        }
        if borrow != Borrow::No {
            let (Some(sf), Some(gf)) = borrow_fields(&sib_state) else { continue };
            // Threshold zero: anyone may borrow by adding one token unit.
            sib_state.insert(sf, ArtifactValue::Byte(1));
            sib_state.insert(gf, ArtifactValue::Bytes(vec![0; 32]));
            if borrow == Borrow::OnPlusOne {
                if let Some(ArtifactValue::Int(a)) = sib_state.get_mut("amount") {
                    *a += 1;
                }
            }
        }
        // Who owns the coin spent alongside: the coin under test (custody),
        // unless the entry never reads it; and if the custody draft cannot be
        // built, once more with the spender's own coin (a seller filling a bid
        // whose code keeps the token's id in its state). The first try is the
        // one that worked before, so nothing that was explored changes.
        let first = !in_state && !body.contains("readInputState");
        let tries = if first || borrow != Borrow::No { vec![first] } else { vec![false, true] };
        let base_state = sib_state.clone();
        for keyed in tries {
        let mut sib_state = base_state.clone();
        if keyed {
            let attacker = main.wallets.attacker.xonly().to_vec();
            for f in cov_fields(&sib.contract) {
                sib_state.insert(f, ArtifactValue::Bytes(attacker.clone()));
            }
            if let Some((sel, _)) = cov_branch(&sib.contract) {
                let p2pk = source_consts(&sib.contract.source)
                    .into_iter()
                    .find(|(n, _)| n.contains("P2PK") && !n.contains("P2PKH"))
                    .map(|(_, v)| v)
                    .unwrap_or(ArtifactValue::Byte(0));
                sib_state.insert(sel, p2pk);
            }
        }
        let sib_redeem = encode_state(&sib.contract, &sib_state)?;
        let sib_spk = pay_to_script_hash_script(&sib_redeem);
        // The coin under test drives (it carries the proof or the data); the
        // other program only takes part: its entry needs nothing but states
        // and template parts the tool can fill.
        let passive = |e: &&crate::contract::Entry| {
            !e.params.is_empty()
                && e.params.iter().all(|p| {
                    let n = norm(&p.name);
                    !matches!(p.ty, TypeArtifact::Bytes) || n.contains("prefix") || n.contains("suffix") || n.contains("witness")
                })
        };
        for sib_entry in sib.contract.entries.iter().filter(passive) {
            // The main entry's arguments.
            let me = main.entry(entry)?;
            // Whoever the data pays: an honest party, never the attacker.
            let owner_key = match main.wallets.parties.first() {
                Some(w) => w.keypair,
                None => {
                    let mut w = crate::wallets::Wallets::new();
                    let i = w.party("depositor");
                    w.parties[i].keypair
                }
            };
            let owner = owner_key.x_only_public_key().0.serialize().to_vec();
            let bytes_of = |name: &str| -> Option<Vec<u8>> {
                let v = main.args.iter().find(|a| a.name == name).map(|a| a.value.clone()).or_else(|| state.get(name).cloned())?;
                match v {
                    ArtifactValue::Bytes(b) => Some(b),
                    _ => None,
                }
            };
            let int_of = |name: &str| -> Option<i64> {
                match main.args.iter().find(|a| a.name == name).map(|a| a.value.clone()).or_else(|| state.get(name).cloned())? {
                    ArtifactValue::Int(n) => Some(n),
                    _ => None,
                }
            };
            let mut args = Vec::new();
            let flat: String = body.split_whitespace().collect();
            for p in &me.params {
                let n = norm(&p.name);
                // A signature the entry checks against a key of the contract
                // (`checkSig(s, beneficiary)`): that party signs.
                if matches!(p.ty, TypeArtifact::Sig) {
                    let key = main
                        .args
                        .iter()
                        .find(|a| flat.contains(&format!("checkSig({},{})", p.name, a.name)))
                        .and_then(|a| main.wallets.parties.iter().position(|w| w.label == a.name))
                        .map(KeyRef::Party)
                        .unwrap_or(KeyRef::Attacker);
                    args.push(ArgRecipe::Sig(key));
                    continue;
                }
                // A state of the other program the entry checks field by field
                // (`TokenState rest`): start from the coin spent alongside.
                if let TypeArtifact::Struct { name } = &p.ty {
                    if let Some(fields) = main.struct_fields(name) {
                        let same = fields.len() == sib.contract.state_fields.len()
                            && fields.iter().zip(sib.contract.state_fields.iter()).all(|(a, b)| a.1 == b.1);
                        if same {
                            let mut m = BTreeMap::new();
                            for ((fname, _), (sname, _)) in fields.iter().zip(sib.contract.state_fields.iter()) {
                                m.insert(fname.clone(), sib_state.get(sname).cloned().unwrap_or(ArtifactValue::Int(0)));
                            }
                            args.push(ArgRecipe::Value(ArtifactValue::Object(m)));
                            continue;
                        }
                    }
                }
                args.push(ArgRecipe::Value(if matches!(p.ty, TypeArtifact::FixedBytes { len: 32 }) && n.contains("owner") {
                    // Whoever the spend pays: an honest party the tool holds.
                    ArtifactValue::Bytes(owner.clone())
                } else if n.contains("proof") || n.contains("seal") {
                    ArtifactValue::Bytes(crate::zk::test_proof())
                } else if n.contains("journal") {
                    ArtifactValue::Bytes(journal_with_record(body, &main.source, &p.name, &bytes_of, &int_of, &owner)?)
                } else if n.contains("prefix") || n.contains("suffix") {
                    let core = n.replace("prefix", "").replace("suffix", "").replace("gen", "");
                    let prog = programs.iter().find(|pr| norm(&pr.contract.contract_name) == core)?;
                    let (pre, suf) = template_parts(&prog.contract)?;
                    ArtifactValue::Bytes(if n.contains("prefix") { pre } else { suf })
                } else if matches!(p.ty, TypeArtifact::Int)
                    && (!in_state || flat.contains(&format!("OpInputCovenantId({})", p.name)) || flat.contains(&format!("tx.inputs[{}]", p.name)) || flat.contains(&format!("tx.outputs[{}]", p.name)))
                {
                    // An index the spender names: the other program's input,
                    // or its second new coin.
                    let q = &p.name;
                    let has = |pats: &[String]| pats.iter().any(|x| flat.contains(x.as_str()));
                    if has(&[
                        format!("validateOutputState({q},"),
                        format!("validateOutputStateWithTemplate({q},"),
                        format!("validateOutputStateWithInputTemplate({q},"),
                        format!("OpOutputCovenantId({q})"),
                    ]) {
                        // The other program's new coin: first for a coin with no
                        // state, after the two continuations otherwise.
                        ArtifactValue::Int(if in_state { 2 } else { 0 })
                    } else if has(&[
                        format!("OpInputCovenantId({q})"),
                        format!("tx.inputs[{q}]"),
                        format!("readInputStateWithTemplate({q},"),
                        format!("readInputState({q})"),
                    ]) || flat.contains(&format!(",{q},")) && flat.contains("InputTemplate(")
                    {
                        ArtifactValue::Int(1)
                    } else if flat.contains(&format!("tx.outputs[{q}].scriptPubKey==this.activeScriptPubKey")) {
                        // Its own continuation.
                        ArtifactValue::Int(if in_state { 0 } else { 1 })
                    } else if flat.contains(&format!("tx.outputs[{q}]")) {
                        ArtifactValue::Int(2)
                    } else {
                        crate::sandbox::zero_value(&p.ty)
                    }
                } else {
                    crate::sandbox::zero_value(&p.ty)
                }));
            }
            let value = crate::sandbox::COVENANT_VALUE;
            let sib_value = 100_000_000u64;
            let cell_value = 100_000_000u64;
            let sib_binding = Some(CovenantBinding::new(1, Hash::from_bytes(sib.cov_id)));
            let mut plan = SpendPlan::simple(
                vec![
                    InputSpec::Covenant { entry: entry.to_string(), args, value, sequence: 0, state: Some(state.clone()) },
                    InputSpec::Raw(RawInput {
                        outpoint: None,
                        signature_script: vec![],
                        sequence: 0,
                        sig_op_count: 0,
                        compute_budget: 2_000,
                        entry: UtxoEntry::new(sib_value, sib_spk.clone(), UTXO_DAA, false, Some(Hash::from_bytes(sib.cov_id))),
                        target: false,
                        signed: false,
                        resign: None,
                    }),
                    InputSpec::P2pk { owner: KeyRef::Attacker, value: 2 * cell_value },
                ],
                vec![
                    OutputSpec::new(value - BASE_FEE, Dest::Successor(state.clone())),
                    OutputSpec { value: sib_value, to: Dest::Raw(sib_spk.clone()), covenant: sib_binding, own: false },
                    // The new coin's KAS is the relayer's own contribution: shortening
                    // it takes from nobody (its token amount is what matters).
                    OutputSpec { value: cell_value, to: Dest::Raw(sib_spk.clone()), covenant: sib_binding, own: true },
                    OutputSpec::new(cell_value - BASE_FEE, Dest::Key(KeyRef::Attacker)),
                ],
                0,
                pov_daa,
                block_time,
            );
            if !in_state {
                // A coin with no state of its own (an order): it may continue
                // as itself; the other program's new coins come first, where
                // the order pays out at its own input's index.
                plan.outputs = vec![
                    OutputSpec { value: cell_value, to: Dest::Raw(sib_spk.clone()), covenant: sib_binding, own: false },
                    OutputSpec::new(value - BASE_FEE, Dest::SelfCovenant),
                    OutputSpec::new(cell_value - BASE_FEE, Dest::Key(KeyRef::Attacker)),
                ];
                if let Some(InputSpec::Covenant { state, .. }) = plan.inputs.get_mut(0) {
                    *state = None;
                }
            }
            plan.version = 1;
            let sib_key = keyed.then_some(main.wallets.attacker.keypair);
            if let (Some((name, v)), Some(InputSpec::Covenant { args, .. })) = (&seed, plan.inputs.get_mut(0)) {
                if let Some(i) = me.params.iter().position(|p| &p.name == name) {
                    args[i] = ArgRecipe::Value(if matches!(me.params[i].ty, TypeArtifact::FixedBytes { len: 8 }) {
                        ArtifactValue::Bytes((*v as u64).to_le_bytes().to_vec())
                    } else {
                        ArtifactValue::Int(*v)
                    });
                }
            }
            let mut d = Draft { plan, sib: 1, sib_entry: sib_entry.name.clone(), sib_args: vec![], redeems: BTreeMap::new(), repaired: Default::default(), sib_state: Some(sib_state.clone()), delegate: None, sib_key, last_fix: None, frozen: match borrow {
                Borrow::No => vec![],
                Borrow::On => sib_state.keys().filter(|k| norm(k).contains("borrow")).cloned().collect(),
                Borrow::OnPlusOne => sib_state.keys().filter(|k| norm(k).contains("borrow") || k.as_str() == "amount").cloned().collect(),
            } };
            let mut notes = Vec::new();
            for _ in 0..24 {
                d.sib_args = sibling_args(sib, &sib_entry.name, programs, &d)?;
                rebuild_sibling(&mut d, sib, &sib_state)?;
                let (verdict, built) = judge.run(main, &d.plan);
                if let Verdict::Accepted { .. } = verdict {
                    // KAS the repairs left to the miner goes back to the spender's
                    // change, so the honest spend pays a normal fee.
                    let fee = d.plan.input_total().saturating_sub(d.plan.output_total());
                    if fee > 10 * BASE_FEE {
                        let mut tidy = d.plan.clone();
                        match tidy.outputs.iter_mut().find(|o| o.to == Dest::Key(KeyRef::Attacker)) {
                            Some(o) => o.value += fee - BASE_FEE,
                            None => tidy.outputs.push(OutputSpec::new(fee - BASE_FEE, Dest::Key(KeyRef::Attacker))),
                        }
                        if let (Verdict::Accepted { .. }, _) = judge.run(main, &tidy) {
                            d.plan = tidy;
                        }
                    }
                    notes.push(format!(
                        "family: `{entry}` was spent together with a coin of {} (`{}`), each with its own covenant id; outputs it authorizes belong to its family. The tool learned the scripts of the outputs from the programs' own checks.",
                        sib.file, sib_entry.name
                    ));
                    notes.push(format!("family-member: {}|{}|{}|{entry}+{}", sib.file, sib_entry.name, main.file_name, sib_entry.name));
                    if let Some(del) = &d.delegate {
                        // The follower entry ran too, on a coin an honest key owns.
                        notes.push(format!("family-member: {}|{}|{}|{entry}+{}", sib.file, del.entry, main.file_name, sib_entry.name));
                    }
                    // The coins this spend created, for the next step: spending them.
                    let attacker = main.wallets.attacker.xonly().to_vec();
                    for (k, r) in d.redeems.iter().filter(|(k, _)| **k >= 2) {
                        if let Some(p) = programs.iter().find(|p| decode_state(&p.contract, r).is_some()) {
                            // The spender's own coin (what a buyer takes) is no one else's to test.
                            if decode_state(&p.contract, r).is_some_and(|st| st.values().any(|v| *v == ArtifactValue::Bytes(attacker.clone()))) {
                                continue;
                            }
                            // A coin a covenant owns (an order's remainder) moves only with that covenant.
                            let main_id = crate::sandbox::sandbox_covenant_id().as_bytes().to_vec();
                            if decode_state(&p.contract, r).is_some_and(|st| st.values().any(|v| *v == ArtifactValue::Bytes(main_id.clone()))) {
                                continue;
                            }
                            notes.push(format!("minted: {}|{}|{entry}+{}|{k}", p.file, faster_hex::hex_string(r), sib_entry.name));
                        }
                    }
                    let status = PathStatus {
                        entry: format!("{entry}+{}", sib_entry.name),
                        name: entry.to_string(),
                        state: Some(state.clone()),
                        baseline: Some(Baseline {
                            variants: match borrow {
                                Borrow::No => {
                                    let mut v = variants(main, &d, sib, &sib_state, programs, judge);
                                    v.extend(borrow_variants(main, entry, programs, judge, &seed, scale, &d, sib, keyed));
                                    v
                                }
                                // The stranger's borrow of the coin as it is now, for the caller.
                                Borrow::On => stranger_borrow(main, &d, sib).map(|p| ("BOR", String::new(), p, String::new())).into_iter().collect(),
                                Borrow::OnPlusOne => vec![],
                            },
                            signers: d.plan.signers(),
                            plan: d.plan,
                            secrets: if body.contains("proof") || body.contains("seal") { vec!["the tool's test proof".into()] } else { vec![] },
                            lock: None,
                        }),
                        unexplored_reason: None,
                        tries: 1,
                        imported: false,
                    };
                    return Some((status, notes));
                }
                let Some(built) = built else { break };
                if std::env::var_os("REDTEAM_DEBUG").is_some() {
                    eprintln!("family {entry}+{}: {verdict:?}", sib_entry.name);
                }
                let failing = (0..d.plan.inputs.len()).find_map(|i| trace_failure(&built, i));
                let Some(f) = failing else { break };
                if std::env::var_os("REDTEAM_DEBUG").is_some() {
                    eprintln!("  input {} {} a={} b={}", f.input, f.op, faster_hex::hex_string(&f.a[..f.a.len().min(40)]), faster_hex::hex_string(&f.b[..f.b.len().min(40)]));
                }
                if std::env::var_os("REDTEAM_DEBUG").is_some() {
                    for (k, o) in built.tx.outputs.iter().enumerate() {
                        eprintln!("    out {k} {} {:?}", faster_hex::hex_string(&spk_bytes(&o.script_public_key)), o.covenant);
                    }
                }
                if add_or_drop_coins(&mut d, &f, sib, &owner_key) {
                    continue;
                }
                if rest_to_spender(&mut d, &f, sib, main) {
                    continue;
                }
                if !repair(&mut d, &built, &f, main) && !slice_fix(&mut d, &f, sib) {
                    break;
                }
            }
        }
        }
    }
    None
}

/// Hostile versions of an accepted family spend: each changes what the
/// family's new coins say (amount, owner, how many, which family), or how the
/// authority continues, or replays the same data on the next state. Every
/// version is internally consistent (the other program's arguments are
/// rebuilt to match), so only the rules under test decide.
fn variants(
    main: &Contract,
    d: &Draft,
    sib: &Program,
    sib_state: &StateValues,
    programs: &[Program],
    judge: &Judge,
) -> Vec<(&'static str, String, SpendPlan, String)> {
    let _ = judge;
    let mut out = Vec::new();
    // The new coins: after the two continuations, or, for a coin with no state
    // of its own (an order), every new coin of the other program's family.
    let sib_id = Hash::from_bytes(sib.cov_id);
    let stateless = matches!(d.plan.inputs.first(), Some(InputSpec::Covenant { state: None, .. }));
    let cells: Vec<usize> = d
        .redeems
        .keys()
        .copied()
        .filter(|k| *k >= 2 || stateless && d.plan.outputs.get(*k).and_then(|o| o.covenant).map(|c| c.covenant_id) == Some(sib_id))
        // The spender's own new coin (a buyer's tokens): changing it only
        // cheats the spender.
        .filter(|k| {
            let mine = main.wallets.attacker.xonly().to_vec();
            !d.redeems
                .get(k)
                .and_then(|r| decode_state(&sib.contract, r))
                .is_some_and(|st| cov_fields(&sib.contract).iter().any(|f| st.get(f) == Some(&ArtifactValue::Bytes(mine.clone()))))
        })
        .collect();
    let attacker = main.wallets.attacker.xonly().to_vec();
    let base = format!("{:?}", d.plan);
    let finish = |mut v: Draft| -> Option<SpendPlan> {
        v.sib_args = sibling_args(sib, &v.sib_entry, programs, &v)?;
        rebuild_sibling(&mut v, sib, sib_state)?;
        // A version that changes nothing is no attack.
        (format!("{:?}", v.plan) != base).then_some(v.plan)
    };
    let clone = |d: &Draft| Draft {
        plan: d.plan.clone(),
        sib: d.sib,
        sib_entry: d.sib_entry.clone(),
        sib_args: vec![],
        redeems: d.redeems.clone(),
        repaired: d.repaired.clone(),
        sib_state: d.sib_state.clone(),
        delegate: d.delegate.clone(),
        sib_key: d.sib_key,
        last_fix: d.last_fix,
        frozen: d.frozen.clone(),
    };
    // A new coin with its state changed: re-encoded with its own program.
    let restate = |d: &Draft, k: usize, f: &dyn Fn(&mut StateValues)| -> Option<Draft> {
        let r = d.redeems.get(&k)?;
        let prog = programs.iter().find(|p| decode_state(&p.contract, r).is_some())?;
        let mut st = decode_state(&prog.contract, r)?;
        f(&mut st);
        let nr = encode_state(&prog.contract, &st)?;
        let mut v = clone(d);
        v.plan.outputs[k].to = Dest::Raw(pay_to_script_hash_script(&nr));
        v.redeems.insert(k, nr);
        Some(v)
    };
    for &k in &cells {
        if let Some(v) = restate(d, k, &|st| {
            if let Some(ArtifactValue::Int(a)) = st.get_mut("amount") {
                *a = a.saturating_mul(2).saturating_add(100_000_000);
            }
        }) {
            if let Some(p) = finish(v) {
                out.push(("FAM-01", format!("output {k} mints more than the data says"), p,
                    format!("the new coin at output {k} was minted with a larger amount than the proven data allows, and the family accepted it. Whoever relays a valid proof can mint extra tokens.")));
            }
        }
        if let Some(v) = restate(d, k, &|st| {
            if let Some(ArtifactValue::Bytes(o)) = st.get_mut("owner") {
                if o.len() == attacker.len() {
                    *o = attacker.clone();
                }
            }
        }) {
            if let Some(p) = finish(v) {
                out.push(("FAM-02", format!("output {k} owned by the attacker"), p,
                    format!("the new coin at output {k} names the attacker as owner instead of whoever the proven data names, and the family accepted it. Whoever relays a valid proof can take the minted tokens.")));
            }
        }
        // One more coin than the data pays for.
        let mut v = clone(d);
        let extra = d.plan.outputs[k].clone();
        let at = d.plan.outputs.len() - 1;
        v.plan.outputs.insert(at, extra);
        // The relayer pays the extra coin's KAS too.
        if let Some(InputSpec::P2pk { value, .. }) = v.plan.inputs.iter_mut().find(|i| matches!(i, InputSpec::P2pk { .. })) {
            *value += d.plan.outputs[k].value;
        }
        v.redeems.insert(at, d.redeems[&k].clone());
        if let Some(p) = finish(v) {
            out.push(("FAM-03", format!("a second copy of output {k}"), p,
                "a second new coin, identical to the one the proven data pays for, was minted in the same transaction and the family accepted it. Every deposit can be minted twice.".into()));
        }
        // The same coin, bound to the other covenant (counterfeit family).
        let mut v = clone(d);
        if stateless {
            // A look-alike: the same script with no covenant id, while the real
            // tokens go to the attacker in a coin of their own.
            v.plan.outputs[k].covenant = None;
            let kept = restate(&v, k, &|st| {
                for f in cov_fields(&sib.contract) {
                    st.insert(f, ArtifactValue::Bytes(attacker.clone()));
                }
                if let Some((sel, _)) = cov_branch(&sib.contract) {
                    let p2pk = source_consts(&sib.contract.source)
                        .into_iter()
                        .find(|(n, _)| n.contains("P2PK") && !n.contains("P2PKH"))
                        .map(|(_, v)| v)
                        .unwrap_or(ArtifactValue::Byte(0));
                    st.insert(sel, p2pk);
                }
            });
            if let Some(kept) = kept {
                let at = v.plan.outputs.len();
                let mut o = kept.plan.outputs[k].clone();
                o.covenant = d.plan.outputs[k].covenant;
                o.own = true;
                v.plan.outputs.push(o);
                v.redeems.remove(&k);
                v.redeems.insert(at, kept.redeems[&k].clone());
                if let Some(InputSpec::P2pk { value, .. }) = v.plan.inputs.iter_mut().find(|i| matches!(i, InputSpec::P2pk { .. })) {
                    *value += d.plan.outputs[k].value;
                }
            }
        } else {
            v.plan.outputs[k].covenant = Some(CovenantBinding::new(0, crate::sandbox::sandbox_covenant_id()));
        }
        if let Some(p) = finish(v) {
            out.push(("FAM-04", format!("output {k} in the wrong covenant family"), p,
                format!("the new coin at output {k} was created under a different covenant id than the token's family (or none), and the transaction was accepted. Counterfeit coins with the right program and the wrong family can exist next to real ones; here the real tokens stayed with the attacker.")));
        }
    }
    // The authority does not continue: its value goes to the attacker instead.
    if d.plan.outputs.len() > 1 {
        let mut v = clone(d);
        v.plan.outputs[1].to = Dest::Key(KeyRef::Attacker);
        v.plan.outputs[1].covenant = None;
        v.plan.outputs[1].own = false;
        if let Some(p) = finish(v) {
            out.push(("FAM-05", "the other program's coin paid to the attacker".into(), p,
                format!("the coin of {} that took part did not continue; its value went to the attacker and the transaction was accepted.", sib.file)));
        }
    }
    // The same data again, on the state this spend leads to.
    if let Some(next) = d.redeems.get(&0).and_then(|r| decode_state(main, r)) {
        let mut v = clone(d);
        if let Some(InputSpec::Covenant { state, .. }) = v.plan.inputs.get_mut(0) {
            *state = Some(next.clone());
        }
        v.plan.outputs[0].to = Dest::Successor(next);
        v.plan.outputs[0].covenant = None;
        if let Some(p) = finish(v) {
            out.push(("FAM-06", "the same proof and data replayed on the next state".into(), p,
                "the same proof and data were accepted a second time, on the state the first spend left. Every deposit can be minted again and again.".into()));
        }
    }
    // Nothing guards the spend (no proof, no signature): what the coin under
    // test hands out must be paid for. The new coins go to the attacker and
    // the coin's KAS stays where it was.
    let guarded = main.entry(&main_entry(d)).is_some_and(|e| {
        e.params.iter().any(|p| {
            let n = norm(&p.name);
            matches!(p.ty, TypeArtifact::Sig) || n.contains("proof") || n.contains("seal") || n.contains("journal")
        })
    });
    let paid_in = match d.plan.inputs.first() {
        Some(InputSpec::Covenant { value, .. }) => Some(*value),
        _ => None,
    };
    if !guarded && !cells.is_empty() {
        if let Some(paid_in) = paid_in {
            let mut v = Some(clone(d));
            for &k in &cells {
                v = v.and_then(|v| {
                    restate(&v, k, &|st| {
                        if let Some(ArtifactValue::Bytes(o)) = st.get_mut("owner") {
                            if o.len() == attacker.len() {
                                *o = attacker.clone();
                            }
                        }
                    })
                });
            }
            if let Some(mut v) = v {
                // The spender names the owner in its arguments: the attacker names itself.
                let before: Vec<Vec<u8>> = cells
                    .iter()
                    .filter_map(|k| d.redeems.get(k))
                    .filter_map(|r| programs.iter().find_map(|p| decode_state(&p.contract, r)))
                    .filter_map(|st| match st.get("owner") {
                        Some(ArtifactValue::Bytes(o)) => Some(o.clone()),
                        _ => None,
                    })
                    .collect();
                if let Some(InputSpec::Covenant { args, .. }) = v.plan.inputs.get_mut(0) {
                    for a in args.iter_mut() {
                        if let ArgRecipe::Value(ArtifactValue::Bytes(b)) = a {
                            if before.contains(b) {
                                *b = attacker.clone();
                            }
                        }
                    }
                }
                let delta = v.plan.outputs[0].value.saturating_sub(paid_in);
                v.plan.outputs[0].value -= delta;
                if let Some(InputSpec::P2pk { value, .. }) = v.plan.inputs.iter_mut().find(|i| matches!(i, InputSpec::P2pk { .. })) {
                    *value = value.saturating_sub(delta).max(BASE_FEE * 2);
                }
                if let Some(p) = finish(v) {
                    out.push(("FAM-09", "the new coins to the attacker, the coin's KAS unchanged".into(), p,
                        format!("anyone spent the coin, took the new coins of {} it created and added no KAS to it, and the transaction was accepted. Whatever the program sells, it gives away. If it is meant to hand its tokens out for free, this is by design.", sib.file)));
                }
            }
        }
    }
    if let Some(v) = stray_coin(main, d, sib, programs) {
        if let Some(p) = finish(v) {
            let signed = !d.plan.signers().is_empty();
            let who = if signed {
                "Only the holder of the key this path requires can do it, but they take tokens that were never under their schedule or terms."
            } else {
                "Tokens sent to it can be taken by anyone; if anyone is meant to sweep them, this is by design."
            };
            out.push(("FAM-10", "a second coin the coin under test owns, swept to the spender".into(), p,
                format!("a second coin of {} owned by this contract (tokens someone sent to it, or a second deposit) was spent in the same transaction and its tokens went to the spender, and the transaction was accepted. The contract checked only the coin it was pointed at. {who}", sib.file)));
        }
    }
    out
}

/// A second coin of the other program owned by the coin under test (its
/// covenant id as owner), spent with the follower entry next to the one the
/// spend uses, its tokens paid to the attacker in a coin of their own.
fn stray_coin(main: &Contract, d: &Draft, sib: &Program, programs: &[Program]) -> Option<Draft> {
    let _ = programs;
    let st = d.sib_state.clone()?;
    let main_id = crate::sandbox::sandbox_covenant_id();
    let by_id = cov_fields(&sib.contract).iter().any(|f| st.get(f) == Some(&ArtifactValue::Bytes(main_id.as_bytes().to_vec())));
    let by_script = p2sh_owned(sib, d);
    if !(by_id || by_script) || d.delegate.is_some() || d.sib_key.is_some() {
        return None;
    }
    let follower = sib.contract.entries.iter().find(|e| {
        e.name != d.sib_entry
            && !e.params.is_empty()
            && e.params.iter().all(|p| norm(&p.name).contains("witness"))
            && crate::tune::entry_body(&sib.contract.source, &e.name).is_some_and(|b| b.contains("!= this.activeInputIndex"))
    })?;
    let stray_amount = 100_000_000i64;
    let mut stray = st.clone();
    stray.insert("amount".into(), ArtifactValue::Int(stray_amount));
    let redeem = encode_state(&sib.contract, &stray)?;
    let artifact = sib.contract.artifact.as_ref()?;
    // Owned by a covenant id: the witness is empty (no path byte for a follower);
    // by a script hash: the index of the input that carries the script.
    let w = if by_script { vec![0x00] } else { vec![] };
    let args: Vec<ArtifactValue> = follower.params.iter().map(|_| ArtifactValue::Bytes(w.clone())).collect();
    let mut script = silverscript_abi::encode_contract_entry_sig_script(artifact, &sib.contract.contract_name, &follower.name, &args).ok()?;
    script.extend(crate::sandbox::push_data(&redeem).ok()?);
    let id = Hash::from_bytes(sib.cov_id);
    let value = 100_000_000u64;
    let mut v = Draft {
        plan: d.plan.clone(),
        sib: d.sib,
        sib_entry: d.sib_entry.clone(),
        sib_args: vec![],
        redeems: d.redeems.clone(),
        repaired: d.repaired.clone(),
        sib_state: d.sib_state.clone(),
        delegate: None,
        sib_key: None,
        last_fix: d.last_fix,
        frozen: d.frozen.clone(),
    };
    v.plan.inputs.insert(
        d.sib + 1,
        InputSpec::Raw(RawInput {
            outpoint: None,
            signature_script: script,
            sequence: 0,
            sig_op_count: 0,
            compute_budget: 2_000,
            entry: UtxoEntry::new(value, pay_to_script_hash_script(&redeem), UTXO_DAA, false, Some(id)),
            target: false,
            signed: false,
            resign: None,
        }),
    );
    // The swept tokens, in a coin the attacker owns.
    let attacker = main.wallets.attacker.xonly().to_vec();
    let mut mine = st;
    mine.insert("amount".into(), ArtifactValue::Int(stray_amount));
    for f in cov_fields(&sib.contract) {
        mine.insert(f, ArtifactValue::Bytes(attacker.clone()));
    }
    if let Some((sel, _)) = cov_branch(&sib.contract) {
        let p2pk = source_consts(&sib.contract.source)
            .into_iter()
            .find(|(n, _)| n.contains("P2PK") && !n.contains("P2PKH"))
            .map(|(_, v)| v)
            .unwrap_or(ArtifactValue::Byte(0));
        mine.insert(sel, p2pk);
    }
    let r2 = encode_state(&sib.contract, &mine)?;
    let k = v.plan.outputs.len();
    v.plan.outputs.push(OutputSpec {
        value,
        to: Dest::Raw(pay_to_script_hash_script(&r2)),
        covenant: Some(CovenantBinding::new(d.sib as u16, id)),
        own: true,
    });
    v.redeems.insert(k, r2);
    Some(v)
}

fn main_entry(d: &Draft) -> String {
    match d.plan.inputs.first() {
        Some(InputSpec::Covenant { entry, .. }) => entry.clone(),
        _ => String::new(),
    }
}

/// Paths that start a new covenant family (`OpOutputCovenantId(1)` of an
/// output no input carries yet): a bridge's `init` creating its mint
/// authority, a launch creating a token's first coins. The draft pays the
/// coin under test's successor plus one new coin of a project program, whose
/// covenant id consensus derives from the authorizing input and the new
/// outputs (genesis); the scripts' own checks then fill in both scripts.
pub fn explore_genesis(main: &Contract, entry: &str, programs: &[Program], judge: &Judge) -> Option<(PathStatus, Vec<String>)> {
    let body = crate::tune::entry_body(&main.source, entry)?;
    if !body.contains("OpOutputCovenantId") {
        return None;
    }
    let init = main.initial_state.clone()?;
    let (pov_daa, block_time) = crate::baseline::pov(main);
    let main_id = crate::sandbox::sandbox_covenant_id();
    let core = |n: &str| norm(n).replace("init", "").replace("gen", "");
    for prog in programs.iter().filter(|p| p.contract.is_stateful()) {
        // Before the family exists, the field that will name it is empty.
        let mut state = init.clone();
        for f in cov_fields(main) {
            state.insert(f, ArtifactValue::Bytes(vec![0; 32]));
        }
        // The new coin's starting state: shared names from the coin under test,
        // covenant-id fields naming it.
        let mut st = prog.contract.initial_state.clone()?;
        for (field, v) in st.iter_mut() {
            let c = core(field);
            if let Some(a) = main.args.iter().find(|a| core(&a.name) == c && a.ty == "byte[32]") {
                *v = a.value.clone();
            }
        }
        for f in cov_fields(&prog.contract) {
            st.insert(f, ArtifactValue::Bytes(main_id.as_bytes().to_vec()));
        }
        let redeem = encode_state(&prog.contract, &st)?;
        let me = main.entry(entry)?;
        let mut args = Vec::new();
        for p in &me.params {
            let n = norm(&p.name);
            args.push(ArgRecipe::Value(if n.contains("prefix") || n.contains("suffix") {
                // `bm_prefix`: the program being created, when the name does not say.
                let core = n.replace("prefix", "").replace("suffix", "").replace("gen", "");
                let target = programs
                    .iter()
                    .find(|pr| norm(&pr.contract.contract_name) == core || norm(&pr.contract.contract_name).starts_with(&core) && core.len() >= 2)
                    .unwrap_or(prog);
                let (pre, suf) = template_parts(&target.contract)?;
                ArtifactValue::Bytes(if n.contains("prefix") { pre } else { suf })
            } else if matches!(p.ty, TypeArtifact::Int) && n.contains("out") {
                // `cell_out`: where the new coin sits in this draft.
                ArtifactValue::Int(1)
            } else {
                crate::sandbox::zero_value(&p.ty)
            }));
        }
        let value = crate::sandbox::COVENANT_VALUE;
        let new_value = 100_000_000u64;
        let mut plan = SpendPlan::simple(
            vec![
                InputSpec::Covenant { entry: entry.to_string(), args, value, sequence: 0, state: Some(state.clone()) },
                InputSpec::P2pk { owner: KeyRef::Attacker, value: new_value + BASE_FEE },
            ],
            vec![
                // The coin under test keeps every sompi; the funding coin pays the fee.
                OutputSpec::new(value, Dest::Successor(state.clone())),
                OutputSpec { value: new_value, to: Dest::Raw(pay_to_script_hash_script(&redeem)), covenant: None, own: true },
            ],
            0,
            pov_daa,
            block_time,
        );
        plan.version = 1;
        plan.genesis = vec![(1, vec![1])];
        let mut d = Draft { plan, sib: usize::MAX, sib_entry: String::new(), sib_args: vec![], redeems: BTreeMap::new(), repaired: Default::default(), sib_state: None, delegate: None, sib_key: None, last_fix: None, frozen: vec![] };
        d.redeems.insert(1, redeem);
        for _ in 0..16 {
            let (verdict, built) = judge.run(main, &d.plan);
            if let Verdict::Accepted { .. } = verdict {
                let mut variants = Vec::new();
                // Starting the family again from the state this spend leads to.
                if let Some(next) = d.redeems.get(&0).and_then(|r| decode_state(main, r)) {
                    let mut p = d.plan.clone();
                    if let Some(InputSpec::Covenant { state, .. }) = p.inputs.get_mut(0) {
                        *state = Some(next.clone());
                    }
                    p.outputs[0].to = Dest::Successor(next);
                    p.outputs[0].covenant = None;
                    variants.push(("FAM-07", "the family started a second time, from the next state".to_string(), p,
                        format!("`{entry}` started a second family of {} from the state its first run left, and consensus accepted it. Two families of the same program, each with a valid-looking start, can exist.", prog.file)));
                }
                let notes = vec![format!(
                    "genesis: `{entry}` started a new covenant family with a coin of {}; its covenant id was derived as consensus does, from the authorizing input and the new outputs.",
                    prog.file
                )];
                let status = PathStatus {
                    entry: entry.to_string(),
                    name: entry.to_string(),
                    state: Some(state),
                    baseline: Some(Baseline { plan: d.plan, signers: vec![], secrets: vec![], lock: None, variants }),
                    unexplored_reason: None,
                    tries: 1,
                    imported: false,
                };
                return Some((status, notes));
            }
            let Some(built) = built else { break };
            let failing = (0..d.plan.inputs.len()).find_map(|i| trace_failure(&built, i));
            let Some(f) = failing else { break };
            if std::env::var_os("REDTEAM_DEBUG").is_some() {
                eprintln!("genesis {entry}: input {} {} a={} b={}", f.input, f.op, faster_hex::hex_string(&f.a[..f.a.len().min(40)]), faster_hex::hex_string(&f.b[..f.b.len().min(40)]));
            }
            if !repair(&mut d, &built, &f, main) {
                break;
            }
        }
    }
    None
}

/// Constants of a source: `byte constant X = 0x02;`, `int constant N = 3;`.
fn source_consts(source: &str) -> BTreeMap<String, ArtifactValue> {
    let mut m = BTreeMap::new();
    for l in source.lines() {
        let l = l.trim();
        let Some((lhs, rhs)) = l.split_once('=') else { continue };
        let mut w = lhs.split_whitespace();
        let (Some(ty), Some(c), Some(name)) = (w.next(), w.next(), w.next()) else { continue };
        if c != "constant" {
            continue;
        }
        let v = rhs.trim().trim_end_matches(';').trim();
        let val = match ty {
            "byte" => v.strip_prefix("0x").and_then(|h| u8::from_str_radix(h, 16).ok()).map(ArtifactValue::Byte),
            "int" => v.replace('_', "").parse().ok().map(ArtifactValue::Int),
            "bool" => v.parse().ok().map(ArtifactValue::Bool),
            _ => None,
        };
        if let Some(val) = val {
            m.insert(name.to_string(), val);
        }
    }
    m
}

/// What the source requires of a struct-typed name, field by field:
/// `require(p.f == X)`, `require(p.f)`, `require(!p.f)`. `own_id` stands for
/// values the source takes from `OpInputCovenantId(this.activeInputIndex)`.
fn field_requirements(source: &str, p: &str, own_id: &[u8]) -> BTreeMap<String, ArtifactValue> {
    let consts = source_consts(source);
    let own_vars: Vec<String> = source
        .lines()
        .filter(|l| l.contains("OpInputCovenantId(this.activeInputIndex)") && l.contains('='))
        .filter_map(|l| l.split('=').next()?.split_whitespace().last().map(str::to_string))
        .collect();
    let mut m = BTreeMap::new();
    for l in source.lines() {
        let l = l.split("//").next().unwrap_or("").trim();
        let Some(inner) = l.strip_prefix("require(") else { continue };
        let inner = inner.trim_end_matches(';').trim_end_matches(')');
        let (neg, inner) = match inner.strip_prefix('!') {
            Some(r) => (true, r),
            None => (false, inner),
        };
        let Some(rest) = inner.strip_prefix(&format!("{p}.")) else { continue };
        let field: String = rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
        let tail = rest[field.len()..].trim();
        if tail.is_empty() {
            m.insert(field, ArtifactValue::Bool(!neg));
        } else if let Some(x) = tail.strip_prefix("==") {
            let x = x.trim().trim_end_matches(')');
            if let Some(v) = consts.get(x) {
                m.insert(field, v.clone());
            } else if own_vars.iter().any(|o| o == x) || x.contains("OpInputCovenantId(this.activeInputIndex)") {
                m.insert(field, ArtifactValue::Bytes(own_id.to_vec()));
            }
        }
    }
    m
}

/// The branch a program takes when its owner is a covenant id: in
/// `if (identifierType == IDENTIFIER_COVENANT_ID) { require(OpCovInputCount(ownerIdentifier) > 0); }`
/// the selector field and its value.
fn cov_branch(c: &Contract) -> Option<(String, ArtifactValue)> {
    let consts = source_consts(&c.source);
    let lines: Vec<&str> = c.source.lines().collect();
    for (i, l) in lines.iter().enumerate() {
        let al = aliases(&c.source);
        let hit = cov_fields(c).iter().any(|f| {
            l.contains(&format!("({f})")) || al.iter().any(|(p, x)| x == f && l.contains(&format!("({p})")))
        });
        if !(l.contains("OpCovInputCount(") && hit) {
            continue;
        }
        for back in lines[..i].iter().rev().take(4) {
            let b = back.trim();
            if let Some(at) = b.find("if") {
                let cond = &b[at..];
                let cond = cond.trim_start_matches("if").trim().trim_start_matches('(');
                if let Some((lhs, rhs)) = cond.split_once("==") {
                    let lhs = lhs.trim().to_string();
                    let lhs = aliases(&c.source).get(&lhs).cloned().unwrap_or(lhs);
                    let rhs = rhs.trim().trim_end_matches('{').trim().trim_end_matches(')').trim();
                    if let Some(v) = consts.get(rhs) {
                        return Some((lhs, v.clone()));
                    }
                }
                break;
            }
        }
    }
    None
}

/// The other family shape: the coin under test controls a coin of another
/// program by covenant id (an owner field set to its id) and passes the new
/// coins of that program as typed arguments it checks field by field (a
/// minter with `minterKcc20NewState`, `recipientKcc20NewState`). The draft
/// takes those requirements from the source; the controlled coin spends with
/// its own entry and lists the same new coins.
pub fn explore_owned(main: &Contract, entry: &str, programs: &[Program], judge: &Judge) -> Option<(PathStatus, Vec<String>)> {
    let me = main.entry(entry)?;
    let main_cov = cov_fields(main);
    let init = main.initial_state.clone()?;
    let foreign: Vec<(String, String)> = me
        .params
        .iter()
        .filter_map(|p| match &p.ty {
            TypeArtifact::Struct { name } if name != "State" => Some((p.name.clone(), name.clone())),
            _ => None,
        })
        .collect();
    if main_cov.is_empty() || foreign.is_empty() {
        return None;
    }
    let (pov_daa, block_time) = crate::baseline::pov(main);
    let main_id = crate::sandbox::sandbox_covenant_id();
    let debug = std::env::var_os("REDTEAM_DEBUG").is_some();
    for sib in programs.iter().filter(|p| p.contract.is_stateful() && !cov_fields(&p.contract).is_empty()) {
        let mut state = init.clone();
        for f in &main_cov {
            state.insert(f.clone(), ArtifactValue::Bytes(sib.cov_id.to_vec()));
        }
        // The entry's own requirements on the state it starts from:
        // `require(initialized)`, `require(!paused)`.
        if let Some(body) = crate::tune::entry_body(&main.source, entry) {
            for l in body.lines() {
                let l = l.split("//").next().unwrap_or("").trim();
                let Some(inner) = l.strip_prefix("require(") else { continue };
                let inner = inner.trim_end_matches(';').trim_end_matches(')').trim();
                let (neg, name) = match inner.strip_prefix('!') {
                    Some(r) => (true, r.trim()),
                    None => (false, inner),
                };
                if matches!(state.get(name), Some(ArtifactValue::Bool(_))) {
                    state.insert(name.to_string(), ArtifactValue::Bool(!neg));
                }
            }
        }
        // The controlled coin: owned by the coin under test's covenant id, on the
        // branch that checks that ownership.
        let mut sib_state = sib.contract.initial_state.clone()?;
        let sib_default = sib_state.clone();
        for f in cov_fields(&sib.contract) {
            sib_state.insert(f, ArtifactValue::Bytes(main_id.as_bytes().to_vec()));
        }
        if let Some((sel, v)) = cov_branch(&sib.contract) {
            sib_state.insert(sel, v);
        }
        // Each typed argument's required fields; the one that keeps the owner is
        // the controlled coin's continuation, and its requirements apply to the
        // coin itself too (a minter stays a minter).
        let reqs: Vec<BTreeMap<String, ArtifactValue>> =
            foreign.iter().map(|(p, _)| field_requirements(&main.source, p, &main_id.as_bytes())).collect();
        let owner_fields = cov_fields(&sib.contract);
        let cont = reqs.iter().position(|r| owner_fields.iter().any(|f| r.get(f) == Some(&ArtifactValue::Bytes(main_id.as_bytes().to_vec()))));
        if let Some(k) = cont {
            for (f, v) in &reqs[k] {
                if sib_state.contains_key(f) {
                    sib_state.insert(f.clone(), v.clone());
                }
            }
        }
        let depositor = {
            let mut w = crate::wallets::Wallets::new();
            let i = w.party("depositor");
            w.parties[i].xonly().to_vec()
        };
        let cells: Vec<StateValues> = reqs
            .iter()
            .enumerate()
            .map(|(k, r)| {
                let mut st = sib_state.clone();
                if Some(k) != cont {
                    // A recipient: a key the tool holds, the program's default owner kind.
                    for f in &owner_fields {
                        st.insert(f.clone(), ArtifactValue::Bytes(depositor.clone()));
                    }
                    if let Some((sel, _)) = cov_branch(&sib.contract) {
                        if let Some(v) = sib_default.get(&sel) {
                            st.insert(sel, v.clone());
                        }
                    }
                    if let Some(ArtifactValue::Int(a)) = st.get_mut("amount") {
                        *a = 100_000_000;
                    }
                }
                for (f, v) in r {
                    if st.contains_key(f) {
                        st.insert(f.clone(), v.clone());
                    }
                }
                st
            })
            .collect();
        let sib_redeem = encode_state(&sib.contract, &sib_state)?;
        let sib_spk = pay_to_script_hash_script(&sib_redeem);
        let sib_binding = Some(CovenantBinding::new(1, Hash::from_bytes(sib.cov_id)));
        // The coin under test's arguments.
        let owner_party = main.wallets.parties.first().map(|_| KeyRef::Party(0)).unwrap_or(KeyRef::Attacker);
        let mut args = Vec::new();
        let mut fi = 0;
        for p in &me.params {
            args.push(match &p.ty {
                TypeArtifact::Sig => ArgRecipe::Sig(owner_party),
                TypeArtifact::Struct { name } if name == "State" => {
                    ArgRecipe::States { inputs: false, array: false, item: "State".into() }
                }
                TypeArtifact::Struct { name } => {
                    let fields = main.struct_fields(name)?;
                    let v = struct_obj(&fields, &cells[fi]);
                    fi += 1;
                    ArgRecipe::Value(v)
                }
                ty => ArgRecipe::Value(crate::sandbox::zero_value(ty)),
            });
        }
        let value = crate::sandbox::COVENANT_VALUE;
        let sib_value = 100_000_000u64;
        let mut outputs = vec![OutputSpec::new(value - BASE_FEE, Dest::Successor(state.clone()))];
        let mut redeems = BTreeMap::new();
        for (k, st) in cells.iter().enumerate() {
            let r = encode_state(&sib.contract, st)?;
            outputs.push(OutputSpec { value: sib_value, to: Dest::Raw(pay_to_script_hash_script(&r)), covenant: sib_binding, own: true });
            redeems.insert(k + 1, r);
        }
        outputs.push(OutputSpec::new(sib_value - BASE_FEE, Dest::Key(KeyRef::Attacker)));
        for sib_entry in sib.contract.entries.iter().filter(|e| e.params.iter().any(|p| matches!(p.ty, TypeArtifact::DynamicArray { .. }))) {
            let mut plan = SpendPlan::simple(
                vec![
                    InputSpec::Covenant { entry: entry.to_string(), args: args.clone(), value, sequence: 0, state: Some(state.clone()) },
                    InputSpec::Raw(RawInput {
                        outpoint: None,
                        signature_script: vec![],
                        sequence: 0,
                        sig_op_count: 0,
                        compute_budget: 2_000,
                        entry: UtxoEntry::new(sib_value, sib_spk.clone(), UTXO_DAA, false, Some(Hash::from_bytes(sib.cov_id))),
                        target: false,
                        signed: false,
                        resign: None,
                    }),
                    InputSpec::P2pk { owner: KeyRef::Attacker, value: sib_value * cells.len() as u64 },
                ],
                outputs.clone(),
                0,
                pov_daa,
                block_time,
            );
            plan.version = 1;
            let mut d = Draft { plan, sib: 1, sib_entry: sib_entry.name.clone(), sib_args: vec![], redeems: redeems.clone(), repaired: Default::default(), sib_state: None, delegate: None, sib_key: None, last_fix: None, frozen: vec![] };
            for _ in 0..16 {
                let mut sa = sibling_args(sib, &sib_entry.name, programs, &d)?;
                // Signature-typed arguments of the controlled coin: never checked on
                // the covenant-id branch, but they must be well formed.
                for (v, p) in sa.iter_mut().zip(sib.contract.entry(&sib_entry.name)?.params.iter()) {
                    if matches!(p.ty, TypeArtifact::Sig) {
                        *v = ArtifactValue::Bytes(vec![0; 65]);
                    }
                }
                d.sib_args = sa;
                rebuild_sibling(&mut d, sib, &sib_state)?;
                let (verdict, built) = judge.run(main, &d.plan);
                if let Verdict::Accepted { .. } = verdict {
                    let mut notes = vec![format!(
                        "family: `{entry}` was spent together with a coin of {} it controls by covenant id (`{}`), creating {} new coin(s) of it from its typed arguments.",
                        sib.file, sib_entry.name, cells.len()
                    )];
                    // New coins that are not the controlled coin's continuation: spent next by their owner.
                    for k in 0..cells.len() {
                        if Some(k) != cont {
                            if let Some(r) = d.redeems.get(&(k + 1)) {
                                notes.push(format!("minted: {}|{}|{entry}+{}|{}", sib.file, faster_hex::hex_string(r), sib_entry.name, k + 1));
                            }
                        }
                    }
                    let variants = owned_variants(main, &d, sib, &sib_state, programs, &me.params, &cells, cont, &state);
                    let status = PathStatus {
                        entry: format!("{entry}+{}", sib_entry.name),
                        name: entry.to_string(),
                        state: Some(state.clone()),
                        baseline: Some(Baseline { plan: d.plan, signers: vec![owner_party], secrets: vec![], lock: None, variants }),
                        unexplored_reason: None,
                        tries: 1,
                        imported: false,
                    };
                    return Some((status, notes));
                }
                let Some(built) = built else {
                    if debug {
                        eprintln!("owned {entry}+{}: {verdict:?}", sib_entry.name);
                    }
                    break;
                };
                let Some(f) = (0..d.plan.inputs.len()).find_map(|i| trace_failure(&built, i)) else { break };
                if debug {
                    eprintln!("owned {entry}+{}: input {} {} a={} b={}", sib_entry.name, f.input, f.op, faster_hex::hex_string(&f.a[..f.a.len().min(40)]), faster_hex::hex_string(&f.b[..f.b.len().min(40)]));
                }
                if !repair(&mut d, &built, &f, main) {
                    break;
                }
            }
        }
    }
    None
}

/// Hostile versions of an owned-family spend. The coin under test's typed
/// arguments, the controlled coin's arguments, the new coins and the next
/// state are all rebuilt to agree, so only the rules decide. The signer is the
/// coin's own owner: these ask what the person who may mint can get away with.
#[allow(clippy::too_many_arguments)]
fn owned_variants(
    main: &Contract,
    d: &Draft,
    sib: &Program,
    sib_state: &StateValues,
    programs: &[Program],
    params: &[crate::contract::EntryParam],
    cells: &[StateValues],
    cont: Option<usize>,
    state: &StateValues,
) -> Vec<(&'static str, String, SpendPlan, String)> {
    let mut out = Vec::new();
    // Rebuild a plan from (possibly changed) new coins and next state.
    let build = |cells: &[StateValues], next: Option<&StateValues>, extra: Option<StateValues>, family: Option<CovenantBinding>| -> Option<SpendPlan> {
        let mut v = Draft {
            plan: d.plan.clone(),
            sib: d.sib,
            sib_entry: d.sib_entry.clone(),
            sib_args: vec![],
            redeems: BTreeMap::new(),
            repaired: d.repaired.clone(),
            sib_state: d.sib_state.clone(),
            delegate: d.delegate.clone(),
            sib_key: d.sib_key,
            last_fix: d.last_fix,
            frozen: d.frozen.clone(),
        };
        if let Some(InputSpec::Covenant { args, .. }) = v.plan.inputs.get_mut(0) {
            let mut fi = 0;
            for (a, p) in args.iter_mut().zip(params) {
                if let TypeArtifact::Struct { name } = &p.ty {
                    if name != "State" {
                        let fields = main.struct_fields(name)?;
                        *a = ArgRecipe::Value(struct_obj(&fields, &cells[fi]));
                        fi += 1;
                    }
                }
            }
        }
        for (k, st) in cells.iter().enumerate() {
            let r = encode_state(&sib.contract, st)?;
            v.plan.outputs[k + 1].to = Dest::Raw(pay_to_script_hash_script(&r));
            v.redeems.insert(k + 1, r);
        }
        if let Some(n) = next {
            v.plan.outputs[0].to = Dest::Successor(n.clone());
        }
        if let Some(e) = extra {
            let r = encode_state(&sib.contract, &e)?;
            let at = cells.len() + 1;
            v.plan.outputs.insert(at, OutputSpec { value: 100_000_000, to: Dest::Raw(pay_to_script_hash_script(&r)), covenant: family.or(d.plan.outputs[1].covenant), own: true });
            v.redeems.insert(at, r);
            if let Some(InputSpec::P2pk { value, .. }) = v.plan.inputs.iter_mut().find(|i| matches!(i, InputSpec::P2pk { .. })) {
                *value += 100_000_000;
            }
        }
        let mut sa = sibling_args(sib, &v.sib_entry, programs, &v)?;
        for (x, p) in sa.iter_mut().zip(sib.contract.entry(&v.sib_entry)?.params.iter()) {
            if matches!(p.ty, TypeArtifact::Sig) {
                *x = ArtifactValue::Bytes(vec![0; 65]);
            }
        }
        v.sib_args = sa;
        rebuild_sibling(&mut v, sib, sib_state)?;
        Some(v.plan)
    };
    let next = match &d.plan.outputs[0].to {
        Dest::Successor(s) => s.clone(),
        _ => state.clone(),
    };
    let allowance = match state.get("amount") {
        Some(ArtifactValue::Int(a)) => *a,
        _ => 0,
    };
    let recipient = (0..cells.len()).find(|k| Some(*k) != cont);
    if let Some(r) = recipient {
        // More than the allowance: the books say what is left, the coin says more.
        let mut c2 = cells.to_vec();
        if let Some(ArtifactValue::Int(a)) = c2[r].get_mut("amount") {
            *a += allowance + 100_000_000;
            let mut n2 = next.clone();
            if let Some(ArtifactValue::Int(left)) = n2.get_mut("amount") {
                *left -= allowance + 100_000_000;
            }
            if let Some(p) = build(&c2, Some(&n2), None, None) {
                out.push(("FAM-01", format!("output {} mints more than the allowance left", r + 1), p,
                    format!("the coin's owner minted more than its remaining allowance ({}) and the books went below zero, and the family accepted it.", crate::kas(allowance as u64))));
            }
        }
        // A second coin no argument describes.
        if let Some(p) = build(cells, Some(&next), Some(cells[r].clone()), None) {
            out.push(("FAM-03", "a coin of the family that no argument describes".into(), p,
                "an extra new coin, not among the ones the coin under test checked, was created in the same transaction and accepted. Tokens can be minted outside the books.".into()));
        }
        // The recipient's coin in the wrong family.
        if let Some(mut p) = build(cells, Some(&next), None, None) {
            p.outputs[r + 1].covenant = Some(CovenantBinding::new(0, crate::sandbox::sandbox_covenant_id()));
            out.push(("FAM-04", format!("output {} in the wrong covenant family", r + 1), p,
                format!("the new coin at output {} was created under the coin under test's own covenant id instead of the token's family, and the transaction was accepted.", r + 1)));
        }
        // Minting power handed to the recipient.
        let mut c3 = cells.to_vec();
        if let (Some(k), Some(ArtifactValue::Bool(_))) = (cont, cells[r].get("isMinter").or(None)) {
            let _ = k;
            c3[r].insert("isMinter".into(), ArtifactValue::Bool(true));
            if let Some(p) = build(&c3, Some(&next), None, None) {
                out.push(("FAM-08", format!("output {} given the minting power", r + 1), p,
                    "a new coin for a recipient carries the authority flag, and the family accepted it. Whoever receives it can mint too.".into()));
            }
        }
    }
    // The controlled coin does not stay under the coin under test's control.
    if let Some(k) = cont {
        let mut c4 = cells.to_vec();
        let attacker = main.wallets.attacker.xonly().to_vec();
        for f in cov_fields(&sib.contract) {
            c4[k].insert(f, ArtifactValue::Bytes(attacker.clone()));
        }
        if let Some((sel, _)) = cov_branch(&sib.contract) {
            if let Some(v) = sib.contract.initial_state.as_ref().and_then(|s| s.get(&sel)) {
                c4[k].insert(sel, v.clone());
            }
        }
        if let Some(p) = build(&c4, Some(&next), None, None) {
            out.push(("FAM-05", "the controlled coin handed to the attacker".into(), p,
                "the coin the coin under test controls by covenant id continued with the attacker's key as owner, and the family accepted it. The minting authority can be taken away from the contract.".into()));
        }
    }
    out
}

#[cfg(test)]
mod alias_tests {
    #[test]
    fn helper_params_resolve_to_state_fields() {
        let src = "function require_owner_authorized(byte[32] gen__glob_owner, byte gen__glob_owner_scheme, byte[] w) {\n  if (gen__glob_owner_scheme == OWNER_COVENANT_ID) {\n    require(OpCovInputCount(gen__glob_owner) > 0);\n  }\n}\nentry t() { require_owner_authorized(owner, owner_scheme, path_witness); }";
        let a = super::aliases(src);
        assert_eq!(a.get("gen__glob_owner").map(String::as_str), Some("owner"));
        assert_eq!(a.get("gen__glob_owner_scheme").map(String::as_str), Some("owner_scheme"));
    }
}

/// The state fields that hold the borrow scheme and its guard, if the program has them.
fn borrow_fields(st: &StateValues) -> (Option<String>, Option<String>) {
    let f = |part: &str| st.keys().find(|k| {
        let n = norm(k);
        n.contains("borrow") && n.contains(part)
    }).cloned();
    (f("scheme"), f("guard"))
}

/// A coin the coin under test holds by covenant id, with borrowing turned on:
/// if the covenant accepts it, a stranger can spend that coin without the
/// covenant (a borrowed receive, KCC-20 section 5). Whether the covenant still
/// works afterwards decides how bad that is.
#[allow(clippy::too_many_arguments)]
fn borrow_variants(
    main: &Contract,
    entry: &str,
    programs: &[Program],
    judge: &Judge,
    seed: &Option<(String, i64)>,
    scale: i64,
    d: &Draft,
    sib: &Program,
    keyed: bool,
) -> Vec<(&'static str, String, SpendPlan, String)> {
    let Some(st) = d.sib_state.clone() else { return vec![] };
    let main_id = crate::sandbox::sandbox_covenant_id().as_bytes().to_vec();
    let owned = !keyed && cov_fields(&sib.contract).iter().any(|f| st.get(f) == Some(&ArtifactValue::Bytes(main_id.clone())));
    let (Some(sf), Some(gf)) = borrow_fields(&st) else { return vec![] };
    if !owned {
        return vec![];
    }
    let file = &sib.file;
    match explore_seeded(main, entry, programs, judge, seed.clone(), scale, Borrow::On) {
        None => {
            // Refused: the honest spend with a borrowable coin, for the record.
            let mut v = Draft {
                plan: d.plan.clone(),
                sib: d.sib,
                sib_entry: d.sib_entry.clone(),
                sib_args: vec![],
                redeems: d.redeems.clone(),
                repaired: d.repaired.clone(),
                sib_state: d.sib_state.clone(),
                delegate: d.delegate.clone(),
                sib_key: d.sib_key,
                last_fix: d.last_fix,
                frozen: vec![],
            };
            if let Some(s2) = v.sib_state.as_mut() {
                s2.insert(sf, ArtifactValue::Byte(1));
                s2.insert(gf, ArtifactValue::Bytes(vec![0; 32]));
            }
            let Some(args) = sibling_args(sib, &v.sib_entry, programs, &v) else { return vec![] };
            v.sib_args = args;
            if rebuild_sibling(&mut v, sib, &st).is_none() {
                return vec![];
            }
            let why = String::new();
            let _ = why;
            vec![("BOR-01", "the coin it holds with borrowing on".into(), v.plan, String::new())]
        }
        Some((a, _)) => {
            let Some(borrow_tx) = a.baseline.as_ref().and_then(|b| b.variants.iter().find(|x| x.0 == "BOR")).map(|x| x.2.clone()) else {
                return vec![];
            };
            let bricked = explore_seeded(main, entry, programs, judge, seed.clone(), scale, Borrow::OnPlusOne).is_none();
            if bricked {
                vec![("BOR-01", "a stranger borrows the coin it holds; the path no longer works".into(), borrow_tx, format!(
                    "the covenant accepted a coin of {file} with borrowing turned on (anyone may borrow it by adding one token unit), and a stranger did so with no part of the covenant in the transaction. Afterwards this path could not be spent any more: the coin's amount no longer matches what the covenant expects. One token unit from anyone bricks it."
                ))]
            } else {
                vec![("BOR-02", "a stranger borrows the coin it holds".into(), borrow_tx, format!(
                    "the covenant accepted a coin of {file} with borrowing turned on (anyone may borrow it by adding one token unit), and a stranger did so with no part of the covenant in the transaction. This path still works afterwards, but the coin's outpoint changed: anyone can keep moving it, so every transaction prepared against it fails."
                ))]
            }
        }
    }
}

/// A stranger's borrowed receive of the coin spent alongside: that coin leads a
/// transfer on the borrow path, the stranger's own coin of the same token
/// follows, and the borrowed coin comes back with one token unit more.
fn stranger_borrow(main: &Contract, d: &Draft, sib: &Program) -> Option<SpendPlan> {
    let st = d.sib_state.clone()?;
    let artifact = sib.contract.artifact.as_ref()?;
    let leader = sib.contract.entries.iter().find(|e| e.name == d.sib_entry)?;
    let follower = sib.contract.entries.iter().find(|e| {
        e.name != d.sib_entry
            && !e.params.is_empty()
            && e.params.iter().all(|p| norm(&p.name).contains("witness"))
            && crate::tune::entry_body(&sib.contract.source, &e.name).is_some_and(|b| b.contains("!= this.activeInputIndex"))
    })?;
    let attacker = main.wallets.attacker.xonly().to_vec();
    let mut mine = st.clone();
    for f in cov_fields(&sib.contract) {
        mine.insert(f, ArtifactValue::Bytes(attacker.clone()));
    }
    if let Some((sel, _)) = cov_branch(&sib.contract) {
        let p2pk = source_consts(&sib.contract.source)
            .into_iter()
            .find(|(n, _)| n.contains("P2PK") && !n.contains("P2PKH"))
            .map(|(_, v)| v)
            .unwrap_or(ArtifactValue::Byte(0));
        mine.insert(sel, p2pk);
    }
    let (Some(sf), _) = borrow_fields(&st) else { return None };
    mine.insert(sf, ArtifactValue::Byte(0));
    let theirs: i64 = 100_000_000;
    mine.insert("amount".into(), ArtifactValue::Int(theirs));
    let mut grown = st.clone();
    if let Some(ArtifactValue::Int(a)) = grown.get_mut("amount") {
        *a += 1;
    }
    let mut left = mine.clone();
    left.insert("amount".into(), ArtifactValue::Int(theirs - 1));
    // The leader's arguments: the two new states, and the borrow path byte.
    let (TypeArtifact::DynamicArray { item } | TypeArtifact::FixedArray { item, .. }) = &leader.params.first()?.ty else { return None };
    let TypeArtifact::Struct { name } = item.as_ref() else { return None };
    let fields = sib.contract.struct_fields(name)?;
    let mut args = vec![ArtifactValue::Array(vec![struct_obj(&fields, &grown), struct_obj(&fields, &left)])];
    for p in leader.params.iter().skip(1) {
        args.push(if norm(&p.name).contains("witness") { ArtifactValue::Bytes(vec![0x01]) } else { crate::sandbox::zero_value(&p.ty) });
    }
    let lead_redeem = encode_state(&sib.contract, &st)?;
    let mut lead_script = silverscript_abi::encode_contract_entry_sig_script(artifact, &sib.contract.contract_name, &leader.name, &args).ok()?;
    lead_script.extend(crate::sandbox::push_data(&lead_redeem).ok()?);
    let marker = vec![0xa5u8; 65];
    let fargs: Vec<ArtifactValue> = follower.params.iter().map(|_| ArtifactValue::Bytes(marker.clone())).collect();
    let mut f_script = silverscript_abi::encode_contract_entry_sig_script(artifact, &sib.contract.contract_name, &follower.name, &fargs).ok()?;
    let at = f_script.windows(65).position(|w| w == marker.as_slice())?;
    let f_redeem = encode_state(&sib.contract, &mine)?;
    f_script.extend(crate::sandbox::push_data(&f_redeem).ok()?);
    let id = Hash::from_bytes(sib.cov_id);
    let value = 100_000_000u64;
    let (pov_daa, block_time) = crate::baseline::pov(main);
    let mut plan = SpendPlan::simple(
        vec![
            InputSpec::Raw(RawInput {
                outpoint: None,
                signature_script: lead_script,
                sequence: 0,
                sig_op_count: 0,
                compute_budget: 2_000,
                entry: UtxoEntry::new(value, pay_to_script_hash_script(&lead_redeem), UTXO_DAA, false, Some(id)),
                target: false,
                signed: false,
                resign: None,
            }),
            InputSpec::Raw(RawInput {
                outpoint: None,
                signature_script: f_script,
                sequence: 0,
                sig_op_count: 1,
                compute_budget: 2_000,
                entry: UtxoEntry::new(value, pay_to_script_hash_script(&f_redeem), UTXO_DAA, false, Some(id)),
                target: false,
                signed: false,
                resign: Some(crate::sandbox::Resign { keypair: main.wallets.attacker.keypair, at }),
            }),
            InputSpec::P2pk { owner: KeyRef::Attacker, value: value },
        ],
        vec![
            OutputSpec { value, to: Dest::Raw(pay_to_script_hash_script(&encode_state(&sib.contract, &grown)?)), covenant: Some(CovenantBinding::new(0, id)), own: false },
            OutputSpec { value, to: Dest::Raw(pay_to_script_hash_script(&encode_state(&sib.contract, &left)?)), covenant: Some(CovenantBinding::new(0, id)), own: true },
            OutputSpec::new(value - BASE_FEE, Dest::Key(KeyRef::Attacker)),
        ],
        0,
        pov_daa,
        block_time,
    );
    plan.version = 1;
    Some(plan)
}

/// The borrowed receive of a token program, one path per enabled borrow
/// scheme (KCC-20 section 5): the coin leads a transfer on the borrow path
/// without its owner, a coin of the borrower's follows and adds one token unit.
/// Each comes with the hostile versions BOR-03 to BOR-07.
pub fn borrow_paths(c: &Contract, judge: &Judge) -> Vec<PathStatus> {
    if std::env::var_os("REDTEAM_DEBUG").is_some() {
        eprintln!("borrow paths for {}: state {}", c.file_name, c.initial_state.is_some());
    }
    let Some(init) = c.initial_state.clone() else { return vec![] };
    let (Some(sf), Some(gf)) = borrow_fields(&init) else { return vec![] };
    let Some(leader) = c.entries.iter().find(|e| {
        e.params.len() >= 2
            && matches!(e.params[0].ty, TypeArtifact::DynamicArray { .. } | TypeArtifact::FixedArray { .. })
            && e.params.iter().any(|p| norm(&p.name).contains("witness"))
    }) else {
        return vec![];
    };
    let Some(follower) = c.entries.iter().find(|e| {
        e.name != leader.name
            && !e.params.is_empty()
            && e.params.iter().all(|p| norm(&p.name).contains("witness"))
            && crate::tune::entry_body(&c.source, &e.name).is_some_and(|b| b.contains("!= this.activeInputIndex"))
    }) else {
        return vec![];
    };
    let mut cov_id = [0u8; 32];
    cov_id.copy_from_slice(crate::sandbox::sandbox_covenant_id().as_bytes().as_slice());
    let mut out = Vec::new();
    for (scheme, label) in [(1u8, "threshold"), (2, "key"), (3, "chain")] {
        let entry = format!("{}[borrow:{label}]", leader.name);
        let Some(b) = BorrowTx::new(c, cov_id, &init, &sf, &gf, scheme) else { continue };
        let honest = b.build(&leader.name, &follower.name, &Twist::None);
        let ok = honest.as_ref().is_some_and(|p| {
            let v = judge.run(c, p);
            if std::env::var_os("REDTEAM_DEBUG").is_some() {
                eprintln!("borrow {label}: {:?}", v.0);
                if let Some(b) = &v.1 {
                    if let Some(f) = (0..p.inputs.len()).find_map(|i| crate::sandbox::trace_failure(b, i)) {
                        eprintln!("  input {} {} a={} b={}", f.input, f.op, faster_hex::hex_string(&f.a), faster_hex::hex_string(&f.b));
                    }
                }
            }
            matches!(v.0, Verdict::Accepted { .. })
        });
        if !ok {
            out.push(PathStatus {
                entry: entry.clone(),
                name: entry.clone(),
                state: Some(b.state.clone()),
                baseline: None,
                unexplored_reason: Some("a borrowed receive (KCC-20 section 5) the tool built was refused; the program may not support this borrow scheme".into()),
                tries: 1,
                imported: false,
            });
            continue;
        }
        let mut variants = Vec::new();
        let tw: [(&'static str, Twist, &str, String); 5] = [
            ("BOR-03", Twist::TakeOwner, "the borrowed coin comes back owned by the borrower", format!("on a borrowed receive the coin came back owned by the borrower and the transaction was accepted. Anyone allowed to borrow takes the coin.")),
            ("BOR-04", Twist::NoIncrease, "the borrowed coin comes back with no more tokens", format!("on a borrowed receive the coin came back with the same token amount and the transaction was accepted. The borrow rule requires an increase; without it, anyone allowed to borrow moves the coin for free.")),
            ("BOR-05", Twist::LessKas, "the borrowed coin comes back with less KAS", format!("on a borrowed receive the coin came back with less KAS than it had and the borrower kept the difference, and the transaction was accepted.")),
            ("BOR-06", Twist::Unauthorized, "a borrow without the borrow key or link", format!("a borrowed receive was authorized by the wrong key or a wrong hash-chain link, and the transaction was accepted. Anyone can borrow a coin whose owner allowed only one borrower.")),
            ("BOR-07", Twist::Settings, "the borrowed coin comes back with other borrow settings", format!("on a borrowed receive the coin came back with its borrow scheme or guard changed, and the transaction was accepted. The borrower rewrites who may borrow next, or locks the owner out of their own settings.")),
        ];
        for (id, t, what, why) in tw {
            if matches!(t, Twist::Unauthorized) && scheme == 1 {
                continue; // anyone may borrow under the threshold scheme
            }
            if let Some(p) = b.build(&leader.name, &follower.name, &t) {
                variants.push((id, what.to_string(), p, why));
            }
        }
        out.push(PathStatus {
            entry: entry.clone(),
            name: entry.clone(),
            state: Some(b.state.clone()),
            baseline: Some(Baseline { plan: honest.unwrap(), signers: vec![], secrets: vec![], lock: None, variants }),
            unexplored_reason: None,
            tries: 1,
            imported: false,
        });
    }
    out
}

enum Twist {
    None,
    TakeOwner,
    NoIncrease,
    LessKas,
    Unauthorized,
    Settings,
}

struct BorrowTx<'a> {
    c: &'a Contract,
    cov_id: [u8; 32],
    state: StateValues,
    scheme: u8,
    sf: String,
    gf: String,
    /// Who borrows: the attacker for the threshold scheme (anyone may), an
    /// honest key the owner named for the key and chain schemes.
    borrower: secp256k1::Keypair,
    next_guard: Vec<u8>,
}

impl<'a> BorrowTx<'a> {
    fn new(c: &'a Contract, cov_id: [u8; 32], init: &StateValues, sf: &str, gf: &str, scheme: u8) -> Option<Self> {
        let borrower = match scheme {
            1 => c.wallets.attacker.keypair,
            2 => crate::wallets::Wallet::derive("borrower").keypair,
            _ => crate::wallets::Wallet::derive("borrow link").keypair,
        };
        let pk = borrower.x_only_public_key().0.serialize().to_vec();
        let next = vec![0x11u8; 32];
        let guard = match scheme {
            1 => vec![0u8; 32],
            2 => pk.clone(),
            _ => {
                let mut pre = next.clone();
                pre.extend(&pk);
                blake3::hash(&pre).as_bytes().to_vec()
            }
        };
        let mut state = init.clone();
        state.insert(sf.to_string(), ArtifactValue::Byte(scheme));
        state.insert(gf.to_string(), ArtifactValue::Bytes(guard.clone()));
        let next_guard = if scheme == 3 { next } else { guard };
        Some(Self { c, cov_id, state, scheme, sf: sf.to_string(), gf: gf.to_string(), borrower, next_guard })
    }

    fn build(&self, leader: &str, follower: &str, t: &Twist) -> Option<SpendPlan> {
        let c = self.c;
        let artifact = c.artifact.as_ref()?;
        let lead_entry = c.entry(leader)?;
        let attacker = c.wallets.attacker.xonly().to_vec();
        let bpk = self.borrower.x_only_public_key().0.serialize().to_vec();
        // The borrower's own coin: P2PK owner, borrowing off.
        let mut theirs = self.state.clone();
        for f in cov_fields(c) {
            theirs.insert(f, ArtifactValue::Bytes(bpk.clone()));
        }
        if let Some((sel, _)) = cov_branch(c) {
            let p2pk = source_consts(&c.source)
                .into_iter()
                .find(|(n, _)| n.contains("P2PK") && !n.contains("P2PKH"))
                .map(|(_, v)| v)
                .unwrap_or(ArtifactValue::Byte(0));
            theirs.insert(sel, p2pk);
        }
        theirs.insert(self.sf.clone(), ArtifactValue::Byte(0));
        theirs.insert(self.gf.clone(), ArtifactValue::Bytes(vec![0; 32]));
        let amount = match self.state.get("amount") {
            Some(ArtifactValue::Int(a)) => *a,
            _ => return None,
        };
        let add: i64 = 1;
        theirs.insert("amount".into(), ArtifactValue::Int(100_000_000));
        let mut grown = self.state.clone();
        grown.insert("amount".into(), ArtifactValue::Int(amount + add));
        grown.insert(self.gf.clone(), ArtifactValue::Bytes(self.next_guard.clone()));
        let mut left = theirs.clone();
        left.insert("amount".into(), ArtifactValue::Int(100_000_000 - add));
        match t {
            Twist::TakeOwner => {
                for f in cov_fields(c) {
                    grown.insert(f, ArtifactValue::Bytes(attacker.clone()));
                }
            }
            Twist::NoIncrease => {
                grown.insert("amount".into(), ArtifactValue::Int(amount));
                left.insert("amount".into(), ArtifactValue::Int(100_000_000));
            }
            Twist::Settings => {
                grown.insert(self.sf.clone(), ArtifactValue::Byte(if self.scheme == 1 { 2 } else { 1 }));
                grown.insert(self.gf.clone(), ArtifactValue::Bytes(attacker.clone()));
            }
            _ => {}
        }
        let (TypeArtifact::DynamicArray { item } | TypeArtifact::FixedArray { item, .. }) = &lead_entry.params.first()?.ty else { return None };
        let TypeArtifact::Struct { name } = item.as_ref() else { return None };
        let fields = c.struct_fields(name)?;
        // The borrow witness: path byte 1, then what the scheme asks for.
        let marker = vec![0xa5u8; 65];
        let mut witness = vec![0x01];
        match self.scheme {
            2 => witness.extend(&marker),
            3 => {
                let wrong = matches!(t, Twist::Unauthorized);
                witness.extend(if wrong { vec![0x22; 32] } else { self.next_guard.clone() });
                witness.extend(&bpk);
                witness.extend(&marker);
            }
            _ => {}
        }
        let mut args = vec![ArtifactValue::Array(vec![struct_obj(&fields, &grown), struct_obj(&fields, &left)])];
        for p in lead_entry.params.iter().skip(1) {
            args.push(if norm(&p.name).contains("witness") { ArtifactValue::Bytes(witness.clone()) } else { crate::sandbox::zero_value(&p.ty) });
        }
        let lead_redeem = encode_state(c, &self.state)?;
        let mut lead_script = silverscript_abi::encode_contract_entry_sig_script(artifact, &c.contract_name, leader, &args).ok()?;
        let lead_sig = lead_script.windows(65).position(|w| w == marker.as_slice());
        lead_script.extend(crate::sandbox::push_data(&lead_redeem).ok()?);
        let lead_key = if matches!(t, Twist::Unauthorized) { c.wallets.attacker.keypair } else { self.borrower };
        let f_entry = c.entry(follower)?;
        let fargs: Vec<ArtifactValue> = f_entry.params.iter().map(|_| ArtifactValue::Bytes(marker.clone())).collect();
        let mut f_script = silverscript_abi::encode_contract_entry_sig_script(artifact, &c.contract_name, follower, &fargs).ok()?;
        let at = f_script.windows(65).position(|w| w == marker.as_slice())?;
        let f_redeem = encode_state(c, &theirs)?;
        f_script.extend(crate::sandbox::push_data(&f_redeem).ok()?);
        let id = Hash::from_bytes(self.cov_id);
        let value = 100_000_000u64;
        let kept = if matches!(t, Twist::LessKas) { value / 2 } else { value };
        let (pov_daa, block_time) = crate::baseline::pov(c);
        let mut plan = SpendPlan::simple(
            vec![
                InputSpec::Raw(RawInput {
                    outpoint: None,
                    signature_script: lead_script,
                    sequence: 0,
                    sig_op_count: if lead_sig.is_some() { 1 } else { 0 },
                    compute_budget: 2_000,
                    entry: UtxoEntry::new(value, pay_to_script_hash_script(&lead_redeem), UTXO_DAA, false, Some(id)),
                    target: true,
                    signed: false,
                    resign: lead_sig.map(|at| crate::sandbox::Resign { keypair: lead_key, at }),
                }),
                InputSpec::Raw(RawInput {
                    outpoint: None,
                    signature_script: f_script,
                    sequence: 0,
                    sig_op_count: 1,
                    compute_budget: 2_000,
                    entry: UtxoEntry::new(value, pay_to_script_hash_script(&f_redeem), UTXO_DAA, false, Some(id)),
                    target: false,
                    signed: false,
                    resign: Some(crate::sandbox::Resign { keypair: self.borrower, at }),
                }),
                InputSpec::P2pk { owner: KeyRef::Attacker, value },
            ],
            vec![
                OutputSpec { value: kept, to: Dest::Raw(pay_to_script_hash_script(&encode_state(c, &grown)?)), covenant: Some(CovenantBinding::new(0, id)), own: false },
                OutputSpec { value, to: Dest::Raw(pay_to_script_hash_script(&encode_state(c, &left)?)), covenant: Some(CovenantBinding::new(0, id)), own: true },
                OutputSpec::new(value + (value - kept) - BASE_FEE, Dest::Key(KeyRef::Attacker)),
            ],
            0,
            pov_daa,
            block_time,
        );
        plan.version = 1;
        Some(plan)
    }
}

/// The coin spent alongside is owned by a script hash (its owner scheme is the
/// program's P2SH constant).
fn p2sh_owned(sib: &Program, d: &Draft) -> bool {
    let Some(st) = &d.sib_state else { return false };
    let Some((sel, _)) = cov_branch(&sib.contract) else { return false };
    let consts = source_consts(&sib.contract.source);
    consts.iter().any(|(n, v)| n.contains("P2SH") && st.get(&sel) == Some(v))
}

/// A check on raw bytes of the coin spent alongside (`tin.slice(43, 46) ==
/// 0x040100`, read by hand rather than by field): when the compared bytes
/// occur once in that coin's encoded state, they are replaced there and the
/// state is read back. Tried only when no other repair applies.
fn slice_fix(d: &mut Draft, f: &FailedCheck, sib: &Program) -> bool {
    if !matches!(f.op.as_str(), "OpEqual" | "OpEqualVerify") || f.a.len() != f.b.len() || f.a.is_empty() || f.a == f.b {
        return false;
    }
    let Some(st) = d.sib_state.clone() else { return false };
    let Some(redeem) = encode_state(&sib.contract, &st) else { return false };
    let Some((pre, suf)) = template_parts(&sib.contract) else { return false };
    if redeem.len() < pre.len() + suf.len() {
        return false;
    }
    let body = &redeem[pre.len()..redeem.len() - suf.len()];
    for (from, to) in [(&f.a, &f.b), (&f.b, &f.a)] {
        let hits: Vec<usize> = body.windows(from.len()).enumerate().filter(|(_, w)| *w == from.as_slice()).map(|(i, _)| i).collect();
        if hits.len() != 1 {
            continue;
        }
        let mut nb = body.to_vec();
        nb[hits[0]..hits[0] + to.len()].copy_from_slice(to);
        let mut full = pre.clone();
        full.extend(&nb);
        full.extend(&suf);
        if let Some(new) = decode_state(&sib.contract, &full) {
            let frozen = &d.frozen;
            if new.iter().any(|(k, v)| frozen.contains(k) && st.get(k) != Some(v)) {
                continue;
            }
            d.sib_state = Some(new);
            return true;
        }
    }
    false
}
