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
    c.state_fields
        .iter()
        .filter(|(name, ty)| {
            matches!(ty, TypeArtifact::FixedBytes { len: 32 })
                && c.source.lines().any(|l| {
                    l.contains("OpCov")
                        && (l.contains(&format!("(prev_state.{name}")) || l.contains(&format!("({name})")) || l.contains(&format!("({name},")))
                })
        })
        .map(|(n, _)| n.clone())
        .collect()
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
    if let Some((k, want)) = matches.pop() {
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
        let binding = out.covenant;
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
                for (k, r) in &d.redeems {
                    if *k == 0 {
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
            ty => crate::sandbox::zero_value(ty),
        });
    }
    Some(out)
}

fn rebuild_sibling(d: &mut Draft, sib: &Program, sib_state: &StateValues) -> Option<()> {
    let artifact = sib.contract.artifact.as_ref()?;
    let mut s =
        silverscript_abi::encode_contract_entry_sig_script(artifact, &sib.contract.contract_name, &d.sib_entry, &d.sib_args).ok()?;
    let redeem = encode_state(&sib.contract, sib_state)?;
    s.extend(crate::sandbox::push_data(&redeem).ok()?);
    if let InputSpec::Raw(r) = &mut d.plan.inputs[d.sib] {
        r.signature_script = s;
    }
    Some(())
}

/// Tries to spend `entry` of `main` together with a coin of another program of
/// the project, creating coins of a third. Returns the accepted spend.
pub fn explore(main: &Contract, entry: &str, programs: &[Program], judge: &Judge) -> Option<(PathStatus, Vec<String>)> {
    let body = crate::tune::entry_body(&main.source, entry)?;
    let main_cov = cov_fields(main);
    let init = main.initial_state.clone()?;
    if main_cov.is_empty() || !main_cov.iter().any(|f| body.contains(f.as_str())) {
        return None;
    }
    let (pov_daa, block_time) = crate::baseline::pov(main);
    let main_id = crate::sandbox::sandbox_covenant_id();
    for sib in programs.iter().filter(|p| p.contract.is_stateful() && !cov_fields(&p.contract).is_empty()) {
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
        let sib_redeem = encode_state(&sib.contract, &sib_state)?;
        let sib_spk = pay_to_script_hash_script(&sib_redeem);
        // The coin under test drives (it carries the proof or the data); the
        // other program only takes part: its entry needs nothing but states
        // and template parts the tool can fill.
        let passive = |e: &&crate::contract::Entry| {
            !e.params.is_empty()
                && e.params.iter().all(|p| {
                    let n = norm(&p.name);
                    !matches!(p.ty, TypeArtifact::Bytes) || n.contains("prefix") || n.contains("suffix")
                })
        };
        for sib_entry in sib.contract.entries.iter().filter(passive) {
            // The main entry's arguments.
            let me = main.entry(entry)?;
            // Whoever the data pays: an honest party, never the attacker.
            let owner = match main.wallets.parties.first() {
                Some(w) => w.xonly().to_vec(),
                None => {
                    let mut w = crate::wallets::Wallets::new();
                    let i = w.party("depositor");
                    w.parties[i].xonly().to_vec()
                }
            };
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
            for p in &me.params {
                let n = norm(&p.name);
                args.push(ArgRecipe::Value(if n.contains("proof") || n.contains("seal") {
                    ArtifactValue::Bytes(crate::zk::test_proof())
                } else if n.contains("journal") {
                    ArtifactValue::Bytes(journal_with_record(body, &main.source, &p.name, &bytes_of, &int_of, &owner)?)
                } else if n.contains("prefix") || n.contains("suffix") {
                    let core = n.replace("prefix", "").replace("suffix", "").replace("gen", "");
                    let prog = programs.iter().find(|pr| norm(&pr.contract.contract_name) == core)?;
                    let (pre, suf) = template_parts(&prog.contract)?;
                    ArtifactValue::Bytes(if n.contains("prefix") { pre } else { suf })
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
            plan.version = 1;
            let mut d = Draft { plan, sib: 1, sib_entry: sib_entry.name.clone(), sib_args: vec![], redeems: BTreeMap::new(), repaired: Default::default() };
            let mut notes = Vec::new();
            for _ in 0..24 {
                d.sib_args = sibling_args(sib, &sib_entry.name, programs, &d)?;
                rebuild_sibling(&mut d, sib, &sib_state)?;
                let (verdict, built) = judge.run(main, &d.plan);
                if let Verdict::Accepted { .. } = verdict {
                    notes.push(format!(
                        "family: `{entry}` was spent together with a coin of {} (`{}`), each with its own covenant id; outputs it authorizes belong to its family. The tool learned the scripts of the outputs from the programs' own checks.",
                        sib.file, sib_entry.name
                    ));
                    notes.push(format!("family-member: {}|{}|{}|{entry}+{}", sib.file, sib_entry.name, main.file_name, sib_entry.name));
                    // The coins this spend created, for the next step: spending them.
                    for (k, r) in d.redeems.iter().filter(|(k, _)| **k >= 2) {
                        if let Some(p) = programs.iter().find(|p| decode_state(&p.contract, r).is_some()) {
                            notes.push(format!("minted: {}|{}|{entry}+{}|{k}", p.file, faster_hex::hex_string(r), sib_entry.name));
                        }
                    }
                    let status = PathStatus {
                        entry: format!("{entry}+{}", sib_entry.name),
                        name: entry.to_string(),
                        state: Some(state.clone()),
                        baseline: Some(Baseline {
                            variants: variants(main, &d, sib, &sib_state, programs, judge),
                            plan: d.plan,
                            signers: vec![],
                            secrets: vec!["the tool's test proof".into()],
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
                if !repair(&mut d, &built, &f, main) {
                    break;
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
    let cells: Vec<usize> = d.redeems.keys().copied().filter(|k| *k >= 2).collect();
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
        v.plan.outputs[k].covenant = Some(CovenantBinding::new(0, crate::sandbox::sandbox_covenant_id()));
        if let Some(p) = finish(v) {
            out.push(("FAM-04", format!("output {k} in the wrong covenant family"), p,
                format!("the new coin at output {k} was created under a different covenant id than the token's family, and the transaction was accepted. Counterfeit coins with the right program and the wrong family can exist next to real ones.")));
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
    out
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
            } else {
                crate::sandbox::zero_value(&p.ty)
            }));
        }
        let value = crate::sandbox::COVENANT_VALUE;
        let new_value = 100_000_000u64;
        let mut plan = SpendPlan::simple(
            vec![
                InputSpec::Covenant { entry: entry.to_string(), args, value, sequence: 0, state: Some(state.clone()) },
                InputSpec::P2pk { owner: KeyRef::Attacker, value: new_value },
            ],
            vec![
                OutputSpec::new(value - BASE_FEE, Dest::Successor(state.clone())),
                OutputSpec { value: new_value, to: Dest::Raw(pay_to_script_hash_script(&redeem)), covenant: None, own: true },
            ],
            0,
            pov_daa,
            block_time,
        );
        plan.version = 1;
        plan.genesis = vec![(1, vec![1])];
        let mut d = Draft { plan, sib: usize::MAX, sib_entry: String::new(), sib_args: vec![], redeems: BTreeMap::new(), repaired: Default::default() };
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
        if !(l.contains("OpCovInputCount(") && cov_fields(c).iter().any(|f| l.contains(&format!("({f})")))) {
            continue;
        }
        for back in lines[..i].iter().rev().take(4) {
            let b = back.trim();
            if let Some(at) = b.find("if") {
                let cond = &b[at..];
                let cond = cond.trim_start_matches("if").trim().trim_start_matches('(');
                if let Some((lhs, rhs)) = cond.split_once("==") {
                    let lhs = lhs.trim().to_string();
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
            let mut d = Draft { plan, sib: 1, sib_entry: sib_entry.name.clone(), sib_args: vec![], redeems: redeems.clone(), repaired: Default::default() };
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
