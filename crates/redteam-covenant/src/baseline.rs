//! Honest-spend search. Before anything is attacked, the engine finds, for
//! each spend path, one transaction the covenant accepts: who signs, what
//! arguments, where the money goes, which lock values, which state comes next.
//! Attacks then mutate that baseline. A path with no baseline is reported as
//! unexplored, never as safe.
//!
//! Stateful covenants are explored breadth-first: every successor state an
//! accepted spend produces becomes a new starting state, so paths that only
//! open later (`claim` after `approve`) get their own baselines.

use crate::contract::Contract;
use crate::sandbox::{
    ArgRecipe, BASE_FEE, COVENANT_VALUE, Dest, InputSpec, Judge, OutputSpec, STAND_IN_VALUE, SpendPlan, StateValues,
    UTXO_DAA,
};
use crate::script::{self, Token};
use crate::wallets::KeyRef;
use kaspa_consensus_core::constants::LOCK_TIME_THRESHOLD;
use rayon::prelude::*;
use serde::Serialize;
use silverscript_abi::{ArtifactValue, TypeArtifact};

const MAX_TRIES_PER_PATH: usize = 25_000;
const MAX_ARG_COMBOS: usize = 256;
const MAX_STATES: usize = 4;
const MAX_SUCCESSORS: usize = 12;

#[derive(Debug, Clone, Serialize)]
pub struct LockInfo {
    /// "lock_time" (absolute, CLTV) or "sequence" (relative, CSV).
    pub field: &'static str,
    pub used: u64,
    /// Smallest value consensus accepted, found by bisection.
    pub earliest: u64,
}

#[derive(Debug, Clone)]
pub struct Baseline {
    pub plan: SpendPlan,
    pub signers: Vec<KeyRef>,
    /// Labels of secrets or signed readings the spend reveals.
    pub secrets: Vec<String>,
    pub lock: Option<LockInfo>,
}

impl Baseline {
    /// No transaction signature is needed: anyone (or anyone who has seen the
    /// revealed secret or reading) can build this spend.
    pub fn permissionless(&self) -> bool {
        self.signers.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct PathStatus {
    /// Display id: the entry name, plus `@state` for non-initial states.
    pub entry: String,
    /// The entry point name alone.
    pub name: String,
    pub state: Option<StateValues>,
    pub baseline: Option<Baseline>,
    pub unexplored_reason: Option<String>,
    pub tries: usize,
    /// Came from an imported baseline file rather than the search.
    pub imported: bool,
}

#[derive(Clone, Copy)]
struct Timing {
    lock_time: u64,
    sequence: u64,
}

pub fn pov(contract: &Contract) -> (u64, u64) {
    let max_daa_lock = contract.cltv_values.iter().copied().filter(|v| *v < LOCK_TIME_THRESHOLD).max().unwrap_or(0);
    let max_time_lock = contract.cltv_values.iter().copied().filter(|v| *v >= LOCK_TIME_THRESHOLD).max().unwrap_or(0);
    let max_csv = contract.csv_values.iter().copied().max().unwrap_or(0);
    let pov_daa = (10_000_000u64).max(max_daa_lock + 1).max(UTXO_DAA + max_csv + 1).min(LOCK_TIME_THRESHOLD - 1);
    let block_time = (4_000_000_000_000u64).max(max_time_lock + 1);
    (pov_daa, block_time)
}

/// Short label for a state, naming only the fields that differ from the start.
pub fn state_label(c: &Contract, s: &StateValues) -> String {
    let init = c.initial_state.as_ref();
    let parts: Vec<String> = s
        .iter()
        .filter(|(k, v)| init.and_then(|i| i.get(*k)) != Some(v))
        .map(|(k, v)| format!("{k}={}", value_label(v)))
        .collect();
    if parts.is_empty() { "start".into() } else { parts.join(",") }
}

fn value_label(v: &ArtifactValue) -> String {
    match v {
        ArtifactValue::Int(n) => n.to_string(),
        ArtifactValue::Bool(b) => b.to_string(),
        ArtifactValue::Byte(b) => format!("0x{b:02x}"),
        ArtifactValue::Bytes(b) if b.len() > 6 => format!("0x{}..", faster_hex::hex_string(&b[..4])),
        ArtifactValue::Bytes(b) => format!("0x{}", faster_hex::hex_string(b)),
        ArtifactValue::Text(t) => format!("{t:?}"),
        other => format!("{other:?}"),
    }
}

pub fn search_all(contract: &Contract, judge: &Judge) -> Vec<PathStatus> {
    let mut out = Vec::new();
    let mut states: Vec<Option<StateValues>> = vec![None];
    let mut i = 0;
    while i < states.len() && i < MAX_STATES {
        let st = states[i].clone();
        let level: Vec<PathStatus> =
            contract.entries.par_iter().map(|e| search_path(contract, judge, &e.name, st.as_ref())).collect();
        for ps in &level {
            if let Some(b) = &ps.baseline {
                for o in &b.plan.outputs {
                    if let Dest::Successor(s) = &o.to {
                        let canon = if Some(s) == contract.initial_state.as_ref() { None } else { Some(s.clone()) };
                        if !states.contains(&canon) {
                            states.push(canon);
                        }
                    }
                }
            }
        }
        out.extend(level);
        i += 1;
    }
    out
}

pub fn search_path(contract: &Contract, judge: &Judge, entry_name: &str, state: Option<&StateValues>) -> PathStatus {
    let entry = contract.entry(entry_name).expect("entry exists");
    let id = match state {
        None => entry_name.to_string(),
        Some(s) => format!("{entry_name}@{}", state_label(contract, s)),
    };
    let mut status = PathStatus {
        entry: id,
        name: entry_name.into(),
        state: state.cloned(),
        baseline: None,
        unexplored_reason: None,
        tries: 0,
        imported: false,
    };

    // Candidate values for each parameter.
    let msg_arg = entry.params.iter().position(|p| matches!(p.ty, TypeArtifact::Bytes));
    let has_datasig = entry.params.iter().any(|p| matches!(p.ty, TypeArtifact::Datasig));
    let mut per_param: Vec<Vec<(ArgRecipe, Option<String>)>> = Vec::new();
    for p in &entry.params {
        match candidates(contract, &p.name, &p.ty, has_datasig, msg_arg) {
            Ok(c) => per_param.push(c),
            Err(why) => {
                status.unexplored_reason = Some(format!("parameter `{}`: {why}", p.name));
                return status;
            }
        }
    }
    let combos = ranked_cartesian(&per_param, MAX_ARG_COMBOS);
    let (pov_daa, block_time) = pov(contract);
    let timings = timings(contract, pov_daa, block_time);

    // Input layouts: alone, or next to a stand-in coin the covenant names.
    let mut layouts: Vec<(Vec<InputSpec>, usize)> = vec![(vec![], 0)];
    for k in 0..contract.stand_ins.len().min(2) {
        layouts.push((vec![InputSpec::StandIn { target: k, value: STAND_IN_VALUE }], 0));
        layouts.push((vec![InputSpec::StandIn { target: k, value: STAND_IN_VALUE }], 1));
    }

    // Coin sizes: the default, then "exactly an amount plus a small fee",
    // for covenants that only accept a precisely funded deposit.
    let mut coin_values = vec![COVENANT_VALUE];
    for a in contract.ctor_ints.iter().filter(|a| **a >= 1_000_000 && (**a as u64) < COVENANT_VALUE) {
        let v = *a as u64 + BASE_FEE;
        if coin_values.len() < 3 && !coin_values.contains(&v) {
            coin_values.push(v);
        }
    }
    let mut runs: Vec<(u64, &Vec<InputSpec>, usize)> = Vec::new();
    for cv in &coin_values {
        for (extra, pos) in &layouts {
            runs.push((*cv, extra, *pos));
        }
    }

    // Shapes per run (coin size x input layout), computed once.
    let prepared: Vec<(u64, &Vec<InputSpec>, usize, Vec<Vec<OutputSpec>>)> = runs
        .into_iter()
        .map(|(cv, extra, pos)| {
            let extra_value: u64 = extra.iter().map(|i| i.value()).sum();
            (cv, extra, pos, output_candidates(contract, cv, extra_value, state))
        })
        .collect();

    // Arguments outermost (best-ranked first), then coin size and layout, then
    // output shapes, then lock values.
    for (args, secrets) in &combos {
        for (cov_value, extra, cov_pos, shapes) in &prepared {
            for outs in shapes {
                for t in &timings {
                    if status.tries >= MAX_TRIES_PER_PATH {
                        status.unexplored_reason = Some(format!(
                            "no accepted spend in {MAX_TRIES_PER_PATH} tries; pass --arg values or import a baseline (--baseline)"
                        ));
                        return status;
                    }
                    status.tries += 1;
                    let cov = InputSpec::Covenant {
                        entry: entry_name.into(),
                        args: args.clone(),
                        value: *cov_value,
                        sequence: t.sequence,
                        state: state.cloned(),
                    };
                    let mut inputs = (*extra).clone();
                    inputs.insert(*cov_pos, cov);
                    let plan = SpendPlan::simple(inputs, outs.clone(), t.lock_time, pov_daa, block_time);
                    if judge.run(contract, &plan).0.accepted() {
                        let lock = if t.lock_time > 0 {
                            Some(bisect_lock(contract, judge, &plan, "lock_time", t.lock_time))
                        } else if t.sequence > 0 {
                            Some(bisect_lock(contract, judge, &plan, "sequence", t.sequence))
                        } else {
                            None
                        };
                        let signers = plan.signers();
                        status.baseline = Some(Baseline { plan, signers, secrets: secrets.clone(), lock });
                        return status;
                    }
                }
            }
        }
    }
    status.unexplored_reason = Some(format!(
        "no accepted spend among {} candidates (signers x arguments x outputs x locks); pass --arg values or import a baseline (--baseline)",
        status.tries
    ));
    status
}

fn timings(c: &Contract, pov_daa: u64, block_time: u64) -> Vec<Timing> {
    let mut v = vec![Timing { lock_time: 0, sequence: 0 }];
    for x in &c.cltv_values {
        v.push(Timing { lock_time: *x, sequence: 0 });
    }
    for x in &c.csv_values {
        v.push(Timing { lock_time: 0, sequence: *x });
    }
    if let (Some(l), Some(s)) = (c.cltv_values.last(), c.csv_values.last()) {
        v.push(Timing { lock_time: *l, sequence: *s });
    }
    // Locks computed at run time (`tx.time >= start + period * n`) push no
    // usable constant: try "as late as possible" in both domains.
    let toks = script::tokenize(&c.bytecode);
    if toks.iter().any(|t| matches!(t, Token::Op(0xb0))) {
        v.push(Timing { lock_time: block_time - 1, sequence: 0 });
        v.push(Timing { lock_time: pov_daa - 1, sequence: 0 });
    }
    let mut seen = std::collections::HashSet::new();
    v.retain(|t| seen.insert((t.lock_time, t.sequence)));
    v
}

fn bisect_lock(contract: &Contract, judge: &Judge, plan: &SpendPlan, field: &'static str, used: u64) -> LockInfo {
    let target = plan.first_target().unwrap_or(0);
    let set = |p: &mut SpendPlan, v: u64| {
        if field == "lock_time" {
            p.lock_time = v;
        } else if let InputSpec::Covenant { sequence, .. } = &mut p.inputs[target] {
            *sequence = v;
        }
    };
    // Same lock-time domain as `used` (DAA score vs milliseconds).
    let mut lo = if field == "lock_time" && used >= LOCK_TIME_THRESHOLD { LOCK_TIME_THRESHOLD } else { 1 };
    let mut hi = used;
    let accepts = |v: u64| {
        let mut p = plan.clone();
        set(&mut p, v);
        judge.run(contract, &p).0.accepted()
    };
    if accepts(lo) {
        return LockInfo { field, used, earliest: lo };
    }
    while lo + 1 < hi {
        let mid = lo + (hi - lo) / 2;
        if accepts(mid) { hi = mid } else { lo = mid }
    }
    LockInfo { field, used, earliest: hi }
}

fn mentions(line: &str, name: &str) -> bool {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    line.match_indices(name).any(|(i, _)| {
        line[..i].chars().next_back().is_none_or(|c| !is_ident(c))
            && line[i + name.len()..].chars().next().is_none_or(|c| !is_ident(c))
    })
}

/// Signature parameters are usually named after their signer (`ownerSig`,
/// `advSig`, `modSig`): try the best-matching party first.
fn name_affinity(param: &str, party: &str) -> usize {
    let p = param.to_ascii_lowercase().replace("sig", "");
    let q = party.to_ascii_lowercase();
    p.chars().zip(q.chars()).take_while(|(a, b)| a == b).count()
}

fn parties_by_affinity(c: &Contract, param: &str) -> Vec<KeyRef> {
    // Strongest signal: the source checks this parameter against a named key,
    // e.g. `checkSig(paySig, payout)` or `checkMsgSig(s, ..., conductor)`.
    let checked_with: Vec<&str> = c
        .source
        .lines()
        .filter(|l| (l.contains("checkSig") || l.contains("checkMsgSig")) && mentions(l, param))
        .collect();
    let mut v: Vec<(usize, usize)> = c
        .wallets
        .parties
        .iter()
        .enumerate()
        .map(|(i, w)| {
            let named = checked_with.iter().any(|l| mentions(l, &w.label));
            (i, if named { 1000 } else { name_affinity(param, &w.label) })
        })
        .collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v.into_iter().map(|(i, _)| KeyRef::Party(i)).collect()
}

fn candidates(
    c: &Contract,
    param: &str,
    ty: &TypeArtifact,
    has_datasig: bool,
    msg_arg: Option<usize>,
) -> Result<Vec<(ArgRecipe, Option<String>)>, String> {
    let v = |a: ArtifactValue| (ArgRecipe::Value(a), None);
    let parties = parties_by_affinity(c, param);
    Ok(match ty {
        TypeArtifact::Sig => {
            if parties.is_empty() {
                vec![(ArgRecipe::Sig(KeyRef::Attacker), None)]
            } else {
                parties.iter().map(|k| (ArgRecipe::Sig(*k), None)).collect()
            }
        }
        TypeArtifact::Datasig => {
            let Some(arg) = msg_arg else {
                return Err("data signature with no byte[] message argument to sign".into());
            };
            if c.msg_candidates.is_empty() {
                return Err("data signature, but no message shape could be read from the script".into());
            }
            let keys = if parties.is_empty() { vec![KeyRef::Attacker] } else { parties };
            keys.iter()
                .map(|k| {
                    (
                        ArgRecipe::DataSigOf { key: *k, arg, hash: c.msg_hash },
                        Some(format!("reading signed by {}", c.wallets.label(*k))),
                    )
                })
                .collect()
        }
        TypeArtifact::Pubkey => {
            let mut out: Vec<_> =
                parties.iter().map(|k| v(ArtifactValue::Bytes(c.wallets.get(*k).xonly().to_vec()))).collect();
            if out.is_empty() {
                out.push(v(ArtifactValue::Bytes(c.wallets.attacker.xonly().to_vec())));
            }
            out
        }
        TypeArtifact::Int | TypeArtifact::Temporal => {
            // Small counters first (an index or `upto`), then constructor
            // values, then constants the script compares against.
            let mut ints: Vec<i64> = vec![1, 0];
            ints.extend(c.ctor_ints.iter().copied());
            ints.push(2);
            ints.extend(c.pushed_ints.iter().filter(|n| **n < 1_000_000_000_000).map(|n| *n as i64));
            ints.push((COVENANT_VALUE / 2) as i64);
            let mut seen = std::collections::HashSet::new();
            ints.retain(|x| seen.insert(*x));
            ints.into_iter().take(10).map(|n| v(ArtifactValue::Int(n))).collect()
        }
        TypeArtifact::Bool => vec![v(ArtifactValue::Bool(true)), v(ArtifactValue::Bool(false))],
        TypeArtifact::Byte => vec![v(ArtifactValue::Byte(0)), v(ArtifactValue::Byte(1))],
        TypeArtifact::Bytes => {
            let mut out: Vec<_> = Vec::new();
            if has_datasig {
                out.extend(c.msg_candidates.iter().map(|m| v(ArtifactValue::Bytes(m.clone()))));
            }
            out.extend(
                c.secrets
                    .iter()
                    .map(|s| (ArgRecipe::Value(ArtifactValue::Bytes(s.preimage.clone())), Some(s.label.clone()))),
            );
            out.push(v(ArtifactValue::Bytes(vec![0x11; 20])));
            out.push(v(ArtifactValue::Bytes(vec![])));
            out
        }
        TypeArtifact::FixedBytes { len } => {
            let mut out: Vec<_> = c
                .secrets
                .iter()
                .filter(|s| s.preimage.len() == *len)
                .map(|s| (ArgRecipe::Value(ArtifactValue::Bytes(s.preimage.clone())), Some(s.label.clone())))
                .collect();
            if *len == 32 {
                out.extend(c.wallets.parties.iter().map(|w| v(ArtifactValue::Bytes(w.xonly().to_vec()))));
            }
            out.push(v(ArtifactValue::Bytes(vec![0u8; *len])));
            out
        }
        TypeArtifact::Text => {
            let mut out: Vec<_> = c
                .secrets
                .iter()
                .filter_map(|s| {
                    String::from_utf8(s.preimage.clone())
                        .ok()
                        .map(|t| (ArgRecipe::Value(ArtifactValue::Text(t)), Some(s.label.clone())))
                })
                .collect();
            out.push(v(ArtifactValue::Text("redteam".into())));
            out
        }
        TypeArtifact::FixedArray { .. } | TypeArtifact::DynamicArray { .. } => {
            return Err("array arguments are not searched yet; import a baseline (--baseline)".into());
        }
        TypeArtifact::Struct { name } => {
            return Err(format!("struct `{name}` arguments are not searched yet; import a baseline (--baseline)"));
        }
    })
}

/// Cartesian product ordered by total rank: every parameter's best candidate
/// first, then combinations one step away, and so on.
fn ranked_cartesian(per_param: &[Vec<(ArgRecipe, Option<String>)>], cap: usize) -> Vec<(Vec<ArgRecipe>, Vec<String>)> {
    if per_param.is_empty() {
        return vec![(vec![], vec![])];
    }
    let max_total: usize = per_param.iter().map(|p| p.len().saturating_sub(1)).sum();
    let mut out = Vec::new();
    let mut idx = vec![0usize; per_param.len()];
    fn rec(
        per: &[Vec<(ArgRecipe, Option<String>)>],
        k: usize,
        left: usize,
        idx: &mut Vec<usize>,
        out: &mut Vec<(Vec<ArgRecipe>, Vec<String>)>,
        cap: usize,
    ) {
        if out.len() >= cap {
            return;
        }
        if k == per.len() - 1 {
            if left < per[k].len() {
                idx[k] = left;
                let args = idx.iter().enumerate().map(|(i, j)| per[i][*j].0.clone()).collect();
                let secrets = idx.iter().enumerate().filter_map(|(i, j)| per[i][*j].1.clone()).collect();
                out.push((args, secrets));
            }
            return;
        }
        for j in 0..per[k].len().min(left + 1) {
            idx[k] = j;
            rec(per, k + 1, left - j, idx, out, cap);
        }
    }
    for total in 0..=max_total {
        rec(per_param, 0, total, &mut idx, &mut out, cap);
        if out.len() >= cap {
            break;
        }
    }
    out
}

/// Successor states one or two field changes away from `from`, fewest changes first.
fn successors(c: &Contract, from: &StateValues) -> Vec<StateValues> {
    let mut alts: Vec<(String, Vec<ArtifactValue>)> = Vec::new();
    for (name, ty) in &c.state_fields {
        let cur = from.get(name).cloned();
        let mut vals: Vec<ArtifactValue> = Vec::new();
        match (ty, &cur) {
            (TypeArtifact::Bool, Some(ArtifactValue::Bool(b))) => vals.push(ArtifactValue::Bool(!b)),
            (TypeArtifact::Int | TypeArtifact::Temporal, Some(ArtifactValue::Int(n))) => {
                let mut ints = vec![n + 1, 1, 0, n - 1, 2];
                ints.extend(c.ctor_ints.iter().copied().take(3));
                for x in ints {
                    if x != *n && !vals.contains(&ArtifactValue::Int(x)) {
                        vals.push(ArtifactValue::Int(x));
                    }
                }
                vals.truncate(5);
            }
            (TypeArtifact::FixedBytes { len }, Some(ArtifactValue::Bytes(b))) => {
                let zero = vec![0u8; *len];
                if *b != zero {
                    vals.push(ArtifactValue::Bytes(zero));
                }
                if *len == 32 {
                    for w in c.wallets.parties.iter().take(2) {
                        vals.push(ArtifactValue::Bytes(w.xonly().to_vec()));
                    }
                }
            }
            _ => {}
        }
        alts.push((name.clone(), vals));
    }
    let mut out = vec![from.clone()];
    for (name, vals) in &alts {
        for v in vals {
            let mut s = from.clone();
            s.insert(name.clone(), v.clone());
            out.push(s);
        }
    }
    'pairs: for (i, (n1, v1s)) in alts.iter().enumerate() {
        for (n2, v2s) in alts.iter().skip(i + 1) {
            for a in v1s.iter().take(2) {
                for b in v2s.iter().take(2) {
                    if out.len() >= MAX_SUCCESSORS {
                        break 'pairs;
                    }
                    let mut s = from.clone();
                    s.insert(n1.clone(), a.clone());
                    s.insert(n2.clone(), b.clone());
                    out.push(s);
                }
            }
        }
    }
    out.truncate(MAX_SUCCESSORS);
    out
}

/// Output shapes an honest spend might take, most common first.
fn output_candidates(
    c: &Contract,
    cov_value: u64,
    extra_value: u64,
    state: Option<&StateValues>,
) -> Vec<Vec<OutputSpec>> {
    // Fee candidates: the default, then small constants the script pushes
    // (a hard-coded `minerFee = 1000` must be matched exactly), then
    // constructor amounts (a prize or fee passed at deploy).
    let mut fees = vec![BASE_FEE];
    let ctor_amounts = c.ctor_ints.iter().filter(|v| **v > 0 && (**v as u64) <= COVENANT_VALUE / 2).map(|v| *v as u64);
    for v in c.pushed_ints.iter().copied().filter(|v| (100..=2_000_000).contains(v)).chain(ctor_amounts) {
        if fees.len() >= 6 {
            break;
        }
        if !fees.contains(&v) {
            fees.push(v);
        }
    }

    let mut payees: Vec<Dest> = (0..c.wallets.parties.len()).map(|i| Dest::Key(KeyRef::Party(i))).collect();
    payees.extend((0..c.stand_ins.len()).map(Dest::StandIn));
    let conts: Vec<Dest> = match (c.is_stateful(), state.or(c.initial_state.as_ref())) {
        (true, Some(s)) => successors(c, s).into_iter().map(Dest::Successor).collect(),
        _ => vec![Dest::SelfCovenant],
    };
    let mut everyone = payees.clone();
    everyone.extend(conts.iter().cloned());

    let total = cov_value + extra_value;
    let mut out: Vec<Vec<OutputSpec>> = Vec::new();
    let o = |v: u64, d: &Dest| OutputSpec::new(v, d.clone());

    for (fi, fee) in fees.iter().enumerate() {
        if *fee >= total {
            continue;
        }
        let v = total - fee;
        let mut amounts: Vec<u64> =
            c.ctor_ints.iter().filter(|n| **n > 0 && (**n as u64) < v).map(|n| *n as u64).collect();
        amounts.extend(c.pushed_ints.iter().copied().filter(|n| (10_000..v).contains(n)).take(4));
        amounts.push(cov_value / 2);
        // Basis-point splits: a * b / 10000 for an amount a and a rate b.
        let mut bps: Vec<(u64, u64)> = Vec::new();
        for a in c.ctor_ints.iter().filter(|a| **a >= 1_000_000 && (**a as u64) < v) {
            for b in c.ctor_ints.iter().filter(|b| (1..10_000).contains(*b)) {
                let cut = (*a as i128 * *b as i128 / 10_000) as u64;
                if cut > 0 && !bps.contains(&(*a as u64, cut)) {
                    bps.push((*a as u64, cut));
                    amounts.push(*a as u64 - cut);
                    amounts.push(cut);
                }
            }
        }
        let mut seen = std::collections::HashSet::new();
        amounts.retain(|x| *x > 0 && *x < v && seen.insert(*x));
        amounts.truncate(8);
        bps.truncate(3);

        for d in &everyone {
            out.push(vec![o(v, d)]);
        }
        if fi >= 3 {
            continue;
        }
        // Pairs: an amount to one, the rest to another.
        for a in &amounts {
            for p in &everyone {
                for q in &everyone {
                    if p == q || (conts.contains(p) && conts.contains(q)) {
                        continue;
                    }
                    out.push(vec![o(*a, p), o(v - a, q)]);
                }
            }
        }
        if extra_value > 0 {
            for p in &everyone {
                for q in &everyone {
                    if p != q {
                        out.push(vec![o(cov_value - fee, p), o(extra_value, q)]);
                    }
                }
            }
        }
        if fi >= 2 {
            continue;
        }
        // Triples: amount minus cut, cut, and the rest.
        for (a, cut) in &bps {
            for p in &payees {
                for q in &payees {
                    if p == q {
                        continue;
                    }
                    for r in &everyone {
                        if r == p || r == q {
                            continue;
                        }
                        out.push(vec![o(a - cut, p), o(*cut, q), o(v - a, r)]);
                    }
                }
            }
        }
        if payees.len() >= 2 {
            out.push(vec![o(v / 2, &payees[0]), o(v - v / 2, &payees[1])]);
        }
    }
    out
}
