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

/// Optional wall-clock deadline for the whole search (`--deadline`). Past it,
/// every search stops and reports its path as unexplored, so a run always
/// returns a report instead of being killed.
static DEADLINE: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
/// A project's share of the deadline for the file being searched now.
static FILE_DEADLINE: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);

pub fn set_deadline(at: std::time::Instant) {
    let _ = DEADLINE.set(at);
}

pub fn deadline() -> Option<std::time::Instant> {
    DEADLINE.get().copied()
}

/// Limits the search of one file of a project (None: only the overall deadline).
pub fn set_file_deadline(at: Option<std::time::Instant>) {
    *FILE_DEADLINE.lock().unwrap() = at;
}

/// A file deadline, when set, replaces the overall one: it is either a share
/// of what is left, or a short grace for a step that comes after (spending
/// minted coins), which would otherwise get no time at all.
pub fn out_of_time() -> bool {
    let now = std::time::Instant::now();
    match *FILE_DEADLINE.lock().unwrap() {
        Some(d) => now >= d,
        None => DEADLINE.get().is_some_and(|d| now >= *d),
    }
}

pub const TIME_LIMIT_REASON: &str =
    "search stopped at the time limit; run kaspa-redteam on your own machine for no limit, or pass --arg values";
const MAX_ARG_COMBOS: usize = 256;
/// First pass: this many top-ranked argument combinations, each against
/// this many of the most common output shapes, before the full search.
const FIRST_PASS_COMBOS: usize = 16;
const FIRST_PASS_SHAPES: usize = 100;
const MAX_STATES: usize = 4;
const MAX_SUCCESSORS: usize = 18;
/// One-field changes first, then this many slots are left for two-field changes.
const MAX_SINGLE_SUCCESSORS: usize = 12;

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
    /// Hostile versions of a family spend, built where the other programs are
    /// known (see `family`): attack id, label, plan, what acceptance means.
    pub variants: Vec<(&'static str, String, SpendPlan, String)>,
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
    while i < states.len() && i < MAX_STATES && (i == 0 || !out_of_time()) {
        let st = states[i].clone();
        // An entry that requires another coin of its covenant to lead
        // (`OpCovInputIdx(id, 0) != this.activeInputIndex`) can never pass
        // alone: a short solo try, and the time goes to pairing it below.
        let follower = |name: &str| {
            contract.cov_mode
                && crate::tune::entry_body(&contract.source, name).is_some_and(|b| b.contains("!= this.activeInputIndex"))
        };
        let mut level: Vec<PathStatus> = contract
            .entries
            .par_iter()
            .map(|e| {
                if follower(&e.name) {
                    search_path_budget(contract, judge, &e.name, st.as_ref(), 256)
                } else {
                    search_path(contract, judge, &e.name, st.as_ref())
                }
            })
            .collect();
        // Delegate entries (a KCC-20 `transfer_delegator`) only run next to a
        // leader coin of the same covenant: retry them beside an explored path.
        if contract.cov_mode {
            let leaders: Vec<Baseline> = level
                .iter()
                .filter_map(|p| p.baseline.clone())
                .filter(|b| b.plan.inputs.iter().filter(|i| matches!(i, InputSpec::Covenant { .. })).count() == 1)
                .collect();
            for ps in level.iter_mut().filter(|p| p.baseline.is_none()) {
                for leader in &leaders {
                    if let Some(b) = search_cospend(contract, judge, &ps.name, st.as_ref(), leader, &mut ps.tries) {
                        ps.baseline = Some(b);
                        ps.unexplored_reason = None;
                        break;
                    }
                }
            }
        }
        for ps in &level {
            if let Some(b) = &ps.baseline {
                // States reached only by merging two coins are not new starting points.
                if b.plan.inputs.iter().filter(|i| matches!(i, InputSpec::Covenant { .. })).count() > 1 {
                    continue;
                }
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
    // A token program's borrowed receive (KCC-20 section 5): built directly,
    // one path per borrow scheme, since the search never turns borrowing on.
    out.extend(crate::family::borrow_paths(contract, judge));
    out
}

pub fn search_path(contract: &Contract, judge: &Judge, entry_name: &str, state: Option<&StateValues>) -> PathStatus {
    search_path_budget(contract, judge, entry_name, state, MAX_TRIES_PER_PATH)
}

/// `search_path` with a custom try budget (smaller when tuning constructor values).
pub fn search_path_budget(
    contract: &Contract,
    judge: &Judge,
    entry_name: &str,
    state: Option<&StateValues>,
    budget: usize,
) -> PathStatus {
    let first = search_layouts(contract, judge, entry_name, state, budget, false);
    if first.baseline.is_some()
        || out_of_time()
        || first.unexplored_reason.as_deref().is_some_and(|r| r.starts_with("parameter"))
    {
        return first;
    }
    // Fallback: the spender adds a coin of their own (outputs worth more than
    // the covenant coin). Tried last so ordinary paths keep their search order.
    let mut second = search_layouts(contract, judge, entry_name, state, budget / 2, true);
    second.tries += first.tries;
    if second.baseline.is_none() {
        second.unexplored_reason = first.unexplored_reason.map(|r| {
            r.replace(&format!("among {} candidates", first.tries), &format!("among {} candidates", second.tries))
        });
    }
    second
}

fn search_layouts(
    contract: &Contract,
    judge: &Judge,
    entry_name: &str,
    state: Option<&StateValues>,
    budget: usize,
    funding: bool,
) -> PathStatus {
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
        let body = crate::tune::entry_body(&contract.source, entry_name).unwrap_or("");
        match candidates(contract, body, &p.name, &p.ty, has_datasig, msg_arg) {
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
    let mut layouts: Vec<(Vec<InputSpec>, usize)> = if funding { vec![] } else { vec![(vec![], 0)] };
    for k in (0..contract.stand_ins.len()).filter(|k| contract.stand_ins[*k].linked.is_none()).take(2) {
        if funding {
            break;
        }
        layouts.push((vec![InputSpec::StandIn { target: k, value: STAND_IN_VALUE }], 0));
        layouts.push((vec![InputSpec::StandIn { target: k, value: STAND_IN_VALUE }], 1));
    }
    // A plain coin of the spender's own after the covenant, for paths whose
    // outputs must carry more than the covenant coin holds (a successor that
    // keeps every sompi, a payment on top): the spender pays the fee or more.
    if funding {
        layouts.push((vec![InputSpec::P2pk { owner: KeyRef::Attacker, value: COVENANT_VALUE }], 0));
    }

    // Coin sizes: the default, then "exactly an amount plus a small fee",
    // for covenants that only accept a precisely funded deposit.
    let mut coin_values = vec![COVENANT_VALUE];
    // A coin the entry caps or fixes in its own source
    // (`tx.inputs[this.activeInputIndex].value <= a + b + fee`) comes first.
    // Payouts the entry fixes from constructor values (`tx.outputs[1].value ==
    // driverAmount`): a coin that holds them all plus a fee.
    if let Some(total) = pinned_payout_total(contract, entry_name) {
        let v = total + BASE_FEE;
        if !coin_values.contains(&v) {
            coin_values.insert(0, v);
        }
    }
    for v in input_value_caps(contract, entry_name) {
        if !coin_values.contains(&v) {
            coin_values.insert(0, v);
        }
    }
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
            (cv, extra, pos, output_candidates_for(contract, Some(entry_name), cv, extra_value, state))
        })
        .collect();

    // Two passes so one wrong guess cannot eat the whole budget: first every
    // argument combination against the most common output shapes, then the
    // rest of the shapes. Within a pass: arguments (best-ranked first), coin
    // size and layout, output shapes, lock values.
    for pass in 0..2 {
        for (ci, (args, secrets)) in combos.iter().enumerate() {
            if pass == 0 && ci >= FIRST_PASS_COMBOS {
                break;
            }
            for (cov_value, extra, cov_pos, shapes) in &prepared {
                let cut = shapes.len().min(FIRST_PASS_SHAPES);
                // Pass 1 skips only what pass 0 already tried.
                let slice = match (pass, ci < FIRST_PASS_COMBOS) {
                    (0, _) => &shapes[..cut],
                    (_, true) => &shapes[cut..],
                    _ => &shapes[..],
                };
                for outs in slice {
                    for t in &timings {
                        if status.tries >= budget {
                            status.unexplored_reason = Some(format!(
                                "no accepted spend in {budget} tries; pass --arg values or import a baseline (--baseline)"
                            ));
                            return status;
                        }
                        // Past the deadline a path still gets its first few hundred
                        // tries: the easy ones (a plain signed transfer) are found
                        // in a handful, and a slower server must not lose them.
                        if status.tries >= 512 && status.tries % 64 == 0 && out_of_time() {
                            status.unexplored_reason = Some(TIME_LIMIT_REASON.into());
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
                        let (verdict, built) = judge.run(contract, &plan);
                        if crate::debug_on() && (status.tries <= 3 || status.tries % 5000 == 0) {
                            eprintln!("search {entry_name} try {}: {verdict:?}", status.tries);
                            if let Some(b) = &built {
                                if let Some(f) = (0..plan.inputs.len()).find_map(|i| crate::sandbox::trace_failure(b, i)) {
                                    let h = |v: &[u8]| faster_hex::hex_string(&v[..v.len().min(24)]);
                                    eprintln!("  input {} {} a={} b={}", f.input, f.op, h(&f.a), h(&f.b));
                                }
                            }
                        }
                        if verdict.accepted() {
                            let lock = if t.lock_time > 0 {
                                Some(bisect_lock(contract, judge, &plan, "lock_time", t.lock_time))
                            } else if t.sequence > 0 {
                                Some(bisect_lock(contract, judge, &plan, "sequence", t.sequence))
                            } else {
                                None
                            };
                            let signers = plan.signers();
                            status.baseline = Some(Baseline { plan, signers, secrets: secrets.clone(), lock, variants: vec![] });
                            return status;
                        }
                    }
                }
            }
        }
    }
    let sibling = if contract.source.contains("WithTemplate(") || contract.source.contains("WithInputTemplate(") {
        "; it may need a coin of another program (the contract reads or creates states by template hash), which cannot be built from this file alone"
    } else {
        ""
    };
    status.unexplored_reason = Some(format!(
        "no accepted spend among {} candidates (signers x arguments x outputs x locks){sibling}; pass --arg values or import a baseline (--baseline)",
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

fn parties_by_affinity(c: &Contract, param: &str, body: &str) -> Vec<KeyRef> {
    // Strongest signal: the source checks this parameter against a named key,
    // e.g. `checkSig(paySig, payout)` or `checkMsgSig(s, ..., conductor)`.
    // The entry's own body first: `deptSig` is checked against `parks` in
    // `pullParks` and against `police` in `pullPolice`.
    let checks = |text: &str| -> Vec<String> {
        text.lines()
            .filter(|l| (l.contains("checkSig") || l.contains("checkMsgSig")) && mentions(l, param))
            .map(String::from)
            .collect()
    };
    let local = checks(body);
    let checked_with: Vec<String> = if local.is_empty() { checks(&c.source) } else { local };
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
    body: &str,
    param: &str,
    ty: &TypeArtifact,
    has_datasig: bool,
    msg_arg: Option<usize>,
) -> Result<Vec<(ArgRecipe, Option<String>)>, String> {
    let v = |a: ArtifactValue| (ArgRecipe::Value(a), None);
    let parties = parties_by_affinity(c, param, body);
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
            // A ZK covenant: the test proof for the proof argument, and journals
            // that carry a party's key (the usual recipient field) for the journal.
            if c.zk_keys > 0 {
                let n = param.to_ascii_lowercase();
                if n.contains("proof") || n.contains("seal") {
                    out.push((ArgRecipe::Value(ArtifactValue::Bytes(crate::zk::test_proof())), Some("the tool's test proof".into())));
                    return Ok(out);
                }
                if n.contains("journal") || n.contains("output") || n.contains("public") {
                    // Laid out the way the entry slices it, from constructor and state values.
                    let bytes_of = |name: &str| -> Option<Vec<u8>> {
                        let from_arg = c.args.iter().find(|a| a.name == name).map(|a| a.value.clone());
                        let from_state = c.initial_state.as_ref().and_then(|s| s.get(name).cloned());
                        match from_arg.or(from_state)? {
                            ArtifactValue::Bytes(b) => Some(b),
                            _ => None,
                        }
                    };
                    if let Some(j) = crate::zk::journal_from_source(body, param, &bytes_of) {
                        out.push((ArgRecipe::Value(ArtifactValue::Bytes(j)), Some("a journal laid out as the entry reads it".into())));
                    }
                    let keys = if parties.is_empty() { vec![KeyRef::Attacker] } else { parties.clone() };
                    for k in keys.iter().take(2) {
                        out.push(v(ArtifactValue::Bytes(c.wallets.get(*k).xonly().to_vec())));
                    }
                }
            }
            // A signature carried inside bytes (`sig(byte[65](witness))`):
            // the signature alone, or after a one-byte path selector.
            if c.source.contains("sig(byte[65](") {
                let keys = if parties.is_empty() { vec![KeyRef::Attacker] } else { parties.clone() };
                // A path byte in front only when the script slices one off (`witness.slice(1, ...)`).
                let path_first = c.source.contains(".slice(1,");
                for k in keys.iter().take(2) {
                    let bare = (ArgRecipe::SigBytes { key: *k, prefix: vec![] }, None);
                    let path = (ArgRecipe::SigBytes { key: *k, prefix: vec![0x00] }, None);
                    if path_first {
                        out.push(path);
                        out.push(bare);
                    } else {
                        out.push(bare);
                        out.push(path);
                    }
                }
            }
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
        // State-shaped arguments follow the transaction: the successor states
        // its outputs carry, or (`prevStates`) the states its covenant inputs hold.
        TypeArtifact::Struct { name } if c.struct_fields(name).is_some() => {
            vec![(ArgRecipe::States { inputs: is_input_param(param), array: false, item: name.clone() }, None)]
        }
        TypeArtifact::FixedArray { item, .. } | TypeArtifact::DynamicArray { item } if matches!(item.as_ref(), TypeArtifact::Struct { name } if c.struct_fields(name).is_some()) =>
        {
            let TypeArtifact::Struct { name } = item.as_ref() else { unreachable!() };
            vec![(ArgRecipe::States { inputs: is_input_param(param), array: true, item: name.clone() }, None)]
        }
        TypeArtifact::FixedArray { .. } | TypeArtifact::DynamicArray { .. } => {
            return Err("arrays of plain values are not searched yet; import a baseline (--baseline)".into());
        }
        TypeArtifact::Struct { name } => {
            return Err(format!("struct `{name}` is not defined in this file; import a baseline (--baseline)"));
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
                // n + 1, then 2n (two coins merged), then small values.
                let mut ints = vec![n + 1, 2 * n, 1, 0, n - 1, 2];
                ints.extend(c.ctor_ints.iter().copied().take(3));
                for x in ints {
                    if x != *n && !vals.contains(&ArtifactValue::Int(x)) {
                        vals.push(ArtifactValue::Int(x));
                    }
                }
                vals.truncate(6);
            }
            (TypeArtifact::FixedBytes { len }, Some(ArtifactValue::Bytes(b))) => {
                // A covenant id recorded in state (`newState.covid == OpOutputCovenantId(0)`).
                if c.cov_mode && *len == 32 {
                    let id = crate::sandbox::sandbox_covenant_id().as_bytes().to_vec();
                    if *b != id {
                        vals.push(ArtifactValue::Bytes(id));
                    }
                }
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
            if out.len() >= MAX_SINGLE_SUCCESSORS {
                break;
            }
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
/// Output shapes for one entry: shapes the entry's own source pins come first,
/// and payees it names are tried before the others.
fn output_candidates_for(
    c: &Contract,
    entry: Option<&str>,
    cov_value: u64,
    extra_value: u64,
    state: Option<&StateValues>,
) -> Vec<Vec<OutputSpec>> {
    let body = entry.and_then(|e| crate::tune::entry_body(&c.source, e)).unwrap_or("");
    let mut out = pinned_shapes(c, body, cov_value + extra_value);
    // A ZK payout to the key a journal names: the whole coin, less a fee, to
    // the keys the journal candidates carry.
    if c.zk_keys > 0 && body.contains("ScriptPubKeyP2PK(pubkey(") {
        let keys: Vec<KeyRef> = if c.wallets.parties.is_empty() { vec![KeyRef::Attacker] } else { (0..c.wallets.parties.len().min(2)).map(KeyRef::Party).collect() };
        for k in keys {
            out.push(vec![OutputSpec::new((cov_value + extra_value).saturating_sub(BASE_FEE), Dest::Key(k))]);
        }
    }
    out.extend(generic_shapes(c, body, cov_value, extra_value, state));
    out
}

/// `tx.outputs[i].scriptPubKey == byte[](new ScriptPubKeyP2PK(name))` and
/// `tx.outputs[i].value == amount` lines read straight from the entry, plus a
/// change output where it returns to `tx.inputs[this.activeInputIndex].scriptPubKey`.
fn pinned_shapes(c: &Contract, body: &str, total: u64) -> Vec<Vec<OutputSpec>> {
    use std::collections::BTreeMap;
    let ints: BTreeMap<&str, i64> = c
        .args
        .iter()
        .filter_map(|a| match a.value {
            ArtifactValue::Int(n) => Some((a.name.as_str(), n)),
            _ => None,
        })
        .collect();
    let mut dest: BTreeMap<usize, Dest> = BTreeMap::new();
    let mut value: BTreeMap<usize, u64> = BTreeMap::new();
    for line in body.lines() {
        let l = line.trim();
        let Some(rest) = l.strip_prefix("require(tx.outputs[") else { continue };
        let Some((idx, rest)) = rest.split_once(']') else { continue };
        let Ok(i) = idx.trim().parse::<usize>() else { continue };
        if let Some(r) = rest.strip_prefix(".scriptPubKey == byte[](new ScriptPubKeyP2PK(") {
            let name = r.split(')').next().unwrap_or("").trim();
            if let Some(p) = c.wallets.parties.iter().position(|w| w.label == name) {
                dest.insert(i, Dest::Key(KeyRef::Party(p)));
            }
        } else if rest.starts_with(".scriptPubKey == tx.inputs[this.activeInputIndex].scriptPubKey") {
            dest.insert(i, Dest::SelfCovenant);
        } else if let Some(r) = rest.strip_prefix(".value == ").or_else(|| rest.strip_prefix(".value <= ")) {
            let e = r.trim_end_matches(';').trim_end_matches(')').trim();
            let v = ints.get(e).copied().or_else(|| e.replace('_', "").parse().ok());
            if let Some(v) = v.filter(|v| *v > 0) {
                value.insert(i, v as u64);
            }
        }
    }
    let n = match dest.keys().max() {
        Some(m) if dest.len() >= 2 && dest.len() == m + 1 => m + 1,
        _ => return vec![],
    };
    let fixed: u64 = value.values().sum();
    let mut shapes = Vec::new();
    for fee in [BASE_FEE, 100_000] {
        if fixed + fee >= total {
            continue;
        }
        let rest = total - fixed - fee;
        let open: Vec<usize> = (0..n).filter(|i| !value.contains_key(i)).collect();
        let mut shape: Vec<OutputSpec> = Vec::with_capacity(n);
        for i in 0..n {
            let v = match value.get(&i) {
                Some(v) => *v,
                None => rest / open.len().max(1) as u64,
            };
            shape.push(OutputSpec::new(v, dest[&i].clone()));
        }
        shapes.push(shape);
    }
    shapes
}

fn generic_shapes(
    c: &Contract,
    body: &str,
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

    // Parties the entry itself names come first (`ScriptPubKeyP2PK(parks)` in `pullParks`).
    let mut order: Vec<usize> = (0..c.wallets.parties.len()).collect();
    order.sort_by_key(|i| !mentions(body, &c.wallets.parties[*i].label));
    let mut payees: Vec<Dest> = order.into_iter().map(|i| Dest::Key(KeyRef::Party(i))).collect();
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
        // Fractions the script computes with (`total * 7 / 10`): p/q of what is
        // left, rounded up, for the small constants it pushes.
        let small: Vec<u64> = c.pushed_ints.iter().copied().filter(|n| (1..=10_000).contains(n)).collect();
        let mut amounts: Vec<u64> = Vec::new();
        'ratios: for q in small.iter().rev() {
            for p in small.iter().filter(|p| *p < q) {
                if amounts.len() >= 3 {
                    break 'ratios;
                }
                amounts.push((v as u128 * *p as u128).div_ceil(*q as u128) as u64);
            }
        }
        amounts.extend(c.ctor_ints.iter().filter(|n| **n > 0 && (**n as u64) < v).map(|n| *n as u64));
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
        // A payment the next state records: a running total that grows by
        // what was just paid out (`spent + amount`), or starts over at it.
        if let (true, Some(base)) = (c.is_stateful(), state.or(c.initial_state.as_ref())) {
            let int_fields: Vec<&String> =
                c.state_fields.iter().filter(|(_, t)| matches!(t, TypeArtifact::Int)).map(|(n, _)| n).collect();
            // Constructor amounts first: a running total is usually checked against one.
            let mut coupled: Vec<u64> =
                amounts.iter().copied().filter(|a| c.ctor_ints.contains(&(*a as i64))).collect();
            coupled.extend(amounts.iter().copied().filter(|a| !c.ctor_ints.contains(&(*a as i64))));
            for a in coupled.iter().take(5) {
                for f in &int_fields {
                    let Some(ArtifactValue::Int(cur)) = base.get(*f) else { continue };
                    for nv in [cur + *a as i64, *a as i64] {
                        let mut st = base.clone();
                        st.insert((*f).clone(), ArtifactValue::Int(nv));
                        // Also with another int field moved by a constructor value
                        // (a period start advancing by `period`).
                        let mut variants = vec![st.clone()];
                        for g in int_fields.iter().filter(|g| *g != f) {
                            let Some(ArtifactValue::Int(gv)) = base.get(*g) else { continue };
                            for k in c.ctor_ints.iter().filter(|k| **k > 0).take(4) {
                                let mut s2 = st.clone();
                                s2.insert((*g).clone(), ArtifactValue::Int(gv + k));
                                variants.push(s2);
                            }
                        }
                        for s in variants {
                            for p in payees.iter().take(3) {
                                out.push(vec![o(*a, p), o(v - a, &Dest::Successor(s.clone()))]);
                            }
                        }
                    }
                }
            }
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
                        // The extra coin pays the fee; the covenant's value moves whole.
                        if extra_value > *fee {
                            out.push(vec![o(cov_value, p), o(extra_value - fee, q)]);
                        }
                    }
                }
            }
            // The covenant's value moves whole and the extra coin's change goes back to its owner.
            if extra_value > *fee {
                for p in &conts {
                    out.push(vec![o(cov_value, p), o(extra_value - fee, &Dest::Key(KeyRef::Attacker))]);
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

/// `prevStates`, `inputStates`, `old`: states being spent rather than created.
fn is_input_param(param: &str) -> bool {
    let p = param.to_ascii_lowercase();
    ["prev", "input", "old", "current", "spent"].iter().any(|k| p.contains(k))
}

/// Searches `entry_name` as a second coin of the same covenant next to the
/// leader spend `leader` (its input first, as covenant index 0). The two coins
/// share the outputs, so successor states may carry both coins' amounts.
fn search_cospend(
    contract: &Contract,
    judge: &Judge,
    entry_name: &str,
    state: Option<&StateValues>,
    leader: &Baseline,
    tries: &mut usize,
) -> Option<Baseline> {
    const BUDGET: usize = 6_000;
    let entry = contract.entry(entry_name)?;
    let lead_input = leader.plan.inputs.iter().find(|i| matches!(i, InputSpec::Covenant { .. }))?.clone();
    let lead_value = lead_input.value();
    let msg_arg = entry.params.iter().position(|p| matches!(p.ty, TypeArtifact::Bytes));
    let has_datasig = entry.params.iter().any(|p| matches!(p.ty, TypeArtifact::Datasig));
    let mut per_param = Vec::new();
    for p in &entry.params {
        let body = crate::tune::entry_body(&contract.source, entry_name).unwrap_or("");
        per_param.push(candidates(contract, body, &p.name, &p.ty, has_datasig, msg_arg).ok()?);
    }
    let combos = ranked_cartesian(&per_param, 64);
    let (pov_daa, block_time) = (leader.plan.pov_daa, leader.plan.block_time);
    let shapes = output_candidates_for(contract, Some(entry_name), COVENANT_VALUE, lead_value, state);
    let mut tried = 0;
    // Shapes outer: the arguments here are few (a witness, a signature),
    // the shapes many, and one wrong argument must not use up the budget.
    for outs in &shapes {
        for (args, secrets) in &combos {
            // A few hundred tries even past the deadline: a leader is already
            // found, pairing is cheap, and without it the follower stays unexplored.
            if tried >= BUDGET || (tried >= 512 && tried % 64 == 0 && out_of_time()) {
                return None;
            }
            tried += 1;
            *tries += 1;
            let me = InputSpec::Covenant {
                entry: entry_name.into(),
                args: args.clone(),
                value: COVENANT_VALUE,
                sequence: 0,
                state: state.cloned(),
            };
            let plan = SpendPlan::simple(vec![lead_input.clone(), me], outs.clone(), 0, pov_daa, block_time);
            let (v, _) = judge.run(contract, &plan);
            if v.accepted() {
                let signers = plan.signers();
                return Some(Baseline { plan, signers, secrets: secrets.clone(), lock: None, variants: vec![] });
            }
        }
    }
    None
}

/// Values the entry pins its own coin to, read from lines like
/// `require(tx.inputs[this.activeInputIndex].value <= a + b + maxFee)`:
/// the expression is a sum or difference of constructor ints and literals.
fn input_value_caps(contract: &Contract, entry_name: &str) -> Vec<u64> {
    let Some(body) = crate::tune::entry_body(&contract.source, entry_name) else { return vec![] };
    let ints: std::collections::BTreeMap<&str, i64> = contract
        .args
        .iter()
        .filter_map(|a| match &a.value {
            ArtifactValue::Int(n) => Some((a.name.as_str(), *n)),
            _ => None,
        })
        .collect();
    let mut out = Vec::new();
    for line in body.lines() {
        let Some(at) = line.find("tx.inputs[this.activeInputIndex].value") else { continue };
        let rest = line[at + 38..].trim_start();
        let (op, expr) = if let Some(e) = rest.strip_prefix("<=") {
            ("<=", e)
        } else if let Some(e) = rest.strip_prefix("==") {
            ("==", e)
        } else if let Some(e) = rest.strip_prefix('<') {
            ("<", e)
        } else {
            continue;
        };
        let expr = expr.split(|c| c == ')' || c == ';' || c == '&' || c == '|').next().unwrap_or("");
        let mut total: i64 = 0;
        let mut sign = 1;
        let mut ok = true;
        for tok in expr.split_inclusive(|c| c == '+' || c == '-') {
            let (term, next) = match tok.chars().last() {
                Some('+') => (&tok[..tok.len() - 1], 1),
                Some('-') => (&tok[..tok.len() - 1], -1),
                _ => (tok, 1),
            };
            let term = term.trim();
            let v = term.replace('_', "").parse::<i64>().ok().or_else(|| ints.get(term).copied());
            match v {
                Some(v) => total += sign * v,
                None => {
                    ok = false;
                    break;
                }
            }
            sign = next;
        }
        if !ok || total <= 0 {
            continue;
        }
        let v = if op == "<" { total - 1 } else { total } as u64;
        if v > BASE_FEE && !out.contains(&v) {
            out.push(v);
        }
    }
    out
}

/// Sum of the output values an entry pins to a constructor int or literal,
/// one per output index.
fn pinned_payout_total(contract: &Contract, entry_name: &str) -> Option<u64> {
    let body = crate::tune::entry_body(&contract.source, entry_name)?;
    let ints: std::collections::BTreeMap<&str, i64> = contract
        .args
        .iter()
        .filter_map(|a| match &a.value {
            ArtifactValue::Int(n) => Some((a.name.as_str(), *n)),
            _ => None,
        })
        .collect();
    let mut by_index: std::collections::BTreeMap<String, i64> = Default::default();
    for line in body.lines() {
        let Some(at) = line.find("tx.outputs[") else { continue };
        let rest = &line[at + 11..];
        let Some(close) = rest.find(']') else { continue };
        let idx = rest[..close].trim().to_string();
        let Some(v) = rest[close + 1..].trim_start().strip_prefix(".value") else { continue };
        let Some(expr) = v.trim_start().strip_prefix("==") else { continue };
        let term = expr.split(|c| c == ')' || c == ';').next().unwrap_or("").trim();
        if let Some(n) = term.replace('_', "").parse::<i64>().ok().or_else(|| ints.get(term).copied()) {
            if n > 0 {
                by_index.insert(idx, n);
            }
        }
    }
    (by_index.len() >= 2).then(|| by_index.values().sum::<i64>() as u64)
}
