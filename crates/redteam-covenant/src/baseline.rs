//! Honest-spend search. Before anything is attacked, the engine finds, for
//! each spend path, one transaction the covenant accepts: who signs, what
//! arguments, where the money goes, which lock values. Attacks then mutate
//! that baseline. A path with no baseline is reported as unexplored, never as
//! safe.

use crate::contract::Contract;
use crate::sandbox::{
    ArgRecipe, BASE_FEE, COVENANT_VALUE, Dest, InputSpec, Judge, OutputSpec, SpendPlan, UTXO_DAA,
};
use crate::wallets::KeyRef;
use kaspa_consensus_core::constants::LOCK_TIME_THRESHOLD;
use serde::Serialize;
use silverscript_abi::{ArtifactValue, TypeArtifact};

const MAX_TRIES_PER_PATH: usize = 6_000;
const MAX_ARG_COMBOS: usize = 512;

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
    /// Labels of secrets whose preimage the spend reveals.
    pub secrets: Vec<String>,
    pub lock: Option<LockInfo>,
}

impl Baseline {
    /// Nobody's signature is needed: anyone (or anyone who saw the secret) can
    /// build this spend.
    pub fn permissionless(&self) -> bool {
        self.signers.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct PathStatus {
    pub entry: String,
    pub baseline: Option<Baseline>,
    pub unexplored_reason: Option<String>,
    pub tries: usize,
}

struct Timing {
    lock_time: u64,
    sequence: u64,
}

pub fn search_all(contract: &Contract, judge: &Judge) -> Vec<PathStatus> {
    contract
        .entries
        .iter()
        .map(|e| search_path(contract, judge, &e.name))
        .collect()
}

pub fn pov(contract: &Contract) -> (u64, u64) {
    let max_daa_lock = contract
        .cltv_values
        .iter()
        .copied()
        .filter(|v| *v < LOCK_TIME_THRESHOLD)
        .max()
        .unwrap_or(0);
    let max_time_lock = contract
        .cltv_values
        .iter()
        .copied()
        .filter(|v| *v >= LOCK_TIME_THRESHOLD)
        .max()
        .unwrap_or(0);
    let max_csv = contract.csv_values.iter().copied().max().unwrap_or(0);
    let pov_daa = (10_000_000u64)
        .max(max_daa_lock + 1)
        .max(UTXO_DAA + max_csv + 1)
        .min(LOCK_TIME_THRESHOLD - 1);
    let block_time = (4_000_000_000_000u64).max(max_time_lock + 1);
    (pov_daa, block_time)
}

pub fn search_path(contract: &Contract, judge: &Judge, entry_name: &str) -> PathStatus {
    let entry = contract.entry(entry_name).expect("entry exists");
    let mut status = PathStatus {
        entry: entry_name.into(),
        baseline: None,
        unexplored_reason: None,
        tries: 0,
    };

    // Candidate values for each parameter.
    let mut per_param: Vec<Vec<(ArgRecipe, Option<String>)>> = Vec::new();
    for p in &entry.params {
        match candidates(contract, &p.ty) {
            Ok(c) => per_param.push(c),
            Err(why) => {
                status.unexplored_reason = Some(format!("parameter `{}`: {why}", p.name));
                return status;
            }
        }
    }
    let combos = cartesian(&per_param, MAX_ARG_COMBOS);
    let (pov_daa, block_time) = pov(contract);

    let mut timings = vec![Timing {
        lock_time: 0,
        sequence: 0,
    }];
    for v in &contract.cltv_values {
        timings.push(Timing {
            lock_time: *v,
            sequence: 0,
        });
    }
    for v in &contract.csv_values {
        timings.push(Timing {
            lock_time: 0,
            sequence: *v,
        });
    }
    if let (Some(l), Some(s)) = (contract.cltv_values.last(), contract.csv_values.last()) {
        timings.push(Timing {
            lock_time: *l,
            sequence: *s,
        });
    }

    // Fee candidates: the default, then small constants the script pushes
    // (a hard-coded `minerFee = 1000` must be matched exactly).
    // Constructor amounts too: a prize or fee passed at deploy is often the
    // exact amount a path burns.
    let mut fees = vec![BASE_FEE];
    let ctor_amounts = contract
        .ctor_ints
        .iter()
        .filter(|v| **v > 0 && (**v as u64) <= COVENANT_VALUE / 2)
        .map(|v| *v as u64);
    for v in contract
        .pushed_ints
        .iter()
        .copied()
        .filter(|v| (100..=1_000_000).contains(v))
        .chain(ctor_amounts)
    {
        if fees.len() >= 6 {
            break;
        }
        if !fees.contains(&v) {
            fees.push(v);
        }
    }
    let outputs: Vec<Vec<OutputSpec>> = fees
        .iter()
        .flat_map(|f| output_candidates(contract, *f))
        .collect();

    for t in &timings {
        for outs in &outputs {
            for (args, secrets) in &combos {
                if status.tries >= MAX_TRIES_PER_PATH {
                    status.unexplored_reason = Some(format!(
                        "no accepted spend in {MAX_TRIES_PER_PATH} tries; pass --arg values or a spec to guide the search"
                    ));
                    return status;
                }
                status.tries += 1;
                let plan = SpendPlan {
                    inputs: vec![InputSpec::Covenant {
                        entry: entry_name.into(),
                        args: args.clone(),
                        value: COVENANT_VALUE,
                        sequence: t.sequence,
                    }],
                    outputs: outs.clone(),
                    lock_time: t.lock_time,
                    pov_daa,
                    block_time,
                };
                if judge.run(contract, &plan).0.accepted() {
                    let lock = if t.lock_time > 0 {
                        Some(bisect_lock(
                            contract,
                            judge,
                            &plan,
                            "lock_time",
                            t.lock_time,
                        ))
                    } else if t.sequence > 0 {
                        Some(bisect_lock(contract, judge, &plan, "sequence", t.sequence))
                    } else {
                        None
                    };
                    let signers = plan.signers();
                    status.baseline = Some(Baseline {
                        plan,
                        signers,
                        secrets: secrets.clone(),
                        lock,
                    });
                    return status;
                }
            }
        }
    }
    status.unexplored_reason = Some(format!(
        "no accepted spend among {} candidates (signers x arguments x outputs x locks); pass --arg values to guide the search",
        status.tries
    ));
    status
}

fn bisect_lock(
    contract: &Contract,
    judge: &Judge,
    plan: &SpendPlan,
    field: &'static str,
    used: u64,
) -> LockInfo {
    let set = |p: &mut SpendPlan, v: u64| {
        if field == "lock_time" {
            p.lock_time = v;
        } else if let InputSpec::Covenant { sequence, .. } = &mut p.inputs[0] {
            *sequence = v;
        }
    };
    // Same lock-time domain as `used` (DAA score vs milliseconds).
    let mut lo = if field == "lock_time" && used >= LOCK_TIME_THRESHOLD {
        LOCK_TIME_THRESHOLD
    } else {
        1
    };
    let mut hi = used;
    let accepts = |v: u64| {
        let mut p = plan.clone();
        set(&mut p, v);
        judge.run(contract, &p).0.accepted()
    };
    if accepts(lo) {
        return LockInfo {
            field,
            used,
            earliest: lo,
        };
    }
    while lo + 1 < hi {
        let mid = lo + (hi - lo) / 2;
        if accepts(mid) { hi = mid } else { lo = mid }
    }
    LockInfo {
        field,
        used,
        earliest: hi,
    }
}

fn candidates(c: &Contract, ty: &TypeArtifact) -> Result<Vec<(ArgRecipe, Option<String>)>, String> {
    let v = |a: ArtifactValue| (ArgRecipe::Value(a), None);
    let parties: Vec<KeyRef> = (0..c.wallets.parties.len()).map(KeyRef::Party).collect();
    Ok(match ty {
        TypeArtifact::Sig => {
            if parties.is_empty() {
                vec![(ArgRecipe::Sig(KeyRef::Attacker), None)]
            } else {
                parties.iter().map(|k| (ArgRecipe::Sig(*k), None)).collect()
            }
        }
        TypeArtifact::Pubkey => {
            let mut out: Vec<_> = c
                .wallets
                .parties
                .iter()
                .map(|w| v(ArtifactValue::Bytes(w.xonly().to_vec())))
                .collect();
            if out.is_empty() {
                out.push(v(ArtifactValue::Bytes(c.wallets.attacker.xonly().to_vec())));
            }
            out
        }
        TypeArtifact::Int | TypeArtifact::Temporal => {
            // Constructor values, then constants the script compares against.
            let mut ints: Vec<i64> = c.ctor_ints.clone();
            ints.extend([0, 1]);
            ints.extend(
                c.pushed_ints
                    .iter()
                    .filter(|n| **n < 1_000_000_000_000)
                    .map(|n| *n as i64),
            );
            ints.push((COVENANT_VALUE / 2) as i64);
            let mut seen = std::collections::HashSet::new();
            ints.retain(|x| seen.insert(*x));
            ints.into_iter()
                .take(10)
                .map(|n| v(ArtifactValue::Int(n)))
                .collect()
        }
        TypeArtifact::Bool => vec![v(ArtifactValue::Bool(true)), v(ArtifactValue::Bool(false))],
        TypeArtifact::Byte => vec![v(ArtifactValue::Byte(0)), v(ArtifactValue::Byte(1))],
        TypeArtifact::Bytes => {
            let mut out: Vec<_> = c
                .secrets
                .iter()
                .map(|s| {
                    (
                        ArgRecipe::Value(ArtifactValue::Bytes(s.preimage.clone())),
                        Some(s.label.clone()),
                    )
                })
                .collect();
            out.push(v(ArtifactValue::Bytes(vec![0x11; 20])));
            out.push(v(ArtifactValue::Bytes(vec![])));
            out
        }
        TypeArtifact::FixedBytes { len } => {
            let mut out: Vec<_> = c
                .secrets
                .iter()
                .filter(|s| s.preimage.len() == *len)
                .map(|s| {
                    (
                        ArgRecipe::Value(ArtifactValue::Bytes(s.preimage.clone())),
                        Some(s.label.clone()),
                    )
                })
                .collect();
            if *len == 32 {
                out.extend(
                    c.wallets
                        .parties
                        .iter()
                        .map(|w| v(ArtifactValue::Bytes(w.xonly().to_vec()))),
                );
            }
            out.push(v(ArtifactValue::Bytes(vec![0u8; *len])));
            out
        }
        TypeArtifact::Text => {
            let mut out: Vec<_> = c
                .secrets
                .iter()
                .filter_map(|s| {
                    String::from_utf8(s.preimage.clone()).ok().map(|t| {
                        (
                            ArgRecipe::Value(ArtifactValue::Text(t)),
                            Some(s.label.clone()),
                        )
                    })
                })
                .collect();
            out.push(v(ArtifactValue::Text("redteam".into())));
            out
        }
        TypeArtifact::Datasig => {
            return Err("data signatures (oracle input) need a Tier 2 spec".into());
        }
        TypeArtifact::FixedArray { .. } | TypeArtifact::DynamicArray { .. } => {
            return Err("array arguments are not searched yet".into());
        }
        TypeArtifact::Struct { name } => {
            return Err(format!("struct `{name}` arguments are not searched yet"));
        }
    })
}

fn cartesian(
    per_param: &[Vec<(ArgRecipe, Option<String>)>],
    cap: usize,
) -> Vec<(Vec<ArgRecipe>, Vec<String>)> {
    let mut acc: Vec<(Vec<ArgRecipe>, Vec<String>)> = vec![(vec![], vec![])];
    for options in per_param {
        let mut next = Vec::new();
        'outer: for (args, secrets) in &acc {
            for (opt, secret) in options {
                let mut a = args.clone();
                a.push(opt.clone());
                let mut s = secrets.clone();
                if let Some(l) = secret {
                    s.push(l.clone());
                }
                next.push((a, s));
                if next.len() >= cap {
                    break 'outer;
                }
            }
        }
        acc = next;
    }
    acc
}

/// Output shapes an honest spend might take, most common first.
fn output_candidates(c: &Contract, fee: u64) -> Vec<Vec<OutputSpec>> {
    let v = COVENANT_VALUE - fee;
    let parties: Vec<Dest> = (0..c.wallets.parties.len())
        .map(|i| Dest::Key(KeyRef::Party(i)))
        .collect();
    let mut out = Vec::new();
    for p in &parties {
        out.push(vec![OutputSpec {
            value: v,
            to: p.clone(),
        }]);
    }
    out.push(vec![OutputSpec {
        value: v,
        to: Dest::SelfCovenant,
    }]);
    // Capped pulls with change back to the covenant.
    let mut amounts: Vec<u64> = c
        .ctor_ints
        .iter()
        .filter(|n| **n > 0 && (**n as u64) < v)
        .map(|n| *n as u64)
        .collect();
    amounts.push(COVENANT_VALUE / 2);
    amounts.sort_unstable();
    amounts.dedup();
    for p in &parties {
        for a in &amounts {
            out.push(vec![
                OutputSpec {
                    value: *a,
                    to: p.clone(),
                },
                OutputSpec {
                    value: v - a,
                    to: Dest::SelfCovenant,
                },
            ]);
            out.push(vec![
                OutputSpec {
                    value: v - a,
                    to: Dest::SelfCovenant,
                },
                OutputSpec {
                    value: *a,
                    to: p.clone(),
                },
            ]);
        }
    }
    // A capped amount to one party, the rest to another (claim + refund shapes).
    let few = &parties[..parties.len().min(4)];
    for p in few {
        for q in few {
            if p == q {
                continue;
            }
            for a in &amounts {
                out.push(vec![
                    OutputSpec {
                        value: *a,
                        to: p.clone(),
                    },
                    OutputSpec {
                        value: v - a,
                        to: q.clone(),
                    },
                ]);
            }
        }
    }
    // Split between two parties.
    if parties.len() >= 2 {
        out.push(vec![
            OutputSpec {
                value: v / 2,
                to: parties[0].clone(),
            },
            OutputSpec {
                value: v - v / 2,
                to: parties[1].clone(),
            },
        ]);
    }
    out
}
