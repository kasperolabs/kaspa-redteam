//! Attack plugin interface and the run loop.
//!
//! Adding an attack = one file under `attacks/` with a struct implementing
//! [`CovenantAttack`] and one `inventory::submit!` line. Nothing else changes:
//! the runner, `--only`, `list`, the report and the badge pick it up.

use crate::baseline::{self, PathStatus};
use crate::contract::Contract;
use crate::sandbox::{Judge, SpendPlan, Verdict};
use redteam_core::{AttackMeta, AttackResult, Finding, Outcome, RunReport, Severity, Target};
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::time::Instant;

/// One hostile transaction an attack wants judged.
pub struct Attempt {
    /// Spend path being attacked.
    pub path: String,
    /// Short description of the mutation, shown in the finding.
    pub label: String,
    pub plan: SpendPlan,
    /// What it means if consensus accepts this attempt.
    pub explanation: String,
    /// Overrides the attack's default severity for this attempt.
    pub severity: Option<Severity>,
    /// Accepted = the attacker can take everything on this path. Later
    /// attacks skip compromised paths instead of piling on.
    pub takeover: bool,
}

pub struct AttackCx<'a> {
    pub contract: &'a Contract,
    pub judge: &'a Judge,
    pub paths: &'a [PathStatus],
    compromised: RefCell<BTreeSet<String>>,
}

impl AttackCx<'_> {
    pub fn is_compromised(&self, path: &str) -> bool {
        self.compromised.borrow().contains(path)
    }
    /// Paths with a known honest spend that are not already taken over.
    pub fn live_paths(&self) -> impl Iterator<Item = (&PathStatus, &baseline::Baseline)> {
        self.paths
            .iter()
            .filter_map(|p| p.baseline.as_ref().map(|b| (p, b)))
            .filter(|(p, _)| !self.is_compromised(&p.entry))
    }
}

pub trait CovenantAttack: Sync {
    fn meta(&self) -> &'static AttackMeta;
    /// Lower runs first. Takeover attacks (whole path stolen) run before
    /// partial ones so the report names the root cause once.
    fn order(&self) -> u32 {
        100
    }
    /// Hostile transactions to try. `Err(reason)` = does not apply.
    fn attempts(&self, cx: &AttackCx) -> Result<Vec<Attempt>, String>;
}

pub struct CovenantPlugin(pub &'static dyn CovenantAttack);
inventory::collect!(CovenantPlugin);

pub fn registry() -> Vec<&'static dyn CovenantAttack> {
    let mut v: Vec<&'static dyn CovenantAttack> = inventory::iter::<CovenantPlugin>.into_iter().map(|p| p.0).collect();
    v.sort_by(|a, b| a.order().cmp(&b.order()).then(a.meta().id.cmp(b.meta().id)));
    v
}

/// Searches baselines for every path of `contract`, adds `imported` ones
/// (from `--baseline` files), and runs every selected attack.
pub fn run(contract: &Contract, only: &[String], imported: Vec<PathStatus>) -> RunReport {
    let started = Instant::now();
    let judge = Judge::new();
    let paths = baseline::search_all(contract, &judge);
    run_paths_timed(contract, only, paths, imported, vec![], started)
}

/// Runs the attacks on paths already searched (by `tune::tune`, say).
/// `extra_notes` are shown first in the report.
pub fn run_paths(
    contract: &Contract,
    only: &[String],
    paths: Vec<PathStatus>,
    imported: Vec<PathStatus>,
    extra_notes: Vec<String>,
) -> RunReport {
    run_paths_timed(contract, only, paths, imported, extra_notes, Instant::now())
}

/// As `run_paths`, with the report's clock started at `started` (before the search).
pub fn run_paths_timed(
    contract: &Contract,
    only: &[String],
    mut paths: Vec<PathStatus>,
    imported: Vec<PathStatus>,
    extra_notes: Vec<String>,
    started: Instant,
) -> RunReport {
    let judge = Judge::new();
    let imported_count = imported.len();
    paths.extend(imported);
    let cx = AttackCx { contract, judge: &judge, paths: &paths, compromised: RefCell::new(BTreeSet::new()) };

    let mut results = Vec::new();
    for attack in registry() {
        let meta = attack.meta();
        if !redteam_core::selected(meta, only) {
            continue;
        }
        let t = Instant::now();
        let outcome = match attack.attempts(&cx) {
            Err(reason) => Outcome::Skipped { reason },
            Ok(list) if list.is_empty() => {
                Outcome::Skipped { reason: "no explored path this attack applies to".into() }
            }
            Ok(list) => judge_attempts(&cx, meta, list),
        };
        results.push(AttackResult {
            id: meta.id.into(),
            pack: meta.pack.into(),
            target: Target::Covenant,
            title: meta.title.into(),
            outcome,
            millis: t.elapsed().as_millis(),
        });
    }

    let mut notes = extra_notes;
    let mut noted = BTreeSet::new();
    for p in &paths {
        let explored_somewhere = paths.iter().any(|q| q.name == p.name && q.baseline.is_some());
        if let Some(why) = &p.unexplored_reason {
            if !explored_somewhere && noted.insert(p.name.clone()) {
                notes.push(format!("path `{}` unexplored ({why}); attacks did not cover it", p.name));
            }
        }
    }
    let mut seen_states = Vec::new();
    for s in paths.iter().filter_map(|p| p.state.as_ref()) {
        if !seen_states.contains(&s) {
            seen_states.push(s);
        }
    }
    let states = seen_states.len();
    if states > 0 {
        notes.push(format!("stateful covenant: explored the start state and {states} later state(s)"));
    }
    if imported_count > 0 {
        notes.push(format!("{imported_count} baseline transaction(s) imported and attacked as given"));
    }
    if contract.has_covenant_decls {
        notes.push(
            "covenant declarations (#[covenant]) are searched and attacked like entries; no attack targets the continuation rules themselves yet".into(),
        );
    }
    if contract.zk_keys > 0 {
        notes.push(format!(
            "ZK: the script checks {} Groth16 proof(s). In the sandbox the tool swapped the verifying key for a test key of its own and used its test proof, so the paths could be spent. That tests everything around the proof (what it binds, replay, spending without one), not the circuit or whether the real key is the right one.",
            contract.zk_keys
        ));
    }
    notes.push("judge: rusty-kaspa consensus validator 2.1.0 in process (mempool relay policy not applied)".into());

    RunReport {
        tool_version: redteam_core::TOOL_VERSION.into(),
        library_version: redteam_core::LIBRARY_VERSION.into(),
        target: Target::Covenant,
        subject_name: contract.file_name.clone(),
        subject_hash: contract.subject_hash(),
        results,
        context: serde_json::json!({
            "contract": contract.contract_name,
            "constructor_args": contract.args,
            "spend_map": crate::spend_map(contract, &paths),
        }),
        notes,
        millis: started.elapsed().as_millis(),
    }
}

fn judge_attempts(cx: &AttackCx, meta: &'static AttackMeta, list: Vec<Attempt>) -> Outcome {
    let mut attempts = 0;
    let mut findings: Vec<Finding> = Vec::new();
    let mut hit_paths = BTreeSet::new();
    for a in list {
        // One finding per path per attack (the first accepted variant), and
        // nothing more on a path an earlier attack already took over.
        if hit_paths.contains(&a.path) || cx.is_compromised(&a.path) {
            continue;
        }
        attempts += 1;
        let (verdict, built) = cx.judge.run(cx.contract, &a.plan);
        if let (Verdict::Accepted { fee }, Some(b)) = (verdict, built) {
            hit_paths.insert(a.path.clone());
            if a.takeover {
                cx.compromised.borrow_mut().insert(a.path.clone());
            }
            // A stand-in coin is anyone-can-spend in the sandbox. On chain it is
            // spendable by whoever the real covenant at that address allows, so
            // say who the attacker really has to be.
            let mut explanation = a.explanation.clone();
            let stand_ins: Vec<String> = a
                .plan
                .inputs
                .iter()
                .filter_map(|i| match i {
                    crate::sandbox::InputSpec::StandIn { target, .. } => {
                        Some(cx.contract.stand_ins[*target].label.clone())
                    }
                    _ => None,
                })
                .collect();
            if !stand_ins.is_empty() {
                explanation.push_str(&format!(
                    " Note: the spend also uses a coin at `{}`'s address, which the sandbox lets anyone spend; on chain, only whoever can spend that coin can do this.",
                    stand_ins.join("`, `")
                ));
            }
            if a.plan.resigned_by_other(&cx.contract.wallets.attacker.keypair) {
                explanation.push_str(
                    " Note: here the attacker signs with the baseline's listed key, so this is what a user of the covenant holding that key (a buyer, a seller) can do; an outsider cannot.",
                );
            }
            findings.push(Finding {
                id: meta.id.into(),
                title: meta.title.into(),
                severity: a.severity.unwrap_or(meta.severity),
                target: Target::Covenant,
                subject: a.path.clone(),
                explanation,
                fix_pattern: meta.fix_pattern.into(),
                in_practice: meta.in_practice.into(),
                repro: crate::replay::repro_json(cx.contract, &a, &b, fee),
                location: crate::locate::locate(&cx.contract.source, &a.path, meta.id),
            });
        }
    }
    if attempts == 0 {
        Outcome::Skipped { reason: "every path it applies to was already taken over by an earlier finding".into() }
    } else if findings.is_empty() {
        Outcome::Survived { attempts }
    } else {
        Outcome::Found { attempts, findings }
    }
}
