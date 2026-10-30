//! Covenant engine.
//!
//! Pipeline: parse + compile the `.sil` in process (silverscript-lang), give
//! every pubkey constructor argument a test key, search an honest spend for
//! each path, then run every attack plugin against those baselines. Each
//! hostile transaction is signed for real and judged by rusty-kaspa's
//! consensus validator. A finding is a transaction consensus accepted that the
//! attack expected it to reject.

pub mod attacks;
pub mod baseline;
pub mod compiled;
pub mod contract;
pub mod ctor_file;
pub mod import;
pub mod legacy;
pub mod project;
pub mod replay;
pub mod runner;
pub mod sandbox;
pub mod script;
pub mod tune;
pub mod wallets;
pub mod zk;

use baseline::PathStatus;
use contract::Contract;
use sandbox::{Dest, SOMPI_PER_KAS};

pub use runner::{AttackCx, Attempt, CovenantAttack, CovenantPlugin, registry, run, run_paths, run_paths_timed};

pub fn kas(sompi: u64) -> String {
    let whole = sompi / SOMPI_PER_KAS;
    let frac = sompi % SOMPI_PER_KAS;
    if frac == 0 {
        format!("{whole} KAS")
    } else {
        let s = format!("{whole}.{frac:08}");
        format!("{} KAS", s.trim_end_matches('0'))
    }
}

/// Who an output pays, in words.
pub fn dest_label(c: &Contract, d: &Dest) -> String {
    match d {
        Dest::Key(k) => c.wallets.label(*k),
        Dest::SelfCovenant => "the covenant (change)".into(),
        Dest::Successor(st) => format!("the covenant, next state [{}]", baseline::state_label(c, st)),
        Dest::StandIn(i) => format!("{} (its P2SH address)", c.stand_ins[*i].label),
        Dest::Raw(spk) => {
            let hex = faster_hex::hex_string(spk.script());
            format!("script {}..", &hex[..hex.len().min(16)])
        }
    }
}

/// Plain-language map of who can spend each path and where the money went in
/// the honest spend the search found. Entries never explored in any state are
/// listed once with the reason.
pub fn spend_map(c: &Contract, paths: &[PathStatus]) -> serde_json::Value {
    let explored = |name: &str| paths.iter().any(|p| p.name == name && p.baseline.is_some());
    let mut shown_unexplored = std::collections::BTreeSet::new();
    let rows: Vec<_> = paths
        .iter()
        .filter(|p| p.baseline.is_some() || (!explored(&p.name) && shown_unexplored.insert(p.name.clone())))
        .map(|p| {
            let summary = match &p.baseline {
                None => format!("unexplored: {}", p.unexplored_reason.clone().unwrap_or_default()),
                Some(b) => {
                    let who = if b.signers.contains(&wallets::KeyRef::Attacker) {
                        "anyone with any key (the covenant names no key for this path)".to_string()
                    } else if !b.signers.is_empty() {
                        let names: Vec<_> = b.signers.iter().map(|k| c.wallets.label(*k)).collect();
                        format!("signed by {}", names.join(" + "))
                    } else if b.plan.has_resigned() {
                        "a user holding the baseline's listed key (the tool re-signs)".to_string()
                    } else if !b.secrets.is_empty() {
                        if b.secrets.iter().any(|s| s.contains("test proof")) {
                            "anyone holding a valid proof, which every spend reveals (the tool used its test proof; no transaction signature)".to_string()
                        } else {
                            format!("anyone who knows the secret behind {} (no transaction signature)", b.secrets.join(" + "))
                        }
                    } else {
                        "anyone, no signature".to_string()
                    };
                    let pays: Vec<_> = b
                        .plan
                        .outputs
                        .iter()
                        .map(|o| format!("{} to {}", kas(o.value), dest_label(c, &o.to)))
                        .collect();
                    let lock = b
                        .lock
                        .as_ref()
                        .map(|l| format!("; needs {} >= {} (earliest accepted {})", l.field, l.used, l.earliest))
                        .unwrap_or_default();
                    let from = if b.plan.inputs.len() > 1 {
                        format!("{} inputs worth {}", b.plan.inputs.len(), kas(b.plan.input_total()))
                    } else {
                        format!("a {} coin", kas(b.plan.input_total()))
                    };
                    let origin = if p.imported { " [imported]" } else { "" };
                    format!("{who}; from {from} pays {}{lock}{origin}", pays.join(", "))
                }
            };
            serde_json::json!({
                "path": p.entry,
                "explored": p.baseline.is_some(),
                "search_tries": p.tries,
                "summary": summary,
            })
        })
        .collect();
    serde_json::Value::Array(rows)
}

/// `REDTEAM_DEBUG=1`: print search progress and rejection reasons to stderr.
pub fn debug_on() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("REDTEAM_DEBUG").is_some())
}
