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
pub mod contract;
pub mod replay;
pub mod runner;
pub mod sandbox;
pub mod script;
pub mod wallets;

use baseline::PathStatus;
use contract::Contract;
use sandbox::{COVENANT_VALUE, Dest, SOMPI_PER_KAS};

pub use runner::{AttackCx, Attempt, CovenantAttack, CovenantPlugin, registry, run};

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

/// Plain-language map of who can spend each path and where the money went in
/// the honest spend the search found.
pub fn spend_map(c: &Contract, paths: &[PathStatus]) -> serde_json::Value {
    let rows: Vec<_> = paths
        .iter()
        .map(|p| {
            let summary = match &p.baseline {
                None => format!(
                    "unexplored: {}",
                    p.unexplored_reason.clone().unwrap_or_default()
                ),
                Some(b) => {
                    let who = if b.signers.contains(&wallets::KeyRef::Attacker) {
                        "anyone with any key (the covenant names no key for this path)".to_string()
                    } else if !b.signers.is_empty() {
                        let names: Vec<_> = b.signers.iter().map(|k| c.wallets.label(*k)).collect();
                        format!("signed by {}", names.join(" + "))
                    } else if !b.secrets.is_empty() {
                        format!(
                            "anyone who knows secret `{}` (no signature)",
                            b.secrets.join("`, `")
                        )
                    } else {
                        "anyone, no signature".to_string()
                    };
                    let pays: Vec<_> = b
                        .plan
                        .outputs
                        .iter()
                        .map(|o| {
                            let to = match &o.to {
                                Dest::Key(k) => c.wallets.label(*k),
                                Dest::SelfCovenant => "the covenant (change)".into(),
                            };
                            format!("{} to {to}", kas(o.value))
                        })
                        .collect();
                    let lock = b
                        .lock
                        .as_ref()
                        .map(|l| {
                            format!(
                                "; needs {} >= {} (earliest accepted {})",
                                l.field, l.used, l.earliest
                            )
                        })
                        .unwrap_or_default();
                    format!(
                        "{who}; from a {} coin pays {}{lock}",
                        kas(COVENANT_VALUE),
                        pays.join(", ")
                    )
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
