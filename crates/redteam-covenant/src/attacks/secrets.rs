//! Pack `secrets`: hash-lock paths that trust the secret alone.

use super::pay_all_to_attacker;
use crate::runner::{AttackCx, Attempt, CovenantAttack, CovenantPlugin};
use redteam_core::{AttackMeta, Severity, Target};

pub struct Sec01;
static SEC01: AttackMeta = AttackMeta {
    id: "SEC-01",
    pack: "secrets",
    target: Target::Covenant,
    title: "Front-run a revealed secret",
    catches: "hash-lock path with no signature and no fixed recipient",
    severity: Severity::High,
    fix_pattern: "require(sha256(secret) == hash && checkSig(sig, claimer));  // or pin the output to a recipient fixed at deploy",
};

impl CovenantAttack for Sec01 {
    fn meta(&self) -> &'static AttackMeta {
        &SEC01
    }
    fn order(&self) -> u32 {
        12
    }
    fn attempts(&self, cx: &AttackCx) -> Result<Vec<Attempt>, String> {
        Ok(cx
            .live_paths()
            .filter(|(_, b)| b.permissionless() && !b.secrets.is_empty())
            .map(|(p, b)| Attempt {
                path: p.entry.clone(),
                label: "honest claim's secret reused, all value to attacker".into(),
                plan: pay_all_to_attacker(&b.plan),
                explanation: format!(
                    "the path only checks the secret (`{}`). The honest claim puts the secret in the mempool; anyone who sees it can broadcast this competing spend to their own address with a higher fee.",
                    b.secrets.join("`, `")
                ),
                severity: None,
                takeover: true,
            })
            .collect())
    }
}
inventory::submit! { CovenantPlugin(&Sec01) }
