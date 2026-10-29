//! Pack `inputs`: several covenant coins in one transaction.

use super::kas;
use crate::runner::{AttackCx, Attempt, CovenantAttack, CovenantPlugin};
use crate::sandbox::{Dest, OutputSpec};
use crate::wallets::KeyRef;
use redteam_core::{AttackMeta, Severity, Target};

pub struct In01;
static IN01: AttackMeta = AttackMeta {
    id: "IN-01",
    pack: "inputs",
    target: Target::Covenant,
    title: "Two covenant coins, one shared set of outputs",
    catches: "output checks not tied to the active input (double counting)",
    severity: Severity::High,
    fix_pattern: "require(tx.inputs.length == 1);  // or check outputs relative to this.activeInputIndex",
};

impl CovenantAttack for In01 {
    fn meta(&self) -> &'static AttackMeta {
        &IN01
    }
    fn order(&self) -> u32 {
        40
    }
    fn attempts(&self, cx: &AttackCx) -> Result<Vec<Attempt>, String> {
        let mut out = Vec::new();
        for (p, b) in cx.live_paths().filter(|(_, b)| b.permissionless()) {
            let second = b.plan.inputs[0].clone();
            let extra = second.value();
            // a) the second coin to the attacker in an extra output
            let mut plan = b.plan.clone();
            plan.inputs.push(second.clone());
            plan.outputs.push(OutputSpec {
                value: extra,
                to: Dest::Key(KeyRef::Attacker),
            });
            out.push(Attempt {
                path: p.entry.clone(),
                label: "second covenant coin added, its value to attacker".into(),
                plan,
                explanation: format!(
                    "two coins of this covenant were spent together. Both inputs ran the path and both were satisfied by the same outputs, so the second coin ({}) went to the attacker.",
                    kas(extra)
                ),
                severity: None,
                takeover: false,
            });
            // b) no room for an extra output: the second coin becomes fee
            let mut plan = b.plan.clone();
            plan.inputs.push(second);
            out.push(Attempt {
                path: p.entry.clone(),
                label: "second covenant coin added, its value left as fee".into(),
                plan,
                explanation: format!(
                    "two coins of this covenant were spent together and both were satisfied by the outputs meant for one, so the whole second coin ({}) became fee. A miner can do this in their own block and keep it.",
                    kas(extra)
                ),
                severity: Some(Severity::Med),
                takeover: false,
            });
        }
        Ok(out)
    }
}
inventory::submit! { CovenantPlugin(&In01) }
