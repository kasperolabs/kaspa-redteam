//! Pack `fees`: value leaking to the miner.

use super::kas;
use crate::runner::{AttackCx, Attempt, CovenantAttack, CovenantPlugin};
use redteam_core::{AttackMeta, Severity, Target};

pub struct Fee01;
static FEE01: AttackMeta = AttackMeta {
    id: "FEE-01",
    pack: "fees",
    target: Target::Covenant,
    title: "Route value to the miner fee",
    catches: "no lower bound on what the outputs must carry",
    severity: Severity::Med,
    fix_pattern: "bound the fee: require(tx.outputs[0].value >= tx.inputs[this.activeInputIndex].value - MAX_FEE);",
};

impl CovenantAttack for Fee01 {
    fn meta(&self) -> &'static AttackMeta {
        &FEE01
    }
    fn order(&self) -> u32 {
        30
    }
    fn attempts(&self, cx: &AttackCx) -> Result<Vec<Attempt>, String> {
        Ok(cx
            .live_paths()
            .filter(|(_, b)| b.permissionless())
            .map(|(p, b)| {
                let mut plan = b.plan.clone();
                for o in plan.outputs.iter_mut() {
                    o.value /= 2;
                }
                let burned = b.plan.output_total() - plan.output_total();
                Attempt {
                    path: p.entry.clone(),
                    label: "every output halved, difference left as fee".into(),
                    plan,
                    explanation: format!(
                        "anyone can trigger this path with outputs worth half of what was intended; {} went to the miner as fee. A miner can do this to their own block and keep it.",
                        kas(burned)
                    ),
                    severity: None,
                    takeover: false,
                }
            })
            .collect())
    }
}
inventory::submit! { CovenantPlugin(&Fee01) }
