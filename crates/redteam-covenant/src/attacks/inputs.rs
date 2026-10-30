//! Pack `inputs`: several covenant coins in one transaction.

use super::kas;
use crate::runner::{AttackCx, Attempt, CovenantAttack, CovenantPlugin};
use crate::sandbox::{Dest, InputSpec, OutputSpec, SOMPI_PER_KAS};
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
    in_practice: "Two coins end up at the same address: a wallet sends the deposit twice (a double tap, a retry after a timeout), someone tops up, or two deals reuse the same terms. One spend then pays out once and the second coin goes to whoever built the transaction.",
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
            let Some(t) = b.plan.first_target() else { continue };
            let second = b.plan.inputs[t].duplicate();
            let extra = second.value();
            // a) the second coin to the attacker in an extra output
            let mut plan = b.plan.clone();
            plan.inputs.push(second.clone());
            plan.outputs.push(OutputSpec::new(extra, Dest::Key(KeyRef::Attacker)));
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

pub struct In02;
static IN02: AttackMeta = AttackMeta {
    id: "IN-02",
    pack: "inputs",
    target: Target::Covenant,
    title: "Attacker's coin at input 0, covenant moved behind it",
    catches: "values read from a fixed input index instead of this.activeInputIndex",
    severity: Severity::High,
    fix_pattern: "int current = tx.inputs[this.activeInputIndex].value;  // never tx.inputs[0] unless input 0 is pinned",
    in_practice: "Whoever spends puts a coin of their own first in the transaction. Rules that read input 0 now measure the attacker's coin instead of the covenant's, so they pass with the wrong numbers.",
};

impl CovenantAttack for In02 {
    fn meta(&self) -> &'static AttackMeta {
        &IN02
    }
    fn order(&self) -> u32 {
        41
    }
    fn attempts(&self, cx: &AttackCx) -> Result<Vec<Attempt>, String> {
        let mut out = Vec::new();
        for (p, b) in cx.live_paths().filter(|(_, b)| b.permissionless()) {
            let Some(t) = b.plan.first_target() else { continue };
            let cov_value = b.plan.inputs[t].value();
            let bait = SOMPI_PER_KAS / 2;
            if cov_value <= bait {
                continue;
            }
            let fee = b.plan.input_total().saturating_sub(b.plan.output_total());
            let mut plan = b.plan.clone();
            plan.inputs.insert(0, InputSpec::P2pk { owner: KeyRef::Attacker, value: bait });
            // Every honest output shrinks as if the covenant only held `bait`.
            for o in plan.outputs.iter_mut().filter(|o| !o.is_attackers()) {
                o.value = (o.value as u128 * bait as u128 / cov_value as u128) as u64;
            }
            let taken = plan.input_total().saturating_sub(plan.output_total()).saturating_sub(fee);
            if taken == 0 {
                continue;
            }
            plan.outputs.push(OutputSpec::new(taken, Dest::Key(KeyRef::Attacker)));
            out.push(Attempt {
                path: p.entry.clone(),
                label: "attacker coin at input 0, outputs sized to it, rest to attacker".into(),
                plan,
                explanation: format!(
                    "the attacker put a {} coin of their own at input 0. The covenant measured its outputs against that coin instead of itself, so it paid out as if it held {} and the attacker took {}.",
                    kas(bait),
                    kas(bait),
                    kas(taken)
                ),
                severity: None,
                takeover: false,
            });
        }
        Ok(out)
    }
}
inventory::submit! { CovenantPlugin(&In02) }
