//! Pack `outputs`: permissionless paths whose outputs are not fully pinned.
//!
//! These attacks only touch paths that need no signature (anyone, or anyone
//! who has seen the revealed secret, can build the spend). A signed path's
//! outputs are protected by the signer's SIGHASH_ALL signature, so an outsider
//! cannot change them.

use super::{kas, pay_all_to_attacker};
use crate::runner::{AttackCx, Attempt, CovenantAttack, CovenantPlugin};
use crate::sandbox::{Dest, OutputSpec};
use crate::wallets::KeyRef;
use redteam_core::{AttackMeta, Severity, Target};

fn dest_label(cx: &AttackCx, d: &Dest) -> String {
    crate::dest_label(cx.contract, d)
}

pub struct Out01;
static OUT01: AttackMeta = AttackMeta {
    id: "OUT-01",
    pack: "outputs",
    target: Target::Covenant,
    title: "Correct value, attacker's script",
    catches: "output script (recipient) not constrained",
    severity: Severity::High,
    fix_pattern: "require(tx.outputs[0].scriptPubKey == byte[](new ScriptPubKeyP2PK(payee)));",
};

impl CovenantAttack for Out01 {
    fn meta(&self) -> &'static AttackMeta {
        &OUT01
    }
    fn order(&self) -> u32 {
        13
    }
    fn attempts(&self, cx: &AttackCx) -> Result<Vec<Attempt>, String> {
        let mut out = Vec::new();
        for (p, b) in cx.live_paths().filter(|(_, b)| b.permissionless() && b.secrets.is_empty()) {
            out.push(Attempt {
                path: p.entry.clone(),
                label: "every output replaced by one attacker output".into(),
                plan: pay_all_to_attacker(&b.plan),
                explanation: "this path needs no signature and does not pin where the money goes: anyone can spend the whole coin to themselves.".into(),
                severity: None,
                takeover: true,
            });
            for j in 0..b.plan.outputs.len() {
                let mut plan = b.plan.clone();
                let was = dest_label(cx, &plan.outputs[j].to);
                plan.outputs[j].to = Dest::Key(KeyRef::Attacker);
                out.push(Attempt {
                    path: p.entry.clone(),
                    label: format!("output {j} redirected to attacker"),
                    plan,
                    explanation: format!(
                        "this path needs no signature and does not check the recipient of output {j}: the {} meant for {was} can be redirected to anyone.",
                        kas(b.plan.outputs[j].value)
                    ),
                    severity: None,
                    takeover: b.plan.outputs.len() == 1,
                });
            }
        }
        Ok(out)
    }
}
inventory::submit! { CovenantPlugin(&Out01) }

pub struct Out02;
static OUT02: AttackMeta = AttackMeta {
    id: "OUT-02",
    pack: "outputs",
    target: Target::Covenant,
    title: "Correct script, reduced value",
    catches: "output value not constrained",
    severity: Severity::High,
    fix_pattern: "require(tx.outputs[0].value >= expectedAmount);",
};

impl CovenantAttack for Out02 {
    fn meta(&self) -> &'static AttackMeta {
        &OUT02
    }
    fn order(&self) -> u32 {
        20
    }
    fn attempts(&self, cx: &AttackCx) -> Result<Vec<Attempt>, String> {
        let mut out = Vec::new();
        for (p, b) in cx.live_paths().filter(|(_, b)| b.permissionless()) {
            let mut plan = b.plan.clone();
            let honest = plan.outputs[0].value;
            let reduced = (honest / 10).max(10_000);
            if reduced >= honest {
                continue;
            }
            plan.outputs[0].value = reduced;
            plan.outputs.push(OutputSpec::new(honest - reduced, Dest::Key(KeyRef::Attacker)));
            out.push(Attempt {
                path: p.entry.clone(),
                label: "output 0 cut to 10%, difference to attacker".into(),
                plan,
                explanation: format!(
                    "output 0 keeps its recipient ({}) but its value is not checked: it was paid {} instead of {} and the attacker took the {} difference.",
                    dest_label(cx, &b.plan.outputs[0].to),
                    kas(reduced),
                    kas(honest),
                    kas(honest - reduced)
                ),
                severity: None,
                takeover: false,
            });
        }
        Ok(out)
    }
}
inventory::submit! { CovenantPlugin(&Out02) }

pub struct Out03;
static OUT03: AttackMeta = AttackMeta {
    id: "OUT-03",
    pack: "outputs",
    target: Target::Covenant,
    title: "Valid output 0, skim a later output",
    catches: "only the first output checked",
    severity: Severity::High,
    fix_pattern: "check every output the path creates, e.g. require(tx.outputs[1].value >= change && tx.outputs[1].scriptPubKey == tx.inputs[this.activeInputIndex].scriptPubKey);",
};

impl CovenantAttack for Out03 {
    fn meta(&self) -> &'static AttackMeta {
        &OUT03
    }
    fn order(&self) -> u32 {
        21
    }
    fn attempts(&self, cx: &AttackCx) -> Result<Vec<Attempt>, String> {
        let mut out = Vec::new();
        let mut any_multi = false;
        for (p, b) in cx.live_paths().filter(|(_, b)| b.permissionless()) {
            if b.plan.outputs.len() < 2 {
                continue;
            }
            any_multi = true;
            for j in 1..b.plan.outputs.len() {
                let mut plan = b.plan.clone();
                let honest = plan.outputs[j].value;
                let half = honest / 2;
                plan.outputs[j].value = honest - half;
                plan.outputs.push(OutputSpec::new(half, Dest::Key(KeyRef::Attacker)));
                out.push(Attempt {
                    path: p.entry.clone(),
                    label: format!("output 0 untouched, output {j} halved, half to attacker"),
                    plan,
                    explanation: format!(
                        "output 0 is checked but output {j} ({} to {}) is not: the attacker skimmed {} from it.",
                        kas(honest),
                        dest_label(cx, &b.plan.outputs[j].to),
                        kas(half)
                    ),
                    severity: None,
                    takeover: false,
                });
            }
        }
        if !any_multi && out.is_empty() {
            return Err("no explored permissionless path creates more than one output".into());
        }
        Ok(out)
    }
}
inventory::submit! { CovenantPlugin(&Out03) }
