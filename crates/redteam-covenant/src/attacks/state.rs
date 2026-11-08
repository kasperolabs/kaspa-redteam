//! Pack `state`: what the next state of a stateful covenant records.
//!
//! A coin's owner, beneficiary or admin often lives in its state (a token's
//! `owner`, a vault's `beneficiary`). If anyone can spend the coin and choose
//! the next state freely, the attacker writes their own key there and owns it.

use crate::runner::{AttackCx, Attempt, CovenantAttack, CovenantPlugin};
use crate::sandbox::{Dest, SpendPlan};
use crate::wallets::KeyRef;
use redteam_core::{AttackMeta, Severity, Target};
use silverscript_abi::{ArtifactValue, TypeArtifact};

pub struct St01;
static ST01: AttackMeta = AttackMeta {
    id: "ST-01",
    pack: "state",
    target: Target::Covenant,
    title: "Rewrite the recorded owner of the next state",
    catches: "next state's owner/key field chosen by whoever spends, with no signature from the current owner",
    severity: Severity::High,
    fix_pattern: "require(checkSig(sig(byte[65](witness)), pubkey(owner)));  // the current owner signs any change of hands",
    in_practice: "A stranger spends the coin through a path anyone may use and writes their own key as the new owner. From then on the coin, or the name or seat it stands for, is theirs.",
};

impl CovenantAttack for St01 {
    fn meta(&self) -> &'static AttackMeta {
        &ST01
    }
    fn order(&self) -> u32 {
        12
    }
    fn attempts(&self, cx: &AttackCx) -> Result<Vec<Attempt>, String> {
        let c = cx.contract;
        let attacker = c.wallets.attacker.xonly().to_vec();
        // State fields that hold a key: 32-byte values that are a party's key.
        let key_fields: Vec<&String> = c
            .state_fields
            .iter()
            .filter(|(_, ty)| matches!(ty, TypeArtifact::FixedBytes { len: 32 } | TypeArtifact::Pubkey))
            .map(|(n, _)| n)
            .collect();
        let mut out = Vec::new();
        for (p, b) in cx.live_paths().filter(|(_, b)| b.permissionless()) {
            for (j, o) in b.plan.outputs.iter().enumerate() {
                let Dest::Successor(st) = &o.to else { continue };
                for f in &key_fields {
                    let Some(ArtifactValue::Bytes(v)) = st.get(*f) else { continue };
                    if c.key_of(v).is_none() || *v == attacker {
                        continue;
                    }
                    // Arguments that named the honest owner (`transfer(new_owner)`)
                    // name the attacker too, so the next state stays consistent.
                    let old = v.clone();
                    let mut plan = super::map_covenant_args(&b.plan, |a| match a {
                        crate::sandbox::ArgRecipe::Value(ArtifactValue::Bytes(x)) if *x == old => {
                            crate::sandbox::ArgRecipe::Value(ArtifactValue::Bytes(attacker.clone()))
                        }
                        other => other.clone(),
                    });
                    let mut next = st.clone();
                    next.insert((*f).clone(), ArtifactValue::Bytes(attacker.clone()));
                    plan.outputs[j].to = Dest::Successor(next);
                    // A sibling coin the spender creates and pays for (a split
                    // naming the new coin's owner): owning it gives the spender
                    // nothing it did not pay in, as long as the covenant's own
                    // value stays in its other coins. Then the test is whether
                    // the covenant's value can be moved into that coin.
                    if let Some(shifted) = funded_by_spender(&plan, j, &cx.contract.wallets.attacker.keypair) {
                        cx.note(format!(
                            "ST-01 on `{}`: output {j} is a new coin the spender funds (`{f}` names its owner); owning it gives nothing the spender did not pay for, so the test was whether the covenant's own value can be moved into it",
                            p.entry
                        ));
                        out.push(Attempt {
                            path: p.entry.clone(),
                            label: format!("output {j}: `{f}` rewritten to the attacker's key, with the covenant's value moved into it"),
                            plan: shifted.0,
                            explanation: format!(
                                "anyone can spend this coin, write their own key into `{f}` of the new coin at output {j}, and move {} of the covenant's value into it from output {}: the attacker now owns covenant value it did not pay for.",
                                super::kas(shifted.2),
                                shifted.1
                            ),
                            severity: None,
                            takeover: true,
                            benign: None,
                        });
                        continue;
                    }
                    out.push(Attempt {
                        path: p.entry.clone(),
                        label: format!("output {j}: `{f}` rewritten to the attacker's key"),
                        plan,
                        explanation: format!(
                            "anyone can spend this coin and write their own key into `{f}` of the next state (output {j}): the attacker now controls a coin worth {}, and whatever it records.",
                            super::kas(o.value)
                        ),
                        severity: None,
                        takeover: true,
                        benign: None,
                    });
                }
            }
        }
        if out.is_empty() {
            return Err("no explored permissionless path carries a key in its next state".into());
        }
        Ok(out)
    }
}
inventory::submit! { CovenantPlugin(&St01) }

/// When output `j` of `plan` is a coin the spender's own inputs pay for
/// (`super::spender_funded`), the same spend with part of the covenant's value
/// moved from its largest other coin into `j` and the spender's own money
/// given back as change: (plan, the other output, amount).
fn funded_by_spender(plan: &SpendPlan, j: usize, attacker: &secp256k1::Keypair) -> Option<(SpendPlan, usize, u64)> {
    if !super::spender_funded(plan, j, attacker) {
        return None;
    }
    let is_cov = |o: &crate::sandbox::OutputSpec| matches!(o.to, Dest::Successor(_) | Dest::SelfCovenant);
    let vj = plan.outputs[j].value;
    let (k, ok) = plan.outputs.iter().enumerate().filter(|(k, o)| *k != j && is_cov(o)).max_by_key(|(_, o)| o.value)?;
    let delta = vj.min(ok.value / 2);
    if delta == 0 {
        return None;
    }
    let mut p = plan.clone();
    p.outputs[k].value -= delta;
    p.outputs.push(crate::sandbox::OutputSpec::new(delta, Dest::Key(KeyRef::Attacker)));
    Some((p, k, delta))
}
