//! Pack `state`: what the next state of a stateful covenant records.
//!
//! A coin's owner, beneficiary or admin often lives in its state (a token's
//! `owner`, a vault's `beneficiary`). If anyone can spend the coin and choose
//! the next state freely, the attacker writes their own key there and owns it.

use crate::runner::{AttackCx, Attempt, CovenantAttack, CovenantPlugin};
use crate::sandbox::Dest;
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
