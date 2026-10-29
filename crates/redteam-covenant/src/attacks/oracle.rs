//! Pack `oracle`: paths that accept a signed reading (`checkMsgSig`).

use super::{map_covenant_args, pay_all_to_attacker};
use crate::runner::{AttackCx, Attempt, CovenantAttack, CovenantPlugin};
use crate::sandbox::ArgRecipe;
use crate::wallets::KeyRef;
use redteam_core::{AttackMeta, Severity, Target};
use silverscript_abi::ArtifactValue;

pub struct Orc04;
static ORC04: AttackMeta = AttackMeta {
    id: "ORC-04",
    pack: "oracle",
    target: Target::Covenant,
    title: "Reading signed by the attacker's own key",
    catches: "oracle or conductor key not pinned",
    severity: Severity::High,
    fix_pattern: "require(checkMsgSig(s, byte[32](blake2b(msg)), conductor));  // conductor is a constructor param",
};

impl CovenantAttack for Orc04 {
    fn meta(&self) -> &'static AttackMeta {
        &ORC04
    }
    fn order(&self) -> u32 {
        14
    }
    fn attempts(&self, cx: &AttackCx) -> Result<Vec<Attempt>, String> {
        let c = cx.contract;
        let attacker_pk = c.wallets.attacker.xonly().to_vec();
        let mut out = Vec::new();
        for (p, b) in cx.live_paths().filter(|(_, b)| b.permissionless() && b.plan.has_datasig_recipe()) {
            let forged = map_covenant_args(&b.plan, |a| match a {
                ArgRecipe::DataSigOf { arg, hash, .. } => {
                    ArgRecipe::DataSigOf { key: KeyRef::Attacker, arg: *arg, hash: *hash }
                }
                other => other.clone(),
            });
            out.push(Attempt {
                path: p.entry.clone(),
                label: "reading signed by attacker, all value to attacker".into(),
                plan: pay_all_to_attacker(&forged),
                explanation: "a reading signed by a key the covenant never named was accepted, and the attacker took the whole coin.".into(),
                severity: None,
                takeover: true,
            });
            let swapped = map_covenant_args(&forged, |a| match a {
                ArgRecipe::Value(ArtifactValue::Bytes(bytes)) if bytes.len() == 32 && c.key_of(bytes).is_some() => {
                    ArgRecipe::Value(ArtifactValue::Bytes(attacker_pk.clone()))
                }
                other => other.clone(),
            });
            out.push(Attempt {
                path: p.entry.clone(),
                label: "reading and signer key both supplied by attacker".into(),
                plan: pay_all_to_attacker(&swapped),
                explanation: "the path verifies the reading against a key the spender passes in, so anyone can sign their own reading and take the coin.".into(),
                severity: None,
                takeover: true,
            });
            out.push(Attempt {
                path: p.entry.clone(),
                label: "reading signed by attacker, honest outputs".into(),
                plan: forged.clone(),
                explanation: "anyone can trigger this path with a reading they signed themselves. The outputs are still pinned, so nothing is stolen, but the conductor or oracle no longer decides when it happens.".into(),
                severity: Some(Severity::Low),
                takeover: false,
            });
            out.push(Attempt {
                path: p.entry.clone(),
                label: "reading and signer key supplied by attacker, honest outputs".into(),
                plan: swapped,
                explanation: "anyone can trigger this path with a reading they signed themselves. The outputs are still pinned, so nothing is stolen, but the conductor or oracle no longer decides when it happens.".into(),
                severity: Some(Severity::Low),
                takeover: false,
            });
        }
        Ok(out)
    }
}
inventory::submit! { CovenantPlugin(&Orc04) }
