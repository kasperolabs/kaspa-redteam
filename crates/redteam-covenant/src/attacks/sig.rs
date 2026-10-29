//! Pack `sig`: spending a signed path without the right signature.

use super::{map_covenant_args, pay_all_to_attacker};
use crate::runner::{AttackCx, Attempt, CovenantAttack, CovenantPlugin};
use crate::sandbox::ArgRecipe;
use crate::wallets::KeyRef;
use redteam_core::{AttackMeta, Severity, Target};
use silverscript_abi::ArtifactValue;

/// 64 zero bytes + SIGHASH_ALL: well-formed length, cryptographically invalid.
fn garbage_sig() -> Vec<u8> {
    let mut v = vec![0u8; 64];
    v.push(0x01);
    v
}

pub struct Sig01;
static SIG01: AttackMeta = AttackMeta {
    id: "SIG-01",
    pack: "sig",
    target: Target::Covenant,
    title: "Spend a signed path with an invalid signature",
    catches: "checkSig result computed but not enforced",
    severity: Severity::High,
    fix_pattern: "require(checkSig(sig, owner));  // never just evaluate checkSig",
};

impl CovenantAttack for Sig01 {
    fn meta(&self) -> &'static AttackMeta {
        &SIG01
    }
    fn order(&self) -> u32 {
        10
    }
    fn attempts(&self, cx: &AttackCx) -> Result<Vec<Attempt>, String> {
        let mut out = Vec::new();
        for (p, b) in cx.live_paths().filter(|(_, b)| b.plan.has_sig_recipe()) {
            let unsigned = map_covenant_args(&b.plan, |a| match a {
                ArgRecipe::Sig(_) => ArgRecipe::RawSig(garbage_sig()),
                ArgRecipe::SigBytes { prefix, .. } => {
                    let mut b = prefix.clone();
                    b.extend(garbage_sig());
                    ArgRecipe::Value(ArtifactValue::Bytes(b))
                }
                other => other.clone(),
            });
            out.push(Attempt {
                path: p.entry.clone(),
                label: "invalid signature, all value to attacker".into(),
                plan: pay_all_to_attacker(&unsigned),
                explanation: "consensus accepted an invalid signature on a signed path and let the attacker take the whole coin. The signature check runs but its result is not required.".into(),
                severity: None,
                takeover: true,
            });
            out.push(Attempt {
                path: p.entry.clone(),
                label: "invalid signature, honest outputs".into(),
                plan: unsigned,
                explanation: "anyone can trigger this path without the signer's signature. Outputs are still fixed by the covenant, so nothing is stolen, but the signer loses control of when it happens.".into(),
                severity: Some(Severity::Low),
                takeover: false,
            });
        }
        Ok(out)
    }
}
inventory::submit! { CovenantPlugin(&Sig01) }

pub struct Sig02;
static SIG02: AttackMeta = AttackMeta {
    id: "SIG-02",
    pack: "sig",
    target: Target::Covenant,
    title: "Sign with the attacker's own key",
    catches: "signature checked against a caller-supplied key, or the wrong field",
    severity: Severity::High,
    fix_pattern: "require(checkSig(sig, owner));  // owner is a constructor param, never an entry argument",
};

impl CovenantAttack for Sig02 {
    fn meta(&self) -> &'static AttackMeta {
        &SIG02
    }
    fn order(&self) -> u32 {
        11
    }
    fn attempts(&self, cx: &AttackCx) -> Result<Vec<Attempt>, String> {
        let attacker_pk = cx.contract.wallets.attacker.xonly().to_vec();
        let mut out = Vec::new();
        for (p, b) in cx.live_paths().filter(|(_, b)| b.plan.has_sig_recipe()) {
            // a) attacker signature, everything else as the honest spend
            let wrong_key = map_covenant_args(&b.plan, |a| match a {
                ArgRecipe::Sig(_) => ArgRecipe::Sig(KeyRef::Attacker),
                ArgRecipe::SigBytes { prefix, .. } => {
                    ArgRecipe::SigBytes { key: KeyRef::Attacker, prefix: prefix.clone() }
                }
                other => other.clone(),
            });
            out.push(Attempt {
                path: p.entry.clone(),
                label: "attacker's signature".into(),
                plan: pay_all_to_attacker(&wrong_key),
                explanation: "a signature from a key the covenant never named was accepted, and the attacker took the whole coin.".into(),
                severity: None,
                takeover: true,
            });
            // b) attacker signature AND attacker pubkey in every pubkey argument
            let c = cx.contract;
            let swapped = map_covenant_args(&wrong_key, |a| match a {
                ArgRecipe::Value(ArtifactValue::Bytes(bytes)) if bytes.len() == 32 && c.key_of(bytes).is_some() => {
                    ArgRecipe::Value(ArtifactValue::Bytes(attacker_pk.clone()))
                }
                other => other.clone(),
            });
            out.push(Attempt {
                path: p.entry.clone(),
                label: "attacker's signature and attacker's pubkey argument".into(),
                plan: pay_all_to_attacker(&swapped),
                explanation: "the path checks the signature against a pubkey the spender supplies, so anyone can pass their own key and signature and take the coin.".into(),
                severity: None,
                takeover: true,
            });
        }
        Ok(out)
    }
}
inventory::submit! { CovenantPlugin(&Sig02) }
