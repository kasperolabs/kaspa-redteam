//! Tier 1 covenant attacks. One file per pack; each attack registers itself
//! with `inventory::submit!`, so a new file plus a `mod` line is all it takes.
//!
//! Threat model for Tier 1: the attacker holds only their own key, can read
//! the chain and the mempool (so any secret revealed by a pending spend is
//! known), and can build any transaction. Insiders abusing their own
//! signature (a payee taking more than their share) need roles, which is
//! Tier 2.

pub mod family;
pub mod fee;
pub mod inputs;
pub mod oracle;
pub mod outputs;
pub mod secrets;
pub mod sig;
pub mod state;

use crate::sandbox::{ArgRecipe, Dest, InputSpec, OutputSpec, SpendPlan};
use crate::wallets::KeyRef;

/// Every input's value to a single attacker output, the honest spend's fee kept.
pub(crate) fn pay_all_to_attacker(plan: &SpendPlan) -> SpendPlan {
    let mut p = plan.clone();
    let fee = p.input_total().saturating_sub(p.output_total()).max(1);
    p.outputs = vec![OutputSpec::new(p.input_total() - fee, Dest::Key(KeyRef::Attacker))];
    p
}

pub(crate) fn map_covenant_args(plan: &SpendPlan, f: impl Fn(&ArgRecipe) -> ArgRecipe) -> SpendPlan {
    let mut p = plan.clone();
    for i in p.inputs.iter_mut() {
        if let InputSpec::Covenant { args, .. } = i {
            *args = args.iter().map(&f).collect();
        }
    }
    p
}

/// Output `j` is a new covenant coin the spender pays for: a sibling the
/// caller creates (a split naming the new coin's owner), not the covenant's
/// value. The covenant's other coins already carry every sompi of the covenant
/// inputs, and the spender's own inputs paid in at least `j`'s value.
pub(crate) fn spender_funded(plan: &SpendPlan, j: usize, attacker: &secp256k1::Keypair) -> bool {
    let is_cov = |o: &OutputSpec| matches!(o.to, Dest::Successor(_) | Dest::SelfCovenant);
    let Some(oj) = plan.outputs.get(j) else { return false };
    if !is_cov(oj) {
        return false;
    }
    let covenant_in: u64 = plan.inputs.iter().filter(|i| i.is_target()).map(|i| i.value()).sum();
    let elsewhere: u64 = plan.outputs.iter().enumerate().filter(|(k, o)| *k != j && is_cov(o)).map(|(_, o)| o.value).sum();
    let own_in = plan.attacker_input_total(attacker);
    covenant_in > 0 && elsewhere >= covenant_in && own_in >= oj.value
}

/// What the signer's own coins paid into a spend: the attacker's plain coins
/// and every coin a listed baseline key signs for (signed again after each change).
pub(crate) fn signer_input_total(plan: &SpendPlan) -> u64 {
    plan.inputs
        .iter()
        .map(|i| match i {
            InputSpec::P2pk { owner: KeyRef::Attacker, value } => *value,
            InputSpec::Raw(r) if r.resign.is_some() => r.entry.amount,
            _ => 0,
        })
        .sum()
}

/// The coins of an imported spend that belong to someone other than the
/// signer: covenant coins and partner cells no listed key signs for, and plain
/// coins kept as given. None for a spend the search built (not imported).
fn foreign_inputs(plan: &SpendPlan) -> Option<Vec<&crate::sandbox::RawInput>> {
    let mut out = Vec::new();
    for i in &plan.inputs {
        match i {
            InputSpec::Raw(r) if r.resign.is_none() => out.push(r),
            InputSpec::Raw(_) | InputSpec::P2pk { owner: KeyRef::Attacker, .. } => {}
            _ => return None,
        }
    }
    Some(out)
}

/// The bytes that name an output's recipient: a P2PK key, a P2SH hash, or the script.
fn recipient_bytes(spk: &kaspa_consensus_core::tx::ScriptPublicKey) -> Vec<u8> {
    let s = spk.script();
    if s.len() == 34 && s[0] == 0x20 && s[33] == 0xac {
        s[1..33].to_vec()
    } else if s.len() == 35 && s[0] == 0xaa && s[1] == 0x20 && s[34] == 0x87 {
        s[2..34].to_vec()
    } else {
        s.to_vec()
    }
}

/// Output `j` of an imported spend is a payment the signer makes from its own
/// coins, not value a covenant hands over: every coin in the spend is the
/// signer's, or the output is a plain payment (no covenant binding) to an
/// address no one else's coin in the spend names, and the signer's own coins
/// paid in at least its value. Shortening or redirecting it is the signer
/// choosing what to pay. The reason, for the report.
pub(crate) fn signers_own_payment(plan: &SpendPlan, j: usize) -> Option<String> {
    let foreign = foreign_inputs(plan)?;
    let o = plan.outputs.get(j)?;
    let mine = signer_input_total(plan);
    if mine == 0 || mine < o.value {
        return None;
    }
    if foreign.is_empty() {
        return Some(format!("paid from the signer's own coins: every coin this spend uses is the signer's, so output {j} is a payment the signer chose"));
    }
    if let Some(binding) = &o.covenant {
        // A new coin of a covenant family (a token cell the signer sends to
        // someone): its KAS is the signer's when the family's other new coins
        // already carry all the KAS the family's coins brought in.
        let id = binding.covenant_id;
        let family_in: u64 = plan
            .inputs
            .iter()
            .filter_map(|i| match i {
                InputSpec::Raw(r) if r.entry.covenant_id == Some(id) => Some(r.entry.amount),
                _ => None,
            })
            .sum();
        let family_out: u64 = plan
            .outputs
            .iter()
            .enumerate()
            .filter(|(k, x)| *k != j && x.covenant.as_ref().is_some_and(|c| c.covenant_id == id))
            .map(|(_, x)| x.value)
            .sum();
        if family_in == 0 || family_out < family_in {
            return None;
        }
        return Some(format!(
            "paid from the signer's own coins: output {j} is a new coin of a covenant family whose other new coins already carry all the KAS its coins brought in, so its {} came from the signer",
            kas(o.value)
        ));
    }
    let Dest::Raw(spk) = &o.to else { return None };
    let who = recipient_bytes(spk);
    // Only what the other coins' programs and states say counts (the redeem
    // script, the last push); arguments are the spender's own choice.
    let named = |r: &crate::sandbox::RawInput| {
        let program = crate::known::pushes(&r.signature_script)
            .and_then(|p| p.last().map(|(_, d)| d.clone()))
            .unwrap_or_else(|| r.signature_script.clone());
        program.windows(who.len()).any(|w| w == who.as_slice()) || r.entry.script_public_key.script().windows(who.len()).any(|w| w == who.as_slice())
    };
    if who.len() < 20 || foreign.iter().any(|r| named(r)) {
        return None;
    }
    Some(format!(
        "paid from the signer's own coins: output {j} pays an address no other coin's program or state in the spend names, and the signer's coins paid in more than it carries"
    ))
}

/// Every coin of an imported spend is the signer's.
pub(crate) fn all_signers_own(plan: &SpendPlan) -> bool {
    signer_input_total(plan) > 0 && foreign_inputs(plan).is_some_and(|f| f.is_empty())
}

/// A leftover the covenant itself names: the smallest number in the state of a
/// covenant coin under test, named as a tip, fee or budget (`refundTip`,
/// `keeperTip`, `max_extra`, `maxFee`), that covers `left`. Name, value, what it is.
pub(crate) fn designed_leftover(plan: &SpendPlan, left: u64) -> Option<(String, u64, &'static str)> {
    let mut best: Option<(String, u64, &'static str)> = None;
    for i in &plan.inputs {
        let InputSpec::Raw(r) = i else { continue };
        if !r.target {
            continue;
        }
        for (name, v) in &r.named {
            let n = name.to_ascii_lowercase();
            let what = if n.contains("tip") {
                "a tip the covenant pays whoever spends it"
            } else if n.contains("fee") {
                "a fee the covenant allows"
            } else if n.contains("extra") || n.contains("budget") {
                "a budget the covenant gives its spender"
            } else {
                continue;
            };
            if *v <= 0 || (*v as u64) < left {
                continue;
            }
            if best.as_ref().is_none_or(|(_, b, _)| (*v as u64) < *b) {
                best = Some((name.clone(), *v as u64, what));
            }
        }
    }
    best
}

pub(crate) fn kas(v: u64) -> String {
    crate::kas(v)
}
