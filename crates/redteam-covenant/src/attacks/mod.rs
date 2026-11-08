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

pub(crate) fn kas(v: u64) -> String {
    crate::kas(v)
}
