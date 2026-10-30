//! Node and mining attack packs. These start as conformance attacks (the node
//! must refuse what consensus forbids) and are the home for liveness, mempool
//! flooding, p2p and mining-policy attacks as they are written.

pub mod mempool;
pub mod mining;

use crate::simnet::Key;
use kaspa_consensus_core::config::params::SIMNET_PARAMS;
use kaspa_consensus_core::mass::MassCalculator;
use kaspa_consensus_core::sign::sign;
use kaspa_consensus_core::subnets::SubnetworkId;
use kaspa_consensus_core::tx::{
    MutableTransaction, PopulatedTransaction, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry,
};
use redteam_core::{AttackMeta, Finding, Outcome};

/// Generous fee so relay policy never decides a verdict.
pub(crate) const FEE: u64 = 1_000_000;

/// A signed pay-to-pubkey spend of `coins` by `key`, with storage mass committed.
pub(crate) fn p2pk_spend(
    key: &Key,
    coins: &[(TransactionOutpoint, UtxoEntry)],
    outputs: Vec<TransactionOutput>,
) -> Transaction {
    let inputs = coins.iter().map(|(op, _)| TransactionInput::new(*op, vec![], 0, 1)).collect();
    let entries: Vec<UtxoEntry> = coins.iter().map(|(_, e)| e.clone()).collect();
    let mut tx = Transaction::new(0, inputs, outputs, 0, SubnetworkId::default(), 0, vec![]);
    let mass = MassCalculator::new_with_consensus_params(&SIMNET_PARAMS);
    if let Some(m) = mass.calc_contextual_masses(&PopulatedTransaction::new(&tx, entries.clone())) {
        tx.set_storage_mass(m.storage_mass);
    }
    tx.finalize();
    let mut signed = sign(MutableTransaction::with_entries(tx, entries), key.keypair).tx;
    signed.finalize();
    signed
}

pub(crate) fn finding(
    meta: &'static AttackMeta,
    subject: &str,
    explanation: String,
    repro: serde_json::Value,
) -> Finding {
    Finding {
        id: meta.id.into(),
        title: meta.title.into(),
        severity: meta.severity,
        target: meta.target,
        subject: subject.into(),
        explanation,
        fix_pattern: meta.fix_pattern.into(),
        in_practice: meta.in_practice.into(),
        repro,
    }
}

pub(crate) fn found(attempts: usize, f: Finding) -> Outcome {
    Outcome::Found { attempts, findings: vec![f] }
}
