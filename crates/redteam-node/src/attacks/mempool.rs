//! Pack `mempool`: transactions the node must not accept for relay.

use super::{FEE, finding, found, p2pk_spend};
use crate::simnet::{Key, SimNet};
use crate::{NodeAttack, NodeCx, NodePlugin};
use kaspa_consensus_core::tx::{TransactionId, TransactionOutpoint, TransactionOutput, UtxoEntry};
use kaspa_rpc_core::RpcTransaction;
use kaspa_rpc_core::api::rpc::RpcApi;
use redteam_core::{AttackMeta, Outcome, Severity, Target};

fn submit(sim: &SimNet, tx: &kaspa_consensus_core::tx::Transaction) -> Result<(), String> {
    let r = sim
        .block_on(sim.rpc(0).submit_transaction(RpcTransaction::from(tx), false))
        .map(|_| ())
        .map_err(|e| e.to_string());
    crate::debug(&format!("submitTransaction {} -> {r:?}", tx.id()));
    r
}

fn tx_repro(tx: &kaspa_consensus_core::tx::Transaction) -> serde_json::Value {
    serde_json::json!({ "tx_id": tx.id().to_string(), "inputs": tx.inputs.len(), "outputs": tx.outputs.iter().map(|o| o.value).collect::<Vec<_>>() })
}

pub struct Node01;
static NODE01: AttackMeta = AttackMeta {
    id: "NODE-01",
    pack: "mempool",
    target: Target::Node,
    title: "Spend a coin that does not exist",
    catches: "mempool admits transactions with missing inputs as non-orphans",
    severity: Severity::Med,
    fix_pattern: "reject (or orphan-pool, when allowed) any transaction whose inputs are not in the UTXO set",
    in_practice: "Someone relays a transaction that spends a coin that does not exist. A node that admits it wastes resources on it and passes it on.",
};

impl NodeAttack for Node01 {
    fn meta(&self) -> &'static AttackMeta {
        &NODE01
    }
    fn order(&self) -> u32 {
        20
    }
    fn run(&self, sim: &SimNet, _cx: &mut NodeCx) -> Outcome {
        let ghost = TransactionOutpoint::new(TransactionId::from_bytes([0x42; 32]), 0);
        let entry = UtxoEntry::new(10 * FEE, sim.miner.p2pk(), 0, false, None);
        let tx = p2pk_spend(
            &sim.miner,
            &[(ghost, entry)],
            vec![TransactionOutput::new(9 * FEE, Key::derive("attacker").p2pk())],
        );
        match submit(sim, &tx) {
            Err(_) => Outcome::Survived { attempts: 1 },
            Ok(()) => found(
                1,
                finding(
                    &NODE01,
                    "submitTransaction",
                    "the node accepted a transaction spending an outpoint that was never created, with orphans disallowed.".into(),
                    tx_repro(&tx),
                ),
            ),
        }
    }
}
inventory::submit! { NodePlugin(&Node01) }

pub struct Node02;
static NODE02: AttackMeta = AttackMeta {
    id: "NODE-02",
    pack: "mempool",
    target: Target::Node,
    title: "Double-spend a coin already in the mempool",
    catches: "conflicting transactions both admitted without replace-by-fee",
    severity: Severity::High,
    fix_pattern: "a plain submit of a conflicting spend must be rejected; replacement only through the RBF path with a higher fee",
    in_practice: "Someone sends two transactions spending the same coin. A node that keeps both lets one be shown to a merchant while the other confirms.",
};

impl NodeAttack for Node02 {
    fn meta(&self) -> &'static AttackMeta {
        &NODE02
    }
    fn order(&self) -> u32 {
        21
    }
    fn needs_coins(&self) -> bool {
        true
    }
    fn run(&self, sim: &SimNet, cx: &mut NodeCx) -> Outcome {
        let coin = cx.coins.remove(0);
        let value = coin.1.amount;
        let honest = p2pk_spend(
            &sim.miner,
            std::slice::from_ref(&coin),
            vec![TransactionOutput::new(value - FEE, sim.miner.p2pk())],
        );
        if let Err(e) = submit(sim, &honest) {
            return Outcome::Skipped { reason: format!("honest spend refused, cannot set up: {e}") };
        }
        let attacker = Key::derive("attacker");
        let conflict = p2pk_spend(&sim.miner, &[coin], vec![TransactionOutput::new(value - FEE, attacker.p2pk())]);
        match submit(sim, &conflict) {
            Err(_) => Outcome::Survived { attempts: 1 },
            Ok(()) => found(
                1,
                finding(
                    &NODE02,
                    "submitTransaction",
                    format!(
                        "two transactions spending the same coin ({} and {}) were both accepted into the mempool with a plain submit.",
                        honest.id(),
                        conflict.id()
                    ),
                    tx_repro(&conflict),
                ),
            ),
        }
    }
}
inventory::submit! { NodePlugin(&Node02) }

pub struct Node03;
static NODE03: AttackMeta = AttackMeta {
    id: "NODE-03",
    pack: "mempool",
    target: Target::Node,
    title: "Outputs worth more than inputs",
    catches: "value created out of nothing in a relayed transaction",
    severity: Severity::High,
    fix_pattern: "reject any transaction whose outputs exceed its inputs",
    in_practice: "Someone relays a transaction whose outputs are worth more than its inputs. A node that admits it treats coins created out of nothing as real.",
};

impl NodeAttack for Node03 {
    fn meta(&self) -> &'static AttackMeta {
        &NODE03
    }
    fn order(&self) -> u32 {
        22
    }
    fn needs_coins(&self) -> bool {
        true
    }
    fn run(&self, sim: &SimNet, cx: &mut NodeCx) -> Outcome {
        let coin = cx.coins.remove(0);
        let value = coin.1.amount;
        let tx = p2pk_spend(&sim.miner, &[coin], vec![TransactionOutput::new(value + 1, sim.miner.p2pk())]);
        match submit(sim, &tx) {
            Err(_) => Outcome::Survived { attempts: 1 },
            Ok(()) => found(
                1,
                finding(
                    &NODE03,
                    "submitTransaction",
                    format!("a transaction paying {} sompi out of a {value} sompi coin was accepted.", value + 1),
                    tx_repro(&tx),
                ),
            ),
        }
    }
}
inventory::submit! { NodePlugin(&Node03) }
