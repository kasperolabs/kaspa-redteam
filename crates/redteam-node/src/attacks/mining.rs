//! Pack `mining`: blocks a miner should not be able to get accepted.

use super::{finding, found};
use crate::simnet::SimNet;
use crate::{NodeAttack, NodeCx, NodePlugin};
use kaspa_consensus_core::block::Block;
use kaspa_consensus_core::merkle::calc_hash_merkle_root;
use kaspa_consensus_core::tx::TransactionOutput;
use kaspa_rpc_core::RpcRawBlock;
use kaspa_rpc_core::api::rpc::RpcApi;
use redteam_core::{AttackMeta, Outcome, Severity, Target};

pub struct Mine01;
static MINE01: AttackMeta = AttackMeta {
    id: "MINE-01",
    pack: "mining",
    target: Target::Mining,
    title: "Inflate the coinbase by one sompi",
    catches: "coinbase reward not checked against subsidy + fees",
    severity: Severity::High,
    fix_pattern: "consensus must reject any block whose coinbase pays more than the expected reward",
    in_practice: "A miner pays themselves one sompi more than the block reward allows. If the node accepts it, new coins appear out of nothing.",
};

impl NodeAttack for Mine01 {
    fn meta(&self) -> &'static AttackMeta {
        &MINE01
    }
    fn order(&self) -> u32 {
        10
    }
    fn run(&self, sim: &SimNet, _cx: &mut NodeCx) -> Outcome {
        match inflate(sim) {
            Ok(None) => Outcome::Survived { attempts: 1 },
            Ok(Some(f)) => found(1, f),
            Err(e) => Outcome::Skipped { reason: format!("{e:#}") },
        }
    }
}
inventory::submit! { NodePlugin(&Mine01) }

fn inflate(sim: &SimNet) -> anyhow::Result<Option<redteam_core::Finding>> {
    // Mine a few so the coinbase has rewards to pay out.
    sim.mine(5)?;
    // Control: an untouched template block must become the sink, otherwise
    // the sink test below would prove nothing.
    let t = sim.block_on(sim.rpc(0).get_block_template(sim.miner.address(), vec![]))?;
    let honest: Block = t.block.clone().try_into().map_err(|e| anyhow::anyhow!("template decode: {e:?}"))?;
    sim.block_on(sim.rpc(0).submit_block(t.block, false))?;
    if sim.block_on(sim.rpc(0).get_block_dag_info())?.sink != honest.hash() {
        anyhow::bail!("control failed: an honest block did not become the sink, so the check is not meaningful here");
    }
    let t = sim.block_on(sim.rpc(0).get_block_template(sim.miner.address(), vec![]))?;
    let block: Block = t.block.try_into().map_err(|e| anyhow::anyhow!("template decode: {e:?}"))?;
    let mut txs = (*block.transactions).clone();
    let coinbase = &mut txs[0];
    let how = if let Some(o) = coinbase.outputs.first_mut() {
        o.value += 1;
        "first coinbase output raised by 1 sompi"
    } else {
        coinbase.outputs.push(TransactionOutput::new(1, sim.miner.p2pk()));
        "1 sompi coinbase output added where none was due"
    };
    coinbase.finalize();
    let mut header = (*block.header).clone();
    header.hash_merkle_root = calc_hash_merkle_root(txs.iter());
    header.finalize();
    let bad = Block::new(header, txs);
    let r = sim.block_on(sim.rpc(0).submit_block(RpcRawBlock::from(&bad), false))?;
    // Coinbase amounts are checked in UTXO context, after the block joins the
    // DAG. A tampered block may be accepted as a DAG member and still be
    // disqualified from the selected chain, which is correct behaviour. It is a
    // finding only if it becomes the sink (its coinbase takes effect).
    let sink = sim.block_on(sim.rpc(0).get_block_dag_info())?.sink;
    crate::debug(&format!(
        "submitBlock {} ({how}) -> {:?}, sink is {}",
        bad.hash(),
        r.report,
        if sink == bad.hash() { "it" } else { "another block" }
    ));
    if r.report.is_success() && sink == bad.hash() {
        let f = finding(
            &MINE01,
            "submitBlock",
            format!(
                "the node accepted a block whose coinbase was tampered with ({how}). Consensus let a miner print money."
            ),
            serde_json::json!({ "block_hash": bad.hash().to_string(), "change": how }),
        );
        return Ok(Some(f));
    }
    Ok(None)
}
