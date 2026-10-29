//! Mainnet guard. The node engine only ever talks to kaspad processes it
//! started itself with `--simnet`, and still refuses to proceed unless the node
//! confirms it is not on mainnet. There is no flag to turn this off.

use anyhow::{Result, bail};
use kaspa_consensus_core::config::genesis::GENESIS as MAINNET_GENESIS;
use kaspa_consensus_core::network::NetworkType;
use kaspa_rpc_core::api::rpc::RpcApi;

pub async fn refuse_mainnet(rpc: &impl RpcApi) -> Result<String> {
    let net = rpc.get_current_network().await?;
    if net == NetworkType::Mainnet {
        bail!("refusing to run: node reports MAINNET");
    }
    if !matches!(net, NetworkType::Simnet | NetworkType::Devnet) {
        bail!("refusing to run: node reports {net}; only simnet and devnet are allowed");
    }
    let dag = rpc.get_block_dag_info().await?;
    if dag.network.network_type == NetworkType::Mainnet {
        bail!("refusing to run: DAG info reports mainnet");
    }
    // On a fresh node the pruning point is the genesis block.
    if dag.pruning_point_hash == MAINNET_GENESIS.hash {
        bail!("refusing to run: node is built on the mainnet genesis block");
    }
    Ok(dag.network.to_string())
}
