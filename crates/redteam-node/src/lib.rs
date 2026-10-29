//! Node and mining engine.
//!
//! Starts its own kaspad processes with `--simnet` on loopback, refuses to run
//! against anything that reports mainnet, mines blocks on demand and runs the
//! node/mining attack packs. Same plugin pattern as the covenant engine: one
//! file per pack, one `inventory::submit!` per attack.

pub mod attacks;
pub mod guard;
pub mod simnet;

use anyhow::Result;
use kaspa_consensus_core::tx::{TransactionOutpoint, UtxoEntry};
use kaspa_rpc_core::api::rpc::RpcApi;
use redteam_core::{AttackMeta, AttackResult, Outcome, RunReport, Target};
use simnet::SimNet;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// `REDTEAM_DEBUG=1` prints every node verdict to stderr: what was submitted
/// and why it was refused. Useful when writing a new attack.
pub fn debug(msg: &str) {
    if std::env::var_os("REDTEAM_DEBUG").is_some() {
        eprintln!("[debug] {msg}");
    }
}

pub struct NodeOptions {
    pub kaspad: PathBuf,
    pub nodes: usize,
    pub keep_data: bool,
}

/// Shared state attacks can draw on.
pub struct NodeCx {
    /// Mature coinbase coins owned by `sim.miner`, if any attack asked for funds.
    pub coins: Vec<(TransactionOutpoint, UtxoEntry)>,
}

pub trait NodeAttack: Sync {
    fn meta(&self) -> &'static AttackMeta;
    fn order(&self) -> u32 {
        100
    }
    /// Asks the runner to mine until spendable coins exist before running.
    fn needs_coins(&self) -> bool {
        false
    }
    fn run(&self, sim: &SimNet, cx: &mut NodeCx) -> Outcome;
}

pub struct NodePlugin(pub &'static dyn NodeAttack);
inventory::collect!(NodePlugin);

pub fn registry() -> Vec<&'static dyn NodeAttack> {
    let mut v: Vec<&'static dyn NodeAttack> = inventory::iter::<NodePlugin>.into_iter().map(|p| p.0).collect();
    v.sort_by(|a, b| a.order().cmp(&b.order()).then(a.meta().id.cmp(b.meta().id)));
    v
}

pub fn run(opts: &NodeOptions, only: &[String]) -> Result<RunReport> {
    let started = Instant::now();
    let selected: Vec<_> = registry().into_iter().filter(|a| redteam_core::selected(a.meta(), only)).collect();
    let sim = SimNet::start(&opts.kaspad, opts.nodes, opts.keep_data)?;
    let mut notes = vec![format!("{} local kaspad node(s) on {}, data in a temp dir", sim.nodes.len(), sim.network)];

    sim.mine(10)?;
    let mut cx = NodeCx { coins: Vec::new() };
    if selected.iter().any(|a| a.needs_coins()) {
        match fund(&sim) {
            Ok(coins) => {
                notes.push(format!("mined to coinbase maturity, {} spendable coins", coins.len()));
                cx.coins = coins;
            }
            Err(e) => notes.push(format!("could not mine spendable coins: {e:#}")),
        }
    }

    let mut results = Vec::new();
    for a in selected {
        let t = Instant::now();
        let outcome = if a.needs_coins() && cx.coins.is_empty() {
            Outcome::Skipped { reason: "no mature coins".into() }
        } else {
            a.run(&sim, &mut cx)
        };
        let m = a.meta();
        results.push(AttackResult {
            id: m.id.into(),
            pack: m.pack.into(),
            target: m.target,
            title: m.title.into(),
            outcome,
            millis: t.elapsed().as_millis(),
        });
    }
    let version = sim.block_on(sim.rpc(0).get_server_info()).map(|i| i.server_version).unwrap_or_default();
    notes.push(format!("kaspad {version}"));
    Ok(RunReport {
        tool_version: redteam_core::TOOL_VERSION.into(),
        library_version: redteam_core::LIBRARY_VERSION.into(),
        target: Target::Node,
        subject_name: format!("kaspad {version} ({})", opts.kaspad.display()),
        subject_hash: redteam_core::sha256_hex(&[version.as_bytes()]),
        results,
        context: serde_json::json!({ "network": sim.network, "nodes": sim.nodes.len() }),
        notes,
        millis: started.elapsed().as_millis(),
    })
}

/// Mines until the miner owns mature coinbase coins (bounded in time).
fn fund(sim: &SimNet) -> Result<Vec<(TransactionOutpoint, UtxoEntry)>> {
    let maturity = kaspa_consensus_core::config::params::SIMNET_PARAMS.coinbase_maturity();
    let deadline = Instant::now() + Duration::from_secs(240);
    loop {
        sim.mine(100)?;
        let daa = sim.virtual_daa()?;
        let utxos = sim.block_on(sim.rpc(0).get_utxos_by_addresses(vec![sim.miner.address()]))?;
        let mature: Vec<_> = utxos
            .into_iter()
            .filter(|u| !u.utxo_entry.is_coinbase || u.utxo_entry.block_daa_score + maturity < daa)
            .map(|u| (TransactionOutpoint::from(u.outpoint), UtxoEntry::from(u.utxo_entry)))
            .collect();
        if mature.len() >= 4 {
            return Ok(mature);
        }
        if Instant::now() > deadline {
            anyhow::bail!("still immature after 4 minutes (DAA {daa}, maturity {maturity})");
        }
    }
}
