//! Local simnet: starts kaspad processes in throwaway data directories on
//! loopback ports, connects over wRPC (borsh), mines on demand.

use crate::guard;
use anyhow::{Context, Result, anyhow, bail};
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::tx::ScriptPublicKey;
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_wrpc_client::prelude::{ConnectOptions, ConnectStrategy, KaspaRpcClient, WrpcEncoding};
use secp256k1::{Keypair, SECP256K1, SecretKey};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub struct Key {
    pub keypair: Keypair,
}

impl Key {
    pub fn derive(label: &str) -> Self {
        use sha2::{Digest, Sha256};
        let h = Sha256::digest(format!("kaspa-redteam/node-wallet/{label}").as_bytes());
        let sk = SecretKey::from_slice(&h).expect("valid key");
        Self {
            keypair: Keypair::from_secret_key(SECP256K1, &sk),
        }
    }
    pub fn xonly(&self) -> [u8; 32] {
        self.keypair.x_only_public_key().0.serialize()
    }
    pub fn address(&self) -> Address {
        Address::new(Prefix::Simnet, Version::PubKey, &self.xonly())
    }
    pub fn p2pk(&self) -> ScriptPublicKey {
        let mut s = vec![0x20];
        s.extend_from_slice(&self.xonly());
        s.push(0xac);
        ScriptPublicKey::new(0, s.into())
    }
}

pub struct Node {
    pub rpc: KaspaRpcClient,
    pub rpc_url: String,
    pub p2p_addr: String,
    child: Child,
    dir: PathBuf,
}

pub struct SimNet {
    pub rt: tokio::runtime::Runtime,
    pub nodes: Vec<Node>,
    pub network: String,
    /// Receives every mined coinbase.
    pub miner: Key,
    keep_data: bool,
}

fn free_port() -> Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}

impl SimNet {
    pub fn start(kaspad: &PathBuf, count: usize, keep_data: bool) -> Result<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let mut nodes: Vec<Node> = Vec::new();
        let base = std::env::temp_dir().join(format!("kaspa-redteam-{}", std::process::id()));
        for i in 0..count.max(1) {
            let dir = base.join(format!("node{i}"));
            std::fs::create_dir_all(&dir)?;
            let rpc_port = free_port()?;
            let p2p_port = free_port()?;
            let mut cmd = Command::new(kaspad);
            cmd.arg("--simnet")
                .arg(format!("--appdir={}", dir.display()))
                .arg(format!("--rpclisten-borsh=127.0.0.1:{rpc_port}"))
                .arg(format!("--listen=127.0.0.1:{p2p_port}"))
                .args([
                    "--nodnsseed",
                    "--disable-upnp",
                    "--utxoindex",
                    "--enable-unsynced-mining",
                    "--nologfiles",
                    "--yes",
                ])
                .arg("--loglevel=warn")
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            // Nodes after the first connect only to the first: a closed local network.
            if let Some(first) = nodes.first() {
                cmd.arg(format!("--connect={}", first.p2p_addr));
            }
            let child = cmd
                .spawn()
                .with_context(|| format!("start {} (pass --kaspad PATH)", kaspad.display()))?;
            let url = format!("ws://127.0.0.1:{rpc_port}");
            let rpc = KaspaRpcClient::new(WrpcEncoding::Borsh, Some(&url), None, None, None)?;
            let mut node = Node {
                rpc,
                rpc_url: url,
                p2p_addr: format!("127.0.0.1:{p2p_port}"),
                child,
                dir,
            };
            rt.block_on(connect(&node.rpc, &mut node.child))?;
            nodes.push(node);
        }
        let mut network = String::new();
        for n in &nodes {
            network = rt.block_on(guard::refuse_mainnet(&n.rpc))?;
        }
        Ok(Self {
            rt,
            nodes,
            network,
            miner: Key::derive("miner"),
            keep_data,
        })
    }

    pub fn block_on<F: std::future::Future>(&self, f: F) -> F::Output {
        self.rt.block_on(f)
    }

    pub fn rpc(&self, i: usize) -> &KaspaRpcClient {
        &self.nodes[i].rpc
    }

    /// Mines `n` blocks on node 0, paying the miner key.
    pub fn mine(&self, n: usize) -> Result<()> {
        let addr = self.miner.address();
        for _ in 0..n {
            let t = self.block_on(self.rpc(0).get_block_template(addr.clone(), vec![]))?;
            let r = self.block_on(self.rpc(0).submit_block(t.block, false))?;
            if !r.report.is_success() {
                bail!("simnet refused our own template block: {:?}", r.report);
            }
        }
        Ok(())
    }

    pub fn virtual_daa(&self) -> Result<u64> {
        Ok(self
            .block_on(self.rpc(0).get_block_dag_info())?
            .virtual_daa_score)
    }
}

async fn connect(rpc: &KaspaRpcClient, child: &mut Child) -> Result<()> {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            bail!("kaspad exited during startup ({status})");
        }
        let opts = ConnectOptions {
            block_async_connect: true,
            strategy: ConnectStrategy::Fallback,
            connect_timeout: Some(Duration::from_millis(1500)),
            ..Default::default()
        };
        if rpc.connect(Some(opts)).await.is_ok() && rpc.get_server_info().await.is_ok() {
            return Ok(());
        }
        if start.elapsed() > Duration::from_secs(60) {
            return Err(anyhow!("kaspad RPC did not come up within 60s"));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

impl Drop for SimNet {
    fn drop(&mut self) {
        for n in &mut self.nodes {
            let _ = self.rt.block_on(n.rpc.disconnect());
            let _ = n.child.kill();
            let _ = n.child.wait();
            if !self.keep_data {
                let _ = std::fs::remove_dir_all(&n.dir);
            }
        }
    }
}
