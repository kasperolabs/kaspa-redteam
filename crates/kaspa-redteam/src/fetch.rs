//! `kaspa-redteam fetch <txid>...`: real transactions from a public Kaspa API
//! (kaspa-rest-server) or your own node, with every coin they spent, written
//! as a `kaspa-redteam/baseline/1` file. The scan itself stays offline; this is
//! the only part of the tool that talks to the network.
//!
//! Where the data comes from:
//! - Which block holds a transaction, and which block accepted it: the REST
//!   API (`/transactions/{id}`). A node cannot look a transaction up by id.
//! - The transaction itself and the outputs it spent: the full block, from the
//!   node (`--node`) or from the API (`/blocks/{hash}`, which asks its node).
//! - `daaScore` and `pastMedianTime`: the accepting block's header (DAA score
//!   and timestamp; the timestamp stands in for its past median time, which no
//!   RPC returns for an old block, and is at most a few minutes later).
//!
//! Every rebuilt transaction must hash to the id that was asked for, so a field
//! the API left out or mangled is caught before anything is written.

use anyhow::{Context, Result, anyhow, bail};
use kaspa_consensus_core::subnets::SubnetworkId;
use kaspa_consensus_core::tx::{
    CovenantBinding, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_hashes::Hash;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

/// Public REST APIs (kaspa-rest-server) by network.
pub fn api_for(network: &str) -> Option<&'static str> {
    match network {
        "mainnet" => Some("https://api.kaspa.org"),
        "testnet-10" | "tn10" => Some("https://api-tn10.kaspa.org"),
        "testnet-11" | "tn11" => Some("https://api-tn11.kaspa.org"),
        _ => None,
    }
}

/// Where a transaction sits: the blocks that hold it and the chain block that accepted it.
#[derive(Clone, Debug)]
pub struct Located {
    pub blocks: Vec<Hash>,
    pub accepting: Option<Hash>,
}

#[derive(Clone)]
pub struct FetchedTx {
    pub tx: Transaction,
    /// The id the source gave for this transaction.
    pub claimed_id: Hash,
    /// Fields the source did not send, filled with their usual value (0).
    pub assumed: Vec<&'static str>,
}

#[derive(Clone, Default)]
pub struct BlockData {
    pub daa_score: u64,
    pub timestamp: u64,
    pub txs: Vec<FetchedTx>,
}

/// Something that can answer the two questions fetch needs.
pub trait Source: Sync {
    fn locate(&self, txid: &Hash) -> Result<Located>;
    fn block(&self, hash: &Hash, with_txs: bool) -> Result<BlockData>;
    fn describe(&self) -> String;
}

/// A GET that returns JSON, or `None` for 404.
pub trait Http: Sync {
    fn get(&self, path: &str) -> Result<Option<Value>>;
}

// ---------------------------------------------------------------------------
// REST API (kaspa-rest-server)

pub struct Rest<H: Http> {
    pub http: H,
    pub base: String,
}

impl<H: Http> Source for Rest<H> {
    fn locate(&self, txid: &Hash) -> Result<Located> {
        let path = format!("/transactions/{txid}?inputs=false&outputs=false&resolve_previous_outpoints=no");
        let v = self.http.get(&path)?.ok_or_else(|| {
            anyhow!("transaction {txid} is not known to {} (wrong network, or too new to be indexed yet)", self.base)
        })?;
        located_from_rest(&v).with_context(|| format!("transaction {txid}"))
    }

    fn block(&self, hash: &Hash, with_txs: bool) -> Result<BlockData> {
        let path = format!("/blocks/{hash}?includeTransactions={with_txs}");
        let v = self.http.get(&path)?.ok_or_else(|| anyhow!("block {hash} is not known to {}", self.base))?;
        block_from_rest(&v, with_txs).with_context(|| format!("block {hash}"))
    }

    fn describe(&self) -> String {
        self.base.clone()
    }
}

fn located_from_rest(v: &Value) -> Result<Located> {
    let blocks = v
        .get("block_hash")
        .and_then(|b| b.as_array())
        .map(|a| a.iter().filter_map(|h| h.as_str().and_then(|s| Hash::from_str(s).ok())).collect())
        .unwrap_or_default();
    let accepting = match v.get("accepting_block_hash").and_then(|h| h.as_str()) {
        Some(s) if !s.is_empty() => Some(Hash::from_str(s).map_err(|e| anyhow!("accepting_block_hash: {e}"))?),
        _ => None,
    };
    Ok(Located { blocks, accepting })
}

fn num(v: Option<&Value>) -> Option<u64> {
    match v? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn hexbytes(s: &str, what: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let mut out = vec![0u8; s.len() / 2];
    if s.len() % 2 != 0 {
        bail!("{what}: odd-length hex");
    }
    faster_hex::hex_decode(s.as_bytes(), &mut out).map_err(|_| anyhow!("{what}: bad hex"))?;
    Ok(out)
}

/// An output script as the API sends it: `{ "scriptPublicKey": "<hex>", "version": 0 }`
/// (kaspa-rest-server strips leading zeros from the hex, so an odd length gets
/// one back), or rusty-kaspa's `"0000<script hex>"`.
fn spk_from_rest(v: &Value, what: &str) -> Result<ScriptPublicKey> {
    match v {
        Value::Object(o) => {
            let mut s = o.get("scriptPublicKey").and_then(|s| s.as_str()).unwrap_or("").to_string();
            if s.len() % 2 == 1 {
                s.insert(0, '0');
            }
            let version = num(o.get("version")).unwrap_or(0) as u16;
            Ok(ScriptPublicKey::new(version, hexbytes(&s, what)?.into()))
        }
        Value::String(s) => {
            let b = hexbytes(s, what)?;
            if b.len() < 2 {
                bail!("{what}: too short");
            }
            Ok(ScriptPublicKey::new(u16::from_be_bytes([b[0], b[1]]), b[2..].to_vec().into()))
        }
        _ => bail!("{what}: expected a script"),
    }
}

fn tx_from_rest(t: &Value) -> Result<FetchedTx> {
    let mut assumed: Vec<&'static str> = Vec::new();
    let claimed = t
        .pointer("/verboseData/transactionId")
        .and_then(|s| s.as_str())
        .ok_or_else(|| anyhow!("transaction without verboseData.transactionId"))?;
    let claimed_id = Hash::from_str(claimed).map_err(|e| anyhow!("transactionId: {e}"))?;
    let version = num(t.get("version")).unwrap_or(0) as u16;
    let mut inputs = Vec::new();
    for (i, inp) in t.get("inputs").and_then(|x| x.as_array()).map(Vec::as_slice).unwrap_or(&[]).iter().enumerate() {
        let w = format!("{claimed} input {i}");
        let op = inp.get("previousOutpoint").ok_or_else(|| anyhow!("{w}: no previousOutpoint"))?;
        let prev = op.get("transactionId").and_then(|s| s.as_str()).ok_or_else(|| anyhow!("{w}: no transactionId"))?;
        let prev = Hash::from_str(prev).map_err(|e| anyhow!("{w}: {e}"))?;
        let index = num(op.get("index")).unwrap_or(0) as u32;
        let sig = hexbytes(inp.get("signatureScript").and_then(|s| s.as_str()).unwrap_or(""), &w)?;
        let sequence = match num(inp.get("sequence")) {
            Some(s) => s,
            None => {
                if !assumed.contains(&"sequence") {
                    assumed.push("sequence");
                }
                0
            }
        };
        let outpoint = TransactionOutpoint::new(prev, index);
        let input = if kaspa_consensus_core::tx::ComputeCommit::version_expects_compute_budget_field(version) {
            let cb = num(inp.get("computeBudget").or(inp.get("compute_budget"))).unwrap_or(0) as u16;
            TransactionInput::new_with_compute_budget(outpoint, sig, sequence, cb)
        } else {
            let n = num(inp.get("sigOpCount").or(inp.get("sig_op_count"))).unwrap_or(1) as u8;
            TransactionInput::new(outpoint, sig, sequence, n)
        };
        inputs.push(input);
    }
    let mut outputs = Vec::new();
    for (i, o) in t.get("outputs").and_then(|x| x.as_array()).map(Vec::as_slice).unwrap_or(&[]).iter().enumerate() {
        let w = format!("{claimed} output {i}");
        let value = num(o.get("amount").or(o.get("value"))).ok_or_else(|| anyhow!("{w}: no amount"))?;
        let spk = spk_from_rest(o.get("scriptPublicKey").unwrap_or(&Value::Null), &w)?;
        let mut out = TransactionOutput::new(value, spk);
        if let Some(c) = o.get("covenant").filter(|c| !c.is_null()) {
            if let Some(id) = c.get("covenantId").and_then(|s| s.as_str()).filter(|s| !s.is_empty()) {
                let auth = num(c.get("authorizingInput")).unwrap_or(0) as u16;
                out.covenant = Some(CovenantBinding::new(auth, Hash::from_str(id).map_err(|e| anyhow!("{w}: {e}"))?));
            }
        }
        outputs.push(out);
    }
    let lock_time = num(t.get("lockTime")).unwrap_or_else(|| {
        assumed.push("lock time");
        0
    });
    let gas = num(t.get("gas")).unwrap_or(0);
    let subnetwork = match t.get("subnetworkId").and_then(|s| s.as_str()) {
        Some(s) if !s.is_empty() => {
            let b = hexbytes(s, "subnetworkId")?;
            let arr: [u8; 20] = b.try_into().map_err(|_| anyhow!("subnetworkId: not 20 bytes"))?;
            SubnetworkId::from(arr)
        }
        _ => kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE,
    };
    let payload = match t.get("payload").and_then(|s| s.as_str()) {
        Some(s) => hexbytes(s, "payload")?,
        None => vec![],
    };
    let tx = match num(t.get("mass")) {
        Some(m) if m > 0 => {
            Transaction::new_with_mass(version, inputs, outputs, lock_time, subnetwork, gas, payload, m)
        }
        _ => Transaction::new(version, inputs, outputs, lock_time, subnetwork, gas, payload),
    };
    Ok(FetchedTx { tx, claimed_id, assumed })
}

fn block_from_rest(v: &Value, with_txs: bool) -> Result<BlockData> {
    let header = v.get("header").ok_or_else(|| anyhow!("no header"))?;
    let daa_score = num(header.get("daaScore")).ok_or_else(|| anyhow!("header without daaScore"))?;
    let timestamp = num(header.get("timestamp")).ok_or_else(|| anyhow!("header without timestamp"))?;
    let mut txs = Vec::new();
    if with_txs {
        for t in v.get("transactions").and_then(|x| x.as_array()).map(Vec::as_slice).unwrap_or(&[]) {
            txs.push(tx_from_rest(t)?);
        }
    }
    Ok(BlockData { daa_score, timestamp, txs })
}

/// Real HTTP: reqwest on a small tokio runtime.
pub struct Web {
    base: String,
    client: reqwest::Client,
    rt: tokio::runtime::Runtime,
}

impl Web {
    pub fn new(base: &str) -> Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent(concat!("kaspa-redteam/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
        Ok(Self { base: base.trim_end_matches('/').to_string(), client, rt })
    }
}

impl Http for Web {
    fn get(&self, path: &str) -> Result<Option<Value>> {
        let url = format!("{}{path}", self.base);
        self.rt.block_on(async {
            let mut tries = 0;
            loop {
                tries += 1;
                let resp = self.client.get(&url).send().await;
                match resp {
                    Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND => return Ok(None),
                    Ok(r) if r.status() == reqwest::StatusCode::TOO_MANY_REQUESTS || r.status().is_server_error() => {
                        if tries >= 4 {
                            bail!("{url}: HTTP {}", r.status());
                        }
                    }
                    Ok(r) if !r.status().is_success() => bail!("{url}: HTTP {}", r.status()),
                    Ok(r) => return Ok(Some(r.json::<Value>().await.with_context(|| format!("{url}: not JSON"))?)),
                    Err(e) if tries >= 4 => return Err(anyhow!("{url}: {e}")),
                    Err(_) => {}
                }
                tokio::time::sleep(std::time::Duration::from_millis(400 * tries)).await;
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Your own node: blocks over wRPC (Borsh), locations from the REST API.

pub struct Node<H: Http> {
    pub rest: Rest<H>,
    url: String,
    rpc: kaspa_wrpc_client::prelude::KaspaRpcClient,
    rt: tokio::runtime::Runtime,
}

impl<H: Http> Node<H> {
    pub fn connect(url: &str, rest: Rest<H>) -> Result<Self> {
        use kaspa_rpc_core::api::rpc::RpcApi;
        use kaspa_wrpc_client::prelude::{ConnectOptions, ConnectStrategy, KaspaRpcClient, WrpcEncoding};
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
        let rpc = KaspaRpcClient::new(WrpcEncoding::Borsh, Some(url), None, None, None)
            .map_err(|e| anyhow!("node {url}: {e}"))?;
        rt.block_on(async {
            let opts = ConnectOptions {
                block_async_connect: true,
                strategy: ConnectStrategy::Fallback,
                connect_timeout: Some(std::time::Duration::from_secs(10)),
                ..Default::default()
            };
            rpc.connect(Some(opts)).await.map_err(|e| anyhow!("connect to node {url}: {e}"))?;
            rpc.get_server_info().await.map_err(|e| anyhow!("node {url}: {e}"))?;
            Ok::<_, anyhow::Error>(())
        })?;
        Ok(Self { rest, url: url.to_string(), rpc, rt })
    }
}

impl<H: Http> Source for Node<H> {
    fn locate(&self, txid: &Hash) -> Result<Located> {
        self.rest.locate(txid)
    }

    fn block(&self, hash: &Hash, with_txs: bool) -> Result<BlockData> {
        use kaspa_rpc_core::api::rpc::RpcApi;
        let b = self
            .rt
            .block_on(self.rpc.get_block(*hash, with_txs))
            .map_err(|e| anyhow!("block {hash} from your node: {e} (pruned? an archival node keeps old blocks)"))?;
        let mut txs = Vec::new();
        for t in b.transactions {
            let tx = Transaction::try_from(t).map_err(|e| anyhow!("block {hash}: {e}"))?;
            txs.push(FetchedTx { claimed_id: tx.id(), tx, assumed: vec![] });
        }
        Ok(BlockData { daa_score: b.header.daa_score, timestamp: b.header.timestamp, txs })
    }

    fn describe(&self) -> String {
        format!("your node {} (locations from {})", self.url, self.rest.base)
    }
}

// ---------------------------------------------------------------------------
// Assembly

/// One requested transaction: its id and the name it gets in the report.
pub struct Want {
    pub txid: Hash,
    pub label: Option<String>,
}

/// `txid` or `txid:name`.
pub fn parse_want(s: &str) -> Result<Want> {
    let (id, label) = match s.split_once(':') {
        Some((a, b)) if !b.trim().is_empty() => (a, Some(b.trim().to_string())),
        _ => (s, None),
    };
    let id = id.trim();
    if id.len() != 64 || !id.bytes().all(|c| c.is_ascii_hexdigit()) {
        bail!("`{s}` is not a transaction id (64 hex characters, optionally followed by :name)");
    }
    Ok(Want { txid: Hash::from_str(&id.to_ascii_lowercase()).map_err(|e| anyhow!("{s}: {e}"))?, label })
}

/// What fetch found, for the summary.
pub struct Fetched {
    pub doc: Value,
    pub lines: Vec<String>,
    pub skipped: Vec<String>,
    pub source: String,
}

#[derive(Default)]
struct Cache {
    located: Mutex<HashMap<Hash, Located>>,
    blocks: Mutex<HashMap<(Hash, bool), Arc<BlockData>>>,
}

impl Cache {
    fn locate(&self, src: &dyn Source, txid: &Hash) -> Result<Located> {
        if let Some(l) = self.located.lock().unwrap().get(txid) {
            return Ok(l.clone());
        }
        let l = src.locate(txid)?;
        self.located.lock().unwrap().insert(*txid, l.clone());
        Ok(l)
    }

    fn block(&self, src: &dyn Source, hash: &Hash, with_txs: bool) -> Result<Arc<BlockData>> {
        for key in [(*hash, true), (*hash, with_txs)] {
            if let Some(b) = self.blocks.lock().unwrap().get(&key) {
                return Ok(b.clone());
            }
        }
        let b = Arc::new(src.block(hash, with_txs)?);
        self.blocks.lock().unwrap().insert((*hash, with_txs), b.clone());
        Ok(b)
    }

    /// The transaction with this id, from the first block that holds it, and its accepting block.
    fn tx(&self, src: &dyn Source, txid: &Hash) -> Result<(FetchedTx, Arc<BlockData>)> {
        let loc = self.locate(src, txid)?;
        let accepting = loc.accepting.ok_or_else(|| {
            anyhow!("transaction {txid} was not accepted (yet); only accepted transactions can be fetched")
        })?;
        let mut last_err = None;
        for b in &loc.blocks {
            match self.block(src, b, true) {
                Ok(block) => {
                    if let Some(t) = block.txs.iter().find(|t| t.claimed_id == *txid || t.tx.id() == *txid) {
                        let acc = self.block(src, &accepting, false)?;
                        return Ok((t.clone(), acc));
                    }
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("transaction {txid}: none of its blocks could be read")))
    }
}

pub fn is_plain_p2pk(spk: &ScriptPublicKey) -> bool {
    let s = spk.script();
    spk.version() == 0 && s.len() == 34 && s[0] == 0x20 && s[33] == 0xac
}

/// Fetches every wanted transaction and the coins it spent, and builds the
/// baseline document. Transactions with no covenant input (plain payments)
/// are left out and listed in `skipped`.
pub fn fetch(src: &dyn Source, wants: &[Want]) -> Result<Fetched> {
    if wants.is_empty() {
        bail!("give one or more transaction ids");
    }
    let cache = Cache::default();
    let pool = rayon::ThreadPoolBuilder::new().num_threads(6).build()?;
    let results: Vec<Result<Option<(Value, String)>>> = pool.install(|| {
        use rayon::prelude::*;
        wants.par_iter().map(|w| one(src, &cache, w)).collect()
    });
    let mut txs = Vec::new();
    let mut lines = Vec::new();
    let mut skipped = Vec::new();
    let mut latest: Option<(u64, u64)> = None;
    for (w, r) in wants.iter().zip(results) {
        match r? {
            Some((item, line)) => {
                let d = item["daaScore"].as_u64().unwrap_or(0);
                let t = item["pastMedianTime"].as_u64().unwrap_or(0);
                if latest.is_none_or(|(ld, _)| d > ld) {
                    latest = Some((d, t));
                }
                txs.push(item);
                lines.push(line);
            }
            None => skipped.push(format!("{}: a plain payment (no covenant input), nothing to attack", w.txid)),
        }
    }
    if txs.is_empty() {
        bail!("none of these transactions spends a covenant, so there is nothing to attack");
    }
    let (d, t) = latest.unwrap_or_default();
    let doc = json!({
        "format": redteam_covenant::import::FORMAT,
        "source": format!("fetched by kaspa-redteam {} from {}", env!("CARGO_PKG_VERSION"), src.describe()),
        "daaScore": d,
        "pastMedianTime": t,
        "transactions": txs,
    });
    Ok(Fetched { doc, lines, skipped, source: src.describe() })
}

fn short(h: &Hash) -> String {
    h.to_string()[..8].to_string()
}

fn one(src: &dyn Source, cache: &Cache, w: &Want) -> Result<Option<(Value, String)>> {
    let (fetched, acc) = cache.tx(src, &w.txid)?;
    let tx = &fetched.tx;
    if tx.id() != w.txid {
        let why = if fetched.assumed.is_empty() {
            String::new()
        } else {
            format!(
                " The API did not send its {} (the block came from its database, not its node), and the usual value 0 is not it. Fetch it from a node that still has the block: --node ws://<your node>:17110.",
                fetched.assumed.join(" and ")
            )
        };
        bail!("transaction {}: the rebuilt transaction hashes to {}, not to its own id.{why}", w.txid, tx.id());
    }
    let mut utxos = Vec::with_capacity(tx.inputs.len());
    for (i, input) in tx.inputs.iter().enumerate() {
        let op = input.previous_outpoint;
        let (prev, prev_acc) =
            cache.tx(src, &op.transaction_id).with_context(|| format!("transaction {}: input {i}", w.txid))?;
        let out = prev.tx.outputs.get(op.index as usize).ok_or_else(|| {
            anyhow!(
                "transaction {}: input {i} spends output {} of {}, which has no such output",
                w.txid,
                op.index,
                op.transaction_id
            )
        })?;
        utxos.push(UtxoEntry::new(
            out.value,
            out.script_public_key.clone(),
            prev_acc.daa_score,
            prev.tx.is_coinbase(),
            out.covenant.map(|c| c.covenant_id),
        ));
    }
    if utxos.iter().all(|u| is_plain_p2pk(&u.script_public_key)) {
        return Ok(None);
    }
    let label = w.label.clone().unwrap_or_else(|| format!("tx {}", short(&w.txid)));
    let signed: Vec<usize> = tx
        .inputs
        .iter()
        .zip(&utxos)
        .enumerate()
        .filter(|(_, (inp, u))| {
            !is_plain_p2pk(&u.script_public_key) && redteam_covenant::import::carries_signature(&inp.signature_script)
        })
        .map(|(n, _)| n)
        .collect();
    let covenant_inputs = utxos.iter().filter(|u| !is_plain_p2pk(&u.script_public_key)).count();
    let line = format!(
        "{label}: {} input(s), {} covenant input(s){}, {} output(s), DAA {}",
        tx.inputs.len(),
        covenant_inputs,
        if signed.is_empty() { String::new() } else { format!(" ({} carry a signature)", signed.len()) },
        tx.outputs.len(),
        acc.daa_score
    );
    let item = json!({
        "path": label,
        "txid": w.txid.to_string(),
        "daaScore": acc.daa_score,
        "pastMedianTime": acc.timestamp,
        "tx": serde_json::to_value(tx)?,
        "utxos": serde_json::to_value(&utxos)?,
    });
    Ok(Some((item, line)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use redteam_covenant::contract::Contract;
    use redteam_covenant::sandbox::Judge;
    use std::collections::BTreeMap;

    /// Saved API responses, keyed by request path.
    struct Saved(HashMap<String, Value>);
    impl Http for Saved {
        fn get(&self, path: &str) -> Result<Option<Value>> {
            Ok(self.0.get(path).cloned())
        }
    }

    fn hex(b: &[u8]) -> String {
        faster_hex::hex_string(b)
    }

    /// A transaction as kaspa-rest-server's /blocks endpoint sends it (from its
    /// node, after its "legacy" conversion). `db` drops what its database path
    /// leaves out.
    fn rest_tx(tx: &Transaction, db: bool) -> Value {
        let inputs: Vec<Value> = tx
            .inputs
            .iter()
            .map(|i| {
                let mut v = json!({
                    "previousOutpoint": { "transactionId": i.previous_outpoint.transaction_id.to_string(), "index": i.previous_outpoint.index },
                    "signatureScript": hex(&i.signature_script),
                    "sigOpCount": i.compute_commit.sig_op_count().unwrap_or(0),
                    "computeBudget": i.compute_commit.compute_budget(),
                });
                if !db {
                    v["sequence"] = json!(i.sequence.to_string());
                }
                v
            })
            .collect();
        let outputs: Vec<Value> = tx
            .outputs
            .iter()
            .map(|o| {
                // rusty-kaspa JSON "0000<script>", then the server's lstrip("0").
                let full = format!("{:04x}{}", o.script_public_key.version(), hex(o.script_public_key.script()));
                json!({
                    "amount": o.value,
                    "value": o.value,
                    "scriptPublicKey": { "scriptPublicKey": full.trim_start_matches('0'), "version": 0 },
                    "covenant": o.covenant.map(|c| json!({ "authorizingInput": c.authorizing_input, "covenantId": c.covenant_id.to_string() })),
                    "verboseData": { "scriptPublicKeyType": "scripthash", "scriptPublicKeyAddress": "kaspa:x" },
                })
            })
            .collect();
        let mut v = json!({
            "version": tx.version,
            "inputs": inputs,
            "outputs": outputs,
            "subnetworkId": hex(tx.subnetwork_id.as_ref()),
            "payload": hex(&tx.payload),
            "gas": tx.gas,
            "mass": tx.storage_mass(),
            "verboseData": { "transactionId": tx.id().to_string(), "hash": "", "blockTime": 1 },
        });
        if !db {
            v["lockTime"] = json!(tx.lock_time.to_string());
        }
        v
    }

    /// A fake API holding `main` and, for each coin it spends, a funding
    /// transaction that created it.
    fn fake_api(main: &Transaction, spent: &[UtxoEntry], at: (u64, u64), db: bool) -> Saved {
        let mut m = HashMap::new();
        let seed = u64::from_le_bytes(main.id().as_bytes()[..8].try_into().unwrap());
        let mut n = 0u64;
        let mut block_hash = || {
            n += 1;
            Hash::from_u64_word(seed.wrapping_add(n))
        };
        let header =
            |daa: u64| json!({ "daaScore": daa.to_string(), "timestamp": (1_800_000_000_000u64 + daa).to_string() });
        // The main transaction: in block B, accepted by chain block A.
        let (b, a) = (block_hash(), block_hash());
        m.insert(
            format!("/transactions/{}?inputs=false&outputs=false&resolve_previous_outpoints=no", main.id()),
            json!({ "transaction_id": main.id().to_string(), "block_hash": [b.to_string()], "accepting_block_hash": a.to_string(), "is_accepted": true }),
        );
        m.insert(
            format!("/blocks/{b}?includeTransactions=true"),
            json!({ "header": header(500), "transactions": [rest_tx(main, db)] }),
        );
        m.insert(
            format!("/blocks/{a}?includeTransactions=false"),
            json!({ "header": { "daaScore": at.0.to_string(), "timestamp": at.1.to_string() } }),
        );
        // Funding transactions: the API matches them by the id it was asked for.
        for (inp, u) in main.inputs.iter().zip(spent) {
            let op = inp.previous_outpoint;
            let (pb, pa) = (block_hash(), block_hash());
            let mut outs: Vec<Value> = (0..op.index)
                .map(|_| json!({ "amount": 1, "scriptPublicKey": { "scriptPublicKey": "51", "version": 0 } }))
                .collect();
            let full = format!("{:04x}{}", u.script_public_key.version(), hex(u.script_public_key.script()));
            outs.push(json!({
                "amount": u.amount,
                "scriptPublicKey": { "scriptPublicKey": full.trim_start_matches('0'), "version": 0 },
                "covenant": u.covenant_id.map(|c| json!({ "authorizingInput": 0, "covenantId": c.to_string() })),
            }));
            let funding = json!({
                "version": 0, "inputs": [], "outputs": outs, "subnetworkId": "0000000000000000000000000000000000000000",
                "payload": "", "gas": 0, "lockTime": "0", "verboseData": { "transactionId": op.transaction_id.to_string() },
            });
            m.insert(
                format!("/transactions/{}?inputs=false&outputs=false&resolve_previous_outpoints=no", op.transaction_id),
                json!({ "block_hash": [pb.to_string()], "accepting_block_hash": pa.to_string() }),
            );
            m.insert(
                format!("/blocks/{pb}?includeTransactions=true"),
                json!({ "header": header(u.block_daa_score), "transactions": [funding] }),
            );
            m.insert(format!("/blocks/{pa}?includeTransactions=false"), json!({ "header": header(u.block_daa_score) }));
        }
        Saved(m)
    }

    /// The honest spends the search finds for an example, as real transactions.
    fn honest(file: &str) -> (Contract, Judge, Vec<(Transaction, Vec<UtxoEntry>, (u64, u64))>) {
        let path = format!("{}/../../examples/{file}", env!("CARGO_MANIFEST_DIR"));
        let src = std::fs::read_to_string(&path).unwrap();
        let (src, _) = redteam_covenant::legacy::prepare(file, &src).unwrap();
        let judge = Judge::new();
        let t = redteam_covenant::tune::tune(file, &src, &BTreeMap::new(), &judge).unwrap();
        let mut out = Vec::new();
        for p in &t.paths {
            if let Some(b) = &p.baseline {
                let built = judge.build(&t.contract, &b.plan).unwrap();
                out.push((built.tx.clone(), built.entries.clone(), (b.plan.pov_daa, b.plan.block_time)));
            }
        }
        (t.contract, judge, out)
    }

    fn check_round_trip(file: &str) {
        let (contract, _judge, spends) = honest(file);
        assert!(!spends.is_empty(), "{file}: the search found no honest spend");
        for (tx, entries, at) in spends {
            let api = Rest { http: fake_api(&tx, &entries, at, false), base: "test".into() };
            let got = fetch(&api, &[Want { txid: tx.id(), label: Some("p".into()) }]).unwrap();
            let item = &got.doc["transactions"][0];
            assert_eq!(item["tx"], serde_json::to_value(&tx).unwrap(), "{file}: tx differs");
            assert_eq!(item["utxos"], serde_json::to_value(&entries).unwrap(), "{file}: utxos differ");
            assert_eq!(item["daaScore"], json!(at.0));
            // The written file loads and consensus accepts it as given.
            let dir = std::env::temp_dir().join(format!("rt-fetch-{}-{}", std::process::id(), tx.id()));
            std::fs::create_dir_all(&dir).unwrap();
            let f = dir.join("b.json");
            std::fs::write(&f, serde_json::to_string(&got.doc).unwrap()).unwrap();
            let c = Contract::for_import("b.json", std::fs::read(&f).unwrap().as_slice());
            let paths = redteam_covenant::import::load(&f, &c, &Judge::new())
                .unwrap_or_else(|e| panic!("{file}: {e:#}\n{}", serde_json::to_string(&got.doc).unwrap()));
            assert_eq!(paths.len(), 1);
            let _ = std::fs::remove_dir_all(&dir);
            let _ = &contract;
        }
    }

    #[test]
    fn round_trip_examples() {
        for f in ["escrow_PASS.sil", "milestone_escrow_PASS.sil", "crowdfund_PASS.sil"] {
            check_round_trip(f);
        }
    }

    #[test]
    fn database_block_without_lock_time_is_caught() {
        let (_, _, spends) = honest("escrow_PASS.sil");
        let (tx, entries, at) = spends.into_iter().next().unwrap();
        // Same transaction with a lock time: the API's database copy leaves it out.
        let tx = Transaction::new(
            tx.version,
            tx.inputs.clone(),
            tx.outputs.clone(),
            5,
            tx.subnetwork_id,
            tx.gas,
            tx.payload.clone(),
        );
        let full = Rest { http: fake_api(&tx, &entries, at, false), base: "test".into() };
        assert!(fetch(&full, &[Want { txid: tx.id(), label: None }]).is_ok());
        let db = Rest { http: fake_api(&tx, &entries, at, true), base: "test".into() };
        let e = fetch(&db, &[Want { txid: tx.id(), label: None }]).err().expect("a missing lock time must be caught");
        let e = format!("{e:#}");
        assert!(e.contains("lock time") && e.contains("--node"), "{e}");
    }

    #[test]
    fn unknown_and_unaccepted() {
        let api = Rest { http: Saved(HashMap::new()), base: "https://api.example".into() };
        let id = Hash::from_u64_word(7);
        let e = fetch(&api, &[Want { txid: id, label: None }]).err().unwrap();
        assert!(format!("{e:#}").contains("not known to https://api.example"), "{e:#}");
        let mut m = HashMap::new();
        m.insert(
            format!("/transactions/{id}?inputs=false&outputs=false&resolve_previous_outpoints=no"),
            json!({ "block_hash": [Hash::from_u64_word(8).to_string()], "accepting_block_hash": null }),
        );
        let e = fetch(&Rest { http: Saved(m), base: "x".into() }, &[Want { txid: id, label: None }]).err().unwrap();
        assert!(format!("{e:#}").contains("not accepted"), "{e:#}");
    }

    /// Writes a fake API (request path -> JSON) for a local smoke test of the
    /// real HTTP path: `REDTEAM_DUMP=api.json cargo test -- --ignored dump_fake_api`.
    #[test]
    #[ignore]
    fn dump_fake_api() {
        let out = std::env::var("REDTEAM_DUMP").expect("REDTEAM_DUMP");
        let mut all = serde_json::Map::new();
        let mut ids = Vec::new();
        for f in ["escrow_PASS.sil", "milestone_escrow_PASS.sil"] {
            let (_, _, spends) = honest(f);
            for (tx, entries, at) in spends {
                ids.push(tx.id().to_string());
                for (k, v) in fake_api(&tx, &entries, at, false).0 {
                    all.insert(k, v);
                }
            }
        }
        all.insert("_ids".into(), json!(ids));
        std::fs::write(out, serde_json::to_string(&all).unwrap()).unwrap();
    }

    #[test]
    fn want_syntax() {
        let id = "a".repeat(64);
        assert!(parse_want(&id).unwrap().label.is_none());
        assert_eq!(parse_want(&format!("{id}:buy")).unwrap().label.as_deref(), Some("buy"));
        assert!(parse_want("abc").is_err());
    }
}
