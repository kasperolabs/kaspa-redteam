//! Real transactions in the shape the Studio caches them (kaspa-rest-server `/transactions/{id}` with
//! `resolve_previous_outpoints=light`), rebuilt into rusty-kaspa types with the coins they spent.

use crate::script::{hex, unhex};
use anyhow::{Context, Result, anyhow, bail};
use kaspa_consensus_core::subnets::SubnetworkId;
use kaspa_consensus_core::tx::{
    ComputeCommit, CovenantBinding, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry,
};
use kaspa_hashes::Hash;
use serde_json::Value;
use std::str::FromStr;

#[derive(Clone)]
#[allow(dead_code)]
pub struct RealTx {
    pub claimed_id: String,
    pub tx: Transaction,
    /// One per input; `None` when the copy does not say what the input spent.
    pub entries: Vec<Option<UtxoEntry>>,
    /// Fields the copy did not carry, filled with their usual value.
    pub assumed: Vec<String>,
    pub id_matches: bool,
    pub block_time: Option<u64>,
}

impl RealTx {
    pub fn complete(&self) -> bool {
        self.entries.iter().all(|e| e.is_some())
    }
    pub fn entries(&self) -> Vec<UtxoEntry> {
        self.entries.iter().map(|e| e.clone().unwrap()).collect()
    }
}

fn s<'a>(v: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    for k in keys {
        if let Some(x) = v.get(*k) {
            if !x.is_null() && x.as_str() != Some("None") && x.as_str() != Some("") {
                return Some(x);
            }
        }
    }
    None
}

fn num(v: Option<&Value>) -> Option<u64> {
    match v? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn spk_from(v: &Value, ver: Option<u64>) -> Result<ScriptPublicKey> {
    match v {
        Value::String(st) => Ok(ScriptPublicKey::new(ver.unwrap_or(0) as u16, unhex(st)?.into())),
        Value::Object(o) => {
            let st = o.get("scriptPublicKey").or(o.get("script")).and_then(|x| x.as_str()).unwrap_or("");
            let ver = num(o.get("version")).or(ver).unwrap_or(0);
            Ok(ScriptPublicKey::new(ver as u16, unhex(st)?.into()))
        }
        _ => bail!("script: unexpected shape"),
    }
}

fn spk_from_address(a: &str) -> Result<ScriptPublicKey> {
    let addr = kaspa_addresses::Address::try_from(a).map_err(|e| anyhow!("address {a}: {e}"))?;
    Ok(kaspa_txscript::pay_to_address_script(&addr))
}

/// Unwraps `{ txid, tx }`, `{ txid, json: "<string>" }` and plain transaction objects.
pub fn unwrap_tx(v: &Value) -> Result<Value> {
    if let Some(t) = v.get("tx").filter(|t| t.is_object()) {
        return Ok(t.clone());
    }
    if let Some(j) = v.get("json") {
        if let Some(s) = j.as_str() {
            return serde_json::from_str(s).context("tx json string");
        }
        if j.is_object() {
            return Ok(j.clone());
        }
    }
    Ok(v.clone())
}

pub fn parse(v: &Value) -> Result<RealTx> {
    let t = unwrap_tx(v)?;
    let mut assumed: Vec<String> = Vec::new();
    let mut assume = |f: &str| {
        if !assumed.iter().any(|x| x == f) {
            assumed.push(f.to_string());
        }
    };
    let claimed = s(&t, &["transaction_id", "transactionId", "txid"])
        .and_then(|x| x.as_str())
        .or_else(|| t.pointer("/verboseData/transactionId").and_then(|x| x.as_str()))
        .unwrap_or("")
        .to_string();
    let version = num(s(&t, &["version"])).unwrap_or(0) as u16;
    let mut inputs = Vec::new();
    let mut entries = Vec::new();
    let empty = vec![];
    let ins = t.get("inputs").and_then(|x| x.as_array()).unwrap_or(&empty);
    for (i, inp) in ins.iter().enumerate() {
        let w = format!("{claimed} input {i}");
        let (prev, index) = if let Some(op) = inp.get("previousOutpoint").filter(|x| x.is_object()) {
            (
                op.get("transactionId").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                num(op.get("index")).unwrap_or(0),
            )
        } else {
            (
                s(inp, &["previous_outpoint_hash"]).and_then(|x| x.as_str()).ok_or_else(|| anyhow!("{w}: no previous outpoint"))?.to_string(),
                num(s(inp, &["previous_outpoint_index"])).unwrap_or(0),
            )
        };
        let prev = Hash::from_str(&prev).map_err(|e| anyhow!("{w}: {e}"))?;
        let sig = unhex(s(inp, &["signature_script", "signatureScript"]).and_then(|x| x.as_str()).unwrap_or(""))?;
        let sequence = match num(s(inp, &["sequence"])) {
            Some(x) => x,
            None => {
                assume("sequence");
                0
            }
        };
        let outpoint = TransactionOutpoint::new(prev, index as u32);
        let input = if ComputeCommit::version_expects_compute_budget_field(version) {
            let cb = match num(s(inp, &["compute_budget", "computeBudget"])) {
                Some(x) => x,
                None => {
                    assume("compute_budget");
                    0
                }
            };
            TransactionInput::new_with_compute_budget(outpoint, sig, sequence, cb as u16)
        } else {
            let n = match num(s(inp, &["sig_op_count", "sigOpCount"])) {
                Some(x) => x,
                None => {
                    assume("sig_op_count");
                    1
                }
            };
            TransactionInput::new(outpoint, sig, sequence, n as u8)
        };
        inputs.push(input);

        // The coin it spent.
        let amount = num(s(inp, &["previous_outpoint_amount", "utxo_amount"]))
            .or_else(|| inp.pointer("/utxoEntry/amount").and_then(|x| num(Some(x))));
        let spk = if let Some(x) = s(inp, &["previous_outpoint_script", "utxo_script_public_key"]) {
            Some(spk_from(x, None)?)
        } else if let Some(x) = inp.pointer("/utxoEntry/scriptPublicKey") {
            Some(spk_from(x, None)?)
        } else if let Some(a) = s(inp, &["previous_outpoint_address"]).and_then(|x| x.as_str()) {
            Some(spk_from_address(a).with_context(|| w.clone())?)
        } else {
            None
        };
        let cov = s(inp, &["covenant_id", "utxo_covenant_id"])
            .or_else(|| inp.pointer("/utxoEntry/covenantId").filter(|x| !x.is_null()))
            .and_then(|x| x.as_str())
            .map(Hash::from_str)
            .transpose()
            .map_err(|e| anyhow!("{w} covenant id: {e}"))?;
        // A copy that resolved the outpoint states the input covenant (null for a plain coin); one that did not, cannot.
        let says_cov = ["covenant_id", "utxo_covenant_id"].iter().any(|k| inp.get(*k).is_some())
            || inp.pointer("/utxoEntry/covenantId").is_some();
        entries.push(match (amount, spk, says_cov) {
            (Some(a), Some(spk), true) => Some(UtxoEntry::new(a, spk, 0, false, cov)),
            _ => None,
        });
    }
    let mut outputs = Vec::new();
    let outs = t.get("outputs").and_then(|x| x.as_array()).unwrap_or(&empty);
    for (i, o) in outs.iter().enumerate() {
        let w = format!("{claimed} output {i}");
        let value = num(s(o, &["amount", "value"])).ok_or_else(|| anyhow!("{w}: no amount"))?;
        let ver = num(s(o, &["script_public_key_version"]));
        let spk = spk_from(s(o, &["script_public_key", "scriptPublicKey"]).ok_or_else(|| anyhow!("{w}: no script"))?, ver)?;
        let mut out = TransactionOutput::new(value, spk);
        let (cid, auth) = if let Some(c) = o.get("covenant").filter(|c| c.is_object()) {
            (c.get("covenantId").and_then(|x| x.as_str()).map(|x| x.to_string()), num(c.get("authorizingInput")))
        } else {
            (
                s(o, &["covenant_id"]).and_then(|x| x.as_str()).map(|x| x.to_string()),
                num(s(o, &["covenant_authorizing_input"])),
            )
        };
        if let Some(cid) = cid {
            let id = Hash::from_str(&cid).map_err(|e| anyhow!("{w} covenant: {e}"))?;
            out.covenant = Some(CovenantBinding::new(auth.unwrap_or(0) as u16, id));
        }
        outputs.push(out);
    }
    let lock_time = match num(s(&t, &["lock_time", "lockTime"])) {
        Some(x) => x,
        None => {
            assume("lock_time");
            0
        }
    };
    let subnet = s(&t, &["subnetwork_id", "subnetworkId"]).and_then(|x| x.as_str()).unwrap_or("0000000000000000000000000000000000000000");
    let subnetwork_id = SubnetworkId::from_str(subnet).map_err(|e| anyhow!("subnetwork: {e}"))?;
    let gas = num(s(&t, &["gas"])).unwrap_or(0);
    let payload = unhex(s(&t, &["payload"]).and_then(|x| x.as_str()).unwrap_or(""))?;
    let mut tx = Transaction::new(version, inputs, outputs, lock_time, subnetwork_id, gas, payload);
    let mut id_matches = !claimed.is_empty() && tx.id().to_string() == claimed.to_lowercase();
    // The REST API sends null for some sequence values; the usual non-zero one is u64::MAX (all inputs final).
    if !id_matches && !claimed.is_empty() && assumed.iter().any(|a| a == "sequence") {
        let mut alt = tx.clone();
        for i in alt.inputs.iter_mut() {
            i.sequence = u64::MAX;
        }
        alt.finalize();
        if alt.id().to_string() == claimed.to_lowercase() {
            tx = alt;
            id_matches = true;
            assumed.retain(|a| a != "sequence");
            assumed.push("sequence (u64::MAX, the only value that rebuilds the id)".into());
        }
    }
    let block_time = num(s(&t, &["block_time", "accepting_block_time"]));
    Ok(RealTx { claimed_id: claimed, tx, entries, assumed, id_matches, block_time })
}

/// rusty-kaspa JSON for a transaction and the coins it spent (the `kaspa-redteam/baseline/1` shape),
/// so a witnessed mutation can be replayed by anyone.
pub fn evidence(tx: &Transaction, entries: &[UtxoEntry]) -> Value {
    let spk = |s: &ScriptPublicKey| format!("{:04x}{}", s.version(), hex(s.script()));
    let inputs: Vec<Value> = tx
        .inputs
        .iter()
        .map(|i| {
            let mut m = serde_json::json!({
                "previousOutpoint": { "transactionId": i.previous_outpoint.transaction_id.to_string(), "index": i.previous_outpoint.index },
                "signatureScript": hex(&i.signature_script),
                "sequence": i.sequence.to_string(),
            });
            match i.compute_commit {
                ComputeCommit::ComputeBudget(_) => m["computeBudget"] = i.compute_commit.compute_budget().unwrap_or(0).into(),
                ComputeCommit::SigopCount(_) => m["sigOpCount"] = i.compute_commit.sig_op_count().unwrap_or(0).into(),
            }
            m
        })
        .collect();
    let outputs: Vec<Value> = tx
        .outputs
        .iter()
        .map(|o| {
            serde_json::json!({
                "value": o.value.to_string(),
                "scriptPublicKey": spk(&o.script_public_key),
                "covenant": o.covenant.map(|c| serde_json::json!({ "authorizingInput": c.authorizing_input, "covenantId": c.covenant_id.to_string() })),
            })
        })
        .collect();
    let utxos: Vec<Value> = entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "amount": e.amount.to_string(), "scriptPublicKey": spk(&e.script_public_key),
                "blockDaaScore": e.block_daa_score.to_string(), "isCoinbase": e.is_coinbase,
                "covenantId": e.covenant_id.map(|c| c.to_string()),
            })
        })
        .collect();
    serde_json::json!({
        "id": tx.id().to_string(),
        "tx": { "version": tx.version, "inputs": inputs, "outputs": outputs, "lockTime": tx.lock_time.to_string(),
                "subnetworkId": tx.subnetwork_id.to_string(), "gas": tx.gas.to_string(), "payload": hex(&tx.payload) },
        "utxos": utxos,
    })
}
