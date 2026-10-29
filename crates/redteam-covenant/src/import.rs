//! Baseline import. When a covenant is too exotic for the search (covenant
//! families, sibling programs, computed outputs), the builder hands the tool
//! honest transactions from their own test harness and the attacks mutate
//! those. Format: BASELINE.md. Every imported transaction must first pass the
//! judge as given; otherwise the run stops, because mutating a transaction
//! consensus already rejects proves nothing.

use crate::baseline::{Baseline, PathStatus};
use crate::contract::Contract;
use crate::sandbox::{Dest, InputSpec, Judge, OutputSpec, RawInput, Resign, SpendPlan, Verdict};
use crate::script::{self, Token};
use crate::wallets::KeyRef;
use anyhow::{Context, Result, anyhow, bail};
use kaspa_consensus_core::hashing::sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, ScriptPublicKey, TransactionId, TransactionOutpoint, UtxoEntry,
};
use kaspa_hashes::Hash;
use serde_json::Value;
use std::str::FromStr;

pub const FORMAT: &str = "kaspa-redteam/baseline/1";
const DEFAULT_DAA: u64 = 10_000_000;
const DEFAULT_TIME: u64 = 4_000_000_000_000;

fn num(v: &Value, what: &str) -> Result<u64> {
    match v {
        Value::Number(n) => n.as_u64().ok_or_else(|| anyhow!("{what}: not an unsigned integer")),
        Value::String(s) => s.trim().parse().map_err(|_| anyhow!("{what}: `{s}` is not an unsigned integer")),
        _ => Err(anyhow!("{what}: expected a number")),
    }
}

fn opt_num(v: &Value, key: &str) -> Result<Option<u64>> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(x) => num(x, key).map(Some),
    }
}

fn hex(v: &Value, what: &str) -> Result<Vec<u8>> {
    let s = v.as_str().ok_or_else(|| anyhow!("{what}: expected a hex string"))?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    let mut out = vec![0u8; s.len() / 2];
    faster_hex::hex_decode(s.as_bytes(), &mut out).map_err(|_| anyhow!("{what}: bad hex"))?;
    Ok(out)
}

/// A script public key as `"0000<script hex>"` (rusty-kaspa JSON: 2-byte
/// big-endian version, then the script) or `{ "version": 0, "script": "<hex>" }`.
fn spk(v: &Value, what: &str) -> Result<ScriptPublicKey> {
    match v {
        Value::String(_) => {
            let b = hex(v, what)?;
            if b.len() < 2 {
                bail!("{what}: too short");
            }
            Ok(ScriptPublicKey::new(u16::from_be_bytes([b[0], b[1]]), b[2..].to_vec().into()))
        }
        Value::Object(_) => {
            let version = opt_num(v, "version")?.unwrap_or(0) as u16;
            let script = hex(v.get("script").ok_or_else(|| anyhow!("{what}: missing script"))?, what)?;
            Ok(ScriptPublicKey::new(version, script.into()))
        }
        _ => Err(anyhow!("{what}: expected a string or object")),
    }
}

fn hash(v: &Value, what: &str) -> Result<Hash> {
    let s = v.as_str().ok_or_else(|| anyhow!("{what}: expected a hex string"))?;
    Hash::from_str(s.strip_prefix("0x").unwrap_or(s)).map_err(|e| anyhow!("{what}: {e}"))
}

fn is_plain_p2pk(spk: &ScriptPublicKey) -> bool {
    let s = spk.script();
    spk.version() == 0 && s.len() == 34 && s[0] == 0x20 && s[33] == 0xac
}

/// A 65-byte push ending in a sighash type: a Schnorr transaction signature.
/// (A 64-byte push is not counted: KCC-20 transfer arguments, for one, pack two
/// 32-byte fields into exactly that.)
fn carries_signature(sig_script: &[u8]) -> bool {
    script::tokenize(sig_script).iter().any(
        |t| matches!(t, Token::Push(b) if b.len() == 65 && matches!(b[64], 0x01 | 0x02 | 0x03 | 0x81 | 0x82 | 0x83)),
    )
}

/// Reads a baseline file into paths ready to attack. The `contract` gives
/// labels; for a run with no `.sil`, pass `Contract::for_import`.
pub fn load(path: &std::path::Path, contract: &Contract, judge: &Judge) -> Result<Vec<PathStatus>> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let doc: Value = serde_json::from_str(&raw).with_context(|| format!("{}: not JSON", path.display()))?;
    if let Some(f) = doc.get("format").and_then(|f| f.as_str()) {
        if f != FORMAT {
            bail!("{}: format `{f}` is not `{FORMAT}`", path.display());
        }
    }
    let file_daa = opt_num(&doc, "daaScore")?.unwrap_or(DEFAULT_DAA);
    let file_time = opt_num(&doc, "pastMedianTime")?.unwrap_or(DEFAULT_TIME);
    let keys = parse_keys(&doc).with_context(|| format!("{}: keys", path.display()))?;
    let txs: Vec<&Value> = match doc.get("transactions") {
        Some(Value::Array(a)) => a.iter().collect(),
        _ if doc.get("tx").is_some() => vec![&doc],
        _ => bail!("{}: expected `transactions` (an array) or a single `tx`", path.display()),
    };

    let mut out = Vec::new();
    for (n, item) in txs.iter().enumerate() {
        let label = item.get("path").and_then(|p| p.as_str()).map(String::from).unwrap_or_else(|| format!("tx{n}"));
        let ctx = |e: anyhow::Error| e.context(format!("{}: transaction `{label}`", path.display()));
        let plan = parse_one(item, file_daa, file_time, &keys, contract, judge).map_err(ctx)?;
        match judge.run(contract, &plan) {
            (Verdict::Accepted { .. }, _) => {}
            (Verdict::Rejected(why), _) => {
                bail!(
                    "{}: transaction `{label}` is rejected by consensus as given ({why}); fix the baseline first",
                    path.display()
                )
            }
        }
        let signers = plan.signers();
        out.push(PathStatus {
            entry: format!("{label} (imported)"),
            name: label.clone(),
            state: None,
            baseline: Some(Baseline { plan, signers, secrets: vec![], lock: None }),
            unexplored_reason: None,
            tries: 0,
            imported: true,
        });
    }
    Ok(out)
}

/// Throwaway keys the harness signed with (`"keys": ["<64 hex>"]`). Any
/// transaction signature one of them made is the attacker's to remake.
fn parse_keys(doc: &Value) -> Result<Vec<secp256k1::Keypair>> {
    let Some(list) = doc.get("keys") else { return Ok(vec![]) };
    let list = list.as_array().ok_or_else(|| anyhow!("expected an array of 64-hex private keys"))?;
    let mut out = Vec::new();
    for (i, k) in list.iter().enumerate() {
        let b = hex(k, &format!("keys[{i}]"))?;
        let sk = secp256k1::SecretKey::from_slice(&b).map_err(|e| anyhow!("keys[{i}]: {e}"))?;
        out.push(secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, &sk));
    }
    Ok(out)
}

/// For each input, a signature in its script that one of `keys` made over the
/// transaction as given.
fn find_resigns(
    specs: &[RawInput],
    plan: &SpendPlan,
    keys: &[secp256k1::Keypair],
    contract: &Contract,
    judge: &Judge,
) -> Result<Vec<Option<Resign>>> {
    let mut out = vec![None; specs.len()];
    if keys.is_empty() {
        return Ok(out);
    }
    let built = judge.build(contract, plan)?;
    let populated = PopulatedTransaction::new(&built.tx, built.entries.clone());
    let reused = SigHashReusedValuesUnsync::new();
    for (i, s) in specs.iter().enumerate() {
        let sighash = calc_schnorr_signature_hash(&populated, i, SIG_HASH_ALL, &reused);
        let msg = secp256k1::Message::from_digest_slice(sighash.as_bytes().as_slice()).expect("32-byte digest");
        'offsets: for at in script::sig_push_offsets(&s.signature_script) {
            let b = &s.signature_script[at..at + 65];
            if b[64] != SIG_HASH_ALL.to_u8() {
                continue;
            }
            let Ok(sig) = secp256k1::schnorr::Signature::from_slice(&b[..64]) else { continue };
            for kp in keys {
                if secp256k1::SECP256K1.verify_schnorr(&sig, &msg, &kp.x_only_public_key().0).is_ok() {
                    out[i] = Some(Resign { keypair: *kp, at });
                    break 'offsets;
                }
            }
        }
    }
    Ok(out)
}

fn parse_one(
    item: &Value,
    file_daa: u64,
    file_time: u64,
    keys: &[secp256k1::Keypair],
    contract: &Contract,
    judge: &Judge,
) -> Result<SpendPlan> {
    let tx = item.get("tx").ok_or_else(|| anyhow!("missing `tx`"))?;
    let utxos =
        item.get("utxos").and_then(|u| u.as_array()).ok_or_else(|| anyhow!("missing `utxos` (one per input)"))?;
    let inputs = tx.get("inputs").and_then(|i| i.as_array()).ok_or_else(|| anyhow!("tx: missing `inputs`"))?;
    let outputs = tx.get("outputs").and_then(|o| o.as_array()).ok_or_else(|| anyhow!("tx: missing `outputs`"))?;
    if utxos.len() != inputs.len() {
        bail!("{} inputs but {} utxos; give the spent coin of every input, in order", inputs.len(), utxos.len());
    }
    if let Some(sn) = tx.get("subnetworkId") {
        if !hex(sn, "subnetworkId")?.iter().all(|b| *b == 0) {
            bail!("only native-subnetwork transactions are supported");
        }
    }
    let version = opt_num(tx, "version")?.unwrap_or(0) as u16;
    let targets: Option<Vec<usize>> = item
        .get("targets")
        .and_then(|t| t.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_u64().map(|v| v as usize)).collect());

    let mut entries = Vec::with_capacity(utxos.len());
    for (i, u) in utxos.iter().enumerate() {
        let w = format!("utxos[{i}]");
        let amount = num(u.get("amount").ok_or_else(|| anyhow!("{w}: missing amount"))?, &w)?;
        let s = spk(u.get("scriptPublicKey").ok_or_else(|| anyhow!("{w}: missing scriptPublicKey"))?, &w)?;
        let daa = opt_num(u, "blockDaaScore")?.unwrap_or(0);
        let coinbase = u.get("isCoinbase").and_then(|b| b.as_bool()).unwrap_or(false);
        let cov = match u.get("covenantId") {
            None | Some(Value::Null) => None,
            Some(h) => Some(hash(h, &format!("{w}.covenantId"))?),
        };
        entries.push(UtxoEntry::new(amount, s, daa, coinbase, cov));
    }

    let mut specs = Vec::with_capacity(inputs.len());
    for (i, inp) in inputs.iter().enumerate() {
        let w = format!("inputs[{i}]");
        let op = inp.get("previousOutpoint").ok_or_else(|| anyhow!("{w}: missing previousOutpoint"))?;
        let txid: TransactionId =
            hash(op.get("transactionId").ok_or_else(|| anyhow!("{w}: missing transactionId"))?, &w)?;
        let index = num(op.get("index").ok_or_else(|| anyhow!("{w}: missing index"))?, &w)? as u32;
        let sig_script = hex(inp.get("signatureScript").unwrap_or(&Value::String(String::new())), &w)?;
        let entry = entries[i].clone();
        let target = match &targets {
            Some(t) => t.contains(&i),
            None => !is_plain_p2pk(&entry.script_public_key),
        };
        specs.push(RawInput {
            outpoint: Some(TransactionOutpoint::new(txid, index)),
            signed: carries_signature(&sig_script),
            signature_script: sig_script,
            sequence: opt_num(inp, "sequence")?.unwrap_or(0),
            sig_op_count: opt_num(inp, "sigOpCount")?.unwrap_or(1) as u8,
            compute_budget: opt_num(inp, "computeBudget")?.unwrap_or(0) as u16,
            entry,
            target,
            resign: None,
        });
    }
    if !specs.iter().any(|s| s.target) {
        bail!("no input is a covenant under test; set `targets` to the covenant input indexes");
    }
    let own: Vec<usize> = item
        .get("own")
        .and_then(|t| t.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_u64().map(|v| v as usize)).collect())
        .unwrap_or_default();
    let raw_outputs = parse_outputs(outputs, &[], &own)?;
    let lock_time = opt_num(tx, "lockTime")?.unwrap_or(0);
    let payload = match tx.get("payload") {
        None | Some(Value::Null) => vec![],
        Some(p) => hex(p, "payload")?,
    };
    let pov_daa = opt_num(item, "daaScore")?.unwrap_or(file_daa);
    let block_time = opt_num(item, "pastMedianTime")?.unwrap_or(file_time);
    let as_given = SpendPlan {
        version,
        inputs: specs.iter().cloned().map(InputSpec::Raw).collect(),
        outputs: raw_outputs,
        lock_time,
        payload: payload.clone(),
        pov_daa,
        block_time,
    };
    let resigns = find_resigns(&specs, &as_given, keys, contract, judge)?;
    for (s, r) in specs.iter_mut().zip(resigns) {
        if r.is_some() {
            s.signed = false;
            s.resign = r;
        }
    }

    // Plain P2PK funding coins become the attacker's own coins, re-signed by
    // the tool, so attacks can change outputs. This is only possible when no
    // covenant input carries a transaction signature: those commit to every
    // outpoint and would break. Then everything stays verbatim.
    // A signature the tool can remake (a baseline key made it) does not count.
    let any_signed_target = specs.iter().any(|s| s.signed && (s.target || !is_plain_p2pk(&s.entry.script_public_key)));
    // Coins and outputs at a listed key's own address belong to the attacker too.
    let mut replaced: Vec<ScriptPublicKey> = keys
        .iter()
        .map(|kp| {
            let mut s = Vec::with_capacity(34);
            s.push(0x20);
            s.extend_from_slice(&kp.x_only_public_key().0.serialize());
            s.push(0xac);
            ScriptPublicKey::new(0, s.into())
        })
        .collect();
    let mut plan_inputs = Vec::with_capacity(specs.len());
    for s in specs {
        if !s.target && !any_signed_target && is_plain_p2pk(&s.entry.script_public_key) {
            replaced.push(s.entry.script_public_key.clone());
            plan_inputs.push(InputSpec::P2pk { owner: KeyRef::Attacker, value: s.entry.amount });
        } else {
            plan_inputs.push(InputSpec::Raw(s));
        }
    }

    let plan_outputs = parse_outputs(outputs, &replaced, &own)?;

    Ok(SpendPlan { version, inputs: plan_inputs, outputs: plan_outputs, lock_time, payload, pov_daa, block_time })
}

/// Outputs; those paying a `replaced` funding script go to the attacker, who now owns it.
fn parse_outputs(outputs: &[Value], replaced: &[ScriptPublicKey], own: &[usize]) -> Result<Vec<OutputSpec>> {
    let mut plan_outputs = Vec::with_capacity(outputs.len());
    for (i, o) in outputs.iter().enumerate() {
        let w = format!("outputs[{i}]");
        let value = num(o.get("value").ok_or_else(|| anyhow!("{w}: missing value"))?, &w)?;
        let s = spk(o.get("scriptPublicKey").ok_or_else(|| anyhow!("{w}: missing scriptPublicKey"))?, &w)?;
        let covenant = match o.get("covenant") {
            None | Some(Value::Null) => None,
            Some(c) => Some(CovenantBinding::new(
                num(c.get("authorizingInput").ok_or_else(|| anyhow!("{w}.covenant: missing authorizingInput"))?, &w)?
                    as u16,
                hash(c.get("covenantId").ok_or_else(|| anyhow!("{w}.covenant: missing covenantId"))?, &w)?,
            )),
        };
        let to = if replaced.contains(&s) { Dest::Key(KeyRef::Attacker) } else { Dest::Raw(s) };
        plan_outputs.push(OutputSpec { value, own: own.contains(&i), to, covenant });
    }
    Ok(plan_outputs)
}

/// Writes the honest spends the search found as a baseline file: a working
/// example of the format, and a template to edit (change outputs, add inputs)
/// for paths the search cannot reach.
pub fn export(contract: &Contract, judge: &Judge, paths: &[PathStatus]) -> Result<Value> {
    let mut txs = Vec::new();
    for p in paths {
        let Some(b) = &p.baseline else { continue };
        let built = judge.build(contract, &b.plan)?;
        let targets: Vec<usize> =
            b.plan.inputs.iter().enumerate().filter(|(_, i)| i.is_target()).map(|(n, _)| n).collect();
        txs.push(serde_json::json!({
            "path": p.entry,
            "targets": targets,
            "daaScore": b.plan.pov_daa,
            "pastMedianTime": b.plan.block_time,
            "tx": serde_json::to_value(&built.tx)?,
            "utxos": serde_json::to_value(&built.entries)?,
        }));
    }
    Ok(serde_json::json!({
        "format": FORMAT,
        "name": contract.file_name,
        "transactions": txs,
    }))
}
