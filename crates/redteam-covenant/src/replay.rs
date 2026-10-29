//! Finding records and replay. A finding file carries the exact signed
//! transaction and the UTXO entries it spends, borsh-encoded, so replay needs
//! neither the contract file nor the compiler: it hands the bytes straight to
//! the consensus validator again.

use crate::contract::Contract;
use crate::runner::Attempt;
use crate::sandbox::{Built, Judge, Verdict};
use anyhow::{Context, Result, anyhow};
use kaspa_consensus_core::tx::{Transaction, UtxoEntry};

pub fn repro_json(contract: &Contract, a: &Attempt, b: &Built, fee: u64) -> serde_json::Value {
    let tx_hex = faster_hex::hex_string(&borsh::to_vec(&b.tx).expect("tx encodes"));
    let entries_hex = faster_hex::hex_string(&borsh::to_vec(&b.entries).expect("entries encode"));
    let outputs: Vec<_> = a
        .plan
        .outputs
        .iter()
        .map(|o| {
            serde_json::json!({
                "value_sompi": o.value,
                "to": crate::dest_label(contract, &o.to),
            })
        })
        .collect();
    serde_json::json!({
        "contract_file": contract.file_name,
        "contract_hash": contract.subject_hash(),
        "constructor_args": contract.args,
        "attempt": a.label,
        "tx_id": b.tx.id().to_string(),
        "input_total_sompi": a.plan.input_total(),
        "outputs": outputs,
        "fee_sompi": fee,
        "pov_daa_score": a.plan.pov_daa,
        "past_median_time_ms": a.plan.block_time,
        "plan": a.plan,
        "tx_borsh_hex": tx_hex,
        "utxo_entries_borsh_hex": entries_hex,
    })
}

pub struct ReplayResult {
    pub id: String,
    pub path: String,
    pub tx_id: String,
    pub verdict: Verdict,
}

/// Re-judges a saved finding. Accepted = the finding still reproduces.
pub fn replay_file(path: &std::path::Path) -> Result<ReplayResult> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let v: serde_json::Value = serde_json::from_str(&raw)?;
    let repro = v.get("repro").ok_or_else(|| anyhow!("no `repro` in finding file"))?;
    let hex = |k: &str| -> Result<Vec<u8>> {
        let s = repro.get(k).and_then(|x| x.as_str()).ok_or_else(|| anyhow!("missing {k}"))?;
        let mut out = vec![0u8; s.len() / 2];
        faster_hex::hex_decode(s.as_bytes(), &mut out).map_err(|_| anyhow!("{k}: bad hex"))?;
        Ok(out)
    };
    let tx: Transaction = borsh::from_slice(&hex("tx_borsh_hex")?).context("decode tx")?;
    let entries: Vec<UtxoEntry> = borsh::from_slice(&hex("utxo_entries_borsh_hex")?).context("decode entries")?;
    let num = |k: &str| repro.get(k).and_then(|x| x.as_u64()).ok_or_else(|| anyhow!("missing {k}"));
    let judge = Judge::new();
    let tx_id = tx.id().to_string();
    let verdict = judge.verify(&Built { tx, entries }, num("pov_daa_score")?, num("past_median_time_ms")?);
    Ok(ReplayResult {
        id: v.get("id").and_then(|x| x.as_str()).unwrap_or("?").into(),
        path: v.get("spend_path").and_then(|x| x.as_str()).unwrap_or("?").into(),
        tx_id,
        verdict,
    })
}
