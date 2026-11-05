//! The judge: a transaction and the coins it spends, run through rusty-kaspa's script engine (kaspa-txscript at the
//! revision kcc20-reference pins), with the transaction-level rules a covenant cannot see for itself.
//!
//! Checked here: input count, duplicate inputs, output values (non-zero, in range, total), inputs cover outputs,
//! the covenant bindings and genesis rules (CovenantsContext::from_tx, the same call consensus makes), and every
//! input's script with covenants enabled and the input's own script-unit budget.
//! Not checked: mass and fee policy, sequence locks and lock time (block context), standardness. A mutation the judge
//! accepts could still be refused by a node for one of those; none of them protects a holder's coin.

use kaspa_consensus_core::mass::Gram;
use kaspa_consensus_core::tx::{PopulatedTransaction, Transaction, UtxoEntry, VerifiableTransaction};
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine};
use std::collections::BTreeSet;

pub const MAX_SOMPI: u64 = 29_000_000_000 * 100_000_000;

#[derive(Clone, Debug)]
pub struct Verdict {
    pub accepted: bool,
    /// A transaction-level reason (values, bindings) when it failed before any script ran.
    pub tx_error: Option<String>,
    /// Inputs whose script failed, with the engine's error.
    pub input_errors: Vec<(usize, String)>,
    pub fee: i128,
    /// Opcodes executed per input (from the engine's log), for judging how far a guess got.
    pub ops_run: Vec<usize>,
}

impl Verdict {
    pub fn reason(&self) -> String {
        if let Some(e) = &self.tx_error {
            return e.clone();
        }
        self.input_errors.iter().map(|(i, e)| format!("input {i}: {e}")).collect::<Vec<_>>().join("; ")
    }
    pub fn input_ok(&self, i: usize) -> bool {
        self.tx_error.is_none() && !self.input_errors.iter().any(|(k, _)| *k == i)
    }
}

pub fn flags() -> EngineFlags {
    EngineFlags { covenants_enabled: true, sigop_script_units: Gram(1000).into() }
}

pub fn judge(tx: &Transaction, entries: &[UtxoEntry], count_ops: bool) -> Verdict {
    let mut v = Verdict { accepted: false, tx_error: None, input_errors: vec![], fee: 0, ops_run: vec![] };
    if tx.inputs.is_empty() {
        v.tx_error = Some("no inputs".into());
        return v;
    }
    if entries.len() != tx.inputs.len() {
        v.tx_error = Some("coin list does not match the inputs".into());
        return v;
    }
    let mut seen = BTreeSet::new();
    for i in &tx.inputs {
        if !seen.insert((i.previous_outpoint.transaction_id, i.previous_outpoint.index)) {
            v.tx_error = Some("duplicate inputs".into());
            return v;
        }
    }
    let mut total_out: u64 = 0;
    for (i, o) in tx.outputs.iter().enumerate() {
        if o.value == 0 {
            v.tx_error = Some(format!("output {i} has zero value"));
            return v;
        }
        total_out = match total_out.checked_add(o.value) {
            Some(t) if t <= MAX_SOMPI => t,
            _ => {
                v.tx_error = Some("output total out of range".into());
                return v;
            }
        };
    }
    let total_in: u128 = entries.iter().map(|e| e.amount as u128).sum();
    if total_in < total_out as u128 {
        v.tx_error = Some(format!("outputs ({total_out}) exceed inputs ({total_in})"));
        return v;
    }
    v.fee = total_in as i128 - total_out as i128;
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let cov = match CovenantsContext::from_tx(&populated) {
        Ok(c) => c,
        Err(e) => {
            v.tx_error = Some(format!("covenant rules: {e}"));
            return v;
        }
    };
    let cache = Cache::new(256);
    let reused = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&cache).with_covenants_ctx(&cov).with_reused(&reused);
    for (i, (input, entry)) in populated.populated_inputs().enumerate() {
        let limit = input.compute_commit.allowed_script_units();
        let mut log: Vec<u8> = Vec::new();
        let res = if count_ops {
            let mut vm = TxScriptEngine::from_transaction_input_with_script_units_limit(&populated, input, i, entry, ctx, flags(), limit)
                .with_opcode_execution_log_buffer(&mut log);
            vm.execute()
        } else {
            let mut vm = TxScriptEngine::from_transaction_input_with_script_units_limit(&populated, input, i, entry, ctx, flags(), limit);
            vm.execute()
        };
        v.ops_run.push(log.iter().filter(|b| **b == b'\n').count());
        if let Err(e) = res {
            v.input_errors.push((i, e.to_string()));
        }
    }
    v.accepted = v.input_errors.is_empty();
    v
}
