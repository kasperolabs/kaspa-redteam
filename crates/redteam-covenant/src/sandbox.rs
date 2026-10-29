//! The judge. A spend plan is turned into a real, signed Kaspa transaction and
//! checked by rusty-kaspa's own consensus validator (isolation rules, input and
//! output amounts, sequence locks, mass commitment, covenant context, every
//! input script). No node, no network, no hand-written approximation of the
//! rules: if this sandbox accepts a transaction, consensus accepts it.
//!
//! The one rule replicated here is lock-time finalization, which lives in
//! header context and is not exposed by the validator; it is ten lines and
//! mirrors `check_tx_is_finalized` exactly.

use crate::contract::Contract;
use crate::wallets::{KeyRef, Wallets};
use anyhow::{Result, anyhow};
use kaspa_consensus::processes::transaction_validator::{
    TransactionValidator, tx_validation_in_utxo_context::TxValidationFlags,
};
use kaspa_consensus_core::config::params::{MAINNET_PARAMS, Params};
use kaspa_consensus_core::constants::LOCK_TIME_THRESHOLD;
use kaspa_consensus_core::hashing::sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::mass::MassCalculator;
use kaspa_consensus_core::subnets::SubnetworkId;
use kaspa_consensus_core::tx::{
    ComputeCommit, CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId,
    TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_txscript::pay_to_script_hash_script;
use kaspa_txscript::script_builder::ScriptBuilder;
use serde::Serialize;
use silverscript_abi::ArtifactValue;
use std::collections::BTreeMap;

pub const SOMPI_PER_KAS: u64 = 100_000_000;
/// Value of each covenant coin the sandbox deploys.
pub const COVENANT_VALUE: u64 = 10 * SOMPI_PER_KAS;
/// Value of each stand-in coin (another covenant's address) the sandbox deploys.
pub const STAND_IN_VALUE: u64 = SOMPI_PER_KAS;
/// Default fee an honest spend leaves (consensus itself requires none).
pub const BASE_FEE: u64 = 10_000;
/// DAA score at which sandbox coins were created.
pub const UTXO_DAA: u64 = 1_000;

/// Runtime state of a stateful covenant: field name to value.
pub type StateValues = BTreeMap<String, ArtifactValue>;

/// How a data signature's message is hashed before signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MsgHash {
    Blake2b,
    Sha256,
}

impl MsgHash {
    pub fn digest(&self, msg: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        match self {
            MsgHash::Blake2b => out.copy_from_slice(blake2b_simd::Params::new().hash_length(32).hash(msg).as_bytes()),
            MsgHash::Sha256 => {
                use sha2::{Digest, Sha256};
                out.copy_from_slice(&Sha256::digest(msg));
            }
        }
        out
    }
}

/// One argument of a covenant entry call. Signatures are recipes, not bytes,
/// because they can only be made once the transaction (or the message) is known.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", content = "v", rename_all = "snake_case")]
pub enum ArgRecipe {
    Value(ArtifactValue),
    /// Schnorr SIGHASH_ALL signature over this input by this key.
    Sig(KeyRef),
    /// Literal signature bytes (garbage, replayed, truncated).
    RawSig(Vec<u8>),
    /// BIP340 data signature by `key` over hash(the bytes of argument `arg`):
    /// a signed reading, as `checkMsgSig` verifies it.
    DataSigOf {
        key: KeyRef,
        arg: usize,
        hash: MsgHash,
    },
}

/// An input copied verbatim from an imported baseline.
#[derive(Debug, Clone, Serialize)]
pub struct RawInput {
    /// None = give it a fresh sandbox outpoint (used when an attack duplicates it).
    pub outpoint: Option<TransactionOutpoint>,
    #[serde(serialize_with = "hex_ser")]
    pub signature_script: Vec<u8>,
    pub sequence: u64,
    pub sig_op_count: u8,
    pub compute_budget: u16,
    pub entry: UtxoEntry,
    /// Part of the covenant under test (attacks may duplicate or move it).
    pub target: bool,
    /// Its signature script carries a transaction signature the tool cannot
    /// remake (no key for it in the baseline).
    pub signed: bool,
    /// A transaction signature inside the signature script that a baseline
    /// key made: the tool signs it again after every change.
    #[serde(skip)]
    pub resign: Option<Resign>,
}

/// Where a re-signable signature sits, and the key that makes it.
#[derive(Debug, Clone)]
pub struct Resign {
    pub keypair: secp256k1::Keypair,
    /// Byte offset of the 64-byte Schnorr signature inside the signature script
    /// (the sighash-type byte follows it).
    pub at: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InputSpec {
    /// A coin locked by the covenant (in `state`, or its initial state), spent through `entry`.
    Covenant {
        entry: String,
        args: Vec<ArgRecipe>,
        value: u64,
        sequence: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        state: Option<StateValues>,
    },
    /// A plain pay-to-pubkey coin owned by `owner`.
    P2pk { owner: KeyRef, value: u64 },
    /// A coin at a stand-in address the covenant names (another covenant's
    /// P2SH hash). Spendable by anyone; it only has to be there.
    StandIn { target: usize, value: u64 },
    /// Imported from a baseline file.
    Raw(RawInput),
}

impl InputSpec {
    pub fn value(&self) -> u64 {
        match self {
            InputSpec::Covenant { value, .. } | InputSpec::P2pk { value, .. } | InputSpec::StandIn { value, .. } => {
                *value
            }
            InputSpec::Raw(r) => r.entry.amount,
        }
    }
    /// Is this input the covenant under test?
    pub fn is_target(&self) -> bool {
        match self {
            InputSpec::Covenant { .. } => true,
            InputSpec::Raw(r) => r.target,
            _ => false,
        }
    }
    /// A copy that can sit in the same transaction (fresh outpoint).
    pub fn duplicate(&self) -> InputSpec {
        let mut d = self.clone();
        if let InputSpec::Raw(r) = &mut d {
            r.outpoint = None;
        }
        d
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct OutputSpec {
    pub value: u64,
    pub to: Dest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub covenant: Option<CovenantBinding>,
}

impl OutputSpec {
    pub fn new(value: u64, to: Dest) -> Self {
        Self { value, to, covenant: None }
    }
}

/// Where an output goes, symbolically, so attacks can say "pay the attacker"
/// and reports can say who got paid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "v", rename_all = "snake_case")]
pub enum Dest {
    Key(KeyRef),
    /// Back to the covenant's own address, same state as the first covenant input.
    SelfCovenant,
    /// The covenant with this runtime state (a stateful continuation).
    Successor(StateValues),
    /// A stand-in address the covenant names.
    StandIn(usize),
    /// A literal script, from an imported baseline.
    Raw(#[serde(serialize_with = "spk_ser")] ScriptPublicKey),
}

#[derive(Debug, Clone, Serialize)]
pub struct SpendPlan {
    pub version: u16,
    pub inputs: Vec<InputSpec>,
    pub outputs: Vec<OutputSpec>,
    pub lock_time: u64,
    #[serde(skip_serializing_if = "Vec::is_empty", serialize_with = "hex_ser")]
    pub payload: Vec<u8>,
    /// DAA score of the point of view (the block that would include the tx).
    pub pov_daa: u64,
    /// Past median time in ms, for time-based lock times.
    pub block_time: u64,
}

impl SpendPlan {
    pub fn simple(
        inputs: Vec<InputSpec>,
        outputs: Vec<OutputSpec>,
        lock_time: u64,
        pov_daa: u64,
        block_time: u64,
    ) -> Self {
        Self { version: 0, inputs, outputs, lock_time, payload: vec![], pov_daa, block_time }
    }
    pub fn input_total(&self) -> u64 {
        self.inputs.iter().map(|i| i.value()).sum()
    }
    pub fn output_total(&self) -> u64 {
        self.outputs.iter().map(|o| o.value).sum()
    }
    /// Transaction-signature signers the covenant inputs need.
    pub fn signers(&self) -> Vec<KeyRef> {
        let mut v = Vec::new();
        for i in &self.inputs {
            match i {
                InputSpec::Covenant { args, .. } => {
                    for a in args {
                        if let ArgRecipe::Sig(k) = a {
                            if !v.contains(k) {
                                v.push(*k);
                            }
                        }
                    }
                }
                InputSpec::Raw(r) if r.target && r.signed && !v.contains(&KeyRef::External) => v.push(KeyRef::External),
                _ => {}
            }
        }
        v
    }
    pub fn has_sig_recipe(&self) -> bool {
        self.inputs.iter().any(
            |i| matches!(i, InputSpec::Covenant { args, .. } if args.iter().any(|a| matches!(a, ArgRecipe::Sig(_)))),
        )
    }
    pub fn has_datasig_recipe(&self) -> bool {
        self.inputs.iter().any(
            |i| matches!(i, InputSpec::Covenant { args, .. } if args.iter().any(|a| matches!(a, ArgRecipe::DataSigOf { .. }))),
        )
    }
    pub fn first_target(&self) -> Option<usize> {
        self.inputs.iter().position(|i| i.is_target())
    }
}

pub struct Built {
    pub tx: Transaction,
    pub entries: Vec<UtxoEntry>,
}

pub struct Judge {
    params: Params,
    validator: TransactionValidator,
    mass: MassCalculator,
}

#[derive(Debug, Clone)]
pub enum Verdict {
    Accepted { fee: u64 },
    Rejected(String),
}

impl Verdict {
    pub fn accepted(&self) -> bool {
        matches!(self, Verdict::Accepted { .. })
    }
}

impl Default for Judge {
    fn default() -> Self {
        Self::new()
    }
}

fn commit_for(version: u16, sig_ops: u8) -> ComputeCommit {
    if ComputeCommit::version_expects_compute_budget_field(version) {
        // 10 budget units per signature operation (1000 grams / 100), plus room for the script.
        ComputeCommit::ComputeBudget((sig_ops as u16).saturating_mul(10).saturating_add(100).into())
    } else {
        ComputeCommit::SigopCount(sig_ops.into())
    }
}

impl Judge {
    pub fn new() -> Self {
        // Mainnet consensus constants. These are rules, not a connection: the
        // sandbox never talks to any network.
        let params = MAINNET_PARAMS.clone();
        let mass = MassCalculator::new_with_consensus_params(&params);
        let validator = TransactionValidator::new(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity(),
            params.ghostdag_k(),
            Default::default(),
            mass.clone(),
            params.mass_per_sig_op,
        );
        Self { params, validator, mass }
    }

    pub fn params(&self) -> &Params {
        &self.params
    }

    /// The script public key a destination resolves to. `first_state` is the
    /// state of the first covenant input, for `SelfCovenant`.
    pub fn dest_spk(
        contract: &Contract,
        wallets: &Wallets,
        d: &Dest,
        first_state: Option<&StateValues>,
    ) -> Result<ScriptPublicKey> {
        Ok(match d {
            Dest::Key(k) => wallets.get(*k).p2pk(),
            Dest::SelfCovenant => pay_to_script_hash_script(&contract.script_for(first_state)?),
            Dest::Successor(s) => pay_to_script_hash_script(&contract.script_for(Some(s))?),
            Dest::StandIn(i) => pay_to_script_hash_script(&contract.stand_ins[*i].redeem),
            Dest::Raw(spk) => spk.clone(),
        })
    }

    /// Builds and signs the transaction a plan describes.
    pub fn build(&self, contract: &Contract, plan: &SpendPlan) -> Result<Built> {
        let wallets = &contract.wallets;
        let first_state = plan
            .inputs
            .iter()
            .find_map(|i| match i {
                InputSpec::Covenant { state, .. } => Some(state.as_ref()),
                _ => None,
            })
            .flatten();
        let mut inputs = Vec::with_capacity(plan.inputs.len());
        let mut entries = Vec::with_capacity(plan.inputs.len());
        let mut redeems: Vec<Option<Vec<u8>>> = Vec::with_capacity(plan.inputs.len());
        for (i, spec) in plan.inputs.iter().enumerate() {
            let fresh = TransactionOutpoint::new(fake_txid(i), i as u32);
            match spec {
                InputSpec::Covenant { value, sequence, state, .. } => {
                    let script = contract.script_for(state.as_ref())?;
                    inputs.push(TransactionInput::new_with_mass(
                        fresh,
                        vec![],
                        *sequence,
                        commit_for(plan.version, contract.sig_ops),
                    ));
                    entries.push(UtxoEntry::new(*value, pay_to_script_hash_script(&script), UTXO_DAA, false, None));
                    redeems.push(Some(script));
                }
                InputSpec::P2pk { owner, value } => {
                    inputs.push(TransactionInput::new_with_mass(fresh, vec![], 0, commit_for(plan.version, 1)));
                    entries.push(UtxoEntry::new(*value, wallets.get(*owner).p2pk(), UTXO_DAA, false, None));
                    redeems.push(None);
                }
                InputSpec::StandIn { target, value } => {
                    let redeem = contract.stand_ins[*target].redeem.clone();
                    inputs.push(TransactionInput::new_with_mass(fresh, vec![], 0, commit_for(plan.version, 0)));
                    entries.push(UtxoEntry::new(*value, pay_to_script_hash_script(&redeem), UTXO_DAA, false, None));
                    redeems.push(Some(redeem));
                }
                InputSpec::Raw(r) => {
                    let commit = if ComputeCommit::version_expects_compute_budget_field(plan.version) {
                        ComputeCommit::ComputeBudget(r.compute_budget.into())
                    } else {
                        ComputeCommit::SigopCount(r.sig_op_count.into())
                    };
                    inputs.push(TransactionInput::new_with_mass(
                        r.outpoint.unwrap_or(fresh),
                        r.signature_script.clone(),
                        r.sequence,
                        commit,
                    ));
                    entries.push(r.entry.clone());
                    redeems.push(None);
                }
            }
        }
        let mut outputs = Vec::with_capacity(plan.outputs.len());
        for o in &plan.outputs {
            outputs.push(TransactionOutput::with_covenant(
                o.value,
                Self::dest_spk(contract, wallets, &o.to, first_state)?,
                o.covenant,
            ));
        }

        let mut tx = Transaction::new(
            plan.version,
            inputs,
            outputs,
            plan.lock_time,
            SubnetworkId::default(),
            0,
            plan.payload.clone(),
        );

        // Commit the storage mass first: it is part of what gets signed.
        {
            let populated = PopulatedTransaction::new(&tx, entries.clone());
            if let Some(m) = self.mass.calc_contextual_masses(&populated) {
                tx.set_storage_mass(m.storage_mass);
            }
        }
        tx.finalize();

        // Sign. Kaspa sighashes exclude signature scripts, so each input can be
        // hashed now and its script filled in afterwards.
        let reused = SigHashReusedValuesUnsync::new();
        let mut scripts: Vec<Option<Vec<u8>>> = Vec::with_capacity(plan.inputs.len());
        {
            let populated = PopulatedTransaction::new(&tx, entries.clone());
            for (i, spec) in plan.inputs.iter().enumerate() {
                let script = match spec {
                    InputSpec::Raw(r) => match &r.resign {
                        None => None,
                        Some(rs) => {
                            let sighash = calc_schnorr_signature_hash(&populated, i, SIG_HASH_ALL, &reused);
                            let msg = secp256k1::Message::from_digest_slice(sighash.as_bytes().as_slice())
                                .expect("32-byte digest");
                            let sig = rs.keypair.sign_schnorr(msg);
                            let mut s = r.signature_script.clone();
                            s[rs.at..rs.at + 64].copy_from_slice(sig.as_ref());
                            s[rs.at + 64] = SIG_HASH_ALL.to_u8();
                            Some(s)
                        }
                    },
                    InputSpec::StandIn { .. } => Some(push_data(redeems[i].as_ref().expect("stand-in redeem"))?),
                    _ => {
                        let sighash = calc_schnorr_signature_hash(&populated, i, SIG_HASH_ALL, &reused);
                        let msg = secp256k1::Message::from_digest_slice(sighash.as_bytes().as_slice())
                            .expect("32-byte digest");
                        let sign = |k: KeyRef| -> Vec<u8> {
                            let sig = wallets.get(k).keypair.sign_schnorr(msg);
                            let mut v = sig.as_ref().to_vec();
                            v.push(SIG_HASH_ALL.to_u8());
                            v
                        };
                        match spec {
                            InputSpec::Covenant { entry, args, .. } => {
                                let artifact =
                                    contract.artifact.as_ref().ok_or_else(|| anyhow!("no compiled contract"))?;
                                let mut values: Vec<ArtifactValue> = Vec::with_capacity(args.len());
                                for a in args {
                                    values.push(match a {
                                        ArgRecipe::Value(v) => v.clone(),
                                        ArgRecipe::Sig(k) => ArtifactValue::Bytes(sign(*k)),
                                        ArgRecipe::RawSig(b) => ArtifactValue::Bytes(b.clone()),
                                        ArgRecipe::DataSigOf { key, arg, hash } => {
                                            let Some(ArgRecipe::Value(ArtifactValue::Bytes(m))) = args.get(*arg) else {
                                                return Err(anyhow!("data signature points at a non-bytes argument"));
                                            };
                                            let digest = secp256k1::Message::from_digest(hash.digest(m));
                                            ArtifactValue::Bytes(
                                                wallets.get(*key).keypair.sign_schnorr(digest).as_ref().to_vec(),
                                            )
                                        }
                                    });
                                }
                                let mut s = silverscript_abi::encode_contract_entry_sig_script(
                                    artifact,
                                    &contract.contract_name,
                                    entry,
                                    &values,
                                )
                                .map_err(|e| anyhow!("encode `{entry}` args: {e}"))?;
                                s.extend(push_data(redeems[i].as_ref().expect("covenant redeem"))?);
                                Some(s)
                            }
                            InputSpec::P2pk { owner, .. } => Some(push_data(&sign(*owner))?),
                            _ => unreachable!(),
                        }
                    }
                };
                scripts.push(script);
            }
        }
        for (input, s) in tx.inputs.iter_mut().zip(scripts) {
            if let Some(s) = s {
                input.signature_script = s;
            }
        }
        tx.finalize();
        Ok(Built { tx, entries })
    }

    /// Runs consensus validation on a built transaction.
    pub fn verify(&self, b: &Built, pov_daa: u64, block_time: u64) -> Verdict {
        if let Err(e) = self.validator.validate_tx_in_isolation(&b.tx) {
            return Verdict::Rejected(format!("isolation: {e}"));
        }
        if let Err(e) = check_finalized(&b.tx, pov_daa, block_time) {
            return Verdict::Rejected(e);
        }
        let populated = PopulatedTransaction::new(&b.tx, b.entries.clone());
        match self.validator.validate_populated_transaction_and_get_fee(
            &populated,
            pov_daa,
            pov_daa,
            TxValidationFlags::Full,
            None,
            None,
        ) {
            Ok(fee) => Verdict::Accepted { fee },
            Err(e) => Verdict::Rejected(e.to_string()),
        }
    }

    /// Build, sign and judge in one step. Build errors (an argument the ABI
    /// refuses to encode) count as rejections: no such transaction can exist.
    pub fn run(&self, contract: &Contract, plan: &SpendPlan) -> (Verdict, Option<Built>) {
        match self.build(contract, plan) {
            Ok(b) => (self.verify(&b, plan.pov_daa, plan.block_time), Some(b)),
            Err(e) => (Verdict::Rejected(format!("unbuildable: {e}")), None),
        }
    }
}

/// Mirrors rusty-kaspa `check_tx_is_finalized`.
pub fn check_finalized(tx: &Transaction, pov_daa: u64, block_time: u64) -> std::result::Result<(), String> {
    if tx.lock_time == 0 {
        return Ok(());
    }
    let ctx = if tx.lock_time < LOCK_TIME_THRESHOLD { pov_daa } else { block_time };
    if tx.lock_time < ctx {
        return Ok(());
    }
    if tx.inputs.iter().all(|i| i.sequence == u64::MAX) {
        return Ok(());
    }
    Err(format!("transaction not finalized: lock time {} not reached (context {ctx})", tx.lock_time))
}

pub fn push_data(data: &[u8]) -> Result<Vec<u8>> {
    let mut b = ScriptBuilder::new();
    b.add_data(data).map_err(|e| anyhow!("push: {e}"))?;
    Ok(b.drain())
}

fn fake_txid(i: usize) -> TransactionId {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(format!("kaspa-redteam/utxo/{i}").as_bytes());
    TransactionId::from_slice(&h)
}

fn hex_ser<S: serde::Serializer>(v: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&faster_hex::hex_string(v))
}

fn spk_ser<S: serde::Serializer>(v: &ScriptPublicKey, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&format!("{:04x}{}", v.version(), faster_hex::hex_string(v.script())))
}
