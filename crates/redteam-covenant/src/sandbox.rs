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
    /// A `byte[]` argument carrying a transaction signature by `key` after a
    /// fixed prefix (a KCC-20 witness: path byte `0x00`, then the signature).
    SigBytes {
        key: KeyRef,
        prefix: Vec<u8>,
    },
    /// A state-shaped argument (`State next`, `KCC20State[] next_states`)
    /// filled from the transaction itself: the states of the covenant's
    /// successor outputs (or, for `inputs`, of its covenant inputs), mapped
    /// field by field onto struct `item`.
    States {
        inputs: bool,
        array: bool,
        item: String,
    },
}

/// Covenant id of every sandbox covenant coin, for contracts that read
/// covenant ids (`OpInputCovenantId`, `OpCovInputCount`, `OpAuthOutputCount`).
pub fn sandbox_covenant_id() -> kaspa_hashes::Hash {
    let mut b = [0u8; 32];
    b.copy_from_slice(blake2b_simd::Params::new().hash_length(32).hash(b"kaspa-redteam/covenant-id").as_bytes());
    kaspa_hashes::Hash::from_bytes(b)
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
    /// Already the attacker's (an imported output the baseline marks as the
    /// signing user's own): taking from it takes nothing from anyone else.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub own: bool,
}

impl OutputSpec {
    pub fn new(value: u64, to: Dest) -> Self {
        Self { value, to, covenant: None, own: false }
    }
    /// The attacker's own output: redirecting or skimming it proves nothing.
    pub fn is_attackers(&self) -> bool {
        self.own || self.to == Dest::Key(KeyRef::Attacker)
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
    /// New covenant families this transaction starts: (authorizing input,
    /// outputs). Their ids are computed as consensus does (genesis).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub genesis: Vec<(u16, Vec<u32>)>,
}

impl SpendPlan {
    pub fn simple(
        inputs: Vec<InputSpec>,
        outputs: Vec<OutputSpec>,
        lock_time: u64,
        pov_daa: u64,
        block_time: u64,
    ) -> Self {
        Self { version: 0, inputs, outputs, lock_time, payload: vec![], pov_daa, block_time, genesis: vec![] }
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
                        if let ArgRecipe::Sig(k) | ArgRecipe::SigBytes { key: k, .. } = a {
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
    /// Some input carries a signature the tool remakes with a baseline key.
    pub fn has_resigned(&self) -> bool {
        self.inputs.iter().any(|i| matches!(i, InputSpec::Raw(r) if r.resign.is_some()))
    }
    /// Some re-signed input belongs to a key other than `attacker` (a seller's
    /// key from a baseline, an honest owner), not just the spender's own coin.
    pub fn resigned_by_other(&self, attacker: &secp256k1::Keypair) -> bool {
        let me = attacker.x_only_public_key().0;
        self.inputs.iter().any(|i| matches!(i, InputSpec::Raw(r) if r.resign.as_ref().is_some_and(|rs| rs.keypair.x_only_public_key().0 != me)))
    }
    pub fn has_sig_recipe(&self) -> bool {
        self.inputs.iter().any(
            |i| matches!(i, InputSpec::Covenant { args, .. } if args.iter().any(|a| matches!(a, ArgRecipe::Sig(_) | ArgRecipe::SigBytes { .. }))),
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
    commit_with_zk(version, sig_ops, 0)
}

/// `zk`: Groth16 verifications the script runs (about 14,000 budget units each).
fn commit_with_zk(version: u16, sig_ops: u8, zk: usize) -> ComputeCommit {
    if ComputeCommit::version_expects_compute_budget_field(version) {
        // 10 budget units per signature operation (1000 grams / 100), plus room for the script.
        ComputeCommit::ComputeBudget(
            (sig_ops as u16).saturating_mul(10).saturating_add(100).saturating_add((zk as u16).saturating_mul(15_000)).into(),
        )
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
            Dest::StandIn(i) => match &contract.stand_ins[*i].hash {
                // OP_BLAKE2B <hash> OP_EQUAL: the P2SH script of a hash we have no redeem for.
                Some(h) => {
                    let mut script = vec![0xaa, 0x20];
                    script.extend_from_slice(h);
                    script.push(0x87);
                    ScriptPublicKey::new(0, script.into())
                }
                None => pay_to_script_hash_script(&contract.stand_ins[*i].redeem),
            },
            Dest::Raw(spk) => spk.clone(),
        })
    }

    /// Builds and signs the transaction a plan describes.
    pub fn build(&self, contract: &Contract, plan: &SpendPlan) -> Result<Built> {
        let wallets = &contract.wallets;
        // Covenant-aware contracts get real covenant identity: version 1, a
        // covenant id on every covenant coin, successor outputs bound to it.
        // Covenant ids and ZK verification need version-1 transactions (compute budget).
        let version = if contract.cov_mode || contract.zk_keys > 0 { plan.version.max(1) } else { plan.version };
        let cov_id = contract.cov_mode.then(sandbox_covenant_id);
        let first_cov = plan.inputs.iter().position(|i| matches!(i, InputSpec::Covenant { .. }));
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
                        commit_with_zk(version, contract.sig_ops, contract.zk_keys),
                    ));
                    entries.push(UtxoEntry::new(*value, pay_to_script_hash_script(&script), UTXO_DAA, false, cov_id));
                    redeems.push(Some(script));
                }
                InputSpec::P2pk { owner, value } => {
                    inputs.push(TransactionInput::new_with_mass(fresh, vec![], 0, commit_for(version, 1)));
                    entries.push(UtxoEntry::new(*value, wallets.get(*owner).p2pk(), UTXO_DAA, false, None));
                    redeems.push(None);
                }
                InputSpec::StandIn { target, value } => {
                    let redeem = contract.stand_ins[*target].redeem.clone();
                    inputs.push(TransactionInput::new_with_mass(fresh, vec![], 0, commit_for(version, 0)));
                    entries.push(UtxoEntry::new(*value, pay_to_script_hash_script(&redeem), UTXO_DAA, false, None));
                    redeems.push(Some(redeem));
                }
                InputSpec::Raw(r) => {
                    let commit = if ComputeCommit::version_expects_compute_budget_field(version) {
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
            let binding = match (o.covenant, cov_id, first_cov, &o.to) {
                (Some(b), ..) => Some(b),
                (None, Some(id), Some(at), Dest::SelfCovenant | Dest::Successor(_)) => {
                    Some(CovenantBinding::new(at as u16, id))
                }
                _ => None,
            };
            outputs.push(TransactionOutput::with_covenant(
                o.value,
                Self::dest_spk(contract, wallets, &o.to, first_state)?,
                binding,
            ));
        }

        let mut tx = Transaction::new(
            version,
            inputs,
            outputs,
            plan.lock_time,
            SubnetworkId::default(),
            0,
            plan.payload.clone(),
        );

        // Genesis outputs get their new covenant id the way consensus computes it.
        if !plan.genesis.is_empty() {
            for (_, outs) in &plan.genesis {
                for &o in outs {
                    if let Some(out) = tx.outputs.get_mut(o as usize) {
                        out.covenant = None;
                    }
                }
            }
            let groups: Vec<kaspa_consensus_core::tx::GenesisCovenantGroup> = plan
                .genesis
                .iter()
                .map(|(a, outs)| kaspa_consensus_core::tx::GenesisCovenantGroup::new(*a, outs.clone()))
                .collect();
            tx.populate_genesis_covenants(&groups).map_err(|e| anyhow!("genesis: {e}"))?;
        }
        // A zero-value output never reaches the mass rules (and divides by zero in them).
        if tx.outputs.iter().any(|o| o.value == 0) {
            return Err(anyhow!("an output carries no value"));
        }
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
                                        ArgRecipe::SigBytes { key, prefix } => {
                                            let mut b = prefix.clone();
                                            b.extend(sign(*key));
                                            ArtifactValue::Bytes(b)
                                        }
                                        ArgRecipe::States { inputs, array, item } => {
                                            states_arg(contract, plan, *inputs, *array, item)?
                                        }
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
            Err(e) => {
                let msg = e.to_string();
                match failing_input(&populated) {
                    Some((i, why)) if msg.contains("signature script") => {
                        Verdict::Rejected(format!("{msg} (input {i}: {why})"))
                    }
                    _ => Verdict::Rejected(msg),
                }
            }
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

/// Builds a state-shaped argument from the plan: the states its covenant
/// successor outputs carry (or its covenant inputs hold), each mapped onto
/// struct `item` by field name. Fields the state lacks get zero values.
fn states_arg(contract: &Contract, plan: &SpendPlan, inputs: bool, array: bool, item: &str) -> Result<ArtifactValue> {
    let fields = contract.struct_fields(item).ok_or_else(|| anyhow!("unknown struct `{item}`"))?;
    let init = contract.initial_state.as_ref();
    let first_state = plan
        .inputs
        .iter()
        .find_map(|i| match i {
            InputSpec::Covenant { state, .. } => Some(state.as_ref()),
            _ => None,
        })
        .flatten()
        .or(init);
    let states: Vec<Option<&StateValues>> = if inputs {
        plan.inputs
            .iter()
            .filter_map(|i| match i {
                InputSpec::Covenant { state, .. } => Some(state.as_ref().or(init)),
                _ => None,
            })
            .collect()
    } else {
        plan.outputs
            .iter()
            .filter_map(|o| match &o.to {
                Dest::Successor(s) => Some(Some(s)),
                Dest::SelfCovenant => Some(first_state),
                _ => None,
            })
            .collect()
    };
    let to_obj = |s: Option<&StateValues>| {
        let mut m = BTreeMap::new();
        for (name, ty) in &fields {
            let v = s.and_then(|s| s.get(name)).cloned().unwrap_or_else(|| zero_value(ty));
            m.insert(name.clone(), v);
        }
        ArtifactValue::Object(m)
    };
    if array {
        Ok(ArtifactValue::Array(states.into_iter().map(to_obj).collect()))
    } else {
        let first = states.into_iter().next().ok_or_else(|| anyhow!("no covenant state to pass as `{item}`"))?;
        Ok(to_obj(first))
    }
}

pub fn zero_value(ty: &silverscript_abi::TypeArtifact) -> ArtifactValue {
    use silverscript_abi::TypeArtifact as T;
    match ty {
        T::Int | T::Temporal => ArtifactValue::Int(0),
        T::Bool => ArtifactValue::Bool(false),
        T::Byte => ArtifactValue::Byte(0),
        T::FixedBytes { len } => ArtifactValue::Bytes(vec![0; *len]),
        T::Pubkey => ArtifactValue::Bytes(vec![0; 32]),
        T::Text => ArtifactValue::Text(String::new()),
        T::FixedArray { item, len } => ArtifactValue::Array((0..*len).map(|_| zero_value(item)).collect()),
        T::DynamicArray { .. } => ArtifactValue::Array(vec![]),
        _ => ArtifactValue::Bytes(vec![]),
    }
}

/// The first input whose script fails, and why: consensus reports only that
/// some script failed.
fn failing_input(tx: &PopulatedTransaction) -> Option<(usize, String)> {
    use kaspa_consensus_core::tx::VerifiableTransaction;
    use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine, caches::Cache, covenants::CovenantsContext};
    let cov = CovenantsContext::from_tx(tx).ok()?;
    let cache = Cache::new(64);
    let reused = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&cache).with_covenants_ctx(&cov).with_reused(&reused);
    let flags = EngineFlags { sigop_script_units: kaspa_consensus_core::mass::Gram(1000).into() };
    for (i, (input, entry)) in tx.populated_inputs().enumerate() {
        let limit = input.compute_commit.allowed_script_units();
        let mut vm =
            TxScriptEngine::from_transaction_input_with_script_units_limit(tx, input, i, entry, ctx, flags, limit);
        if let Err(e) = vm.execute() {
            return Some((i, e.to_string()));
        }
    }
    None
}

/// What an input's script compared when it failed: the two operands of the
/// last comparison before the failing verify, as the engine's own execution
/// log shows them. Lets the tool ask a script what it expected.
#[derive(Debug, Clone)]
pub struct FailedCheck {
    pub input: usize,
    pub op: String,
    /// Second from top (the left-hand side as compiled), then top.
    pub a: Vec<u8>,
    pub b: Vec<u8>,
    /// Every stack element seen during the run (preimages of hashes live here).
    pub seen: Vec<Vec<u8>>,
    /// The opcodes run just before the comparison (what produced its operands:
    /// `OpCovOutputCount`, `OpTxInputAmount`, ...).
    pub recent: Vec<String>,
}

pub fn trace_failure(b: &Built, input: usize) -> Option<FailedCheck> {
    use kaspa_consensus_core::tx::VerifiableTransaction;
    use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine, caches::Cache, covenants::CovenantsContext};
    let populated = PopulatedTransaction::new(&b.tx, b.entries.clone());
    let cov = CovenantsContext::from_tx(&populated).ok()?;
    let cache = Cache::new(64);
    let reused = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&cache).with_covenants_ctx(&cov).with_reused(&reused);
    let flags = EngineFlags { sigop_script_units: kaspa_consensus_core::mass::Gram(1000).into() };
    let (inp, entry) = populated.populated_inputs().nth(input)?;
    let limit = inp.compute_commit.allowed_script_units();
    let mut log: Vec<u8> = Vec::new();
    let failed = {
        let mut vm = TxScriptEngine::from_transaction_input_with_script_units_limit(&populated, inp, input, entry, ctx, flags, limit)
            .with_opcode_execution_log_buffer(&mut log);
        vm.execute().is_err()
    };
    if !failed {
        return None;
    }
    let text = String::from_utf8_lossy(&log);
    let lines: Vec<&str> = text.lines().filter(|l| l.starts_with("Executing opcode:")).collect();
    let parse = |l: &str| -> (String, Vec<Vec<u8>>) {
        let op = l["Executing opcode: ".len()..].split(',').next().unwrap_or("").trim().to_string();
        let d = l.find("dstack:").map(|i| &l[i..]).unwrap_or("");
        let items = d
            .split('"')
            .filter(|t| t.starts_with("0x"))
            .map(|t| {
                let h = &t[2..];
                let mut v = vec![0u8; h.len() / 2];
                let _ = faster_hex::hex_decode(h.as_bytes(), &mut v);
                v
            })
            .collect();
        (op, items)
    };
    let mut seen: Vec<Vec<u8>> = Vec::new();
    for l in &lines {
        for v in parse(l).1 {
            if v.len() >= 32 && !seen.contains(&v) {
                seen.push(v);
            }
        }
    }
    if std::env::var_os("REDTEAM_TRACE").is_some() {
        for l in lines.iter().rev().take(40).rev() {
            eprintln!("      {}", &l[..l.len().min(160)]);
        }
    }
    let (last_op, last_stack) = parse(lines.last()?);
    let (op, stack) = if last_op.ends_with("Verify") && last_op != "OpVerify" {
        (last_op, last_stack)
    } else if lines.len() >= 2 {
        parse(lines[lines.len() - 2])
    } else {
        return None;
    };
    if stack.len() < 2 {
        return None;
    }
    let n = stack.len();
    let at = lines.iter().rposition(|l| parse(l).0 == op).unwrap_or(lines.len());
    let recent = lines[at.saturating_sub(6)..at].iter().map(|l| parse(l).0).collect();
    Some(FailedCheck { input, op, a: stack[n - 2].clone(), b: stack[n - 1].clone(), seen, recent })
}
