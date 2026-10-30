//! Loading a covenant: parse the SilverScript source, pick constructor
//! arguments (test keys by default), compile in process, and describe the
//! spend paths.

use crate::sandbox::{MsgHash, StateValues};
use crate::script::{self, Token};
use crate::wallets::{KeyRef, Wallets};
use anyhow::{Context, Result, anyhow, bail};
use silverscript_abi::{ArtifactValue, SilAbiArtifact, TypeArtifact};
use std::collections::BTreeMap;

/// An address the covenant names by hash (`ScriptPubKeyP2SH(h)`), standing in
/// for another covenant. The sandbox gives it a redeem script anyone can spend,
/// so the covenant can pay it or find a coin of it next to itself.
#[derive(Debug, Clone)]
pub struct StandIn {
    pub label: String,
    pub redeem: Vec<u8>,
    /// The address of another contract in the same project (its real script).
    /// Such a coin can be paid but not spent by the sandbox.
    pub linked: Option<String>,
    /// A real script hash given by the user (an address the tool has no script
    /// for): paid to by its hash, never spent.
    pub hash: Option<Vec<u8>>,
}

impl StandIn {
    fn new(label: &str) -> Self {
        // <label> OP_DROP OP_TRUE
        let mut redeem = crate::sandbox::push_data(format!("redteam-standin:{label}").as_bytes()).expect("small push");
        redeem.extend_from_slice(&[0x75, 0x51]);
        Self { label: label.into(), redeem, linked: None, hash: None }
    }
}

/// Addresses of other contracts in the same project, by constructor parameter
/// name: the program's name and its redeem script.
#[derive(Debug, Clone, Default)]
pub struct Links {
    pub p2sh: BTreeMap<String, (String, Vec<u8>)>,
    /// Values taken from another file of the project: a template hash (`kcc20_template`
    /// -> KCC20.sil's template), with the program it came from.
    pub values: BTreeMap<String, (String, Vec<u8>)>,
    /// Ints taken from another file (a template prefix or suffix length).
    pub ints: BTreeMap<String, (String, i64)>,
}

/// A secret the tool knows the preimage of. Constructor hash parameters are
/// filled with sha256(preimage), so hash-lock paths stay explorable.
#[derive(Debug, Clone)]
pub struct Secret {
    pub label: String,
    pub preimage: Vec<u8>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CtorArg {
    pub name: String,
    pub ty: String,
    /// How the value was chosen: "default", "override", "party:<label>".
    pub origin: String,
    pub value: ArtifactValue,
}

#[derive(Debug, Clone)]
pub struct EntryParam {
    pub name: String,
    pub ty: TypeArtifact,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub params: Vec<EntryParam>,
}

impl Entry {
    pub fn has_sig(&self) -> bool {
        self.params.iter().any(|p| matches!(p.ty, TypeArtifact::Sig))
    }
}

pub struct Contract {
    pub file_name: String,
    pub source: String,
    pub contract_name: String,
    pub args: Vec<CtorArg>,
    /// None for a run built only from imported baselines.
    pub artifact: Option<SilAbiArtifact>,
    pub bytecode: Vec<u8>,
    /// Runtime state fields (`int claimed = 0;`), in declaration order.
    pub state_fields: Vec<(String, TypeArtifact)>,
    /// The state the deployed coin starts in.
    pub initial_state: Option<StateValues>,
    pub stand_ins: Vec<StandIn>,
    /// How `checkMsgSig` hashes its message in this source.
    pub msg_hash: MsgHash,
    /// Candidate messages for data-signature paths, built from the constants
    /// the script checks (tags, ids, lengths).
    pub msg_candidates: Vec<Vec<u8>>,
    pub entries: Vec<Entry>,
    pub wallets: Wallets,
    pub secrets: Vec<Secret>,
    pub sig_ops: u8,
    /// Positive ints pushed by the script; candidate values for the search.
    pub pushed_ints: Vec<u64>,
    pub cltv_values: Vec<u64>,
    pub csv_values: Vec<u64>,
    /// Ctor int values, reused as entry-argument candidates.
    pub ctor_ints: Vec<i64>,
    pub has_covenant_decls: bool,
    /// The source reads covenant ids or authorized outputs: sandbox coins get
    /// a covenant id and successor outputs are bound to it.
    pub cov_mode: bool,
    /// Groth16 verifying keys in the script swapped for the tool's test key
    /// (see `zk`): proof-checked paths become explorable with its test proof.
    pub zk_keys: usize,
}

impl Contract {
    /// `overrides`: `name=value` pairs from the command line.
    pub fn load(file_name: &str, source: &str, overrides: &BTreeMap<String, String>) -> Result<Self> {
        Self::load_linked(file_name, source, overrides, &Links::default())
    }

    /// `load`, with constructor parameters that name another contract of the
    /// project filled with that contract's real address.
    pub fn load_linked(
        file_name: &str,
        source: &str,
        overrides: &BTreeMap<String, String>,
        links: &Links,
    ) -> Result<Self> {
        let ast = silverscript_lang::ast::parse_contract_ast(source).map_err(|e| anyhow!("parse error: {e}"))?;
        let mut wallets = Wallets::new();
        let mut secrets = Vec::new();
        let mut args = Vec::new();
        let mut ctor_ints = Vec::new();
        let mut stand_ins = Vec::new();

        for p in &ast.params {
            let type_name = p.type_ref.type_name();
            let ty = parse_type(&type_name).with_context(|| format!("constructor `{}`", p.name))?;
            let (value, origin) = match overrides.get(&p.name) {
                Some(raw) => {
                    let v = parse_override(raw, &ty, &mut wallets).with_context(|| format!("--arg {}", p.name))?;
                    // Your own address of another contract: paid to as given.
                    if let ArtifactValue::Bytes(h) = &v {
                        if h.len() == 32 && matches!(hash_use(source, &p.name), HashUse::P2shTarget) {
                            stand_ins.push(StandIn {
                                label: p.name.clone(),
                                redeem: vec![],
                                linked: Some("your address".into()),
                                hash: Some(h.clone()),
                            });
                        }
                    }
                    (v, "override".into())
                }
                None if links.ints.contains_key(&p.name) => {
                    let (program, v) = &links.ints[&p.name];
                    (ArtifactValue::Int(*v), format!("template length of {program}"))
                }
                None if links.values.contains_key(&p.name) => {
                    let (program, v) = &links.values[&p.name];
                    (ArtifactValue::Bytes(v.clone()), format!("template of {program}"))
                }
                None => match links.p2sh.get(&p.name) {
                    Some((program, redeem)) if matches!(ty, TypeArtifact::FixedBytes { len: 32 }) => {
                        stand_ins.push(StandIn {
                            label: format!("{} ({program})", p.name),
                            redeem: redeem.clone(),
                            linked: Some(program.clone()),
                            hash: None,
                        });
                        (ArtifactValue::Bytes(blake2b(redeem)), format!("address of {program}"))
                    }
                    _ => default_value(source, &p.name, &ty, &mut wallets, &mut secrets, &mut stand_ins).with_context(
                        || format!("constructor `{}` ({type_name}) needs a value: pass --arg {}=...", p.name, p.name),
                    )?,
                },
            };
            if let ArtifactValue::Int(n) = value {
                ctor_ints.push(n);
            }
            args.push(CtorArg { name: p.name.clone(), ty: type_name, origin, value });
        }
        for k in overrides.keys() {
            if !ast.params.iter().any(|p| &p.name == k) {
                bail!("--arg {k}: the contract has no constructor parameter named `{k}`");
            }
        }

        let values: Vec<ArtifactValue> = args.iter().map(|a| a.value.clone()).collect();
        let mut artifact = silverscript_lang::compiler::compile_to_sil_abi_artifact(source, &values)
            .map_err(|e| anyhow!("compile error: {e}"))?;
        // A `byte[32] ...template` parameter is the program's own template hash
        // (what `readInputStateWithTemplate` checks a sibling coin of the same
        // program against). The hash does not depend on state, so compile once,
        // read it, and compile again with it.
        let own_template = artifact.contracts.values().next().map(|c| c.compiled.template_hash.to_vec());
        let mut retemplated = false;
        if let Some(h) = own_template {
            for a in args.iter_mut() {
                if a.ty == "byte[32]"
                    && a.name.to_ascii_lowercase().contains("template")
                    && a.origin != "override"
                    && !a.origin.starts_with("template of")
                {
                    a.value = ArtifactValue::Bytes(h.clone());
                    a.origin = "own template hash".into();
                    retemplated = true;
                }
            }
        }
        if retemplated {
            let values: Vec<ArtifactValue> = args.iter().map(|a| a.value.clone()).collect();
            artifact = silverscript_lang::compiler::compile_to_sil_abi_artifact(source, &values)
                .map_err(|e| anyhow!("compile error: {e}"))?;
        }
        if artifact.contracts.len() != 1 {
            bail!("expected exactly one contract in the file, found {}", artifact.contracts.len());
        }
        // ZK verifying keys pushed by the script: swapped for the test key, in
        // the sandbox only, so the test proof passes (see `zk`).
        let zk_keys = {
            let c = artifact.contracts.values_mut().next().unwrap();
            let (swapped, n) = crate::zk::swap_keys(&c.compiled.bytecode);
            if n > 0 {
                let sp = c.compiled.state_span;
                c.compiled.template_hash =
                    silverscript_core::utils::template_hash(&swapped[..sp.offset], &swapped[sp.offset + sp.len..]);
                c.compiled.bytecode = swapped;
            }
            n
        };
        // A proof that names its recipient (`ScriptPubKeyP2PK(pubkey(...journal...))`):
        // the honest recipient is a party of its own, not the attacker.
        if zk_keys > 0 && source.contains("ScriptPubKeyP2PK(pubkey(") {
            wallets.party("recipient");
        }
        let (contract_name, c) = artifact.contracts.iter().next().unwrap();
        let bytecode = c.compiled.bytecode.clone();
        if std::env::var_os("REDTEAM_DEBUG").is_some() {
            eprintln!(
                "compiled {contract_name}: {} bytes, state at {}..{}, template {}",
                bytecode.len(),
                c.compiled.state_span.offset,
                c.compiled.state_span.offset + c.compiled.state_span.len,
                faster_hex::hex_string(&c.compiled.template_hash)
            );
        }
        let entries = c
            .entries
            .iter()
            .map(|(name, e)| Entry {
                name: name.clone(),
                params: e.params.iter().map(|p| EntryParam { name: p.name.clone(), ty: p.ty.clone() }).collect(),
            })
            .collect();
        let (cltv_values, csv_values) = script::lock_values(&bytecode);
        let has_covenant_decls = !c.cov_decl_to_abi.is_empty();

        let state_fields: Vec<(String, TypeArtifact)> =
            c.runtime_state.fields.iter().map(|f| (f.name.clone(), f.ty.clone())).collect();
        let initial_state = if state_fields.is_empty() || c.compiled.state_span.len == 0 {
            None
        } else {
            let span =
                &bytecode[c.compiled.state_span.offset..c.compiled.state_span.offset + c.compiled.state_span.len];
            Some(
                silverscript_abi::decode_runtime_state_script(&artifact, &c.runtime_state, span)
                    .map_err(|e| anyhow!("decode initial state: {e}"))?,
            )
        };
        let dispatch_tags: Vec<Vec<u8>> = c.entries.values().map(|e| e.dispatch_tag.as_bytes().to_vec()).collect();
        // Ids a reading may carry: byte[32] constructor values (not pubkeys).
        let v32s: Vec<Vec<u8>> = args
            .iter()
            .filter(|a| a.ty == "byte[32]")
            .filter_map(|a| match &a.value {
                ArtifactValue::Bytes(b) if b.len() == 32 => Some(b.clone()),
                _ => None,
            })
            .collect();
        let msg_candidates = message_candidates(&bytecode, &dispatch_tags, &v32s, &ctor_ints);
        let msg_hash = if source.lines().filter(|l| l.contains("checkMsgSig")).any(|l| l.contains("sha256")) {
            MsgHash::Sha256
        } else {
            MsgHash::Blake2b
        };

        Ok(Self {
            file_name: file_name.into(),
            source: source.into(),
            contract_name: contract_name.clone(),
            args,
            sig_ops: script::sig_op_estimate(&bytecode),
            pushed_ints: script::pushed_ints(&bytecode),
            cltv_values,
            csv_values,
            ctor_ints,
            has_covenant_decls,
            cov_mode: has_covenant_decls
                || ["OpInputCovenantId", "OpCovInput", "OpCovOutput", "OpAuthOutput"]
                    .iter()
                    .any(|k| source.contains(k)),
            entries,
            wallets,
            secrets,
            state_fields,
            initial_state,
            stand_ins,
            msg_hash,
            msg_candidates,
            bytecode,
            artifact: Some(artifact.clone()),
            zk_keys,
        })
    }

    /// A contract-less subject for runs built only from imported baselines.
    pub fn for_import(name: &str, raw: &[u8]) -> Self {
        Self {
            file_name: name.into(),
            source: String::from_utf8_lossy(raw).into(),
            contract_name: String::new(),
            args: vec![],
            artifact: None,
            bytecode: vec![],
            state_fields: vec![],
            initial_state: None,
            stand_ins: vec![],
            msg_hash: MsgHash::Blake2b,
            msg_candidates: vec![],
            entries: vec![],
            wallets: Wallets::new(),
            secrets: vec![],
            sig_ops: 1,
            pushed_ints: vec![],
            cltv_values: vec![],
            csv_values: vec![],
            ctor_ints: vec![],
            has_covenant_decls: false,
            cov_mode: false,
            zk_keys: 0,
        }
    }

    /// The redeem script of this covenant in `state` (None = as compiled).
    pub fn script_for(&self, state: Option<&StateValues>) -> Result<Vec<u8>> {
        let Some(state) = state else { return Ok(self.bytecode.clone()) };
        let abi = self.artifact.as_ref().ok_or_else(|| anyhow!("no compiled contract"))?;
        let c = abi.contracts.values().next().ok_or_else(|| anyhow!("no contract"))?;
        let span = c.compiled.state_span;
        let encoded = silverscript_abi::encode_runtime_state_script(abi, &c.runtime_state, state)
            .map_err(|e| anyhow!("encode state: {e}"))?;
        let mut out = self.bytecode[..span.offset].to_vec();
        out.extend(encoded);
        out.extend_from_slice(&self.bytecode[span.offset + span.len..]);
        Ok(out)
    }

    /// Fields of struct `name`; `State` is the contract's runtime state.
    pub fn struct_fields(&self, name: &str) -> Option<Vec<(String, TypeArtifact)>> {
        if name == "State" {
            return Some(self.state_fields.clone());
        }
        let s = self.artifact.as_ref()?.structs.get(name)?;
        Some(s.fields.iter().map(|f| (f.name.clone(), f.ty.clone())).collect())
    }

    pub fn is_stateful(&self) -> bool {
        self.initial_state.is_some()
    }

    pub fn entry(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// sha256 over source and constructor args: what the badge certifies.
    pub fn subject_hash(&self) -> String {
        let args = serde_json::to_vec(&self.args).unwrap_or_default();
        redteam_core::sha256_hex(&[self.source.as_bytes(), &args])
    }

    /// Which party (if any) a pubkey argument value belongs to.
    pub fn key_of(&self, bytes: &[u8]) -> Option<KeyRef> {
        if bytes == self.wallets.attacker.xonly() {
            return Some(KeyRef::Attacker);
        }
        self.wallets.parties.iter().position(|w| w.xonly() == bytes).map(KeyRef::Party)
    }
}

/// Parses SilverScript type names like `int`, `byte[32]`, `pubkey[]`, `byte[][2]`.
pub fn parse_type(name: &str) -> Result<TypeArtifact> {
    let (base, dims) = match name.find('[') {
        Some(i) => (&name[..i], &name[i..]),
        None => (name, ""),
    };
    let mut parts: Vec<Option<usize>> = Vec::new();
    for seg in dims.split('[').skip(1) {
        let inner = seg.trim_end_matches(']');
        parts.push(if inner.is_empty() {
            None
        } else {
            Some(inner.parse().map_err(|_| anyhow!("unsupported array size `{inner}`"))?)
        });
    }
    let mut ty = match (base, parts.first()) {
        ("byte", Some(Some(n))) => TypeArtifact::FixedBytes { len: *n },
        ("byte", Some(None)) => TypeArtifact::Bytes,
        _ => TypeArtifact::from_parts(base, None),
    };
    let skip = if base == "byte" && !parts.is_empty() { 1 } else { 0 };
    for d in parts.into_iter().skip(skip) {
        ty = match d {
            Some(len) => TypeArtifact::FixedArray { item: Box::new(ty), len },
            None => TypeArtifact::DynamicArray { item: Box::new(ty) },
        };
    }
    Ok(ty)
}

fn sha256(b: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(b).to_vec()
}

/// Unkeyed blake2b-256, SilverScript's `blake2b()`.
pub fn blake2b(b: &[u8]) -> Vec<u8> {
    blake2b_simd::Params::new().hash_length(32).hash(b).as_bytes().to_vec()
}

enum HashUse {
    /// `ScriptPubKeyP2SH(h)`: the address of another covenant.
    P2shTarget,
    /// Used as a key itself (`pubkey(owner)`), or named like one.
    Key,
    PubkeyBlake2b,
    SecretSha256,
    SecretBlake2b,
}

/// A short plain-words description of what a constructor parameter holds, and
/// a kind the web form uses to show the value in human terms (`ms` time,
/// `ms-span`, `daa`, `daa-span`, `sompi`, `bps`, `p2sh`).
pub fn param_hint(source: &str, name: &str, ty: &str) -> (Option<&'static str>, String) {
    let n = name.to_ascii_lowercase();
    let wall = source.contains("tx.time") && !source.contains("ageDaa");
    let span = ["period", "duration", "interval", "delay", "window", "timeout", "blocks"].iter().any(|k| n.ends_with(k));
    let timeish = span
        || ["time", "start", "end", "deadline", "until", "after", "at", "expiry", "expires", "daa", "lock"].iter().any(|k| n.ends_with(k));
    match ty {
        "byte[32]" => match hash_use(source, name) {
            HashUse::P2shTarget => (Some("p2sh"), "script hash of another contract: paste its kaspa:p… address".into()),
            HashUse::Key => (None, "a key: a kaspa:q… address or 32 bytes of hex".into()),
            HashUse::PubkeyBlake2b => (None, "hash of a key".into()),
            _ if n.contains("template") => (None, "template hash of a contract program (64 hex)".into()),
            _ if n.contains("covid") || n.contains("covenant") || n.ends_with("id") => (None, "covenant id (64 hex)".into()),
            _ if n.contains("commitment") => (None, "commitment hash (64 hex)".into()),
            _ if played_by_tool(source, name).is_some() => (None, "hash lock".into()),
            _ => (None, "32 bytes as hex, or a kaspa: address".into()),
        },
        "int" | "temporal" if timeish || ty == "temporal" => {
            if wall {
                if span {
                    (Some("ms-span"), "duration in milliseconds".into())
                } else {
                    (Some("ms"), "time in milliseconds since 1970".into())
                }
            } else if span || n.contains("delay") || n.contains("age") {
                (Some("daa-span"), "DAA score difference (about 10 per second)".into())
            } else {
                (Some("daa"), "DAA score (the chain's clock, about 10 per second)".into())
            }
        }
        "int" if n.contains("bps") || n.contains("basis") => (Some("bps"), "basis points (100 = 1%)".into()),
        "int" if ["count", "periods", "installments", "rounds", "slots", "max_ins", "maxins"].iter().any(|k| n.contains(k)) => {
            (None, "a count".into())
        }
        "int" => (Some("sompi"), "amount in sompi (100,000,000 = 1 KAS)".into()),
        "pubkey" => (None, "a key".into()),
        "bool" => (None, "true or false".into()),
        _ => (None, String::new()),
    }
}

/// What the tool must play itself for a `byte[32]` parameter, because a real
/// value would need a secret it does not have: a key, a key hash, a hash lock.
pub fn played_by_tool(source: &str, name: &str) -> Option<&'static str> {
    match hash_use(source, name) {
        HashUse::Key => Some("key"),
        HashUse::PubkeyBlake2b => Some("key hash"),
        // Only a value the script actually hashes against is a lock; any other
        // byte[32] (an id, a template, a commitment) is the user's to give.
        HashUse::SecretSha256 | HashUse::SecretBlake2b => {
            let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
            let hashed = source.lines().any(|l| {
                (l.contains("sha256(") || l.contains("blake2b("))
                    && l.match_indices(name).any(|(i, _)| {
                        l[..i].chars().next_back().is_none_or(|c| !is_ident(c))
                            && l[i + name.len()..].chars().next().is_none_or(|c| !is_ident(c))
                    })
            });
            hashed.then_some("hash lock")
        }
        HashUse::P2shTarget => None,
    }
}

/// Guesses what a `byte[32]` constructor parameter is a hash of by reading the
/// source lines that mention it: `blake2b(byte[](pk)) == owner` is a pubkey
/// hash, `sha256(secret) == hash` a hash lock. Wrong guesses only leave a path
/// unexplored; `--arg` overrides.
fn hash_use(source: &str, name: &str) -> HashUse {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mentions = |line: &str| {
        line.match_indices(name).any(|(i, _)| {
            let before = line[..i].chars().next_back().is_none_or(|c| !is_ident(c));
            let after = line[i + name.len()..].chars().next().is_none_or(|c| !is_ident(c));
            before && after
        })
    };
    let lines: Vec<&str> = source.lines().filter(|l| mentions(l) && !l.trim_start().starts_with("contract")).collect();
    let any = |pat: &str| lines.iter().any(|l| l.contains(pat));
    if any("ScriptPubKeyP2SH(") {
        HashUse::P2shTarget
    } else if any("blake2b(byte[](") || (any("blake2b(") && (any("pk") || any("pubkey") || any("Pk"))) {
        HashUse::PubkeyBlake2b
    } else if any(&format!("pubkey({name})")) || {
        let n = name.to_ascii_lowercase();
        ["owner", "pk", "pubkey", "key"].iter().any(|k| n.contains(k))
            && !["hash", "script", "template", "commitment", "guard", "id"].iter().any(|k| n.contains(k))
    } {
        HashUse::Key
    } else if any("blake2b(") {
        HashUse::SecretBlake2b
    } else {
        HashUse::SecretSha256
    }
}

/// `int_default`, adjusted by how the source uses time and running totals.
fn int_default_in(source: &str, name: &str) -> i64 {
    let n = name.to_ascii_lowercase();
    // Running totals a coin starts with (`init_spent`, `claimed`): nothing yet.
    if ["spent", "used", "claimed", "paid", "sold", "minted", "withdrawn", "released"].iter().any(|k| n.contains(k)) {
        return 0;
    }
    // Wall-clock contracts (`tx.time`, no DAA ages): times and durations in milliseconds.
    if source.contains("tx.time") && !source.contains("ageDaa") {
        if ["period", "duration", "interval", "delay", "window"].iter().any(|k| n.ends_with(k)) {
            return 2_592_000_000; // 30 days
        }
        if ["start", "time", "deadline", "until", "after", "end", "at"].iter().any(|k| n.ends_with(k)) {
            return 1_600_000_000_000;
        }
    }
    int_default(name)
}

fn int_default(name: &str) -> i64 {
    let n = name.to_ascii_lowercase();
    let counts = ["periods", "count", "installments", "rounds", "slots", "max_ins", "maxins"];
    if n.contains("fee") {
        50_000
    } else if n.contains("bps") || n.contains("basis") {
        500 // 5%
    } else if counts.iter().any(|k| n.contains(k)) || n == "n" {
        2
    } else if ["time", "lock", "deadline", "age", "daa", "after", "until", "period", "delay", "blocks", "duration"]
        .iter()
        .any(|k| n.contains(k))
    {
        1_000
    } else {
        100_000_000 // 1 KAS in sompi
    }
}

fn default_value(
    source: &str,
    name: &str,
    ty: &TypeArtifact,
    w: &mut Wallets,
    secrets: &mut Vec<Secret>,
    stand_ins: &mut Vec<StandIn>,
) -> Result<(ArtifactValue, String)> {
    Ok(match ty {
        TypeArtifact::Int if loop_bound(source, name) => (ArtifactValue::Int(3), "default (loop bound)".into()),
        TypeArtifact::Int => (ArtifactValue::Int(int_default_in(source, name)), "default".into()),
        TypeArtifact::Temporal => (ArtifactValue::Int(1_600_000_000_000), "default".into()),
        TypeArtifact::Bool => (ArtifactValue::Bool(true), "default".into()),
        // Scheme, type and mode selectors: 0 is the first (usually the plain key) case.
        TypeArtifact::Byte
            if ["scheme", "type", "kind", "mode", "identifier", "flag"]
                .iter()
                .any(|k| name.to_ascii_lowercase().contains(k)) =>
        {
            (ArtifactValue::Byte(0), "default".into())
        }
        TypeArtifact::Byte => (ArtifactValue::Byte(0x11), "default".into()),
        // `ownerScript`, `payoutScript`...: a full scriptPubKey as the script sees it
        // (2-byte version + script). Give it a test party's P2PK so paths paying it
        // can be explored.
        TypeArtifact::Bytes if name.to_ascii_lowercase().contains("script") => {
            let i = w.party(name);
            let mut v = vec![0x00, 0x00];
            v.extend_from_slice(w.parties[i].p2pk().script());
            (ArtifactValue::Bytes(v), format!("p2pk(party:{name})"))
        }
        TypeArtifact::Bytes => (ArtifactValue::Bytes(vec![0x11; 20]), "default".into()),
        TypeArtifact::Text => (ArtifactValue::Text("redteam".into()), "default".into()),
        TypeArtifact::Pubkey => {
            let i = w.party(name);
            (ArtifactValue::Bytes(w.parties[i].xonly().to_vec()), format!("party:{name}"))
        }
        TypeArtifact::FixedBytes { len: 32 } => match hash_use(source, name) {
            HashUse::P2shTarget => {
                let st = StandIn::new(name);
                let h = blake2b(&st.redeem);
                stand_ins.push(st);
                (ArtifactValue::Bytes(h), format!("p2sh(stand-in:{name})"))
            }
            HashUse::Key => {
                let i = w.party(name);
                (ArtifactValue::Bytes(w.parties[i].xonly().to_vec()), format!("party:{name}"))
            }
            HashUse::PubkeyBlake2b => {
                let i = w.party(name);
                (ArtifactValue::Bytes(blake2b(&w.parties[i].xonly())), format!("blake2b(party:{name})"))
            }
            HashUse::SecretBlake2b => {
                let preimage = format!("redteam-secret:{name}").into_bytes();
                secrets.push(Secret { label: name.into(), preimage: preimage.clone() });
                (ArtifactValue::Bytes(blake2b(&preimage)), format!("blake2b(secret:{name})"))
            }
            HashUse::SecretSha256 => {
                let preimage = format!("redteam-secret:{name}").into_bytes();
                secrets.push(Secret { label: name.into(), preimage: preimage.clone() });
                (ArtifactValue::Bytes(sha256(&preimage)), format!("sha256(secret:{name})"))
            }
        },
        TypeArtifact::FixedBytes { len } => (ArtifactValue::Bytes(vec![0x11; *len]), "default".into()),
        TypeArtifact::Sig => (ArtifactValue::Bytes(vec![0; 65]), "default".into()),
        TypeArtifact::Datasig => (ArtifactValue::Bytes(vec![0; 64]), "default".into()),
        TypeArtifact::FixedArray { item, len } => {
            let mut v = Vec::with_capacity(*len);
            for k in 0..*len {
                v.push(default_value(source, &format!("{name}[{k}]"), item, w, secrets, stand_ins)?.0);
            }
            (ArtifactValue::Array(v), "default".into())
        }
        TypeArtifact::DynamicArray { item } => {
            let mut v = Vec::new();
            for k in 0..2 {
                v.push(default_value(source, &format!("{name}[{k}]"), item, w, secrets, stand_ins)?.0);
            }
            (ArtifactValue::Array(v), "default".into())
        }
        TypeArtifact::Struct { name: s } => bail!("struct `{s}` has no automatic default"),
    })
}

/// `--arg` syntax: `123`, `-5`, `0xdeadbeef`, `true`, `@alice` (pubkey of a test
/// party named alice, created if new), anything else is text.
/// A Kaspa address (`kaspa:q...` key, `kaspa:p...` script hash) as its payload bytes.
pub fn decode_address(raw: &str) -> Option<(kaspa_addresses::Version, Vec<u8>)> {
    let a = kaspa_addresses::Address::try_from(raw.trim()).ok()?;
    Some((a.version, a.payload.to_vec()))
}

fn parse_override(raw: &str, ty: &TypeArtifact, w: &mut Wallets) -> Result<ArtifactValue> {
    if raw.trim().starts_with("kaspa") && raw.contains(':') {
        let (version, payload) =
            decode_address(raw).ok_or_else(|| anyhow!("`{raw}` is not a valid Kaspa address (check for a typo)"))?;
        if matches!(ty, TypeArtifact::Pubkey) && version != kaspa_addresses::Version::PubKey {
            bail!("`{raw}` is a contract (P2SH) address; this parameter takes a key, a kaspa:q... address");
        }
        return Ok(ArtifactValue::Bytes(payload));
    }
    if let Some(label) = raw.strip_prefix('@') {
        let i = w.party(label);
        return Ok(ArtifactValue::Bytes(w.parties[i].xonly().to_vec()));
    }
    if let Some(hex) = raw.strip_prefix("0x") {
        let mut out = vec![0u8; hex.len() / 2];
        faster_hex::hex_decode(hex.as_bytes(), &mut out).map_err(|_| anyhow!("bad hex"))?;
        return Ok(match ty {
            TypeArtifact::Byte if out.len() == 1 => ArtifactValue::Byte(out[0]),
            _ => ArtifactValue::Bytes(out),
        });
    }
    match ty {
        TypeArtifact::Int | TypeArtifact::Temporal => Ok(ArtifactValue::Int(raw.replace('_', "").parse()?)),
        TypeArtifact::Bool => Ok(ArtifactValue::Bool(raw.parse()?)),
        TypeArtifact::Byte => Ok(ArtifactValue::Byte(raw.parse()?)),
        TypeArtifact::Text => Ok(ArtifactValue::Text(raw.into())),
        other => bail!("use 0x-hex or @party for type {other:?}"),
    }
}

/// Messages a data-signature path might accept, built from what the script
/// itself compares against: 4-byte tags, 32-byte constructor values (ids), and
/// the lengths it requires, zero-filled. Covers "tag + id + fields" readings.
fn message_candidates(bytecode: &[u8], dispatch_tags: &[Vec<u8>], v32s: &[Vec<u8>], ints: &[i64]) -> Vec<Vec<u8>> {
    let toks = script::tokenize(bytecode);
    let mut tags: Vec<Vec<u8>> = Vec::new();
    for t in &toks {
        if let Token::Push(b) = t {
            if b.len() == 4 && !dispatch_tags.contains(b) && !tags.contains(b) {
                tags.push(b.clone());
            }
        }
    }
    tags.truncate(6);
    let mut lengths: Vec<usize> =
        script::pushed_ints(bytecode).into_iter().filter(|n| (4..=512).contains(n)).map(|n| n as usize).collect();
    lengths.truncate(8);
    let mut ids: Vec<Vec<u8>> = v32s.iter().take(4).cloned().collect();
    ids.push(vec![]);
    // Rank: (0) tag + id at a length the script requires, (1) tag + id
    // filled out to a required length, (2) everything else. A contract with
    // several entries has several tags; ranking keeps each entry's most
    // likely message near the front instead of behind another tag's variants.
    let mut ranked: Vec<(u8, Vec<u8>)> = Vec::new();
    let tag_opts: Vec<Vec<u8>> = if tags.is_empty() { vec![vec![]] } else { tags };
    for tag in &tag_opts {
        for id in &ids {
            let mut base = tag.clone();
            base.extend_from_slice(id);
            let exact = lengths.contains(&base.len());
            ranked.push((if exact && !id.is_empty() { 0 } else { 2 }, base.clone()));
            for l in &lengths {
                if *l > base.len() {
                    let prio = if id.is_empty() { 2 } else { 1 };
                    let mut m = base.clone();
                    m.resize(*l, 0);
                    ranked.push((prio, m));
                    // A trailing 8-byte field may have to equal a constructor value.
                    if *l == base.len() + 8 {
                        for n in ints.iter().take(4) {
                            let mut m = base.clone();
                            m.extend_from_slice(&n.to_le_bytes());
                            ranked.push((prio, m));
                        }
                    }
                }
            }
        }
    }
    ranked.sort_by_key(|(p, _)| *p);
    let mut out: Vec<Vec<u8>> = Vec::new();
    for (_, m) in ranked {
        if !m.is_empty() && !out.contains(&m) {
            out.push(m);
        }
    }
    out.truncate(48);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types() {
        assert_eq!(parse_type("byte[32]").unwrap(), TypeArtifact::FixedBytes { len: 32 });
        assert_eq!(parse_type("byte[]").unwrap(), TypeArtifact::Bytes);
        assert_eq!(
            parse_type("pubkey[3]").unwrap(),
            TypeArtifact::FixedArray { item: Box::new(TypeArtifact::Pubkey), len: 3 }
        );
    }
}

/// `name` is the bound of a `for (i, from, to, BOUND)` loop: the compiler
/// unrolls it, so it must be small.
fn loop_bound(source: &str, name: &str) -> bool {
    let mut rest = source;
    while let Some(i) = rest.find("for") {
        let after = &rest[i + 3..];
        let before_ok = rest[..i].chars().next_back().is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'));
        let t = after.trim_start();
        if before_ok && t.starts_with('(') {
            if let Some(close) = t.find(')') {
                let parts: Vec<&str> = t[1..close].split(',').map(str::trim).collect();
                if parts.len() == 4 && parts[3] == name {
                    return true;
                }
            }
        }
        rest = after;
    }
    false
}

#[cfg(test)]
mod address_tests {
    use super::*;
    use kaspa_addresses::{Address, Prefix, Version};

    #[test]
    fn addresses_decode_to_payloads() {
        let p2sh = Address::new(Prefix::Mainnet, Version::ScriptHash, &[7u8; 32]).to_string();
        let key = Address::new(Prefix::Mainnet, Version::PubKey, &[9u8; 32]).to_string();
        println!("{p2sh}\n{key}");
        let mut w = Wallets::new();
        let ty32 = TypeArtifact::FixedBytes { len: 32 };
        assert_eq!(parse_override(&p2sh, &ty32, &mut w).unwrap(), ArtifactValue::Bytes(vec![7u8; 32]));
        assert_eq!(parse_override(&key, &TypeArtifact::Pubkey, &mut w).unwrap(), ArtifactValue::Bytes(vec![9u8; 32]));
        assert!(parse_override(&p2sh, &TypeArtifact::Pubkey, &mut w).is_err());
        let typo = format!("{}x", &p2sh[..p2sh.len() - 1]);
        assert!(parse_override(&typo, &ty32, &mut w).is_err());
    }
}
