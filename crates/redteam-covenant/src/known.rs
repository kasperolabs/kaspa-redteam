//! Known programs. A real transaction often spends coins of a program the user
//! did not hand over (a KCC-20 token cell next to the market under test). When
//! such a coin's redeem script is, byte for byte outside its state window, a
//! pinned program, the tool knows its state layout and entry points and can
//! read and rebuild its signature script like any project file.
//!
//! Identification is the KCC-1 template hash: BLAKE3(u64le(|prefix|) ‖ prefix
//! ‖ u64le(|suffix|) ‖ suffix), where prefix and suffix are the program around
//! its state window. Exact matching only: a program that differs by one byte
//! outside the state is not the pinned one and stays opaque.
//!
//! Shipped pins: the KCC-20 reference (argent-lang/kcc20-reference c8a0871),
//! `library/kcc20-reference/`. A `.sil` file given next to a baseline becomes a
//! pin of its own (`from_contract`).

use crate::contract::Contract;
use crate::sandbox::StateValues;
use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use silverscript_abi::{ArtifactValue, SilAbiArtifact, TypeArtifact};
use std::sync::{Arc, OnceLock};

const KCC20_TEMPLATES: &str = include_str!("../library/kcc20-reference/templates.json");
const KCC20_ABI: &str = include_str!("../library/kcc20-reference/sil-abi.json");
/// The shipped sources, for users who want to attack the reference itself.
pub const LIBRARY_SOURCES: &[(&str, &str)] = &[
    ("KCC20.sil", include_str!("../library/kcc20-reference/KCC20.sil")),
    ("PublicMint.sil", include_str!("../library/kcc20-reference/PublicMint.sil")),
    ("TokenSeed.sil", include_str!("../library/kcc20-reference/TokenSeed.sil")),
];
pub const TEMPLATES_FORMAT: &str = "kaspa-program-templates/1";

/// KCC-1 TemplateHash.
pub fn template_hash(prefix: &[u8], suffix: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&(prefix.len() as u64).to_le_bytes());
    h.update(prefix);
    h.update(&(suffix.len() as u64).to_le_bytes());
    h.update(suffix);
    *h.finalize().as_bytes()
}

/// A program the tool can recognize in a transaction.
#[derive(Clone)]
pub struct Pin {
    pub name: String,
    /// Where it comes from, for the report: `argent-lang/kcc20-reference@c8a0871`
    /// or the file name a user gave.
    pub origin: String,
    pub hash: [u8; 32],
    pub prefix: Vec<u8>,
    pub suffix: Vec<u8>,
    pub state_len: usize,
    pub abi: Arc<SilAbiArtifact>,
    pub contract: String,
    /// One of the KCC-20 reference programs: its witness layout is known.
    pub kcc20: bool,
}

impl Pin {
    pub fn hash_hex(&self) -> String {
        faster_hex::hex_string(&self.hash)
    }
    pub fn short_hash(&self) -> String {
        self.hash_hex()[..12].to_string()
    }
    fn contract_abi(&self) -> Option<&silverscript_abi::SilContractArtifact> {
        self.abi.contracts.get(&self.contract)
    }
    /// The redeem script of this program in `state`.
    pub fn redeem(&self, state: &StateValues) -> Option<Vec<u8>> {
        let c = self.contract_abi()?;
        let window = silverscript_abi::encode_runtime_state_script(&self.abi, &c.runtime_state, state).ok()?;
        if window.len() != self.state_len {
            return None;
        }
        let mut out = self.prefix.clone();
        out.extend(window);
        out.extend(&self.suffix);
        Some(out)
    }
    /// The signature script for `entry(args)` spending the coin with `redeem`.
    pub fn sig_script(&self, entry: &str, args: &[ArtifactValue], redeem: &[u8]) -> Option<Vec<u8>> {
        let mut s = silverscript_abi::encode_contract_entry_sig_script(&self.abi, &self.contract, entry, args).ok()?;
        s.extend(crate::sandbox::push_data(redeem).ok()?);
        Some(s)
    }
}

fn hex_field(v: &Value, what: &str) -> Result<Vec<u8>> {
    let s = v.as_str().ok_or_else(|| anyhow!("{what}: expected hex"))?;
    let mut out = vec![0u8; s.len() / 2];
    faster_hex::hex_decode(s.as_bytes(), &mut out).map_err(|_| anyhow!("{what}: bad hex"))?;
    Ok(out)
}

/// Pins from a `kaspa-program-templates/1` file, encoded with `abi`. Every
/// stated template hash is checked against the bytes, and every pin's bytecode
/// against the ABI's compiled program: a mismatch is refused.
pub fn load_templates(json: &str, abi: Arc<SilAbiArtifact>) -> Result<Vec<Pin>> {
    let doc: Value = serde_json::from_str(json).context("templates: not JSON")?;
    if doc.get("format").and_then(|f| f.as_str()) != Some(TEMPLATES_FORMAT) {
        bail!("templates: format is not `{TEMPLATES_FORMAT}`");
    }
    let list = doc.get("templates").and_then(|t| t.as_array()).ok_or_else(|| anyhow!("templates: missing list"))?;
    let mut out = Vec::new();
    for t in list {
        let name = t.get("name").and_then(|n| n.as_str()).unwrap_or("unnamed").to_string();
        let code = hex_field(t.get("bytecode").unwrap_or(&Value::Null), &name)?;
        let start = t.get("stateStart").and_then(|v| v.as_u64()).ok_or_else(|| anyhow!("{name}: stateStart"))? as usize;
        let len = t.get("stateLen").and_then(|v| v.as_u64()).ok_or_else(|| anyhow!("{name}: stateLen"))? as usize;
        if start + len > code.len() {
            bail!("template {name}: state window {start}+{len} does not fit its {} bytes", code.len());
        }
        let prefix = code[..start].to_vec();
        let suffix = code[start + len..].to_vec();
        let hash = template_hash(&prefix, &suffix);
        if let Some(stated) = t.get("templateHash") {
            let stated = hex_field(stated, &name)?;
            if stated != hash {
                bail!(
                    "template {name}: stated hash {} but the bytes hash to {}",
                    faster_hex::hex_string(&stated),
                    faster_hex::hex_string(&hash)
                );
            }
        }
        let c = abi.contracts.get(&name).ok_or_else(|| anyhow!("template {name}: not in the ABI"))?;
        if c.compiled.bytecode != code {
            bail!("template {name}: bytecode differs from the ABI's compiled program");
        }
        let origin = t
            .get("origin")
            .map(|o| {
                let repo = o.get("repo").and_then(|r| r.as_str()).unwrap_or("");
                let repo = repo.trim_start_matches("https://github.com/");
                let commit = o.get("commit").and_then(|r| r.as_str()).unwrap_or("");
                format!("{repo}@{}", &commit[..commit.len().min(7)])
            })
            .unwrap_or_default();
        let family = t.get("family").and_then(|f| f.as_str()).unwrap_or("");
        out.push(Pin {
            kcc20: family == "KCC-20 reference",
            name: name.clone(),
            origin,
            hash,
            prefix,
            suffix,
            state_len: len,
            abi: abi.clone(),
            contract: name,
        });
    }
    Ok(out)
}

/// The pins shipped with the tool.
pub fn builtin() -> &'static [Pin] {
    static PINS: OnceLock<Vec<Pin>> = OnceLock::new();
    PINS.get_or_init(|| {
        let abi: SilAbiArtifact = serde_json::from_str(KCC20_ABI).expect("bundled KCC-20 ABI parses");
        load_templates(KCC20_TEMPLATES, Arc::new(abi)).expect("bundled KCC-20 templates match their bytes")
    })
}

/// A user's `.sil` file as a pin (its program as compiled here, with the
/// constructor values the run uses). None when it has no state window.
pub fn from_contract(c: &Contract) -> Option<Pin> {
    let abi = c.artifact.clone()?;
    let (name, ca) = abi.contracts.iter().next()?;
    let span = ca.compiled.state_span;
    if span.len == 0 || span.offset + span.len > c.bytecode.len() {
        return None;
    }
    let prefix = c.bytecode[..span.offset].to_vec();
    let suffix = c.bytecode[span.offset + span.len..].to_vec();
    Some(Pin {
        name: name.clone(),
        origin: c.file_name.clone(),
        hash: template_hash(&prefix, &suffix),
        prefix,
        suffix,
        state_len: span.len,
        contract: name.clone(),
        abi: Arc::new(abi),
        kcc20: false,
    })
}

/// Pushes of a push-only script, each with the offset of its data.
pub fn pushes(script: &[u8]) -> Option<Vec<(usize, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        i += 1;
        let len = match op {
            0x00 => {
                out.push((i, vec![]));
                continue;
            }
            0x01..=0x4b => op as usize,
            0x4c => {
                let n = *script.get(i)? as usize;
                i += 1;
                n
            }
            0x4d => {
                let n = u16::from_le_bytes([*script.get(i)?, *script.get(i + 1)?]) as usize;
                i += 2;
                n
            }
            0x4e => {
                let b = script.get(i..i + 4)?;
                i += 4;
                u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize
            }
            0x4f => {
                out.push((i, vec![0x81]));
                continue;
            }
            0x51..=0x60 => {
                out.push((i, vec![op - 0x50]));
                continue;
            }
            _ => return None,
        };
        out.push((i, script.get(i..i + len)?.to_vec()));
        i += len;
    }
    Some(out)
}

/// A coin of a pinned program, as an input spends it.
#[derive(Clone)]
pub struct Recognized {
    pub pin: Pin,
    pub state: StateValues,
    pub redeem: Vec<u8>,
    /// The entry it is spent through and its arguments, when the signature
    /// script decodes and encodes back to the same bytes.
    pub call: Option<Call>,
}

#[derive(Clone)]
pub struct Call {
    pub entry: String,
    pub args: Vec<ArtifactValue>,
    /// Offset in the signature script of the data of each argument's first push.
    pub arg_at: Vec<usize>,
}

/// The program a redeem script is, exactly, among `pins`.
pub fn match_redeem(redeem: &[u8], pins: &[Pin]) -> Option<(Pin, StateValues)> {
    for p in pins {
        if redeem.len() != p.prefix.len() + p.state_len + p.suffix.len()
            || !redeem.starts_with(&p.prefix)
            || !redeem.ends_with(&p.suffix)
        {
            continue;
        }
        let c = p.contract_abi()?;
        let window = &redeem[p.prefix.len()..p.prefix.len() + p.state_len];
        if let Ok(state) = silverscript_abi::decode_runtime_state_script(&p.abi, &c.runtime_state, window) {
            return Some((p.clone(), state));
        }
    }
    None
}

/// An input's signature script, if it spends a coin of one of `pins` (the
/// redeem script is its last push).
pub fn recognize(sig_script: &[u8], pins: &[Pin]) -> Option<Recognized> {
    let ps = pushes(sig_script)?;
    let (_, redeem) = ps.last()?;
    let (pin, state) = match_redeem(redeem, pins)?;
    let call = decode_call(&pin, sig_script, &ps[..ps.len() - 1], redeem);
    Some(Recognized { pin, state, redeem: redeem.clone(), call })
}

fn fixed_size(ty: &TypeArtifact) -> Option<usize> {
    Some(match ty {
        TypeArtifact::Int => 8,
        TypeArtifact::Byte | TypeArtifact::Bool => 1,
        TypeArtifact::Pubkey => 32,
        TypeArtifact::FixedBytes { len } => *len,
        _ => return None,
    })
}

fn fixed_value(ty: &TypeArtifact, b: &[u8]) -> Option<ArtifactValue> {
    Some(match ty {
        TypeArtifact::Int => {
            let mut m = [0u8; 8];
            m.copy_from_slice(b);
            let neg = m[7] & 0x80 != 0;
            m[7] &= 0x7f;
            let n = i64::from_le_bytes(m);
            ArtifactValue::Int(if neg { -n } else { n })
        }
        TypeArtifact::Byte => ArtifactValue::Byte(b[0]),
        TypeArtifact::Bool => ArtifactValue::Bool(b[0] != 0),
        _ => ArtifactValue::Bytes(b.to_vec()),
    })
}

/// Reads the arguments back from a signature script, and keeps them only if
/// they encode to exactly the same bytes.
fn decode_call(pin: &Pin, sig_script: &[u8], args: &[(usize, Vec<u8>)], redeem: &[u8]) -> Option<Call> {
    let (_, tag) = args.last()?;
    let c = pin.contract_abi()?;
    let (entry, e) = c.entries.iter().find(|(_, e)| e.dispatch_tag.as_bytes() == tag.as_slice())?;
    let mut at = 0;
    let mut values = Vec::new();
    let mut arg_at = Vec::new();
    for p in &e.params {
        arg_at.push(args.get(at)?.0);
        let v = match &p.ty {
            TypeArtifact::DynamicArray { item } | TypeArtifact::FixedArray { item, .. } => {
                let TypeArtifact::Struct { name } = item.as_ref() else { return None };
                let fields = &pin.abi.structs.get(name)?.fields;
                let mut columns = Vec::new();
                let mut n = None;
                for f in fields {
                    let size = fixed_size(&f.ty)?;
                    let data = &args.get(at)?.1;
                    at += 1;
                    if data.len() % size != 0 || n.is_some_and(|n| n != data.len() / size) {
                        return None;
                    }
                    n = Some(data.len() / size);
                    columns.push(data.chunks(size).map(|b| fixed_value(&f.ty, b)).collect::<Option<Vec<_>>>()?);
                }
                let n = n.unwrap_or(0);
                let items = (0..n)
                    .map(|k| {
                        ArtifactValue::Object(
                            fields.iter().zip(&columns).map(|(f, col)| (f.name.clone(), col[k].clone())).collect(),
                        )
                    })
                    .collect();
                ArtifactValue::Array(items)
            }
            TypeArtifact::Bytes => {
                at += 1;
                ArtifactValue::Bytes(args[at - 1].1.clone())
            }
            TypeArtifact::Int => {
                at += 1;
                ArtifactValue::Int(crate::script::script_num(&args[at - 1].1)?)
            }
            ty => {
                let size = fixed_size(ty).or(matches!(ty, TypeArtifact::Sig).then_some(65))?;
                at += 1;
                let b = &args[at - 1].1;
                if b.len() != size {
                    return None;
                }
                fixed_value(ty, b)?
            }
        };
        values.push(v);
    }
    if at + 1 != args.len() {
        return None;
    }
    let again = pin.sig_script(entry, &values, redeem)?;
    (again == sig_script).then(|| Call { entry: entry.clone(), args: values, arg_at })
}

pub fn byte_of(st: &StateValues, field: &str) -> Option<u8> {
    match st.get(field)? {
        ArtifactValue::Byte(b) => Some(*b),
        ArtifactValue::Int(i) => u8::try_from(*i).ok(),
        _ => None,
    }
}

pub fn int_of(st: &StateValues, field: &str) -> Option<i64> {
    match st.get(field)? {
        ArtifactValue::Int(i) => Some(*i),
        _ => None,
    }
}

pub fn bytes_of<'a>(st: &'a StateValues, field: &str) -> Option<&'a [u8]> {
    match st.get(field)? {
        ArtifactValue::Bytes(b) => Some(b),
        _ => None,
    }
}

/// KCC-2 owner schemes, as KCC-20 numbers them.
pub fn owner_scheme_name(s: u8) -> &'static str {
    match s {
        0 => "P2PK Schnorr",
        1 => "P2PKH Schnorr",
        2 => "P2PKH ECDSA",
        3 => "P2SH",
        4 => "covenant id",
        _ => "unknown scheme",
    }
}

/// A transaction signature inside a KCC-20 witness (the token owner's, or the
/// borrow guard's): offset of the 64-byte signature in the signature script,
/// and whether it is Schnorr (the tool can remake those with a listed key).
#[derive(Clone, Copy, Debug)]
pub struct WitnessSig {
    pub at: usize,
    pub schnorr: bool,
}

/// Signatures a KCC-20 witness carries. KCC-20's `transfer(next_states,
/// witness)` puts the owner's signature inside the `witness` bytes (path byte,
/// then the scheme's own layout), never as a push of its own.
pub fn witness_signatures(r: &Recognized) -> Vec<WitnessSig> {
    if !r.pin.kcc20 || r.pin.name != "KCC20" {
        return vec![];
    }
    let Some(call) = &r.call else { return vec![] };
    let Some(wi) = call.entry_param_index("witness", &r.pin) else { return vec![] };
    let Some(ArtifactValue::Bytes(w)) = call.args.get(wi) else { return vec![] };
    let base = call.arg_at[wi];
    let owner = byte_of(&r.state, "owner_scheme").unwrap_or(255);
    let borrow = byte_of(&r.state, "borrow_scheme").unwrap_or(255);
    // (offset in the witness, expected witness length, schnorr)
    let spot = if call.entry == "transfer" {
        match (w.first().copied(), owner, borrow) {
            (Some(0), 0, _) => Some((1, 66, true)),
            (Some(0), 1, _) => Some((33, 98, true)),
            (Some(0), 2, _) => Some((34, 99, false)),
            (Some(1), _, 2) => Some((1, 66, true)),
            (Some(1), _, 3) => Some((65, 130, true)),
            _ => None,
        }
    } else {
        match owner {
            0 => Some((0, 65, true)),
            1 => Some((32, 97, true)),
            2 => Some((33, 98, false)),
            _ => None,
        }
    };
    match spot {
        Some((off, len, schnorr)) if w.len() == len => vec![WitnessSig { at: base + off, schnorr }],
        _ => vec![],
    }
}

impl Call {
    fn entry_param_index(&self, name: &str, pin: &Pin) -> Option<usize> {
        pin.contract_abi()?.entries.get(&self.entry)?.params.iter().position(|p| p.name == name)
    }
}

/// Offsets of transaction signatures inside known witnesses of this signature
/// script (builtin pins only).
pub fn builtin_witness_signatures(sig_script: &[u8]) -> Vec<WitnessSig> {
    recognize(sig_script, builtin()).map(|r| witness_signatures(&r)).unwrap_or_default()
}

/// One line per recognized coin, for the report.
pub fn describe(input: usize, r: &Recognized) -> String {
    let mut s = format!(
        "recognized {} at input {input} by template hash {}… ({}); ",
        r.pin.name,
        r.pin.short_hash(),
        r.pin.origin
    );
    if r.pin.kcc20 && r.pin.name == "KCC20" {
        let amount = int_of(&r.state, "amount").map(|a| a.to_string()).unwrap_or_else(|| "?".into());
        let scheme = byte_of(&r.state, "owner_scheme").unwrap_or(255);
        let borrow = byte_of(&r.state, "borrow_scheme").unwrap_or(255);
        s.push_str(&format!(
            "a KCC-20 cell of {amount} units, owner scheme {} ({}), borrowing {}",
            scheme,
            owner_scheme_name(scheme),
            if borrow == 0 { "off".to_string() } else { format!("on (scheme {borrow})") }
        ));
        if let Some(c) = &r.call {
            s.push_str(&format!(", spent through `{}`", c.entry));
        }
    } else {
        s.push_str("its state and entry points are known");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_pins_load_with_the_studio_hashes() {
        let pins = builtin();
        let by = |n: &str| pins.iter().find(|p| p.name == n).unwrap().hash_hex();
        assert_eq!(by("KCC20"), "9703112ee6e3555107cd168858992b77d3b74f655205b2b463b1f9ec2ec73cf7");
        assert_eq!(by("PublicMint"), "14b0f06bc176b78c94f19292e409c622636f31dae6bb31ff3d4d3308a6053b49");
        assert_eq!(by("TokenSeed"), "f79a3fccf6f87d7076662410a17e54d1531889d9b60f630f9fbb8465a384e62d");
        for p in pins {
            assert_eq!(p.abi.contracts[&p.name].compiled.template_hash, p.hash, "{}", p.name);
        }
    }

    #[test]
    fn a_tampered_template_is_refused() {
        let mut doc: Value = serde_json::from_str(KCC20_TEMPLATES).unwrap();
        doc["templates"][0]["templateHash"] = Value::String("00".repeat(32));
        let abi: SilAbiArtifact = serde_json::from_str(KCC20_ABI).unwrap();
        assert!(load_templates(&doc.to_string(), Arc::new(abi)).is_err());
    }

    fn cell(owner_scheme: u8, amount: i64) -> StateValues {
        let k = builtin().iter().find(|p| p.name == "KCC20").unwrap();
        let mut st = StateValues::new();
        st.insert("gen__kcc20_template".into(), ArtifactValue::Bytes(k.hash.to_vec()));
        st.insert("amount".into(), ArtifactValue::Int(amount));
        st.insert("owner".into(), ArtifactValue::Bytes(vec![7; 32]));
        st.insert("owner_scheme".into(), ArtifactValue::Byte(owner_scheme));
        st.insert("borrow_scheme".into(), ArtifactValue::Byte(0));
        st.insert("borrow_guard".into(), ArtifactValue::Bytes(vec![0; 32]));
        st.insert("extension_commitment".into(), ArtifactValue::Bytes(vec![0; 32]));
        st
    }

    fn next(amount: i64) -> ArtifactValue {
        let mut o = std::collections::BTreeMap::new();
        o.insert("amount".into(), ArtifactValue::Int(amount));
        o.insert("owner".into(), ArtifactValue::Bytes(vec![9; 32]));
        o.insert("owner_scheme".into(), ArtifactValue::Byte(0));
        o.insert("borrow_scheme".into(), ArtifactValue::Byte(0));
        o.insert("borrow_guard".into(), ArtifactValue::Bytes(vec![0; 32]));
        o.insert("extension_commitment".into(), ArtifactValue::Bytes(vec![0; 32]));
        ArtifactValue::Object(o)
    }

    #[test]
    fn a_kcc20_transfer_reads_back_and_finds_the_owner_signature() {
        let k = builtin().iter().find(|p| p.name == "KCC20").unwrap();
        let redeem = k.redeem(&cell(0, 1000)).unwrap();
        let mut w = vec![0u8];
        w.extend([0xab; 64]);
        w.push(0x01);
        let args = vec![ArtifactValue::Array(vec![next(600), next(400)]), ArtifactValue::Bytes(w)];
        let s = k.sig_script("transfer", &args, &redeem).unwrap();
        let r = recognize(&s, builtin()).expect("recognized");
        assert_eq!(r.pin.name, "KCC20");
        assert_eq!(int_of(&r.state, "amount"), Some(1000));
        let call = r.call.clone().expect("call decodes");
        assert_eq!(call.entry, "transfer");
        assert_eq!(call.args, args);
        let sigs = witness_signatures(&r);
        assert_eq!(sigs.len(), 1);
        assert_eq!(&s[sigs[0].at..sigs[0].at + 64], &[0xab; 64]);
        assert_eq!(s[sigs[0].at + 64], 0x01);
        // A covenant-owned cell carries no signature.
        let r2 = k.redeem(&cell(4, 1000)).unwrap();
        let s2 = k.sig_script("transfer", &[args[0].clone(), ArtifactValue::Bytes(vec![0])], &r2).unwrap();
        assert!(witness_signatures(&recognize(&s2, builtin()).unwrap()).is_empty());
    }

    #[test]
    fn one_byte_off_is_not_the_reference() {
        let k = builtin().iter().find(|p| p.name == "KCC20").unwrap();
        let mut redeem = k.redeem(&cell(4, 5)).unwrap();
        let n = redeem.len();
        redeem[n - 3] ^= 1;
        assert!(match_redeem(&redeem, builtin()).is_none());
    }
}
