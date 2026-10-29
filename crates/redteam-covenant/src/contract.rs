//! Loading a covenant: parse the SilverScript source, pick constructor
//! arguments (test keys by default), compile in process, and describe the
//! spend paths.

use crate::script;
use crate::wallets::{KeyRef, Wallets};
use anyhow::{Context, Result, anyhow, bail};
use silverscript_abi::{ArtifactValue, SilAbiArtifact, TypeArtifact};
use std::collections::BTreeMap;

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
        self.params
            .iter()
            .any(|p| matches!(p.ty, TypeArtifact::Sig))
    }
}

pub struct Contract {
    pub file_name: String,
    pub source: String,
    pub contract_name: String,
    pub args: Vec<CtorArg>,
    pub artifact: SilAbiArtifact,
    pub bytecode: Vec<u8>,
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
}

impl Contract {
    /// `overrides`: `name=value` pairs from the command line.
    pub fn load(
        file_name: &str,
        source: &str,
        overrides: &BTreeMap<String, String>,
    ) -> Result<Self> {
        let ast = silverscript_lang::ast::parse_contract_ast(source)
            .map_err(|e| anyhow!("parse error: {e}"))?;
        let mut wallets = Wallets::new();
        let mut secrets = Vec::new();
        let mut args = Vec::new();
        let mut ctor_ints = Vec::new();

        for p in &ast.params {
            let type_name = p.type_ref.type_name();
            let ty = parse_type(&type_name).with_context(|| format!("constructor `{}`", p.name))?;
            let (value, origin) = match overrides.get(&p.name) {
                Some(raw) => (
                    parse_override(raw, &ty, &mut wallets)
                        .with_context(|| format!("--arg {}", p.name))?,
                    "override".into(),
                ),
                None => default_value(source, &p.name, &ty, &mut wallets, &mut secrets)
                    .with_context(|| {
                        format!(
                            "constructor `{}` ({type_name}) needs a value: pass --arg {}=...",
                            p.name, p.name
                        )
                    })?,
            };
            if let ArtifactValue::Int(n) = value {
                ctor_ints.push(n);
            }
            args.push(CtorArg {
                name: p.name.clone(),
                ty: type_name,
                origin,
                value,
            });
        }
        for k in overrides.keys() {
            if !ast.params.iter().any(|p| &p.name == k) {
                bail!("--arg {k}: the contract has no constructor parameter named `{k}`");
            }
        }

        let values: Vec<ArtifactValue> = args.iter().map(|a| a.value.clone()).collect();
        let artifact = silverscript_lang::compiler::compile_to_sil_abi_artifact(source, &values)
            .map_err(|e| anyhow!("compile error: {e}"))?;
        if artifact.contracts.len() != 1 {
            bail!(
                "expected exactly one contract in the file, found {}",
                artifact.contracts.len()
            );
        }
        let (contract_name, c) = artifact.contracts.iter().next().unwrap();
        let bytecode = c.compiled.bytecode.clone();
        let entries = c
            .entries
            .iter()
            .map(|(name, e)| Entry {
                name: name.clone(),
                params: e
                    .params
                    .iter()
                    .map(|p| EntryParam {
                        name: p.name.clone(),
                        ty: p.ty.clone(),
                    })
                    .collect(),
            })
            .collect();
        let (cltv_values, csv_values) = script::lock_values(&bytecode);
        let has_covenant_decls = !c.cov_decl_to_abi.is_empty();

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
            entries,
            wallets,
            secrets,
            bytecode,
            artifact: artifact.clone(),
        })
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
        self.wallets
            .parties
            .iter()
            .position(|w| w.xonly() == bytes)
            .map(KeyRef::Party)
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
            Some(
                inner
                    .parse()
                    .map_err(|_| anyhow!("unsupported array size `{inner}`"))?,
            )
        });
    }
    let mut ty = match (base, parts.first()) {
        ("byte", Some(Some(n))) => TypeArtifact::FixedBytes { len: *n },
        ("byte", Some(None)) => TypeArtifact::Bytes,
        _ => TypeArtifact::from_parts(base, None),
    };
    let skip = if base == "byte" && !parts.is_empty() {
        1
    } else {
        0
    };
    for d in parts.into_iter().skip(skip) {
        ty = match d {
            Some(len) => TypeArtifact::FixedArray {
                item: Box::new(ty),
                len,
            },
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
    blake2b_simd::Params::new()
        .hash_length(32)
        .hash(b)
        .as_bytes()
        .to_vec()
}

enum HashUse {
    PubkeyBlake2b,
    SecretSha256,
    SecretBlake2b,
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
            let after = line[i + name.len()..]
                .chars()
                .next()
                .is_none_or(|c| !is_ident(c));
            before && after
        })
    };
    let lines: Vec<&str> = source
        .lines()
        .filter(|l| mentions(l) && !l.trim_start().starts_with("contract"))
        .collect();
    let any = |pat: &str| lines.iter().any(|l| l.contains(pat));
    if any("blake2b(byte[](") || (any("blake2b(") && (any("pk") || any("pubkey") || any("Pk"))) {
        HashUse::PubkeyBlake2b
    } else if any("blake2b(") {
        HashUse::SecretBlake2b
    } else {
        HashUse::SecretSha256
    }
}

fn int_default(name: &str) -> i64 {
    let n = name.to_ascii_lowercase();
    if n.contains("fee") {
        50_000
    } else if [
        "time", "lock", "deadline", "age", "daa", "after", "until", "period", "delay", "blocks",
        "duration",
    ]
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
) -> Result<(ArtifactValue, String)> {
    Ok(match ty {
        TypeArtifact::Int => (ArtifactValue::Int(int_default(name)), "default".into()),
        TypeArtifact::Temporal => (ArtifactValue::Int(1_600_000_000_000), "default".into()),
        TypeArtifact::Bool => (ArtifactValue::Bool(true), "default".into()),
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
            (
                ArtifactValue::Bytes(w.parties[i].xonly().to_vec()),
                format!("party:{name}"),
            )
        }
        TypeArtifact::FixedBytes { len: 32 } => match hash_use(source, name) {
            HashUse::PubkeyBlake2b => {
                let i = w.party(name);
                (
                    ArtifactValue::Bytes(blake2b(&w.parties[i].xonly())),
                    format!("blake2b(party:{name})"),
                )
            }
            HashUse::SecretBlake2b => {
                let preimage = format!("redteam-secret:{name}").into_bytes();
                secrets.push(Secret {
                    label: name.into(),
                    preimage: preimage.clone(),
                });
                (
                    ArtifactValue::Bytes(blake2b(&preimage)),
                    format!("blake2b(secret:{name})"),
                )
            }
            HashUse::SecretSha256 => {
                let preimage = format!("redteam-secret:{name}").into_bytes();
                secrets.push(Secret {
                    label: name.into(),
                    preimage: preimage.clone(),
                });
                (
                    ArtifactValue::Bytes(sha256(&preimage)),
                    format!("sha256(secret:{name})"),
                )
            }
        },
        TypeArtifact::FixedBytes { len } => {
            (ArtifactValue::Bytes(vec![0x11; *len]), "default".into())
        }
        TypeArtifact::Sig => (ArtifactValue::Bytes(vec![0; 65]), "default".into()),
        TypeArtifact::Datasig => (ArtifactValue::Bytes(vec![0; 64]), "default".into()),
        TypeArtifact::FixedArray { item, len } => {
            let mut v = Vec::with_capacity(*len);
            for k in 0..*len {
                v.push(default_value(source, &format!("{name}[{k}]"), item, w, secrets)?.0);
            }
            (ArtifactValue::Array(v), "default".into())
        }
        TypeArtifact::DynamicArray { item } => {
            let mut v = Vec::new();
            for k in 0..2 {
                v.push(default_value(source, &format!("{name}[{k}]"), item, w, secrets)?.0);
            }
            (ArtifactValue::Array(v), "default".into())
        }
        TypeArtifact::Struct { name: s } => bail!("struct `{s}` has no automatic default"),
    })
}

/// `--arg` syntax: `123`, `-5`, `0xdeadbeef`, `true`, `@alice` (pubkey of a test
/// party named alice, created if new), anything else is text.
fn parse_override(raw: &str, ty: &TypeArtifact, w: &mut Wallets) -> Result<ArtifactValue> {
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
        TypeArtifact::Int | TypeArtifact::Temporal => {
            Ok(ArtifactValue::Int(raw.replace('_', "").parse()?))
        }
        TypeArtifact::Bool => Ok(ArtifactValue::Bool(raw.parse()?)),
        TypeArtifact::Byte => Ok(ArtifactValue::Byte(raw.parse()?)),
        TypeArtifact::Text => Ok(ArtifactValue::Text(raw.into())),
        other => bail!("use 0x-hex or @party for type {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types() {
        assert_eq!(
            parse_type("byte[32]").unwrap(),
            TypeArtifact::FixedBytes { len: 32 }
        );
        assert_eq!(parse_type("byte[]").unwrap(), TypeArtifact::Bytes);
        assert_eq!(
            parse_type("pubkey[3]").unwrap(),
            TypeArtifact::FixedArray {
                item: Box::new(TypeArtifact::Pubkey),
                len: 3
            }
        );
    }
}
