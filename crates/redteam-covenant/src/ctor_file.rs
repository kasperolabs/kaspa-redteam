//! Constructor values from a file: the same JSON a project deploys with.
//!
//! Accepted shapes:
//! - `{ "owner": "0x...", "cap": 500000000, "open": true }` (by name)
//! - `[ "0x...", 500000000, true ]` (in constructor order)
//! - `{ "args": [...] }` or `{ "constructorArgs": ... }` around either of those
//! - `[ { "name": "cap", "value": 500000000 }, ... ]`
//!
//! Keys are the one thing the tool cannot use as given: it cannot sign as your
//! real key. A `pubkey` parameter is played by a test key of the same name
//! (`@owner`), and the report says so. Hashes, ids, templates and numbers are
//! kept exactly.

use anyhow::{Result, anyhow, bail};
use serde_json::Value;
use std::collections::BTreeMap;

fn scalar(v: &Value) -> Result<String> {
    Ok(match v {
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::String(s) => {
            let t = s.trim();
            if t.len() >= 2 && t.chars().all(|c| c.is_ascii_hexdigit()) && t.len() % 2 == 0 && t.len() >= 16 {
                format!("0x{t}") // bare hex, as many tools write it
            } else {
                t.to_string()
            }
        }
        other => bail!("a constructor value must be a number, true/false or a string, not {other}"),
    })
}

/// Name -> value strings (as `--arg` takes them), plus notes for the report.
/// `sources` are the project's contract sources, for parameter names and types.
pub fn load(raw: &str, sources: &[&str]) -> Result<(BTreeMap<String, String>, Vec<String>)> {
    load_full(raw, sources).map(|(v, n, _)| (v, n))
}

/// `load`, plus the real values of the parameters the tool plays (name -> the
/// file's value), so a compiled script built with them can be matched.
pub fn load_full(raw: &str, sources: &[&str]) -> Result<(BTreeMap<String, String>, Vec<String>, BTreeMap<String, String>)> {
    let mut v: Value = serde_json::from_str(raw).map_err(|e| anyhow!("the constructor values file is not JSON: {e}"))?;
    for key in ["constructorArgs", "constructor_args", "args", "params", "constructor"] {
        if let Some(inner) = v.get(key) {
            v = inner.clone();
            break;
        }
    }
    let mut params: Vec<(String, String)> = Vec::new();
    for s in sources {
        if let Ok(ast) = silverscript_lang::ast::parse_contract_ast(s) {
            for p in &ast.params {
                if !params.iter().any(|(n, _)| *n == p.name) {
                    params.push((p.name.clone(), p.type_ref.type_name()));
                }
            }
        }
    }
    let mut out = BTreeMap::new();
    match &v {
        Value::Object(o) => {
            for (k, x) in o {
                out.insert(k.clone(), scalar(x)?);
            }
        }
        Value::Array(a) if a.iter().all(|x| x.get("name").is_some() && x.get("value").is_some()) && !a.is_empty() => {
            for x in a {
                let name = x["name"].as_str().ok_or_else(|| anyhow!("`name` must be a string"))?;
                out.insert(name.to_string(), scalar(&x["value"])?);
            }
        }
        Value::Array(a) => {
            if sources.len() != 1 {
                bail!("constructor values in order (a JSON array) work with one contract; for a project, give them by name");
            }
            if a.len() != params.len() {
                bail!("the file gives {} constructor values in order, the contract takes {}", a.len(), params.len());
            }
            for ((name, _), x) in params.iter().zip(a) {
                out.insert(name.clone(), scalar(x)?);
            }
        }
        _ => bail!("expected a JSON object (name: value) or array (in constructor order)"),
    }
    // Values that only work with a secret the tool does not have.
    let mut keys = Vec::new();
    let mut played = Vec::new();
    let mut real = BTreeMap::new();
    for (name, ty) in &params {
        let Some(val) = out.get(name).cloned() else { continue };
        if val.starts_with('@') {
            continue;
        }
        real.insert(name.clone(), val.clone());
        if ty == "pubkey" {
            out.insert(name.clone(), format!("@{name}"));
            keys.push(name.clone());
        } else if ty == "byte[32]" {
            let src = sources.iter().find(|s| s.contains(name.as_str())).copied().unwrap_or("");
            if let Some(what) = crate::contract::played_by_tool(src, name) {
                out.remove(name);
                played.push(format!("`{name}` ({what})"));
            } else {
                real.remove(name);
            }
        }
    }
    let unknown: Vec<&String> = out.keys().filter(|k| !params.iter().any(|(n, _)| n == *k)).collect();
    if !unknown.is_empty() {
        bail!(
            "the constructor values file names {} that no contract here takes: {}",
            if unknown.len() == 1 { "a parameter" } else { "parameters" },
            unknown.iter().map(|k| format!("`{k}`")).collect::<Vec<_>>().join(", ")
        );
    }
    let mut notes = vec![format!("constructor values: {} from your file", out.len() + played.len())];
    if !played.is_empty() {
        notes.push(format!(
            "played by the tool, because a real value needs a secret it does not have: {}. It uses one it knows (a test key, or the hash of a test secret).",
            played.join(", ")
        ));
    }
    if !keys.is_empty() {
        notes.push(format!(
            "keys from your file are played by test keys of the same name, because the tool cannot sign as your real keys: {}. Every other value (hashes, ids, templates, amounts) is yours, exactly.",
            keys.iter().map(|k| format!("`{k}`")).collect::<Vec<_>>().join(", ")
        ));
    }
    real.retain(|k, _| keys.contains(k) || played.iter().any(|p| p.starts_with(&format!("`{k}`"))));
    Ok((out, notes, real))
}

#[cfg(test)]
mod tests {
    use super::*;
    const SRC: &str = "pragma silverscript ^0.1.0;\ncontract C(pubkey owner, byte[32] lockHash, int cap) {\n    entry open(byte[] secret, sig s) {\n        require(sha256(secret) == lockHash);\n        require(checkSig(s, owner));\n        require(tx.outputs[0].value == cap);\n    }\n}\n";

    #[test]
    fn shapes_and_played_values() {
        let (v, notes) = load(r#"{"constructorArgs":{"owner":"0x11","lockHash":"aa","cap":5}}"#, &[SRC]).unwrap();
        assert_eq!(v.get("owner").map(String::as_str), Some("@owner"));
        assert!(!v.contains_key("lockHash"));
        assert_eq!(v.get("cap").map(String::as_str), Some("5"));
        assert!(notes.iter().any(|n| n.contains("`lockHash` (hash lock)")));
        let (v, _) = load(r#"["0x11", "0x22", 7]"#, &[SRC]).unwrap();
        assert_eq!(v.get("cap").map(String::as_str), Some("7"));
        let (v, _) = load(r#"[{"name":"cap","value":9}]"#, &[SRC]).unwrap();
        assert_eq!(v.get("cap").map(String::as_str), Some("9"));
        assert!(load(r#"{"nope": 1}"#, &[SRC]).is_err());
        assert!(load(r#"[1]"#, &[SRC]).is_err());
    }
}
