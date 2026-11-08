//! Constructor values from a file: the same JSON a project deploys with.
//!
//! Accepted shapes:
//! - `{ "owner": "0x...", "cap": 500000000, "open": true }` (by name)
//! - `[ "0x...", 500000000, true ]` (in constructor order)
//! - `{ "args": [...] }` or `{ "constructorArgs": ... }` around either of those
//! - `[ { "name": "cap", "value": 500000000 }, ... ]`
//! - `[ { "kind": "bytes", "value": [3, 3, ...] }, { "kind": "int", "value": 1 } ]`
//!   (silverc's own constructor file: values in order, each with its kind)
//!
//! Keys are the one thing the tool cannot use as given: it cannot sign as your
//! real key. A `pubkey` parameter is played by a test key of the same name
//! (`@owner`), and the report says so. Hashes, ids, templates and numbers are
//! kept exactly.

use anyhow::{Result, anyhow, bail};
use serde_json::Value;
use std::collections::BTreeMap;

/// A `{kind, value}` value, as silverc takes it: `int`, `bool`, `byte` (a
/// number), `bytes` / `pubkey` / `byte[N]` (an array of numbers or a hex string).
fn kind_value(kind: &str, v: &Value) -> Result<String> {
    let k = kind.trim().to_ascii_lowercase();
    match k.as_str() {
        "int" | "byte" | "bool" => match v {
            Value::Number(_) | Value::Bool(_) => scalar(v),
            Value::String(s) if k != "bool" && s.trim().parse::<i128>().is_ok() => Ok(s.trim().to_string()),
            other => bail!("a `{k}` value must be a number{}, not {other}", if k == "bool" { " or true/false" } else { "" }),
        },
        _ if k == "bytes" || k == "pubkey" || k.starts_with("byte[") => match v {
            Value::Array(a) => {
                let mut b = Vec::with_capacity(a.len());
                for x in a {
                    let n = x.as_u64().filter(|n| *n < 256).ok_or_else(|| anyhow!("a `{k}` value must be numbers 0..255, not {x}"))?;
                    b.push(n as u8);
                }
                Ok(format!("0x{}", faster_hex::hex_string(&b)))
            }
            Value::String(s) => {
                let t = s.trim().trim_start_matches("0x");
                if t.len() % 2 != 0 || !t.chars().all(|c| c.is_ascii_hexdigit()) {
                    bail!("a `{k}` value given as a string must be hex, not `{s}`");
                }
                Ok(format!("0x{t}"))
            }
            other => bail!("a `{k}` value must be an array of byte numbers or a hex string, not {other}"),
        },
        _ => bail!("unknown constructor value kind `{kind}` (expected int, bool, byte, bytes or pubkey)"),
    }
}

/// Does a `{kind}` from the file fit a parameter of type `ty`?
fn kind_fits(kind: &str, ty: &str) -> bool {
    match kind.trim().to_ascii_lowercase().as_str() {
        "int" => ty == "int",
        "bool" => ty == "bool",
        "byte" => ty == "byte",
        _ => ty == "pubkey" || ty.starts_with("byte[") || ty == "bytes",
    }
}

fn scalar(v: &Value) -> Result<String> {
    if let Some(kind) = v.get("kind").and_then(|k| k.as_str()) {
        if let Some(inner) = v.get("value") {
            return kind_value(kind, inner);
        }
    }
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
    let mut per_source: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for s in sources {
        if let Ok(ast) = silverscript_lang::ast::parse_contract_ast(s) {
            let mine: Vec<(String, String)> = ast.params.iter().map(|p| (p.name.clone(), p.type_ref.type_name())).collect();
            for p in &mine {
                if !params.iter().any(|(n, _)| *n == p.0) {
                    params.push(p.clone());
                }
            }
            per_source.push((ast.name.clone(), mine));
        }
    }
    let mut picked_note = None;
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
            // In order: one contract, or in a project the one contract whose
            // parameters the values fit (count, and kinds where the file gives them).
            let fits = |ps: &[(String, String)]| {
                ps.len() == a.len()
                    && ps.iter().zip(a).all(|((_, ty), x)| match x.get("kind").and_then(|k| k.as_str()) {
                        Some(k) => kind_fits(k, ty),
                        None => true,
                    })
            };
            let order: Vec<(String, String)> = if per_source.len() <= 1 {
                if a.len() != params.len() {
                    bail!("the file gives {} constructor values in order, the contract takes {}", a.len(), params.len());
                }
                params.clone()
            } else {
                let matching: Vec<&(String, Vec<(String, String)>)> = per_source.iter().filter(|(_, ps)| fits(ps)).collect();
                match matching.as_slice() {
                    [one] => {
                        picked_note = Some(format!("constructor values in order: they fit `{}` (by count and kind), so they are its values", one.0));
                        one.1.clone()
                    }
                    [] => bail!(
                        "the file gives {} constructor values in order and no contract here takes that many of those kinds; give them by name for a project",
                        a.len()
                    ),
                    many => bail!(
                        "the file gives {} constructor values in order, which fit {} contracts here ({}); give them by name for a project",
                        a.len(),
                        many.len(),
                        many.iter().map(|(n, _)| format!("`{n}`")).collect::<Vec<_>>().join(", ")
                    ),
                }
            };
            for (i, ((name, ty), x)) in order.iter().zip(a).enumerate() {
                if let Some(k) = x.get("kind").and_then(|k| k.as_str()) {
                    if !kind_fits(k, ty) {
                        bail!("value {} (`{name}`) is given as `{k}`, but the parameter is `{ty}`", i + 1);
                    }
                }
                out.insert(name.clone(), scalar(x).map_err(|e| anyhow!("value {} (`{name}`): {e}", i + 1))?);
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
    notes.extend(picked_note);
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

    const KINDS: &str = "pragma silverscript ^0.1.0;\ncontract K(byte[32] tag, int cap, byte flag, bool open, pubkey owner) {\n    entry go(sig s) {\n        require(checkSig(s, owner));\n        require(tx.outputs[0].value == cap);\n        require(open);\n        require(flag == 4);\n        require(tag != tag);\n    }\n}\n";

    #[test]
    fn silverc_kind_value_files() {
        // Every kind: bytes as numbers and as hex, int, byte, bool, pubkey.
        let raw = format!(
            r#"[{{"kind":"bytes","value":[{}]}}, {{"kind":"int","value":1000}}, {{"kind":"byte","value":4}}, {{"kind":"bool","value":true}}, {{"kind":"pubkey","value":"{}"}}]"#,
            vec!["7"; 32].join(","),
            "22".repeat(32)
        );
        let (v, _) = load(&raw, &[KINDS]).unwrap();
        assert_eq!(v["tag"], format!("0x{}", "07".repeat(32)));
        assert_eq!(v["cap"], "1000");
        assert_eq!(v["flag"], "4");
        assert_eq!(v["open"], "true");
        assert_eq!(v["owner"], "@owner");
        let hex = format!(r#"[{{"kind":"bytes","value":"0x{}"}}, {{"kind":"int","value":"5"}}, {{"kind":"byte","value":4}}, {{"kind":"bool","value":false}}, {{"kind":"bytes","value":[{}]}}]"#, "ab".repeat(32), vec!["1"; 32].join(","));
        let (v, _) = load(&hex, &[KINDS]).unwrap();
        assert_eq!(v["tag"], format!("0x{}", "ab".repeat(32)));
        assert_eq!(v["cap"], "5");
        // A kind that does not fit its parameter, a byte out of range, an unknown kind.
        assert!(load(r#"[{"kind":"int","value":1},{"kind":"int","value":1},{"kind":"byte","value":4},{"kind":"bool","value":true},{"kind":"int","value":1}]"#, &[KINDS]).is_err());
        assert!(load(&raw.replace("[7,", "[700,"), &[KINDS]).is_err());
        assert!(load(&raw.replace("\"byte\"", "\"float\""), &[KINDS]).is_err());
    }

    #[test]
    fn silverc_file_with_many_values_in_order() {
        let n = 34;
        let params: Vec<String> =
            (0..n).map(|i| if i % 5 == 0 { format!("byte[32] h{i}") } else { format!("int v{i}") }).collect();
        let uses: String = (0..n)
            .map(|i| if i % 5 == 0 { format!("        require(h{i} != h{i});\n") } else { format!("        require(v{i} >= 0);\n") })
            .collect();
        let src = format!("pragma silverscript ^0.1.0;\ncontract Many({}) {{\n    entry go() {{\n{uses}    }}\n}}\n", params.join(", "));
        let vals: Vec<String> = (0..n)
            .map(|i| if i % 5 == 0 { format!(r#"{{"kind":"bytes","value":[{}]}}"#, vec![i.to_string(); 32].join(",")) } else { format!(r#"{{"kind":"int","value":{}}}"#, i * 10) })
            .collect();
        let raw = format!("[{}]", vals.join(", "));
        let (v, notes) = load(&raw, &[&src]).unwrap();
        assert_eq!(v.len(), n);
        assert_eq!(v["v33"], "330");
        assert_eq!(v["h30"], format!("0x{}", "1e".repeat(32)));
        assert!(notes[0].contains("34 from your file"), "{notes:?}");
        // In a project, the values go to the one contract they fit.
        let (v, notes) = load(&raw, &[KINDS, &src]).unwrap();
        assert_eq!(v["v1"], "10");
        assert!(notes.iter().any(|n| n.contains("fit `Many`")), "{notes:?}");
    }
}
