//! Testing the compiled script itself: the bytes a project's own (pinned)
//! compiler produced, instead of today's compile of the source.
//!
//! The source is still read, for the entries, their parameters and the hints
//! the search uses. The bytes come from the file. Values the tool must play
//! (keys, key hashes, hash locks) are swapped in place: each is a 32-byte push,
//! so swapping it changes no length and no structure. Everything else in the
//! script is exactly as compiled.
//!
//! Accepted files: a SilverScript ABI artifact (`silverc` JSON), any JSON with
//! a `bytecode` / `redeemScript` / `script` hex string (top level or under a
//! contract), or a plain hex file.

use crate::contract::Contract;
use anyhow::{Result, anyhow, bail};
use serde_json::Value;
use silverscript_abi::ArtifactValue;
use std::collections::BTreeMap;

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    let h: String = s.trim().trim_start_matches("0x").chars().filter(|c| !c.is_whitespace()).collect();
    if h.is_empty() || h.len() % 2 != 0 {
        return None;
    }
    let mut out = vec![0u8; h.len() / 2];
    faster_hex::hex_decode(h.as_bytes(), &mut out).ok()?;
    Some(out)
}

fn find_script(v: &Value, depth: usize) -> Option<Vec<u8>> {
    if depth > 4 {
        return None;
    }
    match v {
        Value::String(s) => hex_bytes(s),
        Value::Array(a) if !a.is_empty() && a.iter().all(|x| x.as_u64().is_some_and(|n| n < 256)) => {
            Some(a.iter().map(|x| x.as_u64().unwrap() as u8).collect())
        }
        Value::Object(o) => {
            for k in ["bytecode", "redeemScript", "redeem_script", "script", "redeem"] {
                if let Some(x) = o.get(k) {
                    if let Some(b) = find_script(x, depth + 1) {
                        return Some(b);
                    }
                }
            }
            for k in ["compiled", "contracts", "contract", "artifact"] {
                if let Some(x) = o.get(k) {
                    if let Some(b) = find_script(x, depth + 1) {
                        return Some(b);
                    }
                }
            }
            // `contracts: { Name: {...} }`
            if o.len() == 1 {
                return find_script(o.values().next().unwrap(), depth + 1);
            }
            None
        }
        _ => None,
    }
}

/// The script bytes in a compiled-output file.
pub fn read_script(raw: &[u8]) -> Result<Vec<u8>> {
    let text = String::from_utf8_lossy(raw);
    if let Ok(v) = serde_json::from_str::<Value>(&text) {
        return find_script(&v, 0).ok_or_else(|| {
            anyhow!("found no script in the compiled file (looked for `bytecode`, `redeemScript` or `script` as hex)")
        });
    }
    hex_bytes(&text).ok_or_else(|| anyhow!("the compiled file is neither JSON nor hex"))
}

fn replace_push(script: &[u8], from: &[u8], to: &[u8]) -> (Vec<u8>, usize) {
    let mut pat = vec![from.len() as u8];
    pat.extend_from_slice(from);
    let mut out = Vec::with_capacity(script.len());
    let mut i = 0;
    let mut n = 0;
    while i < script.len() {
        if script[i..].starts_with(&pat) {
            out.push(pat[0]);
            out.extend_from_slice(to);
            i += pat.len();
            n += 1;
        } else {
            out.push(script[i]);
            i += 1;
        }
    }
    (out, n)
}

fn find(hay: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return vec![];
    }
    (0..=hay.len() - needle.len()).filter(|i| &hay[*i..*i + needle.len()] == needle).collect()
}

/// Replaces the contract's bytes with `script`, swapping in the tool's values
/// for `real` (parameter name -> the file's value). Returns notes for the report.
pub fn apply(c: &mut Contract, script: Vec<u8>, real: &BTreeMap<String, String>) -> Result<Vec<String>> {
    let today = c.bytecode.clone();
    let mut bytes = script;
    let original_len = bytes.len();
    let digest = redteam_core::sha256_hex(&[&bytes]);
    let mut swapped = Vec::new();
    let mut missing = Vec::new();
    for (name, raw) in real {
        let Some(arg) = c.args.iter().find(|a| &a.name == name) else { continue };
        let ArtifactValue::Bytes(test) = &arg.value else { continue };
        let Some(real_bytes) = hex_bytes(raw).filter(|b| b.len() == test.len()) else { continue };
        let (out, n) = replace_push(&bytes, &real_bytes, test);
        if n == 0 {
            missing.push(format!("`{name}`"));
        } else {
            swapped.push(format!("`{name}`"));
            bytes = out;
        }
    }
    if !missing.is_empty() {
        bail!(
            "the compiled script does not contain the value your file gives for {}. Was it compiled with these constructor values?",
            missing.join(", ")
        );
    }

    // Every entry's dispatch tag must be in the script, or the source does not describe these bytes.
    let abi = c.artifact.as_mut().ok_or_else(|| anyhow!("no compiled contract"))?;
    let (_, art) = abi.contracts.iter_mut().next().ok_or_else(|| anyhow!("no contract"))?;
    let mut lost = Vec::new();
    if art.entries.len() > 1 {
        for (name, e) in &art.entries {
            let mut pat = vec![4u8];
            pat.extend_from_slice(e.dispatch_tag.as_bytes());
            if find(&bytes, &pat).is_empty() {
                lost.push(name.clone());
            }
        }
    }
    if !lost.is_empty() {
        bail!(
            "the compiled script has no entry tag for {} as the source declares it: the source and the compiled file are not the same contract (or the compiler names entries differently)",
            lost.join(", ")
        );
    }

    // The runtime state: where today's compile puts it, found in the given bytes.
    let span = art.compiled.state_span;
    if span.len > 0 {
        let state = &today[span.offset..span.offset + span.len];
        let at = find(&bytes, state);
        match at.as_slice() {
            [one] => art.compiled.state_span.offset = *one,
            [] => bail!("could not find the contract's starting state in the compiled script (the state encoding may differ between compiler versions)"),
            _ => bail!("the contract's starting state appears more than once in the compiled script; cannot tell where it is"),
        }
    }
    let sp = art.compiled.state_span;
    art.compiled.template_hash =
        silverscript_core::utils::template_hash(&bytes[..sp.offset], &bytes[sp.offset + sp.len..]);
    art.compiled.bytecode = bytes.clone();

    let same = bytes == today;
    c.bytecode = bytes;
    c.sig_ops = crate::script::sig_op_estimate(&c.bytecode);
    c.pushed_ints = crate::script::pushed_ints(&c.bytecode);
    let (cltv, csv) = crate::script::lock_values(&c.bytecode);
    c.cltv_values = cltv;
    c.csv_values = csv;

    let mut notes = vec![format!(
        "tested your compiled script ({original_len} bytes, sha256 {}), not today's compile of the source{}",
        &digest[..16],
        if same { "; they are identical".to_string() } else { format!("; today's compile is {} bytes and differs", today.len()) }
    )];
    if !swapped.is_empty() {
        notes.push(format!(
            "in that script, these values were swapped for the tool's own (same length, nothing else touched): {}",
            swapped.join(", ")
        ));
    }
    Ok(notes)
}
