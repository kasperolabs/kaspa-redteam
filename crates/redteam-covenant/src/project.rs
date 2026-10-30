//! Projects: several `.sil` files that work together (a treasury and its
//! department funds, a token and its market). Each file is searched and
//! attacked, and where one contract refers to another, the reference is
//! wired to the real thing instead of a stand-in:
//!
//! - **address**: a `byte[32]` parameter used as `ScriptPubKeyP2SH(...)` whose
//!   name matches another contract (`treasury` and `TownTreasury`) gets that
//!   contract's real address, so payments to it go to its actual script;
//! - **template**: a `byte[32]` constant or value that equals another
//!   contract's template hash (a market pinning its token's program) is
//!   recorded, so the report shows the project's shape.
//!
//! Every link the tool makes is listed in the report.

use crate::contract::{Contract, Links};
use crate::sandbox::Judge;
use anyhow::{Result, bail};
use redteam_core::RunReport;
use serde::Serialize;
use silverscript_abi::ArtifactValue;
use std::collections::BTreeMap;

pub struct ProjectFile {
    pub name: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Link {
    /// File that refers to another.
    pub from: String,
    /// The parameter or constant that carries the reference.
    pub via: String,
    /// File referred to.
    pub to: String,
    /// `address` (pays to its P2SH address) or `template` (pins its program).
    pub kind: &'static str,
}

struct Compiled {
    file: String,
    stem: String,
    contract: Contract,
    template: Vec<u8>,
}

fn norm(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_lowercase()
}

/// Constructor overrides that belong to `source` (others are for other files).
fn overrides_for(source: &str, all: &BTreeMap<String, String>) -> Result<BTreeMap<String, String>> {
    let ast = silverscript_lang::ast::parse_contract_ast(source).map_err(|e| anyhow::anyhow!("parse error: {e}"))?;
    Ok(all.iter().filter(|(k, _)| ast.params.iter().any(|p| &p.name == *k)).map(|(k, v)| (k.clone(), v.clone())).collect())
}

/// `byte[32](0x...)` literals in a source file.
fn hash_literals(source: &str) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for line in source.lines() {
        let Some(at) = line.find("byte[32](0x") else { continue };
        let hex: String = line[at + 11..].chars().take_while(|c| c.is_ascii_hexdigit()).collect();
        if hex.len() != 64 {
            continue;
        }
        let mut b = vec![0u8; 32];
        if faster_hex::hex_decode(hex.as_bytes(), &mut b).is_err() {
            continue;
        }
        // The constant's name: `byte[32] constant NAME = ...`
        let name = line
            .split('=')
            .next()
            .and_then(|l| l.split_whitespace().last())
            .unwrap_or("constant")
            .to_string();
        out.push((name, b));
    }
    out
}

/// Finds the links between files and returns them with each file's `Links`.
pub fn detect(files: &[ProjectFile], overrides: &BTreeMap<String, String>) -> Result<(Vec<Link>, Vec<Links>)> {
    let mut compiled = Vec::new();
    for f in files {
        let ov = overrides_for(&f.source, overrides)?;
        let contract = Contract::load(&f.name, &f.source, &ov).map_err(|e| e.context(f.name.clone()))?;
        let template = contract
            .artifact
            .as_ref()
            .and_then(|a| a.contracts.values().next())
            .map(|c| c.compiled.template_hash.to_vec())
            .unwrap_or_default();
        let stem = f.name.rsplit_once('.').map(|(s, _)| s).unwrap_or(&f.name).to_string();
        compiled.push(Compiled { file: f.name.clone(), stem, contract, template });
    }

    let mut links = Vec::new();
    let mut per_file = vec![Links::default(); compiled.len()];
    for (ai, a) in compiled.iter().enumerate() {
        // Addresses: P2SH-target parameters that name another contract.
        for arg in a.contract.args.iter().filter(|x| x.origin.starts_with("p2sh(stand-in:")) {
            let p = norm(&arg.name);
            if p.len() < 4 {
                continue;
            }
            let best = compiled
                .iter()
                .enumerate()
                .filter(|(bi, _)| *bi != ai)
                .filter_map(|(bi, b)| {
                    let names = [norm(&b.contract.contract_name), norm(&b.stem)];
                    names.iter().any(|n| n.contains(&p) || (n.len() >= 4 && p.contains(n.as_str()))).then_some(bi)
                })
                .max_by_key(|bi| norm(&compiled[*bi].contract.contract_name).len());
            if let Some(bi) = best {
                let b = &compiled[bi];
                per_file[ai].p2sh.insert(arg.name.clone(), (b.contract.contract_name.clone(), b.contract.bytecode.clone()));
                links.push(Link { from: a.file.clone(), via: arg.name.clone(), to: b.file.clone(), kind: "address" });
            }
        }
        // Templates: a pinned hash that is another file's program.
        let mut pinned: Vec<(String, Vec<u8>)> = hash_literals(&a.contract.source);
        for arg in &a.contract.args {
            if let ArtifactValue::Bytes(v) = &arg.value {
                if v.len() == 32 {
                    pinned.push((arg.name.clone(), v.clone()));
                }
            }
        }
        for (name, value) in pinned {
            for (bi, b) in compiled.iter().enumerate() {
                if bi != ai && !b.template.is_empty() && b.template == value {
                    links.push(Link { from: a.file.clone(), via: name.clone(), to: b.file.clone(), kind: "template" });
                }
            }
        }
    }
    Ok((links, per_file))
}

/// Searches and attacks every file of the project, with the links applied.
pub fn run(
    files: &[ProjectFile],
    overrides: &BTreeMap<String, String>,
    only: &[String],
    judge: &Judge,
) -> Result<(Vec<Link>, Vec<RunReport>)> {
    if files.is_empty() {
        bail!("no files");
    }
    for k in overrides.keys() {
        let known = files.iter().any(|f| {
            silverscript_lang::ast::parse_contract_ast(&f.source).is_ok_and(|a| a.params.iter().any(|p| &p.name == k))
        });
        if !known {
            bail!("--arg {k}: no contract in the project has a constructor parameter named `{k}`");
        }
    }
    let (links, per_file) = detect(files, overrides)?;
    let mut reports = Vec::new();
    for (f, l) in files.iter().zip(per_file.iter()) {
        let started = std::time::Instant::now();
        let ov = overrides_for(&f.source, overrides)?;
        let t = crate::tune::tune_linked(&f.name, &f.source, &ov, l, judge)?;
        let mut notes = t.notes;
        for x in links.iter().filter(|x| x.from == f.name) {
            notes.push(match x.kind {
                "address" => format!("project: `{}` is the address of {} (its real script, not a stand-in)", x.via, x.to),
                _ => format!("project: `{}` pins the program of {}", x.via, x.to),
            });
        }
        reports.push(crate::run_paths_timed(&t.contract, only, t.paths, vec![], notes, started));
    }
    Ok((links, reports))
}
