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
        // Templates by name: `kcc20_template` / `gen__init_bridge_mint_template` names
        // a program of the project; it gets that program's real template hash.
        for arg in a.contract.args.iter().filter(|x| x.ty == "byte[32]" && x.origin != "override") {
            let n = norm(&arg.name);
            if !n.contains("template") {
                continue;
            }
            let core = n.replace("template", "").replace("gen", "").replace("init", "");
            if core.len() < 3 {
                continue;
            }
            let best = compiled.iter().enumerate().filter(|(bi, b)| *bi != ai && !b.template.is_empty()).find_map(|(bi, b)| {
                [norm(&b.contract.contract_name), norm(&b.stem)].iter().any(|nm| *nm == core).then_some(bi)
            });
            if let Some(bi) = best {
                let b = &compiled[bi];
                per_file[ai].values.insert(arg.name.clone(), (b.contract.contract_name.clone(), b.template.clone()));
                links.push(Link { from: a.file.clone(), via: arg.name.clone(), to: b.file.clone(), kind: "template" });
            }
        }
        // Templates by role: the template argument of `readInputStateWithTemplate`,
        // `validateOutputStateWithTemplate` or `validateOutputStateWithInputTemplate`
        // is another program of the project whatever it is called; with one other
        // program to choose from, it is that one. Length arguments in the same
        // call get that program's prefix and suffix lengths.
        let linked_names: Vec<String> = per_file[ai].values.keys().cloned().collect();
        for call in template_calls(&a.contract.source) {
            let Some(tpl) = call.last().cloned() else { continue };
            let is_param = |n: &str| a.contract.args.iter().any(|x| x.name == n && x.origin != "override");
            if !is_param(&tpl) || linked_names.contains(&tpl) && !per_file[ai].values.contains_key(&tpl) {
                continue;
            }
            // The other program is the one whose state is the struct the call
            // reads or writes (`KCC20State { amount, owner, ... }`); a program
            // without that state cannot be it, even when it is the only other one.
            // By field types in order, so a contract that names the fields its
            // own way (`tokTemplate`, `ownerScheme`) still matches.
            let structs: Vec<Vec<String>> = a
                .contract
                .artifact
                .as_ref()
                .map(|art| art.structs.values().map(|s| s.fields.iter().map(|f| format!("{:?}", f.ty)).collect()).collect())
                .unwrap_or_default();
            let fits = |b: &Compiled| {
                structs.is_empty() || {
                    let mine: Vec<String> = b.contract.state_fields.iter().map(|(_, t)| format!("{t:?}")).collect();
                    !mine.is_empty() && structs.iter().any(|s| *s == mine)
                }
            };
            let others: Vec<usize> = (0..compiled.len())
                .filter(|bi| *bi != ai && !compiled[*bi].template.is_empty() && fits(&compiled[*bi]))
                .collect();
            let bi = match per_file[ai].values.get(&tpl) {
                Some((prog, _)) => match compiled.iter().position(|c| &c.contract.contract_name == prog) {
                    Some(i) => i,
                    None => continue,
                },
                None if others.len() == 1 => others[0],
                None => continue,
            };
            let b = &compiled[bi];
            if !per_file[ai].values.contains_key(&tpl) {
                per_file[ai].values.insert(tpl.clone(), (b.contract.contract_name.clone(), b.template.clone()));
                links.push(Link { from: a.file.clone(), via: tpl.clone(), to: b.file.clone(), kind: "template" });
            }
            if call.len() >= 4 {
                let (pl, sl) = (&call[call.len() - 3], &call[call.len() - 2]);
                if let Some((pre, suf)) = crate::family::template_parts(&b.contract) {
                    for (name, v) in [(pl, pre.len()), (sl, suf.len())] {
                        if a.contract.args.iter().any(|x| &x.name == name && x.ty == "int" && x.origin != "override") {
                            per_file[ai].ints.insert(name.clone(), (b.contract.contract_name.clone(), v as i64));
                        }
                    }
                }
            }
        }
        // Covenant ids by role: a constructor value the source compares to a
        // coin's covenant id (`OpInputCovenantId(i) == tokenCovId`) names the
        // family of the program its template links to. In the sandbox that
        // family has a fixed id, so the coins the tool builds carry it.
        let targets: std::collections::BTreeSet<String> = per_file[ai].values.values().map(|(p, _)| p.clone()).collect();
        if targets.len() == 1 {
            let prog = targets.iter().next().unwrap().clone();
            if let Some(b) = compiled.iter().find(|c| c.contract.contract_name == prog) {
                let src: String = a.contract.source.split_whitespace().collect::<Vec<_>>().join(" ");
                for arg in a.contract.args.iter().filter(|x| x.ty == "byte[32]" && x.origin != "override") {
                    let n = &arg.name;
                    if per_file[ai].values.contains_key(n) {
                        continue;
                    }
                    let pat = format!("== {n}");
                    let mut used = false;
                    let mut from = 0;
                    while let Some(at) = src[from..].find(&pat) {
                        let at = from + at;
                        let after = src[at + pat.len()..].chars().next().unwrap_or(' ');
                        let before = &src[at.saturating_sub(60)..at];
                        if !(after.is_alphanumeric() || after == '_') && before.contains("CovenantId(") {
                            used = true;
                        }
                        from = at + pat.len();
                    }
                    if used {
                        per_file[ai].values.insert(n.clone(), (b.contract.contract_name.clone(), crate::family::family_id(&b.file).to_vec()));
                        links.push(Link { from: a.file.clone(), via: n.clone(), to: b.file.clone(), kind: "covenant id" });
                    }
                }
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
    let n = files.len();
    for (i, (f, l)) in files.iter().zip(per_file.iter()).enumerate() {
        let started = std::time::Instant::now();
        // Under a deadline, each file gets an equal share of what is left, so
        // the first files cannot use up the time of the last.
        crate::baseline::set_file_deadline(
            crate::baseline::deadline().map(|d| started + d.saturating_duration_since(started) / (n - i) as u32),
        );
        let ov = overrides_for(&f.source, overrides)?;
        let mut t = crate::tune::tune_linked(&f.name, &f.source, &ov, l, judge)?;
        // Paths no single-program spend could open: try them together with a
        // coin of another program of the project (a bridge with its mint authority).
        let mut family_notes = Vec::new();
        if files.len() > 1 {
            let programs: Vec<crate::family::Program> = files
                .iter()
                .zip(per_file.iter())
                .filter(|(g, _)| g.name != f.name)
                .filter_map(|(g, gl)| {
                    let gov = overrides_for(&g.source, overrides).ok()?;
                    let c = Contract::load_linked(&g.name, &g.source, &gov, gl).ok()?;
                    Some(crate::family::Program { file: g.name.clone(), contract: c, cov_id: crate::family::family_id(&g.name) })
                })
                .collect();
            let names: Vec<String> = {
                let mut seen = std::collections::BTreeSet::new();
                t.paths.iter().map(|p| p.name.clone()).filter(|n| seen.insert(n.clone())).collect()
            };
            for name in names {
                // Not gated on the search deadline: a family attempt is a handful of
                // runs, and it is the one way into these paths.
                let found = crate::family::explore(&t.contract, &name, &programs, judge)
                    .or_else(|| crate::family::explore_genesis(&t.contract, &name, &programs, judge))
                    .or_else(|| crate::family::explore_owned(&t.contract, &name, &programs, judge));
                // The entry's other branches, each its own path.
                for (status, notes) in crate::family::explore_branches(&t.contract, &name, &programs, judge) {
                    if !t.paths.iter().any(|p| p.entry == status.entry) {
                        t.paths.push(status);
                        family_notes.extend(notes);
                    }
                }
                if let Some((status, notes)) = found {
                    // A path no single-program spend opened is replaced; an explored
                    // one gains its family variant (a mint next to a heartbeat).
                    match t.paths.iter().position(|p| p.name == name && p.baseline.is_none()) {
                        Some(k) => t.paths[k] = status,
                        None => t.paths.push(status),
                    }
                    family_notes.extend(notes);
                }
            }
        }
        let mut notes = t.notes;
        for n in family_notes {
            if !notes.contains(&n) {
                notes.push(n);
            }
        }
        for x in links.iter().filter(|x| x.from == f.name) {
            notes.push(match x.kind {
                "address" => format!("project: `{}` is the address of {} (its real script, not a stand-in)", x.via, x.to),
                "covenant id" => format!("project: `{}` is the covenant id of {}'s coins (a fixed id in the sandbox)", x.via, x.to),
                _ => format!("project: `{}` pins the program of {}", x.via, x.to),
            });
        }
        reports.push(crate::run_paths_timed(&t.contract, only, t.paths, vec![], notes, started));
    }
    crate::baseline::set_file_deadline(None);
    // Coins a family spend created: spent by their owner with their own
    // program's entries, then attacked there, so the minted coin itself is
    // tested (and a coin nobody can move is reported).
    let minted: Vec<(String, Vec<u8>, String, String)> = reports
        .iter_mut()
        .flat_map(|r| {
            let (keep, m): (Vec<String>, Vec<String>) =
                std::mem::take(&mut r.notes).into_iter().partition(|n| !n.starts_with("minted: "));
            r.notes = keep;
            let from = r.subject_name.clone();
            m.into_iter().filter_map(move |n| {
                let mut it = n["minted: ".len()..].split('|');
                let file = it.next()?.to_string();
                let mut redeem = vec![0u8; it.clone().next()?.len() / 2];
                faster_hex::hex_decode(it.next()?.as_bytes(), &mut redeem).ok()?;
                let path = it.next()?.to_string();
                Some((file, redeem, from.clone(), path))
            })
        })
        .collect();
    let mut done: Vec<String> = Vec::new();
    for (file, redeem, from, path) in minted {
        if done.contains(&file) {
            continue;
        }
        done.push(file.clone());
        let Some(i) = files.iter().position(|f| f.name == file) else { continue };
        let ov = overrides_for(&files[i].source, overrides)?;
        let Ok(mut c) = Contract::load_linked(&files[i].name, &files[i].source, &ov, &per_file[i]) else { continue };
        let Some(state) = crate::family::decode_state(&c, &redeem) else { continue };
        // The owner the data named: a key the tool holds ("depositor"), tried
        // first; and the minted state is where this program's coins start, so
        // a second coin spent alongside (a delegate) is a minted one too.
        // Keys are derived from their labels, so the owner may be a party of
        // another file (an order's `maker`): that label, if it is the owner.
        let owner_label = files
            .iter()
            .filter_map(|g| silverscript_lang::ast::parse_contract_ast(&g.source).ok())
            .flat_map(|a| a.params.into_iter().map(|p| p.name))
            .chain(["depositor".to_string()])
            .find(|l| {
                let x = crate::wallets::Wallet::derive(l).xonly().to_vec();
                state.values().any(|v| *v == ArtifactValue::Bytes(x.clone()))
            })
            .unwrap_or_else(|| "depositor".into());
        let i_dep = c.wallets.party(&owner_label);
        let dep = c.wallets.parties.remove(i_dep);
        c.wallets.parties.insert(0, dep);
        // The program's own bytes carry the minted state, so its coins are the
        // minted coin exactly (a delegate spent alongside is one more of them).
        if let Ok(script) = c.script_for(Some(&state)) {
            if let Some(a) = c.artifact.as_mut() {
                if let Some(cc) = a.contracts.values_mut().next() {
                    cc.compiled.bytecode = script.clone();
                }
            }
            c.bytecode = script;
        }
        c.initial_state = Some(state.clone());
        let mut paths: Vec<crate::baseline::PathStatus> = Vec::new();
        // A short grace of its own, so this step is not starved by the overall deadline.
        crate::baseline::set_file_deadline(Some(std::time::Instant::now() + std::time::Duration::from_secs(20)));
        // The full search: it pairs a delegate with a leader spend it found.
        for mut p in crate::baseline::search_all(&c, judge) {
            p.entry = format!("minted:{}", p.entry);
            paths.push(p);
        }
        crate::baseline::set_file_deadline(None);
        let timed_out = paths.iter().any(|p| p.unexplored_reason.as_deref().is_some_and(|r| r.contains("time limit")));
        let spent: Vec<String> = paths.iter().filter(|p| p.baseline.is_some()).map(|p| p.name.clone()).collect();
        let mut notes = vec![if spent.is_empty() && timed_out {
            format!("minted coins: spending the coin {from}'s `{path}` created was not tried to the end within the time limit; run kaspa-redteam on your own machine for no limit.")
        } else if spent.is_empty() {
            format!("minted coins: the coin {from}'s `{path}` created could not be spent by its owner through any entry of this file. If that is not intended, minted coins are stuck.")
        } else {
            format!("minted coins: the coin {from}'s `{path}` created was spent by its owner through {} and attacked there (paths `minted:...`).", spent.iter().map(|n| format!("`{n}`")).collect::<Vec<_>>().join(", "))
        }];
        let extra = crate::run_paths_timed(&c, only, paths, vec![], std::mem::take(&mut notes), std::time::Instant::now());
        merge_report(&mut reports[i], extra);
    }
    // A program that only took part in another file's family spend says so in
    // its own report, so "nothing could be attacked" is not read as untested.
    let members: Vec<(String, String, String, String)> = reports
        .iter_mut()
        .flat_map(|r| {
            let (keep, member): (Vec<String>, Vec<String>) =
                std::mem::take(&mut r.notes).into_iter().partition(|n| !n.starts_with("family-member: "));
            r.notes = keep;
            member
        })
        .filter_map(|n| {
            let mut it = n["family-member: ".len()..].split('|').map(str::to_string);
            Some((it.next()?, it.next()?, it.next()?, it.next()?))
        })
        .collect();
    for (r, f) in reports.iter_mut().zip(files.iter()) {
        for (sib, entry, main, path) in members.iter().filter(|m| m.0 == f.name) {
            r.notes.insert(
                0,
                format!("family: `{entry}` of this file was spent and attacked as part of {main}'s path `{path}` (see that report): the FAM attacks there change what it creates and how it continues."),
            );
            let _ = sib;
            // Its own search may not have found a spend for that entry (a
            // follower needs a leader): the family spend explored it.
            let covered = format!("explored as part of {main}'s path `{path}` (see that report)");
            if let Some(map) = r.context.get_mut("spend_map").and_then(|m| m.as_array_mut()) {
                for row in map.iter_mut().filter(|x| x["path"] == entry.as_str() && x["explored"] != true) {
                    row["explored"] = serde_json::Value::Bool(true);
                    row["summary"] = serde_json::Value::String(covered.clone());
                }
            }
            r.notes.retain(|n| !n.starts_with(&format!("path `{entry}` unexplored")));
        }
    }
    Ok((links, reports))
}

/// Adds a second run's results to a report: attacks that found something stay
/// found, attempts add up, a skip gives way to a run.
fn merge_report(into: &mut RunReport, extra: RunReport) {
    use redteam_core::Outcome;
    for x in extra.results {
        match into.results.iter_mut().find(|r| r.id == x.id) {
            None => into.results.push(x),
            Some(r) => {
                let merged = match (std::mem::replace(&mut r.outcome, Outcome::Survived { attempts: 0 }), x.outcome) {
                    (Outcome::Found { attempts: a, findings: mut f }, Outcome::Found { attempts: b, findings: g }) => {
                        f.extend(g);
                        Outcome::Found { attempts: a + b, findings: f }
                    }
                    (Outcome::Found { attempts: a, findings }, Outcome::Survived { attempts: b })
                    | (Outcome::Survived { attempts: b }, Outcome::Found { attempts: a, findings }) => {
                        Outcome::Found { attempts: a + b, findings }
                    }
                    (f @ Outcome::Found { .. }, Outcome::Skipped { .. }) | (Outcome::Skipped { .. }, f @ Outcome::Found { .. }) => f,
                    (Outcome::Survived { attempts: a }, Outcome::Survived { attempts: b }) => Outcome::Survived { attempts: a + b },
                    (s @ Outcome::Survived { .. }, Outcome::Skipped { .. }) | (Outcome::Skipped { .. }, s @ Outcome::Survived { .. }) => s,
                    (sk @ Outcome::Skipped { .. }, Outcome::Skipped { .. }) => sk,
                };
                r.outcome = merged;
            }
        }
    }
    if let (Some(a), Some(b)) = (into.context.get_mut("spend_map").and_then(|m| m.as_array_mut()), extra.context.get("spend_map").and_then(|m| m.as_array())) {
        a.extend(b.iter().cloned());
    }
    // Notes from the extra run that say something new (not the judge line again).
    for n in extra.notes {
        if !into.notes.contains(&n) {
            into.notes.insert(0, n);
        }
    }
    into.millis += extra.millis;
}

/// Arguments of every template call in a source, as written (identifiers).
fn template_calls(source: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for name in ["readInputStateWithTemplate(", "validateOutputStateWithTemplate(", "validateOutputStateWithInputTemplate("] {
        let mut from = 0;
        while let Some(at) = source[from..].find(name) {
            let start = from + at + name.len();
            let mut depth = 1;
            let mut args = Vec::new();
            let mut cur = String::new();
            for ch in source[start..].chars() {
                match ch {
                    '(' | '{' | '[' => {
                        depth += 1;
                        cur.push(ch);
                    }
                    ')' | '}' | ']' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                        cur.push(ch);
                    }
                    ',' if depth == 1 => args.push(std::mem::take(&mut cur).trim().to_string()),
                    _ => cur.push(ch),
                }
            }
            args.push(cur.trim().to_string());
            out.push(args);
            from = start;
        }
    }
    out
}
