//! One program: read its bytes, collect its real spends, mutate them, label what the engine accepted.

use crate::judge::{Verdict, judge};
use crate::probe::{self, Case, Draft, Outsider, SignSpot, Variant, short};
use crate::rest::{RealTx, evidence};
use crate::script::{self, hex};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

pub const ANALYZER_VERSION: &str = "kcc20-analyzer/0.1.0+rk-a41a333b";
/// Below this, a move of KAS is reported as slack (rounding), not as a taking.
pub const MIN_TAKE: u64 = 100_000;

pub struct Budget {
    pub max_runs: usize,
    pub max_seconds: u64,
}

pub struct Program {
    pub key: Value,
    pub redeem: Vec<u8>,
    pub txs: Vec<(String, Result<RealTx, String>)>,
}

pub struct Pins {
    pub by_template: BTreeMap<String, Value>,
}

struct Run<'a> {
    o: &'a Outsider,
    runs: usize,
    budget: &'a Budget,
    started: Instant,
    out_of_budget: bool,
}

impl<'a> Run<'a> {
    fn spent(&mut self) -> bool {
        if self.runs >= self.budget.max_runs || self.started.elapsed().as_secs() >= self.budget.max_seconds {
            self.out_of_budget = true;
        }
        self.out_of_budget
    }
    fn judge(&mut self, d: &Draft, count_ops: bool) -> (Verdict, kaspa_consensus_core::tx::Transaction, Vec<kaspa_consensus_core::tx::UtxoEntry>) {
        self.runs += 1;
        let (tx, entries) = d.clone().finish(self.o);
        let v = judge(&tx, &entries, count_ops);
        (v, tx, entries)
    }
}

/// The older KCC-20 layout (kascov's KCC20 state block): owner, identifier type, amount, is_minter.
fn older_kcc20(r: &[u8]) -> Option<Value> {
    let s = if r.len() >= 48 && r[0] == 0x6b && r[1] == 0x20 && r[34] == 0x01 && r[36] == 0x08 && r[45] == 0x01 && r[47] == 0x6c {
        1
    } else if r.len() >= 46 && r[0] == 0x20 && r[33] == 0x01 && r[35] == 0x08 && r[44] == 0x01 {
        0
    } else {
        return None;
    };
    let mut a = [0u8; 8];
    a.copy_from_slice(&r[s + 36..s + 44]);
    Some(json!({
        "owner": hex(&r[s + 1..s + 33]), "identifier_type": r[s + 34], "amount": u64::from_le_bytes(a).to_string(),
        "is_minter": r[s + 45], "guarded": s == 1,
    }))
}

fn same_program(a: &[u8], b: &[u8]) -> bool {
    if a == b {
        return true;
    }
    match (script::state_window(a), script::state_window(b)) {
        (Some(wa), Some(wb)) => a[..wa.start] == b[..wb.start] && a[wa.end..] == b[wb.end..] && wa.pushes.len() == wb.pushes.len(),
        _ => false,
    }
}

struct Finding {
    label: &'static str, // "trap" | "hidden-powers" | "" (fact only)
    power: String,
    detail: Value,
}

fn verdict_json(v: &Verdict) -> Value {
    if v.accepted { json!({ "accepted": true, "fee": v.fee.to_string() }) } else { json!({ "accepted": false, "reason": v.reason() }) }
}

fn wanted_lock_time(v: &Verdict) -> Option<u64> {
    for (_, e) in &v.input_errors {
        if let Some(p) = e.find("transaction locktime: ") {
            let rest = &e[p + "transaction locktime: ".len()..];
            let n: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            return n.parse().ok();
        }
    }
    None
}

/// Facts that differ only in numbers or ids are one fact with a count.
fn dedupe_facts(facts: Vec<Value>) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    let mut keys: Vec<String> = Vec::new();
    for f in facts {
        let t = f["fact"].as_str().unwrap_or("").to_string();
        let key: String = t.split_whitespace().filter(|w| !w.chars().any(|c| c.is_ascii_digit())).collect::<Vec<_>>().join(" ");
        if let Some(i) = keys.iter().position(|k| *k == key) {
            let n = out[i]["occurrences"].as_u64().unwrap_or(1) + 1;
            out[i]["occurrences"] = json!(n);
        } else {
            keys.push(key);
            let mut g = f.clone();
            g["occurrences"] = json!(1);
            out.push(g);
        }
    }
    out
}

fn sig_stopped(v: &Verdict, input: usize) -> bool {
    v.input_errors.iter().any(|(i, e)| *i == input && e.to_lowercase().contains("sig"))
}

pub fn analyze(p: &Program, pins: &Pins, budget: &Budget, o: &Outsider) -> Value {
    let r = &p.redeem;
    let mut run = Run { o, runs: 0, budget, started: Instant::now(), out_of_budget: false };
    let window = script::state_window(r);
    let template = window.as_ref().map(|w| hex(&script::template_hash_of(r, w)));
    let tags = script::entry_tags(r);
    let known = template.as_ref().and_then(|t| pins.by_template.get(t)).cloned();
    let older = older_kcc20(r);
    let mut gaps: Vec<String> = Vec::new();
    let mut findings: Vec<Finding> = Vec::new();
    let mut facts: Vec<Value> = Vec::new();
    let mut payees: BTreeSet<(String, usize)> = BTreeSet::new();

    // ---- the real spends ----
    let mut cases: Vec<Case> = Vec::new();
    let mut case_notes: Vec<Value> = Vec::new();
    let mut coins_seen: Vec<Vec<u8>> = vec![r.clone()];
    let mut older_coins: Vec<Value> = Vec::new();
    for (txid, parsed) in &p.txs {
        let rt = match parsed {
            Ok(x) => x,
            Err(e) => {
                case_notes.push(json!({ "txid": txid, "used": false, "why": format!("unreadable copy: {e}") }));
                continue;
            }
        };
        if !rt.complete() {
            let missing: Vec<usize> = rt.entries.iter().enumerate().filter(|(_, e)| e.is_none()).map(|(i, _)| i).collect();
            case_notes.push(json!({ "txid": txid, "used": false, "why": format!("the copy does not say what inputs {missing:?} spent (fetch it again with resolve_previous_outpoints=light)") }));
            continue;
        }
        let entries = rt.entries();
        let mut targets = Vec::new();
        let mut actors = Vec::new();
        for (i, inp) in rt.tx.inputs.iter().enumerate() {
            let spk = entries[i].script_public_key.script();
            if script::is_p2pk(spk) {
                actors.push(i);
                continue;
            }
            if let Some(items) = script::pushes(&inp.signature_script) {
                if let Some(last) = items.last() {
                    if script::is_p2sh(spk) && script::p2sh(last)[..] == spk[..] && same_program(last, r) {
                        targets.push(i);
                        coins_seen.push(last.clone());
                        if let Some(st) = older_kcc20(last) {
                            older_coins.push(json!({ "txid": txid, "input": i, "state": st }));
                        }
                    }
                }
            }
        }
        if targets.is_empty() {
            case_notes.push(json!({ "txid": txid, "used": false, "why": "no input of this transaction spends this program" }));
            continue;
        }
        let note = json!({ "txid": txid, "id_rebuilt": rt.id_matches, "assumed_fields": rt.assumed, "targets": targets, "actor_inputs": actors });
        case_notes.push(note);
        cases.push(Case { txid: txid.clone(), tx: rt.tx.clone(), entries, targets, actor_inputs: actors });
    }

    // ---- state pushes: constants or state, judged from every copy seen ----
    let mut pushes_report = Vec::new();
    if let Some(w) = &window {
        let mut distinct_coins: BTreeSet<Vec<u8>> = BTreeSet::new();
        for c in &coins_seen {
            distinct_coins.insert(c.clone());
        }
        for (k, (_, _, d)) in w.pushes.iter().enumerate() {
            let mut vals: BTreeSet<String> = BTreeSet::new();
            for c in &distinct_coins {
                if let Some(wc) = script::state_window(c) {
                    if let Some(x) = wc.pushes.get(k) {
                        vals.insert(hex(&x.2));
                    }
                }
            }
            let kind = if distinct_coins.len() < 2 { "unknown (one copy seen)" } else if vals.len() == 1 { "same in every copy seen (a constant, or state that had not changed yet)" } else { "varies (state)" };
            // A push that is (or ends with) a script some observed output pays: a payee written into the coin.
            let mut payee = false;
            for c in &cases {
                for out in &c.tx.outputs {
                    let s = out.script_public_key.script();
                    if s.len() >= 34 && (d.as_slice() == s || d.ends_with(s)) {
                        payee = true;
                    }
                }
            }
            pushes_report.push(json!({ "index": k, "bytes": d.len(), "value": hex(d), "kind": kind, "distinct_values": vals.len(), "pays_an_observed_output": payee }));
        }
        if distinct_coins.len() < 2 {
            gaps.push("only one copy of the program was seen, so constants and state cannot be told apart".into());
        }
    }

    // ---- per case: original, outsider base, mutations ----
    let mut entries_seen: BTreeSet<String> = BTreeSet::new();
    let mut runs_report = Vec::new();
    let mut accepted_count = 0usize;
    let mut by_class: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut base_cases: Vec<(usize, Draft, bool)> = Vec::new();
    for (ci, c) in cases.iter().enumerate() {
        if run.spent() {
            break;
        }
        let v0 = judge(&c.tx, &c.entries, false);
        run.runs += 1;
        for &t in &c.targets {
            if let Some(items) = script::pushes(&c.tx.inputs[t].signature_script) {
                for a in &items[..items.len().saturating_sub(1)] {
                    if a.len() == 4 && tags.iter().any(|g| g[..] == a[..]) {
                        entries_seen.insert(hex(a));
                    }
                }
            }
        }
        let base = c.outsider_base(o);
        let (vb, _, _) = run.judge(&base, false);
        let base_ok = vb.accepted;
        let mut cr = json!({ "txid": c.txid, "original": verdict_json(&v0), "outsider_base": verdict_json(&vb) });
        // A copy whose id could not be rebuilt carries signatures over fields the API did not return; plain-key inputs
        // then fail as copied. Covenant inputs do not depend on those signatures, so the case still counts when they pass.
        let covenant_ok = v0.tx_error.is_none() && v0.input_errors.iter().all(|(i, _)| c.actor_inputs.contains(i));
        if !v0.accepted && !covenant_ok {
            cr["note"] = json!("the engine refuses the transaction as copied, so nothing built from it proves anything");
            runs_report.push(cr);
            continue;
        }
        if !v0.accepted {
            cr["original"]["covenant_inputs_pass"] = json!(true);
            cr["note"] = json!("the copy's id could not be rebuilt from the API fields, so its plain-key signatures fail as copied; every covenant input passes, and the outsider base re-signs those inputs");
        }
        if !base_ok {
            let target_failed = c.targets.iter().any(|t| !vb.input_ok(*t));
            cr["note"] = json!(if target_failed {
                "with the person who made it replaced by an outsider, this program's input fails: the path needs that person's signature (or a value only they had)"
            } else {
                "with the person replaced, another input fails (a partner program that checks their signature); this program's own inputs passed"
            });
        }
        base_cases.push((ci, base.clone(), base_ok));
        let base_gain = {
            let (tx, en) = base.clone().finish(o);
            probe::outsider_gain(&tx, &en, o)
        };

        let mut level1: Vec<Variant> = probe::structural_mutations(c, &base, o, &tags);
        if base_ok {
            level1.extend(probe::value_mutations(&base, o, false));
        }
        let mut level2_bases: Vec<(Draft, String, &'static str)> = Vec::new();
        for var in level1 {
            if run.spent() {
                break;
            }
            let (v, tx, en) = run.judge(&var.draft, false);
            let ch = &var.change[0];
            let e = by_class.entry(ch.class.to_string()).or_default();
            e.0 += 1;
            if !v.accepted {
                continue;
            }
            e.1 += 1;
            accepted_count += 1;
            let gain = probe::outsider_gain(&tx, &en, o) - base_gain;
            classify(&mut findings, &mut facts, &mut payees, c, &base, base_ok, &var, gain, &tx, &en);
            if matches!(ch.class, "signature" | "witness-key" | "sighash" | "entry" | "argument") {
                level2_bases.push((var.draft.clone(), ch.text.clone(), ch.class));
            }
        }
        // Level 2: value mutations on top of an accepted structural change.
        for (d, why, cls) in level2_bases.iter().take(16) {
            for var in probe::value_mutations(d, o, true) {
                if run.spent() {
                    break;
                }
                let (v, tx, en) = run.judge(&var.draft, false);
                let e = by_class.entry(format!("{cls} then {}", var.change[0].class)).or_default();
                e.0 += 1;
                if !v.accepted {
                    continue;
                }
                e.1 += 1;
                accepted_count += 1;
                let gain = probe::outsider_gain(&tx, &en, o) - base_gain;
                let mut var2 = var;
                var2.change.insert(0, probe::Change { class: "after", text: why.clone(), from_output: None, moved: 0 });
                classify(&mut findings, &mut facts, &mut payees, c, &base, base_ok, &var2, gain, &tx, &en);
            }
        }
        runs_report.push(cr);
    }

    // ---- entries nobody was seen using: guessed argument shapes ----
    let mut entries_report = Vec::new();
    let mut unexplored = Vec::new();
    for tag in &tags {
        let t = hex(tag);
        if entries_seen.contains(&t) {
            entries_report.push(json!({ "tag": t, "seen_in_real_spends": true, "explored": true }));
            continue;
        }
        let mut accepted_shape: Option<String> = None;
        let mut deepest = (0usize, String::new(), String::new());
        let mut stopped_at_sig = false;
        'outer: for (ci, base, _) in &base_cases {
            let c = &cases[*ci];
            for &ti in &c.targets {
                let Some(items) = script::pushes(&base.tx.inputs[ti].signature_script) else { continue };
                let n = items.len();
                let args = &items[..n - 1];
                let sel = args.iter().position(|a| a.len() == 4 && tags.iter().any(|g| g[..] == a[..])).unwrap_or(args.len());
                for (name, shape) in probe::guessed_shapes(args, sel, tag, o) {
                    if run.spent() {
                        break 'outer;
                    }
                    let mut d = base.clone();
                    let mut all = shape.clone();
                    all.push(items[n - 1].clone());
                    d.tx.inputs[ti].signature_script = script::push_all(&all);
                    for (k, a) in shape.iter().enumerate() {
                        if a.len() == 65 && a.iter().all(|b| *b == 0) {
                            d.sign.push(SignSpot { input: ti, push: Some(k), hash_type: 0x01 });
                        }
                    }
                    let (mut v, mut tx, mut en) = run.judge(&d, true);
                    // A branch with a lock time: the outsider sets the transaction's lock time to what it asks for.
                    if let Some(n) = wanted_lock_time(&v) {
                        if d.tx.lock_time < n {
                            d.tx.lock_time = n;
                            (v, tx, en) = run.judge(&d, true);
                        }
                    }
                    let ops = v.ops_run.get(ti).copied().unwrap_or(0);
                    if ops > deepest.0 {
                        deepest = (ops, name.clone(), v.reason());
                    }
                    if sig_stopped(&v, ti) {
                        stopped_at_sig = true;
                    }
                    if v.accepted {
                        accepted_shape = Some(name.clone());
                        // What can an outsider do through it?
                        let base_gain = {
                            let (btx, ben) = base.clone().finish(o);
                            probe::outsider_gain(&btx, &ben, o)
                        };
                                        let var = Variant { change: vec![probe::Change { class: "entry", text: format!("input {ti}: entry {t} called with {name}"), from_output: None, moved: 0 }], draft: d.clone() };
                        let gain = probe::outsider_gain(&tx, &en, o) - base_gain;
                        let base_ok = base_cases.iter().any(|(k, _, ok)| k == ci && *ok);
                        classify(&mut findings, &mut facts, &mut payees, c, base, base_ok, &var, gain, &tx, &en);
                        for vv in probe::value_mutations(&d, o, true) {
                            if run.spent() {
                                break;
                            }
                            let (v2, tx2, en2) = run.judge(&vv.draft, false);
                            if v2.accepted {
                                let g2 = probe::outsider_gain(&tx2, &en2, o) - base_gain;
                                let mut vv2 = vv;
                                vv2.change.insert(0, probe::Change { class: "after", text: format!("entry {t} called with {name}"), from_output: None, moved: 0 });
                                classify(&mut findings, &mut facts, &mut payees, c, base, base_ok, &vv2, g2, &tx2, &en2);
                            }
                        }
                        break 'outer;
                    }
                }
            }
        }
        let explored = accepted_shape.is_some() || stopped_at_sig;
        if !explored {
            unexplored.push(t.clone());
        }
        entries_report.push(json!({
            "tag": t, "seen_in_real_spends": false, "explored": explored,
            "accepted_shape": accepted_shape,
            "stopped_at_a_signature_check": stopped_at_sig,
            "deepest_attempt": { "opcodes_run": deepest.0, "shape": deepest.1, "error": deepest.2 },
        }));
    }

    // ---- payees the real spends paid: how little does the program accept? ----
    let mut measured: BTreeSet<Vec<u8>> = BTreeSet::new();
    for (txid, k) in payees.iter() {
        let Some((_, base, _)) = base_cases.iter().find(|(ci, _, _)| cases[*ci].txid == *txid) else { continue };
        let out = &base.tx.outputs[*k];
        let script_b = out.script_public_key.script().to_vec();
        if !measured.insert(script_b.clone()) {
            continue;
        }
        // Not paid at all?
        let mut d = base.clone();
        d.tx.outputs[*k].script_public_key = o.spk.clone();
        let (v_none, _, _) = run.judge(&d, false);
        let (mut lo, mut hi) = (0u64, out.value); // hi accepted (the real payment), lo = rejected or 0
        if !v_none.accepted {
            while hi - lo > 1 && !run.spent() {
                let mid = lo + (hi - lo) / 2;
                let mut d = base.clone();
                d.tx.outputs[*k].value = mid;
                d.pay_outsider(o, out.value - mid);
                let (v, _, _) = run.judge(&d, false);
                if v.accepted { hi = mid } else { lo = mid }
            }
        }
        let who = short(&hex(&script_b));
        let brought: u64 = base.entries.iter().filter(|e| e.script_public_key == o.spk).map(|e| e.amount).sum();
        if v_none.accepted && out.value > brought && out.value >= MIN_TAKE {
            // Nothing makes the transaction pay this script, and what it was paid is more than the outsider brought:
            // the KAS came out of coins the outsider did not fund, and the outsider can keep it.
            let mut d = base.clone();
            d.tx.outputs[*k].script_public_key = o.spk.clone();
            let (v, tx, en) = run.judge(&d, false);
            if v.accepted {
                let ev = json!({ "from_spend": txid, "changes": [format!("output {k} (script {who}) paid to the outsider instead")],
                                 "transaction": evidence(&tx, &en) });
                findings.push(Finding { label: "trap", power: format!(
                    "an outsider can keep KAS the real spend sent to script {who} ({} sompi): nothing requires that payment, and the outsider brought only {brought} sompi", out.value), detail: ev });
                continue;
            }
        }
        facts.push(json!({
            "fact": if v_none.accepted {
                format!("the program does not require paying script {who}; the real spend {txid} paid it {} sompi", out.value)
            } else {
                format!("the program requires paying script {who} at least {hi} sompi in spend {txid} (the real spend paid {}); paying less than that is refused", out.value)
            },
            "payee_script": hex(&script_b), "paid": out.value.to_string(), "minimum_accepted": if v_none.accepted { Value::Null } else { json!(hi.to_string()) },
            "note": "a payee that is not the person making the transaction; the gap is what that person chose to pay above the program's minimum, so it is not a power over holders",
        }));
    }

    if older.is_some() {
        let minters = older_coins.iter().filter(|c| c["state"]["is_minter"] == json!(1)).count();
        facts.push(json!({
            "fact": format!("older KCC-20 layout: its state carries an is_minter flag (a declared power: a coin with is_minter = 1 is the token's minter); {} of {} coins seen spent had is_minter = 1; the sample has is_minter = {}",
                minters, older_coins.len(), older.as_ref().unwrap()["is_minter"]),
            "declared_power": "is_minter",
        }));
    }

    // ---- verdict ----
    let passing = runs_report.iter().filter(|x| x["original"]["accepted"] == json!(true) || x["original"]["covenant_inputs_pass"] == json!(true)).count();
    if cases.is_empty() {
        gaps.push("no real spend of this program could be rebuilt".into());
    } else if passing == 0 {
        gaps.push("the engine refused every copied spend as given".into());
    }
    if !unexplored.is_empty() {
        gaps.push(format!("entries never seen used and not reached with guessed arguments: {}", unexplored.join(", ")));
    }
    if run.out_of_budget {
        gaps.push(format!("budget reached after {} engine runs", run.runs));
    }
    if tags.is_empty() && !cases.is_empty() {
        facts.push(json!({ "fact": "no silverc-style entry dispatch found; the program was explored only through the spends seen" }));
    }
    let label = if findings.iter().any(|f| f.label == "trap") {
        "trap"
    } else if findings.iter().any(|f| f.label == "hidden-powers") {
        "hidden-powers"
    } else {
        "unverified"
    };
    let witnessed = label != "unverified";
    let complete = gaps.is_empty();
    let status = if witnessed || complete { "done" } else { "too-complex" };
    let summary = match (label, complete) {
        ("unverified", true) => "No mutation of the real spends was accepted that moved value or created powers. That is not a proof: the analyzer only tried what it tried, so the program stays unverified.".to_string(),
        ("unverified", false) => format!("Not fully explored ({}). No witnessed power, so it stays unverified.", gaps.join("; ")),
        (l, _) => format!("{} witnessed power(s); label {l}. Each one comes with a transaction the engine accepted.", findings.iter().filter(|f| !f.label.is_empty()).count()),
    };

    json!({
        "analyzer": ANALYZER_VERSION,
        "engine": "kaspa-txscript at rusty-kaspa a41a333b08848f41bf737b72592e463a6011b8ac (the revision argent-lang/kcc20-reference pins), covenants enabled",
        "program": {
            "queue": p.key,
            "bytes": r.len(),
            "redeem_blake2b": hex(&script::blake2b32(r)),
            "kcc1_template_hash": template,
            "state_window": window.as_ref().map(|w| json!({ "start": w.start, "end": w.end, "guarded": w.guarded, "pushes": pushes_report })),
            "entry_tags": tags.iter().map(|t| hex(t)).collect::<Vec<_>>(),
            "opcodes": script::op_facts(r),
            "known_family": known,
            "older_kcc20_state": older,
            "older_kcc20_spent_coins": older_coins,
        },
        "spends": case_notes,
        "runs": runs_report,
        "entries": entries_report,
        "mutations": { "engine_runs": run.runs, "accepted": accepted_count, "by_class": by_class.iter().map(|(k, (n, a))| (k.clone(), json!({ "tried": n, "accepted": a }))).collect::<serde_json::Map<_, _>>() },
        "findings": findings.iter().map(|f| json!({ "label": if f.label.is_empty() { Value::Null } else { json!(f.label) }, "power": f.power, "evidence": f.detail })).collect::<Vec<_>>(),
        "facts": dedupe_facts(facts),
        "coverage": { "complete": complete, "gaps": gaps },
        "label": label,
        "status": status,
        "summary": summary,
    })
}

fn cov_total(outs: &[kaspa_consensus_core::tx::TransactionOutput], id: kaspa_hashes::Hash) -> u64 {
    outs.iter().filter(|o| o.covenant.map(|c| c.covenant_id) == Some(id)).map(|o| o.value).sum()
}

#[allow(clippy::too_many_arguments)]
fn classify(
    findings: &mut Vec<Finding>,
    facts: &mut Vec<Value>,
    payees: &mut BTreeSet<(String, usize)>,
    c: &Case,
    base: &Draft,
    base_ok: bool,
    var: &Variant,
    gain: i128,
    tx: &kaspa_consensus_core::tx::Transaction,
    en: &[kaspa_consensus_core::tx::UtxoEntry],
) {
    let last = var.change.last().unwrap();
    let steps: Vec<String> = var.change.iter().map(|x| x.text.clone()).collect();
    let ev = json!({ "from_spend": c.txid, "changes": steps, "outsider_gain_sompi": gain.to_string(), "transaction": evidence(tx, en) });
    let structural_first = var.change.iter().any(|x| matches!(x.class, "signature" | "witness-key" | "sighash" | "entry" | "argument"));
    let outsider_moves_holder_coin = !base_ok && structural_first;
    let mut push = |label: &'static str, power: String| {
        if !findings.iter().any(|f| f.power == power) {
            findings.push(Finding { label, power, detail: ev.clone() });
        }
    };
    match last.class {
        "recipient" | "amount" | "drop-output" => {
            let k = last.from_output.unwrap_or(usize::MAX);
            let Some(src) = base.tx.outputs.get(k) else { return };
            if outsider_moves_holder_coin {
                push("trap", format!("an outsider can spend the holder's coin without the holder's key and choose where its value goes: {}", steps.join("; then ")));
                return;
            }
            if let Some(cov) = src.covenant {
                // KAS that was inside this covenant's coins before the transaction and is not inside them after.
                let id = cov.covenant_id;
                let before: u64 = base.entries.iter().filter(|e| e.covenant_id == Some(id)).map(|e| e.amount).sum();
                let kept_honest = cov_total(&base.tx.outputs, id);
                let kept_now = cov_total(&tx.outputs, id);
                let loss = before.min(kept_honest).saturating_sub(kept_now);
                // The person making the transaction may own some of this covenant's new coins (a buyer's token cell),
                // and moving KAS out of their own coin is not a taking. Their coins are at most the covenant's other
                // outputs, so only a loss beyond all of those is counted against holders.
                let others: u64 = base.tx.outputs.iter().enumerate()
                    .filter(|(j, o)| *j != k && o.covenant.map(|c| c.covenant_id) == Some(id)).map(|(_, o)| o.value).sum();
                let excess = loss.saturating_sub(others);
                let cid = id.to_string();
                if excess < MIN_TAKE && loss >= MIN_TAKE {
                    facts.push(json!({ "fact": format!("value move accepted ({} sompi out of coins of covenant {}), but it is no larger than that covenant's other new coins, which may belong to the person making the transaction: {}", loss, &cid[..16], last.text), "from_spend": c.txid, "review": true }));
                } else if loss >= MIN_TAKE {
                    push("trap", format!(
                        "an outsider can take KAS that was already in coins of covenant {}: {} sompi left its coins beyond what the real spend allowed ({})",
                        &cid[..16], loss, last.text
                    ));
                } else if loss > 0 {
                    facts.push(json!({ "fact": format!("slack: {} sompi of covenant {} KAS can leave beyond the real spend ({})", loss, &cid[..16], last.text), "from_spend": c.txid }));
                } else {
                    facts.push(json!({ "fact": format!("accepted, but the KAS moved was put in by the person making the transaction, not taken from coins that existed before: {}", last.text), "from_spend": c.txid }));
                }
            } else {
                // A payee other than the person making the transaction: the real spend may simply have paid more than the
                // program requires. Recorded, and the smallest accepted payment is measured afterwards.
                payees.insert((c.txid.clone(), k));
            }
        }
        "duplicate-covenant-output" => {
            push("hidden-powers", format!("anyone can create an extra coin of this covenant: {}", last.text));
        }
        "signature" | "witness-key" | "sighash" | "entry" | "argument" if outsider_moves_holder_coin => {
            push("trap", format!("an outsider can spend the holder's coin without the holder's key: {}", last.text));
        }
        "signature" | "witness-key" | "sighash" | "entry" => {
            facts.push(json!({ "fact": format!("accepted on a path an outsider could already take: {}", last.text), "from_spend": c.txid }));
        }
        "argument" => {
            facts.push(json!({ "fact": format!("accepted with a changed witness number: {}", last.text), "from_spend": c.txid }));
        }
        "state" => {
            facts.push(json!({ "fact": format!("this path does not depend on the changed value: {}", last.text), "from_spend": c.txid }));
        }
        "extra-output" => {
            facts.push(json!({ "fact": "the program does not limit the transaction's other outputs (an extra output was accepted)", "from_spend": c.txid }));
        }
        _ => {}
    }
}
