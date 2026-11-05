//! kcc20-analyzer: program bytes in, report JSON out.
//!
//!   kcc20-analyzer run --queue queue.json --out out/ [--corpus DIR] [--pins DIR] [--max-runs N] [--max-seconds S]
//!   kcc20-analyzer corpus --corpus DIR
//!
//! Deterministic (fixed outsider key, deterministic signatures, ordered iteration, a run-count budget), no keys of
//! anyone, no database, no network. The queue is the Studio's export (kcc20_programs rows with their real spends),
//! completed by server/queue-complete.js.

mod analyze;
mod judge;
mod probe;
mod rest;
mod script;

use analyze::{ANALYZER_VERSION, Budget, Pins, Program};
use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn load_pins(dir: Option<String>) -> Pins {
    let mut by_template = std::collections::BTreeMap::new();
    if let Some(d) = dir {
        let mut files: Vec<PathBuf> = std::fs::read_dir(&d).map(|r| r.filter_map(|e| e.ok().map(|e| e.path())).collect()).unwrap_or_default();
        files.sort();
        for f in files.into_iter().filter(|f| f.extension().map(|e| e == "json").unwrap_or(false)) {
            if let Ok(v) = std::fs::read_to_string(&f).map_err(anyhow::Error::from).and_then(|s| Ok(serde_json::from_str::<Value>(&s)?)) {
                if let Some(t) = v.get("template_hash").or(v.get("templateHash")).and_then(|x| x.as_str()) {
                    let keep = json!({ "source": f.file_name().map(|x| x.to_string_lossy().to_string()), "name": v.get("name"), "family": v.get("family"), "template_hash": t });
                    by_template.insert(t.to_lowercase(), keep);
                }
            }
        }
    }
    Pins { by_template }
}

/// A queue entry: the row's own fields (as the key the write-back uses), the sample program, the real spends.
fn program_of(p: &Value) -> Result<Program> {
    let redeem_hex = p
        .get("sample_redeem_hex")
        .or(p.get("sampleRedeemHex"))
        .or(p.get("redeem_hex"))
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("program without sample_redeem_hex"))?;
    let redeem = script::unhex(redeem_hex)?;
    let mut key = serde_json::Map::new();
    if let Some(o) = p.as_object() {
        for (k, v) in o {
            if matches!(k.as_str(), "sample_redeem_hex" | "sampleRedeemHex" | "redeem_hex" | "spends" | "transactions" | "txs") {
                continue;
            }
            key.insert(k.clone(), v.clone());
        }
    }
    let empty = vec![];
    let spends = p.get("spends").or(p.get("transactions")).or(p.get("txs")).and_then(|x| x.as_array()).unwrap_or(&empty);
    let mut txs = Vec::new();
    for s in spends {
        let txid = s.get("txid").and_then(|x| x.as_str()).unwrap_or("?").to_string();
        txs.push((txid, rest::parse(s).map_err(|e| format!("{e:#}"))));
    }
    Ok(Program { key: Value::Object(key), redeem, txs })
}

fn programs_of(q: &Value) -> Vec<&Value> {
    match q {
        Value::Array(a) => a.iter().collect(),
        _ => q.get("programs").and_then(|x| x.as_array()).map(|a| a.iter().collect()).unwrap_or_default(),
    }
}

fn read_json(p: &Path) -> Result<Value> {
    let s = std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
    serde_json::from_str(&s).with_context(|| format!("parse {}", p.display()))
}

/// Runs every corpus case and says whether each was caught. An attack case is caught when the analyzer gives it
/// the label the case expects (`trap` or `hidden-powers`); a control case (`expect: "no-power"`) passes when no
/// power is witnessed.
fn corpus_check(dir: &str, pins: &Pins, budget: &Budget, o: &probe::Outsider) -> Result<Value> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir).with_context(|| format!("corpus dir {dir}"))?.filter_map(|e| e.ok().map(|e| e.path())).collect();
    files.sort();
    let mut cases = Vec::new();
    let mut all = true;
    for f in files.into_iter().filter(|f| f.extension().map(|e| e == "json").unwrap_or(false)) {
        let v = read_json(&f)?;
        let expect = v.get("expect").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("?").to_string();
        let prog = program_of(v.get("program").ok_or_else(|| anyhow!("{}: no program", f.display()))?)?;
        let r = analyze::analyze(&prog, pins, budget, o);
        let label = r["label"].as_str().unwrap_or("").to_string();
        let caught = if expect == "no-power" { label == "unverified" } else { label == expect };
        all &= caught;
        cases.push(json!({ "file": f.file_name().map(|x| x.to_string_lossy().to_string()), "name": name, "expect": expect, "got": label, "caught": caught,
                           "powers": r["findings"].as_array().map(|a| a.iter().map(|x| x["power"].clone()).collect::<Vec<_>>()) }));
    }
    if cases.is_empty() {
        bail!("the corpus directory {dir} has no cases");
    }
    Ok(json!({ "passed": all, "cases": cases }))
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("error: {e:#}");
        std::process::exit(2);
    }
}

fn real_main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("");
    let budget = Budget {
        max_runs: arg(&args, "--max-runs").and_then(|x| x.parse().ok()).unwrap_or(4000),
        max_seconds: arg(&args, "--max-seconds").and_then(|x| x.parse().ok()).unwrap_or(600),
    };
    let pins = load_pins(arg(&args, "--pins"));
    let o = probe::Outsider::new();
    match cmd {
        "corpus" => {
            let dir = arg(&args, "--corpus").ok_or_else(|| anyhow!("--corpus DIR"))?;
            let c = corpus_check(&dir, &pins, &budget, &o)?;
            println!("{}", serde_json::to_string_pretty(&c)?);
            if c["passed"] != json!(true) {
                std::process::exit(1);
            }
        }
        "run" => {
            let queue = arg(&args, "--queue").ok_or_else(|| anyhow!("--queue FILE"))?;
            let out = PathBuf::from(arg(&args, "--out").unwrap_or_else(|| "analyzer-out".into()));
            let only = arg(&args, "--only");
            let include_unverified = args.iter().any(|a| a == "--include-unverified-rows");
            std::fs::create_dir_all(out.join("reports"))?;
            let corpus = match arg(&args, "--corpus") {
                Some(dir) => {
                    let c = corpus_check(&dir, &pins, &budget, &o)?;
                    eprintln!("corpus: {}", if c["passed"] == json!(true) { "every case caught" } else { "NOT every case caught; the write-back will refuse these reports" });
                    c
                }
                None => json!({ "ran": false, "passed": false, "note": "no --corpus given; the write-back refuses reports made without the corpus check" }),
            };
            let q = read_json(Path::new(&queue))?;
            let mut rows = Vec::new();
            for p in programs_of(&q) {
                let hash = p.get("hash").or(p.get("code_hash")).and_then(|x| x.as_str()).unwrap_or("").to_string();
                if let Some(o) = &only {
                    if !hash.starts_with(o.as_str()) {
                        continue;
                    }
                }
                if !include_unverified && p.get("verified").map(|v| v == &json!(0) || v == &json!("0") || v == &json!(false)).unwrap_or(false) {
                    eprintln!("{}: skipped (verified = 0)", &hash[..hash.len().min(8)]);
                    continue;
                }
                let prog = match program_of(p) {
                    Ok(x) => x,
                    Err(e) => {
                        eprintln!("{hash}: {e:#}");
                        continue;
                    }
                };
                let t0 = std::time::Instant::now();
                let r = analyze::analyze(&prog, &pins, &budget, &o);
                let name = if hash.is_empty() { hex_short(&prog.redeem) } else { hash.clone() };
                std::fs::write(out.join("reports").join(format!("{name}.json")), serde_json::to_string_pretty(&r)?)?;
                eprintln!(
                    "{}  {:>6} B  {:<13} {:<11} runs {:>5}  {:.1}s  {}",
                    &name[..8], prog.redeem.len(), r["label"].as_str().unwrap_or(""), r["status"].as_str().unwrap_or(""),
                    r["mutations"]["engine_runs"], t0.elapsed().as_secs_f64(), r["summary"].as_str().unwrap_or("")
                );
                rows.push(json!({ "hash": hash, "status": r["status"], "label": r["label"], "analyzer_version": ANALYZER_VERSION, "report_json": r }));
            }
            let wb = json!({ "format": "kcc20-analyzer-writeback/1", "analyzer_version": ANALYZER_VERSION, "corpus_check": corpus, "rows": rows });
            std::fs::write(out.join("writeback.json"), serde_json::to_string(&wb)?)?;
            eprintln!("wrote {} reports and {}", rows.len(), out.join("writeback.json").display());
        }
        _ => {
            eprintln!("usage:\n  kcc20-analyzer run --queue FILE --out DIR [--corpus DIR] [--pins DIR] [--only HASHPREFIX] [--max-runs N] [--max-seconds S]\n  kcc20-analyzer corpus --corpus DIR");
            std::process::exit(2);
        }
    }
    Ok(())
}

fn hex_short(b: &[u8]) -> String {
    script::hex(&script::blake2b32(b))
}
