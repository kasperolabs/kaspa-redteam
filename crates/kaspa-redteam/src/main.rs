//! kaspa-redteam: attack your Kaspa covenant before mainnet does.
//!
//!   kaspa-redteam vault.sil                       attack a covenant (in process, no node)
//!   kaspa-redteam vault.sil --arg owner=@alice    pick constructor values
//!   kaspa-redteam vault.sil --only sig,outputs    run selected packs or attack IDs
//!   kaspa-redteam vault.sil --json                machine output for CI
//!   kaspa-redteam replay findings/OUT-01.json     re-judge a saved finding
//!   kaspa-redteam list                            every attack in the library
//!   kaspa-redteam node --kaspad ./kaspad          node and mining packs on a local simnet
//!   kaspa-redteam serve --port 8790               the drop-a-file web page
//!
//! Exit codes: 0 clean, 1 findings, 2 error.

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use redteam_core::report::{TermStyle, render_json, render_terminal, write_findings};
use redteam_core::{RunReport, Target};
use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

mod serve;

#[derive(Parser)]
#[command(name = "kaspa-redteam", version, about = "Attack your Kaspa covenant before mainnet does.")]
#[command(args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
    #[command(flatten)]
    scan: ScanArgs,
}

#[derive(clap::Args, Default)]
struct ScanArgs {
    /// SilverScript contract(s) to attack. Several files are treated as one project.
    files: Vec<PathBuf>,
    /// Constructor value: name=123 | name=0xhex | name=true | name=@party (test key)
    #[arg(long = "arg", value_name = "NAME=VALUE")]
    args: Vec<String>,
    /// Constructor values from a JSON file (the one you deploy with): {"name": value} or [values in order]. --arg wins.
    #[arg(long = "args", value_name = "FILE")]
    args_file: Option<PathBuf>,
    /// Test this compiled script (from your own pinned compiler) instead of compiling the source: silverc JSON, any JSON with a `bytecode` hex, or a hex file. Give the .sil too, and --args with the values it was compiled with.
    #[arg(long, value_name = "FILE")]
    compiled: Option<PathBuf>,
    /// Honest transactions to attack, from your own harness (format: BASELINE.md). Repeatable.
    #[arg(long = "baseline", value_name = "FILE")]
    baselines: Vec<PathBuf>,
    /// Keep the default constructor values even when they leave paths unexplored
    #[arg(long)]
    no_tune: bool,
    /// Stop searching after this many seconds and report what was found (unfinished paths are marked unexplored)
    #[arg(long, value_name = "SECONDS")]
    deadline: Option<u64>,
    #[command(flatten)]
    common: Common,
}

#[derive(clap::Args, Default, Clone)]
struct Common {
    /// Only these packs or attack IDs (comma separated), e.g. sig,OUT-02
    #[arg(long, value_delimiter = ',')]
    only: Vec<String>,
    /// Print the report as JSON
    #[arg(long)]
    json: bool,
    /// Show every attack and the spend map
    #[arg(short, long)]
    verbose: bool,
    /// Where finding files go
    #[arg(long, default_value = "findings")]
    out: PathBuf,
    /// Write redteam-badge.svg and redteam-summary.json on a clean run
    #[arg(long)]
    badge: bool,
    /// Plain text output (also when NO_COLOR is set or output is not a terminal)
    #[arg(long)]
    no_color: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Re-judge saved findings; exit 1 if any still reproduces
    Replay { files: Vec<PathBuf> },
    /// Write the honest spends the search finds as a baseline file (a format example and an editable template)
    Export {
        file: PathBuf,
        #[arg(long = "arg", value_name = "NAME=VALUE")]
        args: Vec<String>,
    },
    /// The constructor parameters of each file, with the values the tool would use (JSON)
    Params {
        files: Vec<PathBuf>,
    },
    /// List the attack library
    List {
        #[arg(long)]
        json: bool,
    },
    /// Web page: drop a .sil file in a browser, get the report (each scan runs isolated, nothing is kept)
    Serve {
        /// Address to listen on (put a reverse proxy in front for a public site)
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
        #[arg(long, default_value_t = 8790)]
        port: u16,
        /// Scans that may run at once
        #[arg(long, default_value_t = 2)]
        jobs: usize,
        /// Seconds before a scan is stopped
        #[arg(long, default_value_t = 120)]
        timeout: u64,
        /// Worker threads per scan
        #[arg(long, default_value_t = 4)]
        threads: usize,
    },
    /// Node and mining attacks on local simnet kaspad processes (never mainnet)
    Node {
        /// Path to a kaspad binary
        #[arg(long, default_value = "kaspad")]
        kaspad: PathBuf,
        /// Simnet nodes to start
        #[arg(long, default_value_t = 1)]
        nodes: usize,
        /// Keep node data directories for inspection
        #[arg(long)]
        keep: bool,
        #[command(flatten)]
        common: Common,
    },
}

fn main() -> ExitCode {
    match real_main() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn real_main() -> Result<ExitCode> {
    let cli = Cli::parse();
    match cli.cmd {
        Some(Cmd::Replay { files }) => replay(&files),
        Some(Cmd::List { json }) => list(json),
        Some(Cmd::Params { files }) => params(&files),
        Some(Cmd::Serve { bind, port, jobs, timeout, threads }) => {
            serve::serve(serve::ServeOptions { bind, port, jobs: jobs.max(1), timeout, threads: threads.max(1) })?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Cmd::Export { file, args }) => {
            let mut overrides = BTreeMap::new();
            for kv in &args {
                let (k, v) = kv.split_once('=').with_context(|| format!("--arg {kv}: expected NAME=VALUE"))?;
                overrides.insert(k.trim().to_string(), v.trim().to_string());
            }
            let source = std::fs::read_to_string(&file).with_context(|| format!("read {}", file.display()))?;
            let name = file.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            let (source, _) = redteam_covenant::legacy::prepare(&name, &source)?;
            let contract = redteam_covenant::contract::Contract::load(&name, &source, &overrides)?;
            let judge = redteam_covenant::sandbox::Judge::new();
            let paths = redteam_covenant::baseline::search_all(&contract, &judge);
            println!(
                "{}",
                serde_json::to_string_pretty(&redteam_covenant::import::export(&contract, &judge, &paths)?)?
            );
            Ok(ExitCode::SUCCESS)
        }
        Some(Cmd::Node { kaspad, nodes, keep, common }) => {
            let opts = redteam_node::NodeOptions { kaspad, nodes, keep_data: keep };
            let report = redteam_node::run(&opts, &common.only)?;
            finish(report, &common)
        }
        None => {
            if cli.scan.files.is_empty() && cli.scan.baselines.is_empty() {
                bail!("give a .sil file to attack, a --baseline file, or a subcommand (try --help)");
            }
            scan(&cli.scan)
        }
    }
}

fn scan(a: &ScanArgs) -> Result<ExitCode> {
    let mut overrides = BTreeMap::new();
    let mut file_notes = Vec::new();
    let mut real_values = BTreeMap::new();
    if let Some(path) = &a.args_file {
        let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let mut sources = Vec::new();
        for f in &a.files {
            let src = std::fs::read_to_string(f).with_context(|| format!("read {}", f.display()))?;
            let name = f.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            sources.push(redteam_covenant::legacy::prepare(&name, &src)?.0);
        }
        let refs: Vec<&str> = sources.iter().map(String::as_str).collect();
        let (vals, notes, real) =
            redteam_covenant::ctor_file::load_full(&raw, &refs).with_context(|| format!("{}", path.display()))?;
        overrides = vals;
        file_notes = notes;
        real_values = real;
    }
    for kv in &a.args {
        let (k, v) = kv.split_once('=').with_context(|| format!("--arg {kv}: expected NAME=VALUE"))?;
        overrides.insert(k.trim().to_string(), v.trim().to_string());
    }
    if a.compiled.is_some() && a.files.len() != 1 {
        bail!("--compiled needs exactly one .sil file next to it (the source of that script)");
    }
    if a.files.len() > 1 {
        return project(a, &overrides, file_notes);
    }
    let short =
        |p: &PathBuf| p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| p.display().to_string());
    let started = std::time::Instant::now();
    if let Some(s) = a.deadline {
        redteam_covenant::baseline::set_deadline(started + std::time::Duration::from_secs(s));
    }
    let judge = redteam_covenant::sandbox::Judge::new();
    let (contract, paths, notes) = match a.files.first() {
        Some(file) => {
            let source = std::fs::read_to_string(file).with_context(|| format!("read {}", file.display()))?;
            let (source, mut legacy) = redteam_covenant::legacy::prepare(&short(file), &source)?;
            if let Some(cpath) = &a.compiled {
                let raw = std::fs::read(cpath).with_context(|| format!("read {}", cpath.display()))?;
                let script = redteam_covenant::compiled::read_script(&raw).with_context(|| format!("{}", cpath.display()))?;
                let mut c = redteam_covenant::contract::Contract::load(&short(file), &source, &overrides)?;
                let notes = redteam_covenant::compiled::apply(&mut c, script, &real_values)
                    .with_context(|| format!("{}", cpath.display()))?;
                if a.args_file.is_none() && c.args.iter().any(|x| x.ty == "pubkey") {
                    legacy.push("no --args file: the compiled script holds your real keys, which the tool cannot sign with, so signed paths stay unexplored. Give the constructor values it was compiled with (--args) and the tool swaps in test keys.".into());
                }
                let p = redteam_covenant::baseline::search_all(&c, &judge);
                legacy.extend(notes);
                legacy.extend(file_notes);
                (c, p, legacy)
            } else if a.no_tune {
                let c = redteam_covenant::contract::Contract::load(&short(file), &source, &overrides)?;
                let p = redteam_covenant::baseline::search_all(&c, &judge);
                legacy.extend(file_notes);
                (c, p, legacy)
            } else {
                let mut t = redteam_covenant::tune::tune(&short(file), &source, &overrides, &judge)?;
                // Unexplored with the tool's default numbers: once more with the
                // feature switches the user did not set at 0 (see tune::zero_overrides).
                let gaps = |p: &[redteam_covenant::baseline::PathStatus]| {
                    let names: std::collections::BTreeSet<&str> = p.iter().map(|x| x.name.as_str()).collect();
                    names.iter().filter(|n| !p.iter().any(|x| x.name == **n && x.baseline.is_some())).count()
                };
                if gaps(&t.paths) > 0 {
                    if let Some((zov, zeroed)) = redteam_covenant::tune::zero_overrides(&t.contract, &overrides, &Default::default()) {
                        if let Ok(mut z) = redteam_covenant::tune::tune(&short(file), &source, &zov, &judge) {
                            if gaps(&z.paths) < gaps(&t.paths) {
                                z.notes.push(format!(
                                    "constructor values: with the tool's defaults some paths could not be spent, so the numbers that switch a feature on (compared with 0 or with the clock) and that you did not set were tried at 0, feature off: {}. Every other number kept the tool's default. Set them yourself to test other settings.",
                                    zeroed.join(", ")
                                ));
                                t = z;
                            }
                        }
                    }
                }
                legacy.extend(file_notes);
                legacy.extend(t.notes);
                (t.contract, t.paths, legacy)
            }
        }
        None => {
            if !overrides.is_empty() {
                bail!("--arg needs a .sil file");
            }
            let mut raw = Vec::new();
            for b in &a.baselines {
                raw.extend(std::fs::read(b).with_context(|| format!("read {}", b.display()))?);
            }
            let names: Vec<String> = a.baselines.iter().map(short).collect();
            (redteam_covenant::contract::Contract::for_import(&names.join(" + "), &raw), vec![], vec![])
        }
    };
    let mut imported = Vec::new();
    for b in &a.baselines {
        imported.extend(redteam_covenant::import::load(b, &contract, &judge)?);
    }
    let report = redteam_covenant::run_paths_timed(&contract, &a.common.only, paths, imported, notes, started);
    finish(report, &a.common)
}

/// Several files: one project, each contract searched and attacked with its
/// links to the others, one combined report.
fn project(a: &ScanArgs, overrides: &BTreeMap<String, String>, file_notes: Vec<String>) -> Result<ExitCode> {
    if !a.baselines.is_empty() {
        bail!("--baseline works with one .sil file at a time for now");
    }
    let started = std::time::Instant::now();
    if let Some(s) = a.deadline {
        redteam_covenant::baseline::set_deadline(started + std::time::Duration::from_secs(s));
    }
    let mut files = Vec::new();
    let mut legacy = Vec::new();
    for f in &a.files {
        let source = std::fs::read_to_string(f).with_context(|| format!("read {}", f.display()))?;
        let name = f.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| f.display().to_string());
        let (source, notes) = redteam_covenant::legacy::prepare(&name, &source)?;
        legacy.push(notes);
        files.push(redteam_covenant::project::ProjectFile { name, source });
    }
    let judge = redteam_covenant::sandbox::Judge::new();
    let (links, mut reports) = redteam_covenant::project::run(&files, overrides, &a.common.only, &judge)?;
    for (r, mut notes) in reports.iter_mut().zip(legacy) {
        notes.extend(file_notes.iter().cloned());
        r.notes.splice(0..0, notes);
    }
    let c = &a.common;
    let mut any = false;
    for (f, r) in files.iter().zip(reports.iter_mut()) {
        if !r.is_clean() {
            any = true;
            let stem = f.name.rsplit_once('.').map(|(s, _)| s).unwrap_or(&f.name);
            let dir = c.out.join(stem);
            write_findings(r, &dir).with_context(|| format!("write findings to {}", dir.display()))?;
        }
    }
    if c.json {
        let names: Vec<&str> = files.iter().map(|f| f.name.as_str()).collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "project": { "files": names, "links": links, "millis": started.elapsed().as_millis() },
                "reports": reports,
            }))?
        );
    } else {
        let style = TermStyle {
            color: !c.no_color && std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
        };
        let findings: usize = reports.iter().map(|r| r.findings().count()).sum();
        println!(
            "project: {} contracts, {} link(s), {} finding(s), {:.1}s",
            files.len(),
            links.len(),
            findings,
            started.elapsed().as_secs_f64()
        );
        for l in &links {
            let what = match l.kind { "address" => "pays to the address of", "covenant id" => "is the covenant id of the coins of", _ => "pins the program of" };
            println!("  {} `{}` {} {}", l.from, l.via, what, l.to);
        }
        if links.is_empty() {
            println!("  no links found between the files (each was attacked on its own)");
        }
        for r in &reports {
            println!();
            print!("{}", render_terminal(r, &style, c.verbose));
        }
    }
    Ok(if any { ExitCode::from(1) } else { ExitCode::SUCCESS })
}

fn finish(mut report: RunReport, c: &Common) -> Result<ExitCode> {
    if !report.is_clean() {
        write_findings(&mut report, &c.out).with_context(|| format!("write findings to {}", c.out.display()))?;
    }
    if c.json {
        println!("{}", render_json(&report));
    } else {
        let style = TermStyle {
            color: !c.no_color && std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
        };
        print!("{}", render_terminal(&report, &style, c.verbose));
    }
    if report.is_clean() {
        if c.badge {
            let date = utc_date();
            std::fs::write("redteam-badge.svg", redteam_core::badge::svg(&report))?;
            let summary = redteam_core::badge::summary(&report, &date);
            std::fs::write("redteam-summary.json", serde_json::to_string_pretty(&summary)?)?;
            if !c.json {
                println!("badge: redteam-badge.svg, redteam-summary.json");
            }
        }
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

fn replay(files: &[PathBuf]) -> Result<ExitCode> {
    if files.is_empty() {
        bail!("give one or more finding files");
    }
    let mut reproduced = 0;
    for f in files {
        let r = redteam_covenant::replay::replay_file(f)?;
        match r.verdict {
            redteam_covenant::sandbox::Verdict::Accepted { fee } => {
                reproduced += 1;
                println!(
                    "REPRODUCES  {} on `{}`  tx {}  (consensus accepted, fee {} sompi)",
                    r.id, r.path, r.tx_id, fee
                );
            }
            redteam_covenant::sandbox::Verdict::Rejected(why) => {
                println!("rejected    {} on `{}`  tx {}  ({why})", r.id, r.path, r.tx_id);
            }
        }
    }
    Ok(if reproduced > 0 { ExitCode::from(1) } else { ExitCode::SUCCESS })
}

/// Constructor parameters as the web form shows them: name, type, the value
/// the tool would use (in `--arg` syntax), where it came from, and whether
/// the tool must play it (a key or a secret it cannot take from you).
fn params(files: &[PathBuf]) -> Result<ExitCode> {
    use silverscript_abi::ArtifactValue;
    let mut out = Vec::new();
    for f in files {
        let name = f.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let raw = std::fs::read_to_string(f).with_context(|| format!("read {}", f.display()))?;
        let (source, _) = redteam_covenant::legacy::prepare(&name, &raw)?;
        let c = redteam_covenant::contract::Contract::load(&name, &source, &BTreeMap::new())?;
        let rows: Vec<serde_json::Value> = c
            .args
            .iter()
            .map(|a| {
                let value = match &a.value {
                    ArtifactValue::Int(n) => n.to_string(),
                    ArtifactValue::Bool(b) => b.to_string(),
                    ArtifactValue::Byte(b) => b.to_string(),
                    ArtifactValue::Bytes(b) => format!("0x{}", faster_hex::hex_string(b)),
                    ArtifactValue::Text(t) => t.clone(),
                    other => format!("{other:?}"),
                };
                let played = if a.ty == "pubkey" {
                    Some("key")
                } else if a.ty == "byte[32]" {
                    redteam_covenant::contract::played_by_tool(&source, &a.name)
                } else {
                    None
                };
                let (kind, hint) = redteam_covenant::contract::param_hint(&source, &a.name, &a.ty);
                serde_json::json!({ "name": a.name, "type": a.ty, "value": value, "origin": a.origin, "played": played, "kind": kind, "hint": hint })
            })
            .collect();
        out.push(serde_json::json!({ "file": name, "params": rows }));
    }
    println!("{}", serde_json::to_string(&out)?);
    Ok(ExitCode::SUCCESS)
}

fn list(json: bool) -> Result<ExitCode> {
    let mut rows: Vec<&'static redteam_core::AttackMeta> =
        redteam_covenant::registry().iter().map(|a| a.meta()).collect();
    rows.extend(redteam_node::registry().iter().map(|a| a.meta()));
    if json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(ExitCode::SUCCESS);
    }
    println!("attack library v{}  ({} attacks)\n", redteam_core::LIBRARY_VERSION, rows.len());
    let mut last: Option<Target> = None;
    for m in rows {
        if last != Some(m.target) {
            println!("{} attacks", m.target.as_str());
            last = Some(m.target);
        }
        println!("  {:<8} {:<9} {:<5} {:<50} catches: {}", m.id, m.pack, m.severity.as_str(), m.title, m.catches);
    }
    Ok(ExitCode::SUCCESS)
}

/// YYYY-MM-DD from the system clock, no extra dependency.
fn utc_date() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let days = (secs / 86_400) as i64;
    // Howard Hinnant's civil_from_days
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}")
}
