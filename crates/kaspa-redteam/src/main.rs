//! kaspa-redteam: attack your Kaspa covenant before mainnet does.
//!
//!   kaspa-redteam vault.sil                       attack a covenant (in process, no node)
//!   kaspa-redteam vault.sil --arg owner=@alice    pick constructor values
//!   kaspa-redteam vault.sil --only sig,outputs    run selected packs or attack IDs
//!   kaspa-redteam vault.sil --json                machine output for CI
//!   kaspa-redteam replay findings/OUT-01.json     re-judge a saved finding
//!   kaspa-redteam list                            every attack in the library
//!   kaspa-redteam node --kaspad ./kaspad          node and mining packs on a local simnet
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
    /// SilverScript contract to attack
    file: Option<PathBuf>,
    /// Constructor value: name=123 | name=0xhex | name=true | name=@party (test key)
    #[arg(long = "arg", value_name = "NAME=VALUE")]
    args: Vec<String>,
    /// Honest transactions to attack, from your own harness (format: BASELINE.md). Repeatable.
    #[arg(long = "baseline", value_name = "FILE")]
    baselines: Vec<PathBuf>,
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
    /// List the attack library
    List {
        #[arg(long)]
        json: bool,
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
        Some(Cmd::Export { file, args }) => {
            let mut overrides = BTreeMap::new();
            for kv in &args {
                let (k, v) = kv.split_once('=').with_context(|| format!("--arg {kv}: expected NAME=VALUE"))?;
                overrides.insert(k.trim().to_string(), v.trim().to_string());
            }
            let source = std::fs::read_to_string(&file).with_context(|| format!("read {}", file.display()))?;
            let name = file.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
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
            if cli.scan.file.is_none() && cli.scan.baselines.is_empty() {
                bail!("give a .sil file to attack, a --baseline file, or a subcommand (try --help)");
            }
            scan(&cli.scan)
        }
    }
}

fn scan(a: &ScanArgs) -> Result<ExitCode> {
    let mut overrides = BTreeMap::new();
    for kv in &a.args {
        let (k, v) = kv.split_once('=').with_context(|| format!("--arg {kv}: expected NAME=VALUE"))?;
        overrides.insert(k.trim().to_string(), v.trim().to_string());
    }
    let short =
        |p: &PathBuf| p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| p.display().to_string());
    let contract = match &a.file {
        Some(file) => {
            let source = std::fs::read_to_string(file).with_context(|| format!("read {}", file.display()))?;
            redteam_covenant::contract::Contract::load(&short(file), &source, &overrides)?
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
            redteam_covenant::contract::Contract::for_import(&names.join(" + "), &raw)
        }
    };
    let judge = redteam_covenant::sandbox::Judge::new();
    let mut imported = Vec::new();
    for b in &a.baselines {
        imported.extend(redteam_covenant::import::load(b, &contract, &judge)?);
    }
    let report = redteam_covenant::run(&contract, &a.common.only, imported);
    finish(report, &a.common)
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
