//! Report output: terminal text, JSON, and per-finding files.

use crate::{Outcome, RunReport};
use std::fmt::Write as _;
use std::path::Path;

pub struct TermStyle {
    pub color: bool,
}

impl TermStyle {
    fn paint(&self, code: &str, s: &str) -> String {
        if self.color { format!("\x1b[{code}m{s}\x1b[0m") } else { s.to_string() }
    }
    fn red(&self, s: &str) -> String {
        self.paint("1;31", s)
    }
    fn green(&self, s: &str) -> String {
        self.paint("32", s)
    }
    fn yellow(&self, s: &str) -> String {
        self.paint("33", s)
    }
    fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }
    fn bold(&self, s: &str) -> String {
        self.paint("1", s)
    }
}

/// Human-readable report. `verbose` adds every attack row and the context block.
pub fn render_terminal(r: &RunReport, style: &TermStyle, verbose: bool) -> String {
    let mut o = String::new();
    let findings: Vec<_> = r.findings().collect();
    let _ = writeln!(
        o,
        "{}  {}  {}",
        style.bold(&format!("kaspa-redteam v{}", r.tool_version)),
        r.subject_name,
        style.dim(&format!("(library v{}, {} target)", r.library_version, r.target.as_str()))
    );
    let verdict = if findings.is_empty() {
        style.green("0 FINDINGS")
    } else {
        style.red(&format!("{} FINDING{}", findings.len(), if findings.len() == 1 { "" } else { "S" }))
    };
    let _ = writeln!(
        o,
        " {} attacks run   {} survived   {} skipped   {}   {}",
        r.count_run(),
        r.count_survived(),
        r.count_skipped(),
        verdict,
        style.dim(&format!("{:.1}s", r.millis as f64 / 1000.0))
    );

    if verbose {
        let _ = writeln!(o);
        for a in &r.results {
            let (tag, detail) = match &a.outcome {
                Outcome::Survived { attempts } => (
                    style.green("survived"),
                    format!("{attempts} attempt{} rejected", if *attempts == 1 { "" } else { "s" }),
                ),
                Outcome::Found { attempts, findings } => {
                    (style.red("FOUND   "), format!("{} of {attempts} attempts accepted", findings.len()))
                }
                Outcome::Skipped { reason } => (style.yellow("skipped "), reason.clone()),
            };
            let _ = writeln!(o, "  {:<7} {}  {:<48} {}", a.id, tag, a.title, style.dim(&detail));
        }
    }

    for f in &findings {
        let _ = writeln!(o);
        let sev = match f.severity {
            crate::Severity::High => style.red("[HIGH]"),
            crate::Severity::Med => style.yellow("[MED] "),
            crate::Severity::Low => style.dim("[LOW] "),
        };
        let _ = writeln!(o, "{sev} {} {}", style.bold(&f.id), f.title);
        let _ = writeln!(o, "  Path `{}`: {}", f.subject, f.explanation);
        if !f.in_practice.is_empty() {
            let _ = writeln!(o, "  In practice: {}", f.in_practice);
        }
        if let Some(file) = f.repro.get("file").and_then(|v| v.as_str()) {
            let _ = writeln!(o, "  Repro: {file}   replay: kaspa-redteam replay {file}");
        }
        let _ = writeln!(o, "  Fix pattern: {}", f.fix_pattern);
    }

    if verbose {
        if let Some(map) = r.context.get("spend_map").and_then(|m| m.as_array()) {
            let _ = writeln!(o, "\n{}", style.bold("Spend map (who can spend each path, as found by search)"));
            for p in map {
                let _ = writeln!(
                    o,
                    "  {:<20} {}",
                    p.get("path").and_then(|v| v.as_str()).unwrap_or("?"),
                    p.get("summary").and_then(|v| v.as_str()).unwrap_or("")
                );
            }
        }
    }
    if !r.notes.is_empty() {
        let _ = writeln!(o);
        for n in &r.notes {
            let _ = writeln!(o, "{}", style.dim(&format!("note: {n}")));
        }
    }
    o
}

pub fn render_json(r: &RunReport) -> String {
    serde_json::to_string_pretty(r).expect("report serializes")
}

/// Writes `findings/<ID>[-n].json` for every finding and records the file name
/// back into each finding's repro so the terminal report can point at it.
pub fn write_findings(r: &mut RunReport, dir: &Path) -> std::io::Result<Vec<String>> {
    let mut written = Vec::new();
    let mut seen: std::collections::HashMap<String, usize> = Default::default();
    for res in r.results.iter_mut() {
        if let Outcome::Found { findings, .. } = &mut res.outcome {
            for f in findings.iter_mut() {
                std::fs::create_dir_all(dir)?;
                let n = seen.entry(f.id.clone()).or_insert(0);
                *n += 1;
                let name = if *n == 1 { format!("{}.json", f.id) } else { format!("{}-{}.json", f.id, n) };
                let path = dir.join(&name);
                let display = path.display().to_string();
                if let Some(obj) = f.repro.as_object_mut() {
                    obj.insert("file".into(), serde_json::Value::String(display.clone()));
                }
                let record = serde_json::json!({
                    "id": f.id,
                    "severity": f.severity,
                    "target": f.target,
                    "spend_path": f.subject,
                    "title": f.title,
                    "explanation": f.explanation,
                    "in_practice": f.in_practice,
                    "fix_pattern": f.fix_pattern,
                    "replay_cmd": format!("kaspa-redteam replay {display}"),
                    "repro": f.repro,
                });
                std::fs::write(&path, serde_json::to_string_pretty(&record).unwrap())?;
                written.push(display);
            }
        }
    }
    Ok(written)
}
