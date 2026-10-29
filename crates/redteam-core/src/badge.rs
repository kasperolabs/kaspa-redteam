//! Badge for a clean run: an SVG plus a summary anyone can check by re-running
//! the same tool and library version against the same subject hash.

use crate::RunReport;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct BadgeSummary {
    pub tool_version: String,
    pub library_version: String,
    pub target: String,
    pub subject_name: String,
    pub subject_hash: String,
    pub attacks_survived: usize,
    pub attacks_skipped: usize,
    pub attack_ids: Vec<String>,
    pub date_utc: String,
    /// sha256 over every field above, so an edited summary no longer matches.
    pub digest: String,
}

pub fn summary(r: &RunReport, date_utc: &str) -> BadgeSummary {
    let attack_ids: Vec<String> = r
        .results
        .iter()
        .filter(|a| matches!(a.outcome, crate::Outcome::Survived { .. }))
        .map(|a| a.id.clone())
        .collect();
    let joined = attack_ids.join(",");
    let digest = crate::sha256_hex(&[
        r.tool_version.as_bytes(),
        r.library_version.as_bytes(),
        r.target.as_str().as_bytes(),
        r.subject_hash.as_bytes(),
        joined.as_bytes(),
        date_utc.as_bytes(),
    ]);
    BadgeSummary {
        tool_version: r.tool_version.clone(),
        library_version: r.library_version.clone(),
        target: r.target.as_str().into(),
        subject_name: r.subject_name.clone(),
        subject_hash: r.subject_hash.clone(),
        attacks_survived: r.count_survived(),
        attacks_skipped: r.count_skipped(),
        attack_ids,
        date_utc: date_utc.into(),
        digest,
    }
}

/// Flat two-part badge, shields.io proportions, no external fonts.
pub fn svg(r: &RunReport) -> String {
    let left = "kaspa-redteam";
    let right = format!("survived {} attacks · v{}", r.count_survived(), r.library_version);
    // ~6.5px per char at 11px Verdana-ish metrics
    let lw = (left.len() as f64 * 6.6 + 14.0).round() as u32;
    let rw = (right.chars().count() as f64 * 6.3 + 14.0).round() as u32;
    let w = lw + rw;
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" role="img" aria-label="{left}: {right}">
<title>{left}: {right}</title>
<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
<clipPath id="r"><rect width="{w}" height="20" rx="3" fill="#fff"/></clipPath>
<g clip-path="url(#r)"><rect width="{lw}" height="20" fill="#2b2f36"/><rect x="{lw}" width="{rw}" height="20" fill="#2a9d74"/><rect width="{w}" height="20" fill="url(#s)"/></g>
<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
<text x="{lx}" y="14">{left}</text><text x="{rx}" y="14">{right}</text></g>
</svg>
"##,
        lx = lw / 2,
        rx = lw + rw / 2,
    )
}
