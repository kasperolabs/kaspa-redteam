//! Shared vocabulary for every kaspa-redteam engine.
//!
//! An *engine* knows how to stand up one kind of target (a covenant in an
//! in-process consensus sandbox, a local simnet node, a miner) and run the
//! attacks written for it. Engines differ; what they report does not. Every
//! engine produces the same [`Outcome`]s, the runner turns them into a
//! [`RunReport`], and the reporters in this crate print it, save findings and
//! write the badge.

pub mod badge;
pub mod report;

use serde::{Deserialize, Serialize};

/// Version of the attack library. Bumped whenever attacks are added or changed,
/// so old badges visibly age.
pub const LIBRARY_VERSION: &str = "0.3.0";
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// What kind of thing an attack targets. New engines add a variant here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    /// A SilverScript covenant, judged by rusty-kaspa consensus code in process.
    Covenant,
    /// A kaspad node (mempool, RPC, p2p) on a local simnet.
    Node,
    /// Block templates, block validation and mining on a local simnet.
    Mining,
}

impl Target {
    pub fn as_str(&self) -> &'static str {
        match self {
            Target::Covenant => "covenant",
            Target::Node => "node",
            Target::Mining => "mining",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    /// Funds can be stolen.
    High,
    /// Funds stuck, or leaked to fees.
    Med,
    /// Griefing, degraded liveness.
    Low,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::High => "HIGH",
            Severity::Med => "MED",
            Severity::Low => "LOW",
        }
    }
}

/// Static description of one attack. Every attack plugin owns one of these.
#[derive(Debug, Clone, Serialize)]
pub struct AttackMeta {
    /// Stable ID, e.g. `OUT-01`. Never reused for a different attack.
    pub id: &'static str,
    /// Pack name used by `--only`, e.g. `outputs`.
    pub pack: &'static str,
    pub target: Target,
    /// One line: what the attack does.
    pub title: &'static str,
    /// One line: the bug class it catches.
    pub catches: &'static str,
    pub severity: Severity,
    /// Short pattern that closes the hole.
    pub fix_pattern: &'static str,
}

/// A confirmed problem. Only produced when the judge accepted something the
/// attack expected to be rejected (or an invariant broke after acceptance).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub target: Target,
    /// Which part of the target failed: a spend path name, an RPC, a rule.
    pub subject: String,
    pub explanation: String,
    pub fix_pattern: String,
    /// Everything needed to replay the finding. Engine specific.
    pub repro: serde_json::Value,
}

/// What one attack run produced.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Outcome {
    /// Every hostile attempt was rejected.
    Survived { attempts: usize },
    /// At least one hostile attempt was accepted.
    Found { attempts: usize, findings: Vec<Finding> },
    /// The attack does not apply to this target, or the engine could not
    /// reach the state it needs. Not a pass and not a failure.
    Skipped { reason: String },
}

/// One row of the report: an attack and what came of it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackResult {
    pub id: String,
    pub pack: String,
    pub target: Target,
    pub title: String,
    pub outcome: Outcome,
    pub millis: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunReport {
    pub tool_version: String,
    pub library_version: String,
    pub target: Target,
    /// File or endpoint that was attacked.
    pub subject_name: String,
    /// sha256 of what was attacked (source + args for a covenant), hex.
    pub subject_hash: String,
    pub results: Vec<AttackResult>,
    /// Engine-specific context worth showing, e.g. the covenant spend map.
    pub context: serde_json::Value,
    /// Plain notes for the reader: limits of this run, unexplored paths.
    pub notes: Vec<String>,
    pub millis: u128,
}

impl RunReport {
    pub fn findings(&self) -> impl Iterator<Item = &Finding> {
        self.results.iter().flat_map(|r| match &r.outcome {
            Outcome::Found { findings, .. } => findings.as_slice(),
            _ => &[],
        })
    }
    pub fn count_run(&self) -> usize {
        self.results.iter().filter(|r| !matches!(r.outcome, Outcome::Skipped { .. })).count()
    }
    pub fn count_survived(&self) -> usize {
        self.results.iter().filter(|r| matches!(r.outcome, Outcome::Survived { .. })).count()
    }
    pub fn count_skipped(&self) -> usize {
        self.results.iter().filter(|r| matches!(r.outcome, Outcome::Skipped { .. })).count()
    }
    pub fn is_clean(&self) -> bool {
        self.findings().next().is_none()
    }
}

/// `--only` filter: matches pack names and attack IDs, case-insensitive.
pub fn selected(meta: &AttackMeta, only: &[String]) -> bool {
    only.is_empty() || only.iter().any(|o| o.eq_ignore_ascii_case(meta.pack) || o.eq_ignore_ascii_case(meta.id))
}

pub fn sha256_hex(parts: &[&[u8]]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for p in parts {
        h.update((p.len() as u64).to_le_bytes());
        h.update(p);
    }
    faster_hex::hex_string(&h.finalize())
}
