//! Family attacks on a real three-program project: Kaspero Labs' ETH bridge
//! (driver, ZK proof), its mint authority (BridgeMint) and the KCC-20 cells it
//! creates. The real contracts survive every FAM attack; a copy with the
//! replay protection and its run-once init check removed is caught by FAM-06
//! and FAM-07.

use redteam_covenant::project::{self, ProjectFile};
use redteam_covenant::sandbox::Judge;
use std::collections::BTreeMap;
use std::path::PathBuf;

fn run(dir: &str) -> Vec<(String, Vec<String>, usize, Vec<String>)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/family").join(dir);
    let files: Vec<ProjectFile> = ["KCC20.sil", "BridgeMint.sil", "bridge.sil"]
        .iter()
        .map(|n| ProjectFile { name: n.to_string(), source: std::fs::read_to_string(dir.join(n)).unwrap() })
        .collect();
    let (links, reports) = project::run(&files, &BTreeMap::new(), &[], &Judge::new()).unwrap();
    assert_eq!(links.iter().filter(|l| l.kind == "template").count(), 3, "{links:?}");
    reports
        .iter()
        .map(|r| {
            let fam_run = r
                .results
                .iter()
                .filter(|x| x.id.starts_with("FAM-") && !matches!(x.outcome, redteam_core::Outcome::Skipped { .. }))
                .count();
            let gaps = r.context["spend_map"]
                .as_array()
                .map(|m| m.iter().filter(|x| x["explored"] != true).map(|x| x["path"].to_string()).collect())
                .unwrap_or_default();
            (r.subject_name.clone(), r.findings().map(|f| f.id.clone()).collect(), fam_run, gaps)
        })
        .collect()
}

#[test]
fn bridge_family() {
    let fixed = run("fixed");
    let bridge = fixed.iter().find(|r| r.0 == "bridge.sil").unwrap();
    assert_eq!(bridge.2, 7, "every FAM attack should run on the mint and the genesis: {fixed:?}");
    assert!(bridge.1.is_empty(), "the real bridge should survive: {:?}", bridge.1);
    // Every path explored: the bridge's (heartbeat, mint, genesis) and the minted coin's own.
    assert!(bridge.3.is_empty(), "bridge gaps: {:?}", bridge.3);
    let cell = fixed.iter().find(|r| r.0 == "KCC20.sil").unwrap();
    assert!(cell.3.is_empty(), "KCC20 gaps (minted coin spends): {:?}", cell.3);

    let vuln = run("vulnerable");
    let bridge = vuln.iter().find(|r| r.0 == "bridge.sil").unwrap();
    assert!(bridge.1.contains(&"FAM-06".to_string()), "replay not caught: {:?}", bridge.1);
    assert!(bridge.1.contains(&"FAM-07".to_string()), "second genesis not caught: {:?}", bridge.1);
}

fn run_pair(dir: &str) -> Vec<(String, Vec<String>, usize, Vec<String>)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/family").join(dir);
    let files: Vec<ProjectFile> = ["kcc20.sil", "kcc20-minter.sil"]
        .iter()
        .map(|n| ProjectFile { name: n.to_string(), source: std::fs::read_to_string(dir.join(n)).unwrap() })
        .collect();
    let (links, reports) = project::run(&files, &BTreeMap::new(), &[], &Judge::new()).unwrap();
    assert!(links.iter().any(|l| l.via == "expectedTemplateHash"), "template link by role: {links:?}");
    reports
        .iter()
        .map(|r| {
            let fam_run = r.results.iter().filter(|x| x.id.starts_with("FAM-") && !matches!(x.outcome, redteam_core::Outcome::Skipped { .. })).count();
            let gaps = r.context["spend_map"].as_array().map(|m| m.iter().filter(|x| x["explored"] != true).map(|x| x["path"].to_string()).collect()).unwrap_or_default();
            (r.subject_name.clone(), r.findings().map(|f| f.id.clone()).collect(), fam_run, gaps)
        })
        .collect()
}

/// The SilverScript repository's own KCC-20 and minter (another author, another
/// design): every path explored, the family attacks run and are rejected; with
/// one check removed, FAM-08 catches it.
#[test]
fn upstream_minter_family() {
    let fixed = run_pair("upstream");
    for r in &fixed {
        assert!(r.1.is_empty(), "{}: {:?}", r.0, r.1);
        assert!(r.3.is_empty(), "{} gaps: {:?}", r.0, r.3);
    }
    let minter = fixed.iter().find(|r| r.0 == "kcc20-minter.sil").unwrap();
    assert!(minter.2 >= 5, "family attacks on the mint: {}", minter.2);
    let vuln = run_pair("upstream_vulnerable");
    let minter = vuln.iter().find(|r| r.0 == "kcc20-minter.sil").unwrap();
    assert!(minter.1.contains(&"FAM-08".to_string()), "minting power not caught: {:?}", minter.1);
}

fn run_files(dir: &str, names: &[&str]) -> Vec<(String, Vec<String>, usize, Vec<String>)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/family").join(dir);
    let files: Vec<ProjectFile> =
        names.iter().map(|n| ProjectFile { name: n.to_string(), source: std::fs::read_to_string(dir.join(n)).unwrap() }).collect();
    let (_, reports) = project::run(&files, &BTreeMap::new(), &[], &Judge::new()).unwrap();
    reports
        .iter()
        .map(|r| {
            let fam_run = r.results.iter().filter(|x| x.id.starts_with("FAM-") && !matches!(x.outcome, redteam_core::Outcome::Skipped { .. })).count();
            let gaps = r.context["spend_map"].as_array().map(|m| m.iter().filter(|x| x["explored"] != true).map(|x| x["path"].to_string()).collect()).unwrap_or_default();
            (r.subject_name.clone(), r.findings().map(|f| f.id.clone()).collect(), fam_run, gaps)
        })
        .collect()
}

/// A market: a bonding curve that owns its token coin by covenant id and
/// computes every coin itself. init, buy and sell (with a seller's second coin)
/// are explored and survive; a copy that forgets the price is caught by FAM-09.
#[test]
fn curve_family() {
    let fixed = run_files("curve", &["curve.sil", "KCC20.sil"]);
    let curve = fixed.iter().find(|r| r.0 == "curve.sil").unwrap();
    assert!(curve.1.is_empty(), "the curve should survive: {:?}", curve.1);
    assert!(curve.3.is_empty(), "curve gaps: {:?}", curve.3);
    assert!(curve.2 >= 6, "family attacks on the curve: {}", curve.2);
    // The follower entry ran inside `sell`, so the token program has no gap either.
    let token = fixed.iter().find(|r| r.0 == "KCC20.sil").unwrap();
    assert!(token.3.is_empty(), "KCC20 gaps: {:?}", token.3);
    let vuln = run_files("curve_vulnerable", &["curve.sil", "KCC20.sil"]);
    let curve = vuln.iter().find(|r| r.0 == "curve.sil").unwrap();
    assert!(curve.1.contains(&"FAM-09".to_string()), "free tokens not caught: {:?}", curve.1);
    // Without the borrow check on the coin it holds, one borrowed token unit bricks it.
    let borrowable = run_files("curve_borrow", &["curve.sil", "KCC20.sil"]);
    let curve = borrowable.iter().find(|r| r.0 == "curve.sil").unwrap();
    assert!(curve.1.contains(&"BOR-01".to_string()), "borrow bricking not caught: {:?}", curve.1);
}

/// A token program's borrowed receive, on every borrow scheme: the KCC-20
/// reference survives BOR-03 to BOR-07; with its owner and KAS checks removed
/// from the borrow path, BOR-03 and BOR-05 catch it.
#[test]
fn kcc20_borrow() {
    let fixed = run_files("curve", &["KCC20.sil"]);
    let token = &fixed[0];
    assert!(token.1.is_empty(), "the reference should survive: {:?}", token.1);
    assert!(token.3.is_empty(), "borrow paths unexplored: {:?}", token.3);
    let vuln = run_files("kcc20_borrow", &["KCC20.sil"]);
    for id in ["BOR-03", "BOR-05"] {
        assert!(vuln[0].1.contains(&id.to_string()), "{id} not caught: {:?}", vuln[0].1);
    }
}
