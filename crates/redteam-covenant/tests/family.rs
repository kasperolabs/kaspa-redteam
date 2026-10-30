//! Family attacks on a real three-program project: Kaspero Labs' ETH bridge
//! (driver, ZK proof), its mint authority (BridgeMint) and the KCC-20 cells it
//! creates. The real contracts survive every FAM attack; a copy with the
//! replay protection and its run-once init check removed is caught by FAM-06
//! and FAM-07.

use redteam_covenant::project::{self, ProjectFile};
use redteam_covenant::sandbox::Judge;
use std::collections::BTreeMap;
use std::path::PathBuf;

fn run(dir: &str) -> Vec<(String, Vec<String>, usize)> {
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
            (r.subject_name.clone(), r.findings().map(|f| f.id.clone()).collect(), fam_run)
        })
        .collect()
}

#[test]
fn bridge_family() {
    let fixed = run("fixed");
    let bridge = fixed.iter().find(|r| r.0 == "bridge.sil").unwrap();
    assert_eq!(bridge.2, 7, "every FAM attack should run on the mint and the genesis: {fixed:?}");
    assert!(bridge.1.is_empty(), "the real bridge should survive: {:?}", bridge.1);

    let vuln = run("vulnerable");
    let bridge = vuln.iter().find(|r| r.0 == "bridge.sil").unwrap();
    assert!(bridge.1.contains(&"FAM-06".to_string()), "replay not caught: {:?}", bridge.1);
    assert!(bridge.1.contains(&"FAM-07".to_string()), "second genesis not caught: {:?}", bridge.1);
}
