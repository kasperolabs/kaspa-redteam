//! Contribution rule enforced in CI: every attack ships a vulnerable fixture
//! it must catch and a fixed fixture on which the whole library stays silent.

use redteam_covenant::{contract::Contract, registry, run};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn load(path: &PathBuf) -> Contract {
    let src = std::fs::read_to_string(path).unwrap();
    Contract::load(&path.display().to_string(), &src, &BTreeMap::new())
        .unwrap_or_else(|e| panic!("{}: {e:#}", path.display()))
}

#[test]
fn every_attack_has_fixtures_and_they_behave() {
    let attacks = registry();
    assert!(attacks.len() >= 8, "registry has only {} attacks", attacks.len());
    let mut failures = Vec::new();
    for attack in attacks {
        let id = attack.meta().id;
        // Family and borrow attacks need a project of several files: tests/family.rs.
        if attack.meta().pack == "family" || attack.meta().pack == "borrow" {
            continue;
        }
        let dir = fixtures_dir().join(id);
        let vuln = dir.join("vulnerable.sil");
        let fixed = dir.join("fixed.sil");
        if !vuln.exists() || !fixed.exists() {
            failures.push(format!("{id}: missing fixtures in {}", dir.display()));
            continue;
        }

        let r = run(&load(&vuln), &[], vec![]);
        let caught: Vec<_> = r.findings().map(|f| format!("{}@{}", f.id, f.subject)).collect();
        if !r.findings().any(|f| f.id == id) {
            failures.push(format!("{id}: vulnerable fixture NOT caught (findings: {caught:?}; notes: {:?})", r.notes));
        }

        let r = run(&load(&fixed), &[], vec![]);
        let noise: Vec<_> = r.findings().map(|f| format!("{}@{}", f.id, f.subject)).collect();
        if !noise.is_empty() {
            failures.push(format!("{id}: fixed fixture raised {noise:?}"));
        }
        let unexplored: Vec<_> = r.notes.iter().filter(|n| n.contains("unexplored")).collect();
        if !unexplored.is_empty() {
            failures.push(format!("{id}: fixed fixture has unexplored paths {unexplored:?}"));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// ST-01 on a split: a new coin the spender funds and names the owner of is
/// not a takeover (the fixed seat stays clean), but moving the covenant's own
/// value into it is (the vulnerable seat is caught).
#[test]
fn st01_split_funded_by_the_spender() {
    let dir = fixtures_dir().join("ST-01");
    let r = run(&load(&dir.join("split_fixed.sil")), &[], vec![]);
    let noise: Vec<_> = r.findings().map(|f| format!("{}@{}", f.id, f.subject)).collect();
    assert!(noise.is_empty(), "fixed split raised {noise:?}; notes {:?}", r.notes);
    assert!(r.notes.iter().any(|n| n.contains("ST-01") && n.contains("the spender funds")), "{:?}", r.notes);
    assert!(!r.notes.iter().any(|n| n.contains("unexplored")), "{:?}", r.notes);
    let r = run(&load(&dir.join("split_vulnerable.sil")), &[], vec![]);
    assert!(r.findings().any(|f| f.id == "ST-01"), "vulnerable split not caught: {:?}; notes {:?}",
        r.findings().map(|f| format!("{}@{}", f.id, f.subject)).collect::<Vec<_>>(), r.notes);
}
