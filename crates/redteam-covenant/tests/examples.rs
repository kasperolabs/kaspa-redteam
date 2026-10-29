//! The example contracts say in their file names what the red team reports:
//! `_FAIL` at least one finding, `_PASS` none, with every path explored.

use redteam_covenant::sandbox::Judge;
use redteam_covenant::{run_paths, tune};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[test]
fn examples_match_their_names() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples");
    let judge = Judge::new();
    let mut failures = Vec::new();
    let mut n = 0;
    for e in std::fs::read_dir(&dir).unwrap() {
        let path = e.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if !name.ends_with(".sil") {
            continue;
        }
        n += 1;
        let src = std::fs::read_to_string(&path).unwrap();
        let t = tune::tune(&name, &src, &BTreeMap::new(), &judge).unwrap();
        let unexplored: Vec<String> =
            t.paths.iter().filter(|p| p.baseline.is_none()).map(|p| p.entry.clone()).collect();
        let r = run_paths(&t.contract, &[], t.paths, vec![], t.notes);
        let found = r.findings().count();
        if name.contains("_FAIL") && found == 0 {
            failures.push(format!("{name}: expected findings, got none (unexplored: {unexplored:?})"));
        }
        if name.contains("_PASS") && (found > 0 || !unexplored.is_empty()) {
            let ids: Vec<String> = r.findings().map(|f| f.id.clone()).collect();
            failures.push(format!("{name}: expected clean, got {ids:?}, unexplored {unexplored:?}"));
        }
    }
    assert!(n >= 10, "only {n} examples found");
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}
