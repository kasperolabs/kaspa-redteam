//! Projects: the town treasury and a department fund are tested together.
//! The fund's `treasury` parameter must be linked to the real treasury
//! script, and the pair must come out clean with every path explored.

use redteam_covenant::project::{self, ProjectFile};
use redteam_covenant::sandbox::Judge;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[test]
fn town_project_links_and_runs_clean() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../corpus/town");
    let files: Vec<ProjectFile> = ["town_treasury.sil", "department_fund.sil"]
        .iter()
        .map(|n| ProjectFile { name: n.to_string(), source: std::fs::read_to_string(dir.join(n)).unwrap() })
        .collect();
    let (links, reports) = project::run(&files, &BTreeMap::new(), &[], &Judge::new()).unwrap();
    assert_eq!(links.len(), 1, "{links:?}");
    assert_eq!((links[0].from.as_str(), links[0].via.as_str(), links[0].to.as_str(), links[0].kind),
        ("department_fund.sil", "treasury", "town_treasury.sil", "address"));
    assert_eq!(reports.len(), 2);
    for r in &reports {
        assert_eq!(r.findings().count(), 0, "{}", r.subject_name);
        let map = r.context["spend_map"].as_array().cloned().unwrap_or_default();
        assert!(!map.is_empty(), "{}: no spend map", r.subject_name);
        let gaps: Vec<_> = map.iter().filter(|m| m["explored"] != true).map(|m| m["path"].to_string()).collect();
        assert!(gaps.is_empty(), "{}: unexplored {gaps:?}", r.subject_name);
    }
}
