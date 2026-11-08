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

/// `BUY_TPL` is the template of ShopBuy (not ShopCondBuy, not the token), and
/// `BUY_PRE` / `BUY_SUF` its lengths, with no constructor values given; the
/// token rule still takes `tokenTplHash`.
#[test]
fn abbreviated_template_names_link_to_their_program() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dir = root.join("../../fixtures/project-links");
    let mut files: Vec<ProjectFile> = ["ShopWatch.sil", "ShopBuy.sil", "ShopSell.sil", "ShopCondBuy.sil"]
        .iter()
        .map(|n| ProjectFile { name: n.to_string(), source: std::fs::read_to_string(dir.join(n)).unwrap() })
        .collect();
    files.push(ProjectFile {
        name: "KCC20.sil".into(),
        source: std::fs::read_to_string(root.join("library/kcc20-reference/KCC20.sil")).unwrap(),
    });
    let (links, per_file) = project::detect(&files, &BTreeMap::new()).unwrap();
    let to = |via: &str| {
        links.iter().filter(|l| l.from == "ShopWatch.sil" && l.via == via).map(|l| l.to.as_str()).collect::<Vec<_>>()
    };
    assert_eq!(to("BUY_TPL"), ["ShopBuy.sil"], "{links:?}");
    assert_eq!(to("SELL_TPL"), ["ShopSell.sil"], "{links:?}");
    assert_eq!(to("init_tokenTplHash"), ["KCC20.sil"], "{links:?}");
    // The token's covenant id still goes to the token when the file links to several programs.
    assert_eq!(to("init_tokenCovId"), ["KCC20.sil"], "{links:?}");
    let ints = &per_file[0].ints;
    for (name, prog) in [("BUY_PRE", "ShopBuy"), ("BUY_SUF", "ShopBuy"), ("SELL_PRE", "ShopSell"), ("SELL_SUF", "ShopSell")] {
        assert_eq!(ints.get(name).map(|(p, _)| p.as_str()), Some(prog), "{name}: {ints:?}");
    }
    assert!(ints["BUY_SUF"].1 > 0);
}
