//! Baseline files with more than one transaction: one that consensus rejects
//! as given is skipped with a note and the rest are attacked; a DAA lock time
//! above the file's context raises the context to lock time + 1.

use redteam_covenant::sandbox::Judge;
use redteam_covenant::{baseline, contract::Contract, import};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn payout() -> (Contract, serde_json::Value) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/OUT-02/fixed.sil");
    let c = Contract::load("fixed.sil", &std::fs::read_to_string(&path).unwrap(), &BTreeMap::new()).unwrap();
    let judge = Judge::new();
    let paths = baseline::search_all(&c, &judge);
    let doc = import::export(&c, &judge, &paths).unwrap();
    (c, doc)
}

fn write(doc: &serde_json::Value, tag: &str) -> PathBuf {
    let f = std::env::temp_dir().join(format!("redteam-bfiles-{tag}-{}.json", std::process::id()));
    std::fs::write(&f, serde_json::to_string(doc).unwrap()).unwrap();
    f
}

#[test]
fn a_rejected_transaction_is_skipped_and_a_daa_lock_raises_the_context() {
    let (c, mut doc) = payout();
    let good = doc["transactions"][0].clone();
    // Rejected as given: the payout is cut below what the covenant requires.
    let mut bad = good.clone();
    bad["path"] = "cut".into();
    let v = bad["tx"]["outputs"][0]["value"].as_u64().unwrap();
    bad["tx"]["outputs"][0]["value"] = (v / 2).into();
    // A DAA lock time above the context: valid only in a later block.
    let mut locked = good.clone();
    locked["path"] = "locked".into();
    locked["daaScore"] = 1000.into();
    locked["tx"]["lockTime"] = 5000.into();
    for i in locked["tx"]["inputs"].as_array_mut().unwrap() {
        i["sequence"] = 0.into();
    }
    doc["transactions"] = serde_json::json!([good, bad, locked]);
    let f = write(&doc, "mixed");
    let judge = Judge::new();
    let (paths, notes) = import::load_with(&f, &c, &judge, &[]).unwrap();
    let names: Vec<&str> = paths.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names.len(), 2, "{names:?}");
    assert!(names.contains(&"locked"), "{names:?}");
    assert!(
        notes.iter().any(|n| n.contains("1 of 3 transaction(s) skipped")
            && n.contains("`cut`")
            && n.contains("rejected by consensus as given")),
        "{notes:?}"
    );
    assert!(notes.iter().any(|n| n.contains("DAA lock time") && n.contains("`locked` (1000 -> 5001)")), "{notes:?}");
    let locked_plan = &paths.iter().find(|p| p.name == "locked").unwrap().baseline.as_ref().unwrap().plan;
    assert_eq!(locked_plan.pov_daa, 5001);
    // The whole run goes on: the attacks run on both transactions.
    let r = redteam_covenant::run_paths(&c, &[], vec![], paths, notes);
    assert!(r.notes.iter().any(|n| n.contains("2 baseline transaction(s) imported")), "{:?}", r.notes);
    // Strict loading (fetch) still refuses the file, and a file where nothing
    // can be attacked is an error with the reasons.
    assert!(import::load_strict(&f, &c, &judge).is_err());
    let mut only_bad = doc.clone();
    only_bad["transactions"] = serde_json::json!([doc["transactions"][1].clone()]);
    let f2 = write(&only_bad, "bad");
    let e = import::load_with(&f2, &c, &judge, &[]).unwrap_err().to_string();
    assert!(e.contains("no transaction can be attacked") && e.contains("`cut`"), "{e}");
    let _ = std::fs::remove_file(f);
    let _ = std::fs::remove_file(f2);
}
