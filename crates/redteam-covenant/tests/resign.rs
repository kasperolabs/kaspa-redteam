//! Baseline `keys`: a signature a listed throwaway key made is remade after
//! every change, so attacks can alter what that key signed over.

use redteam_covenant::sandbox::{InputSpec, Judge, Verdict};
use redteam_covenant::{baseline, contract::Contract, import};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn exported_with_keys(keys: &[String]) -> (Contract, PathBuf) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/SIG-01/fixed.sil");
    let src = std::fs::read_to_string(&path).unwrap();
    let c = Contract::load("fixed.sil", &src, &BTreeMap::new()).unwrap();
    let judge = Judge::new();
    let paths = baseline::search_all(&c, &judge);
    let mut doc = import::export(&c, &judge, &paths).unwrap();
    doc["keys"] = serde_json::json!(keys);
    let out = std::env::temp_dir().join(format!("redteam-resign-{}-{}.json", std::process::id(), keys.len()));
    std::fs::write(&out, serde_json::to_string(&doc).unwrap()).unwrap();
    (c, out)
}

#[test]
fn listed_key_signatures_are_remade() {
    let probe = Contract::load(
        "fixed.sil",
        &std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/SIG-01/fixed.sil"))
            .unwrap(),
        &BTreeMap::new(),
    )
    .unwrap();
    let owner_secret = faster_hex::hex_string(&probe.wallets.parties[0].keypair.secret_bytes());
    let judge = Judge::new();

    for (keys, expect_remade) in [(vec![], false), (vec![owner_secret], true)] {
        let (c, file) = exported_with_keys(&keys);
        let paths = import::load(&file, &c, &judge).unwrap();
        let mut plan = paths[0].baseline.as_ref().unwrap().plan.clone();
        let raw = plan
            .inputs
            .iter()
            .find_map(|i| match i {
                InputSpec::Raw(r) if r.target => Some(r.clone()),
                _ => None,
            })
            .unwrap();
        assert_eq!(raw.resign.is_some(), expect_remade);
        assert_eq!(raw.signed, !expect_remade);

        // Change what was signed: one sompi more fee.
        plan.outputs[0].value -= 1;
        let (v, _) = judge.run(&c, &plan);
        match (expect_remade, v) {
            (true, Verdict::Accepted { .. }) | (false, Verdict::Rejected(_)) => {}
            (e, v) => panic!("keys listed: {e}, verdict {v:?}"),
        }
        let _ = std::fs::remove_file(file);
    }
}
