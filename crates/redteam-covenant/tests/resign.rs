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

/// A listed key's signature inside a witness push (a path byte, then the
/// signature) is found and signed again; the transaction passes as given and
/// after a change. Before 0.17.1 only a bare 65-byte push was looked at.
#[test]
fn listed_key_signature_inside_a_witness_is_remade() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/baseline/witness_vault.sil");
    let src = std::fs::read_to_string(&path).unwrap();
    let c = Contract::load("witness_vault.sil", &src, &BTreeMap::new()).unwrap();
    let judge = Judge::new();
    let paths = baseline::search_all(&c, &judge);
    assert!(paths.iter().any(|p| p.baseline.is_some()), "spend not explored");
    let mut doc = import::export(&c, &judge, &paths).unwrap();
    let sig_script = doc["transactions"][0]["tx"]["inputs"][0]["signatureScript"].as_str().unwrap().to_string();
    assert!(sig_script.starts_with("42"), "expected a 66-byte witness push first: {sig_script}");
    doc["keys"] = serde_json::json!([faster_hex::hex_string(&c.wallets.parties[0].keypair.secret_bytes())]);
    let file = std::env::temp_dir().join(format!("redteam-witness-{}.json", std::process::id()));
    std::fs::write(&file, serde_json::to_string(&doc).unwrap()).unwrap();
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
    assert_eq!(raw.resign.as_ref().map(|r| r.at), Some(2), "signature after the push opcode and the path byte");
    plan.outputs[0].value -= 1;
    assert!(matches!(judge.run(&c, &plan).0, Verdict::Accepted { .. }));
    let _ = std::fs::remove_file(file);
}
