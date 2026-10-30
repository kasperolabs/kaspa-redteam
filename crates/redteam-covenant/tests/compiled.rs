//! A compiled script built with real constructor values (real keys, a real
//! PIN hash) is tested as given: the tool swaps in its own keys and secret,
//! finds both paths, and reports the same bugs as the source.

use redteam_covenant::contract::Contract;
use redteam_covenant::sandbox::Judge;
use redteam_covenant::{baseline, compiled, ctor_file, run_paths};
use std::path::PathBuf;

#[test]
fn compiled_script_with_real_values() {
    let src = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/doordash_escrow_FAIL.sil"),
    )
    .unwrap();
    let file = r#"{
      "restaurant": "0x11b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
      "driver": "0x21b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
      "irs": "0x31b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
      "stateTax": "0x41b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
      "user": "0x51b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
      "pinHash": "0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "restaurantAmount": 2500000000, "driverAmount": 800000000, "irsAmount": 150000000,
      "stateTaxAmount": 100000000, "refundDelayBlocks": 1000 }"#;

    // "Their" build: every value real.
    let v: serde_json::Value = serde_json::from_str(file).unwrap();
    let real_overrides = v.as_object().unwrap().iter().map(|(k, x)| (k.clone(), x.to_string().trim_matches('"').to_string())).collect();
    let theirs = Contract::load("dd.sil", &src, &real_overrides).unwrap().bytecode;
    let hex = faster_hex::hex_string(&theirs);
    let json = format!(r#"{{"contracts":{{"DoorDashEscrow":{{"bytecode":"{hex}"}}}}}}"#);

    let (overrides, _, real) = ctor_file::load_full(file, &[&src]).unwrap();
    let mut c = Contract::load("dd.sil", &src, &overrides).unwrap();
    let notes = compiled::apply(&mut c, compiled::read_script(json.as_bytes()).unwrap(), &real).unwrap();
    assert!(notes.iter().any(|n| n.contains("identical")), "{notes:?}");
    assert!(notes.iter().any(|n| n.contains("`pinHash`") && n.contains("`user`")), "{notes:?}");

    let judge = Judge::new();
    let paths = baseline::search_all(&c, &judge);
    let gaps: Vec<_> = paths.iter().filter(|p| p.baseline.is_none()).map(|p| p.entry.clone()).collect();
    assert!(gaps.is_empty(), "unexplored {gaps:?}");
    let r = run_paths(&c, &[], paths, vec![], notes);
    let ids: Vec<String> = r.findings().map(|f| f.id.clone()).collect();
    assert!(ids.contains(&"IN-01".to_string()) && ids.contains(&"OUT-04".to_string()), "{ids:?}");

    // A script built with other values than the file says is refused, not tested.
    let other = file.replace("0x51b2", "0x61b2");
    let (o2, _, r2) = ctor_file::load_full(&other, &[&src]).unwrap();
    let mut c2 = Contract::load("dd.sil", &src, &o2).unwrap();
    assert!(compiled::apply(&mut c2, theirs.clone(), &r2).is_err());
}
