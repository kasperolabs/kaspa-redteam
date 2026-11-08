//! Real transactions with KCC-20 reference cells: the tool recognizes the cells
//! by template hash, labels the owner's signature inside the token witness,
//! and builds the family and borrow attacks against the covenant that holds
//! them. The covenant here is planted with every bug: a coin anyone can spend
//! (`OP_TRUE`) that owns a KCC-20 cell by its covenant id.

use kaspa_consensus_core::tx::{CovenantBinding, UtxoEntry};
use kaspa_hashes::Hash;
use kaspa_txscript::pay_to_script_hash_script;
use redteam_covenant::contract::Contract;
use redteam_covenant::known::{self, Pin};
use redteam_covenant::sandbox::{
    Dest, InputSpec, Judge, OutputSpec, RawInput, Resign, SpendPlan, StateValues, Verdict, push_data,
};
use redteam_covenant::wallets::KeyRef;
use redteam_covenant::{import, run_paths_timed};
use silverscript_abi::ArtifactValue;

fn kcc20() -> &'static Pin {
    known::builtin().iter().find(|p| p.name == "KCC20").unwrap()
}

fn state(owner: &[u8], scheme: u8, amount: i64) -> StateValues {
    let mut st = StateValues::new();
    st.insert("amount".into(), ArtifactValue::Int(amount));
    st.insert("owner".into(), ArtifactValue::Bytes(owner.to_vec()));
    st.insert("owner_scheme".into(), ArtifactValue::Byte(scheme));
    st.insert("borrow_scheme".into(), ArtifactValue::Byte(0));
    st.insert("borrow_guard".into(), ArtifactValue::Bytes(vec![0; 32]));
    st.insert("extension_commitment".into(), ArtifactValue::Bytes(vec![0; 32]));
    st
}

fn full(st: &StateValues) -> StateValues {
    let mut s = st.clone();
    s.insert("gen__kcc20_template".into(), ArtifactValue::Bytes(kcc20().hash.to_vec()));
    s
}

fn raw(script: Vec<u8>, entry: UtxoEntry, budget: u16, target: bool) -> InputSpec {
    InputSpec::Raw(RawInput {
        outpoint: None,
        signature_script: script,
        sequence: 0,
        sig_op_count: 0,
        compute_budget: budget,
        entry,
        target,
        signed: false,
        resign: None,
        named: Vec::new(),
    })
}

/// Writes `plan` as a baseline file, after checking consensus accepts it.
fn baseline(c: &Contract, judge: &Judge, plan: &SpendPlan, name: &str) -> std::path::PathBuf {
    let (v, built) = judge.run(c, plan);
    assert!(matches!(v, Verdict::Accepted { .. }), "honest {name}: {v:?}");
    let b = built.unwrap();
    let doc = serde_json::json!({
        "format": import::FORMAT,
        "transactions": [{
            "path": name,
            "tx": serde_json::to_value(&b.tx).unwrap(),
            "utxos": serde_json::to_value(&b.entries).unwrap(),
        }],
    });
    let out = std::env::temp_dir().join(format!("redteam-known-{name}-{}.json", std::process::id()));
    std::fs::write(&out, serde_json::to_string(&doc).unwrap()).unwrap();
    out
}

const KAS: u64 = 100_000_000;

#[test]
fn planted_market_loses_swept_and_borrowable_cells() {
    let c = Contract::for_import("planted", b"");
    let judge = Judge::new();
    let market_id = Hash::from_bytes([0x11; 32]);
    let token_id = Hash::from_bytes([0x22; 32]);
    let market = raw(
        push_data(&[0x51]).unwrap(),
        UtxoEntry::new(5 * KAS, pay_to_script_hash_script(&[0x51]), 1000, false, Some(market_id)),
        1,
        true,
    );
    let held = state(market_id.as_bytes().as_slice(), 4, 1000);
    let redeem = kcc20().redeem(&full(&held)).unwrap();
    let next = vec![ArtifactValue::Object(held.clone())];
    let cell_script =
        kcc20().sig_script("transfer", &[ArtifactValue::Array(next), ArtifactValue::Bytes(vec![0])], &redeem).unwrap();
    let cell = raw(
        cell_script,
        UtxoEntry::new(KAS, pay_to_script_hash_script(&redeem), 1000, false, Some(token_id)),
        10,
        false,
    );
    let plan = SpendPlan {
        version: 1,
        inputs: vec![market, cell, InputSpec::P2pk { owner: KeyRef::Attacker, value: 10 * KAS }],
        outputs: vec![
            OutputSpec {
                value: KAS,
                to: Dest::Raw(pay_to_script_hash_script(&redeem)),
                covenant: Some(CovenantBinding::new(1, token_id)),
                own: false,
            },
            OutputSpec::new(15 * KAS - 1_000_000, Dest::Key(KeyRef::Attacker)),
        ],
        lock_time: 0,
        payload: vec![],
        pov_daa: 10_000_000,
        block_time: 4_000_000_000_000,
        genesis: vec![],
    };
    let file = baseline(&c, &judge, &plan, "trade");
    let (paths, notes) = import::load_with(&file, &c, &judge, &[]).unwrap();
    let _ = std::fs::remove_file(&file);
    assert!(notes.iter().any(|n| n.contains("recognized KCC20 at input 1") && n.contains("partner")), "{notes:?}");
    let b = paths[0].baseline.as_ref().unwrap();
    let ids: Vec<&str> = b.variants.iter().map(|v| v.0).collect();
    assert!(ids.contains(&"FAM-10") && ids.contains(&"BOR-01"), "variants {ids:?}, notes {notes:?}");

    let report = run_paths_timed(&c, &[], vec![], paths, notes, std::time::Instant::now());
    let found: Vec<&str> = report.findings().map(|f| f.id.as_str()).collect();
    assert!(found.contains(&"FAM-10"), "sweep not caught: {found:?}");
    assert!(found.contains(&"BOR-01"), "borrowable custody not caught: {found:?}");
}

#[test]
fn token_owner_signature_inside_the_witness_is_seen() {
    let c = Contract::for_import("transfer", b"");
    let judge = Judge::new();
    let token_id = Hash::from_bytes([0x33; 32]);
    let owner = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &[0x42; 32]).unwrap();
    let xonly = owner.x_only_public_key().0.serialize();
    let mine = state(&xonly, 0, 500);
    let redeem = kcc20().redeem(&full(&mine)).unwrap();
    let mut w = vec![0u8];
    w.extend([0u8; 64]);
    w.push(0x01);
    let next = vec![ArtifactValue::Object(state(&[0x55; 32], 0, 500))];
    let script = kcc20()
        .sig_script("transfer", &[ArtifactValue::Array(next.clone()), ArtifactValue::Bytes(w)], &redeem)
        .unwrap();
    let rec = known::recognize(&script, known::builtin()).unwrap();
    let at = known::witness_signatures(&rec)[0].at;
    let out_redeem = kcc20().redeem(&full(&state(&[0x55; 32], 0, 500))).unwrap();
    let plan = SpendPlan {
        version: 1,
        inputs: vec![
            InputSpec::Raw(RawInput {
                outpoint: None,
                signature_script: script.clone(),
                sequence: 0,
                sig_op_count: 0,
                compute_budget: 20,
                entry: UtxoEntry::new(KAS, pay_to_script_hash_script(&redeem), 1000, false, Some(token_id)),
                target: true,
                signed: false,
                resign: Some(Resign { keypair: owner, at }),
                named: Vec::new(),
            }),
            InputSpec::P2pk { owner: KeyRef::Attacker, value: 2 * KAS },
        ],
        outputs: vec![
            OutputSpec {
                value: KAS,
                to: Dest::Raw(pay_to_script_hash_script(&out_redeem)),
                covenant: Some(CovenantBinding::new(0, token_id)),
                own: false,
            },
            OutputSpec::new(2 * KAS - 1_000_000, Dest::Key(KeyRef::Attacker)),
        ],
        lock_time: 0,
        payload: vec![],
        pov_daa: 10_000_000,
        block_time: 4_000_000_000_000,
        genesis: vec![],
    };
    let file = baseline(&c, &judge, &plan, "send");
    let raw_doc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    let sig_hex = raw_doc["transactions"][0]["tx"]["inputs"][0]["signatureScript"].as_str().unwrap().to_string();
    let mut sig = vec![0u8; sig_hex.len() / 2];
    faster_hex::hex_decode(sig_hex.as_bytes(), &mut sig).unwrap();
    assert!(import::carries_signature(&sig), "the witness signature is a signature");
    let (paths, _) = import::load_with(&file, &c, &judge, &[]).unwrap();
    let _ = std::fs::remove_file(&file);
    let map = redteam_covenant::spend_map(&c, &paths);
    let line = map[0]["summary"].as_str().unwrap();
    assert!(line.contains("owner of the KCC20 coin at input 0"), "{line}");
}
