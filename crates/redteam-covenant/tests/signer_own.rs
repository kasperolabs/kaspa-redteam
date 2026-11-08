//! Real transactions from a user's seat (0.17.2): what the signer pays from its
//! own coins, and new token cells it owns, are not covenant value; a leftover
//! the covenant names as a tip is a note. Everything else stays a finding.

use kaspa_consensus_core::tx::{CovenantBinding, UtxoEntry};
use kaspa_hashes::Hash;
use kaspa_txscript::pay_to_script_hash_script;
use redteam_covenant::contract::Contract;
use redteam_covenant::known::{self, Pin};
use redteam_covenant::sandbox::{
    Dest, InputSpec, Judge, OutputSpec, RawInput, Resign, SpendPlan, StateValues, Verdict, push_data,
};
use redteam_covenant::wallets::KeyRef;
use redteam_covenant::{baseline, import, run_paths_timed};
use silverscript_abi::ArtifactValue;
use std::collections::BTreeMap;
use std::path::PathBuf;

const KAS: u64 = 100_000_000;

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

fn raw(script: Vec<u8>, entry: UtxoEntry, budget: u16, target: bool, resign: Option<Resign>) -> InputSpec {
    InputSpec::Raw(RawInput {
        outpoint: None,
        signature_script: script,
        sequence: 0,
        sig_op_count: 0,
        compute_budget: budget,
        entry,
        target,
        signed: false,
        resign,
        named: Vec::new(),
    })
}

/// `plan` as a baseline file (checked first), with `keys` listed.
fn write(c: &Contract, judge: &Judge, plan: &SpendPlan, name: &str, keys: &[&secp256k1::Keypair]) -> PathBuf {
    let (v, built) = judge.run(c, plan);
    assert!(matches!(v, Verdict::Accepted { .. }), "honest {name}: {v:?}");
    let b = built.unwrap();
    let keys: Vec<String> = keys.iter().map(|k| faster_hex::hex_string(&k.secret_bytes())).collect();
    let doc = serde_json::json!({
        "format": import::FORMAT,
        "keys": keys,
        "transactions": [{ "path": name, "tx": serde_json::to_value(&b.tx).unwrap(), "utxos": serde_json::to_value(&b.entries).unwrap() }],
    });
    let out = std::env::temp_dir().join(format!("redteam-own-{name}-{}.json", std::process::id()));
    std::fs::write(&out, serde_json::to_string(&doc).unwrap()).unwrap();
    out
}

fn p2pk(k: &secp256k1::Keypair) -> kaspa_consensus_core::tx::ScriptPublicKey {
    let mut s = vec![0x20];
    s.extend(k.x_only_public_key().0.serialize());
    s.push(0xac);
    kaspa_consensus_core::tx::ScriptPublicKey::new(0, s.into())
}

/// A listed key sends tokens from its own cell: one new cell to a friend, one
/// back to itself, change to itself. Every coin is the signer's, so cutting or
/// redirecting any output is not a finding, and its own new cell is marked own.
#[test]
fn a_send_from_the_signers_own_cell_is_not_a_finding() {
    let c = Contract::for_import("send", b"");
    let judge = Judge::new();
    let token_id = Hash::from_bytes([0x33; 32]);
    let me = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &[0x42; 32]).unwrap();
    let x = me.x_only_public_key().0.serialize();
    let redeem = kcc20().redeem(&full(&state(&x, 0, 500))).unwrap();
    let to_friend = state(&[0x55; 32], 0, 300);
    let to_me = state(&x, 0, 200);
    let mut w = vec![0u8];
    w.extend([0u8; 64]);
    w.push(0x01);
    let next = vec![ArtifactValue::Object(to_friend.clone()), ArtifactValue::Object(to_me.clone())];
    let script =
        kcc20().sig_script("transfer", &[ArtifactValue::Array(next), ArtifactValue::Bytes(w)], &redeem).unwrap();
    let rec = known::recognize(&script, known::builtin()).unwrap();
    let at = known::witness_signatures(&rec)[0].at;
    let funding = UtxoEntry::new(5 * KAS, p2pk(&me), 1000, false, None);
    let plan = SpendPlan {
        version: 1,
        inputs: vec![
            raw(
                script,
                UtxoEntry::new(KAS, pay_to_script_hash_script(&redeem), 1000, false, Some(token_id)),
                20,
                true,
                Some(Resign { keypair: me, at }),
            ),
            raw(vec![], funding, 10, false, None),
        ],
        outputs: vec![
            OutputSpec {
                value: KAS,
                to: Dest::Raw(pay_to_script_hash_script(&kcc20().redeem(&full(&to_friend)).unwrap())),
                covenant: Some(CovenantBinding::new(0, token_id)),
                own: false,
            },
            OutputSpec {
                value: KAS,
                to: Dest::Raw(pay_to_script_hash_script(&kcc20().redeem(&full(&to_me)).unwrap())),
                covenant: Some(CovenantBinding::new(0, token_id)),
                own: false,
            },
            OutputSpec { value: 4 * KAS - 1_000_000, to: Dest::Raw(p2pk(&me)), covenant: None, own: false },
        ],
        lock_time: 0,
        payload: vec![],
        pov_daa: 10_000_000,
        block_time: 4_000_000_000_000,
        genesis: vec![],
    };
    // The funding coin is signed by the tool as the listed key: give it a signature recipe.
    let mut plan = plan;
    if let InputSpec::Raw(r) = &mut plan.inputs[1] {
        let mut s = vec![65u8];
        s.extend([0u8; 65]);
        r.signature_script = s;
        r.resign = Some(Resign { keypair: me, at: 1 });
    }
    let file = write(&c, &judge, &plan, "send", &[&me]);
    let (paths, notes) = import::load_with(&file, &c, &judge, &[]).unwrap();
    let _ = std::fs::remove_file(&file);
    assert!(
        notes.iter().any(|n| n.contains("new token cells owned by a listed key") && n.contains("output 1")),
        "{notes:?}"
    );
    let b = paths[0].baseline.as_ref().unwrap();
    assert!(
        b.plan.outputs[1].own && !b.plan.outputs[0].own,
        "own flags {:?}",
        b.plan.outputs.iter().map(|o| o.own).collect::<Vec<_>>()
    );
    let report = run_paths_timed(&c, &[], vec![], paths, notes, std::time::Instant::now());
    let found: Vec<String> = report.findings().map(|f| f.id.clone()).collect();
    assert!(found.is_empty(), "findings {found:?}; notes {:?}", report.notes);
    assert!(report.notes.iter().any(|n| n.contains("paid from the signer's own coins")), "{:?}", report.notes);
}

/// Someone else's coin (a program that names a payee and checks nothing) next
/// to the signer's funding: a payment to an address that coin does not name is
/// the signer's own (a note), a payment to the address it names stays a finding.
#[test]
fn a_payment_the_other_coin_names_stays_protected() {
    let c = Contract::for_import("pay", b"");
    let judge = Judge::new();
    let payee = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &[0x61; 32]).unwrap();
    let shop = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &[0x62; 32]).unwrap();
    // Redeem: <payee key> OP_DROP OP_TRUE. Anyone can spend it; it names the payee.
    let mut redeem = push_data(&payee.x_only_public_key().0.serialize()).unwrap();
    redeem.extend([0x75, 0x51]);
    let cov = raw(
        push_data(&redeem).unwrap(),
        UtxoEntry::new(KAS, pay_to_script_hash_script(&redeem), 1000, false, Some(Hash::from_bytes([0x44; 32]))),
        1,
        true,
        None,
    );
    let plan = SpendPlan::simple(
        vec![cov, InputSpec::P2pk { owner: KeyRef::Attacker, value: 10 * KAS }],
        vec![
            OutputSpec::new(KAS / 2, Dest::Key(KeyRef::Attacker)),
            OutputSpec::new(2 * KAS, Dest::Raw(p2pk(&shop))),
            OutputSpec::new(3 * KAS, Dest::Raw(p2pk(&payee))),
            OutputSpec::new(5 * KAS + KAS / 2 - 1_000_000, Dest::Key(KeyRef::Attacker)),
        ],
        0,
        10_000_000,
        4_000_000_000_000,
    );
    let file = write(&c, &judge, &plan, "pay", &[]);
    let (paths, notes) = import::load_with(&file, &c, &judge, &[]).unwrap();
    let _ = std::fs::remove_file(&file);
    let report = run_paths_timed(&c, &["OUT-03".into()], vec![], paths, notes, std::time::Instant::now());
    let found: Vec<String> = report.findings().map(|f| f.explanation.clone()).collect();
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("output 2"), "{found:?}");
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("OUT-03") && n.contains("output 1") && n.contains("paid from the signer's own coins")),
        "{:?}",
        report.notes
    );
}

/// A refund that leaves `keeperTip` for the keeper: the leftover is a note
/// naming the field. A refund that leaves more than the tip stays a finding.
#[test]
fn a_leftover_within_a_named_tip_is_a_note() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/baseline");
    let tip = 3_000_000u64;
    for (file, leave, expect_note) in [("tip_refund.sil", tip, true), ("tip_refund_loose.sil", 5 * tip, false)] {
        let src = std::fs::read_to_string(dir.join(file)).unwrap();
        let mut args = BTreeMap::new();
        args.insert("init_keeperTip".to_string(), tip.to_string());
        let c = Contract::load(file, &src, &args).unwrap();
        let judge = Judge::new();
        let paths = baseline::search_all(&c, &judge);
        let mut doc = import::export(&c, &judge, &paths).unwrap();
        let tx = &mut doc["transactions"][0];
        let input = tx["utxos"][0]["amount"].as_u64().unwrap();
        tx["tx"]["outputs"][0]["value"] = (input - leave).into();
        let f = std::env::temp_dir().join(format!("redteam-tip-{file}-{}.json", std::process::id()));
        std::fs::write(&f, serde_json::to_string(&doc).unwrap()).unwrap();
        let pin = known::from_contract(&c).unwrap();
        let (imported, notes) = import::load_with(&f, &c, &judge, &[pin]).unwrap();
        let _ = std::fs::remove_file(&f);
        let r = run_paths_timed(&c, &["OUT-04".into()], vec![], imported, notes, std::time::Instant::now());
        let out04 = r.findings().filter(|x| x.id == "OUT-04").count();
        let noted = r.notes.iter().any(|n| n.contains("OUT-04") && n.contains("within `keeperTip`"));
        assert_eq!((out04 == 0, noted), (expect_note, expect_note), "{file}: findings {out04}, notes {:?}", r.notes);
    }
}
