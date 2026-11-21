//! Paths the search must reach: shapes that used to stay unexplored for reasons
//! unrelated to the contract's safety.

use redteam_covenant::sandbox::Judge;
use redteam_covenant::tune;
use std::collections::BTreeMap;

fn explored(name: &str, src: &str, args: &[(&str, &str)]) -> Vec<String> {
    let judge = Judge::new();
    let overrides: BTreeMap<String, String> = args.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let t = tune::tune(name, src, &overrides, &judge).unwrap();
    t.paths.iter().filter(|p| p.baseline.is_some()).map(|p| p.entry.clone()).collect()
}

/// A hash lock whose preimage must be exactly 32 bytes: the tool's secret has
/// to be 32 bytes too, or the path is never spent.
const FIXED_LEN_LOCK: &str = r#"pragma silverscript ^0.1.0;
contract SealedGift(int maxFee, byte[32] lockHash) {
    entry open(byte[] preimage) {
        require(preimage.length == 32);
        require(sha256(preimage) == lockHash);
        require(tx.outputs.length == 1);
        require(tx.outputs[0].value >= tx.inputs[this.activeInputIndex].value - maxFee);
    }
}
"#;

#[test]
fn a_fixed_length_preimage_is_found() {
    let got = explored("SealedGift.sil", FIXED_LEN_LOCK, &[("maxFee", "50000000")]);
    assert!(got.iter().any(|e| e == "open"), "explored: {got:?}");
}

/// A stateful covenant whose one-way switch is the last of several state
/// fields, next to constructor ints the entry never reads. The next state the
/// entry returns (`done: 1`) must be tried, however many guesses the other
/// fields produce.
const LATE_FIELD: &str = r#"pragma silverscript ^0.1.0;
contract Ledger(int maxFee, int capA, int capB, byte[32] lockHash, byte[32] init_root, byte[32] init_peer, int init_count, int init_done) {
    byte[32] root = init_root;
    byte[32] peer = init_peer;
    int count = init_count;
    int done = init_done;

    #[covenant.singleton(mode = transition)]
    function finish(State prev_state, byte[] preimage) : (State) {
        require(prev_state.done == 0);
        require(preimage.length == 32);
        require(sha256(preimage) == lockHash);
        int out_idx = OpAuthOutputIdx(this.activeInputIndex, 0);
        require(tx.outputs[out_idx].value >= tx.inputs[this.activeInputIndex].value - maxFee);
        return(State { root: prev_state.root, peer: prev_state.peer, count: prev_state.count, done: 1 });
    }

    #[covenant.singleton(mode = transition)]
    function bump(State prev_state) : (State) {
        require(prev_state.done == 0);
        require(prev_state.count < capA + capB);
        int out_idx = OpAuthOutputIdx(this.activeInputIndex, 0);
        require(tx.outputs[out_idx].value >= tx.inputs[this.activeInputIndex].value - maxFee);
        return(State { root: prev_state.root, peer: prev_state.peer, count: prev_state.count + 1, done: prev_state.done });
    }
}
"#;

#[test]
fn a_late_state_field_is_not_crowded_out() {
    let args = [
        ("maxFee", "50000000"),
        ("capA", "30000000"),
        ("capB", "10000000000"),
        ("init_count", "100000000"),
        ("init_done", "0"),
    ];
    let got = explored("Ledger.sil", LATE_FIELD, &args);
    assert!(got.iter().any(|e| e.contains("finish")), "explored: {got:?}");
}
