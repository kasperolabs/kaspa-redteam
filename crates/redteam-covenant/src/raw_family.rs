//! Family and borrow attacks on real transactions. A fetched or imported
//! transaction cannot be re-drafted from a source the way `family` does, but
//! when the token cells it spends are a known program (`known`), their
//! signature scripts and output scripts can be rebuilt exactly. That is enough
//! for the attacks that only touch the token side: a second coin the covenant
//! owns swept to the spender (FAM-10), tokens out with no KAS in (FAM-09), and
//! the covenant's coin with borrowing on (BOR-01/BOR-02).
//!
//! Every variant is judged before it is kept: it must be accepted (a finding)
//! or rejected only by the covenant under test. A variant the token program
//! itself rejects was built wrong, proves nothing, and is dropped with a note.

use crate::contract::Contract;
use crate::known::{self, Pin, Recognized};
use crate::sandbox::{Dest, InputSpec, Judge, OutputSpec, RawInput, Resign, SpendPlan, StateValues, Verdict};
use crate::wallets::KeyRef;
use kaspa_consensus_core::tx::{CovenantBinding, ScriptPublicKey, UtxoEntry};
use kaspa_hashes::Hash;
use kaspa_txscript::pay_to_script_hash_script;
use silverscript_abi::ArtifactValue;

pub type Variant = (&'static str, String, SpendPlan, String);

const MAX_TOKEN_INPUTS: usize = 3;
const MAX_TOKEN_OUTPUTS: usize = 3;
const STRAY_UNITS: i64 = 1_000_000;

struct Cell {
    input: usize,
    rec: Recognized,
}

fn is_kcc20(p: &Pin) -> bool {
    p.kcc20 && p.name == "KCC20"
}

fn raw(plan: &SpendPlan, i: usize) -> Option<&RawInput> {
    match plan.inputs.get(i)? {
        InputSpec::Raw(r) => Some(r),
        _ => None,
    }
}

fn next_states(rec: &Recognized) -> Option<Vec<StateValues>> {
    let call = rec.call.as_ref()?;
    if call.entry != "transfer" {
        return None;
    }
    match call.args.first()? {
        ArtifactValue::Array(items) => items
            .iter()
            .map(|v| match v {
                ArtifactValue::Object(o) => Some(o.clone()),
                _ => None,
            })
            .collect(),
        _ => None,
    }
}

/// An output state of the token: a `next_states` item plus the template field
/// the leader carries in its own state.
fn full_state(leader: &Recognized, next: &StateValues) -> StateValues {
    let mut st = next.clone();
    for (k, v) in &leader.state {
        if k.starts_with("gen__") {
            st.insert(k.clone(), v.clone());
        }
    }
    st
}

/// Who owns a KCC-20 cell, as the covenant under test sees it.
fn owned_by(st: &StateValues, cov_id: Option<Hash>, spk: &ScriptPublicKey) -> bool {
    let scheme = known::byte_of(st, "owner_scheme");
    let owner = known::bytes_of(st, "owner");
    match (scheme, owner) {
        (Some(4), Some(o)) => cov_id.is_some_and(|id| id.as_bytes().as_slice() == o),
        (Some(3), Some(o)) => {
            let s = spk.script();
            s.len() == 35 && s[0] == 0xaa && s[1] == 0x20 && s[34] == 0x87 && &s[2..34] == o
        }
        _ => false,
    }
}

fn same_owner(a: &StateValues, b: &StateValues) -> bool {
    a.get("owner") == b.get("owner") && a.get("owner_scheme") == b.get("owner_scheme")
}

/// Rewrites the token side of `plan`: the leader's `next_states`, the states of
/// any cells listed in `states`, and the scripts of the leader's outputs.
fn rebuild(plan: &mut SpendPlan, leader: &Cell, nexts: &[StateValues], states: &[(usize, StateValues)]) -> Option<()> {
    let pin = &leader.rec.pin;
    // Cells whose own state changes: new redeem, new address.
    for (i, st) in states {
        let InputSpec::Raw(r) = plan.inputs.get_mut(*i)? else { return None };
        let rec = known::recognize(&r.signature_script, std::slice::from_ref(pin))?;
        let call = rec.call.clone()?;
        let redeem = pin.redeem(st)?;
        r.signature_script = pin.sig_script(&call.entry, &call.args, &redeem)?;
        r.entry = UtxoEntry::new(
            r.entry.amount,
            pay_to_script_hash_script(&redeem),
            r.entry.block_daa_score,
            false,
            r.entry.covenant_id,
        );
    }
    // The leader with its new next states.
    {
        let InputSpec::Raw(r) = plan.inputs.get_mut(leader.input)? else { return None };
        let rec = known::recognize(&r.signature_script, std::slice::from_ref(pin))?;
        let mut call = rec.call.clone()?;
        let grew = matches!(call.args.first(), Some(ArtifactValue::Array(a)) if a.len() < nexts.len());
        call.args[0] = ArtifactValue::Array(nexts.iter().map(|s| ArtifactValue::Object(s.clone())).collect());
        r.signature_script = pin.sig_script(&call.entry, &call.args, &rec.redeem)?;
        if grew {
            r.compute_budget = r.compute_budget.saturating_mul(4);
        }
    }
    // Signatures the tool remakes sit where the witness now is.
    for i in 0..plan.inputs.len() {
        if let InputSpec::Raw(r) = &mut plan.inputs[i] {
            if let Some(rs) = &r.resign {
                let kp = rs.keypair;
                let at = known::recognize(&r.signature_script, std::slice::from_ref(pin))
                    .and_then(|rec| known::witness_signatures(&rec).first().map(|w| w.at));
                if let Some(at) = at {
                    r.resign = Some(Resign { keypair: kp, at });
                }
            }
        }
    }
    // The leader's outputs, in order, carry the new states.
    let outs: Vec<usize> = plan
        .outputs
        .iter()
        .enumerate()
        .filter(|(_, o)| o.covenant.is_some_and(|c| c.authorizing_input as usize == leader.input))
        .map(|(k, _)| k)
        .collect();
    if outs.len() != nexts.len() {
        return None;
    }
    for (k, n) in outs.iter().zip(nexts) {
        let redeem = pin.redeem(&full_state(&leader.rec, n))?;
        plan.outputs[*k].to = Dest::Raw(pay_to_script_hash_script(&redeem));
    }
    Some(())
}

/// Every input whose script fails on its own, with the reason.
fn failing(judge: &Judge, contract: &Contract, plan: &SpendPlan) -> Result<(), String> {
    match judge.run(contract, plan) {
        (Verdict::Accepted { .. }, _) => Ok(()),
        (Verdict::Rejected(why), None) => Err(why),
        (Verdict::Rejected(why), Some(b)) => {
            let f = crate::sandbox::failing_inputs(&b);
            let mine: Vec<_> = f.iter().filter(|(i, _)| !raw(plan, *i).is_some_and(|r| r.target)).collect();
            if f.is_empty() {
                Err(why)
            } else if mine.is_empty() {
                Ok(())
            } else {
                Err(mine.iter().map(|(i, e)| format!("input {i}: {e}")).collect::<Vec<_>>().join("; "))
            }
        }
    }
}

/// Hostile versions of an imported transaction that spends KCC-20 reference
/// cells next to the covenant under test, plus notes for the report.
pub fn variants(
    label: &str,
    plan: &SpendPlan,
    contract: &Contract,
    judge: &Judge,
    pins: &[Pin],
) -> (Vec<Variant>, Vec<String>) {
    let mut notes = Vec::new();
    let mut out: Vec<Variant> = Vec::new();
    let cells: Vec<Cell> = plan
        .inputs
        .iter()
        .enumerate()
        .filter_map(|(i, inp)| match inp {
            InputSpec::Raw(r) => known::recognize(&r.signature_script, pins)
                .filter(|rec| is_kcc20(&rec.pin))
                .map(|rec| Cell { input: i, rec }),
            _ => None,
        })
        .collect();
    if cells.is_empty() {
        return (out, notes);
    }
    let targets: Vec<usize> = (0..plan.inputs.len()).filter(|i| raw(plan, *i).is_some_and(|r| r.target)).collect();
    if targets.iter().all(|t| cells.iter().any(|c| c.input == *t)) {
        return (out, notes);
    }
    let skip = |why: String| format!("`{label}`: family and borrow attacks on its KCC-20 cells not built: {why}");
    if let Some(i) = (0..plan.inputs.len()).find(|i| raw(plan, *i).is_some_and(|r| r.signed)) {
        notes.push(skip(format!(
            "input {i} carries a signature the tool cannot remake, so every change breaks it (list the throwaway key in the baseline's `keys` to attack from that signer's seat)"
        )));
        return (out, notes);
    }
    let Some(leader) = cells.iter().find(|c| c.rec.call.as_ref().is_some_and(|k| k.entry == "transfer")) else {
        notes.push(skip("no KCC-20 input leads a transfer".into()));
        return (out, notes);
    };
    let Some(nexts) = next_states(&leader.rec) else {
        notes.push(skip("the leader's next states do not read back".into()));
        return (out, notes);
    };
    let token_id = raw(plan, leader.input).and_then(|r| r.entry.covenant_id);
    let attacker = contract.wallets.attacker.xonly().to_vec();

    for &t in targets.iter().filter(|t| !cells.iter().any(|c| c.input == **t)) {
        let Some(tr) = raw(plan, t) else { continue };
        let held: Vec<&Cell> = cells
            .iter()
            .filter(|c| owned_by(&c.rec.state, tr.entry.covenant_id, &tr.entry.script_public_key))
            .collect();
        if held.is_empty() {
            continue;
        }
        let names = held.iter().map(|c| c.input.to_string()).collect::<Vec<_>>().join(", ");
        notes.push(format!("`{label}`: the KCC-20 cell at input {names} is owned by the covenant at input {t}"));
        let keep = |id: &'static str,
                    what: String,
                    p: SpendPlan,
                    why: String,
                    out: &mut Vec<Variant>,
                    notes: &mut Vec<String>| {
            match failing(judge, contract, &p) {
                Ok(()) => out.push((id, what, p, why)),
                Err(e) => notes
                    .push(format!("`{label}`: {id} variant dropped, the token side rejected it ({e}); not a result")),
            }
        };

        // FAM-10: a second coin the covenant owns, spent as a delegate, its tokens to the spender.
        if let Some(h) = held.iter().find(|c| c.input == leader.input) {
            if cells.len() >= MAX_TOKEN_INPUTS || nexts.len() >= MAX_TOKEN_OUTPUTS {
                notes.push(format!("`{label}`: FAM-10 not built, the transfer already uses the reference's maximum of token inputs or outputs"));
            } else if let (Some(id), Some(scheme)) = (token_id, known::byte_of(&h.rec.state, "owner_scheme")) {
                let mut p = plan.clone();
                let mut stray = h.rec.state.clone();
                stray.insert("amount".into(), ArtifactValue::Int(STRAY_UNITS));
                let witness = if scheme == 3 { vec![t as u8] } else { vec![] };
                let pin = &h.rec.pin;
                let built = pin.redeem(&stray).and_then(|redeem| {
                    pin.sig_script("transfer_delegator", &[ArtifactValue::Bytes(witness)], &redeem).map(|s| (redeem, s))
                });
                let leader_raw = raw(plan, leader.input).cloned();
                if let (Some((redeem, script)), Some(lr)) = (built, leader_raw) {
                    let value = lr.entry.amount;
                    p.inputs.push(InputSpec::Raw(RawInput {
                        outpoint: None,
                        signature_script: script,
                        sequence: 0,
                        sig_op_count: 0,
                        compute_budget: lr.compute_budget,
                        entry: UtxoEntry::new(
                            value,
                            pay_to_script_hash_script(&redeem),
                            lr.entry.block_daa_score,
                            false,
                            Some(id),
                        ),
                        target: false,
                        signed: false,
                        resign: None,
                    }));
                    let mut mine = nexts[0].clone();
                    mine.insert("amount".into(), ArtifactValue::Int(STRAY_UNITS));
                    mine.insert("owner".into(), ArtifactValue::Bytes(attacker.clone()));
                    mine.insert("owner_scheme".into(), ArtifactValue::Byte(0));
                    mine.insert("borrow_scheme".into(), ArtifactValue::Byte(0));
                    mine.insert("borrow_guard".into(), ArtifactValue::Bytes(vec![0; 32]));
                    if let Some(e) = h.rec.state.get("extension_commitment") {
                        mine.insert("extension_commitment".into(), e.clone());
                    }
                    p.outputs.push(OutputSpec {
                        value,
                        to: Dest::Key(KeyRef::Attacker),
                        covenant: Some(CovenantBinding::new(leader.input as u16, id)),
                        own: false,
                    });
                    let mut n2 = nexts.clone();
                    n2.push(mine);
                    if rebuild(&mut p, leader, &n2, &[]).is_some() {
                        keep(
                            "FAM-10",
                            format!("a second KCC-20 cell owned by input {t}, swept to the spender"),
                            p,
                            format!(
                                "a second KCC-20 cell owned by the covenant at input {t} (tokens someone sent to it, or a second deposit) was spent in the same real transaction as a delegate of its cell at input {}, and its {STRAY_UNITS} units went to the spender in a cell of their own. The transaction was accepted: the covenant checked only the cell it was pointed at. Tokens sent to it can be taken by anyone.",
                                leader.input
                            ),
                            &mut out,
                            &mut notes,
                        );
                    }
                }
            }

            // FAM-09: the covenant's tokens leave, its KAS stays the same.
            let before = known::int_of(&h.rec.state, "amount").unwrap_or(0);
            let after: i64 =
                nexts.iter().filter(|n| same_owner(n, &h.rec.state)).filter_map(|n| known::int_of(n, "amount")).sum();
            let cont = plan.outputs.iter().position(|o| {
                o.covenant
                    .is_some_and(|c| c.authorizing_input as usize == t && Some(c.covenant_id) == tr.entry.covenant_id)
            });
            if after < before {
                if let Some(k) = cont.filter(|k| plan.outputs[*k].value > tr.entry.amount) {
                    let mut p = plan.clone();
                    let paid = p.outputs[k].value - tr.entry.amount;
                    p.outputs[k].value = tr.entry.amount;
                    p.outputs.push(OutputSpec::new(paid, Dest::Key(KeyRef::Attacker)));
                    keep(
                        "FAM-09",
                        format!("{} units out of input {t}'s cell, its KAS unchanged", before - after),
                        p,
                        format!(
                            "the real transaction took {} token units out of the cell the covenant at input {t} owns; the same transaction with the covenant's continuation keeping the KAS it had (the {} the buyer paid went back to the spender) was accepted. Whatever the covenant sells, it gives away.",
                            before - after,
                            crate::kas(paid)
                        ),
                        &mut out,
                        &mut notes,
                    );
                }
            }
        }

        // BOR-01/02: the covenant's coin with borrowing on.
        for h in &held {
            let borrow = known::byte_of(&h.rec.state, "borrow_scheme").unwrap_or(0);
            if borrow != 0 {
                out.push((
                    "BOR-02",
                    format!("input {}'s cell already has borrowing on", h.input),
                    plan.clone(),
                    format!(
                        "in the real transaction the KCC-20 cell at input {} that the covenant owns has borrow scheme {borrow}: anyone can add to it with a borrowed receive, without the covenant, and change its outpoint. Whether the covenant still works after such a borrow is not tested on real transactions.",
                        h.input
                    ),
                ));
                continue;
            }
            let mut p = plan.clone();
            let mut st = h.rec.state.clone();
            st.insert("borrow_scheme".into(), ArtifactValue::Byte(1));
            st.insert("borrow_guard".into(), ArtifactValue::Bytes(vec![0; 32]));
            let n2: Vec<StateValues> = nexts
                .iter()
                .map(|n| {
                    let mut n = n.clone();
                    if same_owner(&n, &h.rec.state) {
                        n.insert("borrow_scheme".into(), ArtifactValue::Byte(1));
                        n.insert("borrow_guard".into(), ArtifactValue::Bytes(vec![0; 32]));
                    }
                    n
                })
                .collect();
            if rebuild(&mut p, leader, &n2, &[(h.input, st)]).is_some() {
                keep(
                    "BOR-01",
                    format!("input {}'s cell with borrowing on", h.input),
                    p,
                    format!(
                        "the same real transaction, with the cell the covenant owns at input {} (and the one it gets back) open to borrowing, was accepted: the covenant takes custody of a coin anyone can add one token unit to, without the covenant in that transaction. If the covenant expects an exact amount in it, one unit from a stranger bricks it.",
                        h.input
                    ),
                    &mut out,
                    &mut notes,
                );
            }
        }
    }
    (out, notes)
}

fn p2pk_key(spk: &ScriptPublicKey) -> Option<[u8; 32]> {
    let s = spk.script();
    (spk.version() == 0 && s.len() == 34 && s[0] == 0x20 && s[33] == 0xac).then(|| s[1..33].try_into().unwrap())
}

/// The user's seat, taken by the tool's attacker key. A real transaction is
/// signed by whoever traded (a buyer's coin, a seller's token cell), so as
/// fetched it can only be tested for changes that break those signatures. When
/// the covenant under test itself is unsigned, the same trade by another user
/// is just as valid: every coin and token cell of that user's key becomes the
/// attacker's (new owner in the cell's state, signature made again), and so do
/// the outputs and new token cells that paid that key. The covenant's own
/// coins and state are never touched. Returns the plan and the keys replaced.
pub fn reown(plan: &SpendPlan, contract: &Contract, pins: &[Pin]) -> Option<(SpendPlan, Vec<String>)> {
    let targets: Vec<usize> = (0..plan.inputs.len()).filter(|i| raw(plan, *i).is_some_and(|r| r.target)).collect();
    if targets.is_empty() || targets.iter().any(|t| raw(plan, *t).is_some_and(|r| r.signed)) {
        return None;
    }
    let attacker = &contract.wallets.attacker;
    let me: [u8; 32] = attacker.xonly();
    // Keys whose signatures the transaction carries outside the covenant.
    let mut users: Vec<[u8; 32]> = Vec::new();
    for (i, inp) in plan.inputs.iter().enumerate() {
        let InputSpec::Raw(r) = inp else { continue };
        if !r.signed || r.target {
            continue;
        }
        if let Some(k) = p2pk_key(&r.entry.script_public_key) {
            users.push(k);
            continue;
        }
        let rec = known::recognize(&r.signature_script, pins).filter(|x| is_kcc20(&x.pin))?;
        if known::byte_of(&rec.state, "owner_scheme") != Some(0) || known::witness_signatures(&rec).is_empty() {
            return None;
        }
        let o: [u8; 32] = known::bytes_of(&rec.state, "owner")?.try_into().ok()?;
        users.push(o);
        let _ = i;
    }
    if users.is_empty() {
        return None;
    }
    users.sort();
    users.dedup();
    let is_user = |b: &[u8]| users.iter().any(|u| u.as_slice() == b);
    let mut p = plan.clone();
    let mut leader: Option<Cell> = None;
    for i in 0..p.inputs.len() {
        let InputSpec::Raw(r) = &p.inputs[i] else { continue };
        if r.target {
            continue;
        }
        if p2pk_key(&r.entry.script_public_key).is_some_and(|k| is_user(&k)) {
            let value = r.entry.amount;
            p.inputs[i] = InputSpec::P2pk { owner: KeyRef::Attacker, value };
            continue;
        }
        let Some(rec) = known::recognize(&r.signature_script, pins).filter(|x| is_kcc20(&x.pin)) else { continue };
        if rec.call.as_ref().is_some_and(|c| c.entry == "transfer") {
            leader = Some(Cell { input: i, rec: rec.clone() });
        }
        let owned = known::byte_of(&rec.state, "owner_scheme") == Some(0)
            && known::bytes_of(&rec.state, "owner").is_some_and(is_user);
        if !owned {
            continue;
        }
        let mut st = rec.state.clone();
        st.insert("owner".into(), ArtifactValue::Bytes(me.to_vec()));
        let redeem = rec.pin.redeem(&st)?;
        let call = rec.call.clone()?;
        let script = rec.pin.sig_script(&call.entry, &call.args, &redeem)?;
        let at = known::recognize(&script, pins).and_then(|x| known::witness_signatures(&x).first().map(|w| w.at))?;
        let InputSpec::Raw(r) = &mut p.inputs[i] else { continue };
        r.signature_script = script;
        r.entry = UtxoEntry::new(
            r.entry.amount,
            pay_to_script_hash_script(&redeem),
            r.entry.block_daa_score,
            false,
            r.entry.covenant_id,
        );
        r.signed = false;
        r.resign = Some(Resign { keypair: attacker.keypair, at });
        if leader.as_ref().is_some_and(|l| l.input == i) {
            leader = known::recognize(&r.signature_script, pins).map(|rec| Cell { input: i, rec });
        }
    }
    // Plain outputs to a user's address, and new token cells of a user.
    for o in p.outputs.iter_mut() {
        if let Dest::Raw(spk) = &o.to {
            if p2pk_key(spk).is_some_and(|k| is_user(&k)) {
                o.to = Dest::Key(KeyRef::Attacker);
            }
        }
    }
    if let Some(l) = leader {
        let nexts = next_states(&l.rec)?;
        let n2: Vec<StateValues> = nexts
            .iter()
            .map(|n| {
                let mut n = n.clone();
                if known::byte_of(&n, "owner_scheme") == Some(0) && known::bytes_of(&n, "owner").is_some_and(is_user) {
                    n.insert("owner".into(), ArtifactValue::Bytes(me.to_vec()));
                }
                n
            })
            .collect();
        if n2 != nexts {
            rebuild(&mut p, &l, &n2, &[])?;
            // The user's new token cells are now the attacker's own: shortening
            // them takes nothing from anyone.
            let outs: Vec<usize> = p
                .outputs
                .iter()
                .enumerate()
                .filter(|(_, o)| o.covenant.is_some_and(|c| c.authorizing_input as usize == l.input))
                .map(|(k, _)| k)
                .collect();
            for (k, n) in outs.iter().zip(&n2) {
                if known::bytes_of(n, "owner") == Some(me.as_slice()) {
                    p.outputs[*k].own = true;
                }
            }
        }
    }
    let names = users.iter().map(|u| faster_hex::hex_string(&u[..6]) + "…").collect();
    Some((p, names))
}
