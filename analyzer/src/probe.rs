//! Mutating real spends. A case is one observed transaction that spent the program. Its plain-key inputs (the
//! person who made the transaction: a buyer, a seller, a holder paying the fee) are handed to the analyzer's own
//! outsider key, and outputs that paid them now pay the outsider; that is the "outsider base". Mutations change one
//! thing at a time on the base, the outsider signs again, and the judge decides.

use crate::script::{self, hex};
use kaspa_consensus_core::hashing::sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash};
use kaspa_consensus_core::hashing::sighash_type::{SIG_HASH_ALL, SigHashType};
use kaspa_consensus_core::tx::{
    PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_hashes::Hash;
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

fn sha(s: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(s);
    h.finalize().into()
}

/// The outsider: a fixed key, so every run produces the same transactions.
pub struct Outsider {
    pub kp: Keypair,
    pub xonly: [u8; 32],
    pub spk: ScriptPublicKey,
}

impl Outsider {
    pub fn new() -> Self {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&sha(b"kcc20-analyzer/outsider/1")).expect("valid key");
        let kp = Keypair::from_secret_key(&secp, &sk);
        let xonly = kp.x_only_public_key().0.serialize();
        let mut s = vec![0x20];
        s.extend_from_slice(&xonly);
        s.push(0xac);
        Outsider { kp, xonly, spk: ScriptPublicKey::new(0, s.into()) }
    }
    pub fn coin(&self, n: u32) -> TransactionOutpoint {
        TransactionOutpoint::new(Hash::from_bytes(sha(format!("kcc20-analyzer/coin/{n}").as_bytes())), 0)
    }
}

/// Where a signature goes after the transaction is final.
#[derive(Clone, Debug)]
pub struct SignSpot {
    pub input: usize,
    /// None: the whole signature script is the outsider's P2PK signature. Some(k): push k of the script.
    pub push: Option<usize>,
    pub hash_type: u8,
}

#[derive(Clone)]
pub struct Draft {
    pub tx: Transaction,
    pub entries: Vec<UtxoEntry>,
    pub sign: Vec<SignSpot>,
    next_coin: u32,
}

impl Draft {
    pub fn from(tx: &Transaction, entries: &[UtxoEntry]) -> Self {
        Draft { tx: tx.clone(), entries: entries.to_vec(), sign: vec![], next_coin: 100 }
    }

    /// An outsider coin as a new input, signed with SIGHASH_ALL.
    pub fn add_outsider_input(&mut self, o: &Outsider, value: u64) -> usize {
        let op = o.coin(self.next_coin);
        self.next_coin += 1;
        let like = self.tx.inputs.iter().find(|i| i.signature_script.len() == 66).map(|i| i.compute_commit);
        let commit = like.unwrap_or_else(|| {
            if self.tx.version >= 1 {
                kaspa_consensus_core::tx::ComputeCommit::ComputeBudget(10u16.into())
            } else {
                kaspa_consensus_core::tx::ComputeCommit::SigopCount(1u8.into())
            }
        });
        self.tx.inputs.push(TransactionInput::new_with_mass(op, vec![], 0, commit));
        self.entries.push(UtxoEntry::new(value, o.spk.clone(), 0, false, None));
        let i = self.tx.inputs.len() - 1;
        self.sign.push(SignSpot { input: i, push: None, hash_type: SIG_HASH_ALL.to_u8() });
        i
    }

    /// Pays `value` more to the outsider: into an existing outsider output, or a new one.
    pub fn pay_outsider(&mut self, o: &Outsider, value: u64) {
        if value == 0 {
            return;
        }
        if let Some(out) = self.tx.outputs.iter_mut().find(|x| x.covenant.is_none() && x.script_public_key == o.spk) {
            out.value += value;
        } else {
            self.tx.outputs.push(TransactionOutput::new(value, o.spk.clone()));
        }
    }

    pub fn set_push(&mut self, input: usize, k: usize, data: &[u8]) -> bool {
        let Some(mut items) = script::pushes(&self.tx.inputs[input].signature_script) else { return false };
        if k >= items.len() {
            return false;
        }
        items[k] = data.to_vec();
        self.tx.inputs[input].signature_script = script::push_all(&items);
        true
    }

    /// Signs every spot (P2PK inputs of the outsider and outsider signatures inside witnesses) and finalizes the id.
    pub fn finish(mut self, o: &Outsider) -> (Transaction, Vec<UtxoEntry>) {
        fix_genesis(&mut self.tx, &self.entries);
        self.tx.finalize();
        if !self.sign.is_empty() {
            let secp = Secp256k1::new();
            let mut sigs = Vec::new();
            {
                let populated = PopulatedTransaction::new(&self.tx, self.entries.clone());
                let reused = SigHashReusedValuesUnsync::new();
                for s in &self.sign {
                    let ht = SigHashType::from_u8(s.hash_type).unwrap_or(SIG_HASH_ALL);
                    let h = calc_schnorr_signature_hash(&populated, s.input, ht, &reused);
                    let msg = Message::from_digest_slice(&h.as_bytes()).expect("32 bytes");
                    let sig = secp.sign_schnorr_no_aux_rand(&msg, &o.kp);
                    let mut b = sig.as_ref().to_vec();
                    b.push(s.hash_type);
                    sigs.push(b);
                }
            }
            for (s, b) in self.sign.clone().iter().zip(sigs) {
                match s.push {
                    None => self.tx.inputs[s.input].signature_script = script::push(&b),
                    Some(k) => {
                        self.set_push(s.input, k, &b);
                    }
                }
            }
            self.tx.finalize();
        }
        (self.tx, self.entries)
    }
}

/// One observed spend of the program, ready to mutate.
#[derive(Clone)]
pub struct Case {
    pub txid: String,
    pub tx: Transaction,
    pub entries: Vec<UtxoEntry>,
    /// Inputs that spend the program under analysis.
    pub targets: Vec<usize>,
    /// Plain-key inputs: the person who made the transaction.
    pub actor_inputs: Vec<usize>,
}

pub fn spk_bytes(s: &ScriptPublicKey) -> Vec<u8> {
    s.script().to_vec()
}

impl Case {
    /// The outsider base: the actor's coins swapped for the outsider's, outputs that paid the actor now pay the
    /// outsider, everything signed again. Covenant inputs and their witnesses are untouched.
    pub fn outsider_base(&self, o: &Outsider) -> Draft {
        let mut d = Draft::from(&self.tx, &self.entries);
        let actor_spks: Vec<Vec<u8>> = self.actor_inputs.iter().map(|&i| spk_bytes(&self.entries[i].script_public_key)).collect();
        for &i in &self.actor_inputs {
            let op = o.coin(i as u32);
            d.tx.inputs[i].previous_outpoint = op;
            d.tx.inputs[i].signature_script = vec![];
            d.entries[i] = UtxoEntry::new(self.entries[i].amount, o.spk.clone(), 0, false, None);
            d.sign.push(SignSpot { input: i, push: None, hash_type: SIG_HASH_ALL.to_u8() });
        }
        for out in d.tx.outputs.iter_mut() {
            if out.covenant.is_none() && actor_spks.contains(&spk_bytes(&out.script_public_key)) {
                out.script_public_key = o.spk.clone();
            }
        }
        d
    }
}

/// KAS the outsider ends with minus KAS it brought.
pub fn outsider_gain(tx: &Transaction, entries: &[UtxoEntry], o: &Outsider) -> i128 {
    let out: i128 = tx.outputs.iter().filter(|x| x.covenant.is_none() && x.script_public_key == o.spk).map(|x| x.value as i128).sum();
    let inp: i128 = entries.iter().filter(|e| e.script_public_key == o.spk).map(|e| e.amount as i128).sum();
    out - inp
}


/// What a mutation changed, for the report and for judging whose value moved.
#[derive(Clone, Debug)]
pub struct Change {
    pub class: &'static str,
    pub text: String,
    /// The output whose KAS went to the outsider, and how much.
    pub from_output: Option<usize>,
    #[allow(dead_code)]
    pub moved: u64,
}

pub struct Variant {
    pub change: Vec<Change>,
    pub draft: Draft,
}

fn role(out: &TransactionOutput, o: &Outsider) -> String {
    match out.covenant {
        Some(c) => format!("coin of covenant {}", &c.covenant_id.to_string()[..8]),
        None if out.script_public_key == *o.spk_ref() => "the outsider".into(),
        None => format!("script {}", short(&hex(out.script_public_key.script()))),
    }
}

impl Outsider {
    pub fn spk_ref(&self) -> &ScriptPublicKey {
        &self.spk
    }
}

pub fn short(h: &str) -> String {
    if h.len() > 20 { format!("{}…{}", &h[..12], &h[h.len() - 6..]) } else { h.to_string() }
}

/// Value mutations on a draft: redirect a payee, take part of an output, drop an output.
pub fn value_mutations(base: &Draft, o: &Outsider, keep_shape: bool) -> Vec<Variant> {
    let mut out = Vec::new();
    for (k, x) in base.tx.outputs.iter().enumerate() {
        if x.covenant.is_none() && x.script_public_key == o.spk {
            continue;
        }
        let r = role(x, o);
        if x.covenant.is_none() {
            let mut d = base.clone();
            d.tx.outputs[k].script_public_key = o.spk.clone();
            out.push(Variant {
                change: vec![Change { class: "recipient", text: format!("output {k} ({r}) paid to the outsider instead"), from_output: Some(k), moved: x.value }],
                draft: d,
            });
        }
        let v = x.value;
        let mut deltas = vec![1u64, (v / 100).max(1), v / 2, v.saturating_sub(1)];
        deltas.retain(|d| *d >= 1 && *d < v);
        deltas.dedup();
        for delta in deltas {
            let mut d = base.clone();
            d.tx.outputs[k].value -= delta;
            d.pay_outsider(o, delta);
            out.push(Variant {
                change: vec![Change { class: "amount", text: format!("{delta} sompi of output {k} ({r}) paid to the outsider"), from_output: Some(k), moved: delta }],
                draft: d,
            });
        }
        if !keep_shape {
            let mut d = base.clone();
            let gone = d.tx.outputs.remove(k);
            d.pay_outsider(o, gone.value);
            out.push(Variant {
                change: vec![Change { class: "drop-output", text: format!("output {k} ({r}) left out, its {} sompi paid to the outsider", gone.value), from_output: Some(k), moved: gone.value }],
                draft: d,
            });
        }
    }
    out
}

/// Structural mutations: outputs added, covenant coins duplicated, witness signatures and keys changed, entry tags
/// swapped, sighash types changed, state pushes changed.
pub fn structural_mutations(case: &Case, base: &Draft, o: &Outsider, tags: &[[u8; 4]]) -> Vec<Variant> {
    let mut out = Vec::new();
    // An extra output the program never asked for, funded by the outsider.
    {
        let mut d = base.clone();
        d.add_outsider_input(o, 100_000_000);
        d.tx.outputs.push(TransactionOutput::new(100_000_000, o.spk.clone()));
        out.push(Variant { change: vec![Change { class: "extra-output", text: "an extra output to the outsider (funded by the outsider)".into(), from_output: None, moved: 0 }], draft: d });
    }
    // A second copy of each covenant-bound output, funded by the outsider.
    for (k, x) in base.tx.outputs.iter().enumerate() {
        if let Some(c) = x.covenant {
            let mut d = base.clone();
            d.add_outsider_input(o, x.value + 100_000);
            let mut dup = x.clone();
            dup.covenant = Some(c);
            d.tx.outputs.push(dup);
            out.push(Variant {
                change: vec![Change { class: "duplicate-covenant-output", text: format!("a second copy of output {k} (same script and covenant {}) added, funded by the outsider", &c.covenant_id.to_string()[..8]), from_output: None, moved: 0 }],
                draft: d,
            });
        }
    }
    for &t in &case.targets {
        let Some(items) = script::pushes(&base.tx.inputs[t].signature_script) else { continue };
        let n = items.len();
        if n == 0 {
            continue;
        }
        let args = &items[..n - 1];
        for (k, a) in args.iter().enumerate() {
            if script::looks_like_sig(a) {
                let ht = a[64];
                let mut z = vec![0u8; 64];
                z.push(ht);
                let mut d = base.clone();
                d.set_push(t, k, &z);
                out.push(Variant { change: vec![Change { class: "signature", text: format!("input {t}: signature (push {k}) replaced with zeros"), from_output: None, moved: 0 }], draft: d });
                let mut d = base.clone();
                d.set_push(t, k, &[]);
                out.push(Variant { change: vec![Change { class: "signature", text: format!("input {t}: signature (push {k}) emptied"), from_output: None, moved: 0 }], draft: d });
                let mut d = base.clone();
                d.set_push(t, k, &vec![0u8; 65]);
                d.sign.push(SignSpot { input: t, push: Some(k), hash_type: ht });
                out.push(Variant { change: vec![Change { class: "signature", text: format!("input {t}: signature (push {k}) made by the outsider's key instead"), from_output: None, moved: 0 }], draft: d });
                for (j, b) in args.iter().enumerate() {
                    if b.len() == 32 || b.len() == 33 {
                        let mut d = base.clone();
                        let key = if b.len() == 32 { o.xonly.to_vec() } else { o.kp.public_key().serialize().to_vec() };
                        d.set_push(t, j, &key);
                        d.set_push(t, k, &vec![0u8; 65]);
                        d.sign.push(SignSpot { input: t, push: Some(k), hash_type: ht });
                        out.push(Variant {
                            change: vec![Change { class: "witness-key", text: format!("input {t}: key (push {j}) and signature (push {k}) replaced with the outsider's"), from_output: None, moved: 0 }],
                            draft: d,
                        });
                    }
                }
                for alt in [0x02u8, 0x04, 0x81, 0x82, 0x84, 0x01] {
                    if alt == ht {
                        continue;
                    }
                    let mut d = base.clone();
                    let mut s = a.clone();
                    s[64] = alt;
                    d.set_push(t, k, &s);
                    out.push(Variant { change: vec![Change { class: "sighash", text: format!("input {t}: sighash byte of push {k} changed from {ht:#04x} to {alt:#04x}"), from_output: None, moved: 0 }], draft: d });
                    // The outsider signing that push itself under the other type.
                    let mut d = base.clone();
                    d.set_push(t, k, &vec![0u8; 65]);
                    d.sign.push(SignSpot { input: t, push: Some(k), hash_type: alt });
                    out.push(Variant { change: vec![Change { class: "sighash", text: format!("input {t}: push {k} signed by the outsider with sighash {alt:#04x}"), from_output: None, moved: 0 }], draft: d });
                }
            }
        }
        // Numbers in the witness (amounts, prices, indexes): zero, one, halved, doubled.
        for (k, a) in args.iter().enumerate() {
            if a.is_empty() || a.len() > 8 || (a.len() == 4 && tags.iter().any(|t| t[..] == a[..])) {
                continue;
            }
            let mut n: u64 = 0;
            for (i, b) in a.iter().enumerate() {
                n |= (*b as u64) << (8 * i);
            }
            let mut alts: Vec<u64> = vec![0, 1, n / 2, n.saturating_mul(2)];
            alts.retain(|x| *x != n);
            alts.dedup();
            for x in alts {
                let mut b = x.to_le_bytes()[..a.len()].to_vec();
                if a.len() < 8 && (x >> (8 * a.len())) != 0 {
                    continue;
                }
                if a.len() == 1 && x == 0 {
                    b = vec![];
                }
                let mut d = base.clone();
                d.set_push(t, k, &b);
                out.push(Variant { change: vec![Change { class: "argument", text: format!("input {t}: witness number (push {k}) {} → {}", n, x), from_output: None, moved: 0 }], draft: d });
            }
        }
        // Other entry tags, same arguments.
        if let Some(sel) = args.iter().position(|a| a.len() == 4 && tags.iter().any(|t| t[..] == a[..])) {
            for tag in tags {
                if tag[..] == args[sel][..] {
                    continue;
                }
                let mut d = base.clone();
                d.set_push(t, sel, tag);
                out.push(Variant { change: vec![Change { class: "entry", text: format!("input {t}: entry {} called with the arguments of {}", hex(tag), hex(&args[sel])), from_output: None, moved: 0 }], draft: d });
            }
        }
        // State pushes of the spent coin changed (a copy of the program with another value there).
        let redeem = &items[n - 1];
        if let Some(w) = script::state_window(redeem) {
            for (p, (_, _, data)) in w.pushes.iter().enumerate() {
                let mut nd = data.clone();
                if nd.len() == 32 {
                    nd = o.xonly.to_vec();
                } else if let Some(last) = nd.last_mut() {
                    *last ^= 0x01;
                } else {
                    nd = vec![0x01];
                }
                if nd == *data {
                    continue;
                }
                let mut r = redeem[..w.pushes[p].0].to_vec();
                r.extend_from_slice(&script::push(&nd));
                r.extend_from_slice(&redeem[w.pushes[p].1..]);
                let mut d = base.clone();
                d.set_push(t, n - 1, &r);
                d.entries[t].script_public_key = ScriptPublicKey::new(0, script::p2sh(&r).into());
                out.push(Variant {
                    change: vec![Change { class: "state", text: format!("input {t}: state push {p} of the spent coin changed ({} → {})", short(&hex(data)), short(&hex(&nd))), from_output: None, moved: 0 }],
                    draft: d,
                });
            }
        }
    }
    out
}

/// Argument shapes to try for an entry nobody was seen using.
pub fn guessed_shapes(observed_args: &[Vec<u8>], sel: usize, tag: &[u8; 4], o: &Outsider) -> Vec<(String, Vec<Vec<u8>>)> {
    let mut shapes: Vec<(String, Vec<Vec<u8>>)> = Vec::new();
    let mut with_tag = |name: &str, mut a: Vec<Vec<u8>>| {
        // The selector is the last push before the program in silverc's convention.
        a.push(tag.to_vec());
        shapes.push((name.to_string(), a));
    };
    let before: Vec<Vec<u8>> = observed_args[..sel].to_vec();
    with_tag("observed arguments", before.clone());
    for k in 1..=before.len().min(6) {
        with_tag(&format!("observed arguments minus the last {k}"), before[..before.len() - k].to_vec());
    }
    let sig = vec![0u8; 65];
    let key = o.xonly.to_vec();
    with_tag("none", vec![]);
    with_tag("signature", vec![sig.clone()]);
    with_tag("signature, key", vec![sig.clone(), key.clone()]);
    with_tag("key, signature", vec![key.clone(), sig.clone()]);
    for n in 1..=6usize {
        with_tag(&format!("{n} zero numbers"), vec![vec![]; n]);
        with_tag(&format!("{n} 8-byte numbers"), vec![1u64.to_le_bytes().to_vec(); n]);
    }
    with_tag("number, key", vec![vec![1], key.clone()]);
    with_tag("number, signature, key", vec![vec![1], sig.clone(), key.clone()]);
    shapes
}

/// A covenant output whose authorizing input does not carry that covenant is a genesis, and its id commits to the
/// authorizing outpoint and the group's outputs. Whoever builds the transaction recomputes it, so the analyzer does
/// too after any change (an unchanged group keeps its id).
pub fn fix_genesis(tx: &mut Transaction, entries: &[UtxoEntry]) {
    use std::collections::BTreeMap;
    let mut groups: BTreeMap<(u16, Hash), Vec<usize>> = BTreeMap::new();
    for (k, out) in tx.outputs.iter().enumerate() {
        if let Some(c) = out.covenant {
            let auth = c.authorizing_input as usize;
            if let Some(e) = entries.get(auth) {
                if e.covenant_id != Some(c.covenant_id) {
                    groups.entry((c.authorizing_input, c.covenant_id)).or_default().push(k);
                }
            }
        }
    }
    for ((auth, _), idx) in groups {
        let Some(input) = tx.inputs.get(auth as usize) else { continue };
        let id = kaspa_consensus_core::hashing::covenant_id::covenant_id(
            input.previous_outpoint,
            idx.iter().map(|&i| (i as u32, &tx.outputs[i])),
        );
        for i in idx {
            if let Some(c) = tx.outputs[i].covenant.as_mut() {
                c.covenant_id = id;
            }
        }
    }
}
