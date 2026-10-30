//! ZK covenants in the sandbox: a test verifying key, and a proof it accepts.
//!
//! A Groth16 verifying key is a constant pushed by the script itself (the
//! RISC Zero verifier fragment pushes its fixed 424-byte key; `g16.verify`
//! pushes the contract's own). The tool cannot make a real proof, and should
//! not: that is what the covenant's security rests on. Instead it swaps the
//! key, in the sandbox only, for one it built with known secrets, where every
//! public-input weight is the point at infinity. Its one test proof then
//! verifies for any public inputs: any journal, any image id. This is the same
//! idea as a prover's dev mode.
//!
//! What that tests: everything around the proof (does the covenant bind its
//! outputs to the journal, can a journal be replayed, can value move without
//! a proof). What it cannot test: the circuit, or whether the real key is the
//! right one. The report says so.

use ark_bn254::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};

/// Fixed secrets of the test setup (not secret at all; it is a test key).
fn scalar(label: &str) -> Fr {
    Fr::from_le_bytes_mod_order(&{ let h = redteam_core::sha256_hex(&[format!("kaspa-redteam test zk {label}").as_bytes()]); let mut b = [0u8; 32]; faster_hex::hex_decode(h.as_bytes(), &mut b).expect("hex"); b })
}

fn g1(s: Fr) -> G1Affine {
    (G1Projective::generator() * s).into_affine()
}
fn g2(s: Fr) -> G2Affine {
    (G2Projective::generator() * s).into_affine()
}
fn ser<T: CanonicalSerialize>(t: &T, out: &mut Vec<u8>) {
    t.serialize_compressed(out).expect("serialize");
}

/// A verifying key for `n` public inputs that accepts `test_proof()` whatever
/// the inputs are.
pub fn test_vk(n: usize) -> Vec<u8> {
    let (a, b, g, d, k0) = (scalar("alpha"), scalar("beta"), scalar("gamma"), scalar("delta"), scalar("k0"));
    let mut out = Vec::new();
    ser(&g1(a), &mut out);
    ser(&g2(b), &mut out);
    ser(&g2(g), &mut out);
    ser(&g2(d), &mut out);
    ser(&((n as u64) + 1), &mut out);
    ser(&g1(k0), &mut out);
    for _ in 0..n {
        ser(&G1Affine::zero(), &mut out);
    }
    out
}

/// The proof `test_vk` accepts: e(A,B) = e(α,β)·e(k0·G1,γ)·e(C,δ), so
/// a·b = α·β + k0·γ + c·δ, solved for c.
pub fn test_proof() -> Vec<u8> {
    let (a, b, g, d, k0) = (scalar("alpha"), scalar("beta"), scalar("gamma"), scalar("delta"), scalar("k0"));
    let (pa, pb) = (scalar("proof a"), scalar("proof b"));
    let c = (pa * pb - a * b - k0 * g) * d.inverse().expect("nonzero");
    let mut out = Vec::new();
    ser(&g1(pa), &mut out);
    ser(&g2(pb), &mut out);
    ser(&g1(c), &mut out);
    out
}

/// If `bytes` is a compressed Groth16 verifying key, its public-input count.
fn vk_inputs(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 232 + 64 || (bytes.len() - 232) % 32 != 0 {
        return None;
    }
    let mut r = bytes;
    let _ = G1Affine::deserialize_with_mode(&mut r, Compress::Yes, Validate::Yes).ok()?;
    for _ in 0..3 {
        let _ = G2Affine::deserialize_with_mode(&mut r, Compress::Yes, Validate::Yes).ok()?;
    }
    let count = u64::deserialize_with_mode(&mut r, Compress::Yes, Validate::Yes).ok()? as usize;
    (count >= 1 && r.len() == count * 32).then_some(count - 1)
}

/// Pushes of the script, as (offset of the data, length).
fn pushes(script: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        let (len, head) = match op {
            0x01..=0x4b => (op as usize, 1),
            0x4c if i + 1 < script.len() => (script[i + 1] as usize, 2),
            0x4d if i + 2 < script.len() => (u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize, 3),
            0x4e if i + 4 < script.len() => {
                (u32::from_le_bytes([script[i + 1], script[i + 2], script[i + 3], script[i + 4]]) as usize, 5)
            }
            _ => (0, 1),
        };
        if len > 0 && i + head + len <= script.len() {
            out.push((i + head, len));
        }
        i += head + len;
    }
    out
}

/// Replaces every Groth16 verifying key pushed by `script` with the test key
/// of the same shape. Returns the new script and how many keys were swapped.
pub fn swap_keys(script: &[u8]) -> (Vec<u8>, usize) {
    let mut out = script.to_vec();
    let mut n = 0;
    for (at, len) in pushes(script) {
        if let Some(inputs) = vk_inputs(&script[at..at + len]) {
            let key = test_vk(inputs);
            debug_assert_eq!(key.len(), len);
            out[at..at + len].copy_from_slice(&key);
            n += 1;
        }
    }
    (out, n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Bn254;
    use ark_ec::pairing::Pairing;

    #[test]
    fn test_proof_verifies_for_any_inputs() {
        for n in [1usize, 5] {
            let vk_bytes = test_vk(n);
            assert_eq!(vk_inputs(&vk_bytes), Some(n));
            let mut r = vk_bytes.as_slice();
            let alpha = G1Affine::deserialize_compressed(&mut r).unwrap();
            let beta = G2Affine::deserialize_compressed(&mut r).unwrap();
            let gamma = G2Affine::deserialize_compressed(&mut r).unwrap();
            let delta = G2Affine::deserialize_compressed(&mut r).unwrap();
            let _ = u64::deserialize_compressed(&mut r).unwrap();
            let abc: Vec<G1Affine> = (0..=n).map(|_| G1Affine::deserialize_compressed(&mut r).unwrap()).collect();
            let p = test_proof();
            let mut r = p.as_slice();
            let pa = G1Affine::deserialize_compressed(&mut r).unwrap();
            let pb = G2Affine::deserialize_compressed(&mut r).unwrap();
            let pc = G1Affine::deserialize_compressed(&mut r).unwrap();
            for inputs in [vec![Fr::from(7u64); n], vec![Fr::from(123456u64); n]] {
                let mut x: G1Projective = abc[0].into();
                for (i, v) in inputs.iter().enumerate() {
                    x += abc[i + 1] * v;
                }
                let lhs = Bn254::pairing(pa, pb);
                let rhs = Bn254::pairing(alpha, beta) + Bn254::pairing(x.into_affine(), gamma) + Bn254::pairing(pc, delta);
                assert_eq!(lhs, rhs);
            }
        }
    }
}


/// A journal laid out the way the entry reads it. Journals are read by
/// slicing: `require(byte[32](journal.slice(0, 32)) == chain_commitment)`,
/// `require(journal.length >= 270)`. Each such check places a constructor or
/// state value at its offset; the rest stays zero (so counts read as 0: no
/// deposits, a heartbeat). Returns None when the body never slices `param`.
pub fn journal_from_source(
    body: &str,
    param: &str,
    bytes_of: &dyn Fn(&str) -> Option<Vec<u8>>,
) -> Option<Vec<u8>> {
    let num = |s: &str| s.trim().replace('_', "").parse::<usize>().ok();
    let consts: std::collections::BTreeMap<String, usize> = body
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            let rest = l.strip_prefix("int constant ").or_else(|| l.strip_prefix("int "))?;
            let (name, v) = rest.split_once('=')?;
            Some((name.trim().to_string(), num(v.trim().trim_end_matches(';'))?))
        })
        .collect();
    let val = |s: &str| num(s).or_else(|| consts.get(s.trim()).copied());
    let mut len = 0usize;
    let mut fills: Vec<(usize, Vec<u8>)> = Vec::new();
    let slice_pat = format!("{param}.slice(");
    let mut any = false;
    for line in body.lines() {
        let l = line.trim();
        // length: `param.length >= K` / `== K`
        if let Some(at) = l.find(&format!("{param}.length")) {
            let rest = l[at + param.len() + 7..].trim_start();
            for op in [">=", "=="] {
                if let Some(v) = rest.strip_prefix(op) {
                    let term = v.split(|c| c == ')' || c == ';' || c == '+').next().unwrap_or("");
                    if let Some(k) = val(term) {
                        len = len.max(k);
                        any = true;
                    }
                }
            }
        }
        // a slice compared to a value: `byte[N](param.slice(a, b)) == expr`
        let Some(at) = l.find(&slice_pat) else { continue };
        any = true;
        let args = &l[at + slice_pat.len()..];
        let Some(close) = args.find(')') else { continue };
        let Some((a, b)) = args[..close].split_once(',') else { continue };
        let (Some(a), Some(b)) = (val(a), val(b)) else { continue };
        len = len.max(b);
        let after = &args[close + 1..];
        // `field: byte[N](journal.slice(a, b))` in a returned state: the field's
        // current value, so the next state can equal this one.
        if let Some((field, _)) = l.split_once(':') {
            let field = field.trim();
            if !field.contains(' ') && !field.contains('(') && !after.contains("==") {
                if let Some(v) = bytes_of(field) {
                    if v.len() == b - a {
                        fills.push((a, v));
                    }
                }
                continue;
            }
        }
        let Some(eq) = after.find("==") else { continue };
        let expr = after[eq + 2..].split(|c| c == ')' || c == ';').next().unwrap_or("").trim();
        let expr = expr.rsplit('.').next().unwrap_or(expr);
        if let Some(v) = bytes_of(expr) {
            if v.len() == b - a {
                fills.push((a, v));
            }
        }
    }
    if !any {
        return None;
    }
    let mut out = vec![0u8; len];
    for (a, v) in fills {
        if a + v.len() <= out.len() {
            out[a..a + v.len()].copy_from_slice(&v);
        }
    }
    Some(out)
}
