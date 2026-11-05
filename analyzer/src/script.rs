//! Reading program bytes without running them: pushes, the leading state window, entry tags, opcode facts.

use anyhow::{Result, bail};

/// One parsed opcode. `data` is set for pushes (small-int opcodes carry their value as one byte).
#[derive(Clone, Debug)]
pub struct Op {
    pub pos: usize,
    pub end: usize,
    pub code: u8,
    pub data: Option<Vec<u8>>,
}

pub fn parse(s: &[u8]) -> Result<Vec<Op>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < s.len() {
        let pos = i;
        let code = s[i];
        i += 1;
        let data = match code {
            0x00 => Some(Vec::new()),
            0x01..=0x4b => {
                let n = code as usize;
                if i + n > s.len() {
                    bail!("push at {pos} runs past the end");
                }
                let d = s[i..i + n].to_vec();
                i += n;
                Some(d)
            }
            0x4c | 0x4d | 0x4e => {
                let w = match code {
                    0x4c => 1,
                    0x4d => 2,
                    _ => 4,
                };
                if i + w > s.len() {
                    bail!("push length at {pos} runs past the end");
                }
                let mut n = 0usize;
                for k in 0..w {
                    n |= (s[i + k] as usize) << (8 * k);
                }
                i += w;
                if i + n > s.len() {
                    bail!("push at {pos} runs past the end");
                }
                let d = s[i..i + n].to_vec();
                i += n;
                Some(d)
            }
            0x4f => Some(vec![0x81]),
            0x51..=0x60 => Some(vec![code - 0x50]),
            _ => None,
        };
        out.push(Op { pos, end: i, code, data });
    }
    Ok(out)
}

/// A signature script that is only pushes, as its pushed byte strings.
pub fn pushes(sig: &[u8]) -> Option<Vec<Vec<u8>>> {
    let ops = parse(sig).ok()?;
    ops.into_iter().map(|o| o.data).collect()
}

/// Minimal push encoding of `d` (what a compiler emits for a data argument).
pub fn push(d: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(d.len() + 5);
    let n = d.len();
    if n == 0 {
        v.push(0x00);
    } else if n == 1 && (1..=16).contains(&d[0]) {
        v.push(0x50 + d[0]);
    } else if n == 1 && d[0] == 0x81 {
        v.push(0x4f);
    } else if n <= 0x4b {
        v.push(n as u8);
        v.extend_from_slice(d);
    } else if n <= 0xff {
        v.push(0x4c);
        v.push(n as u8);
        v.extend_from_slice(d);
    } else if n <= 0xffff {
        v.push(0x4d);
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v.extend_from_slice(d);
    } else {
        v.push(0x4e);
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v.extend_from_slice(d);
    }
    v
}

/// Data pushes encoded with an explicit length byte (never the small-int form), the way a witness built by
/// hand or by most SDKs pushes raw bytes. Used only to rebuild a signature script after a change.
pub fn push_all(items: &[Vec<u8>]) -> Vec<u8> {
    items.iter().flat_map(|d| push(d)).collect()
}

/// The leading run of pushes in a program, taken as its state.
/// Guarded builds wrap it in OP_TOALTSTACK (0x6b) ... OP_FROMALTSTACK (0x6c); others start at byte 0.
#[derive(Clone, Debug)]
pub struct StateWindow {
    pub start: usize,
    pub end: usize,
    pub guarded: bool,
    pub pushes: Vec<(usize, usize, Vec<u8>)>, // (pos, end, data)
}

pub fn state_window(r: &[u8]) -> Option<StateWindow> {
    let ops = parse(r).ok()?;
    let guarded = r.first() == Some(&0x6b);
    let skip = if guarded { 1 } else { 0 };
    let mut pushes = Vec::new();
    let mut end = skip;
    for o in ops.iter().skip(skip) {
        match &o.data {
            // A run of state pushes is data, not small-int opcodes (those are code in every build seen).
            Some(d) if (0x01..=0x4e).contains(&o.code) || o.code == 0x00 => {
                pushes.push((o.pos, o.end, d.clone()));
                end = o.end;
            }
            _ => break,
        }
        if pushes.len() >= 64 {
            break;
        }
    }
    if pushes.is_empty() {
        return None;
    }
    if guarded && r.get(end) != Some(&0x6c) {
        return None;
    }
    Some(StateWindow { start: skip, end, guarded, pushes })
}

/// KCC-1 TemplateHash: BLAKE3 over (len prefix, prefix, len suffix, suffix), the state cut out.
pub fn template_hash(prefix: &[u8], suffix: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&(prefix.len() as u64).to_le_bytes());
    h.update(prefix);
    h.update(&(suffix.len() as u64).to_le_bytes());
    h.update(suffix);
    *h.finalize().as_bytes()
}

pub fn template_hash_of(r: &[u8], w: &StateWindow) -> [u8; 32] {
    template_hash(&r[..w.start], &r[w.end..])
}

pub fn blake2b32(b: &[u8]) -> [u8; 32] {
    let h = blake2b_simd::Params::new().hash_length(32).hash(b);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

/// P2SH script (version 0) committing to `redeem`.
pub fn p2sh(redeem: &[u8]) -> Vec<u8> {
    let mut v = vec![0xaa, 0x20];
    v.extend_from_slice(&blake2b32(redeem));
    v.push(0x87);
    v
}

pub fn is_p2sh(spk: &[u8]) -> bool {
    spk.len() == 35 && spk[0] == 0xaa && spk[1] == 0x20 && spk[34] == 0x87
}
pub fn is_p2pk(spk: &[u8]) -> bool {
    (spk.len() == 34 && spk[0] == 0x20 && spk[33] == 0xac) || (spk.len() == 35 && spk[0] == 0x21 && spk[34] == 0xab)
}

/// Entry tags of a silverc-style dispatch: OP_DUP or OP_DROP, a 4-byte push, OP_EQUAL, OP_IF.
pub fn entry_tags(r: &[u8]) -> Vec<[u8; 4]> {
    let Ok(ops) = parse(r) else { return vec![] };
    let mut tags: Vec<[u8; 4]> = Vec::new();
    for w in ops.windows(4) {
        if (w[0].code == 0x76 || w[0].code == 0x75)
            && w[1].code == 0x04
            && w[2].code == 0x87
            && w[3].code == 0x63
        {
            let d = w[1].data.as_ref().unwrap();
            let t = [d[0], d[1], d[2], d[3]];
            if !tags.contains(&t) {
                tags.push(t);
            }
        }
    }
    tags
}

pub fn op_name(c: u8) -> &'static str {
    match c {
        0xac => "OpCheckSig",
        0xad => "OpCheckSigVerify",
        0xae => "OpCheckMultiSig",
        0xaf => "OpCheckMultiSigVerify",
        0xab => "OpCheckSigECDSA",
        0xa9 => "OpCheckMultiSigECDSA",
        0xb0 => "OpCheckLockTimeVerify",
        0xb1 => "OpCheckSequenceVerify",
        0xb2 => "OpTxVersion",
        0xb3 => "OpTxInputCount",
        0xb4 => "OpTxOutputCount",
        0xb5 => "OpTxLockTime",
        0xb6 => "OpTxSubnetId",
        0xb7 => "OpTxGas",
        0xb8 => "OpTxPayloadSubstr",
        0xb9 => "OpTxInputIndex",
        0xba => "OpOutpointTxId",
        0xbb => "OpOutpointIndex",
        0xbc => "OpTxInputScriptSigSubstr",
        0xbd => "OpTxInputSeq",
        0xbe => "OpTxInputAmount",
        0xbf => "OpTxInputSpk",
        0xc0 => "OpTxInputDaaScore",
        0xc1 => "OpTxInputIsCoinbase",
        0xc2 => "OpTxOutputAmount",
        0xc3 => "OpTxOutputSpk",
        0xc4 => "OpTxPayloadLen",
        0xc5 => "OpTxInputSpkLen",
        0xc6 => "OpTxInputSpkSubstr",
        0xc7 => "OpTxOutputSpkLen",
        0xc8 => "OpTxOutputSpkSubstr",
        0xc9 => "OpTxInputScriptSigLen",
        0xcb => "OpAuthOutputCount",
        0xcc => "OpAuthOutputIdx",
        0xcf => "OpInputCovenantId",
        0xd0 => "OpCovInputCount",
        0xd1 => "OpCovInputIdx",
        0xd2 => "OpCovOutputCount",
        0xd3 => "OpCovOutputIdx",
        0xd4 => "OpChainblockSeqCommit",
        0xd5 => "OpOutputCovenantId",
        0xd6 => "OpOutputAuthorizingInput",
        0xd7 => "OpCheckSigFromStack",
        0xd8 => "OpCheckSigFromStackECDSA",
        0xd9 => "OpBlake3",
        0xda => "OpBlake3WithKey",
        0xaa => "OpBlake2b",
        0xa8 => "OpSHA256",
        _ => "",
    }
}

/// Counts of the opcodes that decide who can spend and what a spend must create.
pub fn op_facts(r: &[u8]) -> serde_json::Value {
    let Ok(ops) = parse(r) else { return serde_json::json!({ "parse_error": true }) };
    let mut counts: std::collections::BTreeMap<&'static str, u64> = Default::default();
    let mut n = 0u64;
    for o in &ops {
        if o.data.is_some() {
            continue;
        }
        n += 1;
        let name = op_name(o.code);
        if !name.is_empty() {
            *counts.entry(name).or_default() += 1;
        }
    }
    let sig = ["OpCheckSig", "OpCheckSigVerify", "OpCheckMultiSig", "OpCheckMultiSigVerify", "OpCheckSigECDSA",
        "OpCheckMultiSigECDSA", "OpCheckSigFromStack", "OpCheckSigFromStackECDSA"]
        .iter()
        .map(|k| counts.get(k).copied().unwrap_or(0))
        .sum::<u64>();
    serde_json::json!({ "bytes": r.len(), "opcodes": n, "signature_checks": sig, "by_opcode": counts })
}

/// Pushes that look like a Schnorr signature with a sighash byte (65 bytes, last byte a known type).
pub fn looks_like_sig(d: &[u8]) -> bool {
    d.len() == 65 && matches!(d[64], 0x01 | 0x02 | 0x04 | 0x81 | 0x82 | 0x84)
}

pub fn hex(b: &[u8]) -> String {
    faster_hex::hex_string(b)
}

pub fn unhex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim().trim_start_matches("0x");
    let s = if s.len() % 2 == 1 { format!("0{s}") } else { s.to_string() };
    let mut out = vec![0u8; s.len() / 2];
    faster_hex::hex_decode(s.as_bytes(), &mut out).map_err(|_| anyhow::anyhow!("bad hex"))?;
    Ok(out)
}
