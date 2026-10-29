//! Minimal script tokenizer: enough to count signature operations and collect
//! the integers a script pushes (candidate lock values for the spend search).

#[derive(Debug, Clone)]
pub enum Token {
    Push(Vec<u8>),
    Op(u8),
}

pub fn tokenize(script: &[u8]) -> Vec<Token> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        i += 1;
        let len = match op {
            0x00 => {
                out.push(Token::Push(vec![]));
                continue;
            }
            0x01..=0x4b => op as usize,
            0x4c if i < script.len() => {
                let n = script[i] as usize;
                i += 1;
                n
            }
            0x4d if i + 1 < script.len() => {
                let n = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
                i += 2;
                n
            }
            0x4e if i + 3 < script.len() => {
                let n = u32::from_le_bytes([script[i], script[i + 1], script[i + 2], script[i + 3]]) as usize;
                i += 4;
                n
            }
            0x4f => {
                out.push(Token::Push(vec![0x81]));
                continue;
            }
            0x51..=0x60 => {
                out.push(Token::Push(vec![op - 0x50]));
                continue;
            }
            _ => {
                out.push(Token::Op(op));
                continue;
            }
        };
        let end = (i + len).min(script.len());
        out.push(Token::Push(script[i..end].to_vec()));
        i = end;
    }
    out
}

/// Decodes a minimally or non-minimally encoded script number (up to 8 bytes).
pub fn script_num(bytes: &[u8]) -> Option<i64> {
    if bytes.is_empty() {
        return Some(0);
    }
    if bytes.len() > 8 {
        return None;
    }
    let mut v: i128 = 0;
    for (k, b) in bytes.iter().enumerate() {
        v |= (*b as i128) << (8 * k);
    }
    let last = bytes[bytes.len() - 1];
    if last & 0x80 != 0 {
        v &= !(0x80i128 << (8 * (bytes.len() - 1)));
        v = -v;
    }
    i64::try_from(v).ok()
}

/// Upper bound on signature operations, for the input's sigop commitment.
pub fn sig_op_estimate(script: &[u8]) -> u8 {
    let mut n: u32 = 0;
    for t in tokenize(script) {
        if let Token::Op(op) = t {
            match op {
                0xab | 0xac | 0xad | 0xd7 | 0xd8 => n += 1,
                0xa9 | 0xae | 0xaf => n += 20,
                _ => {}
            }
        }
    }
    n.clamp(1, 255) as u8
}

/// Positive integers pushed by the script, ascending, deduplicated.
pub fn pushed_ints(script: &[u8]) -> Vec<u64> {
    let mut v: Vec<u64> = tokenize(script)
        .into_iter()
        .filter_map(|t| match t {
            Token::Push(b) if !b.is_empty() && b.len() <= 8 => script_num(&b),
            _ => None,
        })
        .filter(|n| *n > 0)
        .map(|n| n as u64)
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// Integers pushed shortly before a lock opcode (CLTV 0xb0, CSV 0xb1). SilverScript v1
/// wraps the lock argument in range checks (`<N> DUP 0 <2^32> WITHIN VERIFY CSV`,
/// `<N> DUP DUP <threshold> GTE VERIFY CLTV`), so we look back a few tokens and keep the
/// first push of the window, which is the lock value itself.
pub fn lock_values(script: &[u8]) -> (Vec<u64>, Vec<u64>) {
    let toks = tokenize(script);
    let mut cltv = Vec::new();
    let mut csv = Vec::new();
    for (i, t) in toks.iter().enumerate() {
        let Token::Op(op @ (0xb0 | 0xb1)) = t else {
            continue;
        };
        let start = i.saturating_sub(7);
        let first_push = toks[start..i].iter().find_map(|t| match t {
            Token::Push(b) if !b.is_empty() && b.len() <= 8 => script_num(b).filter(|n| *n > 0),
            _ => None,
        });
        if let Some(n) = first_push {
            if *op == 0xb0 { cltv.push(n as u64) } else { csv.push(n as u64) }
        }
    }
    cltv.sort_unstable();
    cltv.dedup();
    csv.sort_unstable();
    csv.dedup();
    (cltv, csv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nums() {
        assert_eq!(script_num(&[0x01]), Some(1));
        assert_eq!(script_num(&[0x81]), Some(-1));
        assert_eq!(script_num(&[0xe8, 0x03]), Some(1000));
        assert_eq!(script_num(&[0x00, 0x80]), Some(0));
    }

    #[test]
    fn v1_relative_lock_shape() {
        // <1000> DUP 0 <2^32> WITHIN VERIFY CSV
        let s = [0x02, 0xe8, 0x03, 0x76, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0xa5, 0x69, 0xb1];
        assert_eq!(lock_values(&s).1, vec![1000]);
    }
}
