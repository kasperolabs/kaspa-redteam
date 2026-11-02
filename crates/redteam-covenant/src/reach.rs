//! Paths that can never be spent with the project as written.
//!
//! A follower entry that needs another program's coin in the same transaction
//! (`require(OpCovInputCount(bridge_covenant_id) > 0)`) and ends its own coin's
//! family (`require(OpCovOutputCount(cov) == 0)`) is reachable only if some
//! entry of that other program accepts such a transaction. When every entry of
//! it either keeps this family going (`OpCovOutputCount(T) == 1 + mints`),
//! leaves it untouched (`OpCovInputCount(T) == 0`), or runs only while `T` is
//! unset (before this coin exists), the path is reported as not reachable with
//! that file as written, with the lines that say so. Anything this reading
//! cannot account for leaves the usual "unexplored" wording in place.

use crate::project::{Link, ProjectFile};

/// `require(...)` contents of a body, one per statement, with their byte offset.
fn requires(body: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(i) = body[at..].find("require(") {
        let start = at + i;
        let open = start + "require".len();
        let mut depth = 0usize;
        let mut end = None;
        for (k, ch) in body[open..].char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(open + k);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(end) = end else { break };
        let inner: String = body[open + 1..end].split_whitespace().collect::<Vec<_>>().join(" ");
        out.push((start, inner));
        at = end;
    }
    out
}

/// `{ ... }` starting at the first `{` at or after `from`.
fn braced(src: &str, from: usize) -> Option<(usize, usize)> {
    let open = from + src[from..].find('{')?;
    let mut depth = 0usize;
    for (k, ch) in src[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((open, open + k + 1));
                }
            }
            _ => {}
        }
    }
    None
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// The entries of a source: `entry name(...)`, and `function name(...)` under a
/// `#[covenant...]` attribute. Name and body.
fn entries(src: &str) -> Vec<(String, &str)> {
    let mut out = Vec::new();
    let lines: Vec<(usize, &str)> = src
        .lines()
        .scan(0usize, |off, l| {
            let at = *off;
            *off += l.len() + 1;
            Some((at, l))
        })
        .collect();
    for (n, (at, l)) in lines.iter().enumerate() {
        let t = l.trim_start();
        let name_after = |kw: &str| t.strip_prefix(kw).and_then(|r| r.split('(').next()).map(|s| s.trim().to_string());
        let name = if t.starts_with("entry ") {
            name_after("entry ")
        } else if t.starts_with("function ")
            && lines[..n]
                .iter()
                .rev()
                .map(|(_, p)| p.trim())
                .find(|p| !p.is_empty())
                .is_some_and(|p| p.starts_with("#[covenant"))
        {
            name_after("function ")
        } else {
            None
        };
        let Some(name) = name.filter(|s| !s.is_empty() && s.chars().all(is_ident)) else { continue };
        if let Some((a, b)) = braced(src, *at) {
            out.push((name, &src[a..b]));
        }
    }
    out
}

/// Names holding this coin's own covenant id (`byte[32] cov = OpInputCovenantId(this.activeInputIndex);`).
fn own_ids(text: &str) -> Vec<String> {
    let mut v = vec!["OpInputCovenantId(this.activeInputIndex)".to_string()];
    for l in text.lines() {
        let l = l.trim();
        if let Some(lhs) = l.strip_suffix("= OpInputCovenantId(this.activeInputIndex);") {
            if let Some(name) = lhs.split_whitespace().last() {
                v.push(name.to_string());
            }
        }
    }
    v
}

/// `OpCovInputCount(X) > 0`, `>= 1`, `== 1` or `OpCovOutputCount(X) == 0`: the X.
fn arg_of<'a>(inner: &'a str, op: &str, tails: &[&str]) -> Option<&'a str> {
    let rest = inner.strip_prefix(op)?.strip_prefix('(')?;
    let close = rest.find(')')?;
    let tail = rest[close + 1..].trim();
    tails.contains(&tail).then(|| rest[..close].trim())
}

/// A right-hand side that is at least 1 for any count: `1`, `2`, `1 + mints`, `mints + 1`.
fn at_least_one(rhs: &str) -> bool {
    let num = |s: &str| s.trim().parse::<i64>().ok();
    if num(rhs).is_some_and(|n| n >= 1) {
        return true;
    }
    match rhs.split_once('+') {
        Some((a, b)) => {
            let (a, b) = (a.trim(), b.trim());
            (num(a).is_some_and(|n| n >= 1) && b.chars().all(is_ident))
                || (num(b).is_some_and(|n| n >= 1) && a.chars().all(is_ident))
        }
        None => false,
    }
}

/// What one entry of the partner allows for family `t`.
enum Partner {
    /// Refuses the transaction; the reason, in source words.
    Refuses(String),
    /// Might accept it.
    Unknown,
}

fn partner_entry(name: &str, body: &str, t: &str) -> Partner {
    let reqs = requires(body);
    let on_t: Vec<&(usize, String)> = reqs
        .iter()
        .filter(|(_, r)| {
            r.starts_with(&format!("OpCovInputCount({t})")) || r.starts_with(&format!("OpCovOutputCount({t})"))
        })
        .collect();
    if on_t.is_empty() {
        // Runs only while the family id is unset: before the coin exists.
        let unset = reqs.iter().any(|(_, r)| {
            r.split_once("==").is_some_and(|(a, b)| {
                let b = b.trim();
                a.trim() == t
                    && (b.to_ascii_uppercase().contains("ZERO")
                        || (b.starts_with("0x") && b[2..].chars().all(|c| c == '0')))
            })
        });
        return if unset {
            Partner::Refuses(format!("`{name}` runs only while `{t}` is unset"))
        } else {
            Partner::Unknown
        };
    }
    // Group the checks by the block they sit in; the blocks must be the two arms
    // of one if/else at the top of the body, or the body itself.
    let mut blocks: Vec<(usize, usize)> = Vec::new(); // (open, close) of innermost block per check
    for (at, _) in &on_t {
        let mut best = (0, body.len());
        let mut stack = Vec::new();
        for (k, ch) in body.char_indices() {
            match ch {
                '{' => stack.push(k),
                '}' => {
                    if let Some(o) = stack.pop() {
                        if o < *at && *at < k && k - o < best.1 - best.0 {
                            best = (o, k);
                        }
                    }
                }
                _ => {}
            }
        }
        if !blocks.contains(&best) {
            blocks.push(best);
        }
    }
    let arms_ok = blocks.len() == 1 && blocks[0].0 == 0
        || blocks.len() == 2 && {
            let (a, b) = (blocks[0].min(blocks[1]), blocks[0].max(blocks[1]));
            body[a.1 + 1..b.0].trim() == "else" && body[..a.0].trim_end().ends_with(')')
        };
    if !arms_ok {
        return Partner::Unknown;
    }
    let mut why = Vec::new();
    for (open, close) in &blocks {
        let inside = |at: &usize| *open <= *at && *at <= *close;
        let in_zero = on_t.iter().any(|(at, r)| inside(at) && arg_of(r, "OpCovInputCount", &["== 0"]) == Some(t));
        let keeps = on_t.iter().find_map(|(at, r)| {
            if !inside(at) {
                return None;
            }
            let rhs = r.strip_prefix(&format!("OpCovOutputCount({t})"))?.trim().strip_prefix("==")?.trim();
            at_least_one(rhs).then(|| r.clone())
        });
        match (in_zero, keeps) {
            (true, _) => why.push(format!("`OpCovInputCount({t}) == 0`")),
            (false, Some(r)) => why.push(format!("`{r}`")),
            _ => return Partner::Unknown,
        }
    }
    Partner::Refuses(format!("`{name}` requires {}", why.join(" or ")))
}

/// Why `entry` of `file` can never be spent with the project as written, or
/// `None` when that cannot be read off the sources.
pub fn unpairable(file: &str, source: &str, entry: &str, links: &[Link], files: &[ProjectFile]) -> Option<String> {
    let text = crate::tune::entry_text(source, entry)?;
    let reqs = requires(&text);
    let own = own_ids(source);
    let ends = reqs
        .iter()
        .find(|(_, r)| arg_of(r, "OpCovOutputCount", &["== 0"]).is_some_and(|x| own.iter().any(|o| o == x)))?;
    // The partner: the file this value is linked to as a covenant id, or else the
    // one file that pins this file's program (it creates these coins) and whose
    // name the value carries (`bridge_covenant_id` and bridge.sil).
    let stem = |n: &str| n.rsplit_once('.').map(|(s, _)| s).unwrap_or(n).to_ascii_lowercase();
    let (needs, partner) = reqs.iter().find_map(|(_, r)| {
        let p = arg_of(r, "OpCovInputCount", &["> 0", ">= 1", "== 1"])?;
        if let Some(l) = links.iter().find(|l| l.from == file && l.kind == "covenant id" && l.via == p) {
            return Some((r.clone(), l.to.clone()));
        }
        let creators: Vec<&Link> = links
            .iter()
            .filter(|l| l.to == file && l.from != file && p.to_ascii_lowercase().contains(&stem(&l.from)))
            .collect();
        match creators.as_slice() {
            [l] => Some((r.clone(), l.from.clone())),
            _ => None,
        }
    })?;
    let g = files.iter().find(|f| f.name == partner)?;
    let g_own = own_ids(&g.source);
    // A family born in the transaction (`new_token = OpOutputCovenantId(1)`) is not this coin's.
    let born: Vec<String> = g
        .source
        .lines()
        .filter_map(|l| {
            let (lhs, rhs) = l.trim().split_once('=')?;
            rhs.trim_start()
                .starts_with("OpOutputCovenantId(")
                .then(|| lhs.split_whitespace().last().map(str::to_string))?
        })
        .collect();
    // The expression the partner uses for this coin's family: the one it counts and is not its own.
    let mut t: Option<String> = None;
    for (_, r) in requires(&g.source) {
        for op in ["OpCovInputCount", "OpCovOutputCount"] {
            if let Some(rest) = r.strip_prefix(op).and_then(|x| x.strip_prefix('(')) {
                let x = rest[..rest.find(')')?].trim().to_string();
                if g_own.contains(&x) || born.contains(&x) {
                    continue;
                }
                match &t {
                    None => t = Some(x),
                    Some(y) if *y == x => {}
                    Some(_) => return None,
                }
            }
        }
    }
    let t = t?;
    let mut reasons = Vec::new();
    let es = entries(&g.source);
    if es.is_empty() {
        return None;
    }
    for (name, body) in es {
        match partner_entry(&name, body, &t) {
            Partner::Refuses(why) => reasons.push(why),
            Partner::Unknown => return None,
        }
    }
    Some(format!(
        "not reachable with {partner} as written: `{entry}` needs a coin of {partner} in the same transaction (`{needs}`) and ends this coin without a successor (`{}`), and no entry of {partner} allows that: {}. If `{entry}` is meant to be usable, {partner} needs a path that allows it.",
        ends.1,
        reasons.join("; ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bridge(dir: &str) -> (Vec<ProjectFile>, Vec<Link>) {
        let root = format!("{}/../../fixtures/family/{dir}", env!("CARGO_MANIFEST_DIR"));
        let files: Vec<ProjectFile> = ["BridgeMint.sil", "KCC20.sil", "bridge.sil"]
            .iter()
            .map(|n| ProjectFile {
                name: n.to_string(),
                source: std::fs::read_to_string(format!("{root}/{n}")).unwrap(),
            })
            .collect();
        let (links, _) = crate::project::detect(&files, &Default::default()).unwrap();
        (files, links)
    }

    #[test]
    fn bridge_mint_retire_is_not_reachable() {
        let (files, links) = bridge("fixed");
        let why = unpairable("BridgeMint.sil", &files[0].source, "retire", &links, &files).expect("retire");
        assert!(why.starts_with("not reachable with bridge.sil as written"), "{why}");
        assert!(why.contains("1 + mints") && why.contains("`init` runs only while"), "{why}");
        // mint pairs with advance: never reported as unreachable.
        assert!(unpairable("BridgeMint.sil", &files[0].source, "mint", &links, &files).is_none());
    }

    #[test]
    fn a_partner_that_allows_it_is_not_claimed() {
        let (mut files, links) = bridge("fixed");
        let keep = "require(OpCovOutputCount(prev_state.token) == 1 + mints);";
        assert!(files[2].source.contains(keep));
        files[2].source = files[2].source.replace(keep, "require(OpCovOutputCount(prev_state.token) >= 0);");
        assert!(unpairable("BridgeMint.sil", &files[0].source, "retire", &links, &files).is_none());
    }
}
