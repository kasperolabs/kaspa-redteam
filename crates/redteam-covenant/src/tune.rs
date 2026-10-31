//! Constructor tuning. Default constructor values are guesses from names
//! (`...Fee` small, `...Daa` a few blocks, everything else 1 KAS), and a guess
//! can break a contract's own bound checks (`require(cancelFee >= MIN_OUT)`),
//! leaving a path unexplored for no real reason.
//!
//! For each path the search could not spend, this reads the comparisons the
//! entry makes on integer constructor parameters, takes the values they
//! compare against (literals, `int constant`s, other parameters), and tries
//! them. A value is kept only when it opens the path, and the final set only
//! when it explores at least as many paths as the defaults did. Nothing is
//! assumed: every kept value is backed by an accepted spend.

use crate::baseline::{self, PathStatus};
use crate::contract::Contract;
use crate::sandbox::Judge;
use anyhow::Result;
use silverscript_abi::ArtifactValue;
use std::collections::BTreeMap;

/// Try budget per candidate value: enough for a real path, small enough that
/// a few dozen candidates stay well under a minute.
const TUNE_BUDGET: usize = 6_000;
const MAX_CANDIDATES: usize = 8;
/// Marks a value set by `bound_fixes` rather than for one entry.
const BOUND: &str = "\0bound";

pub struct Tuned {
    pub contract: Contract,
    pub paths: Vec<PathStatus>,
    /// One line per value the tuner chose, for the report.
    pub notes: Vec<String>,
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn mentions(line: &str, name: &str) -> bool {
    line.match_indices(name).any(|(i, _)| {
        line[..i].chars().next_back().is_none_or(|c| !is_ident(c))
            && line[i + name.len()..].chars().next().is_none_or(|c| !is_ident(c))
    })
}

/// The source text of `entry name(...) { ... }`.
pub(crate) fn entry_body<'a>(source: &'a str, name: &str) -> Option<&'a str> {
    let find = |kw: &str, name: &str| {
        source.match_indices(kw).find(|(i, _)| {
            let rest = &source[i + kw.len()..];
            rest.starts_with(name) && rest[name.len()..].trim_start().starts_with('(')
        })
    };
    // A covenant declaration (`#[covenant...] function advance(...)`) compiles to an
    // entry named `__covenant_entrypoint_..._advance`: its body is the function's.
    let start = find("entry ", name).or_else(|| {
        let short = name.strip_prefix("__covenant_entrypoint_")?;
        let short = ["auth_", "cov_", "leader_", "delegate_"].iter().find_map(|p| short.strip_prefix(p)).unwrap_or(short);
        find("function ", short)
    })?;
    let open = start.0 + source[start.0..].find('{')?;
    let mut depth = 0usize;
    for (k, ch) in source[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&source[open..open + k + 1]);
                }
            }
            _ => {}
        }
    }
    None
}

/// The source text of `function name(...) { ... }`.
fn function_body<'a>(source: &'a str, name: &str) -> Option<&'a str> {
    let (at, _) = source.match_indices("function ").find(|(i, _)| {
        let rest = &source[i + 9..];
        rest.starts_with(name) && rest[name.len()..].trim_start().starts_with('(')
    })?;
    let open = at + source[at..].find('{')?;
    let mut depth = 0usize;
    for (k, ch) in source[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&source[open..open + k + 1]);
                }
            }
            _ => {}
        }
    }
    None
}

/// The entry's body, then the bodies of the helper functions it calls (and
/// those they call), so a check made in a helper (`checkValues()`,
/// `payBackAll()`) counts as the entry's own.
pub(crate) fn entry_text(source: &str, name: &str) -> Option<String> {
    let mut text = entry_body(source, name)?.to_string();
    let helpers: Vec<String> = source
        .lines()
        .filter_map(|l| {
            let rest = l.trim().strip_prefix("function ")?;
            let n = rest.split('(').next()?.trim();
            (!n.is_empty() && n.chars().all(is_ident)).then(|| n.to_string())
        })
        .collect();
    let calls = |t: &str, h: &str| {
        t.match_indices(h).any(|(i, _)| {
            t[..i].chars().next_back().is_none_or(|c| !is_ident(c) && c != '.')
                && t[i + h.len()..].trim_start().starts_with('(')
        })
    };
    let mut added: Vec<&String> = Vec::new();
    loop {
        let next = helpers.iter().find(|h| !added.contains(h) && calls(&text, h));
        let Some(h) = next else { break };
        added.push(h);
        if let Some(b) = function_body(source, h) {
            text.push('\n');
            text.push_str(b);
        }
    }
    Some(text)
}

fn parse_int(tok: &str) -> Option<i64> {
    tok.trim().replace('_', "").parse().ok()
}

/// `int constant NAME = 123;` anywhere in the file.
fn int_constants(source: &str) -> BTreeMap<String, i64> {
    let mut out = BTreeMap::new();
    for line in source.lines() {
        let l = line.trim();
        let Some(rest) = l.strip_prefix("int constant ") else { continue };
        let Some((name, value)) = rest.split_once('=') else { continue };
        let value = value.split(';').next().unwrap_or("");
        if let Some(v) = parse_int(value) {
            out.insert(name.trim().to_string(), v);
        }
    }
    out
}

/// Numbers a comment gives for a parameter (`//   period  one month, about
/// 25,920,000 DAA`): tried after the values the code compares against.
fn comment_hints(source: &str, param: &str) -> Vec<i64> {
    let mut out = Vec::new();
    for line in source.lines() {
        let Some(at) = line.find("//") else { continue };
        let comment = &line[at + 2..];
        if !mentions(comment, param) {
            continue;
        }
        // "25,920,000" and "25_920_000" are one number; "2^32" is not.
        let mut tok = String::new();
        let mut prev = ' ';
        for ch in comment.chars().chain(std::iter::once(' ')) {
            let joins = (ch == ',' || ch == '_') && prev.is_ascii_digit();
            if ch.is_ascii_digit() || joins {
                tok.push(ch);
            } else {
                let t = tok.trim_end_matches([',', '_']).replace([',', '_'], "");
                let power = ch == '^' || prev == '^';
                if !power && t.len() >= 3 {
                    if let Ok(v) = t.parse::<i64>() {
                        if !out.contains(&v) {
                            out.push(v);
                        }
                    }
                }
                tok.clear();
            }
            prev = ch;
        }
    }
    out
}

/// One side of a bound: a constructor int, an `int constant`, or a literal.
fn bound_side(tok: &str, ints: &BTreeMap<String, i64>, consts: &BTreeMap<String, i64>) -> Option<(Option<String>, i64)> {
    let t = tok.trim();
    if let Some(v) = parse_int(t) {
        return Some((None, v));
    }
    if let Some(v) = ints.get(t) {
        return Some((Some(t.to_string()), *v));
    }
    consts.get(t).map(|v| (None, *v))
}

/// `require(a OP b)` lines whose two sides are constructor ints, constants or
/// literals (`require(fee >= MIN_LEFTOVER)`, `require(maxNetworkFee < fee)`):
/// they hold on every path that reaches them, so a default that breaks one
/// closes those paths for nothing. Returns new values for the integer
/// parameters the user did not set, so that every such bound holds.
fn bound_fixes(
    text: &str,
    ints: &BTreeMap<String, i64>,
    consts: &BTreeMap<String, i64>,
    fixed: &dyn Fn(&str) -> bool,
) -> BTreeMap<String, i64> {
    let mut bounds: Vec<(String, &'static str, String)> = Vec::new();
    for line in text.lines() {
        let l = line.split("//").next().unwrap_or("").trim();
        let Some(inner) = l.strip_prefix("require(").and_then(|r| r.strip_suffix(");")) else { continue };
        if inner.contains("&&") || inner.contains("||") || inner.contains('(') {
            continue;
        }
        for op in [">=", "<=", "==", "!=", ">", "<"] {
            // Longer operators first, so `>=` is never read as `>`.
            if let Some((a, b)) = inner.split_once(op) {
                bounds.push((a.trim().to_string(), op, b.trim().to_string()));
                break;
            }
        }
    }
    let mut vals = ints.clone();
    let mut changed: BTreeMap<String, i64> = BTreeMap::new();
    for _round in 0..4 {
        let mut again = false;
        for (a, op, b) in &bounds {
            let (Some((pa, va)), Some((pb, vb))) = (bound_side(a, &vals, consts), bound_side(b, &vals, consts)) else {
                continue;
            };
            let holds = match *op {
                ">=" => va >= vb,
                "<=" => va <= vb,
                ">" => va > vb,
                "<" => va < vb,
                "==" => va == vb,
                _ => va != vb,
            };
            if holds {
                continue;
            }
            // Move the side the user left to the tool: the left one first.
            let free = |p: &Option<String>| p.as_ref().filter(|n| !fixed(n)).cloned();
            let (name, want) = match (free(&pa), free(&pb)) {
                (Some(n), _) => (
                    n,
                    match *op {
                        ">=" | "==" => vb,
                        ">" => vb + 1,
                        "<=" => vb,
                        "<" => vb - 1,
                        _ => va + 1,
                    },
                ),
                (None, Some(n)) => (
                    n,
                    match *op {
                        ">=" | "==" => va,
                        ">" => va - 1,
                        "<=" => va,
                        "<" => va + 1,
                        _ => vb + 1,
                    },
                ),
                _ => continue,
            };
            if want < 0 {
                continue;
            }
            vals.insert(name.clone(), want);
            changed.insert(name, want);
            again = true;
        }
        if !again {
            break;
        }
    }
    changed
}

/// Values a parameter is compared against inside an entry, best first:
/// constants and other parameters, then literals, non-zero before zero.
fn candidates(
    body: &str,
    param: &str,
    consts: &BTreeMap<String, i64>,
    others: &BTreeMap<String, i64>,
    hints: &[i64],
) -> Vec<i64> {
    let mut named = Vec::new();
    let mut literal = Vec::new();
    for line in body.lines().filter(|l| mentions(l, param)) {
        if !["<", ">", "=="].iter().any(|op| line.contains(op)) {
            continue;
        }
        for (k, v) in consts {
            if mentions(line, k) {
                named.push(*v);
            }
        }
        for (k, v) in others {
            if k != param && mentions(line, k) {
                named.push(*v);
            }
        }
        for tok in line.split(|c: char| !(c.is_ascii_digit() || c == '_')) {
            if let Some(v) = parse_int(tok) {
                literal.push(v);
            }
        }
    }
    let mut all: Vec<i64> = Vec::new();
    for v in named.iter().chain(literal.iter()).chain(hints.iter()).filter(|v| **v != 0) {
        for x in [*v, v - 1, v + 1] {
            if x > 0 && !all.contains(&x) {
                all.push(x);
            }
        }
    }
    if named.contains(&0) || literal.contains(&0) {
        all.push(0);
    }
    all.truncate(MAX_CANDIDATES);
    all
}

fn explored_names(paths: &[PathStatus]) -> Vec<String> {
    let mut v: Vec<String> = paths.iter().filter(|p| p.baseline.is_some()).map(|p| p.name.clone()).collect();
    v.sort();
    v.dedup();
    v
}

/// Searches `file`, and if paths stay unexplored, tunes integer constructor
/// values the user did not set. Returns the contract and paths to attack.
pub fn tune(file_name: &str, source: &str, overrides: &BTreeMap<String, String>, judge: &Judge) -> Result<Tuned> {
    tune_linked(file_name, source, overrides, &crate::contract::Links::default(), judge)
}

/// `tune` for one contract of a project, with its links to the others.
pub fn tune_linked(
    file_name: &str,
    source: &str,
    overrides: &BTreeMap<String, String>,
    links: &crate::contract::Links,
    judge: &Judge,
) -> Result<Tuned> {
    let contract = Contract::load_linked(file_name, source, overrides, links)?;
    let paths = baseline::search_all(&contract, judge);
    let base_explored = explored_names(&paths);
    let unexplored: Vec<String> =
        contract.entries.iter().map(|e| e.name.clone()).filter(|n| !base_explored.contains(n)).collect();
    if unexplored.is_empty() || baseline::out_of_time() {
        return Ok(Tuned { contract, paths, notes: vec![] });
    }

    let consts = int_constants(source);
    let current: BTreeMap<String, i64> = contract
        .args
        .iter()
        .filter_map(|a| match a.value {
            ArtifactValue::Int(n) => Some((a.name.clone(), n)),
            _ => None,
        })
        .collect();
    // States the default search reached, so later-state paths can be retried there.
    let mut states = vec![None];
    for p in &paths {
        if p.state.is_some() && !states.contains(&p.state) {
            states.push(p.state.clone());
        }
    }

    let mut chosen: BTreeMap<String, (String, String)> = BTreeMap::new();
    // Bounds on constructor values alone (`require(fee >= MIN_LEFTOVER)`, in an
    // entry or a helper it calls): a default that breaks one is simply wrong.
    let fixed = |n: &str| overrides.contains_key(n) || links.ints.contains_key(n);
    for (name, v) in bound_fixes(source, &current, &consts, &fixed) {
        chosen.insert(name, (v.to_string(), BOUND.into()));
    }
    // Those values are the new starting point: search again with them, so the
    // steps below only work on what they leave unexplored (and a flag is not
    // flipped for a path its default already opens).
    let mut unexplored = unexplored;
    let mut bounded: Option<(Contract, Vec<PathStatus>)> = None;
    if !chosen.is_empty() {
        let mut trial = overrides.clone();
        for (k, (v, _)) in &chosen {
            trial.insert(k.clone(), v.clone());
        }
        let opened = Contract::load_linked(file_name, source, &trial, links).ok().and_then(|cb| {
            let pb = baseline::search_all(&cb, judge);
            let eb = explored_names(&pb);
            (eb.len() > base_explored.len() && base_explored.iter().all(|n| eb.contains(n))).then_some((cb, pb))
        });
        match opened {
            Some((cb, pb)) => {
                let eb = explored_names(&pb);
                unexplored.retain(|n| !eb.contains(n));
                for p in &pb {
                    if p.state.is_some() && !states.contains(&p.state) {
                        states.push(p.state.clone());
                    }
                }
                bounded = Some((cb, pb));
            }
            None => chosen.clear(),
        }
    }
    // Flags first: a `bool initialized = true` default closes `init` for good.
    for a in contract.args.iter().filter(|a| !overrides.contains_key(&a.name)) {
        let ArtifactValue::Bool(b) = a.value else { continue };
        if baseline::out_of_time() {
            break;
        }
        let mut trial = overrides.clone();
        for (k, (v, _)) in &chosen {
            trial.insert(k.clone(), v.clone());
        }
        trial.insert(a.name.clone(), (!b).to_string());
        let Ok(c2) = Contract::load_linked(file_name, source, &trial, links) else { continue };
        if let Some(entry) = unexplored.iter().find(|e| {
            !chosen.values().any(|(_, opened)| opened == *e)
                && states
                    .iter()
                    .any(|st| baseline::search_path_budget(&c2, judge, e, st.as_ref(), TUNE_BUDGET).baseline.is_some())
        }) {
            chosen.insert(a.name.clone(), ((!b).to_string(), entry.clone()));
        }
    }
    for entry in &unexplored {
        let Some(text) = entry_text(source, entry) else { continue };
        let body = text.as_str();
        let params: Vec<&String> = current
            .keys()
            .filter(|p| !overrides.contains_key(*p) && !chosen.contains_key(*p) && mentions(body, p))
            .collect();
        'params: for param in params {
            let mut others = current.clone();
            for (k, (v, _)) in &chosen {
                if let Ok(n) = v.parse::<i64>() {
                    others.insert(k.clone(), n);
                }
            }
            for v in candidates(body, param, &consts, &others, &comment_hints(source, param)) {
                if baseline::out_of_time() {
                    break 'params;
                }
                if Some(&v) == current.get(param) {
                    continue;
                }
                let mut trial = overrides.clone();
                for (k, (val, _)) in &chosen {
                    trial.insert(k.clone(), val.clone());
                }
                trial.insert(param.clone(), v.to_string());
                let Ok(c2) = Contract::load_linked(file_name, source, &trial, links) else { continue };
                let opened = states.iter().any(|st| {
                    baseline::search_path_budget(&c2, judge, entry, st.as_ref(), TUNE_BUDGET).baseline.is_some()
                });
                if opened {
                    chosen.insert(param.clone(), (v.to_string(), entry.clone()));
                    break 'params;
                }
            }
        }
    }
    if chosen.is_empty() {
        return Ok(Tuned { contract, paths, notes: vec![] });
    }

    // Keep the tuned set only if it explores at least as much as the defaults.
    let mut trial = overrides.clone();
    for (k, (v, _)) in &chosen {
        trial.insert(k.clone(), v.clone());
    }
    let only_bounds = chosen.values().all(|(_, why)| why == BOUND);
    let (mut tuned, tuned_paths) = match bounded {
        Some(b) if only_bounds => b,
        _ => {
            let t = Contract::load_linked(file_name, source, &trial, links)?;
            let p = baseline::search_all(&t, judge);
            (t, p)
        }
    };
    let tuned_explored = explored_names(&tuned_paths);
    if tuned_explored.len() < base_explored.len() || !base_explored.iter().all(|n| tuned_explored.contains(n)) {
        return Ok(Tuned {
            contract,
            paths,
            notes: vec![
                "constructor tuning found values that opened one path but closed another; kept the defaults".into(),
            ],
        });
    }
    let mut notes = Vec::new();
    for a in tuned.args.iter_mut() {
        if let Some((v, entry)) = chosen.get(&a.name) {
            let default = current.get(&a.name).map(|n| n.to_string()).unwrap_or_else(|| (v != "true").to_string());
            if entry == BOUND {
                a.origin = "tuned to the contract's own bounds".into();
                notes.push(format!(
                    "constructor `{}` set to {v} (default {default} broke a `require` the contract makes on constructor values alone); override with --arg {}=...",
                    a.name, a.name
                ));
                continue;
            }
            a.origin = format!("tuned for `{entry}`");
            notes.push(format!(
                "constructor `{}` set to {v} (default {default} failed a bound in `{entry}`); override with --arg {}=...",
                a.name, a.name
            ));
        }
    }
    Ok(Tuned { contract: tuned, paths: tuned_paths, notes })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_and_candidates() {
        let src = "contract C(int fee, int cap) {\n int constant MIN = 100;\n entry go() {\n require(fee >= MIN && fee <= cap);\n }\n}\n";
        let body = entry_body(src, "go").unwrap();
        let consts = int_constants(src);
        let others: BTreeMap<String, i64> = [("cap".to_string(), 500)].into();
        let c = candidates(body, "fee", &consts, &others, &[]);
        assert_eq!(c[0], 100);
        assert!(c.contains(&500));
    }

    #[test]
    fn helpers_count_as_the_entry() {
        let src = "contract C(int fee) {\n function check() {\n require(fee >= 5);\n inner();\n }\n function inner() {\n require(fee < 9);\n }\n entry go() {\n check();\n }\n}\n";
        let t = entry_text(src, "go").unwrap();
        assert!(t.contains("fee >= 5") && t.contains("fee < 9"));
    }

    #[test]
    fn bounds_on_constructor_values() {
        let src = "int constant MIN = 20000000;\nrequire(fee >= MIN);\nrequire(maxFee >= 0);\nrequire(maxFee < fee);\nrequire(cap > fee);\n";
        let consts = int_constants(src);
        let ints: BTreeMap<String, i64> =
            [("fee".to_string(), 50_000), ("maxFee".to_string(), 50_000), ("cap".to_string(), 1_000)].into();
        let got = bound_fixes(src, &ints, &consts, &|_| false);
        assert_eq!(got.get("fee"), Some(&20_000_000));
        assert_eq!(got.get("cap"), Some(&20_000_001));
        assert!(!got.contains_key("maxFee"));
        // A value the user set is never moved; the other side moves instead.
        let got = bound_fixes(src, &ints, &consts, &|n| n == "fee");
        assert!(!got.contains_key("fee"));
    }

    #[test]
    fn numbers_from_comments() {
        let src = "//   period   one month, about 25,920,000 at 10 per second; below 2^32\ncontract C(int period) {}\n";
        assert_eq!(comment_hints(src, "period"), vec![25_920_000]);
    }
}

/// The numbers that switch a feature on (a DCA interval, a price slope, a
/// start time): compared with 0 (`if (interval > 0)`, `maxFill == 0 ||`,
/// `slope != 0`, `tif == TIF_GTC` with a constant 0) or with the clock
/// (`tx.daa >= activeFrom`, `this.ageDaa >= interval`). Those the user did not
/// set and nothing links go to 0 ("off"); one the source requires to be
/// positive (`require(scale > 0)`, a divisor) keeps its default. Every other
/// number (prices, amounts) keeps its default too. None when nothing changes.
pub fn zero_overrides(
    c: &Contract,
    user: &BTreeMap<String, String>,
    links: &crate::contract::Links,
) -> Option<(BTreeMap<String, String>, Vec<String>)> {
    let flat: String = c.source.split_whitespace().collect();
    // Constants equal to 0 count as 0 (`int constant TIF_GTC = 0;`).
    let zeros: Vec<String> = c
        .source
        .lines()
        .filter_map(|l| {
            let t: String = l.split("//").next().unwrap_or("").split_whitespace().collect();
            let rest = t.strip_prefix("intconstant")?;
            let (name, v) = rest.trim_end_matches(';').split_once('=')?;
            (v == "0").then(|| name.to_string())
        })
        .collect();
    // The value's own name and the state field set from it (`int interval = init_interval;`).
    let names_of = |name: &str| {
        let mut names = vec![name.to_string()];
        for l in c.source.lines() {
            let t = l.split("//").next().unwrap_or("").trim().trim_end_matches(';');
            if let Some((lhs, rhs)) = t.split_once('=') {
                if rhs.trim() == name && lhs.trim_start().starts_with("int ") {
                    if let Some(f) = lhs.split_whitespace().last() {
                        names.push(f.to_string());
                    }
                }
            }
        }
        names
    };
    let has = |pats: Vec<String>| pats.iter().any(|p| {
        // A whole name: the character after it is not part of an identifier.
        let mut from = 0;
        while let Some(at) = flat[from..].find(p.as_str()) {
            let end = from + at + p.len();
            let next = flat[end..].chars().next().unwrap_or(' ');
            let whole = !(p.ends_with(|ch: char| ch.is_alphanumeric() || ch == '_') && (next.is_alphanumeric() || next == '_'));
            // A requirement is not a switch: `require(scale > 0)` always holds.
            // `require(maxFill == 0 || ...)` still is one.
            let required = flat[..from + at].ends_with("require(") && !p.contains("==");
            if whole && (!required || p.starts_with("require(")) {
                return true;
            }
            from = end;
        }
        false
    });
    let mut out = user.clone();
    let mut zeroed = Vec::new();
    for a in c.args.iter().filter(|a| a.ty == "int") {
        if user.contains_key(&a.name) || links.ints.contains_key(&a.name) || a.origin == "override" {
            continue;
        }
        if a.value == ArtifactValue::Int(0) {
            continue;
        }
        let names = names_of(&a.name);
        let positive = names.iter().any(|n| {
            has(vec![format!("require({n}>0)"), format!("require({n}>=1)"), format!("require(0<{n})"), format!("/{n}"), format!("%{n}")])
        });
        let mut switch_pats = Vec::new();
        for n in &names {
            for z in std::iter::once("0".to_string()).chain(zeros.iter().cloned()) {
                switch_pats.extend([format!("{n}>{z}"), format!("{n}!={z}"), format!("{n}=={z}"), format!("{z}<{n}")]);
            }
            switch_pats.extend([format!("tx.daa>={n}"), format!("this.ageDaa>={n}"), format!("{n}<=tx.daa")]);
        }
        // A switch wins over a positive requirement: `if (slope != 0) {
        // require(slope > 0); ... }` asks for a positive slope only when on.
        let _ = positive;
        if !has(switch_pats) {
            continue;
        }
        out.insert(a.name.clone(), "0".into());
        zeroed.push(a.name.clone());
    }
    (!zeroed.is_empty()).then_some((out, zeroed))
}
