//! Older SilverScript. The language changes, and contracts written for an
//! older compiler stop parsing. When a source fails to parse, `prepare` says
//! plainly that this is a syntax error and, for the changes it knows, tries
//! the same contract in today's syntax. The report notes every rewrite, so
//! nobody mistakes the tested source for the original.
//!
//! Known changes:
//! - SilverScript PR #193 (Aug 3, 2026): struct literals and destructuring
//!   name their type. `State s = { a: x }` became `State s = State { a: x }`,
//!   `validateOutputState(0, { .. })` became `validateOutputState(0, State { .. })`,
//!   `{ a: int x } = readInputState(1);` became `State { a: int x } = readInputState(1);`.

use anyhow::{Result, anyhow};

fn parses(source: &str) -> Result<(), String> {
    silverscript_lang::ast::parse_contract_ast(source).map(|_| ()).map_err(|e| e.to_string())
}

fn ident_at_end(s: &str) -> Option<&str> {
    let t = s.trim_end();
    let start = t.rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).map(|i| i + 1).unwrap_or(0);
    let w = &t[start..];
    (!w.is_empty() && w.chars().next().is_some_and(|c| c.is_ascii_alphabetic())).then_some(w)
}

/// Return types of the contract's own functions: `function f(..) : T {`.
fn return_types(source: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in source.lines() {
        let t = line.trim_start();
        let Some(rest) = t.strip_prefix("function ") else { continue };
        let name: String = rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
        let Some(close) = rest.find(')') else { continue };
        let after = rest[close + 1..].trim_start();
        if let Some(ty) = after.strip_prefix(':') {
            let ty: String = ty.trim_start().chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
            if !ty.is_empty() {
                out.push((name, ty));
            }
        }
    }
    out
}

/// Rewrites pre-#193 struct syntax. Returns the new source and how many places changed.
pub fn upgrade_struct_literals(source: &str) -> (String, usize) {
    let fns = return_types(source);
    let mut n = 0;
    let mut out = String::with_capacity(source.len() + 64);
    for line in source.split_inclusive('\n') {
        let mut l = line.to_string();
        // `T name = {`  ->  `T name = T {`
        if let Some(eq) = l.find("= {").or_else(|| l.find("={")) {
            let brace = eq + l[eq..].find('{').unwrap();
            let lhs = l[..eq].trim_end();
            let mut words = lhs.split_whitespace().rev();
            let (_var, ty) = (words.next(), words.next());
            if let Some(ty) = ty.filter(|t| t.chars().next().is_some_and(|c| c.is_ascii_uppercase())) {
                l = format!("{}{} {}", &l[..brace], ty, &l[brace..]);
                n += 1;
            }
        }
        // `validateOutputState...(i, {`  ->  `(i, State {`
        if l.contains("validateOutputState") {
            if let Some(at) = l.find(", {").or_else(|| l.find(",{")) {
                let brace = at + l[at..].find('{').unwrap();
                l = format!("{}State {}", &l[..brace], &l[brace..]);
                n += 1;
            }
        }
        // `{ a: int x, .. } = expr;`  ->  `T { .. } = expr;`
        let t = l.trim_start();
        if t.starts_with('{') && t.contains("} =") {
            let inner = t[1..].trim_start();
            let looks = inner.split_once(':').is_some_and(|(k, _)| k.trim().chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
            if looks {
                let rhs = &t[t.find("} =").unwrap() + 3..];
                let ty = if rhs.contains("readInputState") || rhs.contains("readOutputState") {
                    Some("State".to_string())
                } else {
                    let callee = rhs.trim_start().split('(').next().and_then(ident_at_end).unwrap_or("");
                    fns.iter().find(|(f, _)| f == callee).map(|(_, ty)| ty.clone())
                };
                if let Some(ty) = ty {
                    let indent = &l[..l.len() - t.len()];
                    l = format!("{indent}{ty} {t}");
                    n += 1;
                }
            }
        }
        out.push_str(&l);
    }
    (out, n)
}

/// Source ready to compile, plus notes for the report. A source that does not
/// parse and cannot be upgraded comes back as an error that says what kind of
/// problem it is.
pub fn prepare(file: &str, source: &str) -> Result<(String, Vec<String>)> {
    let Err(err) = parses(source) else { return Ok((source.to_string(), vec![])) };
    let (up, n) = upgrade_struct_literals(source);
    if n > 0 {
        return match parses(&up) {
            Ok(()) => Ok((
                up,
                vec![format!(
                    "{file} is written in SilverScript from before Aug 3, 2026: struct literals without their type name (`State s = {{ .. }}`), which today's compiler rejects as a syntax error. The tool tested it rewritten in current syntax ({n} place(s), `State s = State {{ .. }}`). Update the source the same way before you deploy with a current compiler. What was tested is today's compile of it: if this contract is already on chain, built by an older compiler, its bytecode may differ, and only its real transactions (--baseline) test exactly what is deployed."
                )],
            )),
            Err(after) => Err(anyhow!(
                "syntax error in {file}. It is written in SilverScript from before Aug 3, 2026: struct literals need their type name now (`MyStruct s = MyStruct {{ .. }}`, `validateOutputState(0, State {{ .. }})`). The tool rewrote {n} of those, and the current compiler still rejects the file here, so something else changed too:\n\n{after}"
            )),
        };
    }
    let hint = if err.contains("expected unary") && (source.contains("= {") || source.contains(", {")) {
        "\n\nThis is a syntax error. It looks like SilverScript from before Aug 3, 2026, when struct literals lost their bare form: write `MyStruct s = MyStruct { a: x };` instead of `MyStruct s = { a: x };`, `validateOutputState(0, State { .. })`, and `State { a: int x } = readInputState(1);` for destructuring."
    } else {
        "\n\nThis is a syntax error: the current SilverScript compiler cannot read this line. If the contract was written for an older SilverScript, part of its syntax may have changed since."
    };
    Err(anyhow!("syntax error in {file}: {err}{hint}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrades_the_three_forms() {
        let src = "        KCC20State st = {\n            amount: a,\n        };\n        validateOutputState(0, { count: c });\n        { x: int inX, y: int inY } = readInputState(1);\n        { amount: int a2 } = load(st);\n    function load(KCC20State s) : KCC20State {\n";
        let (up, n) = upgrade_struct_literals(src);
        assert_eq!(n, 4, "{up}");
        assert!(up.contains("KCC20State st = KCC20State {"));
        assert!(up.contains("validateOutputState(0, State { count: c })"));
        assert!(up.contains("State { x: int inX, y: int inY } = readInputState(1);"));
        assert!(up.contains("KCC20State { amount: int a2 } = load(st);"));
    }
}
