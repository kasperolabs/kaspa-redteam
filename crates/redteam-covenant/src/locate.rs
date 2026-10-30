//! Where in the source a finding's fix belongs: the line of the entry that
//! does (or should do) the check the attack got past, with a line either side.

use redteam_core::Location;

/// `path` is a spend-map path (`settle+transfer[n>0]`, `minted:transfer`); its
/// entry is the name before any `+`, `[` or `@`.
pub fn locate(source: &str, path: &str, id: &str) -> Option<Location> {
    let entry = path.trim_start_matches("minted:");
    let entry = entry.split(|c| c == '+' || c == '[' || c == '@').next()?.trim();
    let lines: Vec<&str> = source.lines().collect();
    let head = lines.iter().position(|l| {
        let t = l.trim_start();
        t.starts_with(&format!("entry {entry}(")) || t.starts_with(&format!("entry {entry} ("))
    })?;
    // The entry's body: to the brace that closes it.
    let mut depth = 0i32;
    let mut end = head;
    for (i, l) in lines.iter().enumerate().skip(head) {
        let code = l.split("//").next().unwrap_or("");
        depth += code.matches('{').count() as i32 - code.matches('}').count() as i32;
        end = i;
        if i > head && depth <= 0 {
            break;
        }
    }
    // Each pattern: every part must be on the line. Tried in order.
    let patterns: &[&[&str]] = match id {
        "FAM-10" => &[&["OpInputCovenantId(", "=="], &["readInputStateWithTemplate("], &["OpCovInputCount("]],
        "FAM-04" => &[&["OpOutputCovenantId("], &["OpCovOutputIdx("], &["validateOutputState"]],
        "FAM-01" | "FAM-02" | "FAM-03" | "FAM-08" => &[
            &["validateOutputStateWithTemplate"],
            &["validateOutputStateWithInputTemplate"],
            &["validateOutputState("],
            &["OpCovOutputCount("],
        ],
        "FAM-05" => &[&["OpCovOutputCount("], &["scriptPubKey"]],
        "FAM-09" | "OUT-02" | "OUT-04" | "FEE-01" => &[&[".value >="], &[".value =="], &[".value <="], &["tx.outputs["]],
        "OUT-01" | "OUT-03" => &[&["scriptPubKey"], &["tx.outputs["]],
        x if x.starts_with("SIG") => &[&["checkSig"]],
        _ => &[],
    };
    let at = patterns
        .iter()
        .find_map(|p| {
            (head + 1..=end).find(|i| {
                let code = lines[*i].split("//").next().unwrap_or("");
                p.iter().all(|part| code.contains(part))
            })
        })
        .unwrap_or(head);
    let from = at.saturating_sub(1).max(head);
    let to = (at + 1).min(end);
    Some(Location { line: at + 1, lines: (from..=to).map(|i| (i + 1, lines[i].trim_end().to_string())).collect() })
}

#[cfg(test)]
mod tests {
    #[test]
    fn finds_the_token_check() {
        let src = "contract A() {\n    entry settle(int n) {\n        int self = 0;\n        require(OpInputCovenantId(1) == x);\n        require(n > 0);\n    }\n}\n";
        let l = super::locate(src, "settle+transfer[n>0]", "FAM-10").unwrap();
        assert_eq!(l.line, 4);
        assert_eq!(l.lines.len(), 3);
        let l = super::locate(src, "settle", "XYZ").unwrap();
        assert_eq!(l.line, 2);
    }
}
