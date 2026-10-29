# Changelog

## Tool 0.2.5 (library 0.2.0)

- `kaspa-redteam serve`: a web page where anyone drops a `.sil` file (plus optional constructor values or a baseline file) and gets the report, the spend map and downloadable repro files. Each scan runs as its own child process in a temporary folder, with a time limit, a 2 GiB memory limit, one scan per visitor and a cap on scans at once; the folder is deleted afterwards.

## Tool 0.2.4 (library 0.2.0)

- Baseline `own`: outputs that belong to the signing user; attacks no longer report a user taking from their own output. Outputs to a listed key's address count as its own automatically.
- Baseline import: only a 65-byte push ending in a sighash type counts as a signature (a KCC-20 transfer's 64-byte argument columns made a path look signed by an outsider).
- Reports say when a finding needs the listed key (a user of the covenant), and the spend map names that signer.

## Tool 0.2.3 (library 0.2.0)

- Baseline `keys`: throwaway private keys the harness signed with. A transaction signature one of them made is signed again after every change, so attacks can alter what that key signed over (the seller's own signature in a market sell, for example). Without keys such a path stays outsider-only, as before.
- Baseline import: a signature on any covenant input, not only a target, now keeps funding coins verbatim.

## Tool 0.2.2 (library 0.2.0)

- Constructor tuning: values a path's own bound checks reject are replaced by ones that open it, verified by an accepted spend, listed as report notes; `--no-tune` turns it off.
- Search: each entry's own reading message ranked first; a bounded first pass so one wrong guess cannot use up the budget.
- Report time now includes the search.

# Attack library changelog

## 0.2.0

- ORC-04: reading signed by a key the covenant never named (oracle pack opens).
- IN-02: attacker coin placed at input 0, for covenants that read `tx.inputs[0]` instead of the active input.
- SEC-01 now also covers signed readings: a reading is public once the honest spend is in the mempool.
- Engine: data-signature paths, stateful covenants (successor outputs and state exploration), stand-in coins for `ScriptPubKeyP2SH(h)` addresses (as outputs and as sibling inputs), exact-deposit coin sizes, baseline import (`--baseline`, BASELINE.md) and `export`.
- Considered and not added: replaying a reading on a second coin at the same address. With outputs pinned it moves nothing anyone did not already get; with outputs open, SEC-01 already reports it.

## 0.1.0

- SIG-01, SIG-02, SEC-01, OUT-01, OUT-02, OUT-03, FEE-01: Tier 1 baseline from the design document.
- IN-01: includes the "second coin left as fee" variant, from MinerDrip v1 (Kaspero Labs, Oct 2026), where two equal coins could share one output.
- MINE-01, NODE-01, NODE-02, NODE-03: node and mining conformance on simnet.
