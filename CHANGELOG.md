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
