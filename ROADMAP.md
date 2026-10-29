# Roadmap

## v0.1

- Covenant engine: in-process compile, spend search with lock bisection, consensus judge, replayable findings, badge.
- 8 covenant attacks with fixtures: SIG-01, SIG-02, SEC-01, OUT-01, OUT-02, OUT-03, FEE-01, IN-01.
- Node engine: simnet harness, mainnet guard, MINE-01, NODE-01..03.
- Corpus: Kaspero Labs covenants (MinerDrip v1/v2, Pledge v3, ClaimTicket, DamageDeposit).

## v0.2 (this release)

- Data-signature paths, ORC-04, SEC-01 extended to readings.
- Stateful covenants: successor outputs, breadth-first state exploration.
- Stand-in coins for P2SH-named addresses, as outputs and sibling inputs; IN-02.
- Exact-deposit coin sizes; signer ranking from `checkSig(param, key)` in the source.
- Baseline import and export (BASELINE.md).

## v0.2.2

- Constructor tuning from the bounds each entry checks, verified by search.

## Next, in order

1. **Wider spend search.** Array and struct arguments; covenant declarations (`#[covenant]` continuation outputs and covenant IDs).
2. **Remaining Tier 1:** ST-01..03 (state rollback and replay, malformed and maximum-size state; states are now explored, so these come first), SIG-03 (signature reused across paths), OUT-04 (reorder), TL-01 (lock off-by-one, using the bisected boundary), MS-01/02 (mass limit and dust outputs, judged against relay policy as well as consensus), LIV-01 (state with no valid spend).
3. **GitHub Action** that runs on every `.sil` in a repo, comments the report on the PR, fails on findings.
4. **Tier 2 spec** (`redteam.yaml`): roles (who may be paid what), invariants, property search and shrinking, the rest of the oracle pack (ORC-01..03, 05, 06: stale, replayed, extreme, missing and mismatched readings).
5. **Node packs:** mempool flooding and eviction, orphan pool limits, RBF rules, block template inclusion, p2p message fuzzing on a multi-node simnet, liveness under load.
6. **KCC-20 pack** (mint without lock, burn accounting, gas-tank drain).
7. Read-only `scan <address>`: fetch a deployed script, report known-vulnerable patterns, build nothing.

## Open questions

- License: MIT for now; whether attacks need a license that discourages mainnet packaging.
- A second maintainer for attack PRs before the plugin docs are announced.
- KEF endorsement of the disclosure policy.
