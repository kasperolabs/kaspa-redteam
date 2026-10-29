# Roadmap

## v0.1

- Covenant engine: in-process compile, spend search with lock bisection, consensus judge, replayable findings, badge.
- 8 covenant attacks with fixtures: SIG-01, SIG-02, SEC-01, OUT-01, OUT-02, OUT-03, FEE-01, IN-01.
- Node engine: simnet harness, mainnet guard, MINE-01, NODE-01..03.
- Corpus: Kaspero Labs covenants (MinerDrip v1/v2, Pledge v3, ClaimTicket, DamageDeposit).

## v0.2

- Data-signature paths, ORC-04, SEC-01 extended to readings.
- Stateful covenants: successor outputs, breadth-first state exploration.
- Stand-in coins for P2SH-named addresses, as outputs and sibling inputs; IN-02.
- Exact-deposit coin sizes; signer ranking from `checkSig(param, key)` in the source.
- Baseline import and export (BASELINE.md).

## v0.2.2

- Constructor tuning from the bounds each entry checks, verified by search.

## v0.2.3 to v0.2.5

- Baseline keys (`keys`, re-signed signatures) and own outputs (`own`); `serve`, the web page.

## v0.3 (this release)

- Covenant families: covenant ids and bound successor outputs, struct and struct-array arguments filled from the transaction, signatures inside `byte[]` witnesses, delegate entries beside a leader, own template hash, loop-bound and flag defaults. The KCC-20 reference program's `transfer` and `transfer_delegator` are now explored and attacked from the `.sil` alone.
- ST-01 (rewrite the recorded owner of the next state).

## Next, in order

1. **Sibling programs** (`--with other.sil`): coins of a second program in the same transaction, for contracts that pin another program's template (a market over a KCC-20 token, a minter). Their states are tied to the main contract by arithmetic, so this needs hints or a spec; until then, a baseline.
2. **Remaining Tier 1:** ST-02/03 (state rollback and replay, malformed and maximum-size state; states are now explored, so these come first), SIG-03 (signature reused across paths), OUT-04 (reorder), TL-01 (lock off-by-one, using the bisected boundary), MS-01/02 (mass limit and dust outputs, judged against relay policy as well as consensus), LIV-01 (state with no valid spend).
3. **GitHub Action** that runs on every `.sil` in a repo, comments the report on the PR, fails on findings.
4. **Tier 2 spec** (`redteam.yaml`): roles (who may be paid what), invariants, property search and shrinking, the rest of the oracle pack (ORC-01..03, 05, 06: stale, replayed, extreme, missing and mismatched readings).
5. **Node packs:** mempool flooding and eviction, orphan pool limits, RBF rules, block template inclusion, p2p message fuzzing on a multi-node simnet, liveness under load.
6. **KCC-20 pack** (mint without lock, burn accounting, gas-tank drain).
7. Read-only `scan <address>`: fetch a deployed script, report known-vulnerable patterns, build nothing.

## Open questions

- License: MIT for now; whether attacks need a license that discourages mainnet packaging.
- A second maintainer for attack PRs before the plugin docs are announced.
- KEF endorsement of the disclosure policy.
