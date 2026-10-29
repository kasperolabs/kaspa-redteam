# kaspa-redteam

Attack your Kaspa covenant before mainnet does.

```
kaspa-redteam vault.sil
```

One command, no node, no setup. The tool compiles your SilverScript in process, finds an honest spend for every path, then throws a library of known attacks at it. Every hostile transaction is signed for real and judged by rusty-kaspa's own consensus validator. A finding is reported only when consensus **accepted** a transaction the attack expected it to reject, and it ships with the exact transaction so anyone can replay it.

```
kaspa-redteam v0.1.0  minerdrip_v1.sil  (library v0.1.0, covenant target)
 4 attacks run   3 survived   4 skipped   2 FINDINGS   0.0s

[MED]  IN-01 Two covenant coins, one shared set of outputs
  Path `claim`: two coins of this covenant were spent together and both were satisfied
  by the outputs meant for one, so the whole second coin (10 KAS) became fee.
  A miner can do this in their own block and keep it.
  Repro: findings/IN-01.json   replay: kaspa-redteam replay findings/IN-01.json
  Fix pattern: require(tx.inputs.length == 1);
```

(A real bug from a real mainnet covenant, MinerDrip v1, caught in review in October 2026 and fixed in v2. The tool finds it in milliseconds; v2 comes back clean.)

## Install

```
cargo install --git https://github.com/kasperolabs/kaspa-redteam kaspa-redteam
```

Rust 1.94+. The SilverScript compiler and the rusty-kaspa consensus code are library dependencies: nothing else to install, no `silverc` binary, no node.

## Use

```
kaspa-redteam vault.sil                        # attack it
kaspa-redteam vault.sil -v                     # every attack + the spend map
kaspa-redteam vault.sil --arg owner=@alice     # choose constructor values
kaspa-redteam vault.sil --arg cap=500000000    #   ints, 0xhex, true/false, @party
kaspa-redteam vault.sil --only sig,OUT-02      # packs or attack IDs
kaspa-redteam vault.sil --json                 # for CI
kaspa-redteam vault.sil --badge                # clean run: redteam-badge.svg + summary
kaspa-redteam replay findings/*.json           # re-judge saved findings
kaspa-redteam list                             # the attack library
kaspa-redteam node --kaspad ./kaspad           # node and mining packs (local simnet)
```

Exit codes: `0` clean, `1` findings, `2` error.

## How a covenant run works

1. **Compile.** `silverscript-lang` parses and compiles the file in process.
2. **Keys.** Every `pubkey` constructor argument gets its own deterministic test key, so the tool can sign as every party. `byte[32]` hashes are matched to how the source uses them (`blake2b(byte[](pk))` gets a party's key hash, `sha256(secret)` a known preimage). `byte[]` arguments named `...Script` get a party's P2PK script. Override anything with `--arg`.
3. **Spend search.** For each path the engine searches signers, arguments (constructor values and constants found in the script), output shapes, fees and lock values until consensus accepts one honest spend. Locks are bisected so the spend map shows the earliest accepted value.
4. **Attack.** Each attack mutates those honest spends: wrong signer, garbage signature, redirected or reduced outputs, a second covenant coin, value left as fee.
5. **Judge.** `TransactionValidator` from `kaspa-consensus` 2.1.0 (isolation rules, amounts, sequence locks, storage-mass commitment, covenant context, every input script) plus the lock-time finality rule. Mainnet consensus constants; no network.

A path the search cannot spend is reported as **unexplored**, never as safe.

### Threat model (Tier 1)

The attacker holds only their own key, reads the chain and the mempool (so a secret revealed by a pending claim is public), and can build any transaction. An insider abusing their own signature (a payee taking more than their share) needs to know the roles; that is Tier 2.

## Attack library v0.1.0

| ID | Pack | Attack | Catches |
| --- | --- | --- | --- |
| SIG-01 | sig | Invalid signature on a signed path | `checkSig` evaluated but not required |
| SIG-02 | sig | Attacker's own key and signature | Key taken from the spender, not the constructor |
| SEC-01 | secrets | Front-run a revealed secret | Hash lock with no signature and no fixed recipient |
| OUT-01 | outputs | Same value, attacker's script | Recipient not pinned |
| OUT-02 | outputs | Same script, output 0 cut to 10% | Amount not pinned |
| OUT-03 | outputs | Output 0 valid, later output skimmed | Only the first output checked |
| FEE-01 | fees | Outputs halved, rest to fee | No bound on the fee |
| IN-01 | inputs | Second covenant coin, shared outputs | Checks not tied to the active input |
| MINE-01 | mining | Coinbase inflated by 1 sompi | Reward not checked (simnet) |
| NODE-01 | mempool | Spend a coin that does not exist | Missing inputs admitted |
| NODE-02 | mempool | Double-spend a mempool coin | Conflicts admitted without RBF |
| NODE-03 | mempool | Outputs worth more than inputs | Value created in relay |

Planned next (see ROADMAP.md): SIG-03, OUT-04, IN-02, ST-01..03 state packs, AR-01/02 arithmetic, TL-01 lock boundaries, MS-01/02 mass and dust, LIV-01 stuck funds, the oracle pack (datasig paths), KCC-20 pack, and node liveness/flooding packs.

## Node and mining engine

`kaspa-redteam node` starts its own `kaspad --simnet` processes on loopback in a temp directory, mines to coinbase maturity (about two seconds on simnet) and runs the node and mining packs. Before any attack it asks the node for its network and genesis and refuses anything that is not simnet or devnet. There is no flag to point it at mainnet, and no flag to turn the check off.

`REDTEAM_DEBUG=1` prints every node verdict and refusal reason, which is the fastest way to write a new node attack.

## Adding an attack

One file, one registration line, two fixtures. See [ADDING_AN_ATTACK.md](ADDING_AN_ATTACK.md).

```rust
pub struct Out02;
static OUT02: AttackMeta = AttackMeta { id: "OUT-02", pack: "outputs", ... };
impl CovenantAttack for Out02 {
    fn meta(&self) -> &'static AttackMeta { &OUT02 }
    fn attempts(&self, cx: &AttackCx) -> Result<Vec<Attempt>, String> { ... }
}
inventory::submit! { CovenantPlugin(&Out02) }
```

`cargo test` fails if an attack has no fixtures, misses its vulnerable fixture, or raises anything on its fixed fixture.

## Layout

```
crates/redteam-core       findings, report, badge, shared types
crates/redteam-covenant   compile, spend search, judge, covenant attacks
crates/redteam-node       simnet harness, mainnet guard, node/mining attacks
crates/kaspa-redteam      the CLI
fixtures/<ID>/            vulnerable.sil + fixed.sil per attack
corpus/                   real covenants the library is run against
```

## Safety

Simnet and in-process only. Finding files target sandbox UTXOs, not live coins. A finding against someone else's deployed contract goes privately to its author first (see SECURITY.md).

## License

MIT
