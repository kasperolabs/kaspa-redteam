# kaspa-redteam

Attack your Kaspa covenant before mainnet does.

```
kaspa-redteam vault.sil
```

**Try it in the browser, nothing to install: [redteam.kasperolabs.com](https://redteam.kasperolabs.com)** (drop a `.sil` file, get the report).

One command, no node, no setup. The tool compiles your SilverScript in process, finds an honest spend for every path, then throws a library of known attacks at it. Every hostile transaction is signed for real and judged by rusty-kaspa's own consensus validator. A finding is reported only when consensus **accepted** a transaction the attack expected it to reject, and it ships with the exact transaction so anyone can replay it.

```
kaspa-redteam v0.2.0  minerdrip_v1.sil  (library v0.2.0, covenant target)
 5 attacks run   4 survived   5 skipped   2 FINDINGS   0.0s

[MED]  IN-01 Two covenant coins, one shared set of outputs
  Path `claim`: two coins of this covenant were spent together and both were satisfied
  by the outputs meant for one, so the whole second coin (10 KAS) became fee.
  A miner can do this in their own block and keep it.
  Repro: findings/IN-01.json   replay: kaspa-redteam replay findings/IN-01.json
  Fix pattern: require(tx.inputs.length == 1);
```

(A real bug from a real mainnet covenant, MinerDrip v1, caught in review in October 2026 and fixed in v2. The tool finds it in milliseconds; v2 comes back clean.)

Want to see it work first? `examples/` has everyday contract shapes in a broken (`_FAIL`) and a fixed (`_PASS`) version: see [examples/README.md](examples/README.md).

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
kaspa-redteam vault.sil --arg cap=500000000    #   ints, 0xhex, true/false, @party, kaspa:... address
kaspa-redteam vault.sil --args deploy.json     # constructor values from the JSON you deploy with
kaspa-redteam vault.sil --args deploy.json --compiled build.json   # test your compiler's exact bytes
kaspa-redteam vault.sil --no-tune              # keep default constructor values as they are
kaspa-redteam vault.sil --deadline 60          # stop searching after 60 s, still attack and report what was found
kaspa-redteam vault.sil --only sig,OUT-02      # packs or attack IDs
kaspa-redteam vault.sil --json                 # for CI
kaspa-redteam vault.sil --badge                # clean run: redteam-badge.svg + summary
kaspa-redteam treasury.sil fund.sil -v         # several files that work together: one project
kaspa-redteam --baseline honest.json           # attack transactions from your own harness
kaspa-redteam export vault.sil > example.json  # the honest spends found, as a baseline file
kaspa-redteam replay findings/*.json           # re-judge saved findings
kaspa-redteam list                             # the attack library
kaspa-redteam node --kaspad ./kaspad           # node and mining packs (local simnet)
kaspa-redteam node --kaspad ./kaspad --nodes 2 --keep   # two linked nodes, keep their data dirs
kaspa-redteam serve --port 8790                # the web page: drop a .sil in a browser
```

Common flags: `--out DIR` (where finding files go, default `findings/`), `--no-color`, and `--only`, `--json`, `-v`, `--badge` work on `node` runs too. `kaspa-redteam --help` and `kaspa-redteam <command> --help` list everything.

Exit codes: `0` clean, `1` findings, `2` error.

### Constructor values from your deploy file

`--args FILE` reads the same values you deploy with, so the contract is tested with your numbers, hashes and templates instead of the tool's defaults. `--arg` still wins over the file. On the web page, open "Constructor values" under the file: every parameter of the contract is listed with the value the tool would use, and you change only the ones you know. "Paste values instead" takes `NAME=VALUE` lines or this JSON. When a run leaves paths unexplored, the report links back to the form.

```
{ "cap": 500000000, "feeScript": "0x...", "tokenTemplate": "0x..." }     by name
[ "0x...", 500000000, true ]                                             in constructor order (one contract)
{ "constructorArgs": { ... } }  or  [ { "name": "cap", "value": 500000000 } ]
```

The tool can only spend what it holds the secrets for, so a few values are played by the tool, and the report lists which: `pubkey` parameters become test keys of the same name (`@owner`), and a `byte[32]` used as a key, a key hash or a hash lock gets a test key or the hash of a test secret. Everything else is used exactly as given.

### Your compiler's exact bytes

If you build with a pinned SilverScript, test what you will deploy rather than today's compile of the source:

```
kaspa-redteam vault.sil --args deploy.json --compiled build.json
```

`--compiled` takes your compiler's JSON output (any JSON with a `bytecode`, `redeemScript` or `script` hex, top level or under the contract) or a plain hex file. The `.sil` is still needed: the tool reads its entries and parameters, and the hints its search uses, from the source. `--args` gives the values the script was compiled with.

The bytes are used as they are, with one exception: keys, key hashes and hash locks the tool plays are 32-byte pushes, and it swaps each one for its own (same length, nothing else moves), so it can sign and reveal. The report gives the script's sha256, says whether today's compile is identical, and lists the swapped values. The tool refuses the file, instead of testing something else, when a value from `--args` is not in the script, when an entry's dispatch tag is missing, or when it cannot find the starting state. On the web page: "Compiled script (advanced)".

### Older SilverScript

The language still changes, and the tool compiles with the current SilverScript. A file that does not parse is reported as a syntax error, in those words. For the changes it knows, the tool tests the file rewritten in current syntax and says so in the report:

- Aug 3, 2026 (SilverScript PR #193): struct literals and destructuring name their type. `State s = { a: x }` is now `State s = State { a: x }`, `validateOutputState(0, { .. })` is `validateOutputState(0, State { .. })`, and `{ a: int x } = readInputState(1);` is `State { a: int x } = readInputState(1);`.

What is tested is today's compile. A contract already on chain keeps the bytecode an older compiler made, which may differ; to test exactly what is deployed, give its real transactions with `--baseline`.

### Projects: several contracts that work together

Real systems are often more than one `.sil` file: a treasury and its department funds, a token and the market that sells it. Give all the files in one run and they are treated as one program:

```
kaspa-redteam town_treasury.sil department_fund.sil -v
kaspa-redteam curve.sil kcc20.sil --arg SUPPLY=1000000    # --arg goes to whichever file has that parameter
```

The tool reads how the contracts refer to each other and wires them together instead of using stand-ins:

- **address**: a `byte[32]` parameter used as a P2SH target whose name matches another file (`treasury` and `TownTreasury`) gets that contract's real script, so money paid to it goes to the actual program and is checked there.
- **template**: a `byte[32]` constant or value equal to another file's template hash (a market pinning its token's program) is detected and reported.

The report starts with the links it found, so you can check it understood the project, then each contract's results. Findings go to `out/<file stem>/`. `--json` gives `{ "project": { "files", "links", "millis" }, "reports": [ ... ] }`. `--baseline` is for single contracts only.

Not yet covered: spends that need the linked contracts' own coins in the same transaction (a market buy that moves a token cell). Those paths show as unexplored; cover them with a baseline from your own harness for now. Building them from the source is the next step.

## Web page

```
kaspa-redteam serve                                # http://127.0.0.1:8790
kaspa-redteam serve --port 8790 --jobs 2 --timeout 120 --threads 4
```

A single page where anyone can drop a `.sil` file (or several that work together, tested as one project), or paste one,, optionally add constructor values or a baseline file, and get the same report the command line gives: verdict, findings with fix patterns, the spend map, every attack's result, and the repro files to download. The page is built into the binary; there is nothing else to install.

Every scan runs as a separate child process of the same binary, in a fresh temporary folder that is deleted when it ends. Limits: the search stops at two thirds of `--timeout` (`--deadline`) so the attacks still run and a report always comes back, and the scan is killed at `--timeout` seconds (default 120), 2 GiB of memory, `--threads` worker threads per scan, one running scan per visitor and `--jobs` scans at once (others are told to try again). Uploads are capped at 1 MiB in total, 256 KiB and 8 files per scan. Nothing is logged or kept.

It listens on `127.0.0.1` by default. For a public site, put a reverse proxy in front; the server reads the visitor's address from `X-Real-IP` or `X-Forwarded-For` when the request comes from the same machine. nginx:

```
server {
    server_name redteam.example.com;
    client_max_body_size 2m;
    location / {
        proxy_pass http://127.0.0.1:8790;
        proxy_set_header Host $host;                # link previews use it for absolute URLs
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 180s;
    }
}
```

Behind Cloudflare (orange-cloud proxy): pass the visitor's real address with `proxy_set_header X-Real-IP $http_cf_connecting_ip;` instead, or every visitor looks like a Cloudflare server and they block each other's scans. Cloudflare also gives up on a request after 100 seconds on its free plan, so run `serve` with `--timeout 90`.

Keep it running with pm2 (`pm2 start /path/to/kaspa-redteam --name redteam-web -- serve --port 8790`) or a systemd unit. After pulling a new version and rebuilding, restart it so it serves the new binary.

| Route | What |
| --- | --- |
| `GET /` | the page |
| `POST /api/scan` | `{ filename, source, args: ["name=value"], baseline, baseline_name }` → `{ report, files }` (`report` is the `--json` report) |
| `POST /api/params` | `{ files: [{ filename, source }] }` → each contract's constructor parameters with the value the tool would use and whether it plays them (`kaspa-redteam params FILE...`) |
| `POST /api/scan` (project) | `{ files: [{ filename, source }], args }` → `{ report: { project, reports }, files }`; finding files are named `<stem>/<ID>.json` |
| `GET /api/library` | the attack library |
| `GET /og.png` | the link-preview card (Open Graph / X) |
| `GET /api/examples` | the examples the page offers, broken and fixed, with the bug and the fix in plain words |
| `GET /api/example` | one vulnerable example contract |
| `GET /health` | `ok` |

## How a covenant run works

1. **Compile.** `silverscript-lang` parses and compiles the file in process.
2. **Keys and constants.** Every `pubkey` constructor argument gets its own deterministic test key, so the tool can sign as every party. `byte[32]` values are matched to how the source uses them: `blake2b(byte[](pk))` gets a party's key hash, `sha256(secret)` a known preimage, `ScriptPubKeyP2SH(h)` the address of a stand-in covenant anyone can spend. `byte[]` arguments named `...Script` get a party's P2PK script. Override anything with `--arg`.
3. **Spend search.** For each path the engine searches signers (the key the source checks each signature against comes first), arguments (constructor values and constants found in the script), coin sizes, output shapes, fees and lock values until consensus accepts one honest spend. Locks are bisected so the spend map shows the earliest accepted value.
   - **Signed readings** (`checkMsgSig`): messages are assembled from what the script compares them with (4-byte tags, `byte[32]` ids, required lengths, constructor values in trailing fields) and signed by the party the source names.
   - **Stateful covenants** (`validateOutputState`): successor outputs carry re-encoded state, and every new state an accepted spend reaches is explored in turn, so paths that only open later (`claim` after `approve`) get attacked too.
   - **Sibling coins**: a stand-in coin can sit next to the covenant, for paths that require another covenant's coin as an input.
   - **Covenant families** (KCC-20 and anything else that reads `OpInputCovenantId`, `OpCovInputCount`, `OpAuthOutputCount`): sandbox coins carry a covenant id, successor outputs are bound to it (transaction version 1), state-shaped arguments (`KCC20State[] next_states`, `State newState`) are filled from the successor outputs they must match, a signature can sit inside a `byte[]` witness (`0x00 ‖ sig`), and delegate entries are tried as a second coin beside an explored leader. A `byte[32] ...template` constructor value is set to the program's own template hash. Constructor ints used as loop bounds get small values, and `bool` flags are flipped when the default closes a path.
4. **Tuning.** If a path stays unexplored, the tool reads the comparisons that entry makes on integer constructor parameters (`require(cancelFee >= MIN_OUT && cancelFee <= maxFare)`), tries the values they compare against (`int constant`s, literals, other parameters), and keeps one only when it opens the path without closing another. Every tuned value is listed in the report as a `note: constructor ... set to ...` line; `--arg` overrides it and `--no-tune` turns tuning off.
5. **Attack.** Each attack mutates those honest spends: wrong signer, garbage signature, forged reading, reused secret, redirected or reduced outputs, a second covenant coin, an attacker coin in front, value left as fee.
6. **Judge.** `TransactionValidator` from `kaspa-consensus` 2.1.0 (isolation rules, amounts, sequence locks, storage-mass commitment, covenant context, every input script) plus the lock-time finality rule. Mainnet consensus constants; no network.

### Reading the report

- `N attacks run / survived / skipped`: an attack is skipped when no explored path is one it applies to (signature attacks on a contract with no signed path, say). Skipped is neither a pass nor a fail.
- `-v` adds the **spend map**: for every path, who can spend it, where the honest spend paid, and the earliest lock value consensus accepted. Read it first; it is the tool's understanding of your contract.
- `note: constructor ... set to ...`: a value the tool tuned so a path could be explored. The findings hold for that value; if your deployment uses a different one, pass it with `--arg`.
- `note: path ... unexplored`: the path was not attacked. Clean results say nothing about it.

A path the search cannot spend is reported as **unexplored**, never as safe. For those, two ways in: `--arg` values the search could not guess, or a **baseline file**: honest transactions from your own test harness, which the attacks then mutate. That covers what the search cannot build from one file: another program's coins (a market that only accepts a coin of a pinned KCC-20 template), states tied together by real arithmetic, genesis transactions. Format and a JavaScript emitter: [BASELINE.md](BASELINE.md). A baseline can list the throwaway keys it was signed with (`"keys"`), so the attacks can re-sign after changing a transaction and test what a signing user could get away with.

### Threat model (Tier 1)

The attacker holds only their own key, reads the chain and the mempool (so a secret revealed by a pending claim is public), and can build any transaction. An insider abusing their own signature (a payee taking more than their share) needs to know the roles; that is Tier 2.

## Attack library v0.3.1

| ID | Pack | Attack | Catches |
| --- | --- | --- | --- |
| SIG-01 | sig | Invalid signature on a signed path | `checkSig` evaluated but not required |
| SIG-02 | sig | Attacker's own key and signature | Key taken from the spender, not the constructor |
| ST-01 | state | Attacker's key written into the next state | Owner recorded in state, but anyone may move the coin |
| SEC-01 | secrets | Front-run a revealed secret or reading | Hash lock or signed reading with no spender signature and no fixed recipient |
| ORC-04 | oracle | Reading signed by the attacker's own key | Oracle or conductor key not pinned |
| OUT-01 | outputs | Same value, attacker's script | Recipient not pinned |
| OUT-02 | outputs | Same script, output 0 cut to 10% | Amount not pinned |
| OUT-03 | outputs | Output 0 valid, later output skimmed | Only the first output checked |
| OUT-04 | outputs | Keep what the fixed payouts leave over | Payouts fixed, but nothing ties them to the coin's value |
| FEE-01 | fees | Outputs halved, rest to fee | No bound on the fee |
| IN-01 | inputs | Second covenant coin, shared outputs | Checks not tied to the active input |
| IN-02 | inputs | Attacker coin at input 0 | Values read from `tx.inputs[0]` instead of `this.activeInputIndex` |
| MINE-01 | mining | Coinbase inflated by 1 sompi | Reward not checked (simnet) |
| NODE-01 | mempool | Spend a coin that does not exist | Missing inputs admitted |
| NODE-02 | mempool | Double-spend a mempool coin | Conflicts admitted without RBF |
| NODE-03 | mempool | Outputs worth more than inputs | Value created in relay |

Planned next (see ROADMAP.md): ST-02/03 state packs, AR-01/02 arithmetic, TL-01 lock boundaries, MS-01/02 mass and dust, LIV-01 stuck funds, the rest of the oracle pack, KCC-20 pack, and node liveness/flooding packs.

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
