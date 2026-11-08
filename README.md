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
kaspa-redteam fetch <txid>... -o real.json     # real mainnet/testnet transactions as a baseline file
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
[ "0x...", 500000000, true ]                                             in constructor order
{ "constructorArgs": { ... } }  or  [ { "name": "cap", "value": 500000000 } ]
[ { "kind": "bytes", "value": [3, 3, ...] }, { "kind": "int", "value": 1 } ]   silverc's own file
```

silverc's constructor file works as it is: values in order, each with its `kind` (`int`, `bool`, `byte` as a number; `bytes` or `pubkey` as an array of byte numbers or a hex string). A value whose kind does not fit its parameter is refused with its position. Values in order belong to one contract; in a project (several files) they go to the one contract whose parameters they fit by count and kind, and the report says which. When more than one fits, give them by name.

The tool can only spend what it holds the secrets for, so a few values are played by the tool, and the report lists which: `pubkey` parameters become test keys of the same name (`@owner`), and a `byte[32]` used as a key, a key hash or a hash lock gets a test key or the hash of a test secret. Everything else is used exactly as given.

### Your compiler's exact bytes

If you build with a pinned SilverScript, test what you will deploy rather than today's compile of the source:

```
kaspa-redteam vault.sil --args deploy.json --compiled build.json
```

`--compiled` takes your compiler's JSON output (any JSON with a `bytecode`, `redeemScript` or `script` hex, top level or under the contract) or a plain hex file. The `.sil` is still needed: the tool reads its entries and parameters, and the hints its search uses, from the source. `--args` gives the values the script was compiled with.

The bytes are used as they are, with one exception: keys, key hashes and hash locks the tool plays are 32-byte pushes, and it swaps each one for its own (same length, nothing else moves), so it can sign and reveal. The report gives the script's sha256, says whether today's compile is identical, and lists the swapped values. The tool refuses the file, instead of testing something else, when a value from `--args` is not in the script, when an entry's dispatch tag is missing, or when it cannot find the starting state. On the web page: "Compiled script (advanced)".

### ZK covenants

A covenant that checks a Groth16 proof (`r0.g16.verify`, `g16.verify`) cannot be spent without one, and the tool cannot make a real proof; that is the point of the proof. So in the sandbox it swaps the verifying key the script pushes for a test key of its own, built so that its one test proof verifies for any public inputs (the same idea as a prover's dev mode). A `proof` argument gets that proof, and a `journal` argument is laid out the way the entry reads it: every `journal.slice(a, b) == value` check places that constructor or state value at its offset, and a slice returned into the next state keeps the current value.

That tests everything around the proof: whether the covenant binds its outputs to what the journal says, whether a proof copied from the mempool can be reused with other outputs, whether value can move without one. It does not test the circuit, or whether the key in the script is the right one. The report says so in a note. `examples/zk_payout_FAIL.sil` pays whoever submits a valid proof (SEC-01: copy it from the mempool); `_PASS` binds the payout to the key the journal names.

### Older SilverScript

The language still changes, and the tool compiles with the current SilverScript. A file that does not parse is reported as a syntax error, in those words. For the changes it knows, the tool tests the file rewritten in current syntax and says so in the report:

- Aug 3, 2026 (SilverScript PR #193): struct literals and destructuring name their type. `State s = { a: x }` is now `State s = State { a: x }`, `validateOutputState(0, { .. })` is `validateOutputState(0, State { .. })`, and `{ a: int x } = readInputState(1);` is `State { a: int x } = readInputState(1);`.

What is tested is today's compile. A contract already on chain keeps the bytecode an older compiler made, which may differ; to test exactly what is deployed, give its real transactions with `--baseline`.

Argent files (`.ag`) are not SilverScript. A dropped `.ag` gets a plain message instead of a syntax error: compile it with argentc and test the `sil/*.sil` files it generates, together, in one run. An Argent file that only declares an interface for contracts written in SilverScript needs no testing of its own; test those `.sil` files.

### Real transactions from mainnet or testnet

```
kaspa-redteam fetch 3f1c...e9:buy 77ab...02:sell -o real.json   # :name is optional
kaspa-redteam --baseline real.json                              # attack them
kaspa-redteam curve.sil --baseline real.json                    # with the source, paths get its names
kaspa-redteam fetch <txid> --network testnet-10 -o real.json
kaspa-redteam fetch <txid> --node ws://127.0.0.1:17110 -o real.json   # from your own node
```

`fetch` pulls each transaction and every coin it spent, and writes a baseline file (format: [BASELINE.md](BASELINE.md)). It is the only command that goes online; the scan itself stays offline, so the file can be kept, shared and run again.

- By default everything comes from the public Kaspa REST API (`api.kaspa.org`; `--network testnet-10` or `testnet-11` for those, `--api URL` for any other kaspa-rest-server). With `--node` the transactions, the spent coins and the block data come from your node over wRPC (Borsh); the API is then only asked which block holds each transaction, because a node cannot look one up by id. A pruned node only has recent blocks; an archival node has them all.
- `daaScore` and `pastMedianTime` come from the block that accepted each transaction (its DAA score, and its timestamp in place of its past median time, which no RPC gives for an old block; the timestamp is at most a few minutes later).
- Every rebuilt transaction must hash to the id you asked for, and consensus must accept it as fetched, or nothing is written.
- Transactions with no covenant input (plain payments) are left out.
- The keys that signed a real transaction are not yours to give, so the tool cannot sign again after changing it: a path a signature commits to is only tested for changes that break that signature. Permissionless paths (anyone can spend, given the right outputs) are tested in full, which is where most covenant bugs live.
- When the covenant under test is unsigned and only a trader signed (a buyer's coin, a seller's KCC-20 cell), the trader's seat goes to the tool's own test key: that key's coins and token cells, the outputs that paid it and the new token cells it got all become the test key's, and the signatures are made again after every change. The covenant's own coins and state are never touched. The trade is kept this way only if consensus still accepts it, and the report says so (`the coins and token cells of key 89f4... (the trader) were given to the tool's attacker key`).

### Known programs: KCC-20 cells in real transactions

A market's real transactions spend token cells too, and those run a program you did not hand over. The KCC-20 reference programs (argent-lang/kcc20-reference at c8a0871: `KCC20`, `PublicMint`, `TokenSeed`) ship with the tool in `crates/redteam-covenant/library/kcc20-reference/`. A coin whose redeem script is one of them, byte for byte outside its state window, is recognized by its KCC-1 template hash (BLAKE3 of the program with the state cut out; KCC20 is `9703112e...`). Exact matching only: a copy that differs by one byte is not the reference and stays opaque. When one is recognized:

- The report names it: `recognized KCC20 at input 1 by template hash 9703112ee6e3... (argent-lang/kcc20-reference@c8a0871); a KCC-20 cell of 3000000 units, owner scheme 4 (covenant id), borrowing off, spent through transfer`.
- It is a partner, not the covenant under test (unless the transaction has no other covenant input): the input attacks target the market, not the token.
- The owner's signature inside the token witness (`transfer(next_states, witness)`, the path byte then the signature) counts as a signature, and the spend map says whose: `signed by the owner of the KCC20 coin at input 1 (signature inside its token witness)`.
- Its signature script and the token outputs can be rebuilt, so the family and borrow attacks run on the real transaction: a second cell the covenant owns spent next to the first and paid to the attacker (FAM-10), the covenant's tokens leaving while its own coin keeps its KAS (FAM-09), the covenant's cell with borrowing on (BOR-01), or already borrowable on chain (BOR-02). Each hostile version is checked first: if the token program itself rejects it, it was built wrong, it is dropped with a note, and it does not count as survived.

The other family attacks (FAM-01 to FAM-08) need the search's own draft and run only from sources.

### Projects: several contracts that work together

Real systems are often more than one `.sil` file: a treasury and its department funds, a token and the market that sells it. Give all the files in one run and they are treated as one program:

```
kaspa-redteam town_treasury.sil department_fund.sil -v
kaspa-redteam curve.sil kcc20.sil --arg SUPPLY=1000000    # --arg goes to whichever file has that parameter
```

The tool reads how the contracts refer to each other and wires them together instead of using stand-ins:

- **address**: a `byte[32]` parameter used as a P2SH target whose name matches another file (`treasury` and `TownTreasury`) gets that contract's real script, so money paid to it goes to the actual program and is checked there.
- **template**: a `byte[32]` constant or value equal to another file's template hash (a market pinning its token's program) is detected and reported.

The report starts with the links it found, so you can check it understood the project, then each contract's results. Findings go to `out/<file stem>/`. `--json` gives `{ "project": { "files", "baselines", "links", "millis" }, "reports": [ ... ] }`.

With `--baseline` (or real transactions) next to several files, each file is attacked as above and the transactions get one more report, `real.json (real transactions)`. Every file with a state window becomes a known program for them (its template hash as compiled with the values given), and the file whose program is a covenant input under test labels that report. A deployed program matches only with the constructor values it was deployed with (`--args`).

`--baseline-only` skips the files' own search and attacks: the files are only used to read the real transactions (which program each coin runs, and its state by field name), so a harness dump of thousands of transactions runs in seconds per file. `kaspa-redteam orders/*.sil token.sil --baseline-only --baseline dump.json`. With the state named, a leftover the covenant names as a tip, fee or budget is reported as a note that names the field (BASELINE.md: What the signer pays is the signer's).

- **template by name**: a `byte[32]` parameter named after another file (`kcc20_template`, `gen__init_bridge_mint_template`) gets that program's real template hash.
- **template by abbreviated name**: `ASK_TPL` is the template hash of the project's `...Ask` program, `COND_BID_TPL` of `...CondBid`, and `ASK_PRE` / `ASK_SUF` (or `_PREFIX` / `_SUFFIX`) are its prefix and suffix lengths. The words of the name before `TPL` must end the other contract's name; the closest one wins (`BUY_TPL` is `ShopBuy`, not `ShopCondBuy`), and only when exactly one file is closest. A name with `token` or `tok` in it (`tokenTplHash`) is left to the token rule: with one token program in the project, it is that program's template. Example: `fixtures/project-links/`.
- **template by role**: the template argument of `readInputStateWithTemplate`, `validateOutputStateWithTemplate` or `validateOutputStateWithInputTemplate` is another program of the project whatever it is called (`expectedTemplateHash`); with one other program to choose from it is that one, and length arguments in the same call (`templatePrefixLen`) get that program's prefix and suffix lengths.

**Families: several programs in one transaction.** When a path refers to another program's covenant id (`OpCovInputCount(prev_state.token)`), the tool also tries it together with a coin of that program, each coin with its own covenant id; outputs a coin authorizes belong to its family. The draft comes from the sources (which state fields hold covenant ids, which arguments are template parts, what a journal record looks like); then the scripts themselves finish it: when an input rejects the draft, the engine's execution log shows the comparison that failed and the value the script computed, often a whole output script, and the tool puts that in and runs again. That is how a bridge's mint is built: the bridge coin with a proof and one deposit, its mint authority, and the new token cell, with no bridge-specific code. A program that only took part says so in its own report.

A second shape is a program that controls another program's coin by covenant id (an owner field set to its id, on the branch that checks `OpCovInputCount(owner)`) and passes the new coins as typed arguments it checks field by field (a minter with `minterKcc20NewState`, `recipientKcc20NewState`). The draft takes those requirements from the source (`require(x.isMinter)`, `require(x.identifierType == IDENTIFIER_COVENANT_ID)`, `require(initialized)`), and numbers the next state must carry are taken from the comparison the script makes.

A third shape is a market: a program that owns another program's coin by covenant id and works out every coin it needs from its own state (a bonding curve holding a token's unsold supply). The same repair loop fills the coin it owns from the market's checks (owner scheme, amount, extension commitment), moves the market to a state where a comparison holds (`m <= sold` with something sold), and, when the market asks for one more coin of the other program (`OpCovInputCount(token) == 2`), adds a second coin owned by an honest key and spent with that program's follower entry, signed again after every change. Fewer new coins (`OpCovOutputCount(token) == 1`) drops the extra ones.

A fourth shape is an order: a coin with no state of its own that names a token by constructor values (its covenant id and template hash) and trades with a coin of that token in the same transaction, a bid paying KAS for tokens or an ask selling the tokens it holds. The project gives the covenant-id value the token's id in the sandbox; the token coin belongs to the order (when the order reads it) or to the spender, who signs for it. An entry that switches on a number argument (`if (n == 0)`) has each branch explored as its own path, and the `n > 0` branch once more with the token coin holding more than the trade takes (an order that keeps a remainder). FAM-10 then spends a second coin the covenant owns next to the first (tokens someone sent to its id) and pays it to the attacker.

On those spends the `family` attacks change what the new coins say and run the result past every program involved (the other programs' arguments rebuilt to match, so only the rules decide): mint more than the data says (FAM-01), to the attacker (FAM-02), twice (FAM-03), in the wrong covenant family (FAM-04), the authority not continuing (FAM-05), the same proof replayed on the next state (FAM-06). Two benchmarks by different authors keep this general: `fixtures/family/` has the real ETH bridge (survives all seven; a copy with its replay protection and run-once init check removed is caught by FAM-06 and FAM-07) and the SilverScript repository's own KCC-20 and minter (`upstream/`; every path explored, the family attacks rejected; a copy that lets a recipient become a minter is caught by FAM-08), and a bonding curve with the KCC-20 reference program (`curve/`; init, buy and sell explored and survive; a copy that forgets the price is caught by FAM-09). FAM-09 runs on paths nothing guards (no proof, no signature): the new coins go to the attacker and the coin under test gets no KAS for them. A program meant to give tokens away will show it; that is by design there.

**Borrowed receive.** KCC-20 lets a sender add tokens to a coin the recipient already has, without the recipient's signature, when the coin's `borrow_scheme` allows it (any sender above a threshold, a named borrow key, or one hash-chain link at a time). A token program's borrow path is explored on each scheme and attacked (BOR-03 to BOR-07). A covenant that holds a token coin is tried with that coin borrowable: a stranger borrows it, and if the covenant then stops working (an exact amount check), that is BOR-01; if only the coin's outpoint moves, BOR-02.

**Genesis.** A path that starts a new family (it reads `OpOutputCovenantId` of an output no input carries yet: a bridge's `init` creating its mint authority, a launch creating a token's first coins) is tried with a new coin of a project program whose covenant id is derived exactly as consensus derives it, from the authorizing input's outpoint and the new outputs. FAM-07 then tries to start the family a second time from the state the first run left.

**What was minted, spent.** A coin a family spend created is then spent by its owner with its own program's entries (a minted KCC-20 cell moved with `transfer`, signed by the depositor the data named), and those spends are attacked in that program's report as `minted:...` paths. If no entry can move it, the report says the minted coins may be stuck.

Not yet covered from sources: spends that need a program's coin the project does not include. In real transactions, KCC-20 reference cells need no file (see Known programs).

## Web page

```
kaspa-redteam serve                                # http://127.0.0.1:8790
kaspa-redteam serve --port 8790 --jobs 2 --timeout 120 --threads 4
```

A single page where anyone can drop a `.sil` file (or several that work together, tested as one project), or paste one, optionally add constructor values, a baseline file or real transaction ids (fetched from the public API by the server, as `fetch` does, at most 20), and get the same report the command line gives: verdict, findings with fix patterns, the spend map, every attack's result, and the repro files to download. The page is built into the binary; there is nothing else to install.

Every scan runs as a separate child process of the same binary, in a fresh temporary folder that is deleted when it ends. Limits: the search stops at two thirds of `--timeout` (`--deadline`) so the attacks still run and a report always comes back, and the scan is killed at `--timeout` seconds (default 120), 2 GiB of memory, `--threads` worker threads per scan, one running scan per visitor and `--jobs` scans at once (others are told to try again). Uploads are capped at 1 MiB in total, 256 KiB and 8 files per scan. Nothing is logged or kept, unless the operator passes `--usage-log <file>` (or sets `REDTEAM_USAGE_LOG`): then the server appends one line per scan with the time, an anonymous visitor tag, the uploaded file names and the result, never the code, and the page's privacy line says so:

```
2026-10-30T23:39:41Z  visitor=09ba  files=3  contracts=BridgeMint.sil,KCC20.sil,bridge.sil  verdict=passed attacks=26 findings=0 unexplored=0  secs=40.0
```

The visitor tag is a hash of the address, salted per day with a value that lives only in the server's memory. A run from transaction ids adds `txids=N` (the count, not the ids).

Transaction ids pasted on the page are fetched by the server from the public API before the scan (within half of `--timeout`, at most 90 s). `serve --api URL` (or `REDTEAM_API`) points mainnet fetches at your own kaspa-rest-server instead.

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
| `POST /api/scan` | `{ filename, source, args: ["name=value"], baseline, baseline_name, txids, network }` → `{ report, files }` (`report` is the `--json` report; with `txids`, `files` also holds `fetched-baseline.json`) |
| `POST /api/params` | `{ files: [{ filename, source }] }` → each contract's constructor parameters with the value the tool would use (a default that breaks the contract's own bound, like `require(fee >= MIN_LEFTOVER)`, shows the value the tool moves it to) and whether it plays them; a file that does not compile gets an `error` and the others still show (`kaspa-redteam params FILE...`) |
| `POST /api/scan` (project) | `{ files: [{ filename, source }], args }` → `{ report: { project, reports }, files }`; finding files are named `<stem>/<ID>.json` |
| `GET /api/library` | the attack library |
| `GET /og.png` | the link-preview card (Open Graph / X) |
| `GET /api/examples` | the examples the page offers, broken and fixed, with the bug and the fix in plain words |
| `GET /api/example` | one vulnerable example contract |
| `GET /health` | `ok` |

## How a covenant run works

1. **Compile.** `silverscript-lang` parses and compiles the file in process.
2. **Keys and constants.** Every `pubkey` constructor argument gets its own deterministic test key, so the tool can sign as every party. `byte[32]` values are matched to how the source uses them: `blake2b(byte[](pk))` gets a party's key hash, `sha256(secret)` a known preimage, `ScriptPubKeyP2SH(h)` the address of a stand-in covenant anyone can spend, and the digest a message signature is checked against (`checkMsgSig(sig, cancelDigest, user)`) the hash of a test message. `byte[]` arguments named `...Script` get a party's P2PK script. Override anything with `--arg`.
3. **Spend search.** For each path the engine searches signers (the key the source checks each signature against comes first), arguments (constructor values and constants found in the script), coin sizes, output shapes, fees and lock values until consensus accepts one honest spend. Locks are bisected so the spend map shows the earliest accepted value. Checks made in helper functions count as the entry's own: an entry that calls `payBackAll()` is searched with the outputs `payBackAll` pins.
   - **Signed readings** (`checkMsgSig`): messages are assembled from what the script compares them with (4-byte tags, `byte[32]` ids, required lengths, constructor values in trailing fields) and signed by the party the source names.
   - **Signed messages** (`checkMsgSig(datasig(cancelSig), cancelDigest, user)`, a KIP-5 cancel text and the like): when the digest is a constructor value or a state field, the party the source names signs it. The path is recorded as signed by that party.
   - **The spender's own coin**: an entry that pins an input to a party's address (`require(tx.inputs[1].scriptPubKey == byte[](userScript))`) is tried with that party's ordinary coin there, which only they can sign. The path is recorded as signed by them.
   - **Outputs read from local names and helpers**: `byte[36] merchantScript = new ScriptPubKeyP2PK(merchant)` and `new ScriptPubKeyP2SH(nextScriptHash)` are followed to the party or stand-in address; a script computed at run time (`lockedScript`) is tried as the covenant itself and as each address it names; an output the entry counts (`tx.outputs.length == 2`) but whose script it never checks can go anywhere. When a payment is capped (`value <= fee`, `value >= fee - maxNetworkFee`) the network fee is also taken out of it, so the other outputs can be exact (`value == rest`).
   - **Stateful covenants** (`validateOutputState`): successor outputs carry re-encoded state, and every new state an accepted spend reaches is explored in turn, so paths that only open later (`claim` after `approve`) get attacked too.
   - **Sibling coins**: a stand-in coin can sit next to the covenant, for paths that require another covenant's coin as an input.
   - **Covenant families** (KCC-20 and anything else that reads `OpInputCovenantId`, `OpCovInputCount`, `OpAuthOutputCount`): sandbox coins carry a covenant id, successor outputs are bound to it (transaction version 1), state-shaped arguments (`KCC20State[] next_states`, `State newState`) are filled from the successor outputs they must match, a signature can sit inside a `byte[]` witness (`0x00 ‖ sig`), and delegate entries are tried as a second coin beside an explored leader. A `byte[32] ...template` constructor value is set to the program's own template hash. Constructor ints used as loop bounds get small values, and `bool` flags are flipped when the default closes a path.
4. **Tuning.** If a path stays unexplored, the tool first fixes defaults that break a `require` on constructor values alone (`require(fee >= MIN_LEFTOVER)`, `require(maxNetworkFee < fee)`, in an entry or a helper), since every path that reaches such a line needs it to hold. Then it reads the comparisons each still unexplored entry (and the helpers it calls) makes on integer constructor parameters (`require(cancelFee >= MIN_OUT && cancelFee <= maxFare)`), tries the values they compare against (`int constant`s, literals, other parameters, then numbers a comment gives for the parameter, like `about 25,920,000`), and keeps one only when it opens the path without closing another. Every tuned value is listed in the report as a `note: constructor ... set to ...` line; `--arg` overrides it and `--no-tune` turns tuning off.
5. **Attack.** Each attack mutates those honest spends: wrong signer, garbage signature, forged reading, reused secret, redirected or reduced outputs, a second covenant coin, an attacker coin in front, value left as fee.
6. **Judge.** `TransactionValidator` from `kaspa-consensus` 2.1.0 (isolation rules, amounts, sequence locks, storage-mass commitment, covenant context, every input script) plus the lock-time finality rule. Mainnet consensus constants; no network.

### Reading the report

- `N attacks run / survived / skipped`: an attack is skipped when no explored path is one it applies to (signature attacks on a contract with no signed path, say). Skipped is neither a pass nor a fail.
- The verdict: `PASSED: 0 FINDINGS` (green) when attacks ran, none got through and every path was explored. It means nothing the tool tried broke the contract; it is not an audit or a guarantee. `0 FINDINGS, N PATHS UNEXPLORED` and `NOTHING TESTED` are not passes. `N FINDINGS` counts problems, not attempts.
- `-v` adds the **spend map**: for every path, who can spend it, where the honest spend paid, and the earliest lock value consensus accepted. Read it first; it is the tool's understanding of your contract.
- `note: constructor ... set to ...`: a value the tool tuned so a path could be explored. The findings hold for that value; if your deployment uses a different one, pass it with `--arg`.
- `note: path ... unexplored`: the path was not attacked. Clean results say nothing about it.
- `unexplored: not reachable with X as written`: in a project, a path that needs a coin of X in the same transaction, when no entry of X accepts such a transaction (the reason quotes X's lines: it always keeps this coin's family going, leaves it untouched, or only runs before the coin exists). If the path is meant to be usable, X is where the fix goes. It still counts as unexplored.
- Each finding has three parts: what consensus accepted (the explanation), **in practice**, how that situation comes about in real use (a wallet sending a deposit twice, someone watching the mempool), and the **fix pattern**, the code that closes it. A finding can be real and still not matter for your app: OUT-04 on a deposit that is always exact costs nothing. The in-practice line is there to make that call quickly.

A path the search cannot spend is reported as **unexplored**, never as safe. For those, two ways in: `--arg` values the search could not guess, or a **baseline file**: honest transactions from your own test harness, which the attacks then mutate. That covers what the search cannot build from one file: another program's coins (a market that only accepts a coin of a pinned KCC-20 template), states tied together by real arithmetic, genesis transactions. Format and a JavaScript emitter: [BASELINE.md](BASELINE.md). A baseline can list the throwaway keys it was signed with (`"keys"`), so the attacks can re-sign after changing a transaction and test what a signing user could get away with.

### Threat model (Tier 1)

The attacker holds only their own key, reads the chain and the mempool (so a secret revealed by a pending claim is public), and can build any transaction. An insider abusing their own signature (a payee taking more than their share) needs to know the roles; that is Tier 2.

## Attack library v0.6.0

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
| FAM-01 | family | Mint more than allowed | New coins' amounts not checked against the proof, data or allowance |
| FAM-02 | family | Mint to the attacker | New coins' owner not bound to the recipient the data names |
| FAM-03 | family | Mint one coin twice | Number of new coins not tied to the records paid for |
| FAM-04 | family | Coin of the right program, wrong family | New coins not required to be in the token's covenant family |
| FAM-05 | family | Authority does not continue | Another program's coin allowed to end or move in a normal spend |
| FAM-06 | family | Replay the same proof on the next state | Data already processed accepted again |
| FAM-07 | family | Start the family a second time | A genesis path that can run again after the family exists |
| FAM-08 | family | Hand out the minting power | New coins allowed to carry the authority (a minter flag) |
| FAM-09 | family | Take tokens without paying | A permissionless path hands out another program's coins and gets no KAS for them |
| FAM-10 | family | Sweep coins sent to the covenant | A second coin owned by the covenant's id can be spent and taken in a normal spend |
| BOR-01 | borrow | A stranger borrows the coin it holds and bricks it | A held token coin with borrowing on; one borrowed token unit breaks the covenant |
| BOR-02 | borrow | A stranger borrows the coin it holds | A held token coin with borrowing on; anyone can move its outpoint |
| BOR-03 | borrow | A borrow takes the coin | A token program's borrow path lets the coin change owner |
| BOR-04 | borrow | A borrow adds nothing | A token program's borrow path does not require the amount to grow |
| BOR-05 | borrow | A borrow takes the coin's KAS | A token program's borrow path lets the coin's KAS drop |
| BOR-06 | borrow | A borrow without the borrow key | The borrow key or hash-chain link is not checked |
| BOR-07 | borrow | A borrow rewrites the borrow settings | The borrow scheme or guard can change on a borrow |
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

## Program analyzer (no source needed)

`analyzer/` holds `kcc20-analyzer`, a separate binary for programs already on chain: it takes a program's bytes and
its real spends, mutates those spends one change at a time and has the real script engine judge each one, then
reports what an outsider can do, with the accepted transaction as evidence. It feeds the KCC-20 token safety labels in
SilverScript Studio. See [analyzer/README.md](analyzer/README.md).

## Layout

```
crates/redteam-core       findings, report, badge, shared types
crates/redteam-covenant   compile, spend search, judge, covenant attacks
  library/                known programs shipped with the tool (KCC-20 reference, with its notice)
crates/redteam-node       simnet harness, mainnet guard, node/mining attacks
crates/kaspa-redteam      the CLI, the web page, fetch (the only part that goes online)
fixtures/<ID>/            vulnerable.sil + fixed.sil per attack
corpus/                   real covenants the library is run against
```

## Safety

Simnet and in-process only; `fetch` only reads public chain data. Finding files target sandbox UTXOs, not live coins. A finding against someone else's deployed contract goes privately to its author first (see SECURITY.md).

## License

MIT
