# Changelog

## Tool 0.10.0 (library 0.8.0)

- FAM-10: sweep coins sent to the covenant. A second coin of the token owned by the covenant's id (tokens sent to it by mistake, a second deposit) is spent next to the one the path uses, with the token program's follower entry, and its tokens go to the attacker. An ask order without a token input count check is caught; with `require(OpCovInputCount(tokenCovId) == 1)` it survives. The curve and the bridge survive it.
- Branches: after `[n>0]`, the same branch is tried with the other program's coin holding more than the trade takes (`settle+transfer[n>0,rest kept]`: an order that keeps a remainder and continues), as its own path when the spend comes out different.
- Repair: an output the script asks to be in the other program's family (`OpOutputCovenantId(out) == tokenCovId`) gets that family's binding. The honest spend's leftover KAS goes to a change output even when none was drafted.

## Tool 0.9.1 (library 0.7.0)

- Fix: FAM-01 to FAM-04 no longer change the spender's own new coin (a buyer's tokens from an ask). Making it a look-alike only cheats the spender; 0.9.0 reported that as FAM-04 on `settle+transfer[n>0]`.

## Tool 0.9.0 (library 0.7.0)

- A fourth family shape: orders. A coin with no state of its own that names a token by constructor values (`tokenCovId`, `tokenTplHash`) and trades with a KCC-20 coin in the same transaction (a bid paying KAS for tokens, an ask selling its tokens). Benchmarked on a bid and an ask from another team's order book with the KCC-20 reference program: `fill`, `settle` (refund) and `settle[n>0]` (fill) explored, 0 findings.
- Project links: a template argument links to the program whose state is the struct the call reads or writes, not just "the only other file" (two orders and a token in one upload linked the bid to the ask before). A `byte[32]` constructor value the source compares to a coin's covenant id gets that program's covenant id in the sandbox (new link kind `covenant id`).
- An entry that switches on a number argument (`if (n == 0) { refund } else { fill }`) has each branch explored as its own path (`settle+transfer[n>0]`).
- Repairs: lock times a path asks for; the other program's own books (`output_total == input_total`: the spender takes the rest as a coin of its own); an order ending instead of continuing (`OpCovOutputCount(self) == 0`); an output value plus a contract constant (`value + refundTip >= carriers`); a coin a key owns signs for itself (re-signed after every change). Count repairs act only when the script really counted coins (the opcodes before the comparison are now part of the failed check).
- FAM-04 on orders: the delivered coin is a look-alike with no covenant id while the real tokens stay with the attacker. A bid without `OpOutputCovenantId(out) == tokenCovId` is caught.
- The spend map and findings no longer say "only a user holding the listed key" when the only re-signed coin is the attacker's own.
- KAS the repairs left to the miner goes back to the spender's change, so the honest spend pays a normal fee (no OUT-04 on the tool's own overfunding).
- `REDTEAM_TRACE=1` (with `REDTEAM_DEBUG=1`) prints the last opcodes before each failed check.

## Tool 0.8.2 (library 0.7.0)

- A follower entry (one that requires another coin of its covenant to lead, `OpCovInputIdx(id, 0) != this.activeInputIndex`) gets a short solo search, and its time goes to pairing it with a leader. Before, its solo search used the whole budget first, and on a slower server the pairing step ran out of time (`minted:transfer_delegator` unexplored). The curve project now takes 2.5 s instead of 13.6 s.

## Tool 0.8.1 (library 0.7.0)

- A path of a program that ran inside another file's family spend counts as explored in its own report (`transfer_delegator` of the KCC-20 program, spent by the seller's coin in the curve's `sell`). On a slower server its own search could run out of tries looking for a leader it cannot build alone, and the report showed a gap that was not one.

## Tool 0.8.0 (library 0.7.0)

- A third family shape: a market that owns another program's coin by covenant id and computes every coin itself (a bonding curve). The repair loop now also sets the owned coin's state from the market's checks, moves the market's own state where a comparison asks (`m <= sold`), sets number arguments (`m > 0`) and output values (`successor >= in + cost`, paid by the funding coin).
- A second coin of the other program when the market asks for one (`OpCovInputCount(token) == 2`): owned by an honest key, spent with the follower entry (`transfer_delegator`), signed again after every change. Extra new coins are dropped when the market asks for fewer.
- FAM-09: take tokens without paying. On paths with no proof and no signature, the new coins go to the attacker and the coin under test gets no KAS.
- Benchmark three: `fixtures/family/curve` (a bonding curve and the KCC-20 reference program). init, buy and sell explored, 0 findings; a copy that forgets the price is caught by FAM-09.
- Helper functions are followed: `require_owner_authorized(owner, owner_scheme, ...)` maps its parameters to the state fields, so ownership checks inside helpers are found.
- Fixes: the spend map no longer says "a valid proof" for family paths that take no proof; a genesis path's `*_out` index arguments get the first new output.

## Tool 0.7.0 (library 0.6.0)

- Templates link by role: the template argument of `readInputStateWithTemplate` / `validateOutputStateWithTemplate` / `validateOutputStateWithInputTemplate` gets the other program's template hash whatever it is called, and length arguments in the same call get its prefix and suffix lengths.
- A second family shape: a program that controls another program's coin by covenant id and passes the new coins as typed arguments (a minter). Requirements are read from the source (field checks on the arguments, the ownership branch, the entry's own state checks); numbers the next state must carry come from the script's comparison.
- FAM-08: hand out the minting power. FAM-01 is now "Mint more than allowed" (proof, data or allowance).
- Benchmark two: the SilverScript repository's own KCC-20 and minter (`fixtures/family/upstream`, ISC). Every path explored on both files, minted coins included; a copy without the recipient check is caught by FAM-08.
- Fixes: a path is tried for a family spend once, even when it appears in several states.

## Tool 0.6.1 (library 0.5.0)

- Minted coins: both KCC-20 paths explored (`minted:transfer`, and `minted:transfer_delegator` pairing two minted coins); the program's own bytes carry the minted state. The ETH bridge project now has no unexplored path in any file (tests/family.rs checks it).
- Search debug output (`REDTEAM_DEBUG=1`) shows the comparison a rejected try failed on.

## Tool 0.6.0 (library 0.5.0)

- Genesis: a path that starts a new covenant family is tried with a new coin of a project program, its covenant id derived as consensus does (`SpendPlan.genesis`). The ETH bridge's `init` is now explored, so the bridge has no unexplored paths.
- FAM-07: start the family a second time.
- Minted coins are spent by their owner with their own program's entries and attacked there (`minted:...` paths), with the program's full search, so a delegate spend pairs two minted coins; a coin no entry can move is reported. This step gets up to 20 s of its own under `--deadline`; the web page stops a project's search at half its timeout to leave room.
- A file deadline, when set, replaces the overall one.

## Tool 0.5.1 (library 0.4.0)

- Family spends are tried even when the search deadline has passed (they take a few runs, and they are the only way into those paths). On a slower server the web page skipped them.
- Web project card: a program that was only attacked inside another file's family spend says so instead of "nothing could be attacked".

## Tool 0.5.0 (library 0.4.0)

- Families: a path that refers to another program's covenant id is also tried together with a coin of that program, each with its own covenant id, creating coins of a third (a bridge, its mint authority, the token cells). The draft is repaired from the scripts' own execution logs: a failed comparison shows the value the script computed, often a whole output script, and the tool uses it. Journals with records (`int off = FIXED + LEN * i`, a count, per-record checks) get one record.
- Template links by name: `kcc20_template` gets KCC20.sil's template hash in a project.
- New attack pack `family` (FAM-01 to FAM-06): mint more than the data says, mint to the attacker, mint twice, wrong covenant family, authority not continuing, replay on the next state. `fixtures/family/` and `tests/family.rs`: the real ETH bridge survives all six; a copy without replay protection is caught by FAM-06.
- A program that only took part in another file's family spend says so in its own report.
- Fixes: outputs with no value are refused before mass rules run; the KAS a relayer puts into a new coin is its own (no skim finding).

## Tool 0.4.9 (library 0.3.2)

- Projects on the web page: the project card lists every contract with its verdict and a link to its report, so the second and third contracts are not lost below the first one's tables.
- Projects under `--deadline` (the web page): each file gets an equal share of the time that is left, so the first files cannot use up the search time of the last.

## Tool 0.4.8 (library 0.3.2)

- ZK covenants: the Groth16 verifying key a script pushes (RISC Zero's fixed key, or the contract's own) is swapped in the sandbox for a test key whose one test proof verifies for any public inputs. Proof arguments get that proof; journal arguments are laid out from the entry's own `journal.slice(a, b) == value` checks. Proof-checked paths become explorable; a report note says what this does and does not test. Version-1 transactions with a compute budget for the verification.
- Covenant-declaration entries (`#[covenant...] function advance`) are searched with their function's body, so its hints apply.
- `examples/zk_payout_FAIL.sil` and `_PASS.sil`.

## Tool 0.4.7 (library 0.3.2)

- Every attack says how its situation comes about in real use ("a wallet sends the deposit twice", "someone watching the mempool copies the secret"). Findings carry it as `in_practice` (command line: "In practice:", web page: "How this happens in practice", finding files, JSON), and the attack library on the page lists it.

## Tool 0.4.6 (library 0.3.1)

- Constructor values take Kaspa addresses: `kaspa:q...` gives a key, `kaspa:p...` a contract's script hash (on the command line, in values files and on the page). A contract address where a key is expected, or a typo, is an error.
- Web form: each value says what it is in plain words ("script hash of another contract: paste its kaspa:p… address", "amount in sompi", "time in milliseconds since 1970") and shows it in human terms next to the box (KAS, a UTC date, "30 days", a percentage). Addresses are checked as you type.
- Fix: your own address for a P2SH parameter (`treasury=kaspa:p...`) is paid to as given; before, it left the paths that pay it unexplored.

## Tool 0.4.5 (library 0.3.1)

- Web page: "Constructor values" is a form built from the contract, folded under the file with a summary ("11 · 2 yours, 9 test values"). Every parameter is filled in for testing; a value you change becomes yours, and amounts show in KAS. Keys and hash locks are listed as played by the tool. A report with unexplored paths links back to the form. The old text box is under "Paste values instead".
- `kaspa-redteam params FILE...` and `POST /api/params`: each contract's constructor parameters, with the value the tool would use and whether it plays them.
- A `byte[32]` counts as a hash lock (played by the tool, value from a file ignored) only when the script hashes against it; ids, templates and commitments are always taken as given.

## Tool 0.4.4 (library 0.3.1)

- `--compiled FILE`: test the exact script a project's own (pinned) compiler made, with the `.sil` for entries and hints and `--args` for the values it was compiled with. Keys, key hashes and hash locks are swapped in place for the tool's own (same-length pushes); everything else is the given bytes. The report gives the script's sha256 and whether today's compile matches. A script that does not contain the given values, lacks an entry's dispatch tag, or hides its starting state is refused. The web page has a "Compiled script (advanced)" upload.

## Tool 0.4.3 (library 0.3.1)

- `--args FILE`: constructor values from the JSON a project deploys with (by name, in order, or wrapped in `constructorArgs`). Keys, key hashes and hash locks are played by test keys and secrets, and the report says which; every other value is used exactly. The web page takes the same JSON pasted into the constructor values box.
- Search: an entry that pins several payouts to constructor values (`tx.outputs[1].value == driverAmount`) is tried with a coin that holds them all plus a fee.

## Tool 0.4.2 (library 0.3.1)

- Older SilverScript: a file that does not parse is reported as a syntax error, in those words, with what changed in the language when the tool recognizes it. Files using struct literals from before Aug 3, 2026 (`State s = { .. }`, SilverScript PR #193) are tested rewritten in current syntax, with a note in the report saying so and that deployed bytecode from an older compiler may differ.

## Tool 0.4.1 (library 0.3.1)

- OUT-04 (new): a permissionless path that fixes its payouts but not the coin's value lets whoever spends it keep the rest. For a secret-released path that includes anyone who copies the secret from the mempool.
- Search: a coin the entry caps in its source (`tx.inputs[this.activeInputIndex].value <= a + b + maxFee`, or `==`, `<`) is tried at that value first.
- Spend map: secret paths read "anyone who knows the secret behind `pinHash`".
- `examples/doordash_escrow_FAIL.sil` and `_PASS.sil`: a delivery escrow released by a PIN.

## Tool 0.4.0 (library 0.3.0)

- Projects: give several `.sil` files in one run (`kaspa-redteam treasury.sil fund.sil`) and they are tested as one program. A P2SH parameter named after another file gets that contract's real script instead of a stand-in; a pinned `byte[32]` equal to another file's template hash is detected. The report lists the links, then each contract's results; findings go to `out/<stem>/`; `--arg` goes to whichever file has the parameter.
- Web page: drop or choose several files at once (up to 8) for a project report: the links the tool found, then each contract's verdict, findings and repro downloads.

## Tool 0.3.7 (library 0.3.0)

- Search: signers are ranked by the checks in the entry's own body (`deptSig` against `parks` in `pullParks`), so contracts with many similar paths stop burning their budget on the wrong key. A 12-path municipal budget went from 252 s with 5 paths unexplored to 0.1 s with all explored.
- Search: output shapes the entry pins in its source (`tx.outputs[i].scriptPubKey == ...P2PK(x)` with `.value ==` or `.value <=`, plus a change output back to the covenant) are tried first, including ten-output settlements.
- Search: running totals in state (`spent + amount`, a period start advancing by `period`) are built together with the payment they record.
- Defaults: running totals (`init_spent`, `claimed`) start at 0; in wall-clock contracts (`tx.time`, no DAA ages) times default to a date in milliseconds and periods to 30 days.
- Witness bytes: the signature alone is tried first unless the script slices off a path byte.
- `REDTEAM_DEBUG=1` prints search progress with rejection reasons.
- `corpus/town/`: a town treasury and department fund (council 3 of 5, two signatures per payment, monthly allotments, lapse at year end) with a guide.

## Tool 0.3.6 (library 0.3.0)

- `--deadline SECONDS`: the search stops at the deadline, paths it had not cracked are reported as unexplored (time limit), and everything found is still attacked and reported. The web page sets it to two thirds of `--timeout`, so a slow contract returns a partial report instead of a timeout error.

## Tool 0.3.5 (library 0.3.0)

- Web page: `HEAD` requests are answered like `GET` (they returned 404, and link-preview crawlers often ask `HEAD` first).

## Tool 0.3.4 (library 0.3.0)

- Web page: link-preview card (Open Graph and X `summary_large_image`), served at `/og.png`, with absolute URLs built from the request's host. Behind nginx, pass `proxy_set_header Host $host;`.

## Tool 0.3.3 (library 0.3.0)

- Web page: examples move into the form as one menu with a Broken/Fixed switch. Choosing one fills the source box and explains the bug (or the fix) in plain words; only "Attack it" runs anything. Five examples on the page, one per kind of bug; the rest stay in `examples/`. After an example run, one line offers the other version. Pressing "Attack it" scrolls to the status.

## Tool 0.3.2 (library 0.3.0)

- Web page: the examples are built in. An "Examples" grid under the form loads any of them, broken or fixed, shows the source and runs it in one click. `GET /api/examples` lists them.

## Tool 0.3.1 (library 0.3.0)

- `examples/`: eight everyday contract shapes (swap, inheritance, allowance, escrow, crowdfund, revenue split, oracle bet, name registry), each as `_FAIL` and `_PASS`, plus `leaky_vault_FAIL`; a test keeps the names honest.
- Search: when nothing else works, the spender may add a coin of their own (successors that keep every sompi, payments on top of the covenant's value); amounts at the fractions the script computes with (`total * 7 / 10`).
- ST-01 also rewrites arguments that named the honest owner (`transfer(new_owner)`).

## Tool 0.3.0 (library 0.3.0)

- Covenant families from the `.sil` alone: sandbox coins carry a covenant id and successor outputs are bound to it (version 1 transactions); `struct` and struct-array arguments are built from the successor outputs (or, for `prev...` parameters, the covenant inputs); a signature can sit inside a `byte[]` witness after a path byte; delegate entries are searched as a second coin next to an explored leader; a `byte[32] ...template` constructor value becomes the program's own template hash.
- Defaults: constructor ints used as `for` loop bounds get 3; byte selectors (`...scheme`, `...type`) get 0; `byte[32]` values used or named as keys (`pubkey(owner)`, `genesisPk`) get a party key.
- Tuning also flips `bool` constructor flags when the default closes a path (`require(!initialized)`).
- Successor search leaves room for two-field state changes, and tries doubling an amount (two coins merged).
- Rejections name the failing input (`input 1: signature invalid`).
- Paths that may need another program's coin say so in their unexplored note.
- ST-01: rewrite the recorded owner of the next state. New `state` pack, fixtures included.

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

## 0.6.0

- FAM-08: hand out the minting power. FAM-01 renamed "Mint more than allowed".

## 0.5.0

- FAM-07: start the family a second time.

## 0.4.0

- Pack `family`: FAM-01 mint more than the data says, FAM-02 mint to the attacker, FAM-03 mint one coin twice, FAM-04 coin of the right program in the wrong family, FAM-05 authority does not continue, FAM-06 replay the same proof on the next state.

## 0.3.2

- Every attack has an `in_practice` line: how its situation comes about in real use.

## 0.3.1

- OUT-04: keep what the fixed payouts leave over.

## 0.3.0

- ST-01: anyone may spend a coin whose next state records an owner key, and write their own key there.

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
