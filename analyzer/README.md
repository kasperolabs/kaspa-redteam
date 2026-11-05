# kcc20-analyzer

What can a Kaspa covenant program let an outsider do? Program bytes and its real spends in, report JSON out.
Built by Kaspero Labs for the KCC-20 token safety labels (SilverScript Studio), kept generic: it works on any P2SH
covenant program that has been spent on chain. No `.sil` source needed.

It is a separate binary in this repo with its own Cargo workspace: it judges with `kaspa-txscript` at rusty-kaspa
`a41a333b08848f41bf737b72592e463a6011b8ac`, the revision argent-lang/kcc20-reference pins, while the rest of
kaspa-redteam builds against the crates.io 2.1.0 release.

## Build

```
cd analyzer
RUSTUP_TOOLCHAIN=stable cargo build --release      # target/release/kcc20-analyzer
```

Rust 1.94 or newer. The first build fetches and compiles the pinned rusty-kaspa crates (several minutes).

## Run

```
# 1. make every cached spend complete (input covenant ids, spent scripts); optional: follow the program's next coins
node server/queue-complete.js --only-verified --follow 12 kcc20-analyzer-queue.json > queue-complete.json

# 2. the corpus check, then every program
./target/release/kcc20-analyzer run --queue queue-complete.json --out out --corpus corpus-private

# 3. into the Studio (dry run first, then --apply), from the Studio folder
cd /var/www/silverscript && node /path/to/analyzer/server/writeback.js /path/to/out/writeback.json
cd /var/www/silverscript && node /path/to/analyzer/server/writeback.js /path/to/out/writeback.json --apply
```

Options: `--only <hash prefix>`, `--max-runs N` (engine runs per program, default 4000), `--max-seconds S` (default
600), `--pins DIR` (JSON files with a `template_hash`, such as kascov-decode's `pins/kcc0020`, to name known
families), `--include-unverified-rows`. `kcc20-analyzer corpus --corpus DIR` runs the corpus alone (exit 1 if a case
is missed).

Output: `out/reports/<hash>.json` per program, and `out/writeback.json` (rows plus the corpus result) for the
write-back. Only `server/queue-complete.js` touches the network, and only the public Kaspa REST API.

## Input

The Studio's queue export: `{ "programs": [ { "hash", "kind", "layout", "sample_redeem_hex", "first_covenant_id",
"first_txid", "verified", "spends": [ { "txid", "tx": <kaspa-rest-server transaction> } ] } ] }`. Transactions are in
the `/transactions/{id}?resolve_previous_outpoints=light` shape. A copy that does not say what an input spent (amount,
script or address, covenant id) is skipped with a note; `queue-complete.js` fetches such copies again and fills a
missing input covenant id from the previous transaction's output.

## Method: mutate real spends

For each program, every observed transaction that spent it is rebuilt with the coins it spent (scripts, amounts,
covenant ids). The rebuilt id must equal the real one; the engine must accept the copy as given.

1. **Outsider base.** The person who made the transaction (its plain-key inputs: a buyer, a seller, a holder paying
   the fee) is replaced by the analyzer's own fixed key: their coins become the outsider's, outputs that paid them
   now pay the outsider, everything is signed again. Covenant inputs and their witnesses stay byte for byte. If the
   program's own input then fails, the path needs that person's signature.
2. **One change at a time** on the base, then the outsider signs again and the engine judges:
   - recipient: an output paid to the outsider instead;
   - amounts: 1 sompi, 1%, half, all but 1 sompi of an output paid to the outsider; an output left out;
   - where the coin's KAS goes: the same, on the covenant's own next coins;
   - signatures in the program's witness: zeroed, emptied, made by the outsider's key, the key and signature both
     the outsider's, another sighash byte, signed by the outsider under another sighash type;
   - extra outputs: one to the outsider (funded by the outsider), a second copy of each covenant-bound output;
   - other entry tags with the same arguments;
   - witness numbers: zero, one, halved, doubled;
   - the state pushes of the spent coin, constants included (a copy of the program with another value there).
3. **Second level:** value changes on top of every accepted signature, key, sighash, entry or number change.
4. **Entries nobody was seen using:** argument shapes guessed from the observed arguments and common shapes
   (signature, key, numbers); a branch with a lock time gets the lock time it asks for. An entry no guess reaches is
   unexplored.
5. **Payees** other than the person making the transaction (a platform fee, a creator fee): the smallest payment the
   program accepts is measured by bisection. Paying the minimum is not a power over holders.
6. **State pushes** are compared across every copy seen: same in every copy (a constant, or state that had not
   changed yet) or varies; a push that holds a script some output pays is marked (a payee written into the coin, such
   as a treasury). The code hash cuts these pushes out, so a copy paying another treasury has the same hash; the
   report shows the values.

Every judgement runs every input's script through the pinned engine with covenants enabled and each input's own
script-unit budget, plus the transaction rules a covenant cannot see: duplicate inputs, output values, inputs cover
outputs, covenant bindings and genesis ids (`CovenantsContext::from_tx`, recomputing genesis ids after a change the way
a real builder would).

## Labels and status

Labels state powers, never intent. A label other than `unverified` needs a transaction the engine accepted, and the
report carries it (rusty-kaspa JSON, the `kaspa-redteam/baseline/1` shape, replayable).

- `trap`: an accepted transaction in which an outsider moves holders' value: KAS that was already in the covenant's
  coins leaves them beyond what the real spend allowed (counted only beyond the covenant's other new coins, which may
  be the person's own), a coin spent without its holder's key (a signature, key, sighash, entry or number change made
  a failing outsider base pass), or KAS the real spend sent to a payee that nothing requires and that exceeds what the
  outsider brought.
- `hidden-powers`: an accepted transaction showing a power the program does not declare, such as anyone creating an
  extra coin of the covenant.
- `unverified`: everything else. The analyzer never writes `standard`: a clean run only says that what was tried
  was refused.

Status `done` when a power was witnessed or nothing was left unexplored; `too-complex` when the exploration has gaps:
no rebuildable spend, an entry never reached, only one copy seen (constants and state cannot be told apart), or the
budget ran out. Older KCC-20 cells (kascov-decode's state block: owner, identifier type, amount, is_minter) get their
`is_minter` field reported per coin as a declared power.

## The corpus gate

The write-back refuses a run unless every corpus case was caught. The corpus is private (sim only, never broadcast,
never published): one hostile program per route with one honest spend, plus control programs that must come back
with no witnessed power. Its generator and cases are in `.gitignore` and are kept by Kaspero Labs; add a case for every
new route and every wrong label reported.

## Determinism

Fixed outsider key, deterministic Schnorr signatures (no aux randomness), ordered iteration, a run-count budget: the
same queue and analyzer version give the same reports byte for byte. Only the wall-clock limit (`--max-seconds`) can
cut a run short differently on a slower machine, and a run cut short is `too-complex`, never a label.

## Known limits

- KAS is accounted, tokens are not: a pool that sells tokens below its own price, without losing KAS that was in its
  coins, is not caught. Reading token amounts needs each program's layout.
- A power that needs a key nobody shares (a creator's sweep, an issuer's freeze) cannot be witnessed by an outsider;
  such entries show as stopped at a signature check or unexplored.
- Mass, fee policy, sequence locks and standardness are not checked; none of them protects a holder's coin.
- A spend whose id cannot be rebuilt from the API fields (one seen so far) is used only for its covenant inputs.
- Input DAA scores are unknown in the REST shape and set to 0; a program reading them is judged on that value.

## Credits

kascov-decode (github.com/Knitser/kascov, MIT): the older KCC-20 state block layout and the pin files used to name
families. argent-lang/kcc20-reference (ISC): the rusty-kaspa revision. MIT, Kaspero Labs.
