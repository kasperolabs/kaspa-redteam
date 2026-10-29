# Baseline files

Some covenants are out of reach for the spend search: covenant families with their own IDs, a sibling coin running a different program (a KCC-20 token next to its market), outputs computed by real arithmetic. For those, give kaspa-redteam the honest transactions your own test harness already builds, and it attacks those instead.

```
kaspa-redteam --baseline honest.json                 # no .sil needed
kaspa-redteam curve.sil --baseline honest.json       # search + imported, one report
kaspa-redteam export vault.sil > example.json        # a working file to copy from
```

Nothing is sent anywhere. The file is read, every transaction is first checked by the consensus judge exactly as given (a baseline consensus already rejects proves nothing, so the run stops with the reason), then the attacks mutate it.

## Format `kaspa-redteam/baseline/1`

```json
{
  "format": "kaspa-redteam/baseline/1",
  "daaScore": 10000000,
  "pastMedianTime": 4000000000000,
  "keys": ["<64 hex private key>"],
  "transactions": [
    {
      "path": "buy",
      "targets": [0],
      "tx": { ... },
      "utxos": [ { ... }, { ... } ]
    }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `daaScore`, `pastMedianTime` | The block the transaction would land in (DAA score, past median time in ms). Optional; also settable per transaction. Needed when the covenant has time or DAA locks. |
| `keys` | Optional. Throwaway private keys (64 hex) the harness signed with. Any transaction signature one of them made, in any input, is signed again after each change. See below. |
| `own` | Optional, per transaction. Indexes of outputs that belong to the signing user (a buyer's new token coin, say). Attacks do not take from these: shortchanging yourself is not a finding. Outputs paying a listed key's plain address are recognised without it. |
| `path` | A name for the report: usually the entry point. |
| `targets` | Indexes of the inputs that are the covenant under test. Optional: by default every input that is not a plain pay-to-pubkey coin. |
| `tx` | The transaction, as rusty-kaspa's `Transaction` serializes to JSON (below). |
| `utxos` | The coin each input spends, same order as `tx.inputs`. |

A single transaction can also be given at the top level (`{ "tx": ..., "utxos": ... }`).

### `tx`

rusty-kaspa's own JSON for `kaspa_consensus_core::tx::Transaction`, so from Rust it is `serde_json::to_value(&tx)`. Fields `mass` and `id` are ignored if present. Numbers may be JSON numbers or decimal strings; bytes are hex strings.

```json
{
  "version": 0,
  "inputs": [
    {
      "previousOutpoint": { "transactionId": "<64 hex>", "index": 0 },
      "signatureScript": "<hex>",
      "sequence": 0,
      "sigOpCount": 1
    }
  ],
  "outputs": [
    {
      "value": 999990000,
      "scriptPublicKey": "0000<script hex>",
      "covenant": { "authorizingInput": 0, "covenantId": "<64 hex>" }
    }
  ],
  "lockTime": 0,
  "subnetworkId": "0000000000000000000000000000000000000000",
  "gas": 0,
  "payload": ""
}
```

- Version 1+ transactions carry `computeBudget` instead of `sigOpCount`, and outputs may carry `covenant` (null or absent when unbound).
- `scriptPublicKey` is the 2-byte big-endian version followed by the script, as one hex string (`0000aa20<hash>87` for P2SH). `{ "version": 0, "script": "<hex>" }` is accepted too.

### `utxos[i]`

rusty-kaspa's JSON for `UtxoEntry`:

```json
{ "amount": 1000000000, "scriptPublicKey": "0000aa20...87", "blockDaaScore": 1000, "isCoinbase": false, "covenantId": null }
```

## What the attacks can change

- **Covenant inputs** (`targets`) stay byte for byte as given: their signature scripts, redeem scripts, witnesses. Attacks may add a second copy (IN-01) or put a coin in front (IN-02).
- **Plain pay-to-pubkey inputs** (the coins that pay the fee or fund a purchase) are treated as the attacker's own: the tool swaps them for test coins of the same value and re-signs them, so outputs can change. Change outputs that went back to those coins go to the attacker.
- **If a covenant input carries a transaction signature** (a 65-byte push ending in a sighash type byte) that no listed key made, the path is treated as signed: an outsider cannot change outputs without that key, so only the attacks that make sense for an outsider run, and funding coins are kept verbatim (re-signing them would break the covenant signature, which commits to every input).
- **If a listed key made it** (`keys`), the signature is the attacker's own: the tool signs again after every change, and the path is attacked from that signer's seat. This is how a user-signed path (a seller signing for their own token coin) gets tested: can the signer take more than the covenant allows?

### Which keys to list

Only keys of the role you want attacked *from*: an ordinary user, buyer, seller. Not a key whose signature legitimately authorizes anything (an owner or admin key): with it listed, every redirected output is "accepted" and the report fills with findings that are just the owner spending their own coin. And only throwaway keys: the file holds them in the clear.

## Emitting it from a JavaScript harness

Build the object from the values your harness already has right before it broadcasts:

```js
import fs from "node:fs";

// tx: { version, inputs: [{ txid, index, sigScriptHex, sequence, sigOpCount }],
//       outputs: [{ value, spkVersion, spkScriptHex, covenant? }], lockTime, payloadHex }
// utxos: one per input: { amount, spkVersion, spkScriptHex, blockDaaScore, isCoinbase }
export function dumpBaseline(file, path, tx, utxos, ctx = {}) {
  const spk = (v, hex) => v.toString(16).padStart(4, "0") + hex;
  const doc = {
    format: "kaspa-redteam/baseline/1",
    daaScore: String(ctx.daaScore ?? 10000000),
    pastMedianTime: String(ctx.pastMedianTime ?? 4000000000000),
    transactions: [{
      path,
      tx: {
        version: tx.version,
        inputs: tx.inputs.map(i => ({
          previousOutpoint: { transactionId: i.txid, index: i.index },
          signatureScript: i.sigScriptHex,
          sequence: String(i.sequence ?? 0),
          sigOpCount: i.sigOpCount ?? 1,
        })),
        outputs: tx.outputs.map(o => ({
          value: String(o.value),
          scriptPublicKey: spk(o.spkVersion ?? 0, o.spkScriptHex),
          covenant: o.covenant ?? null,
        })),
        lockTime: String(tx.lockTime ?? 0),
        subnetworkId: "0000000000000000000000000000000000000000",
        gas: 0,
        payload: tx.payloadHex ?? "",
      },
      utxos: utxos.map(u => ({
        amount: String(u.amount),
        scriptPublicKey: spk(u.spkVersion ?? 0, u.spkScriptHex),
        blockDaaScore: String(u.blockDaaScore ?? 0),
        isCoinbase: !!u.isCoinbase,
        covenantId: u.covenantId ?? null,
      })),
    }],
  };
  fs.writeFileSync(file, JSON.stringify(doc, null, 2));
}
```

Run your harness on testnet or simnet keys, or on throwaway keys with made-up funding coins (the file declares every coin it spends, so nothing has to exist on chain, and such a transaction can never be broadcast). A baseline file holds signed transactions; never export one built with mainnet keys you care about.
