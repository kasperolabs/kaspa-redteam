# Examples

Small contracts in the shapes that came first on other chains, each in a broken and a correct version. The file name says what the red team should report: `_FAIL` has at least one finding, `_PASS` has none and every path explored. `cargo test` checks both. They are also built into the web page (`kaspa-redteam serve`): the Examples grid under the form runs any of them in one click.

| Contract | What it is | `_FAIL` is caught by |
| --- | --- | --- |
| `htlc_swap` | Atomic swap: secret plus timeout refund | SEC-01: the revealed secret is enough to take the coin |
| `last_will` | Inheritance after a period of silence | OUT-01: the heir is not pinned |
| `recurring_payment` | Allowance paid out each period | OUT-01, OUT-03: the change output is not checked |
| `escrow` | Buyer, seller and an arbiter | SIG-02: the arbiter key comes from the caller |
| `crowdfund` | All-or-nothing pledge with refund | OUT-01: the refund can go to anyone |
| `revenue_split` | 70/30 payment splitter | IN-01, IN-02: shares measured against input 0 |
| `price_bet` | Bet settled by an oracle reading | ORC-04: the oracle key comes from the caller |
| `name_registry` | One coin per name, owner in state | ST-01: anyone can rewrite the owner |
| `leaky_vault` | Every classic bug in one file | all ten covenant attacks |

```
kaspa-redteam examples/htlc_swap_FAIL.sil -v
for f in examples/*.sil; do kaspa-redteam "$f" | head -2; done
```
