# A town budget on Kaspa

Two covenants, the way a small town actually runs its money: a general fund the council controls, and one fund per department that spends on a schedule with two signatures per payment.

| File | What it is |
| --- | --- |
| `town_treasury.sil` | The general fund. One fixed address for taxes, fees, grants and lapsed money. Only a council vote (3 of 5) moves money out. |
| `department_fund.sil` | One coin per department, funded once a year. Pays vendors and payroll within a monthly allotment, with the department head and the treasurer both signing. Returns to the treasury on a council vote, or by itself after the fiscal year. |

## The town

Illustrative numbers for a town of about 5,000 people with a general fund of $6 million a year. Real towns vary widely; the shape is what matters.

| Department | Annual | Monthly allotment | Head (signs requests) |
| --- | --- | --- | --- |
| Police | $1,800,000 | $150,000 | Police chief |
| Fire & EMS | $1,080,000 | $90,000 | Fire chief |
| Public Works (streets, snow, buildings) | $1,320,000 | $110,000 | Public works director |
| Administration (clerk, finance, IT, legal) | $720,000 | $60,000 | Town manager |
| Parks & Recreation | $480,000 | $40,000 | Parks director |
| Library | $300,000 | $25,000 | Library director |
| Emergency reserve | $300,000 | $100,000 | Mayor |

Water and sewer are usually an enterprise fund, paid by utility bills and kept apart from taxes. That is a second `town_treasury.sil` with its own address, and its own department funds if it wants them.

The emergency reserve is just another department fund whose head is the mayor, with a higher monthly cap: emergency spending needs no special code.

## The people and their keys

| Role | Key | Can do |
| --- | --- | --- |
| Council (5 members) | one key each | With any 3: move treasury money (fund departments, capital projects, transfers); recall any department fund to the treasury |
| Treasurer | one key | Countersign every department payment; merge treasury deposits |
| Each department head | one key | Request payments from their own fund |
| Anyone | none | After the fiscal year ends, send a department's unspent money back to the treasury |

Nobody can spend alone. The treasurer cannot pay anyone without a department head, a department head cannot pay anyone without the treasurer, and the council needs three of five.

## How a year runs

1. **Revenue.** Taxes, fees and grants are paid to the treasury address. It never changes, so it can be printed on tax bills.
2. **Budget adoption.** The council votes the budget. Three members sign one `appropriate` transaction that creates one department fund per department, each holding its annual amount, with its monthly allotment written into it.
3. **Every month.** Departments pay vendors and payroll. Each payment is a `pay` transaction signed by the head and the treasurer. The fund records how much was paid this month and refuses anything over the allotment. The first payment of a new month uses `payNextPeriod`, which starts the count over.
4. **Mid-year change.** The council recalls a fund (3 signatures) and the money goes back to the treasury, then funds a new one with the amended amount.
5. **Year end.** After the fiscal year ends, anyone can send each department's leftover back to the treasury (`lapse`). No key is needed, so the money comes home even if a department head has left.
6. **Housekeeping.** Many small tax payments pile up as separate coins at the treasury address. The treasurer merges them with `consolidate`; every sompi stays in the treasury.

## What the chain guarantees, and what it does not

Guaranteed by the covenants:
- Two signatures on every department payment, three of five for the treasury.
- No department spends more than its allotment in any month, and never ahead of schedule.
- Department money can only leave to a payee both signers approved, or back to the town's own treasury.
- Unspent money returns to the treasury at year end without anyone's key.

Not something the chain can do:
- Know what a payment was for. Invoices, payroll records and audits stay off chain; the chain records who signed, where the money went and when.
- Count calendar months. It checks "at least 30 days after the period started". A month nobody spent can be caught up later; spending can never get ahead.
- Stop people who agree. A department head and the treasurer together can pay a bad invoice, within the allotment. That is what audits and elections are for. The covenant limits how much damage one bad month can do.

## Deploying it

1. Deploy `town_treasury.sil` first, with the treasurer's key, the five council keys and a fee cap.
2. For each department, deploy `department_fund.sil` with the treasury's script hash, the head, the treasurer, the five council keys, the monthly allotment, the period, the fiscal year end and the first period start.
3. The council's first `appropriate` funds every department in one transaction.

## Try a whole year in an afternoon

For a demo, use short times so nothing sits locked for months:

| Setting | Real town | Demo |
| --- | --- | --- |
| `period` | 30 days (2,592,000,000 ms) | 10 minutes (600,000 ms) |
| `fiscalYearEnd` | Dec 31 | 2 hours after deploy |
| `allotment` | monthly budget | 1 KAS |
| Funding | annual budget | 5 KAS per department |

If you hold all five council keys during the demo, you can recall every fund at any moment, so nothing is ever stuck.

## Red team results

Run with kaspa-redteam v0.3.7: both contracts are fully explored and every attack is rejected.

- `town_treasury.sil`: `appropriate` (3 of 5 council) and `consolidate` (treasurer) explored; signature attacks rejected.
- `department_fund.sil`: `pay`, `payNextPeriod`, `recall` and `lapse` explored, including later months; 7 attacks run, 7 rejected. `lapse` needs no signature, and the output attacks could not redirect or shrink it.
