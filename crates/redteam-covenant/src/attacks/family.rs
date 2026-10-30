//! Pack `family`: transactions that spend coins of several programs of a
//! project together (a bridge and its mint authority) and create coins of a
//! third (the token cells). The hostile versions are built by `family`, where
//! the other programs are known; each attack here runs its own kind.

use crate::runner::{AttackCx, Attempt, CovenantAttack, CovenantPlugin};
use redteam_core::{AttackMeta, Severity, Target};

pub struct Fam(&'static AttackMeta, u32);

impl CovenantAttack for Fam {
    fn meta(&self) -> &'static AttackMeta {
        self.0
    }
    fn order(&self) -> u32 {
        self.1
    }
    fn attempts(&self, cx: &AttackCx) -> Result<Vec<Attempt>, String> {
        let id = self.0.id;
        let out: Vec<Attempt> = cx
            .live_paths()
            .flat_map(|(p, b)| {
                b.variants.iter().filter(move |v| v.0 == id).map(move |(_, label, plan, why)| Attempt {
                    path: p.entry.clone(),
                    label: label.clone(),
                    plan: plan.clone(),
                    explanation: why.clone(),
                    severity: None,
                    takeover: false,
                })
            })
            .collect();
        if out.is_empty() {
            return Err("no explored spend creates coins of another program (give the project's files together)".into());
        }
        Ok(out)
    }
}

macro_rules! fam {
    ($name:ident, $id:literal, $title:literal, $catches:literal, $fix:literal, $practice:literal, $order:literal) => {
        static $name: AttackMeta = AttackMeta {
            id: $id,
            pack: "family",
            target: Target::Covenant,
            title: $title,
            catches: $catches,
            severity: Severity::High,
            fix_pattern: $fix,
            in_practice: $practice,
        };
        inventory::submit! { CovenantPlugin(&Fam(&$name, $order)) }
    };
}

fam!(FAM01, "FAM-01", "Mint more than allowed",
    "new coins' amounts not checked against what the proof, data or allowance permits",
    "validateOutputStateWithTemplate(idx, Cell { amount: amount_from_journal, ... }, prefix, suffix, template);  // in the program that holds the proof",
    "Whoever relays a valid proof or reading writes a bigger amount into the coin it creates. The mint authority checks only that the coin is well formed; the amount has to be checked where the proof is.",
    40);
fam!(FAM02, "FAM-02", "Mint to the attacker",
    "new coins' owner not bound to the recipient the data names",
    "owner: byte[32](journal.slice(...))  // the owner comes from the proven data, never from the spender",
    "Whoever relays a valid proof keeps the minted coin by naming themselves as owner. Relaying is permissionless, so the first relayer wins.",
    41);
fam!(FAM03, "FAM-03", "Mint one coin twice",
    "number of new coins not tied to the number of records the data pays for",
    "require(OpCovOutputCount(token) == 1 + mints);",
    "A relayer adds a second copy of a coin the data pays for once. Every deposit pays out twice.",
    42);
fam!(FAM04, "FAM-04", "Coin of the right program, wrong family",
    "new coins not required to be in the token's covenant family",
    "validate new coins at OpCovOutputIdx(token, k), never at a bare output index",
    "A coin with the token's exact program but another covenant id looks real to anyone who checks only the script. Wallets and indexers must check the covenant id, and so must the contract that creates coins.",
    43);
fam!(FAM05, "FAM-05", "Authority does not continue",
    "the other program's coin (a mint authority) allowed to end or move in a normal spend",
    "require(tx.outputs[auth_out].scriptPubKey == tx.inputs[auth_in].scriptPubKey);  // and its value",
    "Whoever relays a spend takes the authority's KAS or ends minting for good, under cover of an ordinary mint.",
    44);
fam!(FAM06, "FAM-06", "Replay the same proof on the next state",
    "data already processed accepted again (no cursor, nonce or state binding)",
    "require(nonce > prev_state.cursor);  // and move the cursor past every record",
    "Proofs and readings are public once used. Anyone resubmits the same one after it was processed and mints again.",
    45);
fam!(FAM07, "FAM-07", "Start the family a second time",
    "a genesis path that can run again after the family exists",
    "require(prev_state.token == ZERO32);  // and record the new family id in the successor state",
    "Anyone runs the start-up path again and creates a second family of the same program next to the real one, for example a second mint authority.",
    46);
fam!(FAM08, "FAM-08", "Hand out the minting power",
    "new coins allowed to carry the authority (a minter flag, an owner by covenant id)",
    "require(!recipientState.isMinter);  // only the authority's own continuation may carry it",
    "A recipient gets a coin that can mint, and from then on mints as much as they like. The token's supply is no longer controlled by the contract.",
    47);
fam!(FAM09, "FAM-09", "Take tokens without paying",
    "a permissionless path that hands out coins of another program without the coin under test receiving KAS for them",
    "require(tx.outputs[next].value >= tx.inputs[this.activeInputIndex].value + price(sold, m));",
    "Nothing but a price check stands between anyone and the program's tokens. Without it, the first spender after deployment takes the supply.",
    48);
