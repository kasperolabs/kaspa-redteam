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
                    // Sweeping stray coins on a path only a key holder can spend:
                    // that holder alone gains, from tokens sent by mistake.
                    severity: (id == "FAM-10" && !b.permissionless()).then_some(Severity::Med),
                    takeover: false,
                })
            })
            .collect();
        if out.is_empty() {
            return Err(if self.0.pack == "borrow" {
                if id >= "BOR-03" {
                    "no token program with a borrowed receive among the explored paths".into()
                } else if id == "BOR-02" {
                    "no explored spend lets a stranger borrow a coin the covenant holds (see BOR-01)".into()
                } else {
                    "no coin the covenant holds was bricked by a borrow (where a borrow only moves it, see BOR-02)".into()
                }
            } else {
                "no explored spend creates coins of another program (give the project's files together)".into()
            });
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
fam!(FAM10, "FAM-10", "Sweep coins sent to the covenant",
    "a second coin of the token owned by the covenant's id (tokens sent to it by mistake, a second deposit) spent and taken in a normal spend",
    "require(OpCovInputCount(tokenCovId) == 1);  // or count and return every coin the covenant owns",
    "Someone sends tokens to an order's or a market's covenant id, or a second deposit lands there. The next spender includes that coin and takes its tokens, because the contract checks only the coin it is pointed at.",
    49);

macro_rules! bor {
    ($name:ident, $id:literal, $title:literal, $catches:literal, $fix:literal, $practice:literal, $sev:expr, $order:literal) => {
        static $name: AttackMeta = AttackMeta {
            id: $id,
            pack: "borrow",
            target: Target::Covenant,
            title: $title,
            catches: $catches,
            severity: $sev,
            fix_pattern: $fix,
            in_practice: $practice,
        };
        inventory::submit! { CovenantPlugin(&Fam(&$name, $order)) }
    };
}

bor!(BOR01, "BOR-01", "A stranger borrows the coin it holds and bricks it",
    "a covenant that holds a token coin with borrowing on (KCC-20 borrowed receive) and expects an exact amount",
    "require(tok.borrow_scheme == BORROW_DISABLED);  // on every token coin the covenant takes into custody, and on the ones it creates",
    "KCC-20 lets anyone add tokens to a coin whose borrow scheme allows it, without the owner. The covenant is not in that transaction, so it cannot object, and afterwards its coin holds one unit more than its books say.",
    Severity::High, 50);
bor!(BOR02, "BOR-02", "A stranger borrows the coin it holds",
    "a covenant that holds a token coin with borrowing on: its outpoint can be changed by anyone",
    "require(tok.borrow_scheme == BORROW_DISABLED);  // or accept that anyone can move the coin's outpoint",
    "Anyone adds a token unit to the covenant's coin through a borrowed receive. Nothing is lost, but the coin's outpoint keeps changing, so prepared transactions fail and the covenant's users must look it up again each time.",
    Severity::Low, 51);
bor!(BOR03, "BOR-03", "A borrow takes the coin",
    "a token program whose borrowed receive lets the borrowed coin change owner",
    "require(next_states[0].owner == owner && next_states[0].owner_scheme == owner_scheme);  // on the borrow path",
    "Borrowing exists so senders can add to a coin the recipient already has. If the coin can come back with another owner, anyone allowed to borrow takes it.",
    Severity::High, 52);
bor!(BOR04, "BOR-04", "A borrow adds nothing",
    "a token program whose borrowed receive does not require the amount to grow",
    "require(next_states[0].amount - amount > amount_threshold);",
    "A borrow is supposed to bring tokens. Without the increase rule, anyone allowed to borrow moves the coin as often as they like for nothing.",
    Severity::Med, 53);
bor!(BOR05, "BOR-05", "A borrow takes the coin's KAS",
    "a token program whose borrowed receive lets the coin's KAS value drop",
    "require(tx.outputs[OpAuthOutputIdx(this.activeInputIndex, 0)].value >= tx.inputs[this.activeInputIndex].value);",
    "Every token coin carries KAS. A borrower who may lower it keeps the difference, coin after coin.",
    Severity::High, 54);
bor!(BOR06, "BOR-06", "A borrow without the borrow key",
    "a token program that does not check the borrow key or the hash-chain link",
    "require(checkSig(borrow_signature, pubkey(borrow_guard)));  // key scheme; hash-chain: the revealed link must hash to the guard",
    "An owner who allows one borrower, or one borrow at a time, finds that anyone can borrow.",
    Severity::Med, 55);
bor!(BOR07, "BOR-07", "A borrow rewrites the borrow settings",
    "a token program whose borrowed receive lets the borrow scheme or guard change",
    "require(next_states[0].borrow_scheme == borrow_scheme && next_states[0].borrow_guard == next_borrow_guard);",
    "The borrower decides who may borrow next, opens the coin to everyone, or shuts the owner's chosen borrower out.",
    Severity::Med, 56);
