# Adding an attack

An attack is one struct in one file. The runner, `--only`, `list`, the report, findings, replay and the badge pick it up from the `inventory::submit!` line. Nothing else is edited.

## Covenant attack

1. Pick a stable ID in an existing pack (`OUT-04`) or a new pack (`ST-01`). IDs are never reused.
2. Add the struct to the pack's file under `crates/redteam-covenant/src/attacks/` (new pack: new file plus a `pub mod` line in `attacks/mod.rs`).
3. Write `attempts()`: start from the honest spends the engine already found and return mutated plans.
4. Add `fixtures/<ID>/vulnerable.sil` (must be caught) and `fixtures/<ID>/fixed.sil` (the whole library must stay silent, every path explored).
5. `cargo test`.

```rust
pub struct Out04;
static OUT04: AttackMeta = AttackMeta {
    id: "OUT-04",
    pack: "outputs",
    target: Target::Covenant,
    title: "Reorder the outputs",
    catches: "index assumptions",
    severity: Severity::High,
    fix_pattern: "pin each output by index: script and value",
};

impl CovenantAttack for Out04 {
    fn meta(&self) -> &'static AttackMeta { &OUT04 }
    fn order(&self) -> u32 { 22 }            // takeover attacks < 20, partial ones after
    fn attempts(&self, cx: &AttackCx) -> Result<Vec<Attempt>, String> {
        let mut out = Vec::new();
        for (p, b) in cx.live_paths().filter(|(_, b)| b.permissionless() && b.plan.outputs.len() >= 2) {
            let mut plan = b.plan.clone();
            plan.outputs.reverse();
            out.push(Attempt {
                path: p.entry.clone(),
                label: "outputs reversed".into(),
                plan,
                explanation: "...what it means if consensus accepts this...".into(),
                severity: None,       // or Some(..) to override per attempt
                takeover: false,      // true = attacker gets the whole path
            });
        }
        Ok(out)
    }
}
inventory::submit! { CovenantPlugin(&Out04) }
```

What you get in `cx`:

- `cx.live_paths()` yields `(PathStatus, Baseline)` for every path with an honest spend that no earlier attack already took over.
- `Baseline.plan` is a `SpendPlan`: inputs (covenant coins with argument recipes, or P2PK coins), outputs (`Dest::Key(KeyRef)` or `Dest::SelfCovenant`), lock time, DAA score, median time.
- `Baseline.signers` lists the parties whose signatures the path needed; empty means anyone can build the spend. `Baseline.secrets` lists preimages it revealed.
- Argument recipes: `ArgRecipe::Value`, `ArgRecipe::Sig(KeyRef)` (signed for real after the tx is final), `ArgRecipe::RawSig(bytes)`, `ArgRecipe::DataSigOf { key, arg, hash }` (a reading over argument `arg`).
- Inputs: `InputSpec::Covenant` (with an optional runtime `state`), `P2pk`, `StandIn` (a coin at an address the covenant names), `Raw` (imported). Use `plan.first_target()` to find the covenant input and `InputSpec::duplicate()` to add a second copy.
- Destinations: `Dest::Key`, `SelfCovenant`, `Successor(state)`, `StandIn(i)`, `Raw(spk)`. `crate::dest_label` turns one into words.
- Imported baselines (`--baseline`) arrive as ordinary paths with `imported: true`, so most attacks need no special handling.
- Helpers in `attacks/mod.rs`: `pay_all_to_attacker`, `map_covenant_args`.

Rules the runner enforces:

- One finding per path per attack (the first accepted variant), so order variants from most to least severe.
- A path taken over (`takeover: true` accepted) is skipped by every later attack.
- Unbuildable plans (the ABI refuses an argument) count as rejected.

## Node or mining attack

Same shape in `crates/redteam-node/src/attacks/`, implementing `NodeAttack`:

```rust
impl NodeAttack for Node04 {
    fn meta(&self) -> &'static AttackMeta { &NODE04 }
    fn needs_coins(&self) -> bool { true }   // runner mines to maturity first
    fn run(&self, sim: &SimNet, cx: &mut NodeCx) -> Outcome { ... }
}
inventory::submit! { NodePlugin(&Node04) }
```

`sim.rpc(i)` is a wRPC client to node `i`, `sim.mine(n)` mines on node 0, `cx.coins` holds mature coins owned by `sim.miner`, `attacks::p2pk_spend` builds a signed spend. Include a control (an honest version that must succeed) whenever "rejected" could also mean "your setup was wrong", as MINE-01 does. Run with `REDTEAM_DEBUG=1` to see every verdict.

## Severity

- HIGH: funds can be stolen.
- MED: funds stuck, or leaked to fees.
- LOW: griefing, timing taken from its owner, degraded liveness.

## The incident loop

When a covenant bug is found anywhere in the ecosystem: reduce it to a pattern, write the attack with both fixtures, note the source in CHANGELOG.md, bump `LIBRARY_VERSION` in `redteam-core`. Every contract that re-runs is then checked against it, and older badges show their age.
