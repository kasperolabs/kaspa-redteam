# Security and disclosure

kaspa-redteam never sends a transaction to any network. Covenant attacks run inside a consensus sandbox in the process; node attacks run only against kaspad processes the tool starts itself with `--simnet`, and stop if a node reports mainnet or the mainnet genesis. There is no override.

## Found a bug in someone else's covenant?

1. Tell the author privately first (open a private advisory on their repository, or contact Kaspero Labs to reach them).
2. Allow 30 days, or until a fix is deployed, before the pattern is published.
3. Then it becomes an attack with fixtures in the next library version, so every builder is checked against it.

## Found a bug in kaspa-redteam itself?

Open a GitHub security advisory on this repository.

## Found a consensus or node bug with the node packs?

Report it to the rusty-kaspa maintainers through their security policy before anything else.
