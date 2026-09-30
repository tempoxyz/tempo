---
tempo: patch
---

Type `--faucet.node-address` as a `Url` so an address that is not a URL is refused by the CLI. The value was previously an unvalidated string that `FaucetArgs::provider` parsed again, where a malformed address panicked the node with `Failed to parse node address`.
