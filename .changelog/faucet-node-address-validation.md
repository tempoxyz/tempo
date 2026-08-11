---
tempo: patch
---

Reject a `--faucet.node-address` that is not a URL. The value was taken as an unvalidated string and parsed again in `FaucetArgs::provider`, where a malformed address panicked the node with `Failed to parse node address` instead of failing as a CLI error.
