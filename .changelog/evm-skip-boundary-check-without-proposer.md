---
tempo-evm: patch
tempo-primitives: patch
---

The DKG boundary outcome check is skipped for blocks without a proposer public key, which are blocks executed outside consensus, such as RPC simulations and pending-block environments. Documented when `TempoBlockExt::proposer_public_key` is `None`.
