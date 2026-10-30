---
tempo-alloy: minor
---

From T14 RPC simulation can model configurable account owner quorums. `TempoTransactionRequest` gains `configurableAccountSimulation`, the claimed quorum of the sender or of the `keyId` delegate, and `keyAuthorizationSimulation`, the claimed quorum of the parent or admin signing the attached key authorization. Simulation checks the claimed approvals against the configuration and builds mock owner signatures in their place, verifies the owner quorum of a configurable-signed key authorization sent without one, and refuses to sign a request that carries either field.
