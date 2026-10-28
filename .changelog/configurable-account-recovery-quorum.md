---
tempo-primitives: minor
---

Signer recovery now verifies configurable account owner quorums: `TempoSignature::recover_signer`, the configurable account access key ID and the sender recovery of a transaction with an inline configurable account key authorization return a recovery error for invalid approvals. `ConfigurableAccountSignature` caches the last verified digest, so `verify_approvals` of an already recovered signature is free, and gains `recover_account`.
