---
tempo-primitives: minor
---

Signer recovery now verifies configurable account owner quorums: `TempoSignature::recover_signer` returns a recovery error for invalid approvals. `ConfigurableAccountSignature` caches the last verified digest, so `verify_approvals` of an already recovered signature is free, and gains `recover_account`.
