---
tempo-primitives: minor
tempo-alloy: patch
---

`Call`, `TempoSignedAuthorization`, `SignedKeyAuthorization` and `TempoTransactionRequest` decode their fields directly instead of through `#[serde(flatten)]`, so unknown fields are skipped rather than buffered. Added `serde_helpers::MapOnly`, which keeps them rejecting arrays as the flattened derives did.
