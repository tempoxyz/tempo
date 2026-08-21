---
tempo-primitives: minor
---

Added `AASigned::decode_for_fee_payer_service`, the inverse of `encode_for_fee_payer_service`, so Rust fee payer services can decode sponsorship requests. Both ox-compatible request forms are supported: the `0x00` fee payer signature placeholder and the bare sender address used by multisig finalize flows, which is returned alongside the transaction.
