---
tempo-primitives: minor
---

Added `AASigned::decode_for_fee_payer_service`, the inverse of `encode_for_fee_payer_service`, so Rust fee payer services can decode sponsorship requests carrying the `0x00` fee payer signature placeholder.
