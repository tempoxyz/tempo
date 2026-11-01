---
tempo-contracts: major
tempo-primitives: minor
---

Starting at T15, payment classification accepts up to 32 extra bytes after the arguments of static-only payment calls, such as an attribution tag (TIP-1045). Added `MAX_PAYMENT_TRAILING_BYTES` and `TempoTxEnvelope::is_payment_v3`. `ITIP20Calls::is_payment` and `ITIP20ChannelReserveCalls::is_payment_with_valid_signature` now take a `max_trailing_bytes` argument.
