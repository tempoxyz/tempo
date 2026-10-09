---
tempo-primitives: patch
---

Reject WebAuthn signatures whose `webauthnData` exceeds `MAX_WEBAUTHN_DATA_LENGTH` when deserializing from JSON, matching the bound already enforced by `PrimitiveSignature::from_bytes`. Oversized key authorization signatures in `eth_call` and `eth_estimateGas` requests are now refused instead of being parsed and hashed during simulation.
