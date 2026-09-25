---
tempo-primitives: minor
tempo-contracts: minor
tempo-alloy: patch
---

Added `TempoSignature::Multisig`, `AccountSignature` and `SignatureType::Multisig`, so native multisig signatures can be encoded and decoded; nodes still reject them in every transaction role. `TempoSignature::signature_type` is replaced by `primitive_signature_type`, which returns `None` for multisig signatures, and keychain and key-authorization signatures now hold an `AccountSignature`.
