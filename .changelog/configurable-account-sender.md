---
tempo-primitives: minor
tempo-evm: minor
---

From T14 a configurable account can send its own transactions: `TempoSignature::ConfigurableAccount` (type byte `0x05`) carries the owner quorum, the handler checks the account, its code and its configuration commitment, registers the account on first use and verifies the quorum, and a configurable sender can rotate its owners with `updateConfig`. `TempoSignature::signature_type` is now `primitive_signature_type` and returns `None` for a configurable account signature, and `TempoInvalidTransaction::ConfigurableAccount` reports the new `ConfigurableAccountError`. Zones reject configurable account signatures and calls that configure an account.
