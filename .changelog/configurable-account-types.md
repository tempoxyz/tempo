---
tempo-primitives: minor
---

Added configurable account primitives: `ConfigurableAccountOwner`, `ConfigurableAccountConfig` and `ConfigurableAccountSignature`, with their encoding, account derivation, configuration commitments and owner-quorum weight accounting. Transaction signatures do not accept them yet. Derived account addresses are the last 20 bytes of the hash of the initial configuration (TIP-1110).
