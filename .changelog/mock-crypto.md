---
tempo-primitives: minor
---

Added `tempo_primitives::crypto` with `verify_p256`, `verify_webauthn` and `verify_ed25519` (and, with the `nitro` feature, `NitroVerifier`). With `mock-crypto`, `crypto::mock` adds keyed mock signature builders, and `mock::install` makes every check also accept them.
