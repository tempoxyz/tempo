---
tempo-primitives: minor
---

Added `tempo_primitives::crypto` with `verify_p256`, `verify_webauthn`, `verify_ed25519` and, with `std`, `verify_p384_der` and `verify_p384_fixed`, plus `KeychainVersion::signing_hash` and `P256SignatureWithPreHash::digest`. With `mock-crypto`, `crypto::mock` adds keyed mock signature builders, and `mock::install` makes every check also accept them.
