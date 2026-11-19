---
tempo-primitives: minor
---

Added the `fuzz-crypto` feature and `tempo_primitives::fuzz_crypto`: keyed signature stand-ins that a fuzzing harness can turn on with `fuzz_crypto::enable`, after which P256 and WebAuthn checks also accept them. Nothing changes until `enable` is called.
