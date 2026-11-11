---
tempo-contracts: minor
tempo-precompiles: minor
---

Added the T14 `SignatureVerifier.verifyAccount` selector. It checks whether a primitive, keychain or configurable account signature approves a hash for an account under its current state, so a migrated account's original key no longer approves (TIP-1113).
