---
tempo-contracts: minor
tempo-precompiles: minor
---

From T15, `SignatureVerifier.verify(account, hash, signature)` checks whether a primitive, keychain or configurable account signature approves `hash` for `account` under its current state (TIP-1168): a migrated account's original key no longer verifies. `recover` stays stateless. Before T15, `verify` is unchanged.
