---
tempo-contracts: minor
tempo-precompiles: minor
---

(+T15) `SignatureVerifier.verify` checks whether the account approves the hash under its current state, so a migrated account's original key no longer verifies (TIP-1168). `recover` stays stateless.
