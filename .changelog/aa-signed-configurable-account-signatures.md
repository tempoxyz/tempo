---
tempo-primitives: minor
---

Added `AASigned::configurable_account_signatures`, which returns the configurable account signatures approving a transaction: the outer signature, directly or inside a keychain envelope, then the inline key authorization's.
