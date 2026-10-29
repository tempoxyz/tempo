---
tempo-contracts: minor
---

From T14 the signature verifier precompile exposes `verifyConfigurableAccount(account, hash, signature)`: it returns whether a configurable account signature's owner quorum approves `hash` for `account` against its current configuration, and reverts for malformed or invalid approvals. Its calldata is exempt from the primitive signature size cap.
