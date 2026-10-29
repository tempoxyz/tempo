---
tempo-precompiles: minor
---

From T14 (TIP-1137), `authorizeAdminKey` and inline `is_admin` key authorizations are rejected, and keys stored as admin act as regular access keys without limits: they keep signing but no longer pass `isAdminKey`, `verifyKeychainAdmin` or any key-management check. Earlier forks are unchanged.
