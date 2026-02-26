---
---

Split shared `ghost_keyWrongSignerAllowed` counter into dedicated `ghost_keyRevokedAllowed` (K7) and `ghost_keyExpiredAllowed` (K8) counters so revoked-key and expired-key invariant violations are tracked independently from wrong-signer (K1) violations.
