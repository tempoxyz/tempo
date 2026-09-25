---
tempo: patch
---

Keep a caller-supplied `nonce_key` in `ExpiringNonceFiller` instead of replacing it with the expiring nonce key, and leave the validity window to expiring nonces. `Random2DNonceFiller` already leaves a caller's key alone.
