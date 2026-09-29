---
tempo: patch
---

Keep a caller-supplied `valid_before` in `ExpiringNonceFiller` instead of replacing it with the filler's own expiry window. Only an unset `valid_before` is defaulted now, which matches how the filler already preserves an explicit TIP-1106 discriminator.
