---
tempo-transaction-pool: patch
---

Admission rechecks transactions it inserted after a canonical update was published while they validated, using the same checks pool maintenance applies to that update, and validates affected ones again, so a transaction validated against the previous state can no longer stay pooled after maintenance scanned for that update.
