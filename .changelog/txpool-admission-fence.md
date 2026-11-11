---
tempo-transaction-pool: patch
---

Admission validates again the transactions it inserted when a canonical update landed while they validated, so a transaction validated against the previous state can no longer stay pooled after maintenance scanned for that update.
