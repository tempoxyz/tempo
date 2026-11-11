---
tempo-transaction-pool: patch
---

Admission validates transactions again before inserting them when a canonical update landed while they validated, so a transaction validated against the previous state can no longer enter the pool after maintenance scanned for that update.
