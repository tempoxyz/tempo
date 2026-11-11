---
tempo-transaction-pool: patch
---

Admission validates transactions again before inserting them when a canonical update landed while they validated, and rejects them when one landed during every attempt, so a transaction validated against the previous state can no longer enter the pool after it was maintained for that update.
