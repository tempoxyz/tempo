---
tempo-transaction-pool: patch
---

Pooled transaction size now includes the heap copied into the cached transaction environment (access lists, authorization lists, AA calls and key authorization), so pool byte limits no longer undercount these transactions.
