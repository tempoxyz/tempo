---
tempo-transaction-pool: patch
---

Pooled transaction size now also counts the cached transaction environment, a second copy of the transaction that shares only its calldata with the envelope, so pool byte limits no longer undercount transactions with large access lists, authorization lists or signatures.
