---
tempo-transaction-pool: patch
---

The pool address filter now also checks every configured owner of a configurable account that signs a transaction directly, as a keychain access key or as an inline key grant, so a filtered owner can no longer transact through a configurable account.
