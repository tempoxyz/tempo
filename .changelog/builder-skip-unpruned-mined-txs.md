---
tempo-payload-builder: patch
tempo-transaction-pool: minor
---

The payload builder skips transactions mined in recent blocks that the pool has not pruned yet, instead of executing them again and marking them invalid.
