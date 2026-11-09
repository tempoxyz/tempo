---
tempo-precompiles: patch
tempo-evm: patch
---

Parallel builder replay records account code hashes read by precompiles and conflicts when they changed earlier in the block, so a configurable account grant to a target that just installed EIP-7702 code is no longer replayed.
