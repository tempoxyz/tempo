---
tempo-precompiles: patch
tempo-evm: patch
---

Parallel builder replay records the code hash of a configurable account grant target and conflicts when it changed earlier in the block, so a grant to a target that just installed EIP-7702 code is no longer replayed.
