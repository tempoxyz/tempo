---
tempo-evm: patch
tempo-payload-builder: patch
---

Parallel builder replay rechecks the code hash, config commitment and emptiness of every account the prewarmed transaction loaded, and conflicts when one changed earlier in the block, so a configurable account grant to a target that just installed EIP-7702 code is no longer replayed.
