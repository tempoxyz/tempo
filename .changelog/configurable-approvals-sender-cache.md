---
tempo-evm: patch
---

`TempoAaTx::new` verifies configurable account owner approvals when the transaction environment is built, so a sender recovery cache hit during block conversion no longer leaves that verification to serial execution.
