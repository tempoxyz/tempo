---
tempo-evm: patch
---

Block conversion recovers keychain and configurable account transactions instead of reading their sender from the sender recovery cache, so the access key id and owner quorum verification they cache run in the parallel conversion step rather than serial execution.
