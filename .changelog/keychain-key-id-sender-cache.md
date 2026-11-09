---
tempo-evm: patch
---

`TempoAaTx::new` recovers the keychain access key id when the transaction environment is built, so a sender recovery cache hit during block conversion no longer leaves that recovery to serial execution.
