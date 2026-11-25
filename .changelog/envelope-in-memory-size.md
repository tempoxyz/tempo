---
tempo-primitives: patch
---

`TempoTxEnvelope::size` counts the full inline enum for every transaction type, so legacy, EIP-2930, EIP-1559 and EIP-7702 transactions are no longer reported at about a quarter of their in-memory size.
