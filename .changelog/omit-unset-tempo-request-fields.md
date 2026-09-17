---
tempo: patch
---

Omit `feeToken`, `keyType`, `keyData` and an empty `calls` from serialized `TempoTransactionRequest`s instead of sending them as `null`/`[]`. A request with no Tempo fields now goes out as a plain Ethereum request, which is how the other seven optional Tempo fields already behave.
