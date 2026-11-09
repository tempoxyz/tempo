---
tempo-evm: patch
---

Traces of AA transactions nest their calls under a synthetic root again, as in v1.17, including transactions with a single call. Batches no longer lose every call but the last.
