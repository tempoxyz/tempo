---
tempo-precompiles: minor
---

Added `StorageCtx::call`, a nested `CALL` or `STATICCALL` from a precompile, with at most `MAX_NESTED_CALLS` running at once and none inside a checkpoint.
