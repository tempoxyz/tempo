---
tempo-precompiles: minor
---

Added nested calls from precompiles. `StorageCtx::call` runs a `CALL` or `STATICCALL` from the running precompile into another account and reports a `CallOutcome`. It is backed by the new `PrecompileStorageProvider::call`.
