---
tempo-precompiles: minor
---

Added nested calls from precompiles. `StorageCtx::call` runs a `CALL` or `STATICCALL` from the running precompile into another account and reports a `CallOutcome`. It is backed by the new `PrecompileStorageProvider::call`. At most `MAX_NESTED_CALLS` nested calls run at once, and `StorageCtx::can_call` tells whether the precompile runs where it can make one. A transaction that makes a nested call is not rebuilt from its storage actions: `StorageActions::take_replay` returns `None` for it.
