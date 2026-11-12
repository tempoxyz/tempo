---
tempo-precompiles: minor
---

Added nested calls from precompiles. `StorageCtx::call` runs a `CALL` or `STATICCALL` from the running precompile into another account and reports a `CallOutcome`. It is backed by the new `PrecompileStorageProvider::call`. At most `MAX_NESTED_CALLS` nested calls run at once: a call past that fails the precompile call with `TempoPrecompileError::NestedCallLimitReached`. `StorageCtx::can_call` tells whether the precompile runs where it can make a nested call, which fails with `TempoPrecompileError::NestedCallUnavailable` elsewhere. A checkpoint revert settles the gas merged from the nested callees it rolls back as if they had reverted. A transaction that makes a nested call is not rebuilt from its storage actions: `StorageActions::take_replay` returns `None` for it.
