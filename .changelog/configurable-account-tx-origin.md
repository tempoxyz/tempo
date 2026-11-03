---
tempo-precompiles: minor
tempo-evm: patch
---

The configurable account precompile reads the transaction origin from the EVM transaction environment through the new `PrecompileStorageProvider::tx_origin`, instead of a transient slot seeded by the handler. `upgradeAccount` costs 100 gas less at T14.
