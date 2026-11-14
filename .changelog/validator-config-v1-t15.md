---
tempo-precompiles: minor
---

From T15, every ValidatorConfig (V1) call and ValidatorConfigV2's `migrateValidator` and `initializeIfMigrated` revert with `UnknownFunctionSelector`. Consensus reads only V2 once it is initialized, so these paths are kept only to replay earlier blocks. Earlier forks are unchanged.
