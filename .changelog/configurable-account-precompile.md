---
tempo-precompiles: minor
---

Added the configurable account precompile (`configurable_account::ConfigurableAccount`: `deriveAccount`, `getConfigCommitment`, `updateConfig`, `upgradeAccount`) and its transaction-authority seed `set_authority` with `UpgradeEligibility`. Nothing registers or calls the precompile yet.
