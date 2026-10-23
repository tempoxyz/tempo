---
tempo-precompiles: minor
---

Added the configurable account precompile (`configurable_account::ConfigurableAccount`: `deriveAccount`, `getConfigCommitment`, `updateConfig`, `upgradeAccount`), its transaction-authority seed `set_authority` with `UpgradeEligibility`, and the test-utils fixture setter `HashMapStorageProvider::set_configurable_account_recovery_factory`. Nothing registers or calls the precompile yet.
