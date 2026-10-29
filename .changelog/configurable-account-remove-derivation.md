---
tempo-primitives: minor
tempo-precompiles: minor
tempo-evm: minor
tempo-contracts: minor
---

Removed configurable account address derivation and first-use registration. Every configurable account now gets its commitment from TIP-1113 migration (`upgradeAccount`), and a configurable-account signature for an account with a zero commitment is rejected with `NotConfigurable` (`verifyConfigurableAccount` returns `false`). Removed `ConfigurableAccountConfig::derive_account`, `CONFIGURABLE_ACCOUNT_DOMAIN`, the `deriveAccount` precompile method, registration gas and the unregistered address-hash term in verification gas. Keyless accounts use Nick's method on the migration transaction instead.
