---
tempo-contracts: minor
tempo-precompiles: minor
tempo-evm: minor
---

Registered the configurable account precompile at T14 and stored configuration commitments in the journaled account extension. The first commitment write is priced like account creation and installs the `0xef` account marker (`CONFIGURABLE_ACCOUNT_CODE`, `CONFIGURABLE_ACCOUNT_CODE_HASH`, `valid_account_code`); later writes cost 5,000 gas. `PrecompileStorageProvider::config_commitment` and `set_config_commitment` are now required, `account_config_commitment` decodes a commitment, `CONFIG_COMMITMENT_REGISTRATION_GAS` is removed, and a registered keychain-signed sender is exempt from EIP-3607 from T14. From T14 the handler seeds the upgrade authority, so a root-signed `upgradeAccount` that is the whole transaction registers its sender, and a registered account can be named as a ConfigurableAccount delegate key.
