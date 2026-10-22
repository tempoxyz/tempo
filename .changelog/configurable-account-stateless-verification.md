---
tempo-primitives: minor
---

Added `ConfigurableAccountSignature::verify_approvals` and `ConfigurableAccountSignature::validate_account_commitment`, which check owner approvals and the account commitment without reading state, along with `ConfigurableAccountStateError`, `ConfigurableAccountQuorumError::OwnerSignatureRecoveryFailed` and `CONFIGURABLE_ACCOUNT_UPGRADE_DOMAIN`. Transaction signatures do not accept configurable account signatures yet.
