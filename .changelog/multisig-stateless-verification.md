---
tempo-primitives: minor
---

Added `MultisigSignature::verify_approvals` and `MultisigSignature::validate_account_commitment`, which check owner approvals and the account commitment without reading state, along with `MultisigStateError`, `MultisigQuorumError::OwnerSignatureRecoveryFailed` and `MULTISIG_UPGRADE_DOMAIN`. Transaction signatures do not accept multisig signatures yet.
