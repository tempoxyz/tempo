use alloy::primitives::{Address, B256};
use tempo_primitives::transaction::{
    MAX_MULTISIG_NESTING_DEPTH, MultisigQuorumError, MultisigSignature, MultisigWeightAccumulator,
    TempoSignature,
};

use super::NativeMultisig;
use crate::{error::TempoPrecompileError, is_valid_multisig_account};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NativeMultisigAuthError {
    #[error("{0}")]
    InvalidTransaction(String),
    #[error("{0}")]
    ValidationFailed(String),
    #[error("Fatal precompile error: {0:?}")]
    Fatal(String),
}

impl From<TempoPrecompileError> for NativeMultisigAuthError {
    fn from(err: TempoPrecompileError) -> Self {
        match err {
            TempoPrecompileError::Fatal(err) => Self::Fatal(err),
            err if err.is_system_error() => Self::Fatal(err.to_string()),
            err => Self::ValidationFailed(err.to_string()),
        }
    }
}

impl NativeMultisigAuthError {
    fn invalid_transaction(reason: impl Into<String>) -> Self {
        Self::InvalidTransaction(reason.into())
    }

    fn validation_failed(reason: impl Into<String>) -> Self {
        Self::ValidationFailed(reason.into())
    }
}

impl NativeMultisig {
    /// Validates every configuration witness against its account's current commitment.
    pub fn validate_authorization_state(
        &self,
        signature: &MultisigSignature,
    ) -> Result<(), NativeMultisigAuthError> {
        let mut account_path = vec![signature.account()];
        self.validate_authorization_state_inner(signature, &mut account_path)
    }

    fn validate_authorization_state_inner(
        &self,
        signature: &MultisigSignature,
        account_path: &mut Vec<Address>,
    ) -> Result<(), NativeMultisigAuthError> {
        signature
            .validate_shape()
            .map_err(|error| NativeMultisigAuthError::invalid_transaction(error.as_str()))?;
        if !is_valid_multisig_account(signature.account(), self.storage.spec()) {
            return Err(NativeMultisigAuthError::invalid_transaction(
                "invalid multisig account",
            ));
        }

        let stored = self.get_config_commitment(signature.account())?;
        let config = signature.config();
        let valid = if config.version == 0 {
            stored.is_zero()
                && config
                    .derive_account()
                    .is_ok_and(|account| account == signature.account())
        } else {
            !stored.is_zero() && config.commitment().is_ok_and(|expected| expected == stored)
        };
        if !valid {
            return Err(NativeMultisigAuthError::validation_failed(
                "multisig configuration commitment mismatch",
            ));
        }

        for approval in signature.signatures() {
            let TempoSignature::Multisig(nested) = approval else {
                continue;
            };
            let account = nested.account();
            if account_path.len() >= MAX_MULTISIG_NESTING_DEPTH {
                return Err(NativeMultisigAuthError::invalid_transaction(
                    "native multisig nesting depth exceeded",
                ));
            }
            if account_path.contains(&account) {
                return Err(NativeMultisigAuthError::invalid_transaction(
                    "native multisig owner cycle detected",
                ));
            }
            account_path.push(account);
            self.validate_authorization_state_inner(nested, account_path)?;
            account_path.pop();
        }
        Ok(())
    }

    /// Verifies owner membership, ordering, signatures, and quorum for a validated witness tree.
    pub fn verify_authorization_quorum(
        inner_digest: B256,
        signature: &MultisigSignature,
    ) -> Result<(), NativeMultisigAuthError> {
        let digest = signature.digest(inner_digest);
        let config = signature.config();
        let mut weight = MultisigWeightAccumulator::new(config.threshold).map_err(quorum_error)?;

        for (index, approval) in signature.signatures().iter().enumerate() {
            let owner = match approval {
                TempoSignature::Primitive(primitive) => {
                    primitive.recover_signer(&digest).map_err(|_| {
                        NativeMultisigAuthError::invalid_transaction(
                            "invalid multisig owner signature",
                        )
                    })?
                }
                TempoSignature::Multisig(nested) => {
                    Self::verify_authorization_quorum(digest, nested)?;
                    nested.account()
                }
                TempoSignature::Keychain(_) => {
                    return Err(NativeMultisigAuthError::invalid_transaction(
                        "keychain signatures cannot authorize native multisig owners",
                    ));
                }
            };

            let owner_weight = config
                .owner_weight(owner)
                .ok_or_else(|| quorum_error(MultisigQuorumError::SignerNotOwner))?;
            weight
                .record_owner(owner, owner_weight)
                .map_err(quorum_error)?;
            if weight.has_quorum() {
                if index + 1 != signature.signatures().len() {
                    return Err(quorum_error(MultisigQuorumError::ExcessSignatures));
                }
                return weight.finish().map(|_| ()).map_err(quorum_error);
            }
        }

        weight.finish().map(|_| ()).map_err(quorum_error)
    }
}

fn quorum_error(error: MultisigQuorumError) -> NativeMultisigAuthError {
    NativeMultisigAuthError::invalid_transaction(error.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{Handler, StorageCtx, hashmap::HashMapStorageProvider};
    use alloy::primitives::Signature;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_primitives::transaction::{MultisigConfig, MultisigOwner, PrimitiveSignature};

    fn signature(version: u64) -> MultisigSignature {
        let config = MultisigConfig {
            salt: B256::ZERO,
            version,
            threshold: 1,
            owners: vec![MultisigOwner {
                owner: Address::repeat_byte(0x11),
                weight: 1,
            }],
        };
        let account = if version == 0 {
            config.derive_account().unwrap()
        } else {
            Address::repeat_byte(0x22)
        };
        MultisigSignature::from_decoded(
            account,
            config,
            vec![TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                Signature::test_signature(),
            ))],
        )
        .unwrap()
    }

    #[test]
    fn initial_witness_requires_zero_commitment() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
        StorageCtx::enter(&mut storage, || {
            NativeMultisig::new().validate_authorization_state(&signature(0))
        })?;
        Ok(())
    }

    #[test]
    fn current_witness_requires_matching_commitment() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
        let signature = signature(1);
        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.config_commitments[signature.account()]
                .write(signature.config().commitment().unwrap())?;
            multisig.validate_authorization_state(&signature)
        })?;
        Ok(())
    }
}
