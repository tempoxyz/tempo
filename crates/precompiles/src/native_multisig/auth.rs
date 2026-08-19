#[cfg(test)]
use alloy::primitives::Address;
use alloy::primitives::B256;
use tempo_primitives::transaction::{
    MultisigQuorumError, MultisigSignature, MultisigWeightAccumulator, TempoSignature,
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
        self.validate_authorization_state_inner(signature)
    }

    fn validate_authorization_state_inner(
        &self,
        signature: &MultisigSignature,
    ) -> Result<(), NativeMultisigAuthError> {
        if !is_valid_multisig_account(signature.account(), self.storage.spec()) {
            return Err(NativeMultisigAuthError::invalid_transaction(
                "invalid multisig account",
            ));
        }

        let stored = self.get_config_commitment(signature.account())?;
        let config = signature.config();
        let valid = if config.version == 0 {
            stored.is_zero()
        } else {
            !stored.is_zero() && signature.config_commitment() == stored
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
            self.validate_authorization_state_inner(nested)?;
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
                return weight.finish().map_err(quorum_error);
            }
        }

        weight.finish().map_err(quorum_error)
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
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_primitives::transaction::{
        MultisigConfig, MultisigOwner, PrimitiveSignature, multisig_digest,
    };

    fn signer(seed: u8) -> PrivateKeySigner {
        PrivateKeySigner::from_bytes(&B256::with_last_byte(seed)).unwrap()
    }

    fn initial_config(owners: &[(Address, u8)], threshold: u8) -> MultisigConfig {
        let mut owners = owners
            .iter()
            .map(|&(owner, weight)| MultisigOwner { owner, weight })
            .collect::<Vec<_>>();
        owners.sort_by_key(|owner| owner.owner);
        MultisigConfig {
            salt: B256::ZERO,
            version: 0,
            threshold,
            owners,
        }
    }

    fn signed_initial(
        config: MultisigConfig,
        inner_digest: B256,
        signers: &[&PrivateKeySigner],
    ) -> MultisigSignature {
        let account = config.derive_account().unwrap();
        let digest = multisig_digest(inner_digest, account, 0);
        let approvals = signers
            .iter()
            .map(|signer| {
                TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                    signer.sign_hash_sync(&digest).unwrap(),
                ))
            })
            .collect();
        MultisigSignature::try_new(account, config, approvals).unwrap()
    }

    fn assert_quorum_error(signature: &MultisigSignature, expected: MultisigQuorumError) {
        assert_eq!(
            NativeMultisig::verify_authorization_quorum(B256::repeat_byte(0x42), signature),
            Err(NativeMultisigAuthError::InvalidTransaction(
                expected.as_str().into()
            ))
        );
    }

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
        MultisigSignature::try_new(
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

    #[test]
    fn primitive_quorum_enforces_membership_order_weight_and_minimality() {
        let signer_a = signer(1);
        let signer_b = signer(2);
        let outsider = signer(3);
        let mut owners = [&signer_a, &signer_b];
        owners.sort_by_key(|signer| signer.address());
        let config = initial_config(
            &owners
                .iter()
                .map(|signer| (signer.address(), 1))
                .collect::<Vec<_>>(),
            2,
        );
        let inner_digest = B256::repeat_byte(0x42);

        let valid = signed_initial(config.clone(), inner_digest, &owners);
        assert_eq!(
            NativeMultisig::verify_authorization_quorum(inner_digest, &valid),
            Ok(())
        );

        let insufficient = signed_initial(config.clone(), inner_digest, &owners[..1]);
        assert_quorum_error(&insufficient, MultisigQuorumError::WeightBelowThreshold);

        owners.reverse();
        let unordered = signed_initial(config.clone(), inner_digest, &owners);
        assert_quorum_error(&unordered, MultisigQuorumError::SignersNotAscending);
        owners.reverse();

        let excess = signed_initial(
            MultisigConfig {
                threshold: 1,
                ..config
            },
            inner_digest,
            &owners,
        );
        assert_quorum_error(&excess, MultisigQuorumError::ExcessSignatures);

        let non_owner = signed_initial(
            initial_config(&[(owners[0].address(), 1)], 1),
            inner_digest,
            &[&outsider],
        );
        assert_quorum_error(&non_owner, MultisigQuorumError::SignerNotOwner);
    }

    #[test]
    fn nested_multisig_quorum_is_verified_recursively() {
        let owner = signer(4);
        let inner_digest = B256::repeat_byte(0x42);
        let nested_config = initial_config(&[(owner.address(), 1)], 1);
        let nested_account = nested_config.derive_account().unwrap();
        let outer_config = initial_config(&[(nested_account, 1)], 1);
        let outer_account = outer_config.derive_account().unwrap();
        let nested = signed_initial(
            nested_config,
            multisig_digest(inner_digest, outer_account, 0),
            &[&owner],
        );
        let outer = MultisigSignature::try_new(
            outer_account,
            outer_config,
            vec![TempoSignature::Multisig(nested)],
        )
        .unwrap();

        assert_eq!(
            NativeMultisig::verify_authorization_quorum(inner_digest, &outer),
            Ok(())
        );
    }
}
