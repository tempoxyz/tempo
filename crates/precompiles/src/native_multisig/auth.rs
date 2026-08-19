use alloy::primitives::{Address, B256};
use tempo_primitives::transaction::{
    InitMultisig, MAX_MULTISIG_NESTING_DEPTH, MultisigQuorumError, MultisigSignature,
    MultisigWeightAccumulator, TempoSignature,
};

use super::{NativeMultisig, RegisteredMultisigConfig};
use crate::error::TempoPrecompileError;

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

#[derive(Clone, Debug)]
pub enum NativeMultisigAuthConfig<'a> {
    Inline(&'a InitMultisig),
    /// An inline config carried by the transaction's other multisig authorization.
    BootstrapCompanion(&'a InitMultisig),
    Registered(RegisteredMultisigConfig),
}

impl NativeMultisigAuthConfig<'_> {
    fn matches_signature(&self, signature: &MultisigSignature) -> bool {
        match (self, signature.init()) {
            (Self::Inline(expected), Some(actual)) => *expected == actual,
            (Self::BootstrapCompanion(_), None) => true,
            (Self::Registered(_), None) => true,
            _ => false,
        }
    }

    fn invalid_owner_signature(&self) -> NativeMultisigAuthError {
        match self {
            Self::Inline(_) | Self::BootstrapCompanion(_) => {
                NativeMultisigAuthError::invalid_transaction("invalid multisig owner signature")
            }
            Self::Registered(_) => {
                NativeMultisigAuthError::validation_failed("invalid multisig owner signature")
            }
        }
    }

    fn threshold(&self) -> u8 {
        match self {
            Self::Inline(config) | Self::BootstrapCompanion(config) => config.threshold,
            Self::Registered(config) => config.threshold,
        }
    }

    fn version(&self) -> u64 {
        match self {
            Self::Inline(_) | Self::BootstrapCompanion(_) => 0,
            Self::Registered(config) => config.version,
        }
    }

    fn owner_weight(&self, owner: Address) -> Result<u8, NativeMultisigAuthError> {
        let weight = match self {
            Self::Inline(config) | Self::BootstrapCompanion(config) => {
                config.owner_weight(owner).unwrap_or_default()
            }
            Self::Registered(config) => config
                .owners
                .binary_search_by_key(&owner, |configured| configured.owner)
                .ok()
                .map(|index| config.owners[index].weight)
                .unwrap_or_default(),
        };
        if weight == 0 {
            return Err(self.quorum_error(MultisigQuorumError::SignerNotOwner));
        }
        Ok(weight)
    }

    fn validate(&self) -> Result<(), NativeMultisigAuthError> {
        match self {
            Self::Inline(config) | Self::BootstrapCompanion(config) => config
                .validate()
                .map(|_| ())
                .map_err(|err| NativeMultisigAuthError::validation_failed(err.as_str())),
            Self::Registered(_) => Ok(()),
        }
    }

    fn quorum_error(&self, err: MultisigQuorumError) -> NativeMultisigAuthError {
        match err {
            MultisigQuorumError::SignerNotOwner | MultisigQuorumError::WeightBelowThreshold => {
                NativeMultisigAuthError::validation_failed(err.as_str())
            }
            MultisigQuorumError::ExcessSignatures | MultisigQuorumError::SignersNotAscending
                if matches!(self, Self::Registered(_)) =>
            {
                NativeMultisigAuthError::validation_failed(err.as_str())
            }
            MultisigQuorumError::EmptySignatures
            | MultisigQuorumError::TooManySignatures
            | MultisigQuorumError::ExcessSignatures
            | MultisigQuorumError::SignersNotAscending
            | MultisigQuorumError::WeightOverflow => {
                NativeMultisigAuthError::invalid_transaction(err.as_str())
            }
        }
    }
}

impl NativeMultisig {
    /// Verifies a native multisig transaction authorization against current stored configs.
    pub fn verify_authorization(
        &self,
        inner_digest: B256,
        signature: &MultisigSignature,
        config: NativeMultisigAuthConfig<'_>,
        mut load_registered_config: impl FnMut(
            Address,
        ) -> Result<
            RegisteredMultisigConfig,
            NativeMultisigAuthError,
        >,
    ) -> Result<(), NativeMultisigAuthError> {
        let mut account_path = vec![signature.account()];
        self.verify_authorization_inner(
            inner_digest,
            signature,
            config,
            &mut account_path,
            &mut load_registered_config,
        )
    }

    fn verify_authorization_inner(
        &self,
        inner_digest: B256,
        signature: &MultisigSignature,
        config: NativeMultisigAuthConfig<'_>,
        account_path: &mut Vec<Address>,
        load_registered_config: &mut impl FnMut(
            Address,
        ) -> Result<
            RegisteredMultisigConfig,
            NativeMultisigAuthError,
        >,
    ) -> Result<(), NativeMultisigAuthError> {
        if !config.matches_signature(signature) {
            return Err(NativeMultisigAuthError::invalid_transaction(
                "multisig authorization config does not match signature",
            ));
        }
        signature
            .validate_shape()
            .map_err(NativeMultisigAuthError::invalid_transaction)?;
        config.validate()?;

        let digest = signature.digest(inner_digest, config.version());
        let mut weight_accumulator = MultisigWeightAccumulator::new(config.threshold());

        for (signature_index, owner_approval) in signature.signatures().iter().enumerate() {
            let (owner, nested_signature) = match owner_approval {
                TempoSignature::Primitive(primitive) => {
                    let owner = primitive
                        .recover_signer(&digest)
                        .map_err(|_| config.invalid_owner_signature())?;
                    (owner, None)
                }
                TempoSignature::Keychain(_) => {
                    return Err(NativeMultisigAuthError::invalid_transaction(
                        "keychain signatures cannot authorize native multisig owners",
                    ));
                }
                TempoSignature::Multisig(nested_signature) => {
                    nested_signature
                        .validate_registered_shape()
                        .map_err(|reason| {
                            NativeMultisigAuthError::invalid_transaction(format!(
                                "invalid nested multisig owner signature: {reason}"
                            ))
                        })?;
                    (nested_signature.account(), Some(nested_signature))
                }
            };

            let weight = config.owner_weight(owner)?;
            weight_accumulator
                .record_owner(owner, weight)
                .map_err(|err| config.quorum_error(err))?;

            if let Some(nested_signature) = nested_signature {
                if account_path.len() >= MAX_MULTISIG_NESTING_DEPTH {
                    return Err(NativeMultisigAuthError::invalid_transaction(
                        "native multisig nesting depth exceeded",
                    ));
                }
                if account_path.contains(&owner) {
                    return Err(NativeMultisigAuthError::invalid_transaction(
                        "native multisig owner cycle detected",
                    ));
                }

                let config = load_registered_config(owner)?;
                account_path.push(owner);
                self.verify_authorization_inner(
                    digest,
                    nested_signature,
                    NativeMultisigAuthConfig::Registered(config),
                    account_path,
                    load_registered_config,
                )?;
                account_path.pop();
            }

            if weight_accumulator.has_quorum() {
                if signature_index + 1 != signature.signatures().len() {
                    return Err(config.quorum_error(MultisigQuorumError::ExcessSignatures));
                }
                return weight_accumulator
                    .finish()
                    .map(|_| ())
                    .map_err(|err| config.quorum_error(err));
            }
        }

        weight_accumulator
            .finish()
            .map(|_| ())
            .map_err(|err| config.quorum_error(err))
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{Address, B256, Signature};
    use tempo_primitives::transaction::{
        InitMultisig, MultisigOwner, MultisigSignature, TempoSignature,
    };

    use super::{NativeMultisigAuthConfig, NativeMultisigAuthError, RegisteredMultisigConfig};
    use crate::native_multisig::NativeMultisig;

    fn init_config() -> InitMultisig {
        InitMultisig {
            salt: B256::ZERO,
            threshold: 1,
            owners: vec![MultisigOwner {
                owner: Address::repeat_byte(0x11),
                weight: 1,
            }],
        }
    }

    #[test]
    fn authorization_config_must_match_signature_address_source() {
        let init = init_config();
        let account = init.account().unwrap();
        let approvals = vec![TempoSignature::from(Signature::test_signature())];
        let inline_signature =
            MultisigSignature::from_decoded(account, approvals.clone(), Some(init.clone()))
                .unwrap();
        let registered_signature =
            MultisigSignature::from_decoded(account, approvals, None).unwrap();
        let registered_config = NativeMultisigAuthConfig::Registered(RegisteredMultisigConfig {
            threshold: init.threshold,
            version: 1,
            owners: init.owners.clone(),
        });

        let verify = |signature, config| {
            NativeMultisig::new().verify_authorization(B256::ZERO, signature, config, |_| {
                unreachable!("mismatched config must fail before nested config loading")
            })
        };

        for result in [
            verify(&inline_signature, registered_config),
            verify(
                &registered_signature,
                NativeMultisigAuthConfig::Inline(&init),
            ),
        ] {
            assert_eq!(
                result,
                Err(NativeMultisigAuthError::InvalidTransaction(
                    "multisig authorization config does not match signature".to_string()
                ))
            );
        }

        assert!(
            NativeMultisigAuthConfig::BootstrapCompanion(&init)
                .matches_signature(&registered_signature)
        );
    }
}
