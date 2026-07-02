use alloy::primitives::{Address, B256};
use tempo_primitives::transaction::{
    InitMultisig, MAX_MULTISIG_NESTING_DEPTH, MultisigQuorumError, MultisigSignature,
    MultisigWeightAccumulator, TempoSignature,
};

use super::NativeMultisig;
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
    pub fn invalid_transaction(reason: impl Into<String>) -> Self {
        Self::InvalidTransaction(reason.into())
    }

    pub fn validation_failed(reason: impl Into<String>) -> Self {
        Self::ValidationFailed(reason.into())
    }

    fn quorum_error(err: MultisigQuorumError) -> Self {
        match err {
            MultisigQuorumError::SignerNotOwner | MultisigQuorumError::WeightBelowThreshold => {
                Self::validation_failed(err.as_str())
            }
            MultisigQuorumError::EmptySignatures
            | MultisigQuorumError::TooManySignatures
            | MultisigQuorumError::SignersNotAscending
            | MultisigQuorumError::WeightOverflow => Self::invalid_transaction(err.as_str()),
        }
    }
}

impl NativeMultisig {
    /// Verifies a native multisig transaction authorization against current stored configs.
    pub fn verify_authorization(
        &self,
        inner_digest: B256,
        signature: &MultisigSignature,
        config: &InitMultisig,
        load_config: impl FnMut(Address) -> Result<InitMultisig, NativeMultisigAuthError>,
    ) -> Result<(), NativeMultisigAuthError> {
        self.verify_authorization_with_keychains(
            inner_digest,
            signature,
            config,
            load_config,
            |_, _| {
                Err(NativeMultisigAuthError::invalid_transaction(
                    "keychain signatures cannot authorize native multisig owners",
                ))
            },
        )
    }

    /// Verifies a native multisig transaction authorization against current stored configs,
    /// optionally allowing owner approvals to be keychain signatures.
    pub fn verify_authorization_with_keychains(
        &self,
        inner_digest: B256,
        signature: &MultisigSignature,
        config: &InitMultisig,
        mut load_config: impl FnMut(Address) -> Result<InitMultisig, NativeMultisigAuthError>,
        mut validate_keychain: impl FnMut(
            B256,
            &tempo_primitives::transaction::KeychainSignature,
        ) -> Result<Address, NativeMultisigAuthError>,
    ) -> Result<(), NativeMultisigAuthError> {
        let mut account_path = vec![signature.account()];
        self.verify_authorization_inner(
            inner_digest,
            signature,
            config,
            &mut account_path,
            &mut load_config,
            &mut validate_keychain,
        )
        .map(|_| ())
    }

    fn verify_authorization_inner(
        &self,
        inner_digest: B256,
        signature: &MultisigSignature,
        config: &InitMultisig,
        account_path: &mut Vec<Address>,
        load_config: &mut impl FnMut(Address) -> Result<InitMultisig, NativeMultisigAuthError>,
        validate_keychain: &mut impl FnMut(
            B256,
            &tempo_primitives::transaction::KeychainSignature,
        ) -> Result<Address, NativeMultisigAuthError>,
    ) -> Result<u8, NativeMultisigAuthError> {
        signature
            .validate_shape()
            .map_err(NativeMultisigAuthError::invalid_transaction)?;
        config
            .validate()
            .map_err(|err| NativeMultisigAuthError::validation_failed(err.as_str()))?;

        let digest = signature.digest(inner_digest);
        let mut weight_accumulator = MultisigWeightAccumulator::new(config);

        for signature_bytes in signature.signatures() {
            let owner_approval = TempoSignature::from_bytes(signature_bytes).map_err(|reason| {
                NativeMultisigAuthError::invalid_transaction(format!(
                    "invalid multisig owner signature: {reason}"
                ))
            })?;

            let (owner, nested_signature) = match owner_approval {
                TempoSignature::Primitive(primitive) => {
                    let owner = primitive.recover_signer(&digest).map_err(|_| {
                        NativeMultisigAuthError::invalid_transaction(
                            "invalid multisig owner signature",
                        )
                    })?;
                    (owner, None)
                }
                TempoSignature::Keychain(keychain) => (validate_keychain(digest, &keychain)?, None),
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

            weight_accumulator
                .record_owner(owner)
                .map_err(NativeMultisigAuthError::quorum_error)?;

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

                let nested_config = load_config(owner)?;
                account_path.push(owner);
                self.verify_authorization_inner(
                    digest,
                    &nested_signature,
                    &nested_config,
                    account_path,
                    load_config,
                    validate_keychain,
                )?;
                account_path.pop();
            }
        }

        weight_accumulator
            .finish()
            .map_err(NativeMultisigAuthError::quorum_error)
    }
}
