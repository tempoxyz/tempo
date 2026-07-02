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
    fn invalid_transaction(reason: impl Into<String>) -> Self {
        Self::InvalidTransaction(reason.into())
    }

    fn validation_failed(reason: impl Into<String>) -> Self {
        Self::ValidationFailed(reason.into())
    }

    fn quorum_error(err: MultisigQuorumError) -> Self {
        match err {
            MultisigQuorumError::SignerNotOwner | MultisigQuorumError::WeightBelowThreshold => {
                Self::validation_failed(err.as_str())
            }
            MultisigQuorumError::EmptySignatures
            | MultisigQuorumError::TooManySignatures
            | MultisigQuorumError::ExcessSignatures
            | MultisigQuorumError::SignersNotAscending
            | MultisigQuorumError::WeightOverflow => Self::invalid_transaction(err.as_str()),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum NativeMultisigAuthConfig<'a> {
    Inline(&'a InitMultisig),
    Registered { account: Address, threshold: u8 },
}

impl NativeMultisigAuthConfig<'_> {
    fn threshold(self) -> u8 {
        match self {
            Self::Inline(config) => config.threshold,
            Self::Registered { threshold, .. } => threshold,
        }
    }

    fn owner_weight(
        self,
        owner: Address,
        load_owner_weight: &mut impl FnMut(Address, Address) -> Result<u8, NativeMultisigAuthError>,
    ) -> Result<u8, NativeMultisigAuthError> {
        let weight = match self {
            Self::Inline(config) => config.owner_weight(owner).unwrap_or_default(),
            Self::Registered { account, .. } => load_owner_weight(account, owner)?,
        };
        if weight == 0 {
            return Err(NativeMultisigAuthError::quorum_error(
                MultisigQuorumError::SignerNotOwner,
            ));
        }
        Ok(weight)
    }

    fn validate(self) -> Result<(), NativeMultisigAuthError> {
        match self {
            Self::Inline(config) => config
                .validate()
                .map(|_| ())
                .map_err(|err| NativeMultisigAuthError::validation_failed(err.as_str())),
            Self::Registered { .. } => Ok(()),
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
        mut load_threshold: impl FnMut(Address) -> Result<u8, NativeMultisigAuthError>,
        mut load_owner_weight: impl FnMut(Address, Address) -> Result<u8, NativeMultisigAuthError>,
    ) -> Result<(), NativeMultisigAuthError> {
        let mut account_path = vec![signature.account()];
        self.verify_authorization_inner(
            inner_digest,
            signature,
            config,
            &mut account_path,
            &mut load_threshold,
            &mut load_owner_weight,
        )
        .map(|_| ())
    }

    fn verify_authorization_inner(
        &self,
        inner_digest: B256,
        signature: &MultisigSignature,
        config: NativeMultisigAuthConfig<'_>,
        account_path: &mut Vec<Address>,
        load_threshold: &mut impl FnMut(Address) -> Result<u8, NativeMultisigAuthError>,
        load_owner_weight: &mut impl FnMut(Address, Address) -> Result<u8, NativeMultisigAuthError>,
    ) -> Result<u8, NativeMultisigAuthError> {
        signature
            .validate_shape()
            .map_err(NativeMultisigAuthError::invalid_transaction)?;
        config.validate()?;

        let digest = signature.digest(inner_digest);
        let mut weight_accumulator = MultisigWeightAccumulator::new(config.threshold());

        for (signature_index, signature_bytes) in signature.signatures().iter().enumerate() {
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

            let weight = config.owner_weight(owner, load_owner_weight)?;
            weight_accumulator
                .record_owner(owner, weight)
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

                let threshold = load_threshold(owner)?;
                account_path.push(owner);
                self.verify_authorization_inner(
                    digest,
                    &nested_signature,
                    NativeMultisigAuthConfig::Registered {
                        account: owner,
                        threshold,
                    },
                    account_path,
                    load_threshold,
                    load_owner_weight,
                )?;
                account_path.pop();
            }

            if weight_accumulator.has_quorum() {
                if signature_index + 1 != signature.signatures().len() {
                    return Err(NativeMultisigAuthError::quorum_error(
                        MultisigQuorumError::ExcessSignatures,
                    ));
                }
                return weight_accumulator
                    .finish()
                    .map_err(NativeMultisigAuthError::quorum_error);
            }
        }

        weight_accumulator
            .finish()
            .map_err(NativeMultisigAuthError::quorum_error)
    }
}
