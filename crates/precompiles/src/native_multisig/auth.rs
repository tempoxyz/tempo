use alloy::primitives::{Address, B256};
use tempo_primitives::transaction::{
    InitMultisig, MAX_MULTISIG_NESTING_DEPTH, MultisigSignature, MultisigWeightAccumulator,
    TempoSignature,
};

use super::NativeMultisig;
use crate::error::TempoPrecompileError;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NativeMultisigAuthError {
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
    fn validation_failed(reason: impl Into<String>) -> Self {
        Self::ValidationFailed(reason.into())
    }
}

impl NativeMultisig {
    /// Verifies a native multisig transaction authorization against current stored configs.
    pub fn verify_authorization(
        &self,
        inner_digest: B256,
        signature: &MultisigSignature,
        config: &InitMultisig,
        mut load_config: impl FnMut(Address) -> Result<InitMultisig, NativeMultisigAuthError>,
    ) -> Result<(), NativeMultisigAuthError> {
        let mut account_path = vec![signature.account()];
        self.verify_authorization_inner(
            inner_digest,
            signature,
            config,
            &mut account_path,
            &mut load_config,
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
    ) -> Result<u8, NativeMultisigAuthError> {
        config
            .validate()
            .map_err(|err| NativeMultisigAuthError::validation_failed(err.as_str()))?;

        let digest = signature.digest(inner_digest);
        let mut weight_accumulator = MultisigWeightAccumulator::new(config);

        for signature_bytes in signature.signatures() {
            let owner_approval = TempoSignature::from_bytes(signature_bytes).map_err(|reason| {
                NativeMultisigAuthError::validation_failed(format!(
                    "invalid multisig owner signature: {reason}"
                ))
            })?;

            let (owner, nested_signature) = match owner_approval {
                TempoSignature::Primitive(primitive) => {
                    let owner = primitive.recover_signer(&digest).map_err(|_| {
                        NativeMultisigAuthError::validation_failed(
                            "invalid multisig owner signature",
                        )
                    })?;
                    (owner, None)
                }
                TempoSignature::Keychain(_) => {
                    return Err(NativeMultisigAuthError::validation_failed(
                        "keychain signatures cannot authorize native multisig owners",
                    ));
                }
                TempoSignature::Multisig(nested_signature) => {
                    nested_signature
                        .validate_registered_shape()
                        .map_err(|reason| {
                            NativeMultisigAuthError::validation_failed(format!(
                                "invalid nested multisig owner signature: {reason}"
                            ))
                        })?;
                    (nested_signature.account(), Some(nested_signature))
                }
            };

            weight_accumulator.record_owner(owner).map_err(|err| {
                NativeMultisigAuthError::validation_failed(err.as_str())
            })?;

            if let Some(nested_signature) = nested_signature {
                if account_path.len() >= MAX_MULTISIG_NESTING_DEPTH {
                    return Err(NativeMultisigAuthError::validation_failed(
                        "native multisig nesting depth exceeded",
                    ));
                }
                if account_path.contains(&owner) {
                    return Err(NativeMultisigAuthError::validation_failed(
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
                )?;
                account_path.pop();
            }
        }

        weight_accumulator
            .finish()
            .map_err(|err| NativeMultisigAuthError::validation_failed(err.as_str()))
    }
}
