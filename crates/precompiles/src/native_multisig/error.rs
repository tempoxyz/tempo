use alloy::primitives::{Address, B256};
use tempo_primitives::transaction::MultisigQuorumError;

use crate::error::TempoPrecompileError;

/// Failure while validating a native multisig authorization.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NativeMultisigAuthError {
    /// Deterministic authorization validation failed.
    #[error(transparent)]
    Invalid(#[from] NativeMultisigAuthorizationError),
    /// Validation against current native multisig state failed.
    #[error(transparent)]
    State(#[from] NativeMultisigStateError),
    /// An unrecoverable precompile operation failed.
    #[error("Fatal precompile error: {0:?}")]
    Fatal(String),
}

impl NativeMultisigAuthError {
    /// Converts a native multisig state-access failure into an unrecoverable error.
    pub fn from_state_access_error(error: TempoPrecompileError) -> Self {
        match error {
            TempoPrecompileError::Fatal(reason) => Self::Fatal(reason),
            error => Self::Fatal(error.to_string()),
        }
    }
}

/// Deterministic native multisig authorization failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum NativeMultisigAuthorizationError {
    /// The signature names an account outside the native multisig address space.
    #[error("invalid multisig account {account}")]
    InvalidAccount { account: Address },
    /// A primitive owner approval could not be recovered.
    #[error("invalid multisig owner signature at approval {approval_index}")]
    OwnerSignatureRecoveryFailed { approval_index: usize },
    /// A keychain signature was supplied as an owner approval.
    #[error("keychain signature cannot authorize multisig owner at approval {approval_index}")]
    KeychainOwnerSignature { approval_index: usize },
    /// Owner membership, ordering, or weight validation failed.
    #[error("{0}")]
    Quorum(MultisigQuorumError),
}

/// Native multisig failure that depends on current precompile state.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum NativeMultisigStateError {
    /// The supplied configuration does not match the account's stored commitment.
    #[error("multisig configuration commitment mismatch: expected {expected}, actual {actual}")]
    ConfigurationCommitmentMismatch { expected: B256, actual: B256 },
}
