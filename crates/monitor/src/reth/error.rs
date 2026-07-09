//! Error classification for the Reth monitor adapter.

use crate::{processor::ProcessorError, store::StoreError};

pub type AdapterResult<T> = Result<T, AdapterError>;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AdapterError {
    #[error("halt: {0}")]
    Halt(String),
    #[error("retry: {0}")]
    Retry(String),
    #[error("ignore: {0}")]
    Ignore(String),
}

impl AdapterError {
    pub const fn is_halt(&self) -> bool {
        matches!(self, Self::Halt(_))
    }

    pub const fn is_retry(&self) -> bool {
        matches!(self, Self::Retry(_))
    }
}

impl From<StoreError> for AdapterError {
    fn from(value: StoreError) -> Self {
        match value {
            StoreError::Poisoned | StoreError::NotFound(_) | StoreError::Database(_) => {
                Self::Retry(format!("{value:?}"))
            }
            StoreError::IncompatibleSchema { .. }
            | StoreError::MigrationBlocked(_)
            | StoreError::Continuity(_)
            | StoreError::InvalidCommit(_)
            | StoreError::Codec(_)
            | StoreError::IdempotencyMismatch(_)
            | StoreError::UnknownInvariant(_) => Self::Halt(format!("{value:?}")),
        }
    }
}

impl From<ProcessorError> for AdapterError {
    fn from(value: ProcessorError) -> Self {
        Self::Halt(format!("{value:?}"))
    }
}
