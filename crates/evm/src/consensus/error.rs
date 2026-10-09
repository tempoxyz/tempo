use alloy_primitives::B256;
use reth_consensus::ConsensusError;

/// Tempo-specific consensus errors.
#[derive(Debug, thiserror::Error)]
pub enum TempoConsensusError {
    /// Timestamp milliseconds part is out of range (must be < 1000).
    #[error("timestamp milliseconds part {millis_part} must be less than 1000")]
    InvalidTimestampMillisPart { millis_part: u64 },

    /// Shared gas limit does not match the expected value derived from block gas limit.
    #[error("shared gas limit {actual} does not match expected {expected}")]
    SharedGasLimitMismatch { expected: u64, actual: u64 },

    /// General gas limit does not match the expected value.
    #[error("general gas limit {actual} does not match expected {expected}")]
    GeneralGasLimitMismatch { expected: u64, actual: u64 },

    /// A system transaction in the block is invalid.
    #[error("invalid system transaction: {tx_hash}")]
    InvalidSystemTransaction { tx_hash: B256 },
}

impl From<TempoConsensusError> for ConsensusError {
    fn from(err: TempoConsensusError) -> Self {
        Self::other(err)
    }
}
