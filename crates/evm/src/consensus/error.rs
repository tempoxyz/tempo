use alloy_primitives::{Address, B256};
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

    /// Block does not contain the required end-of-block system transactions.
    #[error("block must contain {expected} end-of-block system txs, found {actual}")]
    MissingEndOfBlockSystemTxs { expected: usize, actual: usize },

    /// End-of-block system transactions are in the wrong order.
    #[error("invalid end-of-block system tx order: expected {expected}, got {actual}")]
    InvalidEndOfBlockSystemTxOrder { expected: Address, actual: Address },
}

impl From<TempoConsensusError> for ConsensusError {
    fn from(err: TempoConsensusError) -> Self {
        Self::other(err)
    }
}
