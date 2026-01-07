//! Error types for Tempo EVM operations.

use reth_consensus::ConsensusError;

/// Errors that can occur during EVM configuration and execution.
#[derive(Debug, Clone, thiserror::Error)]
pub enum TempoEvmError {
    /// Error decoding fee lane data from extra data field.
    #[error("failed to decode fee lane data: {0}")]
    FeeLaneDecoding(#[from] ConsensusError),

    /// Invalid EVM configuration.
    #[error("invalid EVM configuration: {0}")]
    InvalidEvmConfig(String),

    /// No subblock metadata system transaction is found in the block.
    #[error("couldn't find subblock metadata transaction in block")]
    NoSubblockMetadataFound,
}
