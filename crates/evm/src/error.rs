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
}

/// A transaction used more gas than its block lane had left: the general lane, the registered
/// payment budget or the non-shared gas. The block executor rejects it when it executes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("transaction exceeds its gas lane")]
pub struct LaneGasExceeded;
