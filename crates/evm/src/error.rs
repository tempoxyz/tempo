//! Error types for Tempo EVM operations.

use reth_consensus::ConsensusError;
use tempo_chainspec::hardfork::TempoHardfork;

/// Errors that can occur during EVM configuration and execution.
#[derive(Debug, Clone, thiserror::Error)]
pub enum TempoEvmError {
    /// Error decoding fee lane data from extra data field.
    #[error("failed to decode fee lane data: {0}")]
    FeeLaneDecoding(#[from] ConsensusError),

    /// Invalid EVM configuration.
    #[error("invalid EVM configuration: {0}")]
    InvalidEvmConfig(String),

    /// The block's hardfork predates [`TempoHardfork::MINIMUM_SUPPORTED`].
    #[error("{0} blocks are executed by their frozen era binary, not this release")]
    UnsupportedHardfork(TempoHardfork),
}
