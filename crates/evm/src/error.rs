//! Error types for Tempo EVM operations.

use evm2::registry::HandlerError;
use reth_consensus::ConsensusError;
use reth_evm::{
    BlockExecutionError, BlockValidationError, InternalBlockExecutionError, InvalidTxError,
};

/// Preserves transaction validation classifications for payload building when
/// Tempo bypasses Ethereum's block state-gas limit.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
struct TempoBlockInvalidTx(HandlerError);

impl InvalidTxError for TempoBlockInvalidTx {
    fn is_nonce_too_low(&self) -> bool {
        matches!(self.0, HandlerError::InvalidNonce { expected, got } if got < expected)
    }

    fn is_gas_limit_too_high(&self) -> bool {
        matches!(
            self.0,
            HandlerError::GasLimitMoreThanBlock { .. }
                | HandlerError::TxGasLimitGreaterThanCap { .. }
        )
    }

    fn is_gas_limit_too_low(&self) -> bool {
        matches!(self.0, HandlerError::IntrinsicGasTooLow { .. })
    }

    fn as_any(&self) -> &(dyn std::any::Any + 'static) {
        self
    }
}

pub(crate) fn map_transaction_error(
    error: HandlerError,
    hash: alloy_primitives::B256,
) -> BlockExecutionError {
    match &error {
        HandlerError::Database(database) if !database.is_fatal() => BlockValidationError::EVM {
            hash,
            error: Box::new(error),
        }
        .into(),
        HandlerError::Database(_)
        | HandlerError::Fatal(_)
        | HandlerError::WrongTransactionType { .. } => InternalBlockExecutionError::EVM {
            hash,
            error: Box::new(error),
        }
        .into(),
        _ => BlockValidationError::InvalidTx {
            hash,
            error: Box::new(TempoBlockInvalidTx(error)),
        }
        .into(),
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_errors_retain_hash_and_nonce_classification() {
        let hash = alloy_primitives::B256::repeat_byte(7);
        let error = map_transaction_error(
            HandlerError::InvalidNonce {
                expected: 2,
                got: 1,
            },
            hash,
        );
        let BlockExecutionError::Validation(BlockValidationError::InvalidTx {
            hash: actual,
            error,
        }) = error
        else {
            panic!("invalid transaction must remain skippable by the payload builder");
        };
        assert_eq!(actual, hash);
        assert!(error.is_nonce_too_low());
        assert!(!error.is_gas_limit_too_low());
    }
}
