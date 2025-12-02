use alloy_eips::BlockId;
use alloy_primitives::B256;
use jsonrpsee::types::ErrorObject;
use reth_rpc_eth_types::{EthApiError, error::ToRpcError};
use tempo_precompiles::error::TempoPrecompileError;

/// DEX API specific errors that extend [`EthApiError`].
#[derive(Debug, thiserror::Error)]
pub enum DexApiError {
    /// Precompile storage errors
    #[error(transparent)]
    Precompile(#[from] TempoPrecompileError),

    /// Header not found for block
    #[error("header not found for block {0:?}")]
    HeaderNotFound(BlockId),

    /// Provider error when getting header
    /// Boxed because Provider::Error is an associated type
    #[error("internal node error: failed to get header: {0}")]
    Provider(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Failed to create EVM context
    /// Boxed because ConfigureEvm::Error is an associated type
    #[error("internal node error: failed to create EVM")]
    CreateEvm(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Invalid hex string in order cursor
    #[error("invalid order cursor: expected hex string, got {0}")]
    InvalidOrderCursor(String),

    /// Failed to parse order cursor as u128
    #[error("invalid order cursor: failed to parse hex value")]
    ParseOrderCursor(#[from] std::num::ParseIntError),

    /// Invalid orderbook cursor format
    #[error("invalid orderbook cursor: failed to parse as B256")]
    InvalidOrderbookCursor(String),

    /// Orderbook cursor not found in available books
    #[error("orderbook cursor {0} not found in available books")]
    OrderbookCursorNotFound(B256),
}

impl DexApiError {
    /// Returns the rpc error for this error
    const fn error_code(&self) -> i32 {
        match self {
            Self::InvalidOrderbookCursor(_)
            | Self::InvalidOrderCursor(_)
            | Self::ParseOrderCursor(_) => jsonrpsee::types::error::INVALID_PARAMS_CODE,
            _ => jsonrpsee::types::error::INTERNAL_ERROR_CODE,
        }
    }
}

impl From<DexApiError> for EthApiError {
    fn from(err: DexApiError) -> Self {
        match err {
            DexApiError::HeaderNotFound(block_id) => Self::HeaderNotFound(block_id),
            // All other errors use the Other variant with our error type
            other => Self::other(other),
        }
    }
}

impl ToRpcError for DexApiError {
    fn to_rpc_error(&self) -> ErrorObject<'static> {
        ErrorObject::owned(self.error_code(), self.to_string(), None::<()>)
    }
}

impl From<DexApiError> for ErrorObject<'static> {
    fn from(value: DexApiError) -> Self {
        value.to_rpc_error()
    }
}
