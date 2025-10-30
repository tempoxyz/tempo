use alloy_eips::BlockId;
use alloy_primitives::B256;
use jsonrpsee::types::ErrorObject;
use reth_rpc_eth_types::{EthApiError, error::ToRpcError};
use tempo_precompiles::error::TempoPrecompileError;

/// DEX API specific errors that extend [`EthApiError`].
#[derive(Debug, thiserror::Error)]
pub enum DexApiError {
    /// Wrapper for EthApiError
    #[error(transparent)]
    Eth(#[from] EthApiError),

    /// Precompile storage errors
    #[error(transparent)]
    Precompile(#[from] TempoPrecompileError),

    /// Header not found for block
    #[error("header not found for block {0:?}")]
    HeaderNotFound(BlockId),

    /// Provider error when getting header
    /// Boxed because Provider::Error is an associated type
    #[error("failed to get header")]
    Provider(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Failed to create EVM context
    /// Boxed because ConfigureEvm::Error is an associated type
    #[error("failed to create EVM")]
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

// Convert DexApiError to EthApiError for RPC handling
impl From<DexApiError> for EthApiError {
    fn from(err: DexApiError) -> Self {
        match err {
            DexApiError::Eth(e) => e,
            DexApiError::HeaderNotFound(block_id) => Self::HeaderNotFound(block_id),
            // All other errors use the Other variant with our error type
            other => Self::Other(Box::new(other)),
        }
    }
}

// Implement ToRpcError so DexApiError can be used in EthApiError::Other
impl ToRpcError for DexApiError {
    fn to_rpc_error(&self) -> ErrorObject<'static> {
        // Use internal error code for all DEX-specific errors
        ErrorObject::owned(
            jsonrpsee::types::error::INTERNAL_ERROR_CODE,
            self.to_string(),
            None::<()>,
        )
    }
}
