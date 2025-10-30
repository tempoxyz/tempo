use alloy_eips::BlockId;
use alloy_primitives::B256;
use reth_rpc_eth_types::EthApiError;
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

    /// Failed to get book keys from exchange
    #[error("failed to get book keys from exchange")]
    GetBookKeys,

    /// Failed to get specific book from exchange
    #[error("failed to get book for key {0}")]
    GetBook(B256),

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

    /// Failed to load order from storage
    #[error("failed to load order {0} from storage")]
    LoadOrder(u128),

    /// Failed to load price level from storage
    #[error("failed to load price level at tick {0} from storage")]
    LoadPriceLevel(i16),
}

// Convert DexApiError to EthApiError for RPC handling
impl From<DexApiError> for EthApiError {
    fn from(err: DexApiError) -> Self {
        match err {
            DexApiError::Eth(e) => e,
            DexApiError::HeaderNotFound(block_id) => EthApiError::HeaderNotFound(block_id),
            // For provider errors and other internal errors that are boxed,
            // convert to string and wrap as InvalidParams since we can't create RethError from Box<dyn Error>
            DexApiError::Provider(e) | DexApiError::CreateEvm(e) => {
                EthApiError::InvalidParams(format!("Internal error: {}", e))
            }
            // Precompile errors should be internal errors
            DexApiError::Precompile(e) => {
                EthApiError::InvalidParams(format!("Precompile error: {}", e))
            }
            // All other DEX-specific errors become invalid params
            other => EthApiError::InvalidParams(other.to_string()),
        }
    }
}
