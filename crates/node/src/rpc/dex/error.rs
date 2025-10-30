use std::convert::Infallible;

use alloy_eips::BlockId;
use alloy_primitives::B256;
use alloy_rpc_types_eth::BlockError;
use jsonrpsee::types::ErrorObject;
use reth_evm::revm::context::result::{EVMError, HaltReason};
use reth_provider::ProviderError;
use reth_rpc_convert::{EthTxEnvError, TransactionConversionError};
use reth_rpc_eth_api::AsEthApiError;
use reth_rpc_eth_types::{
    EthApiError,
    error::{ToRpcError, api::FromEvmHalt},
};
use tempo_precompiles::error::TempoPrecompileError;
use tempo_revm::TempoInvalidTransaction;

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

    /// Invalid transaction error
    #[error(transparent)]
    InvalidTransaction(#[from] TempoInvalidTransaction),

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

impl AsEthApiError for DexApiError {
    fn as_err(&self) -> Option<&EthApiError> {
        match self {
            Self::Eth(err) => Some(err),
            _ => None,
        }
    }
}

impl From<DexApiError> for ErrorObject<'static> {
    fn from(value: DexApiError) -> Self {
        value.to_rpc_error()
    }
}

impl<T> From<EVMError<T, TempoInvalidTransaction>> for DexApiError
where
    T: Into<EthApiError>,
{
    fn from(value: EVMError<T, TempoInvalidTransaction>) -> Self {
        match value {
            EVMError::Transaction(err) => Self::InvalidTransaction(err),
            EVMError::Database(err) => Self::Eth(err.into()),
            EVMError::Header(err) => Self::Eth(err.into()),
            EVMError::Custom(err) => Self::Eth(EthApiError::EvmCustom(err)),
        }
    }
}

impl FromEvmHalt<HaltReason> for DexApiError {
    fn from_evm_halt(halt: HaltReason, gas_limit: u64) -> Self {
        EthApiError::from_evm_halt(halt, gas_limit).into()
    }
}

impl From<TransactionConversionError> for DexApiError {
    fn from(value: TransactionConversionError) -> Self {
        Self::Eth(EthApiError::from(value))
    }
}

impl From<EthTxEnvError> for DexApiError {
    fn from(value: EthTxEnvError) -> Self {
        Self::Eth(EthApiError::from(value))
    }
}

impl From<ProviderError> for DexApiError {
    fn from(value: ProviderError) -> Self {
        Self::Eth(EthApiError::from(value))
    }
}

impl From<BlockError> for DexApiError {
    fn from(value: BlockError) -> Self {
        Self::Eth(EthApiError::from(value))
    }
}

impl From<Infallible> for DexApiError {
    fn from(value: Infallible) -> Self {
        match value {}
    }
}
