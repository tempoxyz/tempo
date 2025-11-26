use std::convert::Infallible;

use alloy_primitives::Bytes;
use reth_errors::ProviderError;
use reth_evm::revm::context::result::{EVMError, HaltReason};
use reth_node_core::rpc::result::rpc_err;
use reth_rpc_eth_api::{AsEthApiError, TransactionConversionError};
use reth_rpc_eth_types::{
    EthApiError, RpcInvalidTransactionError,
    error::api::{FromEvmHalt, FromRevert},
};

#[derive(Debug, thiserror::Error)]
pub enum TempoEthApiError {
    #[error(transparent)]
    EthApiError(EthApiError),
}

impl From<TempoEthApiError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(error: TempoEthApiError) -> Self {
        match error {
            TempoEthApiError::EthApiError(err) => err.into(),
        }
    }
}
impl From<Infallible> for TempoEthApiError {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}

impl From<TransactionConversionError> for TempoEthApiError {
    fn from(_: TransactionConversionError) -> Self {
        Self::EthApiError(EthApiError::TransactionConversionError)
    }
}

impl AsEthApiError for TempoEthApiError {
    fn as_err(&self) -> Option<&EthApiError> {
        match self {
            Self::EthApiError(err) => Some(err),
        }
    }
}

impl From<EthApiError> for TempoEthApiError {
    fn from(error: EthApiError) -> Self {
        Self::EthApiError(error)
    }
}

impl From<ProviderError> for TempoEthApiError {
    fn from(error: ProviderError) -> Self {
        EthApiError::from(error).into()
    }
}
impl<T, TxError> From<EVMError<T, TxError>> for TempoEthApiError
where
    T: Into<EthApiError>,
    TxError: reth_evm::InvalidTxError,
{
    fn from(error: EVMError<T, TxError>) -> Self {
        EthApiError::from(error).into()
    }
}

impl FromEvmHalt<HaltReason> for TempoEthApiError {
    fn from_evm_halt(halt: HaltReason, gas_limit: u64) -> Self {
        Self::EthApiError(RpcInvalidTransactionError::halt(halt, gas_limit).into())
    }
}

impl FromRevert for TempoEthApiError {
    fn from_revert(revert: Bytes) -> Self {
        match tempo_precompiles::error::decode_error(&revert.0) {
            Some(error) => Self::EthApiError(EthApiError::Other(Box::new(rpc_err(
                3,
                format!("execution reverted: {}", error.error.to_string()),
                Some(&error.revert_bytes),
            )))),
            None => Self::EthApiError(EthApiError::from_revert(revert)),
        }
    }
}
