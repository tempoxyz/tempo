use std::convert::Infallible;

use alloy_primitives::Bytes;
use reth_errors::ProviderError;
use reth_evm::revm::context::result::EVMError;
use reth_node_core::rpc::result::rpc_err;
use reth_rpc_eth_api::AsEthApiError;
use reth_rpc_eth_types::{
    EthApiError,
    error::api::{FromEvmHalt, FromRevert},
};
use tempo_evm::TempoHaltReason;

/// Error code for Tempo-specific RPC errors.
pub const TEMPO_RPC_ERROR_CODE: i32 = -32000;

#[derive(Debug, thiserror::Error)]
pub enum TempoEthApiError {
    #[error(transparent)]
    EthApiError(EthApiError),
    #[error(
        "Native balance not used. See docs.tempo.xyz/quickstart/wallet-developers for balance queries."
    )]
    NativeBalanceNotSupported,
}

impl From<TempoEthApiError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(error: TempoEthApiError) -> Self {
        match error {
            TempoEthApiError::EthApiError(err) => err.into(),
            TempoEthApiError::NativeBalanceNotSupported => {
                jsonrpsee::types::error::ErrorObject::owned(
                    TEMPO_RPC_ERROR_CODE,
                    error.to_string(),
                    None::<()>,
                )
            }
        }
    }
}
impl From<Infallible> for TempoEthApiError {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}

impl AsEthApiError for TempoEthApiError {
    fn as_err(&self) -> Option<&EthApiError> {
        match self {
            Self::EthApiError(err) => Some(err),
            Self::NativeBalanceNotSupported => None,
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

impl FromEvmHalt<TempoHaltReason> for TempoEthApiError {
    fn from_evm_halt(halt: TempoHaltReason, gas_limit: u64) -> Self {
        EthApiError::from_evm_halt(halt, gas_limit).into()
    }
}

impl FromRevert for TempoEthApiError {
    fn from_revert(revert: Bytes) -> Self {
        match tempo_precompiles::error::decode_error(&revert.0) {
            Some(error) => Self::EthApiError(EthApiError::Other(Box::new(rpc_err(
                3,
                format!("execution reverted: {}", error.error),
                Some(error.revert_bytes),
            )))),
            None => Self::EthApiError(EthApiError::from_revert(revert)),
        }
    }
}
