use std::convert::Infallible;

use alloy_primitives::{Address, Bytes, U256};
use reth_errors::ProviderError;
use reth_evm::revm::context::result::EVMError;
use reth_node_core::rpc::result::rpc_err;
use reth_rpc_eth_api::AsEthApiError;
use reth_rpc_eth_types::{
    EthApiError, RpcInvalidTransactionError,
    error::api::{FromEvmHalt, FromRevert},
};
use tempo_evm::TempoHaltReason;

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct InsufficientFeeTokenFundsData {
    fee_token: Address,
    cost: String,
    balance: String,
}

#[derive(Debug, thiserror::Error)]
pub enum TempoEthApiError {
    #[error(transparent)]
    EthApiError(EthApiError),
    #[error("insufficient funds for gas * price + value: have {balance} want {cost}")]
    InsufficientFeeTokenFunds {
        cost: U256,
        balance: U256,
        fee_token: Address,
        eth_api_error: Box<EthApiError>,
    },
}

impl TempoEthApiError {
    pub fn insufficient_fee_token_funds(cost: U256, balance: U256, fee_token: Address) -> Self {
        Self::InsufficientFeeTokenFunds {
            cost,
            balance,
            fee_token,
            eth_api_error: Box::new(EthApiError::InvalidTransaction(
                RpcInvalidTransactionError::InsufficientFunds { cost, balance },
            )),
        }
    }
}

impl From<TempoEthApiError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(error: TempoEthApiError) -> Self {
        match error {
            TempoEthApiError::EthApiError(err) => err.into(),
            TempoEthApiError::InsufficientFeeTokenFunds {
                cost,
                balance,
                fee_token,
                ..
            } => {
                let err = RpcInvalidTransactionError::InsufficientFunds { cost, balance };
                jsonrpsee::types::error::ErrorObject::owned(
                    err.error_code(),
                    err.to_string(),
                    Some(InsufficientFeeTokenFundsData {
                        fee_token,
                        cost: format!("0x{cost:x}"),
                        balance: format!("0x{balance:x}"),
                    }),
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
            Self::InsufficientFeeTokenFunds { eth_api_error, .. } => Some(eth_api_error.as_ref()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insufficient_fee_token_funds_keeps_standard_error_and_includes_fee_token_data() {
        let cost = U256::from(21_000u64);
        let balance = U256::ZERO;
        let fee_token = Address::with_last_byte(0x42);

        let err = TempoEthApiError::insufficient_fee_token_funds(cost, balance, fee_token);

        let eth_err = err.as_err().expect("must expose core EthApiError");
        assert!(matches!(
            eth_err,
            EthApiError::InvalidTransaction(RpcInvalidTransactionError::InsufficientFunds {
                cost: c,
                balance: b,
            }) if *c == cost && *b == balance
        ));

        let rpc_err: jsonrpsee::types::error::ErrorObject<'static> = err.into();
        assert_eq!(
            rpc_err.code(),
            RpcInvalidTransactionError::InsufficientFunds { cost, balance }.error_code()
        );
        assert_eq!(
            rpc_err.message(),
            "insufficient funds for gas * price + value: have 0 want 21000"
        );

        let data = rpc_err.data().expect("must include structured error data");
        let data: serde_json::Value =
            serde_json::from_str(data.get()).expect("error data must be valid JSON");
        assert_eq!(data["feeToken"], serde_json::json!(fee_token));
        assert_eq!(data["cost"], "0x5208");
        assert_eq!(data["balance"], "0x0");
    }
}
