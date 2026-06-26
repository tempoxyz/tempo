use std::convert::Infallible;

use alloy_primitives::Bytes;
use alloy_rpc_types_eth::error::EthRpcErrorCode;
use jsonrpsee::types::error::ErrorObject;
use reth_errors::ProviderError;
use reth_evm::revm::context::result::EVMError;
use reth_node_core::rpc::result::rpc_err;
use reth_rpc_eth_api::AsEthApiError;
use reth_rpc_eth_types::{
    EthApiError,
    error::{
        RpcPoolError,
        api::{FromEvmHalt, FromRevert},
    },
};
use tempo_evm::{TempoHaltReason, TempoInvalidTransaction};
use tempo_transaction_pool::transaction::TempoPoolTransactionError;

#[derive(Debug, thiserror::Error)]
pub enum TempoEthApiError {
    #[error(transparent)]
    EthApiError(EthApiError),
}

impl From<TempoEthApiError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(error: TempoEthApiError) -> Self {
        if let TempoEthApiError::EthApiError(EthApiError::PoolError(
            RpcPoolError::PoolTransactionError(err),
        )) = &error
            && let Some(TempoPoolTransactionError::Evm(err)) =
                err.as_any().downcast_ref::<TempoPoolTransactionError>()
            && let Some(rpc_error) = fee_token_rpc_error(err)
        {
            return rpc_error;
        }

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
impl<T> From<EVMError<T, TempoInvalidTransaction>> for TempoEthApiError
where
    T: Into<EthApiError>,
{
    fn from(error: EVMError<T, TempoInvalidTransaction>) -> Self {
        if let EVMError::Transaction(err) = &error
            && let Some(rpc_error) = fee_token_rpc_error(err)
        {
            return Self::EthApiError(EthApiError::Other(Box::new(rpc_error)));
        }

        EthApiError::from(error).into()
    }
}

fn fee_token_rpc_error(err: &TempoInvalidTransaction) -> Option<ErrorObject<'static>> {
    let data = match err {
        TempoInvalidTransaction::FeeTokenNotTip20 { address } => serde_json::json!({
            "name": "FeeTokenNotTip20Error",
            "token": address.to_string(),
        }),
        TempoInvalidTransaction::FeeTokenNotUsdCurrency { address, currency } => {
            serde_json::json!({
                "name": "FeeTokenNotUsdError",
                "token": address.to_string(),
                "currency": currency,
            })
        }
        TempoInvalidTransaction::FeeTokenPaused { address } => serde_json::json!({
            "name": "FeeTokenPausedError",
            "token": address.to_string(),
        }),
        _ => return None,
    };

    Some(ErrorObject::owned(
        EthRpcErrorCode::TransactionRejected.code(),
        err.to_string(),
        Some(data),
    ))
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
    use alloy_primitives::Address;

    use super::*;

    fn into_rpc_error(err: TempoInvalidTransaction) -> ErrorObject<'static> {
        let api_error = TempoEthApiError::from(EVMError::<ProviderError, _>::Transaction(err));
        api_error.into()
    }

    fn rpc_error_data(error: &ErrorObject<'static>) -> serde_json::Value {
        serde_json::from_str(error.data().expect("rpc error has data").get())
            .expect("rpc error data is valid json")
    }

    #[test]
    fn fee_token_errors_are_transaction_rejected_rpc_errors() {
        let address = Address::repeat_byte(0x20);
        let cases = [
            (
                TempoInvalidTransaction::FeeTokenNotTip20 { address },
                "is not a TIP-20 token",
                serde_json::json!({
                    "name": "FeeTokenNotTip20Error",
                    "token": address.to_string(),
                }),
            ),
            (
                TempoInvalidTransaction::FeeTokenNotUsdCurrency {
                    address,
                    currency: "EUR".to_string(),
                },
                "uses currency",
                serde_json::json!({
                    "name": "FeeTokenNotUsdError",
                    "token": address.to_string(),
                    "currency": "EUR",
                }),
            ),
            (
                TempoInvalidTransaction::FeeTokenPaused { address },
                "is paused",
                serde_json::json!({
                    "name": "FeeTokenPausedError",
                    "token": address.to_string(),
                }),
            ),
        ];

        for (err, message, expected_data) in cases {
            let rpc_error = into_rpc_error(err);

            assert_eq!(
                rpc_error.code(),
                EthRpcErrorCode::TransactionRejected.code()
            );
            assert!(rpc_error.message().contains(message));
            assert_eq!(rpc_error_data(&rpc_error), expected_data);
        }
    }

    #[test]
    fn pool_fee_token_errors_are_transaction_rejected_rpc_errors() {
        let address = Address::repeat_byte(0x20);
        let error = TempoEthApiError::EthApiError(EthApiError::PoolError(
            RpcPoolError::PoolTransactionError(Box::new(TempoPoolTransactionError::Evm(
                TempoInvalidTransaction::FeeTokenNotTip20 { address },
            ))),
        ));

        let rpc_error: ErrorObject<'static> = error.into();

        assert_eq!(
            rpc_error.code(),
            EthRpcErrorCode::TransactionRejected.code()
        );
        assert!(rpc_error.message().contains("is not a TIP-20 token"));
        assert_eq!(
            rpc_error_data(&rpc_error),
            serde_json::json!({
                "name": "FeeTokenNotTip20Error",
                "token": address.to_string(),
            })
        );
    }
}
