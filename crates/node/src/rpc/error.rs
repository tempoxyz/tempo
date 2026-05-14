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

/// JSON-RPC error code for invalid input (EIP-1474 / geth convention).
///
/// Used for Tempo-specific transaction validation errors where the submitted
/// input is fundamentally invalid (wrong chain_id, bad signature, etc.).
const INVALID_INPUT: i32 = -32000;

#[derive(Debug, thiserror::Error)]
pub enum TempoEthApiError {
    #[error(transparent)]
    EthApiError(EthApiError),

    /// Tempo-specific invalid transaction error.
    ///
    /// Mapped to `-32000` (invalid input) with structured `data` instead of the generic
    /// `-32603` (internal error) that reth's catch-all produces for custom `InvalidTxError`
    /// variants.
    #[error("{message}")]
    TempoInvalidInput {
        message: String,
        data: serde_json::Value,
    },
}

impl From<TempoEthApiError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(error: TempoEthApiError) -> Self {
        match error {
            TempoEthApiError::EthApiError(err) => err.into(),
            TempoEthApiError::TempoInvalidInput { message, data } => {
                jsonrpsee::types::error::ErrorObject::owned(INVALID_INPUT, message, Some(data))
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
            Self::TempoInvalidInput { .. } => None,
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
        match error {
            EVMError::Transaction(ref tx_err) if tx_err.as_invalid_tx_err().is_none() => {
                // Tempo-specific transaction errors (KeyAuthorizationChainIdMismatch, etc.)
                // don't wrap a standard InvalidTransaction, so reth's generic conversion
                // would bucket them into EvmCustom → -32603 Internal error.
                // Surface them as -32000 (invalid input) with structured data instead.
                let message = tx_err.to_string();
                let data = tempo_tx_error_data(&message);
                Self::TempoInvalidInput { message, data }
            }
            other => EthApiError::from(other).into(),
        }
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

/// Build structured JSON `data` for a Tempo-specific transaction error.
///
/// Parses well-known error messages to extract structured fields (e.g. expected/got
/// chain IDs). Falls back to just the error identifier for unrecognised messages.
fn tempo_tx_error_data(message: &str) -> serde_json::Value {
    // KeyAuthorization chain_id mismatch: expected 42431, got 4217
    if let Some(rest) = message.strip_prefix("KeyAuthorization chain_id mismatch: ") {
        if let (Some(expected), Some(got)) = (
            rest.strip_prefix("expected ")
                .and_then(|s| s.split(',').next())
                .and_then(|s| s.trim().parse::<u64>().ok()),
            rest.rsplit("got ")
                .next()
                .and_then(|s| s.trim().parse::<u64>().ok()),
        ) {
            return serde_json::json!({
                "error": "KeyAuthorizationChainIdMismatch",
                "expected": expected,
                "got": got,
            });
        }
    }

    // Default: return the error class derived from the message prefix (up to first ':')
    let error_name = message
        .split(':')
        .next()
        .unwrap_or(message)
        .trim()
        .replace(' ', "");
    serde_json::json!({ "error": error_name })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_id_mismatch_structured_data() {
        let data = tempo_tx_error_data(
            "KeyAuthorization chain_id mismatch: expected 42431, got 4217",
        );
        assert_eq!(data["error"], "KeyAuthorizationChainIdMismatch");
        assert_eq!(data["expected"], 42431);
        assert_eq!(data["got"], 4217);
    }

    #[test]
    fn test_unknown_error_fallback() {
        let data = tempo_tx_error_data("fee payer signature recovery failed");
        assert_eq!(data["error"], "feepayersignaturerecoveryfailed");
    }

    #[test]
    fn test_error_object_code() {
        let err: jsonrpsee::types::error::ErrorObject<'static> =
            TempoEthApiError::TempoInvalidInput {
                message: "KeyAuthorization chain_id mismatch: expected 42431, got 4217"
                    .to_string(),
                data: tempo_tx_error_data(
                    "KeyAuthorization chain_id mismatch: expected 42431, got 4217",
                ),
            }
            .into();
        assert_eq!(err.code(), INVALID_INPUT);
        assert!(err.message().contains("chain_id mismatch"));
    }
}
