//! Tempo-specific transaction validation errors.

use alloy_evm::error::InvalidTxError;
use alloy_primitives::{Address, U256};
use revm::context::result::{EVMError, HaltReason, InvalidTransaction};

/// Tempo-specific invalid transaction errors.
///
/// This enum extends the standard Ethereum [`InvalidTransaction`] with Tempo-specific
/// validation errors that occur during transaction processing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum TempoInvalidTransaction {
    /// Standard Ethereum transaction validation error.
    #[error(transparent)]
    EthInvalidTransaction(#[from] InvalidTransaction),

    /// System transaction must be a call (not a create).
    #[error("system transaction must be a call, not a create")]
    SystemTransactionMustBeCall,

    /// System transaction execution failed.
    #[error("system transaction execution failed")]
    SystemTransactionFailed,

    /// Fee payer signature recovery failed.
    ///
    /// This error occurs when a transaction specifies a fee payer but the
    /// signature recovery for the fee payer fails.
    #[error("fee payer signature recovery failed")]
    InvalidFeePayerSignature,

    // Account Abstraction (AA) transaction errors
    /// Transaction cannot be included before validAfter timestamp.
    ///
    /// AA transactions can specify a validAfter field to restrict when they can be included.
    #[error(
        "transaction not valid yet: current block timestamp {current} < validAfter {valid_after}"
    )]
    ValidAfter {
        /// The current block timestamp.
        current: u64,
        /// The validAfter constraint from the transaction.
        valid_after: u64,
    },

    /// Transaction cannot be included after validBefore timestamp.
    ///
    /// AA transactions can specify a validBefore field to restrict when they can be included.
    #[error("transaction expired: current block timestamp {current} >= validBefore {valid_before}")]
    ValidBefore {
        /// The current block timestamp.
        current: u64,
        /// The validBefore constraint from the transaction.
        valid_before: u64,
    },

    /// P256 signature verification failed.
    ///
    /// The P256 signature could not be verified against the transaction hash.
    #[error("P256 signature verification failed")]
    InvalidP256Signature,

    /// WebAuthn signature verification failed.
    ///
    /// The WebAuthn signature validation failed (could be authenticatorData, clientDataJSON, or
    /// P256 verification).
    #[error("WebAuthn signature verification failed: {reason}")]
    InvalidWebAuthnSignature {
        /// Specific reason for failure.
        reason: String,
    },

    /// Insufficient gas for intrinsic cost.
    ///
    /// AA transactions have variable intrinsic gas costs based on signature type and nonce usage.
    /// This error occurs when the gas_limit is less than the calculated intrinsic gas.
    #[error(
        "insufficient gas for intrinsic cost: gas_limit {gas_limit} < intrinsic_gas {intrinsic_gas}"
    )]
    InsufficientGasForIntrinsicCost {
        /// The transaction's gas limit.
        gas_limit: u64,
        /// The calculated intrinsic gas required.
        intrinsic_gas: u64,
    },

    /// Nonce manager error.
    #[error("nonce manager error: {0}")]
    NonceManagerError(String),

    /// Subblock transaction must have zero fee.
    #[error("subblock transaction must have zero fee")]
    SubblockTransactionMustHaveZeroFee,

    /// Invalid fee token.
    #[error("invalid fee token: {0}")]
    InvalidFeeToken(Address),

    /// Value transfer not allowed.
    #[error("value transfer not allowed")]
    ValueTransferNotAllowed,

    /// Value transfer in AA transaction not allowed.
    #[error("value transfer in AA transaction not allowed")]
    ValueTransferNotAllowedInAATx,

    /// Access key authorization failed.
    ///
    /// This error occurs when attempting to authorize an access key with the AccountKeychain
    /// precompile fails (e.g., key already exists, invalid parameters, unauthorized caller).
    #[error("access key authorization failed: {reason}")]
    AccessKeyAuthorizationFailed {
        /// Specific reason for failure.
        reason: String,
    },

    /// Keychain operations are only supported after Allegretto.
    #[error("keychain operations are only supported after Allegretto")]
    KeychainOpBeforeAllegretto,

    /// KeyAuthorization chain_id does not match the current chain.
    #[error("KeyAuthorization chain_id mismatch: expected {expected}, got {got}")]
    KeyAuthorizationChainIdMismatch {
        /// The expected chain ID (current chain).
        expected: u64,
        /// The chain ID from the KeyAuthorization.
        got: u64,
    },

    /// Keychain operations are not supported in subblock transactions.
    #[error("keychain operations are not supported in subblock transactions")]
    KeychainOpInSubblockTransaction,

    /// Fee payment error.
    #[error(transparent)]
    CollectFeePreTx(#[from] FeePaymentError),
}

impl InvalidTxError for TempoInvalidTransaction {
    fn is_nonce_too_low(&self) -> bool {
        match self {
            Self::EthInvalidTransaction(err) => err.is_nonce_too_low(),
            _ => false,
        }
    }

    fn as_invalid_tx_err(&self) -> Option<&InvalidTransaction> {
        match self {
            Self::EthInvalidTransaction(err) => Some(err),
            _ => None,
        }
    }
}

impl<DBError> From<TempoInvalidTransaction> for EVMError<DBError, TempoInvalidTransaction> {
    fn from(err: TempoInvalidTransaction) -> Self {
        Self::Transaction(err)
    }
}

/// Error type for fee payment errors.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum FeePaymentError {
    /// Insufficient liquidity in the FeeAMM pool to perform fee token swap.
    ///
    /// This indicates the user's fee token cannot be swapped for the native token
    /// because there's insufficient liquidity in the AMM pool.
    #[error("insufficient liquidity in FeeAMM pool to swap fee tokens (required: {fee})")]
    InsufficientAmmLiquidity {
        /// The required fee amount that couldn't be swapped.
        fee: U256,
    },

    /// Insufficient fee token balance to pay for transaction fees.
    ///
    /// This is distinct from the Ethereum `LackOfFundForMaxFee` error because
    /// it applies to custom fee tokens, not native balance.
    #[error("insufficient fee token balance: required {fee}, but only have {balance}")]
    InsufficientFeeTokenBalance {
        /// The required fee amount.
        fee: U256,
        /// The actual balance available.
        balance: U256,
    },

    /// Other error.
    #[error("{0}")]
    Other(String),
}

impl<DBError> From<FeePaymentError> for EVMError<DBError, TempoInvalidTransaction> {
    fn from(err: FeePaymentError) -> Self {
        TempoInvalidTransaction::from(err).into()
    }
}

/// Tempo-specific halt reason.
///
/// Used to extend basic [`HaltReason`] with an edge case of a subblock transaction fee payment
/// error.
#[derive(Debug, Clone, PartialEq, Eq, Hash, derive_more::From)]
pub enum TempoHaltReason {
    /// Basic Ethereum halt reason.
    #[from]
    Ethereum(HaltReason),
    /// Subblock transaction failed to pay fees.
    SubblockTxFeePayment,
}

#[cfg(feature = "rpc")]
impl reth_rpc_eth_types::error::api::FromEvmHalt<TempoHaltReason>
    for reth_rpc_eth_types::EthApiError
{
    fn from_evm_halt(halt_reason: TempoHaltReason, gas_limit: u64) -> Self {
        match halt_reason {
            TempoHaltReason::Ethereum(halt_reason) => Self::from_evm_halt(halt_reason, gas_limit),
            TempoHaltReason::SubblockTxFeePayment => {
                Self::EvmCustom("subblock transaction failed to pay fees".to_string())
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = TempoInvalidTransaction::SystemTransactionMustBeCall;
        assert_eq!(err.to_string(), "system transaction must be a call, not a create");

        let err = FeePaymentError::InsufficientAmmLiquidity { fee: U256::from(1000) };
        assert!(err.to_string().contains("insufficient liquidity in FeeAMM pool"));

        let err = FeePaymentError::InsufficientFeeTokenBalance {
            fee: U256::from(1000),
            balance: U256::from(500),
        };
        assert!(err.to_string().contains("insufficient fee token balance"));
    }

    #[test]
    fn test_from_invalid_transaction() {
        let eth_err = InvalidTransaction::PriorityFeeGreaterThanMaxFee;
        let tempo_err: TempoInvalidTransaction = eth_err.into();
        assert!(matches!(tempo_err, TempoInvalidTransaction::EthInvalidTransaction(_)));
    }
}
