//! Tempo-specific transaction validation errors.

use alloy_evm::error::InvalidTxError;
use alloy_primitives::{Address, U256};
use revm::context::result::{EVMError, ExecutionResult, HaltReason, InvalidTransaction};

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
    #[error("system transaction execution failed, result: {_0:?}")]
    SystemTransactionFailed(ExecutionResult<TempoHaltReason>),

    /// Fee payer signature recovery failed.
    ///
    /// This error occurs when a transaction specifies a fee payer but the
    /// signature recovery for the fee payer fails.
    #[error("fee payer signature recovery failed")]
    InvalidFeePayerSignature,

    // Tempo transaction errors
    /// Transaction cannot be included before validAfter timestamp.
    ///
    /// Tempo transactions can specify a validAfter field to restrict when they can be included.
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
    /// Tempo transactions can specify a validBefore field to restrict when they can be included.
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
    /// The WebAuthn signature validation failed (could be authenticatorData, clientDataJSON, or P256 verification).
    #[error("WebAuthn signature verification failed: {reason}")]
    InvalidWebAuthnSignature {
        /// Specific reason for failure.
        reason: String,
    },

    /// Insufficient gas for intrinsic cost.
    ///
    /// Tempo transactions have variable intrinsic gas costs based on signature type and nonce usage.
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

    /// Value transfer in Tempo Transaction not allowed.
    #[error("value transfer in Tempo Transaction not allowed")]
    ValueTransferNotAllowedInAATx,

    /// Failed to recover access key address from signature.
    ///
    /// This error occurs when attempting to recover the access key address from a Keychain signature fails.
    #[error("failed to recover access key address from signature")]
    AccessKeyRecoveryFailed,

    /// Access keys cannot authorize other keys.
    ///
    /// Only the root key can authorize new access keys. An access key can only authorize itself
    /// in a same-transaction authorization flow.
    #[error("access keys cannot authorize other keys, only the root key can authorize new keys")]
    AccessKeyCannotAuthorizeOtherKeys,

    /// Failed to recover signer from KeyAuthorization signature.
    ///
    /// This error occurs when signature recovery from the KeyAuthorization fails.
    #[error("failed to recover signer from KeyAuthorization signature")]
    KeyAuthorizationSignatureRecoveryFailed,

    /// KeyAuthorization not signed by root account.
    ///
    /// The KeyAuthorization must be signed by the root account (transaction caller),
    /// but was signed by a different address.
    #[error(
        "KeyAuthorization must be signed by root account {expected}, but was signed by {actual}"
    )]
    KeyAuthorizationNotSignedByRoot {
        /// The expected signer (root account).
        expected: Address,
        /// The actual signer recovered from the signature.
        actual: Address,
    },

    /// Access key expiry is in the past.
    ///
    /// An access key cannot be authorized with an expiry timestamp that has already passed.
    #[error("access key expiry {expiry} is in the past (current timestamp: {current_timestamp})")]
    AccessKeyExpiryInPast {
        /// The expiry timestamp from the KeyAuthorization.
        expiry: u64,
        /// The current block timestamp.
        current_timestamp: u64,
    },

    /// AccountKeychain precompile error during key authorization.
    ///
    /// This error occurs when the AccountKeychain precompile rejects the key authorization
    /// (e.g., key already exists, invalid parameters).
    #[error("keychain precompile error: {reason}")]
    KeychainPrecompileError {
        /// The error message from the precompile.
        reason: String,
    },

    /// Keychain user address does not match transaction caller.
    ///
    /// For Keychain signatures, the user_address field must match the transaction caller.
    #[error("keychain user_address {user_address} does not match transaction caller {caller}")]
    KeychainUserAddressMismatch {
        /// The user_address from the Keychain signature.
        user_address: Address,
        /// The transaction caller.
        caller: Address,
    },

    /// Keychain validation failed.
    ///
    /// The access key is not authorized in the AccountKeychain precompile for this user,
    /// or the key has expired, or spending limits are exceeded.
    #[error("keychain validation failed: {reason}")]
    KeychainValidationFailed {
        /// The validation error details.
        reason: String,
    },

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

    /// Root key has been disabled for this account.
    ///
    /// The account has permanently disabled its root key. Only access keys can sign
    /// transactions, and no new keys can be authorized.
    #[error("root key is disabled for this account")]
    RootKeyDisabled,

    /// Fee payment error.
    #[error(transparent)]
    CollectFeePreTx(#[from] FeePaymentError),

    /// Tempo transaction validation error from validate_calls().
    ///
    /// This wraps validation errors from the shared validate_calls function.
    #[error("{0}")]
    CallsValidation(&'static str),
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

impl From<&'static str> for TempoInvalidTransaction {
    fn from(err: &'static str) -> Self {
        Self::CallsValidation(err)
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
/// Used to extend basic [`HaltReason`] with an edge case of a subblock transaction fee payment error.
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
        assert_eq!(
            err.to_string(),
            "system transaction must be a call, not a create"
        );

        let err = FeePaymentError::InsufficientAmmLiquidity {
            fee: U256::from(1000),
        };
        assert!(
            err.to_string()
                .contains("insufficient liquidity in FeeAMM pool")
        );

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
        assert!(matches!(
            tempo_err,
            TempoInvalidTransaction::EthInvalidTransaction(_)
        ));
    }

    #[test]
    fn test_is_nonce_too_low() {
        let err = TempoInvalidTransaction::EthInvalidTransaction(InvalidTransaction::NonceTooLow {
            tx: 1,
            state: 0,
        });
        assert!(err.is_nonce_too_low());
        assert!(err.as_invalid_tx_err().is_some());

        let err = TempoInvalidTransaction::InvalidFeePayerSignature;
        assert!(!err.is_nonce_too_low());
        assert!(err.as_invalid_tx_err().is_none());
    }

    #[test]
    fn test_fee_payment_error() {
        let _: EVMError<(), TempoInvalidTransaction> = FeePaymentError::InsufficientAmmLiquidity {
            fee: U256::from(1000),
        }
        .into();
    }
}
