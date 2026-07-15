//! Tempo EVM and transaction validation errors.

use alloy_primitives::{Address, U256};
use tempo_primitives::transaction::{KeyAuthorizationChainIdError, KeychainVersionError};

/// Errors that can occur while configuring the Tempo EVM.
#[derive(Debug, Clone, thiserror::Error)]
pub enum TempoEvmError {
    /// Error decoding fee lane data from extra data field.
    #[error("failed to decode fee lane data: {0}")]
    FeeLaneDecoding(#[from] reth_consensus::ConsensusError),

    /// Invalid EVM configuration.
    #[error("invalid EVM configuration: {0}")]
    InvalidEvmConfig(String),
}

/// Tempo-specific transaction validation errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TempoInvalidTransaction {
    #[error("system transaction must be a call, not a create")]
    SystemTransactionMustBeCall,
    #[error("system transaction execution failed: {0}")]
    SystemTransactionFailed(String),
    #[error("fee payer signature recovery failed")]
    InvalidFeePayerSignature,
    #[error("fee payer cannot resolve to sender")]
    SelfSponsoredFeePayer,
    #[error(
        "transaction not valid yet: current block timestamp {current} < validAfter {valid_after}"
    )]
    ValidAfter { current: u64, valid_after: u64 },
    #[error("transaction expired: current block timestamp {current} >= validBefore {valid_before}")]
    ValidBefore { current: u64, valid_before: u64 },
    #[error("P256 signature verification failed")]
    InvalidP256Signature,
    #[error("WebAuthn signature verification failed: {reason}")]
    InvalidWebAuthnSignature { reason: String },
    #[error("nonce manager error: {0}")]
    NonceManagerError(String),
    #[error("expiring nonce transaction requires tempo_tx_env")]
    ExpiringNonceMissingTxEnv,
    #[error("expiring nonce transaction requires valid_before to be set")]
    ExpiringNonceMissingValidBefore,
    #[error("expiring nonce transaction must have nonce == 0")]
    ExpiringNonceNonceNotZero,
    #[error("subblock transaction must have zero fee")]
    SubblockTransactionMustHaveZeroFee,
    #[error("invalid fee token: {0}")]
    InvalidFeeToken(Address),
    #[error("fee token {address} is not a TIP-20 token; fee tokens must be TIP-20 tokens")]
    FeeTokenNotTip20 { address: Address },
    #[error(
        "fee token {address} uses currency {currency:?}; fee tokens must be USD-denominated TIP-20 tokens"
    )]
    FeeTokenNotUsdCurrency { address: Address, currency: String },
    #[error("fee token {address} is paused and cannot be used for fees")]
    FeeTokenPaused { address: Address },
    #[error("value transfer not allowed")]
    ValueTransferNotAllowed,
    #[error("value transfer in Tempo Transaction not allowed")]
    ValueTransferNotAllowedInAATx,
    #[error("failed to recover access key address from signature")]
    AccessKeyRecoveryFailed,
    #[error("access keys cannot authorize other keys, only the root key can authorize new keys")]
    AccessKeyCannotAuthorizeOtherKeys,
    #[error("failed to recover signer from KeyAuthorization signature")]
    KeyAuthorizationSignatureRecoveryFailed,
    #[error(
        "KeyAuthorization must be signed by root account {expected}, but was signed by {actual}"
    )]
    KeyAuthorizationNotSignedByRoot { expected: Address, actual: Address },
    #[error("access key expiry {expiry} is in the past (current timestamp: {current_timestamp})")]
    AccessKeyExpiryInPast { expiry: u64, current_timestamp: u64 },
    #[error("keychain precompile error: {reason}")]
    KeychainPrecompileError { reason: String },
    #[error("keychain user_address {user_address} does not match transaction caller {caller}")]
    KeychainUserAddressMismatch {
        user_address: Address,
        caller: Address,
    },
    #[error("keychain validation failed: {reason}")]
    KeychainValidationFailed { reason: String },
    #[error("KeyAuthorization chain_id mismatch: expected {expected}, got {got}")]
    KeyAuthorizationChainIdMismatch { expected: u64, got: u64 },
    #[error("legacy V1 keychain signature is no longer accepted, use V2 (type 0x04)")]
    LegacyKeychainSignature,
    #[error("V2 keychain signature (type 0x04) is not valid before T1C activation")]
    V2KeychainBeforeActivation,
    #[error("keychain operations are not supported in subblock transactions")]
    KeychainOpInSubblockTransaction,
    #[error(transparent)]
    CollectFeePreTx(#[from] FeePaymentError),
    #[error("{0}")]
    CallsValidation(&'static str),
}

impl TempoInvalidTransaction {
    /// Returns whether the transaction is inherently malformed rather than state-dependent.
    pub fn is_bad_transaction(&self) -> bool {
        match self {
            Self::SystemTransactionMustBeCall
            | Self::SystemTransactionFailed(_)
            | Self::InvalidFeePayerSignature
            | Self::SelfSponsoredFeePayer
            | Self::InvalidP256Signature
            | Self::InvalidWebAuthnSignature { .. }
            | Self::AccessKeyRecoveryFailed
            | Self::AccessKeyCannotAuthorizeOtherKeys
            | Self::KeyAuthorizationSignatureRecoveryFailed
            | Self::KeyAuthorizationNotSignedByRoot { .. }
            | Self::KeychainUserAddressMismatch { .. }
            | Self::KeyAuthorizationChainIdMismatch { .. }
            | Self::ValueTransferNotAllowed
            | Self::ValueTransferNotAllowedInAATx
            | Self::ExpiringNonceMissingTxEnv
            | Self::ExpiringNonceMissingValidBefore
            | Self::ExpiringNonceNonceNotZero
            | Self::SubblockTransactionMustHaveZeroFee
            | Self::KeychainOpInSubblockTransaction
            | Self::LegacyKeychainSignature
            | Self::CallsValidation(_) => true,
            Self::ValidAfter { .. }
            | Self::ValidBefore { .. }
            | Self::InvalidFeeToken(_)
            | Self::FeeTokenNotTip20 { .. }
            | Self::FeeTokenNotUsdCurrency { .. }
            | Self::FeeTokenPaused { .. }
            | Self::AccessKeyExpiryInPast { .. }
            | Self::KeychainPrecompileError { .. }
            | Self::KeychainValidationFailed { .. }
            | Self::CollectFeePreTx(_)
            | Self::NonceManagerError(_)
            | Self::V2KeychainBeforeActivation => false,
        }
    }
}

impl From<&'static str> for TempoInvalidTransaction {
    fn from(err: &'static str) -> Self {
        Self::CallsValidation(err)
    }
}

impl From<KeychainVersionError> for TempoInvalidTransaction {
    fn from(err: KeychainVersionError) -> Self {
        match err {
            KeychainVersionError::LegacyPostT1C => Self::LegacyKeychainSignature,
            KeychainVersionError::V2BeforeActivation => Self::V2KeychainBeforeActivation,
        }
    }
}

impl From<KeyAuthorizationChainIdError> for TempoInvalidTransaction {
    fn from(err: KeyAuthorizationChainIdError) -> Self {
        Self::KeyAuthorizationChainIdMismatch {
            expected: err.expected,
            got: err.got,
        }
    }
}

/// Errors raised while collecting transaction fees in TIP-20.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FeePaymentError {
    #[error(
        "insufficient liquidity in FeeAMM pool to swap fee tokens{pair} (required: {fee})",
        pair = liquidity_pair_msg(.user_token, .validator_token)
    )]
    InsufficientAmmLiquidity {
        user_token: Option<Address>,
        validator_token: Option<Address>,
        fee: U256,
    },
    #[error("insufficient fee token balance: required {fee}, but only have {balance}")]
    InsufficientFeeTokenBalance { fee: U256, balance: U256 },
    #[error("{0}")]
    Other(String),
}

fn liquidity_pair_msg(user_token: &Option<Address>, validator_token: &Option<Address>) -> String {
    match (user_token, validator_token) {
        (Some(user_token), Some(validator_token)) => {
            format!(" for pair {user_token} -> {validator_token}")
        }
        (Some(user_token), None) => format!(" for user token {user_token}"),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use evm2::registry::HandlerError;

    #[test]
    fn test_error_display() {
        let err = TempoInvalidTransaction::SystemTransactionMustBeCall;
        assert_eq!(
            err.to_string(),
            "system transaction must be a call, not a create"
        );

        let err = FeePaymentError::InsufficientAmmLiquidity {
            user_token: None,
            validator_token: None,
            fee: U256::from(1000),
        };
        assert!(err.to_string().contains("required: 1000"));

        let user_token = Address::with_last_byte(0x11);
        let validator_token = Address::with_last_byte(0x22);
        let err = FeePaymentError::InsufficientAmmLiquidity {
            user_token: Some(user_token),
            validator_token: Some(validator_token),
            fee: U256::from(1000),
        };
        let msg = err.to_string();
        assert!(msg.contains("insufficient liquidity in FeeAMM pool"));
        assert!(msg.contains(&format!("{user_token} -> {validator_token}")));
        assert!(msg.contains("required: 1000"));

        let err = FeePaymentError::InsufficientFeeTokenBalance {
            fee: U256::from(1000),
            balance: U256::from(500),
        };
        assert!(err.to_string().contains("insufficient fee token balance"));
    }

    #[test]
    fn test_from_invalid_transaction() {
        let error = HandlerError::external(TempoInvalidTransaction::InvalidFeePayerSignature);
        assert!(matches!(
            error.external_ref::<TempoInvalidTransaction>(),
            Some(TempoInvalidTransaction::InvalidFeePayerSignature)
        ));
    }

    #[test]
    fn test_fee_token_errors_are_not_bad_transactions() {
        let address = Address::repeat_byte(0x20);
        let cases = [
            TempoInvalidTransaction::InvalidFeeToken(address),
            TempoInvalidTransaction::FeeTokenNotTip20 { address },
            TempoInvalidTransaction::FeeTokenNotUsdCurrency {
                address,
                currency: "EUR".to_string(),
            },
            TempoInvalidTransaction::FeeTokenPaused { address },
        ];

        for err in cases {
            assert!(!err.is_bad_transaction(), "{err} should not be bad");
        }
    }

    #[test]
    fn test_bad_transaction() {
        let err = TempoInvalidTransaction::InvalidFeePayerSignature;
        assert!(err.is_bad_transaction());

        let err = TempoInvalidTransaction::SelfSponsoredFeePayer;
        assert!(err.is_bad_transaction());
    }

    #[test]
    fn test_fee_payment_error() {
        let error = HandlerError::external(TempoInvalidTransaction::from(
            FeePaymentError::InsufficientAmmLiquidity {
                user_token: None,
                validator_token: None,
                fee: U256::from(1000),
            },
        ));
        assert!(matches!(
            error.external_ref::<TempoInvalidTransaction>(),
            Some(TempoInvalidTransaction::CollectFeePreTx(
                FeePaymentError::InsufficientAmmLiquidity { .. }
            ))
        ));
    }
}
