//! Tempo-specific transaction validation errors.

use alloy_primitives::U256;
use reth_evm::{InvalidTxError, revm::context::result::InvalidTransaction};

/// Tempo-specific invalid transaction errors.
///
/// This enum extends the standard Ethereum [`InvalidTransaction`] with Tempo-specific
/// validation errors that occur during transaction processing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum TempoInvalidTransaction {
    /// Standard Ethereum transaction validation error.
    #[error(transparent)]
    Ethereum(#[from] InvalidTransaction),

    /// System transaction must be a call (not a create).
    #[error("system transaction must be a call, not a create")]
    SystemTransactionMustBeCall,

    /// System transaction execution failed.
    #[error("system transaction execution failed")]
    SystemTransactionFailed,

    /// Insufficient liquidity in the FeeAMM pool to perform fee token swap.
    ///
    /// This indicates the user's fee token cannot be swapped for the native token
    /// because there's insufficient liquidity in the AMM pool.
    #[error("insufficient liquidity in FeeAMM pool to swap fee tokens (required: {fee})")]
    InsufficientAmmLiquidity {
        /// The required fee amount that couldn't be swapped.
        fee: Box<U256>,
    },

    /// Insufficient fee token balance to pay for transaction fees.
    ///
    /// This is distinct from the Ethereum `LackOfFundForMaxFee` error because
    /// it applies to custom fee tokens, not native balance.
    #[error("insufficient fee token balance: required {fee}, but only have {balance}")]
    InsufficientFeeTokenBalance {
        /// The required fee amount.
        fee: Box<U256>,
        /// The actual balance available.
        balance: Box<U256>,
    },

    /// Fee payer signature recovery failed.
    ///
    /// This error occurs when a transaction specifies a fee payer but the
    /// signature recovery for the fee payer fails.
    #[error("fee payer signature recovery failed")]
    InvalidFeePayerSignature,
}

impl InvalidTxError for TempoInvalidTransaction {
    fn is_nonce_too_low(&self) -> bool {
        match self {
            Self::Ethereum(err) => err.is_nonce_too_low(),
            _ => false,
        }
    }

    fn as_invalid_tx_err(&self) -> Option<&InvalidTransaction> {
        match self {
            Self::Ethereum(err) => Some(err),
            _ => None,
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

        let err = TempoInvalidTransaction::InsufficientAmmLiquidity {
            fee: Box::new(U256::from(1000)),
        };
        assert!(
            err.to_string()
                .contains("insufficient liquidity in FeeAMM pool")
        );

        let err = TempoInvalidTransaction::InsufficientFeeTokenBalance {
            fee: Box::new(U256::from(1000)),
            balance: Box::new(U256::from(500)),
        };
        assert!(err.to_string().contains("insufficient fee token balance"));
    }

    #[test]
    fn test_from_invalid_transaction() {
        let eth_err = InvalidTransaction::PriorityFeeGreaterThanMaxFee;
        let tempo_err: TempoInvalidTransaction = eth_err.into();
        assert!(matches!(tempo_err, TempoInvalidTransaction::Ethereum(_)));
    }
}
