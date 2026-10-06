//! Bounded diagnostics for ordered invalid-transaction skips, never admission decisions.

use reth_revm::context::result::InvalidTransaction;
use std::{any::Any, fmt, fmt::Write};
use tempo_evm::TempoInvalidTransaction;

/// Fixed categories: error messages and transaction fields never become metric labels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InvalidTxReason {
    ValidAfter,
    ValidBefore,
    NonceManager,
    NonceTooHigh,
    NonceTooLow,
    GasLimit,
    GasPrice,
    EthereumOther,
    FeePayment,
    FeeToken,
    Keychain,
    Signature,
    TempoOther,
    UnknownType,
}

impl InvalidTxReason {
    pub(crate) fn classify(error: &dyn Any) -> Self {
        if let Some(error) = error.downcast_ref::<TempoInvalidTransaction>() {
            match error {
                TempoInvalidTransaction::EthInvalidTransaction(error) => Self::ethereum(error),
                TempoInvalidTransaction::ValidAfter { .. } => Self::ValidAfter,
                TempoInvalidTransaction::ValidBefore { .. } => Self::ValidBefore,
                // The string contains several nonce-manager failures. Keep it in
                // the bounded sample rather than inferring a subtype from its text.
                TempoInvalidTransaction::NonceManagerError(_) => Self::NonceManager,
                TempoInvalidTransaction::CollectFeePreTx(_) => Self::FeePayment,
                TempoInvalidTransaction::InvalidFeeToken(_)
                | TempoInvalidTransaction::FeeTokenNotTip20 { .. }
                | TempoInvalidTransaction::FeeTokenNotUsdCurrency { .. }
                | TempoInvalidTransaction::FeeTokenPaused { .. } => Self::FeeToken,
                TempoInvalidTransaction::AccessKeyRecoveryFailed
                | TempoInvalidTransaction::AccessKeyCannotAuthorizeOtherKeys
                | TempoInvalidTransaction::KeyAuthorizationSignatureRecoveryFailed
                | TempoInvalidTransaction::KeyAuthorizationNotSignedByRoot { .. }
                | TempoInvalidTransaction::AccessKeyExpiryInPast { .. }
                | TempoInvalidTransaction::KeychainPrecompileError { .. }
                | TempoInvalidTransaction::KeychainUserAddressMismatch { .. }
                | TempoInvalidTransaction::KeychainValidationFailed { .. }
                | TempoInvalidTransaction::KeyAuthorizationChainIdMismatch { .. }
                | TempoInvalidTransaction::LegacyKeychainSignature
                | TempoInvalidTransaction::V2KeychainBeforeActivation => Self::Keychain,
                TempoInvalidTransaction::InvalidFeePayerSignature
                | TempoInvalidTransaction::InvalidP256Signature
                | TempoInvalidTransaction::InvalidWebAuthnSignature { .. } => Self::Signature,
                _ => Self::TempoOther,
            }
        } else if let Some(error) = error.downcast_ref::<InvalidTransaction>() {
            Self::ethereum(error)
        } else {
            Self::UnknownType
        }
    }

    fn ethereum(error: &InvalidTransaction) -> Self {
        match error {
            InvalidTransaction::NonceTooHigh { .. } => Self::NonceTooHigh,
            InvalidTransaction::NonceTooLow { .. } => Self::NonceTooLow,
            InvalidTransaction::CallerGasLimitMoreThanBlock
            | InvalidTransaction::TxGasLimitGreaterThanCap { .. }
            | InvalidTransaction::CallGasCostMoreThanGasLimit { .. }
            | InvalidTransaction::GasFloorMoreThanGasLimit { .. } => Self::GasLimit,
            InvalidTransaction::PriorityFeeGreaterThanMaxFee
            | InvalidTransaction::GasPriceLessThanBasefee => Self::GasPrice,
            _ => Self::EthereumOther,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ValidAfter => "valid_after",
            Self::ValidBefore => "valid_before",
            Self::NonceManager => "nonce_manager",
            Self::NonceTooHigh => "nonce_too_high",
            Self::NonceTooLow => "nonce_too_low",
            Self::GasLimit => "gas_limit",
            Self::GasPrice => "gas_price",
            Self::EthereumOther => "ethereum_other",
            Self::FeePayment => "fee_payment",
            Self::FeeToken => "fee_token",
            Self::Keychain => "keychain",
            Self::Signature => "signature",
            Self::TempoOther => "tempo_other",
            Self::UnknownType => "unknown_type",
        }
    }
}

/// At most one sample per category per build; no clock, allocation or global state.
#[derive(Debug, Default)]
pub(crate) struct InvalidTxSamples(u32);

const _: () = assert!((InvalidTxReason::UnknownType as u32) < u32::BITS);

impl InvalidTxSamples {
    pub(crate) fn take(&mut self, reason: InvalidTxReason) -> bool {
        let bit = 1 << reason as u32;
        let first = self.0 & bit == 0;
        self.0 |= bit;
        first
    }
}

const MAX_ERROR_BYTES: usize = 512;

/// Limit formatting itself, instead of first allocating an arbitrarily large error string.
#[derive(Debug)]
pub(crate) struct ErrorSample {
    pub(crate) message: String,
    pub(crate) truncated: bool,
}

impl ErrorSample {
    pub(crate) fn new(error: &dyn fmt::Display) -> Self {
        let mut sample = Self {
            message: String::new(),
            truncated: false,
        };
        let _ = write!(&mut sample, "{error}");
        sample
    }
}

impl fmt::Write for ErrorSample {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let remaining = MAX_ERROR_BYTES - self.message.len();
        if value.len() <= remaining {
            self.message.push_str(value);
            return Ok(());
        }
        let mut end = remaining;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        self.message.push_str(&value[..end]);
        self.truncated = true;
        Err(fmt::Error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasons_use_types_instead_of_error_text_or_payloads() {
        let early = TempoInvalidTransaction::ValidAfter {
            current: 1,
            valid_after: 2,
        };
        let expired = TempoInvalidTransaction::ValidBefore {
            current: 3,
            valid_before: 2,
        };
        assert_eq!(
            InvalidTxReason::classify(&early),
            InvalidTxReason::ValidAfter
        );
        assert_eq!(
            InvalidTxReason::classify(&expired),
            InvalidTxReason::ValidBefore
        );
        for message in [
            "ExpiringNonceReplay",
            "ExpiringNonceSetFull",
            "arbitrary future message",
        ] {
            let nonce = TempoInvalidTransaction::NonceManagerError(message.into());
            let keychain = TempoInvalidTransaction::KeychainValidationFailed {
                reason: message.into(),
            };
            assert_eq!(
                InvalidTxReason::classify(&nonce),
                InvalidTxReason::NonceManager
            );
            assert_eq!(
                InvalidTxReason::classify(&keychain),
                InvalidTxReason::Keychain
            );
            assert_eq!(
                InvalidTxReason::classify(&message),
                InvalidTxReason::UnknownType
            );
        }
        for (error, expected) in [
            (
                InvalidTransaction::NonceTooHigh { tx: 2, state: 1 },
                InvalidTxReason::NonceTooHigh,
            ),
            (
                InvalidTransaction::NonceTooLow { tx: 1, state: 2 },
                InvalidTxReason::NonceTooLow,
            ),
            (
                InvalidTransaction::CallerGasLimitMoreThanBlock,
                InvalidTxReason::GasLimit,
            ),
            (
                InvalidTransaction::GasPriceLessThanBasefee,
                InvalidTxReason::GasPrice,
            ),
        ] {
            assert_eq!(InvalidTxReason::classify(&error), expected);
            assert_eq!(
                InvalidTxReason::classify(&TempoInvalidTransaction::from(error)),
                expected
            );
        }
    }

    #[test]
    fn samples_are_limited_independently_per_reason_and_per_build() {
        let mut first_build = InvalidTxSamples::default();
        let reasons = [
            InvalidTxReason::ValidAfter,
            InvalidTxReason::ValidBefore,
            InvalidTxReason::NonceManager,
            InvalidTxReason::NonceTooHigh,
            InvalidTxReason::NonceTooLow,
            InvalidTxReason::GasLimit,
            InvalidTxReason::GasPrice,
            InvalidTxReason::EthereumOther,
            InvalidTxReason::FeePayment,
            InvalidTxReason::FeeToken,
            InvalidTxReason::Keychain,
            InvalidTxReason::Signature,
            InvalidTxReason::TempoOther,
            InvalidTxReason::UnknownType,
        ];
        for reason in reasons {
            assert!(first_build.take(reason), "{reason:?}");
            for _ in 0..100 {
                assert!(!first_build.take(reason), "{reason:?}");
            }
        }
        let mut second_build = InvalidTxSamples::default();
        for reason in reasons {
            assert!(second_build.take(reason), "{reason:?}");
            assert!(!first_build.take(reason), "{reason:?}");
        }
    }

    #[test]
    fn error_sample_bounds_streamed_utf8_without_losing_short_errors() {
        let short = ErrorSample::new(&"short error");
        assert_eq!(short.message, "short error");
        assert!(!short.truncated);
        let exact = ErrorSample::new(&"x".repeat(MAX_ERROR_BYTES));
        assert_eq!(exact.message.len(), MAX_ERROR_BYTES);
        assert!(!exact.truncated);
        let long = ErrorSample::new(&format!("{}é", "x".repeat(MAX_ERROR_BYTES - 1)));
        assert_eq!(long.message, "x".repeat(MAX_ERROR_BYTES - 1));
        assert!(long.truncated);

        struct StreamedError;
        impl fmt::Display for StreamedError {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                for _ in 0..MAX_ERROR_BYTES + 1 {
                    formatter.write_str("x")?;
                }
                panic!("formatting must stop when the sample is full");
            }
        }
        let streamed = ErrorSample::new(&StreamedError);
        assert_eq!(streamed.message.len(), MAX_ERROR_BYTES);
        assert!(streamed.truncated);
    }
}
