use std::{
    collections::HashMap,
    sync::{Arc, LazyLock},
};

use crate::tip20::TIP20Error;
use alloy::{
    primitives::{Selector, U256},
    sol_types::{Panic, PanicKind, SolError, SolInterface},
};
use revm::{
    context::journaled_state::JournalLoadErasedError,
    precompile::{PrecompileError, PrecompileOutput, PrecompileResult},
};
use tempo_contracts::precompiles::{
    AccountKeychainError, FeeManagerError, NonceError, RolesAuthError, StablecoinDEXError,
    TIP20FactoryError, TIP403RegistryError, TIPFeeAMMError, UnknownFunctionSelector,
    ValidatorConfigError,
};

/// Top-level error type for all Tempo precompile operations
#[derive(
    Debug, Clone, PartialEq, Eq, thiserror::Error, derive_more::From, derive_more::TryInto,
)]
pub enum TempoPrecompileError {
    /// Stablecoin DEX error
    #[error("Stablecoin DEX error: {0:?}")]
    StablecoinDEX(StablecoinDEXError),

    /// Error from TIP20 token
    #[error("TIP20 token error: {0:?}")]
    TIP20(TIP20Error),

    /// Error from TIP20 factory
    #[error("TIP20 factory error: {0:?}")]
    TIP20Factory(TIP20FactoryError),

    /// Error from roles auth
    #[error("Roles auth error: {0:?}")]
    RolesAuthError(RolesAuthError),

    /// Error from 403 registry
    #[error("TIP403 registry error: {0:?}")]
    TIP403RegistryError(TIP403RegistryError),

    /// Error from TIP  fee manager
    #[error("TIP fee manager error: {0:?}")]
    FeeManagerError(FeeManagerError),

    /// Error from TIP fee AMM
    #[error("TIP fee AMM error: {0:?}")]
    TIPFeeAMMError(TIPFeeAMMError),

    /// Error from Tempo Transaction nonce manager
    #[error("Tempo Transaction nonce error: {0:?}")]
    NonceError(NonceError),

    #[error("Panic({0:?})")]
    Panic(PanicKind),

    /// Error from validator config
    #[error("Validator config error: {0:?}")]
    ValidatorConfigError(ValidatorConfigError),

    /// Error from account keychain precompile
    #[error("Account keychain error: {0:?}")]
    AccountKeychainError(AccountKeychainError),

    #[error("Gas limit exceeded")]
    OutOfGas,

    #[error("Unknown function selector: {0:?}")]
    UnknownFunctionSelector([u8; 4]),

    #[error("Fatal precompile error: {0:?}")]
    #[from(skip)]
    Fatal(String),
}

impl From<JournalLoadErasedError> for TempoPrecompileError {
    fn from(value: JournalLoadErasedError) -> Self {
        match value {
            JournalLoadErasedError::DBError(e) => Self::Fatal(e.to_string()),
            JournalLoadErasedError::ColdLoadSkipped => Self::OutOfGas,
        }
    }
}

/// Result type alias for Tempo precompile operations
pub type Result<T> = std::result::Result<T, TempoPrecompileError>;

impl TempoPrecompileError {
    /// Returns true if this error represents a system-level failure that must be propagated
    /// rather than swallowed, because state may be inconsistent.
    pub fn is_system_error(&self) -> bool {
        match self {
            Self::OutOfGas | Self::Fatal(_) | Self::Panic(_) => true,
            Self::StablecoinDEX(_)
            | Self::TIP20(_)
            | Self::NonceError(_)
            | Self::TIP20Factory(_)
            | Self::RolesAuthError(_)
            | Self::TIPFeeAMMError(_)
            | Self::FeeManagerError(_)
            | Self::TIP403RegistryError(_)
            | Self::ValidatorConfigError(_)
            | Self::AccountKeychainError(_)
            | Self::UnknownFunctionSelector(_) => false,
        }
    }

    pub fn under_overflow() -> Self {
        Self::Panic(PanicKind::UnderOverflow)
    }

    pub fn array_oob() -> Self {
        Self::Panic(PanicKind::ArrayOutOfBounds)
    }

    pub fn into_precompile_result(self, gas: u64) -> PrecompileResult {
        let bytes = match self {
            Self::StablecoinDEX(e) => e.abi_encode().into(),
            Self::TIP20(e) => e.abi_encode().into(),
            Self::TIP20Factory(e) => e.abi_encode().into(),
            Self::RolesAuthError(e) => e.abi_encode().into(),
            Self::TIP403RegistryError(e) => e.abi_encode().into(),
            Self::FeeManagerError(e) => e.abi_encode().into(),
            Self::TIPFeeAMMError(e) => e.abi_encode().into(),
            Self::NonceError(e) => e.abi_encode().into(),
            Self::Panic(kind) => {
                let panic = Panic {
                    code: U256::from(kind as u32),
                };

                panic.abi_encode().into()
            }
            Self::ValidatorConfigError(e) => e.abi_encode().into(),
            Self::AccountKeychainError(e) => e.abi_encode().into(),
            Self::OutOfGas => {
                return Err(PrecompileError::OutOfGas);
            }
            Self::UnknownFunctionSelector(selector) => UnknownFunctionSelector {
                selector: selector.into(),
            }
            .abi_encode()
            .into(),
            Self::Fatal(msg) => {
                return Err(PrecompileError::Fatal(msg));
            }
        };
        Ok(PrecompileOutput::new_reverted(gas, bytes))
    }
}

pub fn add_errors_to_registry<T: SolInterface>(
    registry: &mut TempoPrecompileErrorRegistry,
    converter: impl Fn(T) -> TempoPrecompileError + 'static + Send + Sync,
) {
    let converter = Arc::new(converter);
    for selector in T::selectors() {
        let converter = Arc::clone(&converter);
        registry.insert(
            selector.into(),
            Box::new(move |data: &[u8]| {
                T::abi_decode(data)
                    .ok()
                    .map(|error| DecodedTempoPrecompileError {
                        error: converter(error),
                        revert_bytes: data,
                    })
            }),
        );
    }
}

pub struct DecodedTempoPrecompileError<'a> {
    pub error: TempoPrecompileError,
    pub revert_bytes: &'a [u8],
}

pub type TempoPrecompileErrorRegistry = HashMap<
    Selector,
    Box<dyn for<'a> Fn(&'a [u8]) -> Option<DecodedTempoPrecompileError<'a>> + Send + Sync>,
>;

/// Returns a HashMap mapping error selectors to their decoder functions
/// The decoder returns a `TempoPrecompileError` variant for the decoded error
pub fn error_decoder_registry() -> TempoPrecompileErrorRegistry {
    let mut registry: TempoPrecompileErrorRegistry = HashMap::new();

    add_errors_to_registry(&mut registry, TempoPrecompileError::StablecoinDEX);
    add_errors_to_registry(&mut registry, TempoPrecompileError::TIP20);
    add_errors_to_registry(&mut registry, TempoPrecompileError::TIP20Factory);
    add_errors_to_registry(&mut registry, TempoPrecompileError::RolesAuthError);
    add_errors_to_registry(&mut registry, TempoPrecompileError::TIP403RegistryError);
    add_errors_to_registry(&mut registry, TempoPrecompileError::FeeManagerError);
    add_errors_to_registry(&mut registry, TempoPrecompileError::TIPFeeAMMError);
    add_errors_to_registry(&mut registry, TempoPrecompileError::NonceError);
    add_errors_to_registry(&mut registry, TempoPrecompileError::ValidatorConfigError);
    add_errors_to_registry(&mut registry, TempoPrecompileError::AccountKeychainError);

    registry
}

pub static ERROR_REGISTRY: LazyLock<TempoPrecompileErrorRegistry> =
    LazyLock::new(error_decoder_registry);

/// Decode an error from raw bytes using the selector
pub fn decode_error<'a>(data: &'a [u8]) -> Option<DecodedTempoPrecompileError<'a>> {
    if data.len() < 4 {
        return None;
    }

    let selector: [u8; 4] = data[0..4].try_into().ok()?;
    ERROR_REGISTRY
        .get(&selector)
        .and_then(|decoder| decoder(data))
}

/// Extension trait to convert `Result<T, TempoPrecompileError` into `PrecompileResult`
pub trait IntoPrecompileResult<T> {
    fn into_precompile_result(
        self,
        gas: u64,
        encode_ok: impl FnOnce(T) -> alloy::primitives::Bytes,
    ) -> PrecompileResult;
}

impl<T> IntoPrecompileResult<T> for Result<T> {
    fn into_precompile_result(
        self,
        gas: u64,
        encode_ok: impl FnOnce(T) -> alloy::primitives::Bytes,
    ) -> PrecompileResult {
        match self {
            Ok(res) => Ok(PrecompileOutput::new(gas, encode_ok(res))),
            Err(err) => err.into_precompile_result(gas),
        }
    }
}

impl<T> IntoPrecompileResult<T> for TempoPrecompileError {
    fn into_precompile_result(
        self,
        gas: u64,
        _encode_ok: impl FnOnce(T) -> alloy::primitives::Bytes,
    ) -> PrecompileResult {
        Self::into_precompile_result(self, gas)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempo_contracts::precompiles::StablecoinDEXError;

    #[test]
    fn test_add_errors_to_registry_populates_registry() {
        let mut registry: TempoPrecompileErrorRegistry = HashMap::new();

        assert!(registry.is_empty());

        add_errors_to_registry(&mut registry, TempoPrecompileError::StablecoinDEX);

        assert!(!registry.is_empty());

        let order_not_found_selector = StablecoinDEXError::order_does_not_exist().selector();
        assert!(
            registry.contains_key(&order_not_found_selector),
            "Registry should contain OrderDoesNotExist selector"
        );
    }

    #[test]
    fn test_error_decoder_registry_is_not_empty() {
        let registry = error_decoder_registry();

        assert!(
            !registry.is_empty(),
            "error_decoder_registry should return a populated registry"
        );

        let dex_selector = StablecoinDEXError::order_does_not_exist().selector();
        assert!(registry.contains_key(&dex_selector));
    }

    #[test]
    fn test_decode_error_returns_some_for_valid_error() {
        let error = StablecoinDEXError::order_does_not_exist();
        let encoded = error.abi_encode();

        let result = decode_error(&encoded);
        assert!(
            result.is_some(),
            "decode_error should return Some for valid error"
        );

        let decoded = result.unwrap();
        assert!(matches!(
            decoded.error,
            TempoPrecompileError::StablecoinDEX(StablecoinDEXError::OrderDoesNotExist(_))
        ));
    }

    #[test]
    fn test_decode_error_data_length_boundary() {
        // Empty data (len = 0) should return None (0 < 4)
        let result = decode_error(&[]);
        assert!(result.is_none(), "Empty data should return None");

        // 1 byte (len = 1) should return None (1 < 4)
        let result = decode_error(&[0x01]);
        assert!(result.is_none(), "1 byte should return None");

        // 2 bytes (len = 2) should return None (2 < 4)
        let result = decode_error(&[0x01, 0x02]);
        assert!(result.is_none(), "2 bytes should return None");

        // 3 bytes (len = 3) should return None (3 < 4)
        let result = decode_error(&[0x01, 0x02, 0x03]);
        assert!(result.is_none(), "3 bytes should return None");

        // 4 bytes with unknown selector returns None (selector not found)
        let result = decode_error(&[0x00, 0x00, 0x00, 0x00]);
        assert!(
            result.is_none(),
            "Unknown 4-byte selector should return None"
        );

        // 4 bytes with valid selector (exactly at boundary) should succeed
        let error = StablecoinDEXError::order_does_not_exist();
        let encoded = error.abi_encode();
        let result = decode_error(&encoded);
        assert!(
            result.is_some(),
            "Valid error at 4+ bytes should return Some"
        );
    }

    #[test]
    fn test_decode_error_with_tip20_error() {
        // Use insufficient_allowance which has a unique selector (no collision with other errors)
        let error = TIP20Error::insufficient_allowance();
        let encoded = error.abi_encode();

        let result = decode_error(&encoded);
        assert!(result.is_some(), "Should decode TIP20 errors");

        let decoded = result.unwrap();
        // Verify it's a TIP20 error
        match decoded.error {
            TempoPrecompileError::TIP20(_) => {}
            other => panic!("Expected TIP20 error, got {other:?}"),
        }
    }
}
