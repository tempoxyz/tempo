//! Unified error handling for Tempo precompiles.
//!
//! Provides [`TempoPrecompileError`] — the top-level error enum — along with an
//! ABI-selector-based decoder registry for mapping raw revert bytes back to
//! typed error variants.

use std::{
    collections::HashMap,
    sync::{Arc, LazyLock},
};

use crate::{storage_credits::StorageCreditsErr, tip20::TIP20Error};
use alloy::{
    primitives::{FixedBytes, Selector, U256},
    sol_types::{Panic, PanicKind, SolError, SolInterface},
};
use evm2::{
    ErrorCode,
    evm::precompile::PrecompileOutput,
    precompiles::{PrecompileError, PrecompileHalt, PrecompileResult},
};
use tempo_contracts::precompiles::{
    AccountKeychainError, AddrRegistryError, CurrentCommitteeError, FeeManagerError, NonceError,
    ReceivePolicyGuardError, RolesAuthError, SignatureVerifierError, StablecoinDEXError,
    StorageCreditsError, TIP20ChannelReserveError, TIP20FactoryError, TIP403RegistryError,
    TIPFeeAMMError, UnknownFunctionSelector, ValidatorConfigError, ValidatorConfigV2Error,
    ZoneFactoryError,
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

    /// Error from TIP-20 channel reserve
    #[error("TIP20 channel reserve error: {0:?}")]
    TIP20ChannelReserveError(TIP20ChannelReserveError),

    /// Error from roles auth
    #[error("Roles auth error: {0:?}")]
    RolesAuthError(RolesAuthError),

    /// Error from TIP20 registry (TIP-1022)
    #[error("TIP20 registry error: {0:?}")]
    AddrRegistryError(AddrRegistryError),

    /// Error from 403 registry
    #[error("TIP403 registry error: {0:?}")]
    TIP403RegistryError(TIP403RegistryError),

    /// Error from TIP fee manager
    #[error("TIP fee manager error: {0:?}")]
    FeeManagerError(FeeManagerError),

    /// Error from TIP fee AMM
    #[error("TIP fee AMM error: {0:?}")]
    TIPFeeAMMError(TIPFeeAMMError),

    /// Error from Tempo Transaction nonce manager
    #[error("Tempo Transaction nonce error: {0:?}")]
    NonceError(NonceError),

    /// EVM panic (i.e. arithmetic under/overflow, out-of-bounds access).
    #[error("Panic({0:?})")]
    Panic(PanicKind),

    /// Internal storage delta underflow that carries the observed slot value for error mapping.
    #[error("Storage delta underflow: current={0}")]
    StorageDeltaUnderflow(U256),

    /// Error from validator config
    #[error("Validator config error: {0:?}")]
    ValidatorConfigError(ValidatorConfigError),

    /// Error from validator config v2
    #[error("Validator config v2 error: {0:?}")]
    ValidatorConfigV2Error(ValidatorConfigV2Error),

    /// Error from account keychain precompile
    #[error("Account keychain error: {0:?}")]
    AccountKeychainError(AccountKeychainError),

    /// Error from signature verifier precompile
    #[error("Signature verifier error: {0:?}")]
    SignatureVerifierError(SignatureVerifierError),

    /// Error from TIP-1028 blocked transfers precompile
    #[error("TIP1028 blocked transfers error: {0:?}")]
    ReceivePolicyGuardError(ReceivePolicyGuardError),

    /// Error from TIP-1060 storage credits precompile
    #[error("TIP1060 storage credits error: {0:?}")]
    StorageCreditsError(StorageCreditsError),

    /// Error from current committee precompile
    #[error("Current committee error: {0:?}")]
    CurrentCommitteeError(CurrentCommitteeError),

    /// Error from the TIP-1091 ZoneFactory precompile
    #[error("ZoneFactory error: {0:?}")]
    ZoneFactoryError(ZoneFactoryError),

    /// Gas limit exceeded during precompile execution.
    #[error("Gas limit exceeded")]
    OutOfGas,

    /// Fatal EVM2 host or database error.
    #[error("Fatal EVM2 error: {0:?}")]
    #[from(skip)]
    EvmError(ErrorCode),

    /// The calldata's 4-byte selector does not match any known precompile function.
    #[error("Unknown function selector: {0:?}")]
    UnknownFunctionSelector([u8; 4]),

    /// Unrecoverable internal error (e.g. database failure).
    #[error("Fatal precompile error: {0:?}")]
    #[from(skip)]
    Fatal(String),
}

impl From<ErrorCode> for TempoPrecompileError {
    fn from(code: ErrorCode) -> Self {
        if code == ErrorCode::COLD_LOAD_SKIPPED {
            Self::OutOfGas
        } else {
            Self::EvmError(code)
        }
    }
}

/// Result type alias for Tempo precompile operations
pub type Result<T> = std::result::Result<T, TempoPrecompileError>;

impl TempoPrecompileError {
    /// Returns this error's ABI selector. For those variants which can't be encoded as a selector, it returns `FixedBytes<4>::ZERO`.
    pub fn selector(&self) -> FixedBytes<4> {
        match self {
            Self::StablecoinDEX(e) => e.selector(),
            Self::TIP20(e) => e.selector(),
            Self::TIP20ChannelReserveError(e) => e.selector(),
            Self::NonceError(e) => e.selector(),
            Self::TIP20Factory(e) => e.selector(),
            Self::RolesAuthError(e) => e.selector(),
            Self::AddrRegistryError(e) => e.selector(),
            Self::TIPFeeAMMError(e) => e.selector(),
            Self::FeeManagerError(e) => e.selector(),
            Self::TIP403RegistryError(e) => e.selector(),
            Self::ValidatorConfigError(e) => e.selector(),
            Self::ValidatorConfigV2Error(e) => e.selector(),
            Self::AccountKeychainError(e) => e.selector(),
            Self::SignatureVerifierError(e) => e.selector(),
            Self::ReceivePolicyGuardError(e) => e.selector(),
            Self::StorageCreditsError(e) => e.selector(),
            Self::CurrentCommitteeError(e) => e.selector(),
            Self::ZoneFactoryError(e) => e.selector(),
            Self::UnknownFunctionSelector(selector) => *selector,
            Self::Panic(_) | Self::StorageDeltaUnderflow(_) => Panic::SELECTOR,
            Self::OutOfGas | Self::EvmError(_) | Self::Fatal(_) => [0, 0, 0, 0],
        }
        .into()
    }

    /// Returns true if this error represents a system-level failure that must be propagated
    /// rather than swallowed, because state may be inconsistent.
    pub fn is_system_error(&self) -> bool {
        match self {
            Self::OutOfGas
            | Self::EvmError(_)
            | Self::Fatal(_)
            | Self::Panic(_)
            | Self::StorageDeltaUnderflow(_) => true,
            Self::StablecoinDEX(_)
            | Self::TIP20(_)
            | Self::TIP20ChannelReserveError(_)
            | Self::NonceError(_)
            | Self::TIP20Factory(_)
            | Self::RolesAuthError(_)
            | Self::AddrRegistryError(_)
            | Self::TIPFeeAMMError(_)
            | Self::FeeManagerError(_)
            | Self::TIP403RegistryError(_)
            | Self::ValidatorConfigError(_)
            | Self::ValidatorConfigV2Error(_)
            | Self::AccountKeychainError(_)
            | Self::SignatureVerifierError(_)
            | Self::ReceivePolicyGuardError(_)
            | Self::StorageCreditsError(_)
            | Self::CurrentCommitteeError(_)
            | Self::ZoneFactoryError(_)
            | Self::UnknownFunctionSelector(_) => false,
        }
    }

    /// Creates an arithmetic under/overflow panic error.
    pub fn under_overflow() -> Self {
        Self::Panic(PanicKind::UnderOverflow)
    }

    /// Creates a storage delta underflow that carries the current slot value.
    pub fn storage_delta_underflow(current: U256) -> Self {
        Self::StorageDeltaUnderflow(current)
    }

    /// Creates an enum conversion error panic (Solidity Panic `0x21`).
    pub fn enum_conversion_error() -> Self {
        Self::Panic(PanicKind::EnumConversionError)
    }

    /// Creates an array out-of-bounds panic error.
    pub fn array_oob() -> Self {
        Self::Panic(PanicKind::ArrayOutOfBounds)
    }

    /// Converts this error into EVM2's native precompile result.
    pub fn into_precompile_result(self) -> PrecompileResult {
        let bytes = match self {
            Self::StablecoinDEX(e) => e.abi_encode().into(),
            Self::TIP20(e) => e.abi_encode().into(),
            Self::TIP20Factory(e) => e.abi_encode().into(),
            Self::TIP20ChannelReserveError(e) => e.abi_encode().into(),
            Self::RolesAuthError(e) => e.abi_encode().into(),
            Self::AddrRegistryError(e) => e.abi_encode().into(),
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
            Self::StorageDeltaUnderflow(_) => {
                let panic = Panic {
                    code: U256::from(PanicKind::UnderOverflow as u32),
                };

                panic.abi_encode().into()
            }
            Self::ValidatorConfigError(e) => e.abi_encode().into(),
            Self::ValidatorConfigV2Error(e) => e.abi_encode().into(),
            Self::AccountKeychainError(e) => e.abi_encode().into(),
            Self::SignatureVerifierError(e) => e.abi_encode().into(),
            Self::ReceivePolicyGuardError(e) => e.abi_encode().into(),
            Self::StorageCreditsError(e) => e.abi_encode().into(),
            Self::CurrentCommitteeError(e) => e.abi_encode().into(),
            Self::ZoneFactoryError(e) => e.abi_encode().into(),
            Self::OutOfGas => {
                return Err(PrecompileHalt::OutOfGas.into());
            }
            Self::EvmError(code) => {
                return Err(format!("EVM2 database error {code:?}").into());
            }
            Self::UnknownFunctionSelector(selector) => UnknownFunctionSelector {
                selector: selector.into(),
            }
            .abi_encode()
            .into(),
            Self::Fatal(msg) => {
                return Err(msg.into());
            }
        };
        Err(PrecompileError::Revert(bytes))
    }
}

/// Registers all ABI error selectors for a [`SolInterface`] type into the decoder registry.
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

/// A decoded precompile error together with the raw revert bytes.
pub struct DecodedTempoPrecompileError<'a> {
    pub error: TempoPrecompileError,
    pub revert_bytes: &'a [u8],
}

/// Maps ABI error selectors to their decoder functions.
pub type TempoPrecompileErrorRegistry = HashMap<
    Selector,
    Box<dyn for<'a> Fn(&'a [u8]) -> Option<DecodedTempoPrecompileError<'a>> + Send + Sync>,
>;

/// Builds a [`TempoPrecompileErrorRegistry`] mapping every known error selector to its decoder.
pub fn error_decoder_registry() -> TempoPrecompileErrorRegistry {
    let mut registry: TempoPrecompileErrorRegistry = HashMap::new();

    add_errors_to_registry(&mut registry, TempoPrecompileError::StablecoinDEX);
    add_errors_to_registry(&mut registry, TempoPrecompileError::TIP20);
    add_errors_to_registry(&mut registry, TempoPrecompileError::TIP20Factory);
    add_errors_to_registry(
        &mut registry,
        TempoPrecompileError::TIP20ChannelReserveError,
    );
    add_errors_to_registry(&mut registry, TempoPrecompileError::RolesAuthError);
    add_errors_to_registry(&mut registry, TempoPrecompileError::AddrRegistryError);
    add_errors_to_registry(&mut registry, TempoPrecompileError::TIP403RegistryError);
    add_errors_to_registry(&mut registry, TempoPrecompileError::FeeManagerError);
    add_errors_to_registry(&mut registry, TempoPrecompileError::TIPFeeAMMError);
    add_errors_to_registry(&mut registry, TempoPrecompileError::NonceError);
    add_errors_to_registry(&mut registry, TempoPrecompileError::ValidatorConfigError);
    add_errors_to_registry(&mut registry, TempoPrecompileError::ValidatorConfigV2Error);
    add_errors_to_registry(&mut registry, TempoPrecompileError::AccountKeychainError);
    add_errors_to_registry(&mut registry, TempoPrecompileError::SignatureVerifierError);
    add_errors_to_registry(&mut registry, TempoPrecompileError::ReceivePolicyGuardError);
    add_errors_to_registry(&mut registry, TempoPrecompileError::StorageCreditsError);
    add_errors_to_registry(&mut registry, TempoPrecompileError::CurrentCommitteeError);
    add_errors_to_registry(&mut registry, TempoPrecompileError::ZoneFactoryError);

    registry
}

/// Global lazily-initialized registry of all Tempo precompile error decoders.
pub static ERROR_REGISTRY: LazyLock<TempoPrecompileErrorRegistry> =
    LazyLock::new(error_decoder_registry);

/// Decodes raw revert bytes into a typed [`DecodedTempoPrecompileError`] using the global
/// [`ERROR_REGISTRY`], returning `None` if the data is shorter than 4 bytes or the selector
/// is unrecognized.
pub fn decode_error<'a>(data: &'a [u8]) -> Option<DecodedTempoPrecompileError<'a>> {
    if data.len() < 4 {
        return None;
    }

    let selector: [u8; 4] = data[0..4].try_into().ok()?;
    ERROR_REGISTRY
        .get(&selector)
        .and_then(|decoder| decoder(data))
}

/// Extension trait to convert an error into a [`PrecompileResult`].
pub trait IntoPrecompileResult {
    /// Converts `self` into a [`PrecompileResult`].
    fn into_precompile_result(self) -> PrecompileResult;
}

impl<E: Into<TempoPrecompileError>> IntoPrecompileResult for E {
    #[inline]
    fn into_precompile_result(self) -> PrecompileResult {
        self.into().into_precompile_result()
    }
}

/// Extension trait to convert a [`Result`](core::result::Result) into a [`PrecompileResult`].
pub trait EncodePrecompileResult<T> {
    /// Converts `self` into a [`PrecompileResult`], using `encode_ok` for the success path.
    fn encode_precompile_result(
        self,
        encode_ok: impl FnOnce(T) -> alloy::primitives::Bytes,
    ) -> PrecompileResult;
}

impl<T, E> EncodePrecompileResult<T> for core::result::Result<T, E>
where
    E: IntoPrecompileResult,
{
    fn encode_precompile_result(
        self,
        encode_ok: impl FnOnce(T) -> alloy::primitives::Bytes,
    ) -> PrecompileResult {
        match self {
            Ok(res) => Ok(PrecompileOutput::new(encode_ok(res))),
            Err(err) => err.into_precompile_result(),
        }
    }
}

impl StorageCreditsErr for TempoPrecompileError {
    fn out_of_gas() -> Self {
        Self::OutOfGas
    }

    fn fatal_external() -> Self {
        Self::Fatal("invalid storage credits state".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempo_contracts::precompiles::StablecoinDEXError;

    #[test]
    fn evm2_state_errors_match_storage_load_semantics() {
        assert_eq!(
            TempoPrecompileError::from(ErrorCode::COLD_LOAD_SKIPPED),
            TempoPrecompileError::OutOfGas
        );
        assert_eq!(
            TempoPrecompileError::from(ErrorCode::BAL_NOT_COVERED),
            TempoPrecompileError::EvmError(ErrorCode::BAL_NOT_COVERED)
        );
    }

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
    fn test_into_precompile_result_revert() {
        let error = TempoPrecompileError::StablecoinDEX(StablecoinDEXError::order_does_not_exist());
        let result = error.into_precompile_result();
        assert!(matches!(result, Err(PrecompileError::Revert(_))));
    }

    #[test]
    fn test_encode_precompile_result_trait_success() {
        let result: Result<u64> = Ok(42);
        let precompile_result = result.encode_precompile_result(|val| {
            alloy::primitives::Bytes::from(val.to_be_bytes().to_vec())
        });

        assert!(precompile_result.is_ok());
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
