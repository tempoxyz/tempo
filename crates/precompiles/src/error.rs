use std::{
    collections::HashMap,
    sync::{Arc, LazyLock},
};

use crate::abi::{
    account_keychain::IAccountKeychain, nonce::INonce, stablecoin_dex::IStablecoinDex,
    tip20::ITip20, tip20_factory::ITip20Factory, tip403_registry::ITip403Registry,
    tip_fee_manager::IFeeManager, validator_config::IValidatorConfig,
};
use alloy::{
    primitives::{Selector, U256},
    sol_types::{Panic, PanicKind, SolError, SolInterface},
};
use revm::precompile::{PrecompileError, PrecompileOutput, PrecompileResult};
use crate::contracts::UnknownFunctionSelector;

/// Top-level error type for all Tempo precompile operations
#[derive(
    Debug, Clone, PartialEq, Eq, thiserror::Error, derive_more::From, derive_more::TryInto,
)]
pub enum TempoPrecompileError {
    /// Stablecoin DEX error
    #[error("Stablecoin DEX error: {0:?}")]
    StablecoinDEX(IStablecoinDex::Error),

    /// Error from TIP20 token
    #[error("TIP20 token error: {0:?}")]
    TIP20(ITip20::Error),

    /// Error from TIP20 factory
    #[error("TIP20 factory error: {0:?}")]
    TIP20Factory(ITip20Factory::Error),

    /// Error from 403 registry
    #[error("TIP403 registry error: {0:?}")]
    TIP403Registry(ITip403Registry::Error),

    /// Error from TIP fee manager
    #[error("TIP fee manager error: {0:?}")]
    TipFeeManager(IFeeManager::Error),

    /// Error from Tempo Transaction nonce manager
    #[error("Tempo Transaction nonce error: {0:?}")]
    Nonce(INonce::Error),

    #[error("Panic({0:?})")]
    Panic(PanicKind),

    /// Error from validator config
    #[error("Validator config error: {0:?}")]
    ValidatorConfig(IValidatorConfig::Error),

    /// Error from account keychain precompile
    #[error("Account keychain error: {0:?}")]
    AccountKeychain(IAccountKeychain::Error),

    #[error("Gas limit exceeded")]
    OutOfGas,

    #[error("Unknown function selector: {0:?}")]
    UnknownFunctionSelector([u8; 4]),

    #[error("Fatal precompile error: {0:?}")]
    #[from(skip)]
    Fatal(String),
}

/// Result type alias for Tempo precompile operations
pub type Result<T> = std::result::Result<T, TempoPrecompileError>;

impl TempoPrecompileError {
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
            Self::TIP403Registry(e) => e.abi_encode().into(),
            Self::TipFeeManager(e) => e.abi_encode().into(),
            Self::Nonce(e) => e.abi_encode().into(),
            Self::Panic(kind) => {
                let panic = Panic {
                    code: U256::from(kind as u32),
                };

                panic.abi_encode().into()
            }
            Self::ValidatorConfig(e) => e.abi_encode().into(),
            Self::AccountKeychain(e) => e.abi_encode().into(),
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
    add_errors_to_registry(&mut registry, TempoPrecompileError::TIP403Registry);
    add_errors_to_registry(&mut registry, TempoPrecompileError::TipFeeManager);
    add_errors_to_registry(&mut registry, TempoPrecompileError::Nonce);
    add_errors_to_registry(&mut registry, TempoPrecompileError::ValidatorConfig);
    add_errors_to_registry(&mut registry, TempoPrecompileError::AccountKeychain);

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
