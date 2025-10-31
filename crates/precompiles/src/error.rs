use crate::tip20::TIP20Error;
use alloy::{
    primitives::U256,
    sol_types::{Panic, PanicKind, SolError, SolInterface},
};
use revm::precompile::{PrecompileError, PrecompileOutput, PrecompileResult};
use tempo_contracts::precompiles::{
    AccountKeychainError, FeeManagerError, NonceError, RolesAuthError, StablecoinExchangeError,
    TIP20RewardsRegistryError, TIP403RegistryError, TIPAccountRegistrarError, TIPFeeAMMError,
    UnknownFunctionSelector, ValidatorConfigError,
};

// TODO: add error type for overflow/underflow
/// Top-level error type for all Tempo precompile operations
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, derive_more::From)]
pub enum TempoPrecompileError {
    /// Error from stablecoin exchange
    #[error("Stablecoin exchange error: {0:?}")]
    StablecoinExchange(StablecoinExchangeError),

    /// Error from TIP20 token
    #[error("TIP20 token error: {0:?}")]
    TIP20(TIP20Error),

    /// Error from TIP20RewardsRegistry
    #[error("TIP20 rewards registry error: {0:?}")]
    TIP20RewardsRegistry(TIP20RewardsRegistryError),

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

    /// Error from TIP account registrar
    #[error("TIP account registrar error: {0:?}")]
    TIPAccountRegistrarError(TIPAccountRegistrarError),

    /// Error from native AA nonce manager
    #[error("Native AA nonce error: {0:?}")]
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

/// Result type alias for Tempo precompile operations
pub type Result<T> = std::result::Result<T, TempoPrecompileError>;

impl TempoPrecompileError {
    pub fn under_overflow() -> Self {
        Self::Panic(PanicKind::UnderOverflow)
    }
}

impl From<AccountKeychainError> for TempoPrecompileError {
    fn from(err: AccountKeychainError) -> Self {
        Self::AccountKeychainError(err)
    }
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
        use TempoPrecompileError as TPErr;

        match self {
            Ok(res) => Ok(PrecompileOutput::new(gas, encode_ok(res))),
            Err(err) => {
                let bytes = match err {
                    TPErr::StablecoinExchange(e) => e.abi_encode().into(),
                    TPErr::TIP20(e) => e.abi_encode().into(),
                    TPErr::TIP20RewardsRegistry(e) => e.abi_encode().into(),
                    TPErr::RolesAuthError(e) => e.abi_encode().into(),
                    TPErr::TIP403RegistryError(e) => e.abi_encode().into(),
                    TPErr::TIPAccountRegistrarError(e) => e.abi_encode().into(),
                    TPErr::FeeManagerError(e) => e.abi_encode().into(),
                    TPErr::TIPFeeAMMError(e) => e.abi_encode().into(),
                    TPErr::NonceError(e) => e.abi_encode().into(),
                    TPErr::Panic(kind) => {
                        let panic = Panic {
                            code: U256::from(kind as u32),
                        };

                        panic.abi_encode().into()
                    }
                    TPErr::ValidatorConfigError(e) => e.abi_encode().into(),
                    TPErr::AccountKeychainError(e) => e.abi_encode().into(),
                    TPErr::OutOfGas => {
                        return Err(PrecompileError::OutOfGas);
                    }
                    TPErr::UnknownFunctionSelector(selector) => UnknownFunctionSelector {
                        selector: selector.into(),
                    }
                    .abi_encode()
                    .into(),
                    TPErr::Fatal(msg) => {
                        return Err(PrecompileError::Fatal(msg));
                    }
                };
                Ok(PrecompileOutput::new_reverted(gas, bytes))
            }
        }
    }
}

impl<T> IntoPrecompileResult<T> for TempoPrecompileError {
    fn into_precompile_result(
        self,
        gas: u64,
        _encode_ok: impl FnOnce(T) -> alloy::primitives::Bytes,
    ) -> PrecompileResult {
        let bytes = match self {
            Self::StablecoinExchange(e) => e.abi_encode().into(),
            Self::TIP20(e) => e.abi_encode().into(),
            Self::TIP20RewardsRegistry(e) => e.abi_encode().into(),
            Self::RolesAuthError(e) => e.abi_encode().into(),
            Self::TIP403RegistryError(e) => e.abi_encode().into(),
            Self::TIPAccountRegistrarError(e) => e.abi_encode().into(),
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
