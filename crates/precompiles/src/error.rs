use crate::tip20::TIP20Error;
use alloy::{primitives::Bytes, sol_types::SolInterface};
use tempo_contracts::precompiles::{
    RolesAuthError, StablecoinExchangeError, TIP403RegistryError, TipAccountRegistrarError,
};

/// Top-level error type for all Tempo precompile operations
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TempoPrecompileError {
    /// Error from stablecoin exchange
    #[error("Stablecoin exchange error: {0:?}")]
    StablecoinExchange(StablecoinExchangeError),

    /// Error from TIP20 token
    #[error("TIP20 token error: {0:?}")]
    TIP20(TIP20Error),

    /// Error from roles auth
    #[error("Roles auth error: {0:?}")]
    RolesAuthError(RolesAuthError),

    /// Error from 403 registry
    #[error("Roles auth error: {0:?}")]
    TIP403RegistryError(TIP403RegistryError),

    /// Error from TIP account registrar
    #[error("TIP account registrar error: {0:?}")]
    TIPAccountRegistrarError(TipAccountRegistrarError),

    #[error("Fatal precompile error: {0:?}")]
    Fatal(String),
}

impl From<StablecoinExchangeError> for TempoPrecompileError {
    fn from(err: StablecoinExchangeError) -> Self {
        TempoPrecompileError::StablecoinExchange(err)
    }
}

impl From<TIP20Error> for TempoPrecompileError {
    fn from(err: TIP20Error) -> Self {
        TempoPrecompileError::TIP20(err)
    }
}

impl From<TIP403RegistryError> for TempoPrecompileError {
    fn from(err: TIP403RegistryError) -> Self {
        TempoPrecompileError::TIP403RegistryError(err)
    }
}

impl From<TipAccountRegistrarError> for TempoPrecompileError {
    fn from(err: TipAccountRegistrarError) -> Self {
        TempoPrecompileError::TIPAccountRegistrarError(err)
    }
}

impl TempoPrecompileError {
    pub fn abi_encode(&self) -> Bytes {
        match self {
            TempoPrecompileError::StablecoinExchange(err) => err.abi_encode().into(),
            TempoPrecompileError::TIP20(err) => err.abi_encode().into(),
            TempoPrecompileError::RolesAuthError(err) => err.abi_encode().into(),
            TempoPrecompileError::TIP403RegistryError(err) => err.abi_encode().into(),
            TempoPrecompileError::TIPAccountRegistrarError(err) => err.abi_encode().into(),
            TempoPrecompileError::Fatal(e) => {
                todo!()
            }
        }
    }
}
