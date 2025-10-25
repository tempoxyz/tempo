use crate::tip20::TIP20Error;
use alloy::{primitives::Bytes, sol_types::SolInterface};
use tempo_contracts::precompiles::StablecoinExchangeError;

/// Top-level error type for all Tempo precompile operations
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TempoPrecompileError {
    /// Error from stablecoin exchange operations
    #[error("Stablecoin exchange error: {0:?}")]
    StablecoinExchange(StablecoinExchangeError),

    /// Error from TIP20 token operations
    #[error("TIP20 token error: {0:?}")]
    TIP20(TIP20Error),

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

impl TempoPrecompileError {
    pub fn abi_encode(&self) -> Bytes {
        match self {
            TempoPrecompileError::StablecoinExchange(err) => err.abi_encode().into(),
            TempoPrecompileError::TIP20(err) => err.abi_encode().into(),
        }
    }
}
