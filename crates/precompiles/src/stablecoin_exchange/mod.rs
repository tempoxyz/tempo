// Module for stablecoin_exchange precompile
pub mod dispatch;

use alloy_evm::precompiles::DynPrecompile;
use crate::{
    contracts::{EvmPrecompileStorageProvider, StablecoinExchange},
    precompiles::tempo_precompile,
};

pub struct StablecoinExchangePrecompile;

impl StablecoinExchangePrecompile {
    pub fn create(chain_id: u64) -> DynPrecompile {
        tempo_precompile!("StablecoinExchange", |input| StablecoinExchange::new(
            &mut EvmPrecompileStorageProvider::new(input.internals, chain_id)
        ))
    }
}
