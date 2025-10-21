// Module for tip20_factory precompile
pub mod dispatch;

use alloy_evm::precompiles::DynPrecompile;
use crate::{
    contracts::{EvmPrecompileStorageProvider, TIP20Factory},
    precompiles::tempo_precompile,
};

pub struct TIP20FactoryPrecompile;

impl TIP20FactoryPrecompile {
    pub fn create(chain_id: u64) -> DynPrecompile {
        tempo_precompile!("TIP20Factory", |input| TIP20Factory::new(
            &mut EvmPrecompileStorageProvider::new(input.internals, chain_id)
        ))
    }
}
