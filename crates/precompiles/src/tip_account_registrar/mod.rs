// Module for tip_account_registrar precompile
pub mod bindings;
pub mod dispatch;

use alloy_evm::precompiles::DynPrecompile;
use crate::{
    contracts::{EvmPrecompileStorageProvider, TipAccountRegistrar},
    precompiles::tempo_precompile,
};

pub struct TipAccountRegistrarPrecompile;

impl TipAccountRegistrarPrecompile {
    pub fn create(chain_id: u64) -> DynPrecompile {
        tempo_precompile!("TipAccountRegistrar", |input| TipAccountRegistrar::new(
            &mut EvmPrecompileStorageProvider::new(input.internals, chain_id)
        ))
    }
}
