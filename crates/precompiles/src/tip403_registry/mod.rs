// Module for tip403_registry precompile
pub mod bindings;
pub mod bindings;
pub mod dispatch;

use alloy_evm::precompiles::DynPrecompile;
use crate::{
    contracts::{EvmPrecompileStorageProvider, TIP403Registry},
    precompiles::tempo_precompile,
};

pub struct TIP403RegistryPrecompile;

impl TIP403RegistryPrecompile {
    pub fn create(chain_id: u64) -> DynPrecompile {
        tempo_precompile!("TIP403Registry", |input| TIP403Registry::new(
            &mut EvmPrecompileStorageProvider::new(input.internals, chain_id)
        ))
    }
}
