pub mod dispatch;

use alloy_evm::precompiles::DynPrecompile;
use crate::{
    contracts::{EvmPrecompileStorageProvider, NonceManager},
    precompiles::tempo_precompile,
};

pub struct NoncePrecompile;

impl NoncePrecompile {
    pub fn create(chain_id: u64) -> DynPrecompile {
        tempo_precompile!("NonceManager", |input| NonceManager::new(
            &mut EvmPrecompileStorageProvider::new(input.internals, chain_id)
        ))
    }
}
