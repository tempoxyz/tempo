pub mod dispatch;

use alloy_evm::precompiles::DynPrecompile;
use revm::precompile::PrecompileId;
use crate::{
    contracts::{EvmPrecompileStorageProvider, LinkingUSD},
    precompiles::tempo_precompile,
};

pub struct LinkingUSDPrecompile;
impl LinkingUSDPrecompile {
    pub fn create(chain_id: u64) -> DynPrecompile {
        tempo_precompile!("LinkingUSD", |input| LinkingUSD::new(
            &mut EvmPrecompileStorageProvider::new(input.internals, chain_id),
        ))
    }
}
