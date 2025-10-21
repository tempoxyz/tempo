pub mod dispatch;

use alloy_evm::precompiles::DynPrecompile;
use crate::{
    TIP_FEE_MANAGER_ADDRESS,
    contracts::{EvmPrecompileStorageProvider, tip_fee_manager::TipFeeManager},
    precompiles::tempo_precompile,
};

pub struct TipFeeManagerPrecompile;

impl TipFeeManagerPrecompile {
    pub fn create(chain_id: u64) -> DynPrecompile {
        tempo_precompile!("TipFeeManager", |input| TipFeeManager::new(
            TIP_FEE_MANAGER_ADDRESS,
            input.internals.block_env().beneficiary(),
            &mut EvmPrecompileStorageProvider::new(input.internals, chain_id)
        ))
    }
}
