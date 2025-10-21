// Module for tip4217_registry precompile
pub mod bindings;
pub mod dispatch;

use alloy_evm::precompiles::DynPrecompile;
use crate::{
    contracts::TIP4217Registry,
    precompiles::tempo_precompile,
};

pub struct TIP4217RegistryPrecompile;

impl TIP4217RegistryPrecompile {
    pub fn create() -> DynPrecompile {
        tempo_precompile!("TIP4217Registry", |input| TIP4217Registry::default())
    }
}
