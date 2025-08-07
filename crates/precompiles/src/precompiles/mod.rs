use alloy::primitives::Address;
use reth::revm::{Inspector, precompile::PrecompileResult, primitives::hardfork::SpecId};
use reth_evm::{
    Database, EthEvm, Evm,
    eth::EthEvmContext,
    precompiles::{DynPrecompile, PrecompilesMap},
};

mod dispatch;
pub mod tip20;
pub mod tip20_factory;
pub mod tip403_registry;

use crate::contracts::{
    EvmStorageProvider, TIP20Factory, TIP20Token, TIP403Registry,
    utils::{
        FACTORY_ADDRESS, TIP403_REGISTRY_ADDRESS, address_is_token_address,
        address_to_token_id_unchecked,
    },
};

pub trait Precompile {
    fn call(&mut self, calldata: &[u8], msg_sender: &Address) -> PrecompileResult;
}

pub fn extend_tempo_precompiles<DB: Database, I: Inspector<EthEvmContext<DB>>>(
    evm: &mut EthEvm<DB, I, PrecompilesMap>,
) {
    if evm.cfg.spec >= SpecId::PRAGUE {
        let chain_id = evm.cfg.chain_id;
        let precompiles = evm.precompiles_mut();
        precompiles.set_precompile_lookup(move |address: &Address| {
            if address_is_token_address(address) {
                Some(TIP20Precompile::new(address, chain_id))
            } else if *address == FACTORY_ADDRESS {
                Some(TIP20FactoryPrecompile::new(chain_id))
            } else if *address == TIP403_REGISTRY_ADDRESS {
                Some(TIP403RegistryPrecompile::new(chain_id))
            } else {
                None
            }
        });
    }
}

pub struct TIP20Precompile;
impl TIP20Precompile {
    pub fn new(address: &Address, chain_id: u64) -> DynPrecompile {
        let token_id = address_to_token_id_unchecked(address);
        DynPrecompile::new(move |input| {
            TIP20Token::new(
                token_id,
                &mut EvmStorageProvider::new(input.internals, chain_id),
            )
            .call(input.data, &input.caller)
        })
    }
}

pub struct TIP20FactoryPrecompile;

impl TIP20FactoryPrecompile {
    pub fn new(chain_id: u64) -> DynPrecompile {
        DynPrecompile::new(move |input| {
            TIP20Factory::new(&mut EvmStorageProvider::new(input.internals, chain_id))
                .call(input.data, &input.caller)
        })
    }
}

pub struct TIP403RegistryPrecompile;

impl TIP403RegistryPrecompile {
    pub fn new(chain_id: u64) -> DynPrecompile {
        DynPrecompile::new(move |input| {
            TIP403Registry::new(&mut EvmStorageProvider::new(input.internals, chain_id))
                .call(input.data, &input.caller)
        })
    }
}
