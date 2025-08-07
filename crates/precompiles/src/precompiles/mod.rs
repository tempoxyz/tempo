use alloy::primitives::Address;
use reth::revm::{
    Inspector,
    precompile::{PrecompileError, PrecompileOutput, PrecompileResult},
    primitives::hardfork::SpecId,
};
use reth_evm::{
    Database, EthEvm, Evm,
    eth::EthEvmContext,
    precompiles::{DynPrecompile, PrecompilesMap},
};

pub mod tip20;
pub mod tip20_factory;
pub mod tip403_registry;

use crate::contracts::{
    EvmStorageProvider, TIP20_FACTORY_ADDRESS, TIP20Factory, TIP20Token, TIP403_REGISTRY_ADDRESS,
    TIP403Registry, address_is_token_address, address_to_token_id_unchecked,
};

const METADATA_GAS: u64 = 50;
const VIEW_FUNC_GAS: u64 = 100;
const MUTATE_FUNC_GAS: u64 = 1000;

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
                Some(TIP20Precompile::create(address, chain_id))
            } else if *address == TIP20_FACTORY_ADDRESS {
                Some(TIP20FactoryPrecompile::create(chain_id))
            } else if *address == TIP403_REGISTRY_ADDRESS {
                Some(TIP403RegistryPrecompile::create(chain_id))
            } else {
                None
            }
        });
    }
}

pub struct TIP20Precompile;
impl TIP20Precompile {
    pub fn create(address: &Address, chain_id: u64) -> DynPrecompile {
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
    pub fn create(chain_id: u64) -> DynPrecompile {
        DynPrecompile::new(move |input| {
            TIP20Factory::new(&mut EvmStorageProvider::new(input.internals, chain_id))
                .call(input.data, &input.caller)
        })
    }
}

pub struct TIP403RegistryPrecompile;

impl TIP403RegistryPrecompile {
    pub fn create(chain_id: u64) -> DynPrecompile {
        DynPrecompile::new(move |input| {
            TIP403Registry::new(&mut EvmStorageProvider::new(input.internals, chain_id))
                .call(input.data, &input.caller)
        })
    }
}

#[inline]
fn metadata<T: alloy::sol_types::SolCall>(result: T::Return) -> PrecompileResult {
    Ok(PrecompileOutput::new(
        METADATA_GAS,
        T::abi_encode_returns(&result).into(),
    ))
}

#[inline]
fn view<T: alloy::sol_types::SolCall>(
    calldata: &[u8],
    f: impl FnOnce(T) -> T::Return,
) -> PrecompileResult {
    let call = T::abi_decode(calldata)
        .map_err(|e| PrecompileError::Other(format!("Failed to decode input: {e}")))?;
    Ok(PrecompileOutput::new(
        VIEW_FUNC_GAS,
        T::abi_encode_returns(&f(call)).into(),
    ))
}

#[inline]
fn mutate<T: alloy::sol_types::SolCall, E: alloy::sol_types::SolInterface>(
    calldata: &[u8],
    sender: &Address,
    f: impl FnOnce(&Address, T) -> Result<T::Return, E>,
) -> PrecompileResult {
    let call = T::abi_decode(calldata)
        .map_err(|e| PrecompileError::Other(format!("Failed to decode input: {e}")))?;
    match f(sender, call) {
        Ok(result) => Ok(PrecompileOutput::new(
            MUTATE_FUNC_GAS,
            T::abi_encode_returns(&result).into(),
        )),
        Err(e) => Err(PrecompileError::Other(
            E::abi_encode(&e)
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect(),
        )),
    }
}

#[inline]
fn mutate_void<T: alloy::sol_types::SolCall, E: alloy::sol_types::SolInterface>(
    calldata: &[u8],
    sender: &Address,
    f: impl FnOnce(&Address, T) -> Result<(), E>,
) -> PrecompileResult {
    let call = T::abi_decode(calldata)
        .map_err(|e| PrecompileError::Other(format!("Failed to decode input: {e}")))?;
    match f(sender, call) {
        Ok(()) => Ok(PrecompileOutput::new(
            MUTATE_FUNC_GAS,
            alloy_primitives::Bytes::new(),
        )),
        Err(e) => Err(PrecompileError::Other(
            E::abi_encode(&e)
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect(),
        )),
    }
}
