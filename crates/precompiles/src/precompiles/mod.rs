use alloy::{
    primitives::Address,
    sol_types::{SolCall, SolInterface},
};
use alloy_primitives::Bytes;
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
pub mod tip4217_registry;

use crate::contracts::{
    EvmStorageProvider, TIP20_FACTORY_ADDRESS, TIP20Factory, TIP20Token, TIP403_REGISTRY_ADDRESS,
    TIP403Registry, TIP4217_REGISTRY_ADDRESS, TIP4217Registry, address_is_token_address,
    address_to_token_id_unchecked,
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
            } else if *address == TIP4217_REGISTRY_ADDRESS {
                Some(TIP4217RegistryPrecompile::create())
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

pub struct TIP4217RegistryPrecompile;

impl TIP4217RegistryPrecompile {
    pub fn create() -> DynPrecompile {
        DynPrecompile::new(move |input| TIP4217Registry::default().call(input.data, &input.caller))
    }
}

#[inline]
fn metadata<T: SolCall>(result: T::Return) -> PrecompileResult {
    Ok(PrecompileOutput::new(
        METADATA_GAS,
        T::abi_encode_returns(&result).into(),
    ))
}

#[inline]
fn view<T: SolCall>(calldata: &[u8], f: impl FnOnce(T) -> T::Return) -> PrecompileResult {
    let call = T::abi_decode(calldata)
        .map_err(|e| PrecompileError::Other(format!("Failed to decode input: {e}")))?;
    Ok(PrecompileOutput::new(
        VIEW_FUNC_GAS,
        T::abi_encode_returns(&f(call)).into(),
    ))
}

#[inline]
fn mutate<T: SolCall, E: SolInterface>(
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
                .map(|b| format!("{b:02x}"))
                .collect(),
        )),
    }
}

#[inline]
fn mutate_void<T: SolCall, E: SolInterface>(
    calldata: &[u8],
    sender: &Address,
    f: impl FnOnce(&Address, T) -> Result<(), E>,
) -> PrecompileResult {
    let call = T::abi_decode(calldata)
        .map_err(|e| PrecompileError::Other(format!("Failed to decode input: {e}")))?;
    match f(sender, call) {
        Ok(()) => Ok(PrecompileOutput::new(MUTATE_FUNC_GAS, Bytes::new())),
        Err(e) => Err(PrecompileError::Other(
            E::abi_encode(&e)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        )),
    }
}

#[cfg(test)]
pub fn expect_precompile_error<E>(result: &PrecompileResult, expected_error: E)
where
    E: SolInterface + PartialEq + Debug,
{
    match result {
        Err(PrecompileError::Other(hex_string)) => {
            let bytes =
                hex::decode(hex_string).expect("invalid hex string in PrecompileError::Other");
            let decoded: E = E::abi_decode(&bytes)
                .expect("failed to decode precompile error as expected interface error");
            assert_eq!(decoded, expected_error);
        }
        Ok(_) => panic!("expected error, got Ok result"),
        Err(other) => panic!("expected encoded interface error, got: {:?}", other),
    }
}
