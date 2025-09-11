use alloy::{
    primitives::Address,
    sol,
    sol_types::{SolCall, SolError, SolInterface},
};
use alloy_primitives::Bytes;
use reth_evm::{
    precompiles::{DynPrecompile, PrecompilesMap},
    revm::precompile::{PrecompileError, PrecompileId, PrecompileOutput, PrecompileResult},
};

pub mod tip20;
pub mod tip20_factory;
pub mod tip403_registry;
pub mod tip4217_registry;
pub mod tip_account_registrar;
pub mod tip_fee_manager;

use crate::{
    TIP_ACCOUNT_REGISTRAR, TIP_FEE_MANAGER_ADDRESS, TIP20_FACTORY_ADDRESS, TIP403_REGISTRY_ADDRESS,
    TIP4217_REGISTRY_ADDRESS,
    contracts::{
        EvmStorageProvider, TIP20Factory, TIP20Token, TIP403Registry, TIP4217Registry,
        TipAccountRegistrar, address_is_token_address, address_to_token_id_unchecked,
        tip_fee_manager::TipFeeManager,
    },
};

const METADATA_GAS: u64 = 50;
const VIEW_FUNC_GAS: u64 = 100;
const MUTATE_FUNC_GAS: u64 = 1000;

pub trait Precompile {
    fn call(&mut self, calldata: &[u8], msg_sender: &Address) -> PrecompileResult;
}

pub fn extend_tempo_precompiles(precompiles: &mut PrecompilesMap, chain_id: u64) {
    precompiles.set_precompile_lookup(move |address: &Address| {
        if address_is_token_address(address) {
            Some(TIP20Precompile::create(address, chain_id))
        } else if *address == TIP20_FACTORY_ADDRESS {
            Some(TIP20FactoryPrecompile::create(chain_id))
        } else if *address == TIP403_REGISTRY_ADDRESS {
            Some(TIP403RegistryPrecompile::create(chain_id))
        } else if *address == TIP4217_REGISTRY_ADDRESS {
            Some(TIP4217RegistryPrecompile::create())
        } else if *address == TIP_FEE_MANAGER_ADDRESS {
            Some(TipFeeManagerPrecompile::create(chain_id))
        } else if *address == TIP_ACCOUNT_REGISTRAR {
            Some(TipAccountRegistrarPrecompile::create(chain_id))
        } else {
            None
        }
    });
}

sol! {
    error DelegateCallNotAllowed();
}

macro_rules! tempo_precompile {
    ($id:expr, |$input:ident| $impl:expr) => {
        DynPrecompile::new_stateful(PrecompileId::Custom($id.into()), move |$input| {
            if !$input.is_direct_call() {
                return Ok(PrecompileOutput::new_reverted(
                    0,
                    DelegateCallNotAllowed {}.abi_encode().into(),
                ));
            }
            $impl.call($input.data, &$input.caller)
        })
    };
}

pub struct TIP20Precompile;
impl TIP20Precompile {
    pub fn create(address: &Address, chain_id: u64) -> DynPrecompile {
        let token_id = address_to_token_id_unchecked(address);
        tempo_precompile!("TIP20Token", |input| TIP20Token::new(
            token_id,
            &mut EvmStorageProvider::new(input.internals, chain_id),
        ))
    }
}

pub struct TIP20FactoryPrecompile;

impl TIP20FactoryPrecompile {
    pub fn create(chain_id: u64) -> DynPrecompile {
        tempo_precompile!("TIP20Factory", |input| TIP20Factory::new(
            &mut EvmStorageProvider::new(input.internals, chain_id)
        ))
    }
}

pub struct TIP403RegistryPrecompile;

impl TIP403RegistryPrecompile {
    pub fn create(chain_id: u64) -> DynPrecompile {
        tempo_precompile!("TIP403Registry", |input| TIP403Registry::new(
            &mut EvmStorageProvider::new(input.internals, chain_id)
        ))
    }
}

pub struct TIP4217RegistryPrecompile;

impl TIP4217RegistryPrecompile {
    pub fn create() -> DynPrecompile {
        tempo_precompile!("TIP4217Registry", |input| TIP4217Registry::default())
    }
}

pub struct TipFeeManagerPrecompile;

impl TipFeeManagerPrecompile {
    pub fn create(chain_id: u64) -> DynPrecompile {
        tempo_precompile!("TipFeeManager", |input| TipFeeManager::new(
            TIP_FEE_MANAGER_ADDRESS,
            &mut EvmStorageProvider::new(input.internals, chain_id)
        ))
    }
}

pub struct TipAccountRegistrarPrecompile;

impl TipAccountRegistrarPrecompile {
    pub fn create(chain_id: u64) -> DynPrecompile {
        tempo_precompile!("TipAccountRegistrar", |input| TipAccountRegistrar::new(
            &mut EvmStorageProvider::new(input.internals, chain_id)
        ))
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
pub fn mutate<T: SolCall, E: SolInterface>(
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
    E: SolInterface + PartialEq + std::fmt::Debug,
{
    match result {
        Err(PrecompileError::Other(hex_string)) => {
            let bytes = alloy_primitives::hex::decode(hex_string)
                .expect("invalid hex string in PrecompileError::Other");
            let decoded: E = E::abi_decode(&bytes)
                .expect("failed to decode precompile error as expected interface error");
            assert_eq!(decoded, expected_error);
        }
        Ok(_) => panic!("expected error, got Ok result"),
        Err(other) => panic!("expected encoded interface error, got: {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precompiles::Precompile;
    use alloy_evm::{EthEvmFactory, EvmEnv, EvmFactory, EvmInternals};
    use alloy_primitives::{Address, Bytes, U256};
    use reth_evm::{
        precompiles::{Precompile as AlloyEvmPrecompile, PrecompileInput},
        revm::{
            context::ContextTr,
            database::{CacheDB, EmptyDB},
        },
    };

    #[test]
    fn test_precompile_delegatecall() {
        let precompile = tempo_precompile!("TIP20Token", |input| TIP20Token::new(
            1,
            &mut EvmStorageProvider::new(input.internals, 1),
        ));

        let db = CacheDB::new(EmptyDB::new());
        let mut evm = EthEvmFactory::default().create_evm(db, EvmEnv::default());
        let block = evm.block.clone();
        let evm_internals = EvmInternals::new(evm.journal_mut(), &block);

        let target_address = Address::random();
        let bytecode_address = Address::random();
        let input = PrecompileInput {
            data: &Bytes::new(),
            caller: Address::ZERO,
            internals: evm_internals,
            gas: 0,
            value: U256::ZERO,
            target_address,
            bytecode_address,
        };

        let result = AlloyEvmPrecompile::call(&precompile, input);

        match result {
            Ok(output) => {
                assert!(output.reverted);
                let decoded = DelegateCallNotAllowed::abi_decode(&output.bytes).unwrap();
                assert!(matches!(decoded, DelegateCallNotAllowed {}));
            }
            Err(_) => panic!("expected reverted output"),
        }
    }
}
