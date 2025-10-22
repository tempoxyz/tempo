//! Tempo precompile implementations.
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub mod linking_usd;
pub mod nonce;
pub mod provider;
pub mod stablecoin_exchange;
pub mod storage;
pub mod tip20;
pub mod tip20_factory;
pub mod tip403_registry;
pub mod tip4217_registry;
pub mod tip_account_registrar;
pub mod tip_fee_manager;

use crate::{
    linking_usd::LinkingUSD,
    nonce::NonceManager,
    stablecoin_exchange::StablecoinExchange,
    storage::evm::EvmPrecompileStorageProvider,
    tip_account_registrar::TipAccountRegistrar,
    tip_fee_manager::TipFeeManager,
    tip20::{TIP20Token, address_to_token_id_unchecked, is_tip20},
    tip20_factory::TIP20Factory,
    tip403_registry::TIP403Registry,
    tip4217_registry::TIP4217Registry,
};
use alloy::{
    primitives::{Address, Bytes, address},
    sol,
    sol_types::{SolCall, SolError, SolInterface},
};
use alloy_evm::precompiles::{DynPrecompile, PrecompilesMap};
use revm::{
    context::Block,
    precompile::{PrecompileId, PrecompileOutput, PrecompileResult},
};

pub const TIP_FEE_MANAGER_ADDRESS: Address = address!("0xfeec000000000000000000000000000000000000");
pub const LINKING_USD_ADDRESS: Address = address!("0x20C0000000000000000000000000000000000000");
pub const DEFAULT_FEE_TOKEN: Address = address!("0x20C0000000000000000000000000000000000001");
pub const TIP403_REGISTRY_ADDRESS: Address = address!("0x403C000000000000000000000000000000000000");
pub const TIP20_FACTORY_ADDRESS: Address = address!("0x20FC000000000000000000000000000000000000");
pub const TIP4217_REGISTRY_ADDRESS: Address =
    address!("0x4217C00000000000000000000000000000000000");
pub const TIP_ACCOUNT_REGISTRAR: Address = address!("0x7702ac0000000000000000000000000000000000");
pub const STABLECOIN_EXCHANGE_ADDRESS: Address =
    address!("0xdec0000000000000000000000000000000000000");
pub const NONCE_PRECOMPILE_ADDRESS: Address =
    address!("0x4E4F4E4345000000000000000000000000000000");

const METADATA_GAS: u64 = 50;
const VIEW_FUNC_GAS: u64 = 100;
const MUTATE_FUNC_GAS: u64 = 1000;

pub trait Precompile {
    fn call(&mut self, calldata: &[u8], msg_sender: &Address) -> PrecompileResult;
}

pub fn extend_tempo_precompiles(precompiles: &mut PrecompilesMap, chain_id: u64) {
    precompiles.set_precompile_lookup(move |address: &Address| {
        if is_tip20(address) {
            let token_id = address_to_token_id_unchecked(address);
            if token_id == 0 {
                Some(LinkingUSDPrecompile::create(chain_id))
            } else {
                Some(TIP20Precompile::create(address, chain_id))
            }
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
        } else if *address == STABLECOIN_EXCHANGE_ADDRESS {
            Some(StablecoinExchangePrecompile::create(chain_id))
        } else if *address == NONCE_PRECOMPILE_ADDRESS {
            Some(NoncePrecompile::create(chain_id))
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

pub struct TipAccountRegistrarPrecompile;
impl TipAccountRegistrarPrecompile {
    pub fn create(chain_id: u64) -> DynPrecompile {
        tempo_precompile!("TipAccountRegistrar", |input| TipAccountRegistrar::new(
            &mut crate::storage::evm::EvmPrecompileStorageProvider::new(input.internals, chain_id),
        ))
    }
}

pub struct TIP4217RegistryPrecompile;
impl TIP4217RegistryPrecompile {
    pub fn create() -> DynPrecompile {
        tempo_precompile!("TIP4217Registry", |input| TIP4217Registry::default())
    }
}

pub struct TIP403RegistryPrecompile;
impl TIP403RegistryPrecompile {
    pub fn create(chain_id: u64) -> DynPrecompile {
        tempo_precompile!("TIP403Registry", |input| TIP403Registry::new(
            &mut crate::storage::evm::EvmPrecompileStorageProvider::new(input.internals, chain_id),
        ))
    }
}

pub struct TIP20FactoryPrecompile;
impl TIP20FactoryPrecompile {
    pub fn create(chain_id: u64) -> DynPrecompile {
        tempo_precompile!("TIP20Factory", |input| TIP20Factory::new(
            &mut EvmPrecompileStorageProvider::new(input.internals, chain_id)
        ))
    }
}

pub struct TIP20Precompile;
impl TIP20Precompile {
    pub fn create(address: &Address, chain_id: u64) -> DynPrecompile {
        let token_id = address_to_token_id_unchecked(address);
        tempo_precompile!("TIP20Token", |input| TIP20Token::new(
            token_id,
            &mut EvmPrecompileStorageProvider::new(input.internals, chain_id),
        ))
    }
}

pub struct StablecoinExchangePrecompile;
impl StablecoinExchangePrecompile {
    pub fn create(chain_id: u64) -> DynPrecompile {
        tempo_precompile!("StablecoinExchange", |input| StablecoinExchange::new(
            &mut EvmPrecompileStorageProvider::new(input.internals, chain_id)
        ))
    }
}

pub struct NoncePrecompile;
impl NoncePrecompile {
    pub fn create(chain_id: u64) -> DynPrecompile {
        tempo_precompile!("NonceManager", |input| NonceManager::new(
            &mut EvmPrecompileStorageProvider::new(input.internals, chain_id)
        ))
    }
}

pub struct LinkingUSDPrecompile;
impl LinkingUSDPrecompile {
    pub fn create(chain_id: u64) -> DynPrecompile {
        tempo_precompile!("LinkingUSD", |input| LinkingUSD::new(
            &mut EvmPrecompileStorageProvider::new(input.internals, chain_id),
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
    let Ok(call) = T::abi_decode(calldata) else {
        return Ok(PrecompileOutput::new_reverted(VIEW_FUNC_GAS, Bytes::new()));
    };
    Ok(PrecompileOutput::new(
        VIEW_FUNC_GAS,
        T::abi_encode_returns(&f(call)).into(),
    ))
}

// NOTE: Temporary fix to dispatch view functions that return results. This should be unified with
// `view` when precompiles are refactored
#[inline]
fn view_result<T: SolCall, E: SolInterface>(
    calldata: &[u8],
    f: impl FnOnce(T) -> Result<T::Return, E>,
) -> PrecompileResult {
    let Ok(call) = T::abi_decode(calldata) else {
        return Ok(PrecompileOutput::new_reverted(VIEW_FUNC_GAS, Bytes::new()));
    };
    match f(call) {
        Ok(result) => Ok(PrecompileOutput::new(
            VIEW_FUNC_GAS,
            T::abi_encode_returns(&result).into(),
        )),
        Err(e) => Ok(PrecompileOutput::new_reverted(
            VIEW_FUNC_GAS,
            E::abi_encode(&e).into(),
        )),
    }
}

#[inline]
pub fn mutate<T: SolCall, E: SolInterface>(
    calldata: &[u8],
    sender: &Address,
    f: impl FnOnce(&Address, T) -> Result<T::Return, E>,
) -> PrecompileResult {
    let Ok(call) = T::abi_decode(calldata) else {
        return Ok(PrecompileOutput::new_reverted(
            MUTATE_FUNC_GAS,
            Bytes::new(),
        ));
    };
    match f(sender, call) {
        Ok(result) => Ok(PrecompileOutput::new(
            MUTATE_FUNC_GAS,
            T::abi_encode_returns(&result).into(),
        )),
        Err(e) => Ok(PrecompileOutput::new_reverted(
            MUTATE_FUNC_GAS,
            E::abi_encode(&e).into(),
        )),
    }
}

#[inline]
fn mutate_void<T: SolCall, E: SolInterface>(
    calldata: &[u8],
    sender: &Address,
    f: impl FnOnce(&Address, T) -> Result<(), E>,
) -> PrecompileResult {
    let Ok(call) = T::abi_decode(calldata) else {
        return Ok(PrecompileOutput::new_reverted(
            MUTATE_FUNC_GAS,
            Bytes::new(),
        ));
    };
    match f(sender, call) {
        Ok(()) => Ok(PrecompileOutput::new(MUTATE_FUNC_GAS, Bytes::new())),
        Err(e) => Ok(PrecompileOutput::new_reverted(
            MUTATE_FUNC_GAS,
            E::abi_encode(&e).into(),
        )),
    }
}

#[cfg(test)]
pub fn expect_precompile_revert<E>(result: &PrecompileResult, expected_error: E)
where
    E: SolInterface + PartialEq + std::fmt::Debug,
{
    match result {
        Ok(result) => {
            assert!(result.reverted);
            let decoded = E::abi_decode(&result.bytes).unwrap();
            assert_eq!(decoded, expected_error);
        }
        Err(other) => {
            panic!("expected reverted output, got: {other:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{storage::evm::EvmPrecompileStorageProvider, tip20::TIP20Token};
    use alloy::primitives::{Address, Bytes, U256};
    use alloy_evm::{
        EthEvmFactory, EvmEnv, EvmFactory, EvmInternals,
        precompiles::{Precompile as AlloyEvmPrecompile, PrecompileInput},
    };
    use revm::{
        context::ContextTr,
        database::{CacheDB, EmptyDB},
    };

    #[test]
    fn test_precompile_delegatecall() {
        let precompile = tempo_precompile!("TIP20Token", |input| TIP20Token::new(
            1,
            &mut EvmPrecompileStorageProvider::new(input.internals, 1),
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
