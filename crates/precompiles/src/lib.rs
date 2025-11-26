//! Tempo precompile implementations.
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod error;
pub use error::Result;
use tempo_chainspec::hardfork::TempoHardfork;
pub mod account_keychain;
pub mod nonce;
pub mod path_usd;
pub mod stablecoin_exchange;
pub mod storage;
pub mod tip20;
pub mod tip20_factory;
pub mod tip20_rewards_registry;
pub mod tip403_registry;
pub mod tip_account_registrar;
pub mod tip_fee_manager;
pub mod validator_config;

#[cfg(test)]
pub mod test_util;

use crate::{
    account_keychain::AccountKeychain,
    nonce::NonceManager,
    path_usd::PathUSD,
    stablecoin_exchange::StablecoinExchange,
    storage::{PrecompileStorageProvider, evm::EvmPrecompileStorageProvider},
    tip_account_registrar::TipAccountRegistrar,
    tip_fee_manager::TipFeeManager,
    tip20::{TIP20Token, address_to_token_id_unchecked, is_tip20},
    tip20_factory::TIP20Factory,
    tip20_rewards_registry::TIP20RewardsRegistry,
    tip403_registry::TIP403Registry,
    validator_config::ValidatorConfig,
};
pub use error::IntoPrecompileResult;

#[cfg(test)]
use alloy::sol_types::SolInterface;
use alloy::{
    primitives::{Address, Bytes},
    sol,
    sol_types::{SolCall, SolError},
};
use alloy_evm::precompiles::{DynPrecompile, PrecompilesMap};
use revm::{
    context::CfgEnv,
    precompile::{PrecompileError, PrecompileId, PrecompileOutput, PrecompileResult},
};

pub use tempo_contracts::precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, DEFAULT_FEE_TOKEN_POST_ALLEGRETTO, DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO,
    NONCE_PRECOMPILE_ADDRESS, PATH_USD_ADDRESS, STABLECOIN_EXCHANGE_ADDRESS, TIP_ACCOUNT_REGISTRAR,
    TIP_FEE_MANAGER_ADDRESS, TIP20_FACTORY_ADDRESS, TIP20_REWARDS_REGISTRY_ADDRESS,
    TIP403_REGISTRY_ADDRESS, VALIDATOR_CONFIG_ADDRESS,
};

// Re-export storage layout helpers for read-only contexts (e.g., pool validation)
pub use account_keychain::{AuthorizedKey, compute_keys_slot};

/// Input per word cost. It covers abi decoding and cloning of input into call data.
///
/// Being careful and pricing it twice as COPY_COST to mitigate different abi decodings.
pub const INPUT_PER_WORD_COST: u64 = 6;

#[inline]
pub fn input_cost(calldata_len: usize) -> u64 {
    revm::interpreter::gas::cost_per_word(calldata_len, INPUT_PER_WORD_COST).unwrap_or(u64::MAX)
}

pub trait Precompile {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult;
}

pub fn extend_tempo_precompiles(precompiles: &mut PrecompilesMap, cfg: &CfgEnv<TempoHardfork>) {
    let chain_id = cfg.chain_id;
    let spec = cfg.spec;
    precompiles.set_precompile_lookup(move |address: &Address| {
        if is_tip20(*address) {
            let token_id = address_to_token_id_unchecked(*address);
            if token_id == 0 {
                Some(PathUSDPrecompile::create(chain_id, spec))
            } else {
                Some(TIP20Precompile::create(*address, chain_id, spec))
            }
        } else if *address == TIP20_FACTORY_ADDRESS {
            Some(TIP20FactoryPrecompile::create(chain_id, spec))
        } else if *address == TIP20_REWARDS_REGISTRY_ADDRESS {
            Some(TIP20RewardsRegistryPrecompile::create(chain_id, spec))
        } else if *address == TIP403_REGISTRY_ADDRESS {
            Some(TIP403RegistryPrecompile::create(chain_id, spec))
        } else if *address == TIP_FEE_MANAGER_ADDRESS {
            Some(TipFeeManagerPrecompile::create(chain_id, spec))
        } else if *address == TIP_ACCOUNT_REGISTRAR {
            Some(TipAccountRegistrarPrecompile::create(chain_id, spec))
        } else if *address == STABLECOIN_EXCHANGE_ADDRESS {
            Some(StablecoinExchangePrecompile::create(chain_id, spec))
        } else if *address == NONCE_PRECOMPILE_ADDRESS {
            Some(NoncePrecompile::create(chain_id, spec))
        } else if *address == VALIDATOR_CONFIG_ADDRESS {
            Some(ValidatorConfigPrecompile::create(chain_id, spec))
        } else if *address == ACCOUNT_KEYCHAIN_ADDRESS && spec.is_allegretto() {
            // AccountKeychain is only available after Allegretto hardfork
            Some(AccountKeychainPrecompile::create(chain_id, spec))
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
            $impl.call($input.data, $input.caller)
        })
    };
}

pub struct TipFeeManagerPrecompile;
impl TipFeeManagerPrecompile {
    pub fn create(chain_id: u64, spec: TempoHardfork) -> DynPrecompile {
        tempo_precompile!("TipFeeManager", |input| TipFeeManager::new(
            &mut EvmPrecompileStorageProvider::new(input.internals, input.gas, chain_id, spec)
        ))
    }
}

pub struct TipAccountRegistrarPrecompile;
impl TipAccountRegistrarPrecompile {
    pub fn create(chain_id: u64, spec: TempoHardfork) -> DynPrecompile {
        tempo_precompile!("TipAccountRegistrar", |input| TipAccountRegistrar::new(
            &mut crate::storage::evm::EvmPrecompileStorageProvider::new(
                input.internals,
                input.gas,
                chain_id,
                spec
            ),
        ))
    }
}

pub struct TIP20RewardsRegistryPrecompile;
impl TIP20RewardsRegistryPrecompile {
    pub fn create(chain_id: u64, spec: TempoHardfork) -> DynPrecompile {
        tempo_precompile!("TIP20RewardsRegistry", |input| TIP20RewardsRegistry::new(
            &mut EvmPrecompileStorageProvider::new(input.internals, input.gas, chain_id, spec),
        ))
    }
}

pub struct TIP403RegistryPrecompile;
impl TIP403RegistryPrecompile {
    pub fn create(chain_id: u64, spec: TempoHardfork) -> DynPrecompile {
        tempo_precompile!("TIP403Registry", |input| TIP403Registry::new(
            &mut crate::storage::evm::EvmPrecompileStorageProvider::new(
                input.internals,
                input.gas,
                chain_id,
                spec
            ),
        ))
    }
}

pub struct TIP20FactoryPrecompile;
impl TIP20FactoryPrecompile {
    pub fn create(chain_id: u64, spec: TempoHardfork) -> DynPrecompile {
        tempo_precompile!("TIP20Factory", |input| TIP20Factory::new(
            &mut EvmPrecompileStorageProvider::new(input.internals, input.gas, chain_id, spec)
        ))
    }
}

pub struct TIP20Precompile;
impl TIP20Precompile {
    pub fn create(address: Address, chain_id: u64, spec: TempoHardfork) -> DynPrecompile {
        let token_id = address_to_token_id_unchecked(address);
        tempo_precompile!("TIP20Token", |input| TIP20Token::new(
            token_id,
            &mut EvmPrecompileStorageProvider::new(input.internals, input.gas, chain_id, spec),
        ))
    }
}

pub struct StablecoinExchangePrecompile;
impl StablecoinExchangePrecompile {
    pub fn create(chain_id: u64, spec: TempoHardfork) -> DynPrecompile {
        tempo_precompile!("StablecoinExchange", |input| StablecoinExchange::new(
            &mut EvmPrecompileStorageProvider::new(input.internals, input.gas, chain_id, spec)
        ))
    }
}

pub struct NoncePrecompile;
impl NoncePrecompile {
    pub fn create(chain_id: u64, spec: TempoHardfork) -> DynPrecompile {
        tempo_precompile!("NonceManager", |input| NonceManager::new(
            &mut EvmPrecompileStorageProvider::new(input.internals, input.gas, chain_id, spec)
        ))
    }
}

pub struct AccountKeychainPrecompile;
impl AccountKeychainPrecompile {
    pub fn create(chain_id: u64, spec: TempoHardfork) -> DynPrecompile {
        tempo_precompile!("AccountKeychain", |input| AccountKeychain::new(
            &mut EvmPrecompileStorageProvider::new(input.internals, input.gas, chain_id, spec)
        ))
    }
}

pub struct PathUSDPrecompile;
impl PathUSDPrecompile {
    pub fn create(chain_id: u64, spec: TempoHardfork) -> DynPrecompile {
        tempo_precompile!("PathUSD", |input| PathUSD::new(
            &mut EvmPrecompileStorageProvider::new(input.internals, input.gas, chain_id, spec),
        ))
    }
}

pub struct ValidatorConfigPrecompile;
impl ValidatorConfigPrecompile {
    pub fn create(chain_id: u64, spec: TempoHardfork) -> DynPrecompile {
        tempo_precompile!("ValidatorConfig", |input| ValidatorConfig::new(
            &mut EvmPrecompileStorageProvider::new(input.internals, input.gas, chain_id, spec),
        ))
    }
}

#[inline]
fn metadata<T: SolCall>(f: impl FnOnce() -> Result<T::Return>) -> PrecompileResult {
    f().into_precompile_result(0, |ret| T::abi_encode_returns(&ret).into())
}

#[inline]
fn view<T: SolCall>(calldata: &[u8], f: impl FnOnce(T) -> Result<T::Return>) -> PrecompileResult {
    let Ok(call) = T::abi_decode(calldata) else {
        // TODO refactor
        return Ok(PrecompileOutput::new_reverted(0, Bytes::new()));
    };
    f(call).into_precompile_result(0, |ret| T::abi_encode_returns(&ret).into())
}

#[inline]
pub fn mutate<T: SolCall>(
    calldata: &[u8],
    sender: Address,
    f: impl FnOnce(Address, T) -> Result<T::Return>,
) -> PrecompileResult {
    let Ok(call) = T::abi_decode(calldata) else {
        return Ok(PrecompileOutput::new_reverted(0, Bytes::new()));
    };
    f(sender, call).into_precompile_result(0, |ret| T::abi_encode_returns(&ret).into())
}

#[inline]
fn mutate_void<T: SolCall>(
    calldata: &[u8],
    sender: Address,
    f: impl FnOnce(Address, T) -> Result<()>,
) -> PrecompileResult {
    let Ok(call) = T::abi_decode(calldata) else {
        return Ok(PrecompileOutput::new_reverted(0, Bytes::new()));
    };
    f(sender, call).into_precompile_result(0, |()| Bytes::new())
}

#[inline]
fn fill_precompile_output(
    mut output: PrecompileOutput,
    storage: &mut impl PrecompileStorageProvider,
) -> PrecompileOutput {
    output.gas_used = storage.gas_used();

    // add refund only if it is not reverted
    if !output.reverted && storage.spec().is_moderato() {
        output.gas_refunded = storage.gas_refunded();
    }
    output
}

/// Helper function to return an unknown function selector error
///
/// Before Moderato: Returns a generic PrecompileError::Other
/// Moderato onwards: Returns an ABI-encoded UnknownFunctionSelector error with the selector
#[inline]
pub fn unknown_selector(selector: [u8; 4], gas: u64, spec: TempoHardfork) -> PrecompileResult {
    if spec.is_moderato() {
        error::TempoPrecompileError::UnknownFunctionSelector(selector)
            .into_precompile_result(gas, |_: ()| Bytes::new())
    } else {
        Err(PrecompileError::Other("Unknown function selector".into()))
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
            &mut EvmPrecompileStorageProvider::new(
                input.internals,
                input.gas,
                1,
                Default::default()
            ),
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
