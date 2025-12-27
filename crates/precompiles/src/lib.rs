//! Tempo precompile implementations.
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

// Allow the crate to refer to itself by name (needed for macro-generated code)
extern crate self as tempo_precompiles;

pub mod error;
pub use error::{IntoPrecompileResult, Result};

/// Trait for types that can provide their ABI tuple signature.
///
/// Used by the `#[interface]` macro to generate correct function selectors
/// when custom structs are used as function parameters.
///
/// # Example
///
/// A struct `Transfer { to: Address, amount: U256 }` would have:
/// - `ABI_TUPLE = "(address,uint256)"`
///
/// This allows the interface macro to generate correct signatures like
/// `transfer((address,uint256))` instead of incorrect `transfer(Transfer)`.
pub trait SolTupleSignature {
    /// The ABI tuple representation of this type's fields.
    ///
    /// For a struct with fields `(address, uint256)`, this would be `"(address,uint256)"`.
    const ABI_TUPLE: &'static str;
}

// Re-export for use in generated code
#[doc(hidden)]
pub use const_format;
#[doc(hidden)]
pub use keccak_const;

pub mod storage;

pub mod account_keychain;
pub mod nonce;
pub mod path_usd;
pub mod stablecoin_exchange;
pub mod tip20;
pub mod tip20_factory;
pub mod tip20_rewards_registry;
pub mod tip403_registry;
pub mod tip_account_registrar;
pub mod tip_fee_manager;
pub mod validator_config;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_util;

use crate::{
    account_keychain::AccountKeychain,
    nonce::NonceManager,
    path_usd::PathUSD,
    stablecoin_exchange::StablecoinExchange,
    storage::StorageCtx,
    tip_account_registrar::TipAccountRegistrar,
    tip_fee_manager::TipFeeManager,
    tip20::{TIP20Token, address_to_token_id_unchecked, is_tip20_prefix},
    tip20_factory::TIP20Factory,
    tip20_rewards_registry::TIP20RewardsRegistry,
    tip403_registry::TIP403Registry,
    validator_config::ValidatorConfig,
};
use tempo_chainspec::hardfork::TempoHardfork;

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
pub use account_keychain::AuthorizedKey;

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
        if is_tip20_prefix(*address) {
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
    error StaticCallNotAllowed();
}

macro_rules! tempo_precompile {
    ($id:expr, $chain_id:ident, $spec:ident, |$input:ident| $impl:expr) => {
        DynPrecompile::new_stateful(PrecompileId::Custom($id.into()), move |$input| {
            if !$input.is_direct_call() {
                return Ok(PrecompileOutput::new_reverted(
                    0,
                    DelegateCallNotAllowed {}.abi_encode().into(),
                ));
            }
            let mut storage = crate::storage::evm::EvmPrecompileStorageProvider::new(
                $input.internals,
                $input.gas,
                $chain_id,
                $spec,
                $input.is_static,
            );
            crate::storage::StorageCtx::enter(&mut storage, || {
                $impl.call($input.data, $input.caller)
            })
        })
    };
}

pub struct TipFeeManagerPrecompile;
impl TipFeeManagerPrecompile {
    pub fn create(chain_id: u64, spec: TempoHardfork) -> DynPrecompile {
        tempo_precompile!("TipFeeManager", chain_id, spec, |input| {
            TipFeeManager::new()
        })
    }
}

pub struct TipAccountRegistrarPrecompile;
impl TipAccountRegistrarPrecompile {
    pub fn create(chain_id: u64, spec: TempoHardfork) -> DynPrecompile {
        tempo_precompile!("TipAccountRegistrar", chain_id, spec, |input| {
            TipAccountRegistrar::new()
        })
    }
}

pub struct TIP20RewardsRegistryPrecompile;
impl TIP20RewardsRegistryPrecompile {
    pub fn create(chain_id: u64, spec: TempoHardfork) -> DynPrecompile {
        tempo_precompile!("TIP20RewardsRegistry", chain_id, spec, |input| {
            TIP20RewardsRegistry::new()
        })
    }
}

pub struct TIP403RegistryPrecompile;
impl TIP403RegistryPrecompile {
    pub fn create(chain_id: u64, spec: TempoHardfork) -> DynPrecompile {
        tempo_precompile!("TIP403Registry", chain_id, spec, |input| {
            TIP403Registry::new()
        })
    }
}

pub struct TIP20FactoryPrecompile;
impl TIP20FactoryPrecompile {
    pub fn create(chain_id: u64, spec: TempoHardfork) -> DynPrecompile {
        tempo_precompile!("TIP20Factory", chain_id, spec, |input| {
            TIP20Factory::new()
        })
    }
}

pub struct TIP20Precompile;
impl TIP20Precompile {
    pub fn create(address: Address, chain_id: u64, spec: TempoHardfork) -> DynPrecompile {
        let token_id = address_to_token_id_unchecked(address);
        tempo_precompile!("TIP20Token", chain_id, spec, |input| {
            TIP20Token::new(token_id)
        })
    }
}

pub struct StablecoinExchangePrecompile;
impl StablecoinExchangePrecompile {
    pub fn create(chain_id: u64, spec: TempoHardfork) -> DynPrecompile {
        tempo_precompile!("StablecoinExchange", chain_id, spec, |input| {
            StablecoinExchange::new()
        })
    }
}

pub struct NoncePrecompile;
impl NoncePrecompile {
    pub fn create(chain_id: u64, spec: TempoHardfork) -> DynPrecompile {
        tempo_precompile!("NonceManager", chain_id, spec, |input| {
            NonceManager::new()
        })
    }
}

pub struct AccountKeychainPrecompile;
impl AccountKeychainPrecompile {
    pub fn create(chain_id: u64, spec: TempoHardfork) -> DynPrecompile {
        tempo_precompile!("AccountKeychain", chain_id, spec, |input| {
            AccountKeychain::new()
        })
    }
}

pub struct PathUSDPrecompile;
impl PathUSDPrecompile {
    pub fn create(chain_id: u64, spec: TempoHardfork) -> DynPrecompile {
        tempo_precompile!("PathUSD", chain_id, spec, |input| { PathUSD::new() })
    }
}

pub struct ValidatorConfigPrecompile;
impl ValidatorConfigPrecompile {
    pub fn create(chain_id: u64, spec: TempoHardfork) -> DynPrecompile {
        tempo_precompile!("ValidatorConfig", chain_id, spec, |input| {
            ValidatorConfig::new()
        })
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
    if StorageCtx.is_static() {
        return Ok(PrecompileOutput::new_reverted(
            0,
            StaticCallNotAllowed {}.abi_encode().into(),
        ));
    }
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
    if StorageCtx.is_static() {
        return Ok(PrecompileOutput::new_reverted(
            0,
            StaticCallNotAllowed {}.abi_encode().into(),
        ));
    }
    let Ok(call) = T::abi_decode(calldata) else {
        return Ok(PrecompileOutput::new_reverted(0, Bytes::new()));
    };
    f(sender, call).into_precompile_result(0, |()| Bytes::new())
}

#[inline]
fn fill_precompile_output(
    mut output: PrecompileOutput,
    storage: &mut StorageCtx,
) -> PrecompileOutput {
    output.gas_used = storage.gas_used();

    // add refund only if it is not reverted
    if !output.reverted && storage.spec().is_allegretto() {
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
    use crate::tip20::TIP20Token;
    use alloy::primitives::{Address, Bytes, U256};
    use alloy_evm::{
        EthEvmFactory, EvmEnv, EvmFactory, EvmInternals,
        precompiles::{Precompile as AlloyEvmPrecompile, PrecompileInput},
    };
    use revm::{
        context::ContextTr,
        database::{CacheDB, EmptyDB},
    };
    use tempo_contracts::precompiles::ITIP20;

    #[test]
    fn test_precompile_delegatecall() {
        let (chain_id, spec) = (1, TempoHardfork::default());
        let precompile =
            tempo_precompile!("TIP20Token", chain_id, spec, |input| { TIP20Token::new(1) });

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
            is_static: false,
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

    #[test]
    fn test_precompile_static_call() {
        let (chain_id, spec) = (1, TempoHardfork::default());
        let precompile =
            tempo_precompile!("TIP20Token", chain_id, spec, |input| { TIP20Token::new(1) });

        let target_address = Address::random();

        let call_static = |calldata: Bytes| {
            let db = CacheDB::new(EmptyDB::new());
            let mut evm = EthEvmFactory::default().create_evm(db, EvmEnv::default());
            let block = evm.block.clone();
            let evm_internals = EvmInternals::new(evm.journal_mut(), &block);

            let input = PrecompileInput {
                data: &calldata,
                caller: Address::ZERO,
                internals: evm_internals,
                gas: 100_000,
                is_static: true,
                value: U256::ZERO,
                target_address,
                bytecode_address: target_address,
            };

            AlloyEvmPrecompile::call(&precompile, input)
        };

        // Static calls into mutating functions should fail
        let result = call_static(Bytes::from(
            ITIP20::transferCall {
                to: Address::random(),
                amount: U256::from(100),
            }
            .abi_encode(),
        ));
        let output = result.expect("expected Ok");
        assert!(output.reverted);
        assert!(StaticCallNotAllowed::abi_decode(&output.bytes).is_ok());

        // Static calls into mutate void functions should fail
        let result = call_static(Bytes::from(
            ITIP20::approveCall {
                spender: Address::random(),
                amount: U256::from(100),
            }
            .abi_encode(),
        ));
        let output = result.expect("expected Ok");
        assert!(output.reverted);
        assert!(StaticCallNotAllowed::abi_decode(&output.bytes).is_ok());

        // Static calls into view functions should succeed
        let result = call_static(Bytes::from(
            ITIP20::balanceOfCall {
                account: Address::random(),
            }
            .abi_encode(),
        ));
        let output = result.expect("expected Ok");
        assert!(
            !output.reverted,
            "view function should not revert in static context"
        );
    }
}

/// Tests for the custom precompiles macros (#[solidity], #[derive(SolStruct)]).
///
/// These tests validate that the macros generate correct selectors and EIP-712 signatures,
/// especially for complex types like structs.
#[cfg(test)]
mod macro_tests {
    use alloy::primitives::{Address, U256};
    use alloy::sol_types::{SolCall, SolStruct};
    use tempo_precompiles_macros::solidity;

    use crate::error::Result;

    #[solidity]
    pub mod test_types {
        use super::*;

        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct Inner {
            pub value: U256,
            pub owner: Address,
        }

        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct Outer {
            pub inner: Inner,
            pub count: u64,
        }

        pub trait Interface {
            fn process_inner(&self, data: Inner) -> Result<bool>;
        }
    }

    #[test]
    fn test_sol_struct_abi_tuple_primitives() {
        use crate::SolTupleSignature;

        // Inner struct: (uint256,address)
        assert_eq!(test_types::Inner::ABI_TUPLE, "(uint256,address)");
    }

    #[test]
    fn test_sol_struct_abi_tuple_nested() {
        use crate::SolTupleSignature;

        // Outer struct contains Inner, so its ABI_TUPLE should include the expanded tuple
        // Expected: "((uint256,address),uint64)"
        assert_eq!(test_types::Outer::ABI_TUPLE, "((uint256,address),uint64)");
    }

    #[test]
    fn test_sol_struct_eip712_root_type() {
        // EIP-712 root type uses struct names for nested types
        let inner_root = <test_types::Inner as SolStruct>::eip712_root_type();
        assert_eq!(inner_root.as_ref(), "Inner(uint256 value,address owner)");

        let outer_root = <test_types::Outer as SolStruct>::eip712_root_type();
        assert_eq!(outer_root.as_ref(), "Outer(Inner inner,uint64 count)");
    }

    #[test]
    fn test_sol_struct_eip712_components_nested() {
        // Inner has no dependencies
        let inner_components = <test_types::Inner as SolStruct>::eip712_components();
        assert!(inner_components.is_empty());

        // Outer depends on Inner, so components should include Inner's root type
        let outer_components = <test_types::Outer as SolStruct>::eip712_components();
        assert!(!outer_components.is_empty());
        assert!(
            outer_components
                .iter()
                .any(|c| c.contains("Inner(uint256 value,address owner)")),
            "Outer should have Inner as a component, got: {:?}",
            outer_components
        );
    }

    #[test]
    fn test_interface_struct_param_selector() {
        use crate::SolTupleSignature;

        // The signature should use the tuple form: "processInner((uint256,address))"
        let expected_sig = format!("processInner({})", test_types::Inner::ABI_TUPLE);
        assert_eq!(
            <test_types::processInnerCall as SolCall>::SIGNATURE,
            expected_sig
        );

        // Container enum should have the same selector as the call struct
        let call_selector = <test_types::processInnerCall as SolCall>::SELECTOR;
        assert_eq!(
            test_types::InterfaceCalls::SELECTORS[0],
            call_selector,
            "Container enum selector should match call struct selector"
        );
    }
}
