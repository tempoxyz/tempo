//! Tempo precompile implementations.
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod error;
pub use error::{IntoPrecompileResult, Result};

pub mod storage;

pub mod account_keychain;
pub mod nonce;
pub mod stablecoin_dex;
pub mod tip20;
pub mod tip20_factory;
pub mod tip403_registry;
pub mod tip_fee_manager;
pub mod validator_config;

#[cfg(any(test, feature = "test-utils"))]
pub mod resolver;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_util;

use crate::{
    account_keychain::AccountKeychain,
    nonce::NonceManager,
    stablecoin_dex::StablecoinDEX,
    storage::StorageCtx,
    tip_fee_manager::TipFeeManager,
    tip20::{TIP20Token, is_tip20_prefix},
    tip20_factory::TIP20Factory,
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
    ACCOUNT_KEYCHAIN_ADDRESS, DEFAULT_FEE_TOKEN, NONCE_PRECOMPILE_ADDRESS, PATH_USD_ADDRESS,
    STABLECOIN_DEX_ADDRESS, TIP_FEE_MANAGER_ADDRESS, TIP20_FACTORY_ADDRESS,
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
    calldata_len
        .div_ceil(32)
        .saturating_mul(INPUT_PER_WORD_COST as usize) as u64
}

pub trait Precompile {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult;
}

pub fn extend_tempo_precompiles(precompiles: &mut PrecompilesMap, cfg: &CfgEnv<TempoHardfork>) {
    let cfg = cfg.clone();

    precompiles.set_precompile_lookup(move |address: &Address| {
        if is_tip20_prefix(*address) {
            Some(TIP20Precompile::create(*address, &cfg))
        } else if *address == TIP20_FACTORY_ADDRESS {
            Some(TIP20FactoryPrecompile::create(&cfg))
        } else if *address == TIP403_REGISTRY_ADDRESS {
            Some(TIP403RegistryPrecompile::create(&cfg))
        } else if *address == TIP_FEE_MANAGER_ADDRESS {
            Some(TipFeeManagerPrecompile::create(&cfg))
        } else if *address == STABLECOIN_DEX_ADDRESS {
            Some(StablecoinDEXPrecompile::create(&cfg))
        } else if *address == NONCE_PRECOMPILE_ADDRESS {
            Some(NoncePrecompile::create(&cfg))
        } else if *address == VALIDATOR_CONFIG_ADDRESS {
            Some(ValidatorConfigPrecompile::create(&cfg))
        } else if *address == ACCOUNT_KEYCHAIN_ADDRESS {
            Some(AccountKeychainPrecompile::create(&cfg))
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
    ($id:expr, $cfg:expr, |$input:ident| $impl:expr) => {{
        let spec = $cfg.spec;
        let gas_params = $cfg.gas_params.clone();
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
                spec,
                $input.is_static,
                gas_params.clone(),
            );
            crate::storage::StorageCtx::enter(&mut storage, || {
                $impl.call($input.data, $input.caller)
            })
        })
    }};
}

pub struct TipFeeManagerPrecompile;
impl TipFeeManagerPrecompile {
    pub fn create(cfg: &CfgEnv<TempoHardfork>) -> DynPrecompile {
        tempo_precompile!("TipFeeManager", cfg, |input| { TipFeeManager::new() })
    }
}

pub struct TIP403RegistryPrecompile;
impl TIP403RegistryPrecompile {
    pub fn create(cfg: &CfgEnv<TempoHardfork>) -> DynPrecompile {
        tempo_precompile!("TIP403Registry", cfg, |input| { TIP403Registry::new() })
    }
}

pub struct TIP20FactoryPrecompile;
impl TIP20FactoryPrecompile {
    pub fn create(cfg: &CfgEnv<TempoHardfork>) -> DynPrecompile {
        tempo_precompile!("TIP20Factory", cfg, |input| { TIP20Factory::new() })
    }
}

pub struct TIP20Precompile;
impl TIP20Precompile {
    pub fn create(address: Address, cfg: &CfgEnv<TempoHardfork>) -> DynPrecompile {
        tempo_precompile!("TIP20Token", cfg, |input| {
            TIP20Token::from_address(address).expect("TIP20 prefix already verified")
        })
    }
}

pub struct StablecoinDEXPrecompile;
impl StablecoinDEXPrecompile {
    pub fn create(cfg: &CfgEnv<TempoHardfork>) -> DynPrecompile {
        tempo_precompile!("StablecoinDEX", cfg, |input| { StablecoinDEX::new() })
    }
}

pub struct NoncePrecompile;
impl NoncePrecompile {
    pub fn create(cfg: &CfgEnv<TempoHardfork>) -> DynPrecompile {
        tempo_precompile!("NonceManager", cfg, |input| { NonceManager::new() })
    }
}

pub struct AccountKeychainPrecompile;
impl AccountKeychainPrecompile {
    pub fn create(cfg: &CfgEnv<TempoHardfork>) -> DynPrecompile {
        tempo_precompile!("AccountKeychain", cfg, |input| { AccountKeychain::new() })
    }
}

pub struct ValidatorConfigPrecompile;
impl ValidatorConfigPrecompile {
    pub fn create(cfg: &CfgEnv<TempoHardfork>) -> DynPrecompile {
        tempo_precompile!("ValidatorConfig", cfg, |input| { ValidatorConfig::new() })
    }
}

#[inline]
fn metadata<T: SolCall>(f: impl FnOnce() -> Result<T::Return>) -> PrecompileResult {
    f().into_precompile_result(0, |ret| T::abi_encode_returns(&ret).into())
}

#[inline]
fn view<T: SolCall>(call: T, f: impl FnOnce(T) -> Result<T::Return>) -> PrecompileResult {
    f(call).into_precompile_result(0, |ret| T::abi_encode_returns(&ret).into())
}

#[inline]
fn mutate<T: SolCall>(
    call: T,
    sender: Address,
    f: impl FnOnce(Address, T) -> Result<T::Return>,
) -> PrecompileResult {
    if StorageCtx.is_static() {
        return Ok(PrecompileOutput::new_reverted(
            0,
            StaticCallNotAllowed {}.abi_encode().into(),
        ));
    }
    f(sender, call).into_precompile_result(0, |ret| T::abi_encode_returns(&ret).into())
}

#[inline]
fn mutate_void<T: SolCall>(
    call: T,
    sender: Address,
    f: impl FnOnce(Address, T) -> Result<()>,
) -> PrecompileResult {
    if StorageCtx.is_static() {
        return Ok(PrecompileOutput::new_reverted(
            0,
            StaticCallNotAllowed {}.abi_encode().into(),
        ));
    }
    f(sender, call).into_precompile_result(0, |()| Bytes::new())
}

#[inline]
fn fill_precompile_output(mut output: PrecompileOutput, storage: &StorageCtx) -> PrecompileOutput {
    output.gas_used = storage.gas_used();

    // add refund only if it is not reverted
    if !output.reverted {
        output.gas_refunded = storage.gas_refunded();
    }
    output
}

/// Helper function to return an unknown function selector error.
/// Returns an ABI-encoded UnknownFunctionSelector error with the selector.
#[inline]
pub fn unknown_selector(selector: [u8; 4], gas: u64) -> PrecompileResult {
    error::TempoPrecompileError::UnknownFunctionSelector(selector).into_precompile_result(gas)
}

/// Helper function to decode calldata and dispatch it.
#[inline]
fn dispatch_call<T>(
    calldata: &[u8],
    decode: impl FnOnce(&[u8]) -> core::result::Result<T, alloy::sol_types::Error>,
    f: impl FnOnce(T) -> PrecompileResult,
) -> PrecompileResult {
    let storage = StorageCtx::default();

    if calldata.len() < 4 {
        if storage.spec().is_t1() {
            return Ok(fill_precompile_output(
                PrecompileOutput::new_reverted(0, Bytes::new()),
                &storage,
            ));
        } else {
            return Err(PrecompileError::Other(
                "Invalid input: missing function selector".into(),
            ));
        }
    }
    let result = decode(calldata);

    match result {
        Ok(call) => f(call).map(|res| fill_precompile_output(res, &storage)),
        Err(alloy::sol_types::Error::UnknownSelector { selector, .. }) => {
            unknown_selector(*selector, storage.gas_used())
                .map(|res| fill_precompile_output(res, &storage))
        }
        Err(_) => Ok(fill_precompile_output(
            PrecompileOutput::new_reverted(0, Bytes::new()),
            &storage,
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
    use crate::tip20::TIP20Token;
    use alloy::primitives::{Address, Bytes, U256, bytes};
    use alloy_evm::{
        EthEvmFactory, EvmEnv, EvmFactory, EvmInternals,
        precompiles::{Precompile as AlloyEvmPrecompile, PrecompileInput},
    };
    use revm::{
        context::{ContextTr, TxEnv},
        database::{CacheDB, EmptyDB},
        state::{AccountInfo, Bytecode},
    };
    use tempo_contracts::precompiles::ITIP20;

    #[test]
    fn test_precompile_delegatecall() {
        let cfg = CfgEnv::<TempoHardfork>::default();
        let precompile = tempo_precompile!("TIP20Token", &cfg, |input| {
            TIP20Token::from_address(PATH_USD_ADDRESS).expect("PATH_USD_ADDRESS is valid")
        });

        let db = CacheDB::new(EmptyDB::new());
        let mut evm = EthEvmFactory::default().create_evm(db, EvmEnv::default());
        let block = evm.block.clone();
        let tx = TxEnv::default();
        let evm_internals = EvmInternals::new(evm.journal_mut(), &block, &cfg, &tx);

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
        let cfg = CfgEnv::<TempoHardfork>::default();
        let tx = TxEnv::default();
        let precompile = tempo_precompile!("TIP20Token", &cfg, |input| {
            TIP20Token::from_address(PATH_USD_ADDRESS).expect("PATH_USD_ADDRESS is valid")
        });

        let token_address = PATH_USD_ADDRESS;

        let call_static = |calldata: Bytes| {
            let mut db = CacheDB::new(EmptyDB::new());
            db.insert_account_info(
                token_address,
                AccountInfo {
                    code: Some(Bytecode::new_raw(bytes!("0xEF"))),
                    ..Default::default()
                },
            );
            let mut evm = EthEvmFactory::default().create_evm(db, EvmEnv::default());
            let block = evm.block.clone();
            let evm_internals = EvmInternals::new(evm.journal_mut(), &block, &cfg, &tx);

            let input = PrecompileInput {
                data: &calldata,
                caller: Address::ZERO,
                internals: evm_internals,
                gas: 1_000_000,
                is_static: true,
                value: U256::ZERO,
                target_address: token_address,
                bytecode_address: token_address,
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

    #[test]
    fn test_invalid_calldata_hardfork_behavior() {
        let call_with_spec = |calldata: Bytes, spec: TempoHardfork| {
            let mut cfg = CfgEnv::<TempoHardfork>::default();
            cfg.set_spec(spec);
            let tx = TxEnv::default();
            let precompile = tempo_precompile!("TIP20Token", &cfg, |input| {
                TIP20Token::from_address(PATH_USD_ADDRESS).expect("PATH_USD_ADDRESS is valid")
            });

            let mut db = CacheDB::new(EmptyDB::new());
            db.insert_account_info(
                PATH_USD_ADDRESS,
                AccountInfo {
                    code: Some(Bytecode::new_raw(bytes!("0xEF"))),
                    ..Default::default()
                },
            );
            let mut evm = EthEvmFactory::default().create_evm(db, EvmEnv::default());
            let block = evm.block.clone();
            let evm_internals = EvmInternals::new(evm.journal_mut(), &block, &cfg, &tx);

            let input = PrecompileInput {
                data: &calldata,
                caller: Address::ZERO,
                internals: evm_internals,
                gas: 1_000_000,
                is_static: false,
                value: U256::ZERO,
                target_address: PATH_USD_ADDRESS,
                bytecode_address: PATH_USD_ADDRESS,
            };

            AlloyEvmPrecompile::call(&precompile, input)
        };

        // T1: empty calldata (missing selector) should return a reverted output
        let empty = call_with_spec(Bytes::new(), TempoHardfork::T1)
            .expect("T1: expected Ok with reverted output");
        assert!(empty.reverted, "T1: expected reverted output");
        assert!(empty.bytes.is_empty());
        assert!(empty.gas_used != 0);
        assert_eq!(empty.gas_refunded, 0);

        // T1: unknown selector should return a reverted output with UnknownFunctionSelector error
        let unknown = call_with_spec(Bytes::from([0xAA; 4]), TempoHardfork::T1)
            .expect("T1: expected Ok with reverted output");
        assert!(unknown.reverted, "T1: expected reverted output");

        // Verify it's an UnknownFunctionSelector error with the correct selector
        let decoded =
            tempo_contracts::precompiles::UnknownFunctionSelector::abi_decode(&unknown.bytes)
                .expect("T1: expected UnknownFunctionSelector error");
        assert_eq!(decoded.selector.as_slice(), &[0xAA, 0xAA, 0xAA, 0xAA]);

        // Verify gas is tracked for both cases (unknown selector may cost slightly more due `INPUT_PER_WORD_COST`)
        assert!(unknown.gas_used >= empty.gas_used);
        assert_eq!(unknown.gas_refunded, empty.gas_refunded);

        // Pre-T1 (T0): invalid calldata should return PrecompileError
        let result = call_with_spec(Bytes::new(), TempoHardfork::T0);
        assert!(
            matches!(
                &result,
                Err(PrecompileError::Other(msg)) if msg.contains("missing function selector")
            ),
            "T0: expected PrecompileError for invalid calldata, got {result:?}"
        );
    }
}
