//! Tempo precompile implementations.
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod error;
pub use error::{EncodePrecompileResult, IntoPrecompileResult, Result};

pub mod storage;

pub mod dispatch;
pub use dispatch::*;

pub(crate) mod ip_validation;

pub mod account_keychain;
pub mod address_registry;
pub mod current_committee;
pub mod nonce;
pub mod receive_policy_guard;
pub mod signature_verifier;
pub mod stablecoin_dex;
pub mod storage_credits;
pub mod tip20;
pub mod tip20_channel_reserve;
pub mod tip20_factory;
pub mod tip403_registry;
pub mod tip_fee_manager;
pub mod validator_config;
pub mod validator_config_v2;
pub mod zone_factory;
pub mod zone_verifier;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_util;

use crate::{
    account_keychain::AccountKeychain,
    address_registry::AddressRegistry,
    current_committee::CurrentCommittee,
    nonce::NonceManager,
    receive_policy_guard::ReceivePolicyGuard,
    signature_verifier::SignatureVerifier,
    stablecoin_dex::StablecoinDEX,
    storage::{StorageCtx, actions::StorageActions},
    storage_credits::{NonCreditableSlots, StorageCredits},
    tip_fee_manager::TipFeeManager,
    tip20::TIP20Token,
    tip20_channel_reserve::TIP20ChannelReserve,
    tip20_factory::TIP20Factory,
    tip403_registry::TIP403Registry,
    validator_config::ValidatorConfig,
    validator_config_v2::ValidatorConfigV2,
    zone_factory::ZoneFactory,
    zone_verifier::ZoneVerifier,
};
use std::{cell::RefCell, rc::Rc};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_primitives::TempoAddressExt;

#[cfg(test)]
use alloy::sol_types::SolInterface;
use alloy::{primitives::Address, sol, sol_types::SolError};
use alloy_evm::precompiles::{DynPrecompile, PrecompilesMap};
use revm::{
    context::CfgEnv,
    handler::EthPrecompiles,
    precompile::{PrecompileId, PrecompileOutput, PrecompileResult},
};

pub use tempo_contracts::precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, ADDRESS_REGISTRY_ADDRESS, CURRENT_COMMITTEE_ADDRESS,
    DEFAULT_FEE_TOKEN, NONCE_PRECOMPILE_ADDRESS, PATH_USD_ADDRESS, RECEIVE_POLICY_GUARD_ADDRESS,
    SIGNATURE_VERIFIER_ADDRESS, STABLECOIN_DEX_ADDRESS, STORAGE_CREDITS_ADDRESS,
    SYSTEM_PRECOMPILES, TIP_FEE_MANAGER_ADDRESS, TIP20_CHANNEL_RESERVE_ADDRESS,
    TIP20_FACTORY_ADDRESS, TIP403_REGISTRY_ADDRESS, VALIDATOR_CONFIG_ADDRESS,
    VALIDATOR_CONFIG_V2_ADDRESS, ZONE_FACTORY_ADDRESS, ZONE_MESSENGER_ADDRESS,
    ZONE_PORTAL_IMPL_ADDRESS, ZONE_VERIFIER_ADDRESS,
};

// Re-export storage layout helpers for read-only contexts (e.g., pool validation)
pub use account_keychain::AuthorizedKey;

/// Pre-T11 input per word cost. It covers ABI decoding and cloning of input into calldata.
///
/// This is priced at twice `COPY_COST` to mitigate different ABI decodings.
const PRE_T11_INPUT_PER_WORD_COST: u64 = 6;

/// Input per word cost starting at T11.
const POST_T11_INPUT_PER_WORD_COST: u64 = 30;

/// Additional T11 cost per value processed by duplicate validation.
const T11_DEDUP_PER_ITEM_COST: u64 = 20;

/// Gas cost for `ecrecover` signature verification (used by KeyAuthorization and Permit).
pub const ECRECOVER_GAS: u64 = 3_000;

/// Returns the gas cost for decoding calldata of the given length at `spec`, rounded up to word
/// boundaries, or out-of-gas if the cost cannot be represented as a `u64`.
#[inline]
pub fn input_cost(spec: TempoHardfork, calldata_len: usize) -> Result<u64> {
    let per_word_cost = if spec.is_t11() {
        POST_T11_INPUT_PER_WORD_COST
    } else {
        PRE_T11_INPUT_PER_WORD_COST
    };

    let calldata_len =
        u64::try_from(calldata_len).map_err(|_| error::TempoPrecompileError::OutOfGas)?;

    calldata_len
        .div_ceil(32)
        .checked_mul(per_word_cost)
        .ok_or(error::TempoPrecompileError::OutOfGas)
}

/// Returns the additional gas cost for duplicate validation at `spec`.
#[inline]
pub fn dedup_cost(spec: TempoHardfork, item_count: usize) -> Result<u64> {
    if !spec.is_t11() {
        return Ok(0);
    }

    u64::try_from(item_count)
        .map_err(|_| error::TempoPrecompileError::OutOfGas)?
        .checked_mul(T11_DEDUP_PER_ITEM_COST)
        .ok_or(error::TempoPrecompileError::OutOfGas)
}

/// Charges for duplicate validation, then returns whether `values` contains duplicates.
#[inline]
pub fn has_duplicates_metered<T: Ord>(
    storage: &mut StorageCtx,
    values: impl IntoIterator<Item = T>,
) -> Result<bool> {
    let mut values = values.into_iter().collect::<Vec<_>>();
    storage.deduct_gas(dedup_cost(storage.spec(), values.len())?)?;
    values.sort_unstable();
    Ok(values.windows(2).any(|pair| pair[0] == pair[1]))
}

/// Trait implemented by all Tempo precompile contract types.
///
/// Precompiles must provide a dispatcher that decodes the 4-byte function selector from calldata,
/// ABI-decodes the arguments, and routes to the corresponding method.
pub trait Precompile {
    /// Dispatches an EVM call to this precompile.
    ///
    /// Implementations should deduct calldata gas upfront via [`input_cost`], then decode the
    /// 4-byte function selector from `calldata` and route to the matching method using
    /// `dispatch_call` combined with the `view` or `mutate` helpers.
    ///
    /// Business-logic errors are returned as reverted [`PrecompileOutput`]s with ABI-encoded
    /// error data, while fatal failures (e.g. out-of-gas) are returned as
    /// [`PrecompileError`](revm::precompile::PrecompileError).
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult;
}

/// Shared execution environment captured by Tempo precompile wrappers.
#[derive(Clone)]
pub struct PrecompileEnv {
    cfg: CfgEnv<TempoHardfork>,
    actions: StorageActions,
    non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
}

impl PrecompileEnv {
    pub fn new(
        cfg: &CfgEnv<TempoHardfork>,
        actions: StorageActions,
        non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
    ) -> Self {
        Self {
            cfg: cfg.clone(),
            actions,
            non_creditable_slots,
        }
    }
}

/// Returns the full Tempo precompile set for the given EVM config.
///
/// Uses Osaka built-ins and registers Tempo precompiles via [`extend_tempo_precompiles`].
///
/// [`StorageActions`] records logical precompile storage operations (`SLOAD`, `SSTORE`, `SINC`,
/// `SDEC`, and domain-specific actions such as `FeeAmmSwap`) for node/validator/builder
/// integrations that use the trace for performance; tooling can pass [`StorageActions::disabled`].
///
/// [`NonCreditableSlots`] identifies transaction-local protocol slots whose clears must not mint
/// TIP-1060 storage credits: the fee payer's fee-token balance and, when applicable, the keychain
/// fee key's spending limit. They are part of credit/gas accounting, so gas estimation should pass
/// values derived from the real transaction context rather than mocks.
pub fn tempo_precompiles(
    cfg: &CfgEnv<TempoHardfork>,
    actions: StorageActions,
    non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
) -> PrecompilesMap {
    let spec = cfg.spec.into();
    let mut precompiles = PrecompilesMap::from_static(EthPrecompiles::new(spec).precompiles);
    extend_tempo_precompiles(&mut precompiles, cfg, actions, non_creditable_slots);
    precompiles
}

/// Registers Tempo-specific precompiles into an existing [`PrecompilesMap`] by installing a
/// lookup function that matches addresses to their precompile: TIP-20 tokens (by prefix),
/// TIP20Factory, TIP403Registry, TipFeeManager, StablecoinDEX, NonceManager, ValidatorConfig,
/// AccountKeychain, ValidatorConfigV2, and CurrentCommittee. Each precompile is wrapped via the
/// `tempo_precompile!` macro which enforces direct-call-only (no delegatecall) and sets up the
/// storage context.
///
/// `actions` and `non_creditable_slots` are shared across all wrappers; see [`tempo_precompiles`].
pub fn extend_tempo_precompiles(
    precompiles: &mut PrecompilesMap,
    cfg: &CfgEnv<TempoHardfork>,
    actions: StorageActions,
    non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
) {
    let env = PrecompileEnv::new(cfg, actions, non_creditable_slots);

    precompiles.set_precompile_lookup(move |address: &Address| {
        if address.is_tip20() {
            Some(TIP20Token::create_precompile(*address, &env))
        } else if *address == TIP20_FACTORY_ADDRESS {
            Some(TIP20Factory::create_precompile(&env))
        } else if *address == TIP20_CHANNEL_RESERVE_ADDRESS {
            Some(TIP20ChannelReserve::create_precompile(&env))
        } else if *address == ADDRESS_REGISTRY_ADDRESS {
            Some(AddressRegistry::create_precompile(&env))
        } else if *address == TIP403_REGISTRY_ADDRESS {
            Some(TIP403Registry::create_precompile(&env))
        } else if *address == TIP_FEE_MANAGER_ADDRESS {
            Some(TipFeeManager::create_precompile(&env))
        } else if *address == STABLECOIN_DEX_ADDRESS {
            Some(StablecoinDEX::create_precompile(&env))
        } else if *address == NONCE_PRECOMPILE_ADDRESS {
            Some(NonceManager::create_precompile(&env))
        } else if *address == VALIDATOR_CONFIG_ADDRESS {
            Some(ValidatorConfig::create_precompile(&env))
        } else if *address == ACCOUNT_KEYCHAIN_ADDRESS {
            Some(AccountKeychain::create_precompile(&env))
        } else if *address == VALIDATOR_CONFIG_V2_ADDRESS {
            Some(ValidatorConfigV2::create_precompile(&env))
        } else if *address == SIGNATURE_VERIFIER_ADDRESS {
            Some(SignatureVerifier::create_precompile(&env))
        } else if *address == RECEIVE_POLICY_GUARD_ADDRESS {
            Some(ReceivePolicyGuard::create_precompile(&env))
        } else if *address == STORAGE_CREDITS_ADDRESS {
            Some(StorageCredits::create_precompile(&env))
        } else if *address == CURRENT_COMMITTEE_ADDRESS {
            Some(CurrentCommittee::create_precompile(&env))
        } else if *address == ZONE_FACTORY_ADDRESS {
            Some(ZoneFactory::create_precompile(&env))
        } else if *address == ZONE_VERIFIER_ADDRESS && env.cfg.spec.is_t13() {
            Some(ZoneVerifier::create_precompile(&env))
        } else {
            None
        }
    });
}

sol! {
    error DelegateCallNotAllowed();
}

macro_rules! tempo_precompile {
    ($id:expr, $cfg:expr, |$input:ident| $impl:expr) => {{
        #[cfg(not(test))]
        compile_error!("tempo_precompile! without actions is only available in tests");
        #[cfg(test)]
        let env = PrecompileEnv::new(
            $cfg,
            StorageActions::disabled(),
            Rc::new(RefCell::new(NonCreditableSlots::empty())),
        );
        tempo_precompile!($id, env: &env, |$input| $impl)
    }};
    ($id:expr, env: $env:expr, |$input:ident| $impl:expr) => {{
        let env: &PrecompileEnv = $env;
        let spec = env.cfg.spec;
        let amsterdam_eip8037_enabled = env.cfg.enable_amsterdam_eip8037;
        let gas_params = env.cfg.gas_params.clone();
        let actions = env.actions.clone();
        let non_creditable_slots = env.non_creditable_slots.clone();
        DynPrecompile::new_stateful(PrecompileId::Custom($id.into()), move |$input| {
            if !$input.is_direct_call() {
                return Ok(PrecompileOutput::revert(
                    0,
                    DelegateCallNotAllowed {}.abi_encode().into(),
                    $input.reservoir,
                ));
            }
            let mut storage = crate::storage::evm::EvmPrecompileStorageProvider::new(
                $input.internals,
                $input.gas,
                $input.reservoir,
                spec,
                amsterdam_eip8037_enabled,
                $input.is_static,
                gas_params.clone(),
            )
            .with_actions(actions.clone())
            .with_non_creditable_slots(non_creditable_slots.clone());
            crate::storage::StorageCtx::enter(&mut storage, || {
                $impl.call($input.data, $input.caller)
            })
        })
    }};
}

impl TipFeeManager {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("TipFeeManager", env: env, |input| { Self::new() })
    }
}

impl AddressRegistry {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("AddressRegistry", env: env, |input| { Self::new() })
    }
}

impl TIP403Registry {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("TIP403Registry", env: env, |input| { Self::new() })
    }
}

impl TIP20Factory {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("TIP20Factory", env: env, |input| { Self::new() })
    }
}

impl TIP20Token {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(address: Address, env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("TIP20Token", env: env, |input| {
            Self::from_address(address).expect("TIP20 prefix already verified")
        })
    }
}

impl ZoneFactory {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("ZoneFactory", env: env, |input| { Self::new() })
    }
}

impl ZoneVerifier {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("ZoneVerifier", env: env, |input| { Self::new() })
    }
}

impl StablecoinDEX {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("StablecoinDEX", env: env, |input| { Self::new() })
    }
}

impl NonceManager {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("NonceManager", env: env, |input| { Self::new() })
    }
}

impl AccountKeychain {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("AccountKeychain", env: env, |input| { Self::new() })
    }
}

impl ValidatorConfig {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("ValidatorConfig", env: env, |input| { Self::new() })
    }
}

impl ValidatorConfigV2 {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("ValidatorConfigV2", env: env, |input| { Self::new() })
    }
}

impl CurrentCommittee {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("CurrentCommittee", env: env, |input| { Self::new() })
    }
}

impl SignatureVerifier {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("SignatureVerifier", env: env, |input| { Self::new() })
    }
}

impl TIP20ChannelReserve {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("TIP20ChannelReserve", env: env, |input| { Self::new() })
    }
}

impl ReceivePolicyGuard {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("ReceivePolicyGuard", env: env, |input| { Self::new() })
    }
}

impl StorageCredits {
    /// Creates the EVM precompile for this type.
    pub fn create_precompile(env: &PrecompileEnv) -> DynPrecompile {
        tempo_precompile!("StorageCredits", env: env, |input| { Self::new() })
    }
}

/// Asserts that `result` is a reverted output whose bytes decode to `expected_error`.
#[cfg(test)]
pub fn expect_precompile_revert<E>(result: &PrecompileResult, expected_error: E)
where
    E: SolInterface + PartialEq + std::fmt::Debug,
{
    match result {
        Ok(result) => {
            assert!(result.is_revert());
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
    use crate::{
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        tip20::TIP20Token,
    };
    use alloy::{
        primitives::{Address, B256, Bytes, TxKind, U256, bytes},
        sol_types::SolCall,
    };
    use alloy_evm::{
        EthEvmFactory, Evm, EvmEnv, EvmFactory, EvmInternals,
        precompiles::{Precompile as AlloyEvmPrecompile, PrecompileInput},
    };
    use revm::{
        context::{ContextTr, TxEnv},
        database::InMemoryDB,
        state::{AccountInfo, Bytecode},
    };
    use tempo_contracts::{
        precompiles::{ITIP20, IZoneVerifier, UnknownFunctionSelector},
        zones::T13_ZONE_VERIFIER_RUNTIME,
    };
    use tempo_evm::{TempoBlockEnv, TempoEvmFactory};
    use tempo_revm::TempoTxEnv;

    fn test_tempo_precompiles(cfg_env: &CfgEnv<TempoHardfork>) -> PrecompilesMap {
        tempo_precompiles(
            cfg_env,
            StorageActions::disabled(),
            Rc::new(RefCell::new(NonCreditableSlots::empty())),
        )
    }

    #[test]
    fn test_precompile_delegatecall() {
        let cfg = CfgEnv::<TempoHardfork>::default();
        let precompile = tempo_precompile!("TIP20Token", &cfg, |input| {
            TIP20Token::from_address(PATH_USD_ADDRESS).expect("PATH_USD_ADDRESS is valid")
        });

        let db = InMemoryDB::default();
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
            reservoir: 0,
        };

        let result = AlloyEvmPrecompile::call(&precompile, input);

        match result {
            Ok(output) => {
                assert!(output.is_revert());
                let decoded = DelegateCallNotAllowed::abi_decode(&output.bytes).unwrap();
                assert!(matches!(decoded, DelegateCallNotAllowed {}));
            }
            Err(_) => panic!("expected reverted output"),
        }
    }

    #[test]
    fn test_precompile_static_calls() {
        for spec in [TempoHardfork::T11, TempoHardfork::T12] {
            let mut cfg = CfgEnv::<TempoHardfork>::default();
            cfg.spec = spec;
            let tx = TxEnv::default();
            let precompile = tempo_precompile!("TIP20Token", &cfg, |input| {
                TIP20Token::from_address(PATH_USD_ADDRESS).expect("PATH_USD_ADDRESS is valid")
            });

            let call_static = |calldata: Bytes| {
                let mut db = InMemoryDB::default();
                db.insert_account_info(
                    PATH_USD_ADDRESS,
                    AccountInfo {
                        code: Some(Bytecode::new_raw(bytes!("0xEF"))),
                        ..Default::default()
                    },
                );
                let mut evm = EthEvmFactory::default().create_evm(db, EvmEnv::default());
                let block = evm.block.clone();
                let internals = EvmInternals::new(evm.journal_mut(), &block, &cfg, &tx);

                AlloyEvmPrecompile::call(
                    &precompile,
                    PrecompileInput {
                        data: &calldata,
                        caller: Address::ZERO,
                        internals,
                        gas: 1_000_000,
                        is_static: true,
                        value: U256::ZERO,
                        target_address: PATH_USD_ADDRESS,
                        bytecode_address: PATH_USD_ADDRESS,
                        reservoir: 0,
                    },
                )
                .expect("precompile call should return a frame-local result")
            };

            // Static calls into mutating functions should fail
            for calldata in [
                ITIP20::transferCall {
                    to: Address::random(),
                    amount: U256::from(100),
                }
                .abi_encode(),
                ITIP20::approveCall {
                    spender: Address::random(),
                    amount: U256::from(100),
                }
                .abi_encode(),
            ] {
                let output = call_static(calldata.into());
                if spec.is_t12() {
                    assert!(output.is_halt());
                    assert!(output.bytes.is_empty());
                } else {
                    assert!(output.is_revert());
                    assert!(StaticCallNotAllowed::abi_decode(&output.bytes).is_ok());
                }
            }

            // Static calls into view functions should succeed
            let output = call_static(
                ITIP20::balanceOfCall {
                    account: Address::random(),
                }
                .abi_encode()
                .into(),
            );
            assert!(output.is_success());
        }
    }

    /// Verifies that early-return revert paths in precompile `call()` methods correctly
    /// report gas_used. When a TIP-20 precompile reverts before reaching `dispatch_call`
    /// (e.g., uninitialized token), the gas consumed for input decoding and account info
    /// checks must still be reported in the `PrecompileOutput.gas_used` field.
    #[test]
    fn test_early_return_revert_reports_gas_used() {
        let mut cfg = CfgEnv::<TempoHardfork>::default();
        cfg.set_spec_and_mainnet_gas_params(TempoHardfork::T10);
        let tx = TxEnv::default();
        let precompile = tempo_precompile!("TIP20Token", &cfg, |input| {
            TIP20Token::from_address(PATH_USD_ADDRESS).expect("PATH_USD_ADDRESS is valid")
        });

        let token_address = PATH_USD_ADDRESS;

        // NO bytecode set -- token is uninitialized, early revert before dispatch_call
        let db = InMemoryDB::default();
        let mut evm = EthEvmFactory::default().create_evm(db, EvmEnv::default());
        let block = evm.block.clone();
        let evm_internals = EvmInternals::new(evm.journal_mut(), &block, &cfg, &tx);

        let calldata = Bytes::from(
            ITIP20::transferCall {
                to: Address::random(),
                amount: U256::from(100),
            }
            .abi_encode(),
        );

        let input = PrecompileInput {
            data: &calldata,
            caller: Address::ZERO,
            internals: evm_internals,
            gas: 1_000_000,
            is_static: false,
            value: U256::ZERO,
            target_address: token_address,
            bytecode_address: token_address,
            reservoir: 0,
        };

        let result = AlloyEvmPrecompile::call(&precompile, input);
        let output = result.expect("expected Ok");
        assert!(
            output.status.is_revert(),
            "uninitialized token should revert"
        );
        // Include calldata and account-loading costs in the revert.
        assert!(
            output.gas_used > 0,
            "early-return revert should report non-zero gas_used, got {}",
            output.gas_used
        );
    }

    #[test]
    fn test_invalid_calldata_reverts() {
        let call = |calldata: Bytes| {
            let mut cfg = CfgEnv::<TempoHardfork>::default();
            cfg.set_spec_and_mainnet_gas_params(TempoHardfork::T10);
            let tx = TxEnv::default();
            let precompile = tempo_precompile!("TIP20Token", &cfg, |input| {
                TIP20Token::from_address(PATH_USD_ADDRESS).expect("PATH_USD_ADDRESS is valid")
            });

            let mut db = InMemoryDB::default();
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
                reservoir: 0,
            };

            AlloyEvmPrecompile::call(&precompile, input)
        };

        let empty = call(Bytes::new()).expect("missing selector should revert");
        assert!(empty.is_revert());
        assert!(empty.bytes.is_empty());
        assert!(empty.gas_used > 0);

        let unknown = call(Bytes::from([0xAA; 4])).expect("unknown selector should revert");
        assert!(unknown.is_revert());

        let decoded = UnknownFunctionSelector::abi_decode(&unknown.bytes)
            .expect("expected UnknownFunctionSelector error");
        assert_eq!(decoded.selector.as_slice(), &[0xAA, 0xAA, 0xAA, 0xAA]);

        assert!(unknown.gas_used >= empty.gas_used);
    }

    /// T4+ precompile `state_gas_used` must only include state-creating gas (cold SSTORE
    /// zero->non-zero), not all gas consumed. A read-only operation like `balanceOf` must
    /// have `state_gas_used == 0` even though `gas_used > 0`.
    #[test]
    fn test_t4_state_gas_only_includes_state_creating_ops() {
        let mut cfg = CfgEnv::<TempoHardfork>::default();
        cfg.set_spec_and_mainnet_gas_params(TempoHardfork::T10);

        let sender = Address::repeat_byte(0x01);
        let recipient = Address::repeat_byte(0x02);

        let precompile = tempo_precompile!("TIP20Token", &cfg, |input| {
            TIP20Token::from_address(PATH_USD_ADDRESS).expect("PATH_USD_ADDRESS is valid")
        });

        let db = InMemoryDB::default();
        let mut evm = EthEvmFactory::default().create_evm(db, EvmEnv::default());

        // Set up TIP20 token state: initialize pathUSD and mint tokens to sender
        {
            let block = evm.block.clone();
            let tx = TxEnv::default();
            let internals = EvmInternals::new(evm.journal_mut(), &block, &cfg, &tx);
            let mut provider =
                crate::storage::evm::EvmPrecompileStorageProvider::new_max_gas(internals, &cfg);
            crate::storage::StorageCtx::enter(&mut provider, || {
                crate::test_util::TIP20Setup::path_usd(sender)
                    .with_issuer(sender)
                    .with_mint(sender, U256::from(1000))
                    .apply()
            })
            .expect("TIP20 setup should succeed");
        }

        // 1) Read-only: balanceOf must have state_gas_used == 0
        let calldata: Bytes = ITIP20::balanceOfCall { account: sender }
            .abi_encode()
            .into();
        let block = evm.block.clone();
        let tx = TxEnv::default();
        let evm_internals = EvmInternals::new(evm.journal_mut(), &block, &cfg, &tx);
        let input = PrecompileInput {
            data: &calldata,
            caller: sender,
            internals: evm_internals,
            gas: 1_000_000,
            is_static: false,
            value: U256::ZERO,
            target_address: PATH_USD_ADDRESS,
            bytecode_address: PATH_USD_ADDRESS,
            reservoir: 0,
        };
        let output =
            AlloyEvmPrecompile::call(&precompile, input).expect("balanceOf should succeed");
        assert!(output.is_success());
        assert!(output.gas_used > 0, "balanceOf should consume gas");
        assert_eq!(
            output.state_gas_used, 0,
            "read-only balanceOf must have state_gas_used == 0, got {}",
            output.state_gas_used
        );

        // 2) Transfer to existing account (warm SSTORE, not zero->non-zero for recipient
        //    since we pre-fund recipient): state_gas_used must be less than gas_used
        {
            // Pre-fund recipient so the transfer is warm SSTORE (nonzero->nonzero)
            let block = evm.block.clone();
            let tx = TxEnv::default();
            let internals = EvmInternals::new(evm.journal_mut(), &block, &cfg, &tx);
            let mut provider =
                crate::storage::evm::EvmPrecompileStorageProvider::new_max_gas(internals, &cfg);
            crate::storage::StorageCtx::enter(&mut provider, || {
                crate::test_util::TIP20Setup::path_usd(sender)
                    .with_mint(recipient, U256::ONE)
                    .apply()
            })
            .expect("TIP20 setup should succeed");
        }
        let calldata: Bytes = ITIP20::transferCall {
            to: recipient,
            amount: U256::from(100),
        }
        .abi_encode()
        .into();
        let block = evm.block.clone();
        let tx = TxEnv::default();
        let evm_internals = EvmInternals::new(evm.journal_mut(), &block, &cfg, &tx);
        let input = PrecompileInput {
            data: &calldata,
            caller: sender,
            internals: evm_internals,
            gas: 1_000_000,
            is_static: false,
            value: U256::ZERO,
            target_address: PATH_USD_ADDRESS,
            bytecode_address: PATH_USD_ADDRESS,
            reservoir: 0,
        };
        let output = AlloyEvmPrecompile::call(&precompile, input).expect("transfer should succeed");
        assert!(output.is_success());
        assert!(output.gas_used > 0, "transfer should consume gas");
        assert_eq!(
            output.state_gas_used, 0,
            "transfer to existing account (nonzero->nonzero SSTORE) must have state_gas_used == 0, got {}",
            output.state_gas_used
        );
    }

    #[test]
    fn test_dispatch_macro_applies_hardfork_selector_gates() -> eyre::Result<()> {
        alloy::sol! {
            interface ISelectorGatedTest {
                function added(uint256 value) external;
                function removed() external;
            }
        }
        for spec in [TempoHardfork::T10, TempoHardfork::T11, TempoHardfork::T12] {
            let mut storage = HashMapStorageProvider::new_with_spec(1, spec);
            for (calldata, active) in [
                (
                    ISelectorGatedTest::addedCall { value: U256::ZERO }.abi_encode(),
                    spec.is_t11(),
                ),
                (
                    ISelectorGatedTest::removedCall {}.abi_encode(),
                    !spec.is_t12(),
                ),
            ] {
                let output = StorageCtx::enter(&mut storage, || {
                    dispatch!(
                        &calldata,
                        |call| match call {
                            ISelectorGatedTest::ISelectorGatedTestCalls {
                                #[schedule(since = T11)]
                                added(_) => Ok(PrecompileOutput::new(0, Bytes::new(), 0)),
                                #[schedule(until = T12)]
                                removed(_) => Ok(PrecompileOutput::new(0, Bytes::new(), 0)),
                            }
                        }
                    )
                })?;
                assert_eq!(output.is_success(), active);
                if !active {
                    let decoded = UnknownFunctionSelector::abi_decode(&output.bytes)?;
                    assert_eq!(decoded.selector.as_slice(), &calldata[..4]);
                }
            }
        }
        Ok(())
    }

    #[test]
    fn test_input_cost_schedule() {
        // Empty input should cost 0
        assert_eq!(input_cost(TempoHardfork::T10, 0).unwrap(), 0);
        assert_eq!(input_cost(TempoHardfork::T11, 0).unwrap(), 0);

        // 1 byte rounds up to 1 word.
        assert_eq!(input_cost(TempoHardfork::T10, 1).unwrap(), 6);

        // 32 bytes is 1 word.
        assert_eq!(input_cost(TempoHardfork::T10, 32).unwrap(), 6);

        // 33 bytes rounds up to 2 words.
        assert_eq!(input_cost(TempoHardfork::T10, 33).unwrap(), 12);

        // T11 increases the input charge to 30 gas per word.
        assert_eq!(input_cost(TempoHardfork::T11, 1).unwrap(), 30);
        assert_eq!(input_cost(TempoHardfork::T11, 32).unwrap(), 30);
        assert_eq!(input_cost(TempoHardfork::T11, 33).unwrap(), 60);
    }

    #[test]
    fn test_dedup_cost_schedule() {
        assert_eq!(dedup_cost(TempoHardfork::T10, 65_536).unwrap(), 0);
        assert_eq!(dedup_cost(TempoHardfork::T11, 0).unwrap(), 0);
        assert_eq!(dedup_cost(TempoHardfork::T11, 65_536).unwrap(), 1_310_720);
    }

    #[test]
    fn test_extend_tempo_precompiles_registers_precompiles() {
        let precompiles = test_tempo_precompiles(&CfgEnv::<TempoHardfork>::default());
        for address in [
            TIP20_FACTORY_ADDRESS,
            TIP20_CHANNEL_RESERVE_ADDRESS,
            ADDRESS_REGISTRY_ADDRESS,
            TIP403_REGISTRY_ADDRESS,
            TIP_FEE_MANAGER_ADDRESS,
            STABLECOIN_DEX_ADDRESS,
            NONCE_PRECOMPILE_ADDRESS,
            VALIDATOR_CONFIG_ADDRESS,
            VALIDATOR_CONFIG_V2_ADDRESS,
            ACCOUNT_KEYCHAIN_ADDRESS,
            SIGNATURE_VERIFIER_ADDRESS,
            RECEIVE_POLICY_GUARD_ADDRESS,
            STORAGE_CREDITS_ADDRESS,
            CURRENT_COMMITTEE_ADDRESS,
            ZONE_FACTORY_ADDRESS,
            PATH_USD_ADDRESS,
            Address::from_word(U256::from(256).into()),
        ] {
            assert!(precompiles.get(&address).is_some(), "{address}");
        }
        assert!(precompiles.get(&Address::random()).is_none());
    }

    #[test]
    fn test_zone_factory_registration() {
        let mut t10 = CfgEnv::<TempoHardfork>::default();
        t10.set_spec_and_mainnet_gas_params(TempoHardfork::T10);
        let precompiles = test_tempo_precompiles(&t10);
        assert!(
            precompiles.get(&ZONE_FACTORY_ADDRESS).is_some(),
            "ZoneFactory should be registered at T10"
        );
        assert!(
            precompiles.get(&zone_factory::portal_address(1)).is_none(),
            "ZonePortal storage handles must not be registered as precompiles"
        );
    }

    #[test]
    fn test_zone_verifier_registered_at_t13_only() {
        let activation = SYSTEM_PRECOMPILES
            .iter()
            .find_map(|(address, fork)| (*address == ZONE_VERIFIER_ADDRESS).then_some(*fork))
            .expect("ZoneVerifier must be listed in SYSTEM_PRECOMPILES");
        assert_eq!(activation, TempoHardfork::T13);

        for (spec, active) in [
            (TempoHardfork::T10, false),
            (TempoHardfork::T11, false),
            (TempoHardfork::T12, false),
            (TempoHardfork::T13, true),
        ] {
            let mut cfg = CfgEnv::<TempoHardfork>::default();
            cfg.set_spec_and_mainnet_gas_params(spec);
            assert_eq!(
                test_tempo_precompiles(&cfg)
                    .get(&ZONE_VERIFIER_ADDRESS)
                    .is_some(),
                active,
                "unexpected native ZoneVerifier activation at {spec:?}"
            );
        }
    }

    #[test]
    fn test_zone_verifier_runtime_is_shadowed_at_t13() {
        let calldata = IZoneVerifier::verifyCall {
            zoneId: 1,
            tempoBlockNumber: 1,
            anchorBlockNumber: 1,
            anchorBlockHash: B256::ZERO,
            expectedWithdrawalBatchIndex: 0,
            nextZoneHeight: U256::ZERO,
            blockTransition: IZoneVerifier::BlockTransition {
                prevBlockHash: B256::ZERO,
                nextBlockHash: B256::ZERO,
            },
            depositQueueTransition: IZoneVerifier::DepositQueueTransition {
                prevProcessedHash: B256::ZERO,
                nextProcessedHash: B256::ZERO,
                prevDepositNumber: 0,
                nextDepositNumber: 0,
            },
            tokenEnablementTransition: IZoneVerifier::TokenEnablementTransition {
                prevProcessedTokenCount: 0,
                nextProcessedTokenCount: 0,
            },
            withdrawalQueueHash: B256::ZERO,
            verifierConfig: Bytes::new(),
            proof: Bytes::new(),
        }
        .abi_encode();

        let execute = |spec| {
            let mut cfg = CfgEnv::<TempoHardfork>::default();
            cfg.set_spec_and_mainnet_gas_params(spec);
            // Use a runtime with the matching ABI to isolate the native dispatch boundary.
            let code = Bytecode::new_legacy(T13_ZONE_VERIFIER_RUNTIME);
            let mut db = InMemoryDB::default();
            db.insert_account_info(
                ZONE_VERIFIER_ADDRESS,
                AccountInfo {
                    code_hash: code.hash_slow(),
                    code: Some(code),
                    ..Default::default()
                },
            );
            let mut evm = TempoEvmFactory::default().create_evm(
                db,
                EvmEnv {
                    cfg_env: cfg,
                    block_env: TempoBlockEnv::default(),
                },
            );
            let result = evm
                .transact_raw(TempoTxEnv {
                    inner: TxEnv {
                        caller: Address::repeat_byte(0x77),
                        gas_price: 0,
                        gas_limit: 1_000_000,
                        kind: TxKind::Call(ZONE_VERIFIER_ADDRESS),
                        data: calldata.clone().into(),
                        ..Default::default()
                    },
                    is_system_tx: true,
                    ..Default::default()
                })
                .unwrap();
            let revm::context::result::ExecutionResult::Success {
                output: revm::context::result::Output::Call(output),
                ..
            } = result.result
            else {
                panic!("unexpected Zone verifier result: {:?}", result.result);
            };
            IZoneVerifier::verifyCall::abi_decode_returns(&output).unwrap()
        };

        assert!(execute(TempoHardfork::T10));
        assert!(execute(TempoHardfork::T11));
        assert!(execute(TempoHardfork::T12));
        assert!(!execute(TempoHardfork::T13));
    }
}
