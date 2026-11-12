//! Tempo precompile implementations.
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod error;
pub use error::{EncodePrecompileResult, IntoPrecompileResult, Result};

pub mod storage;

pub mod dispatch;
pub use dispatch::*;

pub(crate) mod ip;

pub mod account_keychain;
pub mod address_registry;
pub mod configurable_account;
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
    configurable_account::ConfigurableAccount,
    current_committee::CurrentCommittee,
    nonce::NonceManager,
    receive_policy_guard::ReceivePolicyGuard,
    signature_verifier::SignatureVerifier,
    stablecoin_dex::StablecoinDEX,
    storage::{
        StorageCtx,
        actions::StorageActions,
        evm::{EvmPrecompileStorageProvider, EvmStorageExt, Frame},
    },
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
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_primitives::{TempoAddressExt, TempoBlockExt};

#[cfg(test)]
use alloy::sol_types::SolInterface;
use alloy::{primitives::Address, sol, sol_types::SolError};
#[cfg(test)]
use evm2::precompiles::PrecompileHalt;
use evm2::{
    Evm, EvmTypes, EvmTypesHost, Precompiles as BasePrecompiles, SpecId,
    evm::{PrewarmSet, precompile::PrecompileProvider},
    interpreter::{GasTracker, Message, MessageKind},
    precompiles::{MovePrecompileError, PrecompileError, PrecompileId, PrecompileResult},
};

pub use tempo_contracts::precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, ADDRESS_REGISTRY_ADDRESS, CONFIGURABLE_ACCOUNT_ADDRESS,
    CURRENT_COMMITTEE_ADDRESS, DEFAULT_FEE_TOKEN, NONCE_PRECOMPILE_ADDRESS, PATH_USD_ADDRESS,
    RECEIVE_POLICY_GUARD_ADDRESS, SIGNATURE_VERIFIER_ADDRESS, STABLECOIN_DEX_ADDRESS,
    STORAGE_CREDITS_ADDRESS, SYSTEM_PRECOMPILES, TIP_FEE_MANAGER_ADDRESS,
    TIP20_CHANNEL_RESERVE_ADDRESS, TIP20_FACTORY_ADDRESS, TIP403_REGISTRY_ADDRESS,
    VALIDATOR_CONFIG_ADDRESS, VALIDATOR_CONFIG_V2_ADDRESS, ZONE_FACTORY_ADDRESS,
    ZONE_MESSENGER_ADDRESS, ZONE_PORTAL_IMPL_ADDRESS, ZONE_VERIFIER_ADDRESS,
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
    /// Business-logic errors are returned as EVM reverts with ABI-encoded error data, while
    /// fatal failures (e.g. out-of-gas) are returned as [`PrecompileError`]s.
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult;
}

sol! {
    error DelegateCallNotAllowed();
}

/// Tempo's built-in and protocol precompiles for EVM2.
#[derive(Debug)]
pub struct TempoPrecompiles<T: EvmTypesHost> {
    base: BasePrecompiles<T>,
    spec: TempoHardfork,
    actions: StorageActions,
    non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
    /// Nested calls from precompiles ([`StorageCtx::call`]) that are running, counted across
    /// the call frames of this provider and limited to
    /// [`MAX_NESTED_CALLS`](storage::evm::MAX_NESTED_CALLS).
    nested_calls: Rc<Cell<u16>>,
}

impl<T: EvmTypesHost> TempoPrecompiles<T> {
    /// Creates the precompile provider for a Tempo hardfork.
    pub fn new(
        spec: TempoHardfork,
        actions: StorageActions,
        non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
    ) -> Self {
        // Tempo used Prague's built-ins before T1C and follows its configured EVM fork after it.
        let base_spec = if spec.is_t1c() {
            spec.into()
        } else {
            SpecId::PRAGUE
        };
        Self {
            base: BasePrecompiles::base(base_spec),
            spec,
            actions,
            non_creditable_slots,
            nested_calls: Rc::default(),
        }
    }

    /// Dispatches to the Tempo precompile at `address`. Takes no `self`, so that the precompile
    /// cannot reach the provider while a nested call re-enters it. That alone does not make the
    /// re-entry sound: see [`Self::execute_in_frame`].
    fn call_tempo(address: Address, calldata: &[u8], caller: Address) -> PrecompileResult {
        if address.is_tip20() {
            TIP20Token::from_address(address)
                .expect("TIP-20 prefix already checked")
                .call(calldata, caller)
        } else if address == TIP20_FACTORY_ADDRESS {
            TIP20Factory::new().call(calldata, caller)
        } else if address == TIP20_CHANNEL_RESERVE_ADDRESS {
            TIP20ChannelReserve::new().call(calldata, caller)
        } else if address == ADDRESS_REGISTRY_ADDRESS {
            AddressRegistry::new().call(calldata, caller)
        } else if address == TIP403_REGISTRY_ADDRESS {
            TIP403Registry::new().call(calldata, caller)
        } else if address == TIP_FEE_MANAGER_ADDRESS {
            TipFeeManager::new().call(calldata, caller)
        } else if address == STABLECOIN_DEX_ADDRESS {
            StablecoinDEX::new().call(calldata, caller)
        } else if address == NONCE_PRECOMPILE_ADDRESS {
            NonceManager::new().call(calldata, caller)
        } else if address == CONFIGURABLE_ACCOUNT_ADDRESS {
            ConfigurableAccount::new().call(calldata, caller)
        } else if address == VALIDATOR_CONFIG_ADDRESS {
            ValidatorConfig::new().call(calldata, caller)
        } else if address == ACCOUNT_KEYCHAIN_ADDRESS {
            AccountKeychain::new().call(calldata, caller)
        } else if address == VALIDATOR_CONFIG_V2_ADDRESS {
            ValidatorConfigV2::new().call(calldata, caller)
        } else if address == SIGNATURE_VERIFIER_ADDRESS {
            SignatureVerifier::new().call(calldata, caller)
        } else if address == RECEIVE_POLICY_GUARD_ADDRESS {
            ReceivePolicyGuard::new().call(calldata, caller)
        } else if address == STORAGE_CREDITS_ADDRESS {
            StorageCredits::new().call(calldata, caller)
        } else if address == CURRENT_COMMITTEE_ADDRESS {
            CurrentCommittee::new().call(calldata, caller)
        } else if address == ZONE_FACTORY_ADDRESS {
            ZoneFactory::new().call(calldata, caller)
        } else if address == ZONE_VERIFIER_ADDRESS {
            ZoneVerifier::new().call(calldata, caller)
        } else {
            unreachable!("Tempo precompile address checked before dispatch")
        }
    }
}

impl<T> TempoPrecompiles<T>
where
    T: EvmTypes<BlockEnvExt = TempoBlockExt>,
    T::EvmExt: EvmStorageExt,
{
    /// Runs `precompile` on the input of `message`, in a storage context over the call frame of
    /// `message`.
    ///
    /// # Re-entrancy
    ///
    /// A precompile's nested call ([`StorageCtx::call`]) can reach a Tempo precompile again.
    /// evm2 then derives a second `&mut` to this provider from its own pointer and calls
    /// [`PrecompileProvider::execute`] on it while the outer call is still in this method. The
    /// Tempo path therefore runs through `&self`: it cannot write to the provider or borrow a
    /// field mutably, and everything `precompile` needs is copied or cloned out of `self` before
    /// it runs.
    fn execute_in_frame(
        &self,
        evm: &mut Evm<'_, T>,
        message: &Message<T>,
        gas: &mut GasTracker,
        precompile: impl FnOnce(&[u8]) -> PrecompileResult,
    ) -> PrecompileResult {
        let is_static = message.caller_is_static || message.kind == MessageKind::StaticCall;
        // Input may borrow the caller's memory, so resolve it before storage borrows the EVM.
        let input = evm.message_input(message).to_vec();
        let mut storage = EvmPrecompileStorageProvider::new(evm, gas, self.spec, is_static)
            .with_actions(self.actions.clone())
            .with_non_creditable_slots(self.non_creditable_slots.clone())
            .with_frame(Frame {
                address: message.call_target,
                depth: message.depth,
                nested_calls: self.nested_calls.clone(),
            });
        let result = StorageCtx::enter(&mut storage, || precompile(&input));
        // A halt already takes all gas, and a fatal error must stay one.
        if storage.gas_overdrawn() && matches!(result, Ok(_) | Err(PrecompileError::Revert(_))) {
            return error::TempoPrecompileError::OutOfGas.into_precompile_result();
        }
        result
    }
}

impl<T> PrecompileProvider<T> for TempoPrecompiles<T>
where
    T: EvmTypes<BlockEnvExt = TempoBlockExt>,
    T::EvmExt: EvmStorageExt,
{
    fn move_precompiles(
        &mut self,
        moves: &[(Address, Address)],
    ) -> std::result::Result<(), MovePrecompileError> {
        self.base.move_precompiles(moves)
    }

    fn addresses(&self) -> Vec<Address> {
        self.base.addresses()
    }

    fn warm_addresses(&self, warm: &mut PrewarmSet) {
        self.base.warm_addresses(warm);
    }

    fn precompile_ids(&self) -> Vec<(Address, PrecompileId)> {
        self.base.precompile_ids()
    }

    fn contains(&self, address: &Address) -> bool {
        self.base.contains(address) || address.is_precompile(self.spec)
    }

    fn execute(
        &mut self,
        evm: &mut Evm<'_, T>,
        message: &Message<T>,
        gas: &mut GasTracker,
    ) -> Option<PrecompileResult> {
        // `contains` checks short addresses without hashing, so Tempo calls skip the map lookup.
        if self.base.contains(&message.call_target) {
            return self.base.execute(evm, message, gas);
        }
        // Dispatch on the requested callee like evm2's membership check: code stored at a
        // precompile address, such as EIP-7702 delegation code from a state override, never
        // replaces the native precompile.
        if !message.call_target.is_precompile(self.spec) {
            return None;
        }
        if message.destination != message.call_target {
            return Some(Err(PrecompileError::Revert(
                DelegateCallNotAllowed {}.abi_encode().into(),
            )));
        }

        // A nested call re-enters this method, so the Tempo path only reads the provider.
        Some(self.execute_in_frame(evm, message, gas, |input| {
            Self::call_tempo(message.call_target, input, message.caller)
        }))
    }
}

/// Asserts that `result` is a reverted output whose bytes decode to `expected_error`.
#[cfg(test)]
pub fn expect_precompile_revert<E>(result: &PrecompileResult, expected_error: E)
where
    E: SolInterface + PartialEq + std::fmt::Debug,
{
    match result {
        Err(PrecompileError::Revert(bytes)) => {
            let decoded = E::abi_decode(bytes).unwrap();
            assert_eq!(decoded, expected_error);
        }
        other => {
            panic!("expected reverted output, got: {other:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::{EncodePrecompileResult, TempoPrecompileError},
        storage::{
            CallOutcome, PrecompileStorageProvider, StorageCtx, evm::MAX_NESTED_CALLS,
            hashmap::HashMapStorageProvider,
        },
    };
    use alloy::{
        primitives::{Bytes, U256, address, bytes, hex},
        sol_types::SolCall,
    };
    use evm2::{
        BaseEvmConfigSelector, ExecutionConfig, Inspector,
        bytecode::Bytecode,
        evm::{
            AccountInfo, InMemoryDB,
            precompile::{NoPrecompiles, PrecompileOutput, PrecompileProvider},
        },
        interpreter::{Host, InstrStop, Interpreter, MessageResult},
        registry::TxRegistry,
        version::GasId,
    };
    use std::{
        panic::{self, AssertUnwindSafe},
        thread,
    };
    use tempo_contracts::precompiles::{ITIP20, UnknownFunctionSelector};
    use tempo_primitives::{TempoBlockEnv, TempoBlockExt};

    /// TIP-20 prefixed address at which [`WithNestedCaller`] runs [`nested_caller`].
    const NESTED_CALLER_ADDRESS: Address = address!("0x20c000000000000000000000ffffffffffffffff");
    /// Contract that forwards its calldata to [`NESTED_CALLER_ADDRESS`], see [`forwarder_code`].
    const FORWARDER: Address = Address::repeat_byte(0xf0);
    /// Contract that changes its storage when called, with code the tests pick.
    const STATE_CHANGER: Address = Address::repeat_byte(0xc5);
    /// [`nested_caller`] calldata that makes no nested call, and makes the forwarder revert.
    const LEAF: u8 = 1;
    /// [`nested_caller`] calldata that calls the caller back with [`LEAF`].
    const CALL_BACK: u8 = 2;
    /// [`nested_caller`] calldata that calls the caller back with the same calldata.
    const RECURSE: u8 = 3;
    /// [`nested_caller`] calldata that calls the caller back, then fails.
    const FAIL_AFTER_CALL: u8 = 4;
    /// [`nested_caller`] calldata that calls the caller back and writes a slot, then rolls both
    /// back with a checkpoint.
    const ROLL_BACK_CALL: u8 = 5;
    /// [`nested_caller`] calldata that fails with a fatal error.
    const FATAL: u8 = 6;
    /// [`nested_caller`] calldata that panics.
    const PANIC: u8 = 7;

    struct TestTypes;

    impl EvmTypesHost for TestTypes {
        type ConfigSelector = BaseEvmConfigSelector;
        type SpecId = SpecId;
        type Tx = ();
        type EvmExt = ();
        type MessageExt = ();
        type MessageResultExt = ();
        type TxEnvExt = ();
        type TxResultExt = ();
        type BlockEnvExt = TempoBlockExt;
        type Host<'a> = Evm<'a, Self>;
    }

    fn test_tempo_precompiles(spec: TempoHardfork) -> TempoPrecompiles<TestTypes> {
        TempoPrecompiles::new(
            spec,
            StorageActions::disabled(),
            Rc::new(RefCell::new(NonCreditableSlots::empty())),
        )
    }

    fn test_evm(spec: TempoHardfork, initialized_token: bool) -> Evm<'static, TestTypes> {
        test_evm_with_amsterdam(spec, initialized_token, false)
    }

    fn test_evm_with_amsterdam(
        spec: TempoHardfork,
        initialized_token: bool,
        amsterdam_eip8037_enabled: bool,
    ) -> Evm<'static, TestTypes> {
        let mut database = InMemoryDB::default();
        if initialized_token {
            database.insert_account_info(
                &PATH_USD_ADDRESS,
                AccountInfo::default().with_code(Bytecode::new_raw(bytes!("0xEF"))),
            );
        }
        let version =
            tempo_chainspec::gas_params::version(SpecId::OSAKA, spec, amsterdam_eip8037_enabled);
        Evm::new_with_execution_config(
            ExecutionConfig::for_spec_and_version(SpecId::OSAKA, version),
            SpecId::OSAKA,
            TempoBlockEnv::default(),
            TxRegistry::new(),
            database,
            NoPrecompiles::default(),
        )
    }

    fn call_tempo(
        spec: TempoHardfork,
        calldata: Bytes,
        kind: MessageKind,
        destination: Address,
        code_address: Address,
        initialized_token: bool,
    ) -> (PrecompileResult, GasTracker) {
        let mut evm = test_evm(spec, initialized_token);
        call_tempo_on(
            &mut evm,
            spec,
            calldata,
            kind,
            destination,
            code_address,
            Address::ZERO,
        )
    }

    fn call_tempo_on(
        evm: &mut Evm<'_, TestTypes>,
        spec: TempoHardfork,
        calldata: Bytes,
        kind: MessageKind,
        destination: Address,
        code_address: Address,
        caller: Address,
    ) -> (PrecompileResult, GasTracker) {
        let mut precompiles = test_tempo_precompiles(spec);
        let message = Message::<TestTypes> {
            kind,
            gas_limit: 1_000_000,
            destination,
            call_target: code_address,
            code_address,
            input: calldata.into(),
            caller,
            ..Default::default()
        };
        let mut gas = GasTracker::new(message.gas_limit);
        let result = precompiles
            .execute(evm, &message, &mut gas)
            .expect("Tempo precompile must be registered");
        (result, gas)
    }

    #[test]
    fn test_precompile_dispatches_on_call_target_over_delegation_code() {
        // Delegation code on a precompile address, which a state override can set, does not
        // replace the precompile: dispatch uses the called address.
        let delegate = Address::repeat_byte(0xd1);
        let mut evm = test_evm(TempoHardfork::T3, true);
        let mut precompiles = test_tempo_precompiles(TempoHardfork::T3);
        let message = Message::<TestTypes> {
            gas_limit: 1_000_000,
            destination: PATH_USD_ADDRESS,
            call_target: PATH_USD_ADDRESS,
            code_address: delegate,
            code: Bytecode::new_eip7702(delegate),
            input: Bytes::new().into(),
            ..Default::default()
        };
        assert!(precompiles.contains(&message.call_target));
        let mut gas = GasTracker::new(message.gas_limit);
        let result = precompiles
            .execute(&mut evm, &message, &mut gas)
            .expect("the precompile at the called address must run");
        assert!(matches!(result, Err(PrecompileError::Revert(_))));

        // A delegatecall to it is still rejected.
        let message = Message::<TestTypes> {
            kind: MessageKind::DelegateCall,
            destination: Address::repeat_byte(0xca),
            ..message
        };
        let mut gas = GasTracker::new(message.gas_limit);
        let result = precompiles.execute(&mut evm, &message, &mut gas).unwrap();
        match result {
            Err(PrecompileError::Revert(output)) => {
                DelegateCallNotAllowed::abi_decode(&output).unwrap();
            }
            other => panic!("expected DelegateCallNotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn test_precompile_delegatecall() {
        let (result, _) = call_tempo(
            TempoHardfork::T3,
            Bytes::new(),
            MessageKind::DelegateCall,
            Address::random(),
            PATH_USD_ADDRESS,
            true,
        );

        match result {
            Err(PrecompileError::Revert(output)) => {
                let decoded = DelegateCallNotAllowed::abi_decode(&output).unwrap();
                assert!(matches!(decoded, DelegateCallNotAllowed {}));
            }
            _ => panic!("expected reverted output"),
        }
    }

    #[test]
    fn test_precompile_static_calls() {
        for spec in [TempoHardfork::T11, TempoHardfork::T12] {
            let call_static = |calldata: Bytes| {
                call_tempo(
                    spec,
                    calldata,
                    MessageKind::StaticCall,
                    PATH_USD_ADDRESS,
                    PATH_USD_ADDRESS,
                    true,
                )
                .0
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
                let result = call_static(calldata.into());
                if spec.is_t12() {
                    assert!(matches!(
                        result,
                        Err(PrecompileError::Halt(PrecompileHalt::Other(_)))
                    ));
                } else {
                    let Err(PrecompileError::Revert(output)) = result else {
                        panic!("expected reverted output");
                    };
                    assert!(StaticCallNotAllowed::abi_decode(&output).is_ok());
                }
            }

            // Static calls into view functions should succeed
            let result = call_static(
                ITIP20::balanceOfCall {
                    account: Address::random(),
                }
                .abi_encode()
                .into(),
            );
            assert!(
                result.is_ok(),
                "view function should succeed in static context"
            );
        }
    }

    #[test]
    fn test_nested_call_reenters_tempo_precompile() {
        let spec = TempoHardfork::T2;
        let mut evm = test_evm(spec, true);
        evm.set_precompiles(test_tempo_precompiles(spec));
        let mut gas = GasTracker::new(1_000_000);
        let mut storage = EvmPrecompileStorageProvider::new(&mut evm, &mut gas, spec, false)
            .with_frame(Frame {
                address: TIP20_FACTORY_ADDRESS,
                depth: 0,
                nested_calls: Rc::default(),
            });
        let calldata = ITIP20::balanceOfCall {
            account: Address::ZERO,
        }
        .abi_encode();

        // The callee enters its own storage context while the factory's stays borrowed.
        let outcome = StorageCtx::enter(&mut storage, || {
            assert!(StorageCtx.can_call());
            StorageCtx.call(PATH_USD_ADDRESS, calldata.into(), 500_000, true)
        });
        assert_eq!(
            outcome,
            Ok(CallOutcome::Success(U256::ZERO.to_be_bytes_vec().into()))
        );
        assert!(gas.spent() > 0);
    }

    /// Test precompile that counts its calls in slot 0, then calls its caller back as the first
    /// calldata byte says. Returns the count as read after that call, then the callee's output.
    fn nested_caller(calldata: &[u8], caller: Address) -> PrecompileResult {
        fn run(mut storage: StorageCtx, calldata: &[u8], caller: Address) -> Result<Bytes> {
            let mode = calldata.first().copied();
            let count = storage.sload(NESTED_CALLER_ADDRESS, U256::ZERO)?;
            storage.sstore(NESTED_CALLER_ADDRESS, U256::ZERO, count + U256::ONE)?;
            let input = match mode {
                Some(CALL_BACK) => Bytes::from_static(&[LEAF]),
                Some(RECURSE) => Bytes::copy_from_slice(calldata),
                Some(FAIL_AFTER_CALL | ROLL_BACK_CALL) => Bytes::new(),
                Some(FATAL) => return Err(TempoPrecompileError::Fatal("fatal mode".to_string())),
                Some(PANIC) => panic!("panic mode"),
                _ => return Ok(Bytes::new()),
            };
            let checkpoint = (mode == Some(ROLL_BACK_CALL)).then(|| storage.checkpoint());
            let outcome = storage.call(caller, input, u64::MAX, false)?;
            if mode == Some(FAIL_AFTER_CALL) {
                // The callee's changes and gas are this frame's until it fails.
                assert_eq!(outcome, CallOutcome::Success(Bytes::new()));
                assert_eq!(storage.sload(caller, U256::ONE)?, U256::ONE);
                assert!(storage.gas_refunded() > 0);
                return Err(TempoPrecompileError::under_overflow());
            }
            if let Some(checkpoint) = checkpoint {
                storage.sstore(NESTED_CALLER_ADDRESS, U256::ONE, U256::ONE)?;
                drop(checkpoint);
            }
            let (CallOutcome::Success(output) | CallOutcome::Failure(output)) = outcome;
            let count = storage.sload(NESTED_CALLER_ADDRESS, U256::ZERO)?;
            Ok([count.to_be_bytes_vec(), output.to_vec()].concat().into())
        }
        run(StorageCtx, calldata, caller).encode_precompile_result(|output| output)
    }

    /// [`TempoPrecompiles`] that also run [`nested_caller`] at [`NESTED_CALLER_ADDRESS`], in the
    /// call frame that the production dispatcher sets up.
    struct WithNestedCaller(TempoPrecompiles<TestTypes>);

    impl PrecompileProvider<TestTypes> for WithNestedCaller {
        fn precompile_ids(&self) -> Vec<(Address, PrecompileId)> {
            self.0.precompile_ids()
        }

        fn contains(&self, address: &Address) -> bool {
            self.0.contains(address)
        }

        fn move_precompiles(
            &mut self,
            moves: &[(Address, Address)],
        ) -> std::result::Result<(), MovePrecompileError> {
            self.0.move_precompiles(moves)
        }

        fn execute(
            &mut self,
            evm: &mut Evm<'_, TestTypes>,
            message: &Message<TestTypes>,
            gas: &mut GasTracker,
        ) -> Option<PrecompileResult> {
            if message.call_target != NESTED_CALLER_ADDRESS {
                return self.0.execute(evm, message, gas);
            }
            Some(self.0.execute_in_frame(evm, message, gas, |input| {
                nested_caller(input, message.caller)
            }))
        }
    }

    /// Bytecode of [`FORWARDER`]: calls [`NESTED_CALLER_ADDRESS`] with its own calldata, then
    /// reverts with its caller's address if the calldata is [`LEAF`] and returns the call's
    /// output otherwise.
    fn forwarder_code() -> Bytes {
        [
            // calldatacopy(0, 0, calldatasize)
            // call(gas, NESTED_CALLER_ADDRESS, 0, 0, calldatasize, 0, 0)
            hex!("365f5f375f5f365f5f73").as_slice(),
            NESTED_CALLER_ADDRESS.as_slice(),
            // if byte(0, calldataload(0)) == LEAF { mstore(0, caller); revert(0, 32) }
            // returndatacopy(0, 0, returndatasize); return(0, returndatasize)
            hex!("5af1505f355f1a6001146032573d5f5f3e3d5ff35b335f5260205ffd").as_slice(),
        ]
        .concat()
        .into()
    }

    /// A call message that [`CallRecorder`] saw.
    #[derive(Debug, PartialEq, Eq)]
    struct RecordedCall {
        depth: u16,
        caller: Address,
        callee: Address,
    }

    impl RecordedCall {
        fn new(depth: u16, caller: Address, callee: Address) -> Self {
            Self {
                depth,
                caller,
                callee,
            }
        }
    }

    /// Records every call message.
    #[derive(Default)]
    struct CallRecorder(Rc<RefCell<Vec<RecordedCall>>>);

    impl Inspector<TestTypes> for CallRecorder {
        fn call(
            &mut self,
            _interp: &mut Interpreter<'_, '_, TestTypes>,
            message: &mut Message<TestTypes>,
        ) -> Option<MessageResult<TestTypes>> {
            self.0.borrow_mut().push(RecordedCall::new(
                message.depth,
                message.caller,
                message.destination,
            ));
            None
        }
    }

    /// EVM whose precompiles are [`WithNestedCaller`], with the code of [`FORWARDER`] and, if any,
    /// of [`STATE_CHANGER`].
    fn nested_call_evm(
        spec: TempoHardfork,
        amsterdam_eip8037_enabled: bool,
        state_changer_code: Option<Bytes>,
    ) -> Evm<'static, TestTypes> {
        let mut evm = test_evm_with_amsterdam(spec, false, amsterdam_eip8037_enabled);
        evm.set_precompiles(WithNestedCaller(test_tempo_precompiles(spec)));
        let mut storage = EvmPrecompileStorageProvider::new_max_gas(&mut evm, spec);
        storage.set_code(FORWARDER, forwarder_code()).unwrap();
        if let Some(code) = state_changer_code {
            storage.set_code(STATE_CHANGER, code).unwrap();
        }
        drop(storage);
        evm
    }

    /// A top-level call from `caller` to `destination`, which runs `code`, with `mode` as calldata.
    fn mode_message(
        caller: Address,
        destination: Address,
        code: Bytes,
        mode: u8,
        gas_limit: u64,
    ) -> Message<TestTypes> {
        Message::<TestTypes> {
            gas_limit,
            caller,
            destination,
            call_target: destination,
            code_address: destination,
            code: Bytecode::new_raw(code),
            input: Bytes::from(vec![mode]).into(),
            ..Default::default()
        }
    }

    /// Reads the count of [`nested_caller`].
    fn nested_caller_count(evm: &mut Evm<'_, TestTypes>, spec: TempoHardfork) -> U256 {
        EvmPrecompileStorageProvider::new_max_gas(evm, spec)
            .sload(NESTED_CALLER_ADDRESS, U256::ZERO)
            .unwrap()
    }

    /// Calls [`FORWARDER`] with `mode` as a top-level message, under `recorder` if any. Returns
    /// the call's result and the final count of [`nested_caller`].
    fn call_forwarder(
        mode: u8,
        gas_limit: u64,
        recorder: Option<CallRecorder>,
    ) -> (MessageResult<TestTypes>, U256) {
        let spec = TempoHardfork::T2;
        let mut evm = nested_call_evm(spec, false, None);
        if let Some(recorder) = recorder {
            evm.set_inspector(recorder);
        }
        let mut message = mode_message(Address::ZERO, FORWARDER, forwarder_code(), mode, gas_limit);
        let result = evm.execute_message(&mut message).unwrap();
        let count = nested_caller_count(&mut evm, spec);
        (result, count)
    }

    /// Runs contract -> precompile -> contract -> precompile through [`TempoPrecompiles::execute`]
    /// and reverts the inner contract.
    #[test]
    fn test_nested_call_through_execute_reenters_precompile_and_rolls_back() {
        let calls = Rc::default();
        let recorder = CallRecorder(Rc::clone(&calls));
        let (result, count) = call_forwarder(CALL_BACK, 1_000_000, Some(recorder));
        assert!(result.is_success());

        // The callee saw the precompile as its caller, one level below the precompile's frame.
        assert_eq!(
            calls.take(),
            [
                RecordedCall::new(0, Address::ZERO, FORWARDER),
                RecordedCall::new(1, FORWARDER, NESTED_CALLER_ADDRESS),
                RecordedCall::new(2, NESTED_CALLER_ADDRESS, FORWARDER),
                RecordedCall::new(3, FORWARDER, NESTED_CALLER_ADDRESS),
            ]
        );
        // The inner precompile call's write was rolled back with the contract that made it, as
        // the outer precompile call saw when the contract returned.
        let expected = [
            U256::ONE.to_be_bytes::<32>(),
            NESTED_CALLER_ADDRESS.into_word().0,
        ];
        assert_eq!(result.output, Bytes::from(expected.concat()));
        assert_eq!(count, U256::ONE);
    }

    /// A precompile that a top-level message calls makes its nested call from depth 0, also with
    /// an inspector installed.
    #[test]
    fn test_top_level_precompile_makes_nested_call_under_inspector() {
        let spec = TempoHardfork::T2;
        let mut evm = nested_call_evm(spec, false, None);
        let calls = Rc::default();
        evm.set_inspector(CallRecorder(Rc::clone(&calls)));

        let mut message = mode_message(
            FORWARDER,
            NESTED_CALLER_ADDRESS,
            Bytes::new(),
            CALL_BACK,
            1_000_000,
        );
        let result = evm.execute_message(&mut message).unwrap();
        assert!(result.is_success());
        assert_eq!(
            calls.take(),
            [
                RecordedCall::new(0, FORWARDER, NESTED_CALLER_ADDRESS),
                RecordedCall::new(1, NESTED_CALLER_ADDRESS, FORWARDER),
                RecordedCall::new(2, FORWARDER, NESTED_CALLER_ADDRESS),
            ]
        );
        let expected = [
            U256::ONE.to_be_bytes::<32>(),
            NESTED_CALLER_ADDRESS.into_word().0,
        ];
        assert_eq!(result.output, Bytes::from(expected.concat()));
        assert_eq!(nested_caller_count(&mut evm, spec), U256::ONE);
    }

    /// A contract and a precompile that call each other until gas runs out stop nesting at
    /// [`MAX_NESTED_CALLS`]. Without the limit, this recursion overflows the 2 MiB stack.
    #[test]
    fn test_nested_call_recursion_stops_at_max_nested_calls() {
        for inspect in [false, true] {
            let (result, count) = thread::Builder::new()
                .stack_size(2 * 1024 * 1024)
                .spawn(move || {
                    let recorder = inspect.then(CallRecorder::default);
                    call_forwarder(RECURSE, 30_000_000, recorder)
                })
                .unwrap()
                .join()
                .unwrap();
            assert!(result.is_success());
            // The precompile runs once more than it nests calls. That run is refused its call
            // and reverts without data, so each run before it returns the count it left.
            assert_eq!(count, U256::from(MAX_NESTED_CALLS));
            let returned = count.to_be_bytes::<32>().repeat(MAX_NESTED_CALLS.into());
            assert_eq!(result.output, Bytes::from(returned));
        }
    }

    /// A precompile call that fails after its nested callee succeeded takes the callee's state,
    /// logs and gas down with it.
    #[test]
    fn test_precompile_failure_rolls_back_successful_nested_callee() {
        let spec = TempoHardfork::T4;
        // sstore(1, 1); sstore(0, 0); log0(0, 0); stop
        let code = bytes!("60016001555f5f555f5fa000");
        let mut evm = nested_call_evm(spec, true, Some(code));
        EvmPrecompileStorageProvider::new_max_gas(&mut evm, spec)
            .sstore(STATE_CHANGER, U256::ZERO, U256::from(7))
            .unwrap();
        // The slot that the callee clears predates the transaction, so clearing it is refunded.
        evm.state_mut().commit_transaction();
        evm.state_mut().clear_transaction_state();

        let reservoir = 1_000_000;
        let mut message = Message::<TestTypes> {
            reservoir,
            ..mode_message(
                STATE_CHANGER,
                NESTED_CALLER_ADDRESS,
                Bytes::new(),
                FAIL_AFTER_CALL,
                10_000_000,
            )
        };
        let result = evm.execute_message(&mut message).unwrap();
        assert_eq!(result.stop, InstrStop::Revert);
        assert_eq!(result.gas.refunded(), 0);
        assert_eq!(result.gas.state_gas_spent(), 0);
        assert_eq!(result.gas.reservoir(), reservoir);
        assert!(evm.logs().is_empty());
        let mut storage = EvmPrecompileStorageProvider::new_max_gas(&mut evm, spec);
        assert_eq!(
            storage.sload(STATE_CHANGER, U256::ZERO).unwrap(),
            U256::from(7)
        );
        assert_eq!(storage.sload(STATE_CHANGER, U256::ONE).unwrap(), U256::ZERO);
        assert_eq!(
            storage.sload(NESTED_CALLER_ADDRESS, U256::ZERO).unwrap(),
            U256::ZERO
        );
    }

    /// A precompile that rolls back a callee's state gas refill after spending it pays the refill
    /// back from its gas, and runs out of gas if it cannot.
    #[test]
    fn test_precompile_pays_back_rolled_back_refill_or_runs_out_of_gas() {
        let spec = TempoHardfork::T4;
        for (gas_limit, out_of_gas) in [(10_000_000, false), (100_000, true)] {
            // sstore(1, 0); stop
            let mut evm = nested_call_evm(spec, true, Some(bytes!("5f60015500")));
            let state_gas = evm.version().gas_params.get(GasId::SstoreSetState);
            // An earlier frame of the transaction creates the slot that the callee clears.
            EvmPrecompileStorageProvider::new_max_gas(&mut evm, spec)
                .sstore(STATE_CHANGER, U256::ONE, U256::ONE)
                .unwrap();

            // The reservoir covers the precompile's count, and the callee's refill its other slot.
            let mut message = Message::<TestTypes> {
                reservoir: state_gas,
                ..mode_message(
                    STATE_CHANGER,
                    NESTED_CALLER_ADDRESS,
                    Bytes::new(),
                    ROLL_BACK_CALL,
                    gas_limit,
                )
            };
            let result = evm.execute_message(&mut message).unwrap();
            if out_of_gas {
                assert_eq!(result.stop, InstrStop::PrecompileOOG);
                assert_eq!(result.gas.remaining(), 0);
            } else {
                // The checkpoint keeps the state gas of the precompile's rolled back slot, which
                // now comes out of its gas.
                assert!(result.is_success());
                assert_eq!(result.gas.state_gas_spent(), 2 * state_gas as i64);
                assert_eq!(result.gas.state_gas_spilled(), state_gas);
            }
            assert_eq!(nested_caller_count(&mut evm, spec), U256::from(!out_of_gas));
        }
    }

    /// The count of running nested calls is restored when the callee does not return a result.
    #[test]
    fn test_nested_call_count_is_restored_when_callee_errors_or_panics() {
        let spec = TempoHardfork::T2;
        let mut evm = nested_call_evm(spec, false, None);
        // A fatal error keeps the gas forwarded to the callee, so leave enough for both calls.
        let mut gas = GasTracker::new(u64::MAX);
        let nested_calls = Rc::new(Cell::new(3));
        let mut storage = EvmPrecompileStorageProvider::new(&mut evm, &mut gas, spec, false)
            .with_frame(Frame {
                address: TIP20_FACTORY_ADDRESS,
                depth: 0,
                nested_calls: Rc::clone(&nested_calls),
            });
        let mut call =
            |mode| storage.call(NESTED_CALLER_ADDRESS, vec![mode].into(), u64::MAX, false);

        assert!(matches!(call(FATAL), Err(TempoPrecompileError::Fatal(_))));
        assert_eq!(nested_calls.get(), 3);

        assert!(panic::catch_unwind(AssertUnwindSafe(|| call(PANIC))).is_err());
        assert_eq!(nested_calls.get(), 3);
    }

    /// Verifies that early-return revert paths in precompile `call()` methods correctly
    /// report gas used. When a TIP-20 precompile reverts before reaching `dispatch_call`
    /// (e.g., uninitialized token), the gas consumed for input decoding and account info
    /// checks must still be reported by the EVM2 gas tracker.
    #[test]
    fn test_early_return_revert_reports_gas_used() {
        // NO bytecode set -- token is uninitialized, early revert before dispatch_call
        let calldata = Bytes::from(
            ITIP20::transferCall {
                to: Address::random(),
                amount: U256::from(100),
            }
            .abi_encode(),
        );
        let (result, gas) = call_tempo(
            TempoHardfork::T1,
            calldata,
            MessageKind::Call,
            PATH_USD_ADDRESS,
            PATH_USD_ADDRESS,
            false,
        );
        assert!(
            matches!(result, Err(PrecompileError::Revert(_))),
            "uninitialized token should revert"
        );
        // Gas used should include input_cost(T1, 68) = 18 + with_account_info cost.
        assert!(
            gas.spent() > 0,
            "early-return revert should report non-zero gas_used, got {}",
            gas.spent()
        );
    }

    #[test]
    fn test_invalid_calldata_hardfork_behavior() {
        let call_with_spec = |calldata: Bytes, spec: TempoHardfork| {
            call_tempo(
                spec,
                calldata,
                MessageKind::Call,
                PATH_USD_ADDRESS,
                PATH_USD_ADDRESS,
                true,
            )
        };

        // T1: empty calldata (missing selector) should return a reverted output
        let (empty, empty_gas) = call_with_spec(Bytes::new(), TempoHardfork::T1);
        let Err(PrecompileError::Revert(empty)) = empty else {
            panic!("T1: expected reverted output");
        };
        assert!(empty.is_empty());
        // Gas was consumed
        assert!(empty_gas.spent() > 0);

        // T1: unknown selector should return a reverted output with UnknownFunctionSelector error
        let (unknown, unknown_gas) = call_with_spec(Bytes::from([0xAA; 4]), TempoHardfork::T1);
        let Err(PrecompileError::Revert(unknown)) = unknown else {
            panic!("T1: expected reverted output");
        };
        // Verify it's an UnknownFunctionSelector error with the correct selector
        let decoded = tempo_contracts::precompiles::UnknownFunctionSelector::abi_decode(&unknown)
            .expect("T1: expected UnknownFunctionSelector error");
        assert_eq!(decoded.selector.as_slice(), &[0xAA, 0xAA, 0xAA, 0xAA]);
        // Verify gas is tracked for both cases (unknown selector may cost slightly more due to its
        // input length).
        assert!(unknown_gas.spent() >= empty_gas.spent());

        // Pre-T1 (T0): invalid calldata should return a halted output
        let (result, _) = call_with_spec(Bytes::new(), TempoHardfork::T0);
        assert!(
            matches!(result, Err(PrecompileError::Halt(_))),
            "T0: expected halted output for invalid calldata"
        );
    }

    /// Pre-T4 precompile calls must not report state gas, because state-gas accounting is not
    /// active before TIP-1016.
    #[test]
    fn test_precompile_state_gas_zero_pre_t4() {
        // Pre-T4 (T2): state gas used must be 0
        let calldata = ITIP20::balanceOfCall::new((Address::ZERO,))
            .abi_encode()
            .into();
        let (result, gas) = call_tempo(
            TempoHardfork::T2,
            calldata,
            MessageKind::Call,
            PATH_USD_ADDRESS,
            PATH_USD_ADDRESS,
            true,
        );
        assert!(result.is_ok(), "T2 balanceOf should succeed");
        assert!(gas.spent() > 0, "precompile should consume gas");
        assert_eq!(
            gas.state_gas_spent(),
            0,
            "pre-T4 precompile must not report state_gas_used, got {}",
            gas.state_gas_spent()
        );

        // Pre-T4 (T1): reverted call should also have zero state gas used
        let (reverted, gas) = call_tempo(
            TempoHardfork::T1,
            Bytes::new(),
            MessageKind::Call,
            PATH_USD_ADDRESS,
            PATH_USD_ADDRESS,
            true,
        );
        assert!(
            matches!(reverted, Err(PrecompileError::Revert(_))),
            "T1 empty should revert"
        );
        assert_eq!(
            gas.state_gas_spent(),
            0,
            "pre-T4 reverted precompile must not report state_gas_used"
        );
    }

    /// T4+ precompile state gas must only include state-creating gas, not all gas consumed. A
    /// read-only operation and a nonzero-to-nonzero storage update must both use no state gas.
    #[test]
    fn test_t4_state_gas_only_includes_state_creating_ops() {
        let spec = TempoHardfork::T4;
        let sender = Address::repeat_byte(0x01);
        let recipient = Address::repeat_byte(0x02);
        let mut evm = test_evm_with_amsterdam(spec, false, true);

        // Set up TIP20 token state: initialize pathUSD and mint tokens to sender
        {
            let mut storage = EvmPrecompileStorageProvider::new_max_gas(&mut evm, spec);
            StorageCtx::enter(&mut storage, || {
                crate::test_util::TIP20Setup::path_usd(sender)
                    .with_issuer(sender)
                    .with_mint(sender, U256::from(1000))
                    .apply()
            })
            .expect("TIP20 setup should succeed");
        }

        // 1) Read-only: balanceOf must have state gas used == 0
        let calldata: Bytes = ITIP20::balanceOfCall { account: sender }
            .abi_encode()
            .into();
        let (output, gas) = call_tempo_on(
            &mut evm,
            spec,
            calldata,
            MessageKind::Call,
            PATH_USD_ADDRESS,
            PATH_USD_ADDRESS,
            sender,
        );
        assert!(output.is_ok(), "balanceOf should succeed");
        assert!(gas.spent() > 0, "balanceOf should consume gas");
        assert_eq!(
            gas.state_gas_spent(),
            0,
            "read-only balanceOf must have state_gas_used == 0, got {}",
            gas.state_gas_spent()
        );

        // 2) Transfer to existing account (warm SSTORE, not zero->non-zero for recipient
        //    since we pre-fund recipient): state gas used must be less than gas used
        {
            // Pre-fund recipient so the transfer is warm SSTORE (nonzero->nonzero)
            let mut storage = EvmPrecompileStorageProvider::new_max_gas(&mut evm, spec);
            StorageCtx::enter(&mut storage, || {
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
        let (output, gas) = call_tempo_on(
            &mut evm,
            spec,
            calldata,
            MessageKind::Call,
            PATH_USD_ADDRESS,
            PATH_USD_ADDRESS,
            sender,
        );
        assert!(output.is_ok(), "transfer should succeed");
        assert!(gas.spent() > 0, "transfer should consume gas");
        assert_eq!(
            gas.state_gas_spent(),
            0,
            "transfer to existing account (nonzero->nonzero SSTORE) must have state_gas_used == 0, got {}",
            gas.state_gas_spent()
        );
    }

    /// T4+ precompile calls that trigger SSTORE refunds must record the refund
    /// in the EVM2 gas tracker so transaction settlement can apply it.
    /// Pre-T4 blocks were executed without refund propagation, so they must NOT
    /// record refunds.
    #[test]
    fn test_precompile_gas_refund_in_reservoir_t4() {
        let spec = TempoHardfork::T4;
        // TIP-1016 gates state-gas refund propagation on Amsterdam EIP-8037.
        let sender = Address::repeat_byte(0x01);
        let recipient = Address::repeat_byte(0x02);
        let mut evm = test_evm_with_amsterdam(spec, false, true);

        // Set up TIP20 token state: initialize pathUSD and mint tokens to sender
        {
            let mut storage = EvmPrecompileStorageProvider::new_max_gas(&mut evm, spec);
            StorageCtx::enter(&mut storage, || {
                crate::test_util::TIP20Setup::path_usd(sender)
                    .with_issuer(sender)
                    .with_mint(sender, U256::from(1000))
                    .apply()
            })
            .expect("TIP20 setup should succeed");
        }

        // Transfer ALL tokens from sender to recipient (sender balance: 1000 → 0)
        // This triggers SSTORE refund because the balance slot goes from nonzero to zero.
        let calldata: Bytes = ITIP20::transferCall {
            to: recipient,
            amount: U256::from(1000),
        }
        .abi_encode()
        .into();
        let (output, gas) = call_tempo_on(
            &mut evm,
            spec,
            calldata,
            MessageKind::Call,
            PATH_USD_ADDRESS,
            PATH_USD_ADDRESS,
            sender,
        );
        assert!(output.is_ok(), "transfer should be successful");

        // T4+: gas refund must be recorded in the gas tracker
        assert!(
            gas.refunded() != 0,
            "T4+ successful precompile with SSTORE refund must record a refund, got 0"
        );
    }

    #[test]
    fn test_dispatch_macro_applies_hardfork_selector_gates() -> eyre::Result<()> {
        alloy::sol! {
            interface ISelectorGatedTest {
                function stable() external;
                function t2Added(uint256 value) external;
                function t3Removed() external;
            }
        }

        let call_with_spec = |spec: TempoHardfork, calldata: &[u8]| {
            let mut storage = HashMapStorageProvider::new_with_spec(1, spec);
            StorageCtx::enter(&mut storage, || {
                dispatch!(
                    calldata,
                    |call| match call {
                        ISelectorGatedTest::ISelectorGatedTestCalls {
                            stable(_) => Ok(PrecompileOutput::new(Bytes::from_static(b"stable"))),
                            #[schedule(since = T2)]
                            t2Added(_) => Ok(PrecompileOutput::new(Bytes::from_static(b"added"))),
                            #[schedule(until = T3)]
                            t3Removed(_) => Ok(PrecompileOutput::new(Bytes::from_static(b"removed"))),
                        }
                    }
                )
            })
        };

        let t2_added_calldata = ISelectorGatedTest::t2AddedCall { value: U256::ZERO }.abi_encode();
        let t3_removed_calldata = ISelectorGatedTest::t3RemovedCall {}.abi_encode();

        // pre-T2: selectors introduced at T2 must still look unknown.
        let pre_t2_added = call_with_spec(TempoHardfork::T1, &t2_added_calldata);
        let Err(PrecompileError::Revert(pre_t2_added)) = pre_t2_added else {
            panic!("pre-T2 selector should revert");
        };
        let decoded = UnknownFunctionSelector::abi_decode(&pre_t2_added)?;
        assert_eq!(
            decoded.selector.as_slice(),
            &ISelectorGatedTest::t2AddedCall::SELECTOR
        );

        // T2+: that selector becomes available and dispatches normally.
        let post_t2_added = call_with_spec(TempoHardfork::T2, &t2_added_calldata);
        assert_eq!(post_t2_added?.bytes(), b"added");

        // pre-T3: selectors removed at T3 still dispatch normally.
        let pre_t3_removed = call_with_spec(TempoHardfork::T2, &t3_removed_calldata);
        assert_eq!(pre_t3_removed?.bytes(), b"removed");

        // T3+: the removed selector must now revert as unknown.
        let post_t3_removed = call_with_spec(TempoHardfork::T3, &t3_removed_calldata);
        let Err(PrecompileError::Revert(post_t3_removed)) = post_t3_removed else {
            panic!("post-T3 removed selector should revert");
        };
        let decoded = UnknownFunctionSelector::abi_decode(&post_t3_removed)?;
        assert_eq!(
            decoded.selector.as_slice(),
            &ISelectorGatedTest::t3RemovedCall::SELECTOR
        );

        // preT2: gated selectors must return `UnknownFunctionSelector` even for selector-only calldata.
        let malformed_added = call_with_spec(
            TempoHardfork::T1,
            &ISelectorGatedTest::t2AddedCall::SELECTOR,
        );
        let Err(PrecompileError::Revert(malformed_added)) = malformed_added else {
            panic!("pre-T2 malformed selector should revert");
        };
        let decoded = UnknownFunctionSelector::abi_decode(&malformed_added)?;
        assert_eq!(
            decoded.selector.as_slice(),
            &ISelectorGatedTest::t2AddedCall::SELECTOR
        );

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
    fn test_t11_evm2_dispatch_input_gas_and_strict_decoding() {
        let calldata = ITIP20::balanceOfCall {
            account: Address::ZERO,
        }
        .abi_encode();
        let execute = |spec, input: Vec<u8>| {
            call_tempo(
                spec,
                input.into(),
                MessageKind::StaticCall,
                PATH_USD_ADDRESS,
                PATH_USD_ADDRESS,
                true,
            )
        };

        let (pre_t11, pre_t11_gas) = execute(TempoHardfork::T10, calldata.clone());
        let (t11, t11_gas) = execute(TempoHardfork::T11, calldata.clone());
        assert_eq!(pre_t11.unwrap(), t11.unwrap());
        assert_eq!(t11_gas.spent() - pre_t11_gas.spent(), 48);

        let mut trailing = calldata;
        trailing.push(0);
        assert!(execute(TempoHardfork::T10, trailing.clone()).0.is_ok());
        let (result, _) = execute(TempoHardfork::T11, trailing);
        assert!(matches!(result, Err(PrecompileError::Revert(bytes)) if bytes.is_empty()));
    }

    #[test]
    fn test_dedup_cost_schedule() {
        assert_eq!(dedup_cost(TempoHardfork::T10, 65_536).unwrap(), 0);
        assert_eq!(dedup_cost(TempoHardfork::T11, 0).unwrap(), 0);
        assert_eq!(dedup_cost(TempoHardfork::T11, 65_536).unwrap(), 1_310_720);
    }

    #[test]
    fn test_extend_tempo_precompiles_registers_precompiles() {
        let precompiles = test_tempo_precompiles(TempoHardfork::T3);

        // TIP20Factory should be registered
        let factory_precompile = precompiles.contains(&TIP20_FACTORY_ADDRESS);
        assert!(factory_precompile, "TIP20Factory should be registered");

        // TIP403Registry should be registered
        let registry_precompile = precompiles.contains(&TIP403_REGISTRY_ADDRESS);
        assert!(registry_precompile, "TIP403Registry should be registered");

        // TipFeeManager should be registered
        let fee_manager_precompile = precompiles.contains(&TIP_FEE_MANAGER_ADDRESS);
        assert!(fee_manager_precompile, "TipFeeManager should be registered");

        // StablecoinDEX should be registered
        let dex_precompile = precompiles.contains(&STABLECOIN_DEX_ADDRESS);
        assert!(dex_precompile, "StablecoinDEX should be registered");

        // NonceManager should be registered
        let nonce_precompile = precompiles.contains(&NONCE_PRECOMPILE_ADDRESS);
        assert!(nonce_precompile, "NonceManager should be registered");

        // ValidatorConfig should be registered
        let validator_precompile = precompiles.contains(&VALIDATOR_CONFIG_ADDRESS);
        assert!(validator_precompile, "ValidatorConfig should be registered");

        // ValidatorConfigV2 should be registered
        let validator_v2_precompile = precompiles.contains(&VALIDATOR_CONFIG_V2_ADDRESS);
        assert!(
            validator_v2_precompile,
            "ValidatorConfigV2 should be registered"
        );

        // AccountKeychain should be registered
        let keychain_precompile = precompiles.contains(&ACCOUNT_KEYCHAIN_ADDRESS);
        assert!(keychain_precompile, "AccountKeychain should be registered");

        // SignatureVerifier should be registered at T3
        let sig_verifier_precompile = precompiles.contains(&SIGNATURE_VERIFIER_ADDRESS);
        assert!(
            sig_verifier_precompile,
            "SignatureVerifier should be registered at T3"
        );

        // Channel reserve should be registered at T5
        let channel_reserve_precompile = precompiles.contains(&TIP20_CHANNEL_RESERVE_ADDRESS);
        assert!(
            !channel_reserve_precompile,
            "TIP20 channel reserve should not be registered before T5"
        );

        // TIP20 tokens with prefix should be registered
        let tip20_precompile = precompiles.contains(&PATH_USD_ADDRESS);
        assert!(tip20_precompile, "TIP20 tokens should be registered");

        // Random address without TIP20 prefix should NOT be registered
        let random_address = Address::random();
        let random_precompile = precompiles.contains(&random_address);
        assert!(
            !random_precompile,
            "Random address should not be a precompile"
        );
    }

    #[test]
    fn test_signature_verifier_not_registered_pre_t3() {
        let precompiles = test_tempo_precompiles(TempoHardfork::T0);

        assert!(
            !precompiles.contains(&SIGNATURE_VERIFIER_ADDRESS),
            "SignatureVerifier should NOT be registered before T3"
        );
    }

    #[test]
    fn test_zone_factory_registered_at_t10_only() {
        let pre_t10 = test_tempo_precompiles(TempoHardfork::T9);
        assert!(
            !pre_t10.contains(&ZONE_FACTORY_ADDRESS),
            "ZoneFactory should not be registered before T10"
        );

        let precompiles = test_tempo_precompiles(TempoHardfork::T10);
        assert!(
            precompiles.contains(&ZONE_FACTORY_ADDRESS),
            "ZoneFactory should be registered at T10"
        );
        assert!(
            !precompiles.contains(&zone_factory::portal_address(1)),
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
            assert_eq!(
                test_tempo_precompiles(spec).contains(&ZONE_VERIFIER_ADDRESS),
                active,
                "unexpected native ZoneVerifier activation at {spec:?}"
            );
        }
    }

    #[test]
    fn test_channel_reserve_registered_at_t5_only() {
        assert!(
            !test_tempo_precompiles(TempoHardfork::T4).contains(&TIP20_CHANNEL_RESERVE_ADDRESS),
            "TIP20 channel reserve should NOT be registered before T5"
        );

        assert!(
            test_tempo_precompiles(TempoHardfork::T5).contains(&TIP20_CHANNEL_RESERVE_ADDRESS),
            "TIP20 channel reserve should be registered at T5"
        );
    }

    #[test]
    fn test_p256verify_availability_across_t1c_boundary() {
        let has_p256 = |spec: TempoHardfork| -> bool {
            // P256VERIFY lives at address 0x100 (256), added in Osaka
            let p256_addr = Address::from_word(U256::from(256).into());

            test_tempo_precompiles(spec).contains(&p256_addr)
        };

        // Pre-T1C hardforks should use Prague precompiles (no P256VERIFY)
        for spec in [
            TempoHardfork::Genesis,
            TempoHardfork::T0,
            TempoHardfork::T1,
            TempoHardfork::T1A,
            TempoHardfork::T1B,
        ] {
            assert!(
                !has_p256(spec),
                "P256VERIFY should NOT be available at {spec:?} (pre-T1C)"
            );
        }

        // T1C+ hardforks should use Osaka precompiles (P256VERIFY available)
        for spec in [TempoHardfork::T1C, TempoHardfork::T2] {
            assert!(
                has_p256(spec),
                "P256VERIFY should be available at {spec:?} (T1C+)"
            );
        }
    }
}
