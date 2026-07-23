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
    storage::{StorageCtx, actions::StorageActions, evm::EvmPrecompileStorageProvider},
    storage_credits::{NonCreditableSlots, StorageCredits},
    tip_fee_manager::TipFeeManager,
    tip20::TIP20Token,
    tip20_channel_reserve::TIP20ChannelReserve,
    tip20_factory::TIP20Factory,
    tip403_registry::TIP403Registry,
    validator_config::ValidatorConfig,
    validator_config_v2::ValidatorConfigV2,
    zone_factory::ZoneFactory,
};
use std::{cell::RefCell, rc::Rc};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_primitives::{TempoAddressExt, TempoBlockExt};

#[cfg(test)]
use alloy::sol_types::SolInterface;
use alloy::{primitives::Address, sol, sol_types::SolError};
use evm2::{
    Evm, EvmTypes, EvmTypesHost, Precompiles as BasePrecompiles, SpecId,
    evm::precompile::PrecompileProvider,
    interpreter::{GasTracker, Message, MessageKind},
    precompiles::{PrecompileError, PrecompileResult},
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

/// Input per word cost. It covers abi decoding and cloning of input into call data.
///
/// Being careful and pricing it twice as COPY_COST to mitigate different abi decodings.
pub const INPUT_PER_WORD_COST: u64 = 6;

/// Gas cost for `ecrecover` signature verification (used by KeyAuthorization and Permit).
pub const ECRECOVER_GAS: u64 = 3_000;

/// Returns the gas cost for decoding calldata of the given length, rounded up to word boundaries.
#[inline]
pub fn input_cost(calldata_len: usize) -> u64 {
    calldata_len
        .div_ceil(32)
        .saturating_mul(INPUT_PER_WORD_COST as usize) as u64
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
    /// `dispatch_call` combined with the `view`, `mutate`, or `mutate_void` helpers.
    ///
    /// Business-logic errors are returned as EVM reverts with ABI-encoded error data, while
    /// fatal failures (e.g. out-of-gas) are returned as [`PrecompileError`]s.
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult;
}

/// Tempo's built-in and protocol precompiles for EVM2.
#[derive(Debug)]
pub struct TempoPrecompiles<T: EvmTypesHost> {
    base: BasePrecompiles<T>,
    spec: TempoHardfork,
    actions: StorageActions,
    non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
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
        }
    }

    #[inline]
    fn contains_tempo(&self, address: &Address) -> bool {
        address.is_tip20()
            || SYSTEM_PRECOMPILES
                .iter()
                .any(|(candidate, activation)| candidate == address && self.spec >= *activation)
    }

    fn call_tempo(&self, address: Address, calldata: &[u8], caller: Address) -> PrecompileResult {
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
        } else {
            unreachable!("Tempo precompile address checked before dispatch")
        }
    }
}

sol! {
    error DelegateCallNotAllowed();
}

impl<T> PrecompileProvider<T> for TempoPrecompiles<T>
where
    T: EvmTypes<BlockEnvExt = TempoBlockExt>,
{
    fn addresses(&self) -> Vec<Address> {
        self.base.addresses()
    }

    fn contains(&self, address: &Address) -> bool {
        self.base.contains(address) || self.contains_tempo(address)
    }

    fn execute(
        &mut self,
        evm: &mut Evm<'_, T>,
        message: &Message<T>,
        gas: &mut GasTracker,
    ) -> Option<PrecompileResult> {
        if let Some(result) = self.base.execute(evm, message, gas) {
            return Some(result);
        }
        if !self.contains_tempo(&message.code_address) {
            return None;
        }
        if message.destination != message.code_address {
            return Some(Err(PrecompileError::Revert(
                DelegateCallNotAllowed {}.abi_encode().into(),
            )));
        }

        let is_static = message.caller_is_static || message.kind == MessageKind::StaticCall;
        let mut storage = EvmPrecompileStorageProvider::new(evm, gas, self.spec, is_static)
            .with_actions(self.actions.clone())
            .with_non_creditable_slots(self.non_creditable_slots.clone());
        Some(StorageCtx::enter(&mut storage, || {
            self.call_tempo(message.code_address, &message.input, message.caller)
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
    use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};
    use alloy::{
        primitives::{Bytes, U256, bytes},
        sol_types::SolCall,
    };
    use evm2::{
        BaseEvmConfigSelector, ExecutionConfig,
        bytecode::Bytecode,
        evm::{
            AccountInfo, InMemoryDB,
            precompile::{NoPrecompiles, PrecompileOutput, PrecompileProvider},
        },
        registry::TxRegistry,
    };
    use tempo_contracts::precompiles::{ITIP20, UnknownFunctionSelector};
    use tempo_primitives::{TempoBlockEnv, TempoBlockExt};

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
        let message = Message {
            kind,
            gas_limit: 1_000_000,
            destination,
            code_address,
            input: calldata,
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
    fn test_precompile_static_call() {
        let call_static = |calldata: Bytes| {
            call_tempo(
                TempoHardfork::T3,
                calldata,
                MessageKind::StaticCall,
                PATH_USD_ADDRESS,
                PATH_USD_ADDRESS,
                true,
            )
            .0
        };

        // Static calls into mutating functions should fail
        let result = call_static(Bytes::from(
            ITIP20::transferCall {
                to: Address::random(),
                amount: U256::from(100),
            }
            .abi_encode(),
        ));
        let Err(PrecompileError::Revert(output)) = result else {
            panic!("expected reverted output");
        };
        assert!(StaticCallNotAllowed::abi_decode(&output).is_ok());

        // Static calls into mutate void functions should fail
        let result = call_static(Bytes::from(
            ITIP20::approveCall {
                spender: Address::random(),
                amount: U256::from(100),
            }
            .abi_encode(),
        ));
        let Err(PrecompileError::Revert(output)) = result else {
            panic!("expected reverted output");
        };
        assert!(StaticCallNotAllowed::abi_decode(&output).is_ok());

        // Static calls into view functions should succeed
        let result = call_static(Bytes::from(
            ITIP20::balanceOfCall {
                account: Address::random(),
            }
            .abi_encode(),
        ));
        assert!(
            result.is_ok(),
            "view function should not revert in static context"
        );
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
        // Gas used should include input_cost(68) = 18 + with_account_info cost
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
        // Verify gas is tracked for both cases (unknown selector may cost slightly more due `INPUT_PER_WORD_COST`)
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
                    .with_mint(recipient, U256::from(1))
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
    fn test_input_cost_returns_non_zero_for_input() {
        // Empty input should cost 0
        assert_eq!(input_cost(0), 0);

        // 1 byte should cost INPUT_PER_WORD_COST (rounds up to 1 word)
        assert_eq!(input_cost(1), INPUT_PER_WORD_COST);

        // 32 bytes (1 word) should cost INPUT_PER_WORD_COST
        assert_eq!(input_cost(32), INPUT_PER_WORD_COST);

        // 33 bytes (2 words) should cost 2 * INPUT_PER_WORD_COST
        assert_eq!(input_cost(33), INPUT_PER_WORD_COST * 2);
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
    fn test_zone_factory_registered_at_t9_only() {
        let pre_t9 = test_tempo_precompiles(TempoHardfork::T8);
        assert!(
            !pre_t9.contains(&ZONE_FACTORY_ADDRESS),
            "ZoneFactory should not be registered before T9"
        );

        let precompiles = test_tempo_precompiles(TempoHardfork::T9);
        assert!(
            precompiles.contains(&ZONE_FACTORY_ADDRESS),
            "ZoneFactory should be registered at T9"
        );
        assert!(
            !precompiles.contains(&zone_factory::portal_address(1)),
            "ZonePortal storage handles must not be registered as precompiles"
        );
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
