//! Shared execution for Zone-native and upstream Tempo precompiles.
//!
//! Every Zone wrapper installs the same EVM-backed [`StorageCtx`], applies Zone-specific
//! [`CallRules`], and forwards admitted calls without changing their calldata or caller.
//! The EVM database decides whether each storage read is local or resolved from L1-anchored state.
//!
//! # Call ordering
//!
//! 1. Direct-call-only rules reject delegate calls before storage access.
//! 2. Reject calls that cannot cover the calldata input cost before admission rules decode it.
//! 3. Decode the selector and reject calls that cannot cover a configured fixed gas charge.
//! 4. Apply [`CallRules`] admission checks using calldata, caller metadata, and anchored state.
//! 5. Forward the original calldata and caller, applying any configured fixed gas charge.
//!
//! Admission-rule rejections include calldata input gas, while early delegate-call rejection is
//! unmetered. Calls without a fixed charge retain normal provider metering, and successful
//! fixed-price calls report exactly the configured charge.

use alloc::rc::Rc;
use core::cell::RefCell;

use alloy_primitives::{Address, Bytes};
use alloy_sol_types::SolError;
use evm2::{
    Evm, EvmTypes,
    interpreter::{GasTracker, Message, MessageKind},
    precompiles::{PrecompileError, PrecompileHalt, PrecompileResult},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{
    DelegateCallNotAllowed, charge_input_cost,
    dispatch::selector_from_calldata,
    error::TempoPrecompileError,
    input_cost,
    storage::{
        PrecompileStorageProvider, StorageCtx, actions::StorageActions,
        evm::EvmPrecompileStorageProvider,
    },
    storage_credits::NonCreditableSlots,
};

/// Shared EVM configuration and accounting state installed for every Zone precompile wrapper.
#[derive(Clone, Debug)]
pub struct ZonePrecompileEnv {
    spec: TempoHardfork,
    actions: StorageActions,
    non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
}

impl ZonePrecompileEnv {
    /// Captures the active EVM configuration and transaction-local storage accounting state.
    pub fn new(
        spec: TempoHardfork,
        actions: StorageActions,
        non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
    ) -> Self {
        Self {
            spec,
            actions,
            non_creditable_slots,
        }
    }
}

/// Result of applying zone-specific pre-execution rules.
pub(crate) enum CallCheck {
    /// Invoke the supplied precompile implementation.
    Continue,
    /// Revert with ABI-encoded data. The execution wrapper MUST apply input gas and reservoir.
    Revert(Bytes),
    /// Return an error raised while evaluating an admission rule.
    Error(TempoPrecompileError),
}

/// Selector and caller dependent precompile call rules evaluated after storage setup.
///
/// Rules may enforce admission policy and duplicate cheap business checks as fail-fast preflight.
/// State-dependent rules resolve reads through the installed storage context.
pub(crate) trait CallRules: 'static {
    /// Return the fixed gas charge for this selector, if one applies.
    fn fixed_gas(&self, _selector: Option<[u8; 4]>) -> Option<u64> {
        None
    }

    /// Applies Zone-specific admission rules.
    fn admit(&self, _data: &[u8], _caller: Address) -> CallCheck {
        CallCheck::Continue
    }
}

/// Rules with no additional selector or caller-specific restrictions, and regular gas pricing.
pub(crate) struct NoCallRules;
impl CallRules for NoCallRules {}

pub(crate) fn execute_precompile<T>(
    evm: &mut Evm<'_, T>,
    message: &Message<T>,
    gas: &mut GasTracker,
    env: &ZonePrecompileEnv,
    rules: impl CallRules,
    execute: impl FnOnce(&[u8], Address) -> PrecompileResult,
) -> PrecompileResult
where
    T: EvmTypes<BlockEnvExt = tempo_primitives::TempoBlockExt>,
{
    if message.destination != message.code_address {
        return Err(PrecompileError::Revert(
            SolError::abi_encode(&DelegateCallNotAllowed {}).into(),
        ));
    }

    let (data, caller) = (message.input.as_ref(), message.caller);
    let Ok(input_gas) = input_cost(env.spec, data.len()) else {
        return Err(PrecompileHalt::OutOfGas.into());
    };
    if gas.remaining() < input_gas {
        return Err(PrecompileHalt::OutOfGas.into());
    }

    let fixed_gas = rules.fixed_gas(selector_from_calldata(data));
    if fixed_gas.is_some_and(|fixed_gas| gas.remaining() < fixed_gas) {
        return Err(PrecompileHalt::OutOfGas.into());
    }

    let is_static = message.caller_is_static || message.kind == MessageKind::StaticCall;
    let mut fixed_gas_tracker = GasTracker::new(u64::MAX);
    let storage_gas = if fixed_gas.is_some() {
        &mut fixed_gas_tracker
    } else {
        &mut *gas
    };
    let mut storage = EvmPrecompileStorageProvider::new(evm, storage_gas, env.spec, is_static)
        .with_actions(env.actions.clone())
        .with_non_creditable_slots(env.non_creditable_slots.clone());
    if fixed_gas.is_some() {
        // The fixed charge replaces storage-dependent pricing. Do not let the call mint,
        // consume, or schedule TIP-1060 credits whose variable charges are discarded below.
        storage.set_tip1060_storage_credits(false);
    }

    let result = StorageCtx::enter(&mut storage, || match rules.admit(data, caller) {
        CallCheck::Continue => execute(data, caller),
        CallCheck::Revert(output) => add_input_cost(
            StorageCtx::default(),
            data,
            Err(PrecompileError::Revert(output)),
        ),
        CallCheck::Error(error) => {
            let s = StorageCtx::default();
            let result = s.error_result(error);
            add_input_cost(s, data, result)
        }
    });
    drop(storage);
    if matches!(result, Ok(_) | Err(PrecompileError::Revert(_)))
        && let Some(fixed_gas) = fixed_gas
    {
        gas.spend(fixed_gas)
            .expect("fixed gas availability checked above");
    }
    result
}

fn add_input_cost(mut s: StorageCtx, data: &[u8], res: PrecompileResult) -> PrecompileResult {
    // Fatal errors must be propagated to abort execution.
    let output = match res {
        result @ (Ok(_) | Err(PrecompileError::Revert(_))) => result,
        Err(error) => return Err(error),
    };

    if let Some(err) = charge_input_cost(&mut s, data) {
        return err;
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TestContext, test_context, test_storage_provider};
    use alloy_primitives::{Bytes, U256};
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
    };
    use tempo_contracts::precompiles::STORAGE_CREDITS_ADDRESS;
    use tempo_evm::TempoEvmTypes;

    const FIXED_GAS: u64 = 123;
    type RuleRecord = Rc<RefCell<Option<(Bytes, Option<[u8; 4]>, Address)>>>;

    struct RecordingRules(RuleRecord);

    impl CallRules for RecordingRules {
        fn fixed_gas(&self, _selector: Option<[u8; 4]>) -> Option<u64> {
            Some(FIXED_GAS)
        }

        fn admit(&self, data: &[u8], caller: Address) -> CallCheck {
            *self.0.borrow_mut() = Some((
                Bytes::copy_from_slice(data),
                selector_from_calldata(data),
                caller,
            ));
            CallCheck::Continue
        }
    }

    fn env(spec: TempoHardfork) -> ZonePrecompileEnv {
        ZonePrecompileEnv::new(
            spec,
            StorageActions::disabled(),
            Rc::new(RefCell::new(NonCreditableSlots::empty())),
        )
    }

    fn call(
        ctx: &mut TestContext,
        spec: TempoHardfork,
        data: &[u8],
        caller: Address,
        gas: u64,
        rules: impl CallRules,
        execute: impl FnOnce(&[u8], Address) -> PrecompileResult,
    ) -> (PrecompileResult, GasTracker) {
        let target = Address::repeat_byte(0x11);
        let message = Message::<TempoEvmTypes> {
            gas_limit: gas,
            caller,
            input: Bytes::copy_from_slice(data),
            destination: target,
            code_address: target,
            ..Default::default()
        };
        let mut gas_tracker = GasTracker::new(gas);
        let result = execute_precompile(
            ctx.evm(),
            &message,
            &mut gas_tracker,
            &env(spec),
            rules,
            execute,
        );
        (result, gas_tracker)
    }

    #[test]
    fn forwards_original_call_applies_rules_and_restores_storage_context() {
        let recorded_rule = Rc::new(RefCell::new(None));
        let recorded_execute = Rc::new(RefCell::new(None));
        let execute_record = recorded_execute.clone();
        let rules = RecordingRules(recorded_rule.clone());
        let execute = move |data: &[u8], caller| {
            *execute_record.borrow_mut() = Some((Bytes::copy_from_slice(data), caller));
            Ok(StorageCtx::default().success_output(Bytes::new()))
        };

        let mut outer_ctx = test_context();
        let mut inner_ctx = test_context();
        let mut outer = test_storage_provider(&mut outer_ctx, 777, false);
        let calldata = [0xde, 0xad, 0xbe, 0xef, 0x01];
        let caller = Address::repeat_byte(0x22);
        let output = StorageCtx::enter(&mut outer, || {
            let (output, gas) = call(
                &mut inner_ctx,
                TempoHardfork::T8,
                &calldata,
                caller,
                FIXED_GAS,
                rules,
                execute,
            );
            assert_eq!(StorageCtx::default().gas_limit(), 777);
            (output.unwrap(), gas)
        });

        assert_eq!(output.1.spent(), FIXED_GAS);
        assert_eq!(
            *recorded_rule.borrow(),
            Some((calldata.into(), Some([0xde, 0xad, 0xbe, 0xef]), caller))
        );
        assert_eq!(*recorded_execute.borrow(), Some((calldata.into(), caller)));
    }

    #[test]
    fn fixed_gas_disables_storage_credits_and_discards_refunds() {
        let storage_owner = Address::repeat_byte(0x33);
        let credit_slot = U256::from_be_slice(storage_owner.as_slice());
        let observed_credit_state = Rc::new(Cell::new(U256::MAX));
        let execute_credit_state = observed_credit_state.clone();
        let rules = RecordingRules(Rc::new(RefCell::new(None)));
        let execute = move |_: &[u8], _| {
            let mut storage = StorageCtx::default();
            storage
                .sstore(storage_owner, U256::ZERO, U256::ONE)
                .unwrap();
            execute_credit_state.set(storage.tload(STORAGE_CREDITS_ADDRESS, credit_slot).unwrap());

            // Model an ordinary SSTORE refund reported by an upstream T4+ precompile.
            storage.refund_gas(4_800);
            Ok(storage.success_output(Bytes::new()))
        };

        let mut ctx = test_context();
        let (output, gas) = call(
            &mut ctx,
            TempoHardfork::T8,
            &[],
            Address::ZERO,
            FIXED_GAS,
            rules,
            execute,
        );
        output.unwrap();

        assert_eq!(gas.spent(), FIXED_GAS);
        assert_eq!(gas.refunded(), 0);
        assert_eq!(observed_credit_state.get(), U256::ZERO);
    }

    #[test]
    fn protocol_precompile_applies_admission_and_evm_spec() {
        let observed_spec = Rc::new(Cell::new(None));
        let execute_spec = observed_spec.clone();
        let checked = Rc::new(Cell::new(false));
        let mut ctx = test_context();
        let (rejected, _) = call(
            &mut ctx,
            TempoHardfork::T8,
            &[1, 2, 3, 4],
            Address::ZERO,
            FIXED_GAS,
            RejectRules(checked.clone()),
            |_, _| panic!("rejected call must not execute"),
        );
        assert!(matches!(rejected, Err(PrecompileError::Revert(_))));
        assert!(checked.get());

        call(
            &mut ctx,
            TempoHardfork::T8,
            &[],
            Address::ZERO,
            u64::MAX,
            NoCallRules,
            move |_, _| {
                execute_spec.set(Some(StorageCtx::default().spec()));
                Ok(StorageCtx::default().success_output(Bytes::new()))
            },
        )
        .0
        .unwrap();

        assert_eq!(observed_spec.get(), Some(TempoHardfork::T8));
    }

    struct RejectRules(Rc<Cell<bool>>);

    impl CallRules for RejectRules {
        fn fixed_gas(&self, _selector: Option<[u8; 4]>) -> Option<u64> {
            Some(FIXED_GAS)
        }

        fn admit(&self, _data: &[u8], _caller: Address) -> CallCheck {
            self.0.set(true);
            CallCheck::Revert(Bytes::from_static(b"denied"))
        }
    }

    #[test]
    fn admission_and_fixed_gas_run_before_forwarded_execution() {
        let checked = Rc::new(Cell::new(false));
        let executed = Rc::new(Cell::new(false));
        let execute_flag = executed.clone();
        let mut ctx = test_context();
        let calldata = [1, 2, 3, 4];

        let (out_of_gas, _) = call(
            &mut ctx,
            TempoHardfork::T8,
            &calldata,
            Address::ZERO,
            FIXED_GAS - 1,
            RejectRules(checked.clone()),
            |_, _| panic!("out-of-gas call must not execute"),
        );
        assert!(matches!(
            out_of_gas,
            Err(PrecompileError::Halt(PrecompileHalt::OutOfGas))
        ));
        assert!(!checked.get());
        assert!(!executed.get());

        let (rejected, gas) = call(
            &mut ctx,
            TempoHardfork::T8,
            &calldata,
            Address::ZERO,
            FIXED_GAS,
            RejectRules(checked.clone()),
            move |_, _| {
                execute_flag.set(true);
                Ok(StorageCtx::default().success_output(Bytes::new()))
            },
        );
        assert!(checked.get());
        assert!(!executed.get());
        assert_eq!(gas.spent(), FIXED_GAS);
        assert!(matches!(
            rejected,
            Err(PrecompileError::Revert(bytes)) if bytes == Bytes::from_static(b"denied")
        ));
    }

    #[test]
    fn input_gas_threshold_tracks_t11() {
        let calldata = [0u8; 32];

        for (spec, required_gas) in [(TempoHardfork::T10, 6), (TempoHardfork::T11, 30)] {
            let mut ctx = test_context();

            let (insufficient, _) = call(
                &mut ctx,
                spec,
                &calldata,
                Address::ZERO,
                required_gas - 1,
                NoCallRules,
                |_, _| Ok(StorageCtx::default().success_output(Bytes::new())),
            );
            assert!(
                matches!(
                    insufficient,
                    Err(PrecompileError::Halt(PrecompileHalt::OutOfGas))
                ),
                "{spec:?} must require {required_gas} input gas"
            );

            let (sufficient, _) = call(
                &mut ctx,
                spec,
                &calldata,
                Address::ZERO,
                required_gas,
                NoCallRules,
                |_, _| Ok(StorageCtx::default().success_output(Bytes::new())),
            );
            assert!(sufficient.is_ok(), "{spec:?} must accept its exact cost");
        }
    }

    struct FatalRules;

    impl CallRules for FatalRules {
        fn admit(&self, _data: &[u8], _caller: Address) -> CallCheck {
            StorageCtx::default().deduct_gas(10).unwrap();
            CallCheck::Error(TempoPrecompileError::Fatal("boom".into()))
        }
    }

    #[test]
    fn input_cost_does_not_replace_fatal_admission_error() {
        let mut ctx = test_context();
        let calldata = [1, 2, 3, 4];

        let (error, _) = call(
            &mut ctx,
            TempoHardfork::T8,
            &calldata,
            Address::ZERO,
            10,
            FatalRules,
            |_, _| panic!("fatal admission must not execute the precompile"),
        );
        assert!(matches!(error, Err(PrecompileError::Fatal(error)) if error.to_string() == "boom"));
    }
}
