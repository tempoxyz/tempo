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

use alloy_evm::precompiles::DynPrecompile;
use alloy_primitives::{Address, Bytes};
use alloy_sol_types::SolError;
use revm::precompile::{PrecompileHalt, PrecompileId, PrecompileOutput, PrecompileResult};
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
#[derive(Clone)]
pub struct ZonePrecompileEnv {
    cfg: revm::context::CfgEnv<TempoHardfork>,
    actions: StorageActions,
    non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
}

impl ZonePrecompileEnv {
    /// Captures the active EVM configuration and transaction-local storage accounting state.
    pub fn new(
        cfg: &revm::context::CfgEnv<TempoHardfork>,
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

pub(crate) fn create_precompile(
    id: &'static str,
    env: &ZonePrecompileEnv,
    rules: impl CallRules,
    execute: impl Fn(&[u8], Address) -> PrecompileResult + 'static,
) -> DynPrecompile {
    let env = env.clone();
    DynPrecompile::new_stateful(PrecompileId::Custom(id.into()), move |input| {
        if !input.is_direct_call() {
            return Ok(PrecompileOutput::revert(
                0,
                SolError::abi_encode(&DelegateCallNotAllowed {}).into(),
                input.reservoir,
            ));
        }

        let (data, caller) = (input.data, input.caller);
        let Ok(input_gas) = input_cost(env.cfg.spec, data.len()) else {
            return Ok(PrecompileOutput::halt(
                PrecompileHalt::OutOfGas,
                input.reservoir,
            ));
        };
        if input.gas < input_gas {
            return Ok(PrecompileOutput::halt(
                PrecompileHalt::OutOfGas,
                input.reservoir,
            ));
        }

        let fixed_gas = rules.fixed_gas(selector_from_calldata(data));
        if fixed_gas.is_some_and(|gas| input.gas < gas) {
            return Ok(PrecompileOutput::halt(
                PrecompileHalt::OutOfGas,
                input.reservoir,
            ));
        }

        let mut storage = EvmPrecompileStorageProvider::new(
            input.internals,
            fixed_gas.map_or(input.gas, |_| u64::MAX),
            input.reservoir,
            env.cfg.spec,
            env.cfg.enable_amsterdam_eip8037,
            input.is_static,
            env.cfg.gas_params.clone(),
        )
        .with_actions(env.actions.clone())
        .with_non_creditable_slots(env.non_creditable_slots.clone());
        if fixed_gas.is_some() {
            // The fixed charge replaces storage-dependent pricing. Do not let the call mint,
            // consume, or schedule TIP-1060 credits whose variable charges are discarded below.
            storage.set_tip1060_storage_credits(false);
        }

        let mut result = StorageCtx::enter(&mut storage, || match rules.admit(data, caller) {
            CallCheck::Continue => execute(data, caller),
            CallCheck::Revert(output) => {
                let s = StorageCtx::default();
                let output = s.revert_output(output);
                add_input_cost(s, data, Ok(output))
            }
            CallCheck::Error(error) => {
                let s = StorageCtx::default();
                let result = s.error_result(error);
                add_input_cost(s, data, result)
            }
        });
        if let (Ok(output), Some(gas)) = (&mut result, fixed_gas) {
            output.gas_used = gas;
            // Disable refunds to not leak any data about previous storage values.
            output.gas_refunded = 0;
        }
        result
    })
}

fn add_input_cost(mut s: StorageCtx, data: &[u8], res: PrecompileResult) -> PrecompileResult {
    // Fatal errors must be propagated to abort execution.
    let mut output = res?;

    let gas_before = s.gas_used();
    if let Some(err) = charge_input_cost(&mut s, data) {
        return err;
    }
    let input_gas = s.gas_used().saturating_sub(gas_before);
    output.gas_used = output.gas_used.saturating_add(input_gas);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{test_context, test_storage_provider};
    use alloy_evm::{
        EvmInternals,
        precompiles::{Precompile as _, PrecompileInput},
    };
    use alloy_primitives::{Bytes, U256};
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
    };
    use tempo_contracts::precompiles::STORAGE_CREDITS_ADDRESS;

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

    fn input<'a>(
        ctx: &'a mut crate::test_utils::TestContext,
        data: &'a [u8],
        caller: Address,
        gas: u64,
    ) -> PrecompileInput<'a> {
        let target = Address::repeat_byte(0x11);
        PrecompileInput {
            data,
            gas,
            reservoir: 0,
            caller,
            value: U256::ZERO,
            target_address: target,
            is_static: false,
            bytecode_address: target,
            internals: EvmInternals::from_context(ctx),
        }
    }

    #[test]
    fn forwards_original_call_applies_rules_and_restores_storage_context() {
        let recorded_rule = Rc::new(RefCell::new(None));
        let recorded_execute = Rc::new(RefCell::new(None));
        let execute_record = recorded_execute.clone();
        let cfg = revm::context::CfgEnv::<TempoHardfork>::default();
        let env = ZonePrecompileEnv::new(
            &cfg,
            StorageActions::disabled(),
            Rc::new(RefCell::new(NonCreditableSlots::empty())),
        );
        let precompile = create_precompile(
            "ForwardingTest",
            &env,
            RecordingRules(recorded_rule.clone()),
            move |data, caller| {
                *execute_record.borrow_mut() = Some((Bytes::copy_from_slice(data), caller));
                Ok(StorageCtx::default().success_output(Bytes::new()))
            },
        );

        let mut outer_ctx = test_context();
        let mut inner_ctx = test_context();
        let mut outer = test_storage_provider(&mut outer_ctx, 777, false);
        let calldata = [0xde, 0xad, 0xbe, 0xef, 0x01];
        let caller = Address::repeat_byte(0x22);
        let output = StorageCtx::enter(&mut outer, || {
            let output = precompile
                .call(input(&mut inner_ctx, &calldata, caller, FIXED_GAS))
                .unwrap();
            assert_eq!(StorageCtx::default().gas_limit(), 777);
            output
        });

        assert_eq!(output.gas_used, FIXED_GAS);
        assert_eq!(
            *recorded_rule.borrow(),
            Some((calldata.into(), Some([0xde, 0xad, 0xbe, 0xef]), caller))
        );
        assert_eq!(*recorded_execute.borrow(), Some((calldata.into(), caller)));
    }

    #[test]
    fn fixed_gas_disables_storage_credits_and_discards_refunds() {
        let mut cfg = revm::context::CfgEnv::<TempoHardfork>::default();
        cfg.spec = TempoHardfork::T8;
        let env = ZonePrecompileEnv::new(
            &cfg,
            StorageActions::disabled(),
            Rc::new(RefCell::new(NonCreditableSlots::empty())),
        );
        let storage_owner = Address::repeat_byte(0x33);
        let credit_slot = U256::from_be_slice(storage_owner.as_slice());
        let observed_credit_state = Rc::new(Cell::new(U256::MAX));
        let execute_credit_state = observed_credit_state.clone();
        let precompile = create_precompile(
            "FixedGasAccountingTest",
            &env,
            RecordingRules(Rc::new(RefCell::new(None))),
            move |_, _| {
                let mut storage = StorageCtx::default();
                storage
                    .sstore(storage_owner, U256::ZERO, U256::ONE)
                    .unwrap();
                execute_credit_state
                    .set(storage.tload(STORAGE_CREDITS_ADDRESS, credit_slot).unwrap());

                // Model an ordinary SSTORE refund reported by an upstream T4+ precompile.
                storage.refund_gas(4_800);
                let mut output = storage.success_output(Bytes::new());
                output.gas_refunded = storage.gas_refunded();
                Ok(output)
            },
        );

        let mut ctx = test_context();
        let output = precompile
            .call(input(&mut ctx, &[], Address::ZERO, FIXED_GAS))
            .unwrap();

        assert_eq!(output.gas_used, FIXED_GAS);
        assert_eq!(output.gas_refunded, 0);
        assert_eq!(observed_credit_state.get(), U256::ZERO);
    }

    #[test]
    fn protocol_precompile_applies_admission_and_evm_spec() {
        let observed_spec = Rc::new(Cell::new(None));
        let execute_spec = observed_spec.clone();
        let mut cfg = revm::context::CfgEnv::<TempoHardfork>::default();
        cfg.spec = TempoHardfork::T8;
        let env = ZonePrecompileEnv::new(
            &cfg,
            StorageActions::disabled(),
            Rc::new(RefCell::new(NonCreditableSlots::empty())),
        );
        let checked = Rc::new(Cell::new(false));
        let rejected = create_precompile(
            "L1AdmissionTest",
            &env,
            RejectRules(checked.clone()),
            |_, _| panic!("rejected call must not execute"),
        );
        let mut ctx = test_context();
        assert!(
            rejected
                .call(input(&mut ctx, &[1, 2, 3, 4], Address::ZERO, FIXED_GAS))
                .unwrap()
                .is_revert()
        );
        assert!(checked.get());

        let precompile = create_precompile("ProtocolTest", &env, NoCallRules, move |_, _| {
            execute_spec.set(Some(StorageCtx::default().spec()));
            Ok(StorageCtx::default().success_output(Bytes::new()))
        });

        precompile
            .call(input(&mut ctx, &[], Address::ZERO, u64::MAX))
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
        let cfg = revm::context::CfgEnv::<TempoHardfork>::default();
        let env = ZonePrecompileEnv::new(
            &cfg,
            StorageActions::disabled(),
            Rc::new(RefCell::new(NonCreditableSlots::empty())),
        );
        let precompile = create_precompile(
            "AdmissionTest",
            &env,
            RejectRules(checked.clone()),
            move |_, _| {
                execute_flag.set(true);
                Ok(StorageCtx::default().success_output(Bytes::new()))
            },
        );
        let mut ctx = test_context();
        let calldata = [1, 2, 3, 4];

        let out_of_gas = precompile
            .call(input(&mut ctx, &calldata, Address::ZERO, FIXED_GAS - 1))
            .unwrap();
        assert!(out_of_gas.is_halt());
        assert_eq!(out_of_gas.halt_reason(), Some(&PrecompileHalt::OutOfGas));
        assert!(!checked.get());
        assert!(!executed.get());

        let rejected = precompile
            .call(input(&mut ctx, &calldata, Address::ZERO, FIXED_GAS))
            .unwrap();
        assert!(checked.get());
        assert!(!executed.get());
        assert_eq!(rejected.gas_used, FIXED_GAS);
        assert_eq!(rejected.bytes, Bytes::from_static(b"denied"));
    }

    #[test]
    fn input_gas_threshold_tracks_t11() {
        let calldata = [0u8; 32];

        for (spec, required_gas) in [(TempoHardfork::T10, 6), (TempoHardfork::T11, 30)] {
            let mut cfg = revm::context::CfgEnv::<TempoHardfork>::default();
            cfg.spec = spec;
            let env = ZonePrecompileEnv::new(
                &cfg,
                StorageActions::disabled(),
                Rc::new(RefCell::new(NonCreditableSlots::empty())),
            );
            let precompile = create_precompile("InputGasTest", &env, NoCallRules, |_, _| {
                Ok(StorageCtx::default().success_output(Bytes::new()))
            });
            let mut ctx = test_context();

            let insufficient = precompile
                .call(input(&mut ctx, &calldata, Address::ZERO, required_gas - 1))
                .unwrap();
            assert_eq!(
                insufficient.halt_reason(),
                Some(&PrecompileHalt::OutOfGas),
                "{spec:?} must require {required_gas} input gas"
            );

            let sufficient = precompile
                .call(input(&mut ctx, &calldata, Address::ZERO, required_gas))
                .unwrap();
            assert!(!sufficient.is_halt(), "{spec:?} must accept its exact cost");
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
        let cfg = revm::context::CfgEnv::<TempoHardfork>::default();
        let env = ZonePrecompileEnv::new(
            &cfg,
            StorageActions::disabled(),
            Rc::new(RefCell::new(NonCreditableSlots::empty())),
        );
        let precompile = create_precompile("FatalAdmissionTest", &env, FatalRules, |_, _| {
            panic!("fatal admission must not execute the precompile")
        });
        let mut ctx = test_context();
        let calldata = [1, 2, 3, 4];

        let error = precompile
            .call(input(&mut ctx, &calldata, Address::ZERO, 10))
            .unwrap_err();
        assert!(matches!(
            error,
            revm::precompile::PrecompileError::Fatal(message) if message == "boom"
        ));
    }
}
