use super::*;
use crate::{TempoEvm, gas_params::tempo_gas_params, handler::TempoEvmHandler};
use alloy_primitives::{address, hex};
use alloy_sol_types::{SolError, SolValue};
use revm::{
    Context, Inspector, MainContext,
    context::{CfgEnv, ContextSetters, TxEnv},
    database::{CacheDB, EmptyDB},
    handler::{Handler, SystemCallTx},
    inspector::InspectorHandler,
    interpreter::{CallOutcome, FrameInput},
    state::{AccountInfo, Bytecode},
};
use tempo_chainspec::hardfork::TempoHardfork;

const FUNDER: Address = address!("ffffffffffffffffffffffffffffffffffff1120");
const SOURCE: Address = address!("0000000000000000000000000000000000001000");
const ACCOUNT: Address = address!("0000000000000000000000000000000000002000");
const ASSET: Address = address!("0000000000000000000000000000000000003000");

// This admission hook is absent from node builds. It supplies one transport-only funding invocation.
pub(super) fn admit<DB: Database>(
    frame: &mut TempoFrame,
    ctx: &mut TempoContext<DB>,
    mut init: FrameInit,
) -> FrameInit {
    if let FrameInput::Call(inputs) = &mut init.frame_input {
        if inputs.bytecode_address == FUNDER {
            let data = inputs.input.bytes(ctx);
            let request = ITIP20Funder::requireFundsCall::abi_decode_validate(&data);
            let stage = if init.depth > 0 {
                Stage::Finished(
                    InstructionResult::Revert,
                    ITIP20Funder::FundingReentrancy {}.abi_encode().into(),
                )
            } else if inputs.is_static
                || inputs.scheme != CallScheme::Call
                || !inputs.value.get().is_zero()
            {
                Stage::Finished(
                    InstructionResult::Revert,
                    ITIP20Funder::InvalidFundingContext {}.abi_encode().into(),
                )
            } else if let Ok(request) = &request {
                if request.sources.len() == 1 {
                    Stage::Prepare(
                        IFundingSource::prepareCall {
                            assetOut: request.asset,
                            maxCost: request.amount,
                            data: request.sources[0].data.clone(),
                            policyData: Bytes::new(),
                            ownerAuthorized: true,
                        }
                        .abi_encode()
                        .into(),
                    )
                } else {
                    Stage::Finished(InstructionResult::Revert, Bytes::new())
                }
            } else {
                Stage::Finished(InstructionResult::Revert, Bytes::new())
            };
            frame.funding = Some(FundingContinuation {
                funder: FUNDER,
                source: request
                    .as_ref()
                    .ok()
                    .and_then(|r| r.sources.first())
                    .map_or(Address::ZERO, |s| s.target),
                account: inputs.caller,
                asset_out: request.as_ref().map_or(Address::ZERO, |r| r.asset),
                amount_out: request.as_ref().map_or(U256::ZERO, |r| r.amount),
                stage,
            });
            inputs.known_bytecode = (
                Default::default(),
                Bytecode::new_raw(Bytes::from_static(&[0])),
            );
        }
    }
    init
}

#[derive(Debug, Default)]
struct Trace {
    calls: Vec<(Address, Address, CallScheme, bool)>,
    ends: Vec<(Address, InstructionResult)>,
    steps: usize,
}
impl Inspector<TempoContext<CacheDB<EmptyDB>>> for Trace {
    fn call(
        &mut self,
        _: &mut TempoContext<CacheDB<EmptyDB>>,
        input: &mut CallInputs,
    ) -> Option<CallOutcome> {
        self.calls.push((
            input.caller,
            input.target_address,
            input.scheme,
            input.is_static,
        ));
        None
    }
    fn call_end(
        &mut self,
        _: &mut TempoContext<CacheDB<EmptyDB>>,
        input: &CallInputs,
        outcome: &mut CallOutcome,
    ) {
        self.ends
            .push((input.target_address, *outcome.instruction_result()));
    }
    fn step(
        &mut self,
        _: &mut revm::interpreter::Interpreter,
        _: &mut TempoContext<CacheDB<EmptyDB>>,
    ) {
        self.steps += 1;
    }
}

fn evm(spec: TempoHardfork) -> TempoEvm<CacheDB<EmptyDB>, Trace> {
    let mut db = CacheDB::new(EmptyDB::new());
    let code = Bytecode::new_raw(
        hex::decode(include_str!("fixtures/FundingSource.hex").trim())
            .unwrap()
            .into(),
    );
    db.insert_account_info(
        SOURCE,
        AccountInfo {
            code_hash: code.hash_slow(),
            code: Some(code),
            ..Default::default()
        },
    );
    let mut cfg = CfgEnv::default();
    cfg.spec = spec;
    cfg.gas_params = tempo_gas_params(spec);
    if spec == TempoHardfork::T4 {
        cfg.enable_amsterdam_eip8037 = true;
        cfg.gas_params = crate::gas_params::tempo_gas_params_with_amsterdam(spec, true);
    }
    let ctx = Context::mainnet()
        .with_db(db)
        .with_block(Default::default())
        .with_cfg(cfg)
        .with_tx(Default::default());
    TempoEvm::new(ctx, Trace::default())
}

fn run(
    evm: &mut TempoEvm<CacheDB<EmptyDB>, Trace>,
    mode: u64,
    gas: u64,
    inspect: bool,
) -> revm::context::result::ExecutionResult {
    let data = ITIP20Funder::requireFundsCall {
        asset: ASSET,
        amount: U256::from(50),
        sources: vec![ITIP20Funder::Source {
            target: SOURCE,
            data: U256::from(mode).abi_encode().into(),
        }],
    }
    .abi_encode()
    .into();
    let mut tx = TxEnv::new_system_tx_with_caller(ACCOUNT, FUNDER, data);
    tx.gas_limit = gas;
    evm.inner.ctx.set_tx(tx.into());
    let mut handler = TempoEvmHandler::new();
    if inspect {
        handler.inspect_run_system_call(evm).unwrap()
    } else {
        handler.run_system_call(evm).unwrap()
    }
}

fn slot(evm: &TempoEvm<CacheDB<EmptyDB>, Trace>, index: u64) -> U256 {
    evm.inner
        .ctx
        .journaled_state
        .state
        .get(&SOURCE)
        .and_then(|account| account.storage.get(&U256::from(index)))
        .map_or(U256::ZERO, |slot| slot.present_value())
}

#[test]
fn prepares_and_funds_with_native_caller() {
    let mut evm = evm(TempoHardfork::T3);
    let result = run(&mut evm, 0, 2_000_000, true);
    assert!(result.is_success(), "{result:?}");
    assert_eq!(slot(&evm, 0), U256::ONE);
    assert_eq!(slot(&evm, 1), U256::from_be_slice(ACCOUNT.as_slice()));
    assert_eq!(slot(&evm, 2), U256::from_be_slice(ASSET.as_slice()));
    assert_eq!(slot(&evm, 3), U256::from(50));
    assert_eq!(
        evm.inner.inspector.calls,
        vec![
            (ACCOUNT, FUNDER, CallScheme::Call, false),
            (FUNDER, SOURCE, CallScheme::StaticCall, true),
            (FUNDER, SOURCE, CallScheme::Call, false),
        ]
    );
    assert_eq!(evm.inner.inspector.ends.len(), 3);
    assert_eq!(evm.inner.inspector.ends.last().unwrap().0, FUNDER);
    assert!(evm.inner.inspector.steps > 0);
    assert_eq!(result.logs().len(), 1);
}

#[test]
fn rejects_static_writes_and_malformed_plans() {
    for mode in [1, 2, 3] {
        let mut evm = evm(TempoHardfork::T3);
        let result = run(&mut evm, mode, 2_000_000, true);
        assert!(!result.is_success(), "mode {mode}");
        assert_eq!(slot(&evm, 0), U256::ZERO);
        assert!(result.logs().is_empty());
        assert_eq!(evm.inner.inspector.calls.len(), 2);
        match mode {
            1 => assert_eq!(
                evm.inner.inspector.ends[0].1,
                InstructionResult::StateChangeDuringStaticCall
            ),
            2 => {
                alloy_sol_types::sol! { error SourceFailure(uint256 mode); }
                assert_eq!(
                    result.output().unwrap().as_ref(),
                    SourceFailure {
                        mode: U256::from(2)
                    }
                    .abi_encode()
                );
            }
            3 => assert_eq!(
                result.output().unwrap().as_ref(),
                ITIP20Funder::InvalidFundingPlan { source: SOURCE }.abi_encode()
            ),
            _ => unreachable!(),
        }
    }
}

#[test]
fn failure_reverts_source_storage_and_logs() {
    for mode in [4, 5] {
        let mut evm = evm(TempoHardfork::T3);
        let result = run(&mut evm, mode, 2_000_000, true);
        assert!(!result.is_success(), "mode {mode}");
        for index in 0..5 {
            assert_eq!(slot(&evm, index), U256::ZERO);
        }
        assert!(result.logs().is_empty());
        assert!(result.tx_gas_used() <= 2_000_000);
        if mode == 4 {
            alloy_sol_types::sol! { error SourceFailure(uint256 mode); }
            assert_eq!(
                result.output().unwrap().as_ref(),
                SourceFailure {
                    mode: U256::from(4)
                }
                .abi_encode()
            );
        }
        if mode == 5 {
            assert!(result.tx_gas_used() > 1_900_000);
        }
    }
}

#[test]
fn nested_revert_and_reentrancy_do_not_corrupt_parent() {
    for mode in [6, 7] {
        let mut evm = evm(TempoHardfork::T3);
        let result = run(&mut evm, mode, 2_000_000, true);
        assert!(result.is_success(), "mode {mode}: {result:?}");
        assert_eq!(slot(&evm, 0), U256::ONE);
        assert_eq!(evm.inner.inspector.calls.len(), 4);
        assert_eq!(evm.inner.inspector.ends.len(), 4);
    }
}

#[test]
fn inspected_and_plain_execution_match() {
    for mode in 0..=8 {
        let mut plain = evm(TempoHardfork::T3);
        let mut inspected = evm(TempoHardfork::T3);
        let a = run(&mut plain, mode, 2_000_000, false);
        let b = run(&mut inspected, mode, 2_000_000, true);
        assert_eq!(a, b, "mode {mode}");
        assert_eq!(
            plain.inner.ctx.journaled_state.state,
            inspected.inner.ctx.journaled_state.state
        );
    }
}

#[test]
fn reused_frame_stack_clears_failed_continuations() {
    let mut evm = evm(TempoHardfork::T3);
    assert!(!run(&mut evm, 4, 2_000_000, true).is_success());
    assert!(run(&mut evm, 0, 2_000_000, true).is_success());
    assert_eq!(slot(&evm, 0), U256::ONE);
    assert!(run(&mut evm, 0, 2_000_000, false).is_success());
    assert_eq!(slot(&evm, 0), U256::from(2));
    assert!(evm.inner.frame_stack.index().is_none());
}

#[test]
fn state_gas_and_refunds_match_with_inspection() {
    for mode in [0, 4, 5, 6, 8] {
        let mut plain = evm(TempoHardfork::T4);
        let mut inspected = evm(TempoHardfork::T4);
        let a = run(&mut plain, mode, 2_000_000, false);
        let b = run(&mut inspected, mode, 2_000_000, true);
        assert_eq!(a, b, "mode {mode}");
        assert_eq!(a.is_success(), matches!(mode, 0 | 6 | 8));
        assert_eq!(
            a.gas().state_gas_spent_final(),
            match mode {
                0 | 6 => 5 * 230_000,
                8 => 4 * 230_000,
                _ => 0,
            }
        );
        assert_eq!(
            plain.inner.ctx.journaled_state.state,
            inspected.inner.ctx.journaled_state.state
        );
    }
}
