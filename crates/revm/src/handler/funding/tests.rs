use super::*;
use crate::{gas_params::tempo_gas_params, handler::TempoEvmHandler};
use alloy_primitives::{address, hex};
use alloy_sol_types::{SolCall, SolError, SolValue};
use revm::{
    Context, MainContext,
    context::{CfgEnv, ContextSetters, TxEnv},
    database::{CacheDB, EmptyDB},
    handler::SystemCallTx,
    state::{AccountInfo, Bytecode},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{IFundingSource, ITIP20Funder};

const FUNDER: Address = address!("ffffffffffffffffffffffffffffffffffff1120");
const SOURCE: Address = address!("0000000000000000000000000000000000001000");
const ACCOUNT: Address = address!("0000000000000000000000000000000000002000");
const ASSET: Address = address!("0000000000000000000000000000000000003000");

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
    run_batch(evm, mode, gas, inspect, false)
}

// Test-only orchestration until transaction admission, policy checks, and input metering are implemented.
fn run_batch(
    evm: &mut TempoEvm<CacheDB<EmptyDB>, Trace>,
    mode: u64,
    limit: u64,
    inspect: bool,
    fail_application: bool,
) -> revm::context::result::ExecutionResult {
    let mut tx = TxEnv::new_system_tx_with_caller(ACCOUNT, ASSET, Bytes::new());
    tx.gas_limit = limit;
    evm.inner.ctx.set_tx(tx.into());
    let original_tx = evm.inner.ctx.tx.clone();
    let checkpoint = evm.ctx_mut().journal_mut().checkpoint();
    let mut handler = TempoEvmHandler::new();
    let mut gas = GasTracker::new(limit, limit, 0);
    let run_loop = if inspect {
        TempoEvmHandler::inspect_run_exec_loop
    } else {
        TempoEvmHandler::run_exec_loop
    };
    let mut result = handler
        .execute_funding_call_with(
            evm,
            &mut gas,
            FundingCall {
                caller: FUNDER,
                source: SOURCE,
                is_static: true,
                data: IFundingSource::quoteCall {
                    account: ACCOUNT,
                    amountOut: U256::from(50),
                    assetOut: ASSET,
                    maxCost: U256::from(50),
                    requestData: U256::from(mode).abi_encode().into(),
                    policyData: Bytes::new(),
                    ownerAuthorized: true,
                }
                .abi_encode()
                .into(),
            },
            run_loop,
        )
        .unwrap();
    if result.instruction_result().is_ok() {
        match IFundingSource::quoteCall::abi_decode_returns_validate(result.output().data()) {
            Ok(plan) => {
                result = handler
                    .execute_funding_call_with(
                        evm,
                        &mut gas,
                        FundingCall {
                            caller: FUNDER,
                            source: SOURCE,
                            is_static: false,
                            data: IFundingSource::fundCall {
                                account: ACCOUNT,
                                assetOut: ASSET,
                                amountOut: U256::from(50),
                                requestData: plan.requestData,
                            }
                            .abi_encode()
                            .into(),
                        },
                        run_loop,
                    )
                    .unwrap();
            }
            Err(_) => {
                result = FrameResult::Call(CallOutcome::new(
                    InterpreterResult {
                        result: InstructionResult::Revert,
                        gas: *result.gas(),
                        output: ITIP20Funder::InvalidFundingQuote { source: SOURCE }
                            .abi_encode()
                            .into(),
                    },
                    0..0,
                ));
            }
        }
    }
    if result.instruction_result().is_ok() && fail_application {
        alloy_sol_types::sol! { function application(); }
        evm.inner.ctx.tx.inner.kind = revm::primitives::TxKind::Call(SOURCE);
        evm.inner.ctx.tx.inner.data = applicationCall {}.abi_encode().into();
        result = if inspect {
            handler.inspect_execute_single_call(evm, &mut gas).unwrap()
        } else {
            handler.execute_single_call(evm, &mut gas).unwrap()
        };
        evm.inner.ctx.tx.inner = original_tx.inner.clone();
    }
    if result.instruction_result().is_ok() {
        evm.ctx_mut().journal_mut().checkpoint_commit();
    } else {
        evm.ctx_mut().journal_mut().checkpoint_revert(checkpoint);
        // The shared tracker includes state gas from earlier successful callbacks.
        super::super::normalize_failed_batch_result_gas(&mut result, limit, 0, 0);
    }
    assert_eq!(evm.inner.ctx.tx.inner, original_tx.inner);
    assert!(evm.inner.frame_stack.index().is_none());
    let result_gas = post_execution::build_result_gas(
        result.instruction_result().is_halt(),
        result.gas(),
        InitialAndFloorGas::default(),
    );
    handler.execution_result(evm, result, result_gas).unwrap()
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
fn quotes_and_funds_with_native_caller() {
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
            (FUNDER, SOURCE, CallScheme::StaticCall, true),
            (FUNDER, SOURCE, CallScheme::Call, false),
        ]
    );
    assert_eq!(evm.inner.inspector.ends.len(), 2);
    assert_eq!(evm.inner.inspector.ends.last().unwrap().0, SOURCE);
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
        assert_eq!(evm.inner.inspector.calls.len(), 1);
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
                ITIP20Funder::InvalidFundingQuote { source: SOURCE }.abi_encode()
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
fn nested_revert_does_not_corrupt_parent() {
    for mode in [6, 7] {
        let mut evm = evm(TempoHardfork::T3);
        let result = run(&mut evm, mode, 2_000_000, true);
        assert!(result.is_success(), "mode {mode}: {result:?}");
        assert_eq!(slot(&evm, 0), U256::ONE);
        assert_eq!(evm.inner.inspector.calls.len(), 3);
        assert_eq!(evm.inner.inspector.ends.len(), 3);
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
fn reuses_standard_frame_stack_after_failure() {
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

#[test]
fn callbacks_charge_the_instruction_base_cost() {
    use revm::bytecode::opcode::{CALL, STATICCALL};
    for inspect in [false, true] {
        let mut baseline = evm(TempoHardfork::T3);
        let mut changed = evm(TempoHardfork::T3);
        changed.inner.instruction.gas_table_mut()[CALL as usize] += 17;
        changed.inner.instruction.gas_table_mut()[STATICCALL as usize] += 31;
        let a = run(&mut baseline, 0, 2_000_000, inspect);
        let b = run(&mut changed, 0, 2_000_000, inspect);
        assert!(a.is_success() && b.is_success());
        assert_eq!(b.tx_gas_used() - a.tx_gas_used(), 48);
        assert_eq!(
            baseline.inner.ctx.journaled_state.state,
            changed.inner.ctx.journaled_state.state
        );
    }
}

#[test]
fn application_failure_reverts_funding() {
    for spec in [TempoHardfork::T3, TempoHardfork::T4] {
        for inspect in [false, true] {
            let mut evm = evm(spec);
            let result = run_batch(&mut evm, 0, 2_000_000, inspect, true);
            assert!(!result.is_success());
            alloy_sol_types::sol! { error SourceFailure(uint256 mode); }
            assert_eq!(
                result.output().unwrap().as_ref(),
                SourceFailure {
                    mode: U256::from(9)
                }
                .abi_encode()
            );
            assert!(result.logs().is_empty());
            assert_eq!(result.gas().state_gas_spent_final(), 0);
            for index in 0..5 {
                assert_eq!(slot(&evm, index), U256::ZERO);
            }
        }
    }
}

#[test]
fn solidity_calls_cannot_start_funding() {
    let mut evm = evm(TempoHardfork::T3);
    let mut tx = TxEnv::new_system_tx_with_caller(ACCOUNT, FUNDER, hex!("1e35b1a8").into());
    tx.gas_limit = 2_000_000;
    evm.inner.ctx.set_tx(tx.into());
    let result = TempoEvmHandler::new()
        .inspect_run_system_call(&mut evm)
        .unwrap();
    assert!(result.is_success()); // An unregistered address has ordinary empty-account behavior.
    assert_eq!(evm.inner.inspector.calls.len(), 1);
    assert_eq!(slot(&evm, 0), U256::ZERO);
}

#[test]
fn public_quotes_grant_no_funding_authority() {
    for inspect in [false, true] {
        let mut evm = evm(TempoHardfork::T3);
        let data = IFundingSource::quoteCall {
            account: ACCOUNT,
            amountOut: U256::from(50),
            assetOut: ASSET,
            maxCost: U256::from(50),
            requestData: U256::ZERO.abi_encode().into(),
            policyData: Bytes::new(),
            ownerAuthorized: true,
        }
        .abi_encode()
        .into();
        let mut tx = TxEnv::new_system_tx_with_caller(ACCOUNT, SOURCE, data);
        tx.gas_limit = 2_000_000;
        evm.inner.ctx.set_tx(tx.into());
        let mut handler = TempoEvmHandler::new();
        let result = if inspect {
            handler.inspect_run_system_call(&mut evm)
        } else {
            handler.run_system_call(&mut evm)
        }
        .unwrap();
        assert!(result.is_success());
        let data = IFundingSource::fundCall {
            account: ACCOUNT,
            assetOut: ASSET,
            amountOut: U256::from(50),
            requestData: IFundingSource::quoteCall::abi_decode_returns_validate(
                result.output().unwrap(),
            )
            .unwrap()
            .data,
        }
        .abi_encode()
        .into();
        let mut tx = TxEnv::new_system_tx_with_caller(ACCOUNT, SOURCE, data);
        tx.gas_limit = 2_000_000;
        evm.inner.ctx.set_tx(tx.into());
        let result = if inspect {
            handler.inspect_run_system_call(&mut evm)
        } else {
            handler.run_system_call(&mut evm)
        }
        .unwrap();
        assert!(!result.is_success());
        assert_eq!(slot(&evm, 0), U256::ZERO);
    }
}
