use super::{
    super::tests::{ACCOUNT, FUNDER, SOURCE, Trace, evm},
    *,
};
use alloy_primitives::{B256, address, hex};
use alloy_sol_types::{SolError, SolValue};
use revm::{
    context::{ContextSetters, TxEnv},
    database::{CacheDB, EmptyDB},
    handler::SystemCallTx,
    primitives::TxKind,
    state::{AccountInfo, Bytecode},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::PATH_USD_ADDRESS;
use tempo_precompiles::{test_util::TIP20Setup, tip20_funder::RATE_SCALE};
use tempo_primitives::transaction::Call;

const SOURCE2: Address = address!("0000000000000000000000000000000000001001");
const RECIPIENT: Address = address!("0000000000000000000000000000000000004000");
const LIMIT: u64 = 3_000_000;

type TestEvm = TempoEvm<CacheDB<EmptyDB>, Trace>;

fn setup(spec: TempoHardfork) -> (TestEvm, Address) {
    let mut evm = evm(spec);
    let code = Bytecode::new_raw(
        hex::decode(include_str!("../fixtures/OwnerFundingSource.hex").trim())
            .unwrap()
            .into(),
    );
    for source in [SOURCE, SOURCE2] {
        evm.inner.ctx.journaled_state.database.insert_account_info(
            source,
            AccountInfo {
                code_hash: code.hash_slow(),
                code: Some(code.clone()),
                ..Default::default()
            },
        );
    }
    evm.inner
        .ctx
        .set_tx(TxEnv::new_system_tx_with_caller(ACCOUNT, RECIPIENT, Bytes::new()).into());
    let output = StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
        TIP20Setup::path_usd(ACCOUNT)
            .with_issuer(ACCOUNT)
            .with_mint(ACCOUNT, U256::from(1000))
            .apply()
            .unwrap();
        TIP20Setup::create("Output", "OUT", ACCOUNT)
            .with_salt(B256::ZERO)
            .with_issuer(ACCOUNT)
            .with_mint(SOURCE, U256::from(1000))
            .with_mint(SOURCE2, U256::from(1000))
            .apply()
            .unwrap()
            .address()
    });
    evm.inner.ctx.journaled_state.logs.clear();
    (evm, output)
}

fn source(
    target: Address,
    debit: u64,
    deliver: u64,
    expected_cost: u64,
    mode: u64,
) -> ITIP20Funder::Source {
    source_with_input(
        target,
        PATH_USD_ADDRESS,
        RATE_SCALE,
        U256::from(debit),
        debit,
        deliver,
        expected_cost,
        mode,
    )
}

#[allow(clippy::too_many_arguments)]
fn source_with_input(
    target: Address,
    asset: Address,
    rate: U256,
    cap: U256,
    debit: u64,
    deliver: u64,
    expected_cost: u64,
    mode: u64,
) -> ITIP20Funder::Source {
    ITIP20Funder::Source {
        target,
        data: (
            asset,
            rate,
            cap,
            U256::from(debit),
            U256::from(deliver),
            U256::from(expected_cost),
            U256::from(mode),
        )
            .abi_encode()
            .into(),
    }
}

fn requirement(
    asset: Address,
    amount: u64,
    sources: Vec<ITIP20Funder::Source>,
) -> FundingRequirement {
    FundingRequirement {
        asset,
        amount: U256::from(amount),
        slippage_bps: 0,
        sources,
    }
}

fn transfer(asset: Address, amount: u64) -> Call {
    Call {
        to: TxKind::Call(asset),
        value: U256::ZERO,
        input: ITIP20::transferCall {
            to: RECIPIENT,
            amount: U256::from(amount),
        }
        .abi_encode()
        .into(),
    }
}

fn balance(evm: &mut TestEvm, asset: Address, account: Address) -> U256 {
    StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
        funding_balance(asset, account).unwrap()
    })
}

fn run(
    evm: &mut TestEvm,
    requirements: &[FundingRequirement],
    calls: Vec<Call>,
    inspect: bool,
    limit: u64,
    reservoir: u64,
) -> FrameResult {
    let mut tx = TxEnv::new_system_tx_with_caller(ACCOUNT, RECIPIENT, Bytes::new());
    tx.gas_limit = limit;
    tx.kind = calls.first().unwrap().to;
    let tempo_env = evm.inner.ctx.tx.tempo_tx_env.clone();
    evm.inner.ctx.set_tx(tx.into());
    evm.inner.ctx.tx.tempo_tx_env = tempo_env;
    let original = evm.inner.ctx.tx.inner.clone();
    let run_loop = if inspect {
        TempoEvmHandler::inspect_run_exec_loop
    } else {
        TempoEvmHandler::run_exec_loop
    };
    let execute_single = if inspect {
        TempoEvmHandler::inspect_execute_single_call
    } else {
        TempoEvmHandler::execute_single_call
    };
    let result = TempoEvmHandler::new()
        .execute_multi_call_with_prelude(
            evm,
            limit,
            reservoir,
            calls,
            |handler, evm, gas| {
                handler.require_owner_funds_with(evm, gas, FUNDER, requirements, run_loop)
            },
            execute_single,
        )
        .unwrap();
    assert_eq!(evm.inner.ctx.tx.inner, original);
    assert!(evm.inner.frame_stack.index().is_none());
    result
}

fn noop() -> Call {
    Call {
        to: TxKind::Call(RECIPIENT),
        value: U256::ZERO,
        input: Bytes::new(),
    }
}

fn funding_events(evm: &TestEvm) -> Vec<&alloy_primitives::Log> {
    evm.inner
        .ctx
        .journaled_state
        .logs
        .iter()
        .filter(|log| log.address == FUNDER)
        .collect()
}

#[test]
fn two_sources_fund_and_pay_without_approvals() {
    for spec in [TempoHardfork::T3, TempoHardfork::T4, TempoHardfork::T5] {
        for inspect in [false, true] {
            let (mut evm, output) = setup(spec);
            let sources = vec![
                source(SOURCE, 30, 30, 50, 0),
                source(SOURCE2, 20, 20, 20, 0),
            ];
            let request_hash = keccak256(&sources[0].data);
            let result = run(
                &mut evm,
                &[requirement(output, 50, sources)],
                vec![transfer(output, 50)],
                inspect,
                LIMIT,
                0,
            );
            assert!(result.instruction_result().is_ok(), "{spec:?}: {result:?}");
            assert_eq!(balance(&mut evm, output, ACCOUNT), U256::ZERO);
            assert_eq!(balance(&mut evm, output, RECIPIENT), U256::from(50));
            assert_eq!(
                balance(&mut evm, PATH_USD_ADDRESS, ACCOUNT),
                U256::from(950)
            );
            let logs = funding_events(&evm);
            assert_eq!(logs.len(), 3);
            let funded = ITIP20Funder::SourceFunded::decode_log(logs[0])
                .unwrap()
                .data;
            assert_eq!(
                (funded.amountIn, funded.amountOut, funded.requestHash),
                (U256::from(30), U256::from(30), request_hash)
            );
            let required = ITIP20Funder::FundsRequired::decode_log(logs[2])
                .unwrap()
                .data;
            assert_eq!(
                (required.key, required.fundedAmount),
                (Address::ZERO, U256::from(50))
            );
            assert!(result.gas().total_gas_spent() > 0 && result.gas().total_gas_spent() < LIMIT);
        }
    }
}

#[test]
fn existing_balance_and_repeated_assets_are_targets() {
    let (mut evm, output) = setup(TempoHardfork::T5);
    let requirements = [
        requirement(output, 20, vec![source(SOURCE, 20, 20, 20, 0)]),
        requirement(output, 10, vec![source(SOURCE, 0, 0, 0, 1)]),
        requirement(output, 50, vec![source(SOURCE2, 30, 30, 30, 0)]),
    ];
    let result = run(
        &mut evm,
        &requirements,
        vec![transfer(output, 50)],
        true,
        LIMIT,
        0,
    );
    assert!(result.instruction_result().is_ok(), "{result:?}");
    assert_eq!(funding_events(&evm).len(), 5);
    let event = ITIP20Funder::FundsRequired::decode_log(funding_events(&evm)[2])
        .unwrap()
        .data;
    assert_eq!(event.fundedAmount, U256::ZERO);
    assert_eq!(
        evm.inner
            .inspector
            .calls
            .iter()
            .filter(|(caller, _, _, _)| *caller == FUNDER)
            .count(),
        4
    );
}

#[test]
fn aggregate_cost_uses_actual_inputs_and_offsets_prices() {
    let (mut evm, output) = setup(TempoHardfork::T5);
    let request = requirement(
        output,
        50,
        vec![
            source_with_input(
                SOURCE,
                PATH_USD_ADDRESS,
                RATE_SCALE,
                U256::from(50),
                20,
                30,
                50,
                0,
            ),
            source(SOURCE2, 30, 20, 30, 0),
        ],
    );
    let result = run(
        &mut evm,
        &[request],
        vec![transfer(output, 50)],
        false,
        LIMIT,
        0,
    );
    assert!(result.instruction_result().is_ok(), "{result:?}");
    assert_eq!(
        balance(&mut evm, PATH_USD_ADDRESS, ACCOUNT),
        U256::from(950)
    );
}

#[test]
fn failures_revert_funding_and_do_not_try_later_sources() {
    for inspect in [false, true] {
        // Source revert, zero delivery with debit, excess output, oversized plan, malformed plan, static write.
        for mode in [1, 2, 3, 7, 8, 9] {
            let (mut evm, output) = setup(TempoHardfork::T5);
            let request = requirement(
                output,
                50,
                vec![
                    source(SOURCE, 20, 20, 50, 0),
                    source(SOURCE2, if mode == 7 { 31 } else { 30 }, 31, 30, mode),
                    source(SOURCE, 0, 0, 0, 1),
                ],
            );
            let result = run(
                &mut evm,
                &[request],
                vec![transfer(output, 50)],
                inspect,
                LIMIT,
                0,
            );
            assert!(!result.instruction_result().is_ok(), "mode {mode}");
            assert_eq!(balance(&mut evm, output, ACCOUNT), U256::ZERO);
            assert_eq!(
                balance(&mut evm, PATH_USD_ADDRESS, ACCOUNT),
                U256::from(1000)
            );
            assert!(evm.inner.ctx.journaled_state.logs.is_empty());
            assert_eq!(result.gas().refunded(), 0);
            if inspect {
                assert_eq!(
                    evm.inner
                        .inspector
                        .calls
                        .iter()
                        .filter(|(caller, target, _, _)| *caller == FUNDER && *target == SOURCE)
                        .count(),
                    2
                );
            }
        }
    }
}

#[test]
fn application_failure_rolls_back_funding_and_clears_permission() {
    alloy_sol_types::sol! { function application(); function steal(address token, address account); }
    for app in [
        applicationCall {}.abi_encode(),
        stealCall {
            token: PATH_USD_ADDRESS,
            account: ACCOUNT,
        }
        .abi_encode(),
    ] {
        let (mut evm, output) = setup(TempoHardfork::T5);
        let result = run(
            &mut evm,
            &[requirement(output, 50, vec![source(SOURCE, 50, 50, 50, 0)])],
            vec![
                transfer(output, 50),
                Call {
                    to: TxKind::Call(SOURCE),
                    value: U256::ZERO,
                    input: app.into(),
                },
            ],
            true,
            LIMIT,
            0,
        );
        assert!(!result.instruction_result().is_ok());
        assert_eq!(balance(&mut evm, output, RECIPIENT), U256::ZERO);
        assert_eq!(
            balance(&mut evm, PATH_USD_ADDRESS, ACCOUNT),
            U256::from(1000)
        );
        assert!(evm.inner.ctx.journaled_state.logs.is_empty());
    }
}

#[test]
fn zero_and_no_input_contributions_continue_in_order() {
    let (mut evm, output) = setup(TempoHardfork::T5);
    let result = run(
        &mut evm,
        &[requirement(
            output,
            50,
            vec![
                source(SOURCE, 0, 0, 50, 0),
                source_with_input(SOURCE2, Address::ZERO, U256::ZERO, U256::ZERO, 0, 50, 50, 0),
            ],
        )],
        vec![transfer(output, 50)],
        true,
        LIMIT,
        0,
    );
    assert!(result.instruction_result().is_ok(), "{result:?}");
    assert_eq!(
        balance(&mut evm, PATH_USD_ADDRESS, ACCOUNT),
        U256::from(1000)
    );
    assert_eq!(funding_events(&evm).len(), 2);
    let event = ITIP20Funder::SourceFunded::decode_log(funding_events(&evm)[0])
        .unwrap()
        .data;
    assert_eq!((event.assetIn, event.amountIn), (Address::ZERO, U256::ZERO));
}

#[test]
fn insufficient_output_and_input_limit_revert() {
    for debit in [49, 51] {
        let (mut evm, output) = setup(TempoHardfork::T5);
        let result = run(
            &mut evm,
            &[requirement(
                output,
                50,
                vec![source(SOURCE, debit, 49, 50, 0)],
            )],
            vec![noop()],
            true,
            LIMIT,
            0,
        );
        assert!(!result.instruction_result().is_ok());
        if debit == 49 {
            assert_eq!(
                result.output().data().as_ref(),
                ITIP20Funder::InsufficientFunding {
                    required: U256::from(50),
                    available: U256::from(49)
                }
                .abi_encode()
            );
        } else {
            assert_eq!(
                result.output().data().as_ref(),
                ITIP20Funder::InputLimitExceeded {
                    source: SOURCE,
                    limit: U256::from(50),
                    attempted: U256::from(51)
                }
                .abi_encode()
            );
        }
        assert_eq!(
            balance(&mut evm, PATH_USD_ADDRESS, ACCOUNT),
            U256::from(1000)
        );
    }
}

#[test]
fn rechecks_all_balances_before_application_calls() {
    let (mut evm, output) = setup(TempoHardfork::T5);
    let requests = [
        requirement(PATH_USD_ADDRESS, 1000, vec![]),
        requirement(output, 50, vec![source(SOURCE, 50, 50, 50, 0)]),
    ];
    let result = run(
        &mut evm,
        &requests,
        vec![transfer(output, 50)],
        true,
        LIMIT,
        0,
    );
    assert_eq!(
        result.output().data().as_ref(),
        ITIP20Funder::InsufficientFunding {
            required: U256::from(1000),
            available: U256::from(950)
        }
        .abi_encode()
    );
    assert_eq!(
        balance(&mut evm, PATH_USD_ADDRESS, ACCOUNT),
        U256::from(1000)
    );
    assert!(evm.inner.ctx.journaled_state.logs.is_empty());
}

#[test]
fn rejects_invalid_context_and_arguments_before_balance_shortcut() {
    for mode in 0..5 {
        let (mut evm, _) = setup(TempoHardfork::T5);
        let mut request = requirement(PATH_USD_ADDRESS, 0, vec![]);
        match mode {
            0 => StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
                AccountKeychain::new().set_transaction_key(SOURCE).unwrap()
            }),
            1 => request.slippage_bps = 10_001,
            2 => request.asset = RECIPIENT,
            3 => request.asset = address!("20c0000000000000000000000000000000000007"),
            4 => request.sources.push(source(Address::ZERO, 0, 0, 0, 0)),
            _ => unreachable!(),
        }
        let result = run(&mut evm, &[request], vec![noop()], true, LIMIT, 0);
        assert!(!result.instruction_result().is_ok(), "mode {mode}");
        assert!(evm.inner.inspector.calls.is_empty());
        assert!(evm.inner.ctx.journaled_state.logs.is_empty());
    }
}

#[test]
fn inspected_execution_matches_plain_gas_and_logs() {
    let mut results = Vec::new();
    for inspect in [false, true] {
        let (mut evm, output) = setup(TempoHardfork::T4);
        let result = run(
            &mut evm,
            &[requirement(
                output,
                50,
                vec![
                    source(SOURCE, 30, 30, 50, 0),
                    source(SOURCE2, 20, 20, 20, 0),
                ],
            )],
            vec![transfer(output, 50)],
            inspect,
            LIMIT,
            100_000,
        );
        assert!(result.instruction_result().is_ok(), "{result:?}");
        results.push((*result.gas(), evm.inner.ctx.journaled_state.logs.clone()));
    }
    assert_eq!(results[0], results[1]);
}

#[test]
fn out_of_gas_rolls_back_every_completed_stage() {
    for limit in [1, 2000, 10_000, 50_000, 100_000] {
        let (mut evm, output) = setup(TempoHardfork::T4);
        let result = run(
            &mut evm,
            &[requirement(
                output,
                50,
                vec![
                    source(SOURCE, 30, 30, 50, 0),
                    source(SOURCE2, 20, 20, 20, 0),
                ],
            )],
            vec![transfer(output, 50)],
            true,
            limit,
            100_000,
        );
        if !result.instruction_result().is_ok() {
            assert_eq!(
                balance(&mut evm, PATH_USD_ADDRESS, ACCOUNT),
                U256::from(1000)
            );
            assert_eq!(balance(&mut evm, output, RECIPIENT), U256::ZERO);
            assert!(evm.inner.ctx.journaled_state.logs.is_empty());
            assert_eq!(result.gas().state_gas_spent(), 0);
            assert_eq!(result.gas().refunded(), 0);
            assert_eq!(result.gas().reservoir(), 100_000);
        }
    }
}

#[test]
fn validates_plans_and_rejects_output_balance_decreases() {
    for mode in 0..5 {
        let (mut evm, output) = setup(TempoHardfork::T5);
        let (asset, request) = match mode {
            0 => (
                output,
                source_with_input(SOURCE, PATH_USD_ADDRESS, U256::ZERO, U256::ONE, 0, 50, 0, 0),
            ),
            1 => (
                output,
                source_with_input(SOURCE, Address::ZERO, RATE_SCALE, U256::ZERO, 0, 50, 0, 0),
            ),
            2 => (
                output,
                source_with_input(SOURCE, Address::ZERO, U256::ZERO, U256::ONE, 0, 50, 0, 0),
            ),
            3 => (output, source(RECIPIENT, 0, 50, 0, 0)),
            // Consume the very output balance being measured.
            _ => (PATH_USD_ADDRESS, source(SOURCE, 1, 0, 0, 0)),
        };
        let result = run(
            &mut evm,
            &[requirement(
                asset,
                if mode == 4 { 1001 } else { 50 },
                vec![request],
            )],
            vec![noop()],
            true,
            LIMIT,
            0,
        );
        assert!(!result.instruction_result().is_ok());
        if mode < 4 {
            assert_eq!(
                result.output().data().as_ref(),
                ITIP20Funder::InvalidFundingPlan {
                    source: if mode == 3 { RECIPIENT } else { SOURCE }
                }
                .abi_encode()
            );
        } else {
            assert_eq!(
                result.output().data().as_ref(),
                ITIP20Funder::UnexpectedFundingAmount {
                    source: SOURCE,
                    maximum: U256::ONE,
                    received: U256::ZERO
                }
                .abi_encode()
            );
        }
        assert_eq!(
            balance(&mut evm, PATH_USD_ADDRESS, ACCOUNT),
            U256::from(1000)
        );
        assert!(evm.inner.ctx.journaled_state.logs.is_empty());
    }
}

#[test]
fn owner_slippage_and_non_unit_rates_bound_total_cost() {
    for debit in [25, 26] {
        let (mut evm, output) = setup(TempoHardfork::T5);
        let mut request = requirement(
            output,
            49,
            vec![source_with_input(
                SOURCE,
                PATH_USD_ADDRESS,
                RATE_SCALE * U256::from(2),
                U256::MAX,
                debit,
                49,
                50,
                0,
            )],
        );
        request.slippage_bps = 205; // floor(49 * 1.0205) = 50; at rate 2, at most 25 inputs.
        let result = run(
            &mut evm,
            &[request],
            vec![transfer(output, 49)],
            true,
            LIMIT,
            0,
        );
        assert_eq!(result.instruction_result().is_ok(), debit == 25);
        assert_eq!(
            balance(&mut evm, PATH_USD_ADDRESS, ACCOUNT),
            U256::from(if debit == 25 { 975 } else { 1000 })
        );
    }
}

#[test]
fn failed_funding_preserves_create_protocol_nonce_only() {
    for nonce_key in [U256::ZERO, U256::ONE] {
        let (mut evm, output) = setup(TempoHardfork::T4);
        evm.inner.ctx.tx.tempo_tx_env = Some(Box::new(TempoBatchCallEnv {
            nonce_key,
            ..Default::default()
        }));
        let result = run(
            &mut evm,
            &[requirement(output, 50, vec![])],
            vec![Call {
                to: TxKind::Create,
                value: U256::ZERO,
                input: Bytes::new(),
            }],
            true,
            LIMIT,
            0,
        );
        assert_eq!(result.instruction_result(), InstructionResult::Revert);
        let nonce = evm
            .inner
            .ctx
            .journaled_state
            .load_account(ACCOUNT)
            .unwrap()
            .data
            .info
            .nonce;
        assert_eq!(nonce, if nonce_key.is_zero() { 1 } else { 0 });
        assert!(evm.inner.inspector.calls.is_empty());
    }
}

#[test]
fn fatal_application_errors_also_revert_funding() {
    let (mut evm, output) = setup(TempoHardfork::T5);
    evm.inner.ctx.tx.inner.gas_limit = LIMIT;
    let requirements = [requirement(output, 50, vec![source(SOURCE, 50, 50, 50, 0)])];
    let result = TempoEvmHandler::new().execute_multi_call_with_prelude(
        &mut evm,
        LIMIT,
        0,
        vec![noop()],
        |handler, evm, gas| {
            handler.require_owner_funds_with(
                evm,
                gas,
                FUNDER,
                &requirements,
                TempoEvmHandler::run_exec_loop,
            )
        },
        |_, _, _| Err(EVMError::Custom("database unavailable".into())),
    );
    assert!(matches!(result, Err(EVMError::Custom(_))));
    assert_eq!(balance(&mut evm, output, ACCOUNT), U256::ZERO);
    assert_eq!(
        balance(&mut evm, PATH_USD_ADDRESS, ACCOUNT),
        U256::from(1000)
    );
    assert!(evm.inner.ctx.journaled_state.logs.is_empty());
}
