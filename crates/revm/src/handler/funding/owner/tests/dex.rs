use super::*;
use tempo_contracts::precompiles::STABLECOIN_DEX_ADDRESS;
use tempo_precompiles::{
    PrecompileEnv, stablecoin_dex::StablecoinDEX, tip20_funder::native_dex::NativeDexFundingSource,
};

const MAKER: Address = address!("0000000000000000000000000000000000005000");
const UNIT: u64 = 1_000_000;

fn setup_dex() -> (TestEvm, Address, Address) {
    let mut evm = evm(TempoHardfork::T13);
    evm.inner
        .ctx
        .set_tx(TxEnv::new_system_tx_with_caller(ACCOUNT, RECIPIENT, Bytes::new()).into());
    let (a, b) = StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
        TIP20Setup::path_usd(MAKER)
            .with_issuer(MAKER)
            .with_mint(MAKER, U256::from(1000 * UNIT))
            .with_approval(MAKER, STABLECOIN_DEX_ADDRESS, U256::MAX)
            .apply()
            .unwrap();
        let a = TIP20Setup::create("USDC.e", "USDC.e", MAKER)
            .with_salt(B256::ZERO)
            .with_issuer(MAKER)
            .with_mint(ACCOUNT, U256::from(200 * UNIT))
            .apply()
            .unwrap()
            .address();
        let b = TIP20Setup::create("OUSD", "OUSD", MAKER)
            .with_salt(B256::repeat_byte(1))
            .with_issuer(MAKER)
            .with_mint(ACCOUNT, U256::from(200 * UNIT))
            .apply()
            .unwrap()
            .address();
        let mut dex = StablecoinDEX::new();
        dex.initialize().unwrap();
        for asset in [a, b] {
            dex.create_pair(asset).unwrap();
            dex.place(MAKER, asset, u128::from(100 * UNIT), true, 0)
                .unwrap();
        }
        (a, b)
    });
    install(&mut evm);
    evm.inner.ctx.journaled_state.logs.clear();
    (evm, a, b)
}

fn install(evm: &mut TestEvm) {
    let env = PrecompileEnv::new(
        &evm.inner.ctx.cfg,
        evm.actions.clone(),
        evm.non_creditable_slots.clone(),
    );
    evm.inner.precompiles.extend_precompiles([(
        SOURCE,
        NativeDexFundingSource::new(SOURCE, FUNDER).create_precompile(&env),
    )]);
}

fn request(asset: Address, cap: U256) -> ITIP20Funder::Source {
    ITIP20Funder::Source {
        target: SOURCE,
        data: (asset, cap).abi_encode().into(),
    }
}

fn dex_balance(evm: &mut TestEvm, account: Address, asset: Address) -> u128 {
    StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
        StablecoinDEX::new().balance_of(account, asset).unwrap()
    })
}

#[test]
fn native_dex_two_input_payment_has_no_owner_approvals() {
    for inspect in [false, true] {
        let (mut evm, a, b) = setup_dex();
        let result = run(
            &mut evm,
            &[requirement(
                PATH_USD_ADDRESS,
                50 * UNIT,
                vec![request(a, U256::from(30 * UNIT)), request(b, U256::MAX)],
            )],
            vec![transfer(PATH_USD_ADDRESS, 50 * UNIT)],
            inspect,
            LIMIT,
            0,
        );
        assert!(result.instruction_result().is_ok(), "{result:?}");
        assert_eq!(
            balance(&mut evm, PATH_USD_ADDRESS, RECIPIENT),
            U256::from(50 * UNIT)
        );
        assert_eq!(balance(&mut evm, a, ACCOUNT), U256::from(170 * UNIT));
        assert_eq!(balance(&mut evm, b, ACCOUNT), U256::from(180 * UNIT));
        assert_eq!(balance(&mut evm, PATH_USD_ADDRESS, ACCOUNT), U256::ZERO);
        let logs = funding_events(&evm);
        assert_eq!(logs.len(), 3);
        for (index, input, amount) in [(0, a, 30 * UNIT), (1, b, 20 * UNIT)] {
            let event = ITIP20Funder::SourceFunded::decode_log(logs[index])
                .unwrap()
                .data;
            assert_eq!(
                (event.assetIn, event.amountIn, event.amountOut),
                (input, U256::from(amount), U256::from(amount))
            );
        }
        StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
            for asset in [a, b] {
                let token = TIP20Token::from_address(asset).unwrap();
                for spender in [SOURCE, STABLECOIN_DEX_ADDRESS] {
                    assert_eq!(
                        token
                            .allowance(ITIP20::allowanceCall {
                                owner: ACCOUNT,
                                spender
                            })
                            .unwrap(),
                        U256::ZERO
                    );
                }
            }
        });
    }
}

#[test]
fn partial_liquidity_and_empty_books_continue_to_next_input() {
    for first in [100 * UNIT, 0] {
        let (mut evm, a, b) = setup_dex();
        if first == 0 {
            StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
                StablecoinDEX::new().cancel(MAKER, 1).unwrap()
            });
            evm.inner.ctx.journaled_state.logs.clear();
        }
        let target = first + 50 * UNIT;
        let result = run(
            &mut evm,
            &[requirement(
                PATH_USD_ADDRESS,
                target,
                vec![request(a, U256::MAX), request(b, U256::MAX)],
            )],
            vec![transfer(PATH_USD_ADDRESS, target)],
            true,
            LIMIT,
            0,
        );
        assert!(result.instruction_result().is_ok(), "{result:?}");
        assert_eq!(
            balance(&mut evm, a, ACCOUNT),
            U256::from(200 * UNIT - first)
        );
        assert_eq!(balance(&mut evm, b, ACCOUNT), U256::from(150 * UNIT));
        assert_eq!(
            balance(&mut evm, PATH_USD_ADDRESS, RECIPIENT),
            U256::from(target)
        );
        assert_eq!(funding_events(&evm).len(), if first == 0 { 2 } else { 3 });
    }
}

#[test]
fn zero_cap_skips_input_and_insufficient_total_funding_reverts_orders() {
    for zero_cap in [true, false] {
        let (mut evm, a, b) = setup_dex();
        let sources = if zero_cap {
            vec![request(a, U256::ZERO), request(b, U256::MAX)]
        } else {
            vec![request(a, U256::from(30 * UNIT))]
        };
        let result = run(
            &mut evm,
            &[requirement(PATH_USD_ADDRESS, 50 * UNIT, sources)],
            vec![transfer(PATH_USD_ADDRESS, 50 * UNIT)],
            true,
            LIMIT,
            0,
        );
        assert_eq!(result.instruction_result().is_ok(), zero_cap, "{result:?}");
        assert_eq!(balance(&mut evm, a, ACCOUNT), U256::from(200 * UNIT));
        if !zero_cap {
            assert!(evm.inner.ctx.journaled_state.logs.is_empty());
            assert_eq!(dex_balance(&mut evm, MAKER, a), 0);
            StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
                assert_eq!(
                    StablecoinDEX::new()
                        .quote_swap_exact_amount_out(a, PATH_USD_ADDRESS, u128::from(100 * UNIT))
                        .unwrap(),
                    u128::from(100 * UNIT)
                );
            });
        }
    }
}

#[test]
fn internal_and_wallet_balances_are_consumed_once() {
    let (mut evm, a, _) = setup_dex();
    StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
        let mut token = TIP20Token::from_address(a).unwrap();
        token
            .approve(
                ACCOUNT,
                ITIP20::approveCall {
                    spender: STABLECOIN_DEX_ADDRESS,
                    amount: U256::from(100 * UNIT),
                },
            )
            .unwrap();
        let mut dex = StablecoinDEX::new();
        let id = dex
            .place(ACCOUNT, a, u128::from(100 * UNIT), false, 10)
            .unwrap();
        dex.cancel(ACCOUNT, id).unwrap();
        token
            .approve(
                ACCOUNT,
                ITIP20::approveCall {
                    spender: STABLECOIN_DEX_ADDRESS,
                    amount: U256::ZERO,
                },
            )
            .unwrap();
        dex.place(MAKER, a, u128::from(100 * UNIT), true, 0)
            .unwrap();
    });
    evm.inner.ctx.journaled_state.logs.clear();
    let result = run(
        &mut evm,
        &[requirement(
            PATH_USD_ADDRESS,
            150 * UNIT,
            vec![request(a, U256::MAX)],
        )],
        vec![transfer(PATH_USD_ADDRESS, 150 * UNIT)],
        true,
        LIMIT,
        0,
    );
    assert!(result.instruction_result().is_ok(), "{result:?}");
    assert_eq!(dex_balance(&mut evm, ACCOUNT, a), 0);
    assert_eq!(balance(&mut evm, a, ACCOUNT), U256::from(50 * UNIT));
    let event = ITIP20Funder::SourceFunded::decode_log(funding_events(&evm)[0])
        .unwrap()
        .data;
    assert_eq!(event.amountIn, U256::from(150 * UNIT));
}

#[test]
fn downstream_failure_reverts_book_fills_and_payment() {
    let (mut evm, a, b) = setup_dex();
    let result = run(
        &mut evm,
        &[requirement(
            PATH_USD_ADDRESS,
            50 * UNIT,
            vec![request(a, U256::from(30 * UNIT)), request(b, U256::MAX)],
        )],
        vec![transfer(PATH_USD_ADDRESS, 51 * UNIT)],
        true,
        LIMIT,
        0,
    );
    assert!(!result.instruction_result().is_ok());
    for asset in [a, b] {
        assert_eq!(balance(&mut evm, asset, ACCOUNT), U256::from(200 * UNIT));
        assert_eq!(dex_balance(&mut evm, MAKER, asset), 0);
    }
    assert_eq!(balance(&mut evm, PATH_USD_ADDRESS, RECIPIENT), U256::ZERO);
    assert!(evm.inner.ctx.journaled_state.logs.is_empty());
}

#[test]
fn unsupported_assets_and_paused_inputs_fail_without_fallback() {
    for paused in [false, true] {
        let (mut evm, mut a, b) = setup_dex();
        if paused {
            StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
                TIP20Setup::config(a)
                    .with_admin(MAKER)
                    .with_role(MAKER, TIP20Token::pause_role())
                    .apply()
                    .unwrap();
                TIP20Token::from_address(a)
                    .unwrap()
                    .pause(MAKER, ITIP20::pauseCall {})
                    .unwrap();
            });
        } else {
            a = StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
                TIP20Setup::create("Euro", "EUR", MAKER)
                    .currency("EUR")
                    .apply()
                    .unwrap()
                    .address()
            });
        }
        evm.inner.ctx.journaled_state.logs.clear();
        let result = run(
            &mut evm,
            &[requirement(
                PATH_USD_ADDRESS,
                50 * UNIT,
                vec![request(a, U256::MAX), request(b, U256::MAX)],
            )],
            vec![noop()],
            true,
            LIMIT,
            0,
        );
        assert!(!result.instruction_result().is_ok());
        assert_eq!(balance(&mut evm, b, ACCOUNT), U256::from(200 * UNIT));
        assert!(evm.inner.ctx.journaled_state.logs.is_empty());
    }
}

#[test]
fn funding_source_registration_follows_t13() {
    for spec in [TempoHardfork::T12, TempoHardfork::T13] {
        let evm = evm(spec);
        assert_eq!(
            evm.inner
                .precompiles
                .get(&tempo_contracts::precompiles::NATIVE_DEX_FUNDING_SOURCE_ADDRESS)
                .is_some(),
            spec.is_t13()
        );
    }
}

#[test]
fn multi_hop_swap_only_charges_original_input() {
    let (mut evm, a, b) = setup_dex();
    StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
        let mut token = TIP20Token::from_address(b).unwrap();
        token
            .transfer(
                ACCOUNT,
                ITIP20::transferCall {
                    to: MAKER,
                    amount: U256::from(200 * UNIT),
                },
            )
            .unwrap();
        token
            .approve(
                MAKER,
                ITIP20::approveCall {
                    spender: STABLECOIN_DEX_ADDRESS,
                    amount: U256::MAX,
                },
            )
            .unwrap();
        StablecoinDEX::new()
            .place(MAKER, b, u128::from(100 * UNIT), false, 0)
            .unwrap();
    });
    evm.inner.ctx.journaled_state.logs.clear();
    let result = run(
        &mut evm,
        &[requirement(b, 50 * UNIT, vec![request(a, U256::MAX)])],
        vec![transfer(b, 50 * UNIT)],
        true,
        LIMIT,
        0,
    );
    assert!(result.instruction_result().is_ok(), "{result:?}");
    assert_eq!(balance(&mut evm, a, ACCOUNT), U256::from(150 * UNIT));
    assert_eq!(balance(&mut evm, b, RECIPIENT), U256::from(50 * UNIT));
    assert_eq!(balance(&mut evm, PATH_USD_ADDRESS, ACCOUNT), U256::ZERO);
    let event = ITIP20Funder::SourceFunded::decode_log(funding_events(&evm)[0])
        .unwrap()
        .data;
    assert_eq!((event.assetIn, event.amountIn), (a, U256::from(50 * UNIT)));
}

#[test]
fn cost_budget_includes_execution_loss() {
    for slippage in [0, 200] {
        let (mut evm, a, _) = setup_dex();
        StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
            let mut dex = StablecoinDEX::new();
            dex.cancel(MAKER, 1).unwrap();
            dex.place(MAKER, a, u128::from(100 * UNIT), true, -1000)
                .unwrap();
        });
        evm.inner.ctx.journaled_state.logs.clear();
        let mut req = requirement(PATH_USD_ADDRESS, 50 * UNIT, vec![request(a, U256::MAX)]);
        req.slippage_bps = slippage;
        let result = run(
            &mut evm,
            &[req],
            vec![transfer(PATH_USD_ADDRESS, 50 * UNIT)],
            true,
            LIMIT,
            0,
        );
        assert_eq!(
            result.instruction_result().is_ok(),
            slippage == 200,
            "{result:?}"
        );
        if slippage == 200 {
            // At 0.99 output per input, ceil(50_000_000 / 0.99) = 50_505_051.
            assert_eq!(balance(&mut evm, a, ACCOUNT), U256::from(149_494_949));
        } else {
            assert_eq!(balance(&mut evm, a, ACCOUNT), U256::from(200 * UNIT));
            assert!(evm.inner.ctx.journaled_state.logs.is_empty());
        }
    }
}

#[test]
fn owner_wallet_balance_limits_contribution_before_next_source() {
    let (mut evm, a, b) = setup_dex();
    StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
        TIP20Token::from_address(a)
            .unwrap()
            .transfer(
                ACCOUNT,
                ITIP20::transferCall {
                    to: MAKER,
                    amount: U256::from(180 * UNIT),
                },
            )
            .unwrap();
    });
    evm.inner.ctx.journaled_state.logs.clear();
    let result = run(
        &mut evm,
        &[requirement(
            PATH_USD_ADDRESS,
            50 * UNIT,
            vec![request(a, U256::MAX), request(b, U256::MAX)],
        )],
        vec![transfer(PATH_USD_ADDRESS, 50 * UNIT)],
        true,
        LIMIT,
        0,
    );
    assert!(result.instruction_result().is_ok(), "{result:?}");
    assert_eq!(balance(&mut evm, a, ACCOUNT), U256::ZERO);
    assert_eq!(balance(&mut evm, b, ACCOUNT), U256::from(170 * UNIT));
}

#[test]
fn native_source_gas_matches_inspected_execution_and_exhaustion_reverts() {
    let mut runs = Vec::new();
    for (inspect, limit) in [(false, LIMIT), (true, LIMIT), (true, 10_000)] {
        let (mut evm, a, b) = setup_dex();
        let result = run(
            &mut evm,
            &[requirement(
                PATH_USD_ADDRESS,
                50 * UNIT,
                vec![request(a, U256::from(30 * UNIT)), request(b, U256::MAX)],
            )],
            vec![transfer(PATH_USD_ADDRESS, 50 * UNIT)],
            inspect,
            limit,
            0,
        );
        if limit == LIMIT {
            assert!(result.instruction_result().is_ok(), "{result:?}");
            runs.push((*result.gas(), evm.inner.ctx.journaled_state.logs.clone()));
        } else {
            assert!(result.instruction_result().is_halt(), "{result:?}");
            assert_eq!(balance(&mut evm, a, ACCOUNT), U256::from(200 * UNIT));
            assert_eq!(balance(&mut evm, b, ACCOUNT), U256::from(200 * UNIT));
            assert!(evm.inner.ctx.journaled_state.logs.is_empty());
        }
    }
    assert_eq!(runs[0], runs[1]);
}

#[test]
fn signed_requirements_use_the_normal_and_inspected_batch_paths() {
    use tempo_primitives::transaction::{FundingRequirement as SignedRequirement, FundingSource};
    for inspect in [false, true] {
        let (mut evm, a, b) = setup_dex();
        let calls = vec![Call {
            to: PATH_USD_ADDRESS.into(),
            value: U256::ZERO,
            input: ITIP20::transferCall {
                to: RECIPIENT,
                amount: U256::from(50 * UNIT),
            }
            .abi_encode()
            .into(),
        }];
        evm.inner.ctx.tx.tempo_tx_env = Some(Box::new(crate::TempoBatchCallEnv {
            aa_calls: calls.clone(),
            require_funds: vec![SignedRequirement {
                token: PATH_USD_ADDRESS,
                amount: U256::from(50 * UNIT),
                slippage_bps: Some(100),
                sources: [request(a, U256::from(30 * UNIT)), request(b, U256::MAX)]
                    .into_iter()
                    .map(|source| FundingSource {
                        address: tempo_contracts::precompiles::NATIVE_DEX_FUNDING_SOURCE_ADDRESS,
                        data: source.data,
                    })
                    .collect(),
            }],
            ..Default::default()
        }));
        let gas = GasTracker::new(LIMIT, LIMIT, 0);
        let mut handler = TempoEvmHandler::new();
        let result = if inspect {
            handler.inspect_execute_multi_call(&mut evm, &gas, calls)
        } else {
            handler.execute_multi_call(&mut evm, &gas, calls)
        }
        .unwrap();
        assert!(result.instruction_result().is_ok(), "{result:?}");
        assert_eq!(
            balance(&mut evm, PATH_USD_ADDRESS, RECIPIENT),
            U256::from(50 * UNIT)
        );
        assert_eq!(balance(&mut evm, a, ACCOUNT), U256::from(170 * UNIT));
        assert_eq!(balance(&mut evm, b, ACCOUNT), U256::from(180 * UNIT));
    }
}
