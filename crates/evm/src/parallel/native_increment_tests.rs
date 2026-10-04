use super::*;
use alloy_evm::FromRecoveredTx;
use alloy_sol_types::SolCall;
use revm::{
    context::{CfgEnv, transaction::AccessListItem},
    database::State,
};
use tempo_precompiles::{
    PATH_USD_ADDRESS, TIP20_CHANNEL_RESERVE_ADDRESS,
    tip20::slots as tip20_slots,
    tip20_channel_reserve::{ITIP20ChannelReserve, slots as reserve_slots},
};
use tempo_primitives::{TempoSignature, TempoTransaction, transaction::Call};

pub(in crate::parallel) fn fixture() -> (TestDB, Env, TempoTxEnv, Address, U256) {
    let (mut db, tokens) = funded_tip20_tokens((0..4).map(address).collect(), 2);
    for &(address, activation) in tempo_precompiles::SYSTEM_PRECOMPILES {
        if activation <= TempoHardfork::T14 {
            contract(&mut db, address, &[0xef]);
        }
    }
    let token = tokens[1];
    let slot = TIP20_CHANNEL_RESERVE_ADDRESS.mapping_slot(tip20_slots::BALANCES);
    db.insert_account_storage(token, slot, U256::from(10))
        .unwrap();
    let (_, mut env) = test_evm_with_basefee(TestDB::default(), 0).finish();
    env.cfg_env = CfgEnv::new_with_spec_and_gas_params(
        TempoHardfork::T14,
        tempo_revm::gas_params::tempo_gas_params(TempoHardfork::T14),
    );
    let signed = TempoTransaction {
        chain_id: 1,
        gas_limit: 1_000_000,
        max_fee_per_gas: 1,
        max_priority_fee_per_gas: 1,
        fee_token: Some(PATH_USD_ADDRESS),
        nonce_key: U256::MAX,
        valid_before: std::num::NonZeroU64::new(25),
        calls: vec![Call {
            to: TIP20_CHANNEL_RESERVE_ADDRESS.into(),
            value: U256::ZERO,
            input: ITIP20ChannelReserve::openCall {
                payee: address(1),
                operator: Address::ZERO,
                token,
                deposit: alloy_primitives::aliases::U96::ONE,
                salt: B256::with_last_byte(1),
                authorizedSigner: Address::ZERO,
            }
            .abi_encode()
            .into(),
        }],
        ..Default::default()
    }
    .into_signed(TempoSignature::default());
    (
        db,
        env,
        TempoTxEnv::from_recovered_tx(&signed, address(0)),
        token,
        slot,
    )
}

#[test]
fn stale_custody_balance_preserves_full_results_and_credit_modes() {
    for cached in [false, true] {
        for credits in [0_u64, 2] {
            for (worker_balance, canonical_balance, rebased) in [
                (U256::from(10), U256::from(20), true),
                (U256::ZERO, U256::from(20), false),
                (U256::from(10), U256::ZERO, false),
                (U256::from(10), U256::MAX, false),
            ] {
                let (mut parent, env, tx, token, slot) = fixture();
                parent
                    .insert_account_storage(token, slot, worker_balance)
                    .unwrap();
                let credit_slot = address(0).mapping_slot(reserve_slots::CHANNEL_STORAGE_CREDITS);
                parent
                    .insert_account_storage(
                        TIP20_CHANNEL_RESERVE_ADDRESS,
                        credit_slot,
                        U256::from(credits),
                    )
                    .unwrap();
                parent
                    .insert_account_storage(
                        tempo_precompiles::STORAGE_CREDITS_ADDRESS,
                        tempo_precompiles::storage_credits::StorageCredits::slot(
                            TIP20_CHANNEL_RESERVE_ADDRESS,
                        ),
                        U256::from(credits),
                    )
                    .unwrap();
                let mut worker = PrewarmingExecutor::new(parent.clone(), env.clone());
                let candidate = worker.execute(tx.clone(), Some(0)).unwrap();
                assert_eq!(
                    candidate.native_increment.is_some(),
                    !worker_balance.is_zero()
                );
                parent
                    .insert_account_storage(token, slot, canonical_balance)
                    .unwrap();
                let mut expected_state = State::builder().with_database(parent.clone()).build();
                let mut expected = TempoEvm::new(&mut expected_state, env.clone());
                let mut state = State::builder().with_database(parent).build();
                let mut actual = TempoEvm::new(&mut state, env);
                if cached {
                    actual.enable_state_cache_validation();
                }
                actual.set_speculative_executor(Some(SpeculativeExecutor::new(1, 1).unwrap()));
                actual.set_preexecuted_transaction(candidate);
                let expected_result = expected.transact_raw(tx.clone()).unwrap();
                let actual_result = actual.transact_raw(tx).unwrap();
                assert_eq!(actual_result, expected_result);
                assert_eq!(actual.validator_fee(), expected.validator_fee());
                assert_eq!(actual.execution_stats().reused, u64::from(rebased));
                assert_eq!(actual.execution_stats().native_rebased, u64::from(rebased));
                expected.db_mut().commit(expected_result.state);
                actual.db_mut().commit(actual_result.state);
                let credits_left = expected
                    .db_mut()
                    .storage(TIP20_CHANNEL_RESERVE_ADDRESS, credit_slot)
                    .unwrap();
                if rebased {
                    assert_eq!(credits_left, U256::from(credits.saturating_sub(1)));
                }
                drop(actual);
                drop(expected);
                assert_eq!(
                    prewarming_bench::state_root(&state),
                    prewarming_bench::state_root(&expected_state)
                );
            }
        }
    }
}

#[test]
fn same_token_fees_and_native_custody_rebase_together() {
    for cached in [false, true] {
        let (mut parent, env, mut tx, _, custody_slot) = fixture();
        let call = &mut tx.tempo_tx_env.as_mut().unwrap().aa_calls[0];
        let mut open = ITIP20ChannelReserve::openCall::abi_decode(&call.input).unwrap();
        open.token = PATH_USD_ADDRESS;
        call.input = open.abi_encode().into();
        tx.inner.data = call.input.clone();
        parent
            .insert_account_storage(PATH_USD_ADDRESS, custody_slot, U256::from(10))
            .unwrap();

        let candidate = PrewarmingExecutor::new(parent.clone(), env.clone())
            .execute(tx.clone(), Some(0))
            .unwrap();
        assert!(candidate.result.result.is_success());
        let witness = candidate
            .native_increment
            .expect("same-token custody witness");
        assert_eq!(witness.target.address, PATH_USD_ADDRESS);
        assert_eq!(witness.target.slot, custody_slot);

        // The same token also holds the fee manager's independent custody slot.
        // Select its recorded fee update and check every arithmetic step before
        // changing the canonical prefix; the native body must not observe it.
        let fee_slot =
            tempo_precompiles::TIP_FEE_MANAGER_ADDRESS.mapping_slot(tip20_slots::BALANCES);
        assert_ne!(fee_slot, custody_slot);
        let fee = candidate
            .fee_updates
            .iter()
            .find(|fee| fee.address == PATH_USD_ADDRESS && fee.slot == fee_slot)
            .expect("unobserved fee manager balance update");
        let old_fee = candidate
            .reads
            .iter()
            .find_map(|(key, value)| match (key, value) {
                (ReadKey::Storage(address, slot), ReadValue::Storage(value))
                    if *address == PATH_USD_ADDRESS && *slot == fee_slot =>
                {
                    Some(*value)
                }
                _ => None,
            })
            .expect("recorded fee balance dependency");
        let worker_fee = &candidate.result.state[&PATH_USD_ADDRESS].storage[&fee_slot];
        assert_eq!(worker_fee.original_value, old_fee);
        assert_eq!(fee.apply(old_fee), Some(worker_fee.present_value));
        let fresh_fee = old_fee.checked_add(U256::from(17)).unwrap();
        let final_fee = fee
            .apply(fresh_fee)
            .expect("all fresh fee operations remain valid");
        parent
            .insert_account_storage(PATH_USD_ADDRESS, fee_slot, fresh_fee)
            .unwrap();
        parent
            .insert_account_storage(PATH_USD_ADDRESS, custody_slot, U256::from(20))
            .unwrap();

        let mut expected_state = State::builder().with_database(parent.clone()).build();
        let mut state = State::builder().with_database(parent).build();
        if cached {
            // State-cache warmth is independent of transaction journal warmth.
            state.storage(PATH_USD_ADDRESS, fee_slot).unwrap();
            state.storage(PATH_USD_ADDRESS, custody_slot).unwrap();
        }
        let mut expected = TempoEvm::new(&mut expected_state, env.clone());
        let mut actual = TempoEvm::new(&mut state, env);
        if cached {
            actual.enable_state_cache_validation();
        }
        actual.set_speculative_executor(Some(SpeculativeExecutor::new(1, 1).unwrap()));
        actual.set_preexecuted_transaction(candidate);
        let expected_result = expected.transact_raw(tx.clone()).unwrap();
        let actual_result = actual.transact_raw(tx).unwrap();
        assert!(expected_result.result.is_success());
        assert_eq!(actual_result, expected_result);
        assert_eq!(actual.validator_fee(), expected.validator_fee());
        let stats = actual.execution_stats();
        assert_eq!(
            (stats.reused, stats.fees_rebased, stats.native_rebased),
            (1, 1, 1)
        );
        assert_eq!(stats.conflicts, 0);
        assert_eq!(
            actual_result.state[&PATH_USD_ADDRESS].storage[&fee_slot].present_value,
            final_fee
        );
        assert_eq!(
            actual_result.state[&PATH_USD_ADDRESS].storage[&custody_slot].present_value,
            U256::from(21)
        );
        actual.db_mut().commit(actual_result.state);
        expected.db_mut().commit(expected_result.state);
        drop(actual);
        drop(expected);
        assert_eq!(
            prewarming_bench::state_root(&state),
            prewarming_bench::state_root(&expected_state)
        );
    }
}

#[test]
fn eligibility_excludes_unproven_calls_and_warm_custody_slots() {
    let (parent, env, tx, token, slot) = fixture();
    assert!(native_rebase::target(&tx, &env).is_some());
    for case in [
        "warm",
        "multi",
        "wrapper",
        "value",
        "system",
        "payer",
        "fee_payer",
        "old_fork",
        "state_gas",
        "legacy_type",
    ] {
        let mut tx = tx.clone();
        let mut env = env.clone();
        match case {
            "warm" => tx.inner.access_list.0.push(AccessListItem {
                address: token,
                storage_keys: vec![slot.into()],
            }),
            "multi" => {
                let aa = tx.tempo_tx_env.as_mut().unwrap();
                aa.aa_calls.push(aa.aa_calls[0].clone());
            }
            "wrapper" => tx.tempo_tx_env.as_mut().unwrap().aa_calls[0].to = address(900).into(),
            "value" => tx.tempo_tx_env.as_mut().unwrap().aa_calls[0].value = U256::ONE,
            "system" => tx.is_system_tx = true,
            "payer" => tx.inner.caller = TIP20_CHANNEL_RESERVE_ADDRESS,
            "fee_payer" => tx.fee_payer = Some(Some(TIP20_CHANNEL_RESERVE_ADDRESS)),
            "old_fork" => env.cfg_env.spec = TempoHardfork::T13,
            "state_gas" => env.cfg_env.enable_amsterdam_eip8037 = true,
            "legacy_type" => tx.inner.tx_type = 0,
            _ => unreachable!(),
        }
        assert!(native_rebase::target(&tx, &env).is_none(), "{case}");
    }
    let mut unrelated = tx;
    unrelated.inner.access_list.0.push(AccessListItem {
        address: token,
        storage_keys: vec![U256::from(987).into()],
    });
    let candidate = PrewarmingExecutor::new(parent, env)
        .execute(unrelated, Some(0))
        .unwrap();
    assert!(candidate.native_increment.is_some());
}

#[test]
fn gas_boundary_and_failed_open_never_reuse_an_incomplete_increment() {
    let (parent, env, tx, token, slot) = fixture();
    let succeeds = |gas_limit| {
        let mut tx = tx.clone();
        tx.inner.gas_limit = gas_limit;
        TempoEvm::new(parent.clone(), env.clone())
            .transact_raw(tx)
            .is_ok_and(|result| result.result.is_success())
    };
    let (mut low, mut high) = (0, tx.inner.gas_limit);
    assert!(succeeds(high));
    while low + 1 < high {
        let middle = low + (high - low) / 2;
        if succeeds(middle) {
            high = middle;
        } else {
            low = middle;
        }
    }
    for gas_limit in [high - 1000, high - 1, high, high + 1] {
        let mut tx = tx.clone();
        tx.inner.gas_limit = gas_limit;
        let mut worker = PrewarmingExecutor::new(parent.clone(), env.clone());
        let candidate = worker.execute(tx.clone(), Some(0)).unwrap();
        assert_eq!(candidate.native_increment.is_some(), gas_limit >= high);
        let mut current = parent.clone();
        current
            .insert_account_storage(token, slot, U256::from(20))
            .unwrap();
        let mut expected = TempoEvm::new(current.clone(), env.clone());
        let mut actual = TempoEvm::new(current, env.clone());
        actual.set_speculative_executor(Some(SpeculativeExecutor::new(1, 1).unwrap()));
        actual.set_preexecuted_transaction(candidate);
        assert_eq!(
            actual.transact_raw(tx.clone()).unwrap(),
            expected.transact_raw(tx).unwrap()
        );
        assert_eq!(
            actual.execution_stats().native_rebased,
            u64::from(gas_limit >= high)
        );
    }
}

#[test]
fn native_patches_wait_for_all_other_dependencies() {
    let (parent, env, tx, token, slot) = fixture();
    let candidate = PrewarmingExecutor::new(parent.clone(), env)
        .execute(tx.clone(), Some(0))
        .unwrap();
    let witness = candidate.native_increment.unwrap();
    let mut candidate = candidate.into_candidate(&tx).unwrap();
    let original_result = candidate.result.as_ref().unwrap().clone();
    let target_index = candidate
        .reads
        .iter()
        .position(|(key, _)| *key == ReadKey::Storage(token, slot))
        .unwrap();
    let credit_slot = address(0).mapping_slot(reserve_slots::CHANNEL_STORAGE_CREDITS);
    let credit_index = candidate
        .reads
        .iter()
        .position(|(key, _)| *key == ReadKey::Storage(TIP20_CHANNEL_RESERVE_ADDRESS, credit_slot))
        .unwrap();
    assert!(credit_index > target_index);
    let mut current = parent;
    current
        .insert_account_storage(token, slot, witness.original + U256::ONE)
        .unwrap();
    current
        .insert_account_storage(TIP20_CHANNEL_RESERVE_ADDRESS, credit_slot, U256::ONE)
        .unwrap();
    assert!(!candidate.validate(&mut current).unwrap());
    assert!(!candidate.native_rebased);
    assert_eq!(candidate.result.as_ref().unwrap(), &original_result);
}

#[test]
fn native_certificate_requires_one_dependency_and_exact_final_journal() {
    let (parent, env, tx, token, slot) = fixture();
    let mut worker = PrewarmingExecutor::new(parent, env);
    for case in [
        "duplicate",
        "read",
        "original",
        "present",
        "created",
        "removed",
        "fees",
    ] {
        let mut candidate = worker.execute(tx.clone(), Some(0)).unwrap();
        let index = candidate
            .reads
            .iter()
            .position(|(key, _)| *key == ReadKey::Storage(token, slot))
            .unwrap();
        match case {
            "duplicate" => candidate.reads.push(candidate.reads[index].clone()),
            "read" => candidate.reads[index].1 = ReadValue::Storage(U256::from(9)),
            "original" => {
                candidate
                    .result
                    .state
                    .get_mut(&token)
                    .unwrap()
                    .storage
                    .get_mut(&slot)
                    .unwrap()
                    .original_value += U256::ONE
            }
            "present" => {
                candidate
                    .result
                    .state
                    .get_mut(&token)
                    .unwrap()
                    .storage
                    .get_mut(&slot)
                    .unwrap()
                    .present_value += U256::ONE
            }
            "created" => candidate
                .result
                .state
                .get_mut(&token)
                .unwrap()
                .mark_created(),
            "removed" => candidate
                .result
                .state
                .get_mut(&token)
                .unwrap()
                .mark_selfdestruct(),
            "fees" => {
                let fee = candidate.fee_updates.first_mut().unwrap();
                fee.address = token;
                fee.slot = slot;
            }
            _ => unreachable!(),
        }
        assert!(
            native_rebase::certify(
                candidate.native_increment,
                Some(&candidate.result),
                &candidate.reads,
                &candidate.fee_updates
            )
            .is_none(),
            "{case}"
        );
    }
}

#[test]
fn provider_error_after_native_mismatch_leaves_result_unmodified() {
    #[derive(Debug, thiserror::Error)]
    #[error("provider unavailable")]
    struct ProviderError;
    impl DBErrorMarker for ProviderError {}

    let (parent, env, tx, token, slot) = fixture();
    let candidate = PrewarmingExecutor::new(parent, env)
        .execute(tx.clone(), Some(0))
        .unwrap();
    let mut candidate = candidate.into_candidate::<ProviderError>(&tx).unwrap();
    let original = candidate.result.as_ref().unwrap().clone();
    let key = ReadKey::Storage(token, slot);
    let mut visited_native = false;
    let result = candidate.validate_with(|_, reads| {
        if let Some(offset) = reads.iter().position(|(read, _)| *read == key) {
            visited_native = true;
            Ok(Some((offset, ReadValue::Storage(U256::from(20)))))
        } else {
            assert!(!reads.is_empty());
            Err(ProviderError)
        }
    });
    assert!(visited_native);
    assert!(result.is_err());
    assert!(!candidate.native_rebased);
    assert_eq!(candidate.result.as_ref().unwrap(), &original);
}
