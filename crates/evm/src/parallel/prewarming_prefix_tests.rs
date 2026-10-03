use super::*;
use alloy_primitives::{Bytes, TxKind};
use revm::{
    Database,
    context::{CfgEnv, TxEnv},
    database::{CacheDB, EmptyDB, State},
    state::{Account, EvmState, EvmStorageSlot},
};

fn changed_slot(original: u64, present: u64) -> EvmStorageSlot {
    EvmStorageSlot::new_changed(
        U256::from(original),
        U256::from(present),
        Default::default(),
    )
}

fn account_with_code(code: &'static [u8]) -> AccountInfo {
    AccountInfo {
        nonce: 1,
        ..Default::default()
    }
    .with_code(Bytecode::new_raw(Bytes::from_static(code)))
}

#[test]
fn pre_execution_storage_seed_reuses_first_speculative_wave() {
    let target = Address::with_last_byte(202);
    // Return slots 0 and 9. Only slot 0 changes during pre-execution; slot 9
    // must continue to fall through to the unchanged parent state.
    let info = account_with_code(&[
        0x60, 0, 0x54, 0x60, 0, 0x52, 0x60, 9, 0x54, 0x60, 32, 0x52, 0x60, 64, 0x60, 0, 0xf3,
    ]);
    let mut parent = CacheDB::<EmptyDB>::default();
    parent.insert_account_info(target, info.clone());
    parent
        .insert_account_storage(target, U256::ZERO, U256::ONE)
        .unwrap();
    parent
        .insert_account_storage(target, U256::from(9), U256::from(11))
        .unwrap();
    let mut change = Account::from(info);
    change.mark_touch();
    change.storage.insert(U256::ZERO, changed_slot(1, 7));
    let changes = EvmState::from_iter([(target, change)]);
    let spec = TempoHardfork::T14;
    let env = Env {
        cfg_env: CfgEnv::new_with_spec_and_gas_params(
            spec,
            tempo_revm::gas_params::tempo_gas_params(spec),
        ),
        block_env: TempoBlockEnv {
            inner: revm::context::BlockEnv {
                gas_limit: 30_000_000,
                ..Default::default()
            },
            ..Default::default()
        },
    };
    for seed in [false, true] {
        let mut canonical_db = State::builder().with_database(parent.clone()).build();
        canonical_db.basic(target).unwrap();
        canonical_db.commit(changes.clone());
        let mut ordered_db = State::builder().with_database(parent.clone()).build();
        ordered_db.basic(target).unwrap();
        ordered_db.commit(changes.clone());
        let prefix = PrewarmingState::default();
        if seed {
            prefix.seed_from_cache(&ordered_db.cache);
        }
        let mut canonical = TempoEvm::new(canonical_db, env.clone());
        let mut ordered = TempoEvm::new(ordered_db, env.clone());
        ordered.set_speculative_executor(Some(SpeculativeExecutor::new(1, 1).unwrap()));
        let mut worker =
            PrewarmingExecutor::new(parent.clone(), env.clone()).with_state(prefix.clone());
        assert_eq!(prefix.read(ReadKey::Storage(target, U256::from(9))), None);
        // The builder dispatches an initial wave before any ordered commit can
        // publish a transaction's observations of the pre-execution changes.
        let candidates = (0..4)
            .map(|index| {
                let tx = TempoTxEnv {
                    inner: TxEnv {
                        caller: Address::with_last_byte(220 + index),
                        kind: TxKind::Call(target),
                        gas_limit: 1_000_000,
                        ..Default::default()
                    },
                    ..Default::default()
                };
                let candidate = worker.execute(tx.clone(), None).unwrap();
                (tx, candidate)
            })
            .collect::<Vec<_>>();
        for (index, (tx, candidate)) in candidates.into_iter().enumerate() {
            ordered.set_preexecuted_transaction(candidate);
            let expected = canonical.transact_raw(tx.clone()).unwrap();
            let actual = ordered.transact_raw(tx).unwrap();
            assert!(expected.result.is_success());
            assert_eq!(actual, expected, "seed={seed}, index={index}");
            let mut output = [0; 64];
            output[..32].copy_from_slice(&U256::from(7).to_be_bytes::<32>());
            output[32..].copy_from_slice(&U256::from(11).to_be_bytes::<32>());
            assert_eq!(actual.result.output().unwrap().as_ref(), output);
            prefix.record(&actual.state, None);
            canonical.db_mut().commit(expected.state);
            ordered.db_mut().commit(actual.state);
        }
        let stats = ordered.execution_stats();
        assert_eq!(stats.reused, if seed { 4 } else { 0 }, "{stats:?}");
        assert_eq!(stats.conflicts, if seed { 0 } else { 4 }, "{stats:?}");
        assert_eq!(canonical.db().cache, ordered.db().cache);
    }
}

#[test]
fn cache_seed_preserves_account_lifecycle_and_bytecode() {
    let deleted = Address::with_last_byte(210);
    let created = Address::with_last_byte(211);
    let upgraded = Address::with_last_byte(212);
    let revived = Address::with_last_byte(213);
    let empty_created = Address::with_last_byte(214);
    let unchanged = Address::with_last_byte(215);
    let old_slot = U256::ONE;
    let new_slot = U256::from(2);
    let old_info = account_with_code(&[0]);
    let new_info = account_with_code(&[0x60, 0, 0]);
    let mut parent = CacheDB::<EmptyDB>::default();
    for address in [deleted, created, upgraded, revived, unchanged] {
        parent.insert_account_info(address, old_info.clone());
        parent
            .insert_account_storage(address, old_slot, U256::from(7))
            .unwrap();
    }
    let mut state = State::builder().with_database(parent).build();
    for address in [deleted, created, upgraded, revived, unchanged] {
        state.basic(address).unwrap();
    }
    let mut changes = EvmState::default();
    for address in [deleted, revived] {
        let mut account = Account::from(old_info.clone());
        account.mark_touch();
        account.mark_selfdestruct();
        changes.insert(address, account);
    }
    let mut account = Account::from(new_info.clone());
    account.mark_touch();
    account.mark_created();
    account.storage.insert(new_slot, changed_slot(0, 9));
    changes.insert(created, account);
    let mut account = Account::from(AccountInfo::default());
    account.mark_touch();
    account.mark_created();
    changes.insert(empty_created, account);
    state.commit(changes);

    // The cache's contracts map can supply code even when account metadata no
    // longer carries inline bytecode. An in-place upgrade exercises the reverse.
    state
        .cache
        .accounts
        .get_mut(&created)
        .unwrap()
        .account
        .as_mut()
        .unwrap()
        .info
        .code = None;
    let inline_info = account_with_code(&[0x60, 1, 0]);
    let mut account = Account::from(inline_info.clone());
    account.mark_touch();
    let mut changes = EvmState::from_iter([(upgraded, account)]);
    let mut account = Account::new_not_existing(Default::default());
    account.info.balance = U256::ONE;
    account.mark_touch();
    account.storage.insert(new_slot, changed_slot(0, 13));
    changes.insert(revived, account);
    state.commit(changes);
    assert!(!state.cache.contracts.contains_key(&inline_info.code_hash));
    let prefix = PrewarmingState::default();
    prefix.seed_from_cache(&state.cache);
    assert_eq!(prefix.read(ReadKey::Account(unchanged)), None);
    for address in [deleted, created, upgraded, revived, empty_created] {
        let key = ReadKey::Account(address);
        assert_eq!(prefix.read(key), Some(read(&mut state, key).unwrap()));
        for slot in [old_slot, new_slot] {
            let key = ReadKey::Storage(address, slot);
            if address == upgraded {
                assert_eq!(prefix.read(key), None);
            } else {
                assert_eq!(prefix.read(key), Some(read(&mut state, key).unwrap()));
            }
        }
    }
    for info in [new_info, inline_info] {
        assert_eq!(
            prefix.read(ReadKey::Code(info.code_hash)),
            Some(ReadValue::Code(info.code.unwrap()))
        );
    }
}

#[test]
fn cache_seed_starts_nonce_predictions_after_pre_execution() {
    let mut parent = CacheDB::<EmptyDB>::default();
    let info = account_with_code(&[0]);
    parent.insert_account_info(NONCE_PRECOMPILE_ADDRESS, info.clone());
    parent
        .insert_account_storage(
            NONCE_PRECOMPILE_ADDRESS,
            nonce_slots::EXPIRING_NONCE_RING_PTR,
            U256::from(7),
        )
        .unwrap();
    let mut state = State::builder().with_database(parent).build();
    state.basic(NONCE_PRECOMPILE_ADDRESS).unwrap();
    let mut account = Account::from(info);
    account.mark_touch();
    account
        .storage
        .insert(nonce_slots::EXPIRING_NONCE_RING_PTR, changed_slot(7, 13));
    state.commit(EvmState::from_iter([(NONCE_PRECOMPILE_ADDRESS, account)]));
    let prefix = PrewarmingState::default();
    prefix.seed_from_cache(&state.cache);
    assert_eq!(prefix.nonce_cursor(0), Some((U256::from(13), 0)));
    assert_eq!(prefix.nonce_cursor(1), Some((U256::from(13), 1)));

    let mut account = Account::default();
    account.mark_touch();
    account.mark_selfdestruct();
    state.commit(EvmState::from_iter([(NONCE_PRECOMPILE_ADDRESS, account)]));
    prefix.seed_from_cache(&state.cache);
    assert_eq!(prefix.nonce_cursor(0), Some((U256::ZERO, 0)));
}

#[test]
fn engine_expiring_omission_preserves_metadata_lifecycle_and_builder_hints() {
    let ptr = nonce_slots::EXPIRING_NONCE_RING_PTR;
    let keyed_slot = U256::from(70);
    let ring_slot = U256::from(71);
    let other = Address::with_last_byte(203);
    let mut nonce = Account::from(account_with_code(&[0]));
    nonce.mark_touch();
    nonce.storage.insert(keyed_slot, changed_slot(0, 4));
    let initial = EvmState::from_iter([(NONCE_PRECOMPILE_ADDRESS, nonce.clone())]);
    let engine = PrewarmingState::default();
    engine.record_engine_timed(&initial, false);
    nonce.info.nonce = 2;
    nonce.info.account_id = revm::state::AccountId::new(7);
    nonce.info.code = Some(Bytecode::new_raw(Bytes::from_static(&[0x60, 0])));
    nonce.info.code_hash = nonce.info.code.as_ref().unwrap().hash_slow();
    nonce.storage.insert(ptr, changed_slot(6, 7));
    nonce.storage.insert(ring_slot, changed_slot(0, 8));
    let mut other_account = Account::from(account_with_code(&[0]));
    other_account.mark_touch();
    other_account.storage.insert(ring_slot, changed_slot(0, 9));
    let changes = EvmState::from_iter([
        (NONCE_PRECOMPILE_ADDRESS, nonce.clone()),
        (other, other_account),
    ]);
    engine.record_engine_timed(&changes, true);
    let ReadValue::Account(Some(info)) = engine
        .read(ReadKey::Account(NONCE_PRECOMPILE_ADDRESS))
        .unwrap()
    else {
        panic!("nonce metadata must remain published");
    };
    assert_eq!(info.nonce, 2);
    assert_eq!(info.account_id, revm::state::AccountId::new(7));
    assert_eq!(info.code, nonce.info.code);
    assert_eq!(
        engine.read(ReadKey::Code(info.code_hash)),
        Some(ReadValue::Code(info.code.unwrap()))
    );
    assert_eq!(
        engine.read(ReadKey::Storage(NONCE_PRECOMPILE_ADDRESS, keyed_slot)),
        Some(ReadValue::Storage(U256::from(4)))
    );
    for slot in [ptr, ring_slot] {
        assert_eq!(
            engine.read(ReadKey::Storage(NONCE_PRECOMPILE_ADDRESS, slot)),
            None
        );
    }
    assert_eq!(engine.nonce_cursor(1), None);
    assert_eq!(
        engine.read(ReadKey::Storage(other, ring_slot)),
        Some(ReadValue::Storage(U256::from(9)))
    );

    // Ordinary keyed commits and both builder entrypoints still publish storage;
    // builder source offsets also retain the accepted ring cursor.
    for timed in [false, true] {
        let builder = PrewarmingState::default();
        if timed {
            builder.record_timed(&changes, Some(3));
        } else {
            builder.record(&changes, Some(3));
        }
        assert_eq!(
            builder.read(ReadKey::Storage(NONCE_PRECOMPILE_ADDRESS, ring_slot)),
            Some(ReadValue::Storage(U256::from(8)))
        );
        assert_eq!(builder.nonce_cursor(4), Some((U256::from(7), 0)));
    }
    engine.record_engine_timed(&changes, false);
    assert_eq!(
        engine.read(ReadKey::Storage(NONCE_PRECOMPILE_ADDRESS, ring_slot)),
        Some(ReadValue::Storage(U256::from(8)))
    );

    // Omission must not bypass lifecycle clearing. Missing slots on a newly
    // created account keep the existing implicit-zero hint semantics.
    nonce.mark_created();
    engine.record_engine_timed(
        &EvmState::from_iter([(NONCE_PRECOMPILE_ADDRESS, nonce.clone())]),
        true,
    );
    assert_eq!(
        engine.read(ReadKey::Storage(NONCE_PRECOMPILE_ADDRESS, keyed_slot)),
        Some(ReadValue::Storage(U256::ZERO))
    );
    nonce.mark_selfdestruct();
    engine.record_engine_timed(
        &EvmState::from_iter([(NONCE_PRECOMPILE_ADDRESS, nonce)]),
        true,
    );
    assert_eq!(
        engine.read(ReadKey::Account(NONCE_PRECOMPILE_ADDRESS)),
        Some(ReadValue::Account(None))
    );
}
