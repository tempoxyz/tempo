use super::{
    super::{commit_prediction, forwarding::Forwarding},
    *,
};
use alloy_evm::FromRecoveredTx;
use alloy_primitives::Bytes;
use alloy_sol_types::SolCall;
use revm::{
    Database,
    context::{CfgEnv, JournalTr},
    database::{CacheDB, EmptyDB, State},
    state::{Account, EvmState, EvmStorageSlot},
};
use tempo_precompiles::{
    PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
    storage::{StorageActions, StorageCtx},
    test_util::TIP20Setup,
    tip20::ITIP20,
};
use tempo_primitives::{TempoSignature, TempoTransaction, transaction::Call};

#[test]
fn predictions_account_lifecycle_matches_revm_state_commit() {
    let address = PATH_USD_ADDRESS;
    let recipient = Address::with_last_byte(100);
    let old_slot = address.mapping_slot(tempo_precompiles::tip20::slots::BALANCES);
    let new_slot = recipient.mapping_slot(tempo_precompiles::tip20::slots::BALANCES);
    let keys = [
        ReadKey::Account(address),
        ReadKey::Storage(address, old_slot),
        ReadKey::Storage(address, new_slot),
    ];
    for case in [
        "untouched",
        "empty",
        "created_empty",
        "created_zero",
        "selfdestruct",
        "created_selfdestruct",
        "native",
    ] {
        let mut initial = Account::from(AccountInfo {
            nonce: 1,
            ..Default::default()
        });
        initial.mark_touch();
        initial.storage.insert(
            old_slot,
            EvmStorageSlot::new_changed(U256::ZERO, U256::from(7), Default::default()),
        );
        let mut changes = EvmState::default();
        changes.insert(address, initial.clone());
        let prefix = PrewarmingState::default();
        let mut overlay = CacheDB::<EmptyDB>::default();
        let mut db = State::builder().with_database(EmptyDB::default()).build();
        prefix.record(&changes, None);
        commit_prediction(&mut overlay, &changes);
        db.commit(changes);
        let prefetched = keys
            .iter()
            .map(|&key| (key, read(&mut db, key).unwrap()))
            .collect();
        let input = (
            aa_transfer(TempoHardfork::T0, address, recipient, 0),
            env(TempoHardfork::T0),
        );
        let forwarding = Forwarding::new(&[input.clone(), input]);
        let seed = forwarding.seed(0, &prefetched);

        let mut account = Account::from(initial.info);
        if case != "untouched" {
            account.mark_touch();
        }
        if case != "native" {
            account.info = AccountInfo::default();
        }
        if case.starts_with("created") {
            account.mark_created();
        }
        if case.ends_with("selfdestruct") {
            account.mark_selfdestruct();
        }
        account.storage.insert(
            new_slot,
            EvmStorageSlot::new_changed(
                U256::ZERO,
                if case == "created_zero" {
                    U256::ZERO
                } else {
                    U256::from(9)
                },
                Default::default(),
            ),
        );
        let mut changes = EvmState::default();
        changes.insert(address, account);
        prefix.record(&changes, None);
        let original = changes.clone();
        commit_prediction(&mut overlay, &changes);
        assert_eq!(changes, original, "prediction changed the execution result");
        forwarding.complete(0, Some(&changes), &seed);
        let forwarded = forwarding.seed(1, &prefetched);
        db.commit(changes);
        for key in keys {
            let expected = read(&mut db, key).unwrap();
            assert_eq!(
                read(&mut overlay, key).unwrap(),
                expected,
                "overlay {case}: {key:?}"
            );
            assert_eq!(
                forwarded.get(&key),
                Some(&expected),
                "forwarding {case}: {key:?}"
            );
            if let Some(hint) = prefix.read(key) {
                assert_eq!(hint, expected, "prefix {case}: {key:?}");
            }
        }
        let deleted = matches!(case, "empty" | "selfdestruct" | "created_selfdestruct");
        assert_eq!(db.basic(address).unwrap().is_none(), deleted, "{case}");
    }
}

#[test]
fn private_prediction_revival_preserves_deleted_parent_storage() {
    let address = Address::with_last_byte(103);
    let old_slot = U256::ONE;
    let new_slot = U256::from(2);
    let initial = AccountInfo {
        nonce: 1,
        ..Default::default()
    };
    let mut parent = CacheDB::<EmptyDB>::default();
    parent.insert_account_info(address, initial.clone());
    parent
        .insert_account_storage(address, old_slot, U256::from(7))
        .unwrap();

    for selfdestruct in [false, true] {
        let mut overlay = CacheDB::new(parent.clone());
        let mut canonical = State::builder().with_database(parent.clone()).build();
        assert_eq!(canonical.basic(address).unwrap(), Some(initial.clone()));
        let mut removed = Account::from(initial.clone());
        removed.mark_touch();
        if selfdestruct {
            removed.mark_selfdestruct();
        } else {
            removed.info = AccountInfo::default();
        }
        let changes = EvmState::from_iter([(address, removed)]);
        commit_prediction(&mut overlay, &changes);
        canonical.commit(changes);
        assert!(overlay.basic(address).unwrap().is_none());

        // Receiving value materializes the deleted address without setting
        // Created. Keep the old slot unread so a cached zero cannot hide an
        // incorrect reload from the parent state after revival.
        let mut revived = Account::new_not_existing(Default::default());
        revived.info.balance = U256::ONE;
        revived.mark_touch();
        revived.storage.insert(
            new_slot,
            EvmStorageSlot::new_changed(U256::ZERO, U256::from(11), Default::default()),
        );
        assert!(!revived.is_created());
        let changes = EvmState::from_iter([(address, revived)]);
        commit_prediction(&mut overlay, &changes);
        assert!(!changes[&address].is_created());
        canonical.commit(changes);
        for key in [
            ReadKey::Account(address),
            ReadKey::Storage(address, old_slot),
            ReadKey::Storage(address, new_slot),
        ] {
            assert_eq!(
                read(&mut overlay, key).unwrap(),
                read(&mut canonical, key).unwrap(),
                "selfdestruct={selfdestruct}: {key:?}"
            );
        }
        assert_eq!(overlay.storage(address, old_slot).unwrap(), U256::ZERO);
        assert_eq!(overlay.storage(address, new_slot).unwrap(), U256::from(11));
    }
}

fn empty_aa_fixture() -> (CacheDB<EmptyDB>, Address, Address) {
    let caller = Address::with_last_byte(101);
    let recipient = Address::with_last_byte(102);
    let mut setup = crate::test_utils::test_evm_with_basefee(CacheDB::<EmptyDB>::default(), 0);
    StorageCtx::enter_ctx(setup.ctx_mut(), StorageActions::disabled(), || {
        TIP20Setup::path_usd(caller)
            .with_issuer(caller)
            .with_mint(caller, U256::from(1_000_000_000u64))
            .with_mint(recipient, U256::ONE)
            .apply()
            .unwrap();
    });
    let changes = setup.ctx_mut().journaled_state.finalize();
    setup.db_mut().commit(changes);
    let mut parent = setup.finish().0;
    // These native accounts exist in node genesis. The sender deliberately has
    // no Ethereum account: TIP-20 funding lives in the token's storage instead.
    for address in [NONCE_PRECOMPILE_ADDRESS, TIP_FEE_MANAGER_ADDRESS] {
        parent.insert_account_info(
            address,
            AccountInfo::default().with_code(Bytecode::new_raw(Bytes::from_static(&[0]))),
        );
    }
    assert!(parent.basic(caller).unwrap().is_none());

    (parent, caller, recipient)
}

fn env(spec: TempoHardfork) -> Env {
    // Every supported Tempo fork uses Osaka, hence post-EIP-161 clearing.
    assert_eq!(
        revm::primitives::hardfork::SpecId::from(spec),
        revm::primitives::hardfork::SpecId::OSAKA
    );
    Env {
        cfg_env: CfgEnv::new_with_spec_and_gas_params(
            spec,
            tempo_revm::gas_params::tempo_gas_params(spec),
        ),
        block_env: TempoBlockEnv {
            inner: revm::context::BlockEnv {
                basefee: 0,
                gas_limit: 30_000_000,
                ..Default::default()
            },
            ..Default::default()
        },
    }
}

fn aa_transfer(
    spec: TempoHardfork,
    caller: Address,
    recipient: Address,
    index: usize,
) -> TempoTxEnv {
    let signed = TempoTransaction {
        chain_id: 1,
        gas_limit: 1_000_000,
        max_fee_per_gas: 1,
        max_priority_fee_per_gas: 1,
        fee_token: Some(PATH_USD_ADDRESS),
        nonce_key: if spec.is_t1() {
            U256::MAX
        } else {
            U256::from(index + 1)
        },
        valid_before: spec
            .is_t1()
            .then_some(std::num::NonZeroU64::new(25).unwrap()),
        calls: vec![Call {
            to: PATH_USD_ADDRESS.into(),
            value: U256::ZERO,
            input: ITIP20::transferCall {
                to: recipient,
                amount: U256::from(index + 1),
            }
            .abi_encode()
            .into(),
        }],
        ..Default::default()
    }
    .into_signed(TempoSignature::default());
    TempoTxEnv::from_recovered_tx(&signed, caller)
}

#[test]
fn repeated_empty_aa_callers_reuse_state_backed_prefix_across_forks() {
    let (parent, caller, recipient) = empty_aa_fixture();
    for &spec in TempoHardfork::VARIANTS {
        let env = env(spec);
        let mut canonical = TempoEvm::new(
            State::builder().with_database(parent.clone()).build(),
            env.clone(),
        );
        let mut ordered = TempoEvm::new(
            State::builder().with_database(parent.clone()).build(),
            env.clone(),
        );
        ordered.set_speculative_executor(Some(SpeculativeExecutor::new(1, 1).unwrap()));
        let prefix = PrewarmingState::default();
        let mut recorder = PrewarmingExecutor::new(parent.clone(), env).with_state(prefix.clone());
        for index in 0..16 {
            let tx = aa_transfer(spec, caller, recipient, index);
            let offset = spec.is_t1().then_some(index);
            let candidate = recorder.execute(tx.clone(), offset).unwrap();
            ordered.set_preexecuted_transaction(candidate);
            let expected = canonical.transact_raw(tx.clone()).unwrap();
            let actual = ordered.transact_raw(tx).unwrap();
            assert!(expected.result.is_success());
            assert_eq!(actual, expected, "{spec:?}, tx={index}");
            prefix.record(&actual.state, offset);
            canonical.db_mut().commit(expected.state);
            ordered.db_mut().commit(actual.state);
            assert!(ordered.db_mut().basic(caller).unwrap().is_none());
            assert_eq!(
                prefix.read(ReadKey::Account(caller)),
                Some(ReadValue::Account(None))
            );
        }
        assert_eq!(ordered.execution_stats().reused, 16, "{spec:?}");
        assert_eq!(ordered.db().cache, canonical.db().cache, "{spec:?}");
    }
}

#[test]
fn repeated_empty_aa_callers_reuse_chained_and_forwarded_predictions() {
    check_aa_predictions(false);
}

#[test]
fn empty_aa_predictions_revalidate_skipped_predecessors() {
    check_aa_predictions(true);
}

fn check_aa_predictions(skip_first: bool) {
    let (parent, caller, recipient) = empty_aa_fixture();
    for &spec in TempoHardfork::VARIANTS {
        let transactions = (0..16)
            .map(|index| aa_transfer(spec, caller, recipient, index))
            .collect::<Vec<_>>();
        for forwarding in [false, true] {
            let mut canonical = TempoEvm::new(
                State::builder().with_database(parent.clone()).build(),
                env(spec),
            );
            let mut ordered = TempoEvm::new(
                State::builder().with_database(parent.clone()).build(),
                env(spec),
            );
            ordered.set_speculative_executor(Some(
                SpeculativeExecutor::new(2, transactions.len())
                    .unwrap()
                    .with_adaptive_backoff(false)
                    .with_streaming(false)
                    .with_state_forwarding(forwarding),
            ));
            // Freeze all predictions before executing the selected prefix. If
            // the first candidate is discarded, its state must never authorize
            // the balances or nonce positions of a later accepted transaction.
            ordered
                .prepare_transactions(transactions.iter().cloned().map(|tx| (tx, Address::ZERO)));
            for (index, tx) in transactions
                .iter()
                .enumerate()
                .skip(usize::from(skip_first))
            {
                let expected = canonical.transact_raw(tx.clone()).unwrap();
                let actual = ordered.transact_raw(tx.clone()).unwrap();
                assert!(expected.result.is_success());
                assert_eq!(
                    actual, expected,
                    "{spec:?}, forwarding={forwarding}, tx={index}"
                );
                assert_eq!(ordered.validator_fee(), canonical.validator_fee());
                canonical.db_mut().commit(expected.state);
                ordered.db_mut().commit(actual.state);
                assert!(ordered.db_mut().basic(caller).unwrap().is_none());
            }
            let stats = ordered.execution_stats();
            if skip_first {
                assert!(
                    stats.conflicts > 0,
                    "{spec:?}, forwarding={forwarding}: {stats:?}"
                );
            } else {
                assert_eq!(
                    stats.reused, 16,
                    "{spec:?}, forwarding={forwarding}: {stats:?}"
                );
                assert_eq!(stats.conflicts + stats.retries, 0);
            }
            assert_same_committed_state(canonical.db_mut(), ordered.db_mut());
        }
    }
}

fn assert_same_committed_state(a: &mut State<CacheDB<EmptyDB>>, b: &mut State<CacheDB<EmptyDB>>) {
    // Compare logical values, including untouched parent storage. Speculation
    // may load additional zero slots (especially for a discarded nonce), so
    // exact cache-layout equality would reject equivalent committed states.
    let mut accounts = std::collections::BTreeSet::new();
    let mut storage = std::collections::BTreeSet::new();
    for db in [&*a, &*b] {
        for (&address, account) in &db.database.cache.accounts {
            accounts.insert(address);
            storage.extend(account.storage.keys().map(|&slot| (address, slot)));
        }
        for (&address, account) in &db.cache.accounts {
            accounts.insert(address);
            if let Some(account) = &account.account {
                storage.extend(account.storage.keys().map(|&slot| (address, slot)));
            }
        }
    }
    for address in accounts {
        assert_eq!(
            a.basic(address).unwrap(),
            b.basic(address).unwrap(),
            "{address}"
        );
    }
    for (address, slot) in storage {
        assert_eq!(
            a.storage(address, slot).unwrap(),
            b.storage(address, slot).unwrap(),
            "{address}, {slot}"
        );
    }
}
