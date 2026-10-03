use super::*;
use alloy_primitives::{Bytes, U256};
use revm::{
    bytecode::Bytecode,
    database::{
        EmptyDB,
        states::{CacheAccount, bundle_state::BundleRetention, reverts::AccountInfoRevert},
    },
    state::{AccountId, EvmStorageSlot, TransactionId, bal::Bal},
};
use std::sync::{Arc, Mutex};

type HookStates = Arc<Mutex<Vec<EvmState>>>;

fn state(hook: bool, transitions: bool, bal: bool) -> (State<EmptyDB>, HookStates) {
    let captured = HookStates::default();
    let mut db = State::builder()
        .with_bundle_update_if(transitions)
        .with_bal_builder_if(bal)
        .build();
    if hook {
        let captured = Arc::clone(&captured);
        db.set_state_hook(Some(Box::new(move |changes: EvmState| {
            captured.lock().unwrap().push(changes);
        })));
    }
    (db, captured)
}

fn address(n: u8) -> Address {
    Address::repeat_byte(n)
}

fn info() -> AccountInfo {
    let code = Bytecode::new_legacy(Bytes::from_static(&[0x5b, 0x00]));
    AccountInfo {
        nonce: 1,
        balance: U256::from(100),
        code_hash: code.hash_slow(),
        code: Some(code),
        account_id: AccountId::new(3),
    }
}

fn account(info: &AccountInfo, slots: &[(u64, u64, u64)], tx: usize) -> Account {
    let mut account = Account::from(info.clone());
    account.set_current_info_as_original();
    account.transaction_id = TransactionId::new(tx).unwrap();
    account.mark_touch();
    for &(key, original, present) in slots {
        let mut slot = EvmStorageSlot::new_changed(
            U256::from(original),
            U256::from(present),
            account.transaction_id,
        );
        slot.mark_cold();
        account.storage.insert(U256::from(key), slot);
    }
    account
}

fn assert_code(a: &Bytecode, b: &Bytecode) {
    // Bytecode::eq only compares original bytes, not their execution kind/analysis.
    assert_eq!(a.kind(), b.kind());
    assert_eq!(a.original_byte_slice(), b.original_byte_slice());
    assert_eq!(a.bytecode(), b.bytecode());
    assert_eq!(a.legacy_jump_table(), b.legacy_jump_table());
}

fn assert_info(a: &AccountInfo, b: &AccountInfo) {
    assert_eq!(a, b);
    assert_eq!(a.account_id, b.account_id);
    match (&a.code, &b.code) {
        (Some(a), Some(b)) => assert_code(a, b),
        (None, None) => {}
        _ => panic!("inline bytecode availability differs"),
    }
}

fn assert_optional_info(a: &Option<AccountInfo>, b: &Option<AccountInfo>) {
    match (a, b) {
        (Some(a), Some(b)) => assert_info(a, b),
        (None, None) => {}
        _ => panic!("account presence differs"),
    }
}

fn assert_changes(a: &EvmState, b: &EvmState) {
    assert_eq!(a, b);
    for (address, a) in a {
        let b = &b[address];
        assert_info(&a.info, &b.info);
        assert_info(&a.original_info(), &b.original_info());
    }
}

fn assert_bal(a: &Bal, b: &Bal) {
    assert_eq!(a, b);
    for (address, a) in &a.accounts {
        let b = &b.accounts[address];
        for ((_, (_, a)), (_, (_, b))) in a.code.writes.iter().zip(&b.code.writes) {
            assert_code(a, b);
        }
    }
}

fn assert_state(a: &State<EmptyDB>, b: &State<EmptyDB>) {
    assert_eq!(a.cache, b.cache);
    for (address, a) in &a.cache.accounts {
        if let Some(a) = &a.account {
            assert_info(
                &a.info,
                &b.cache.accounts[address].account.as_ref().unwrap().info,
            );
        }
    }
    for (hash, code) in &a.cache.contracts {
        assert_code(code, &b.cache.contracts[hash]);
    }
    assert_eq!(a.transition_state, b.transition_state);
    if let (Some(a), Some(b)) = (&a.transition_state, &b.transition_state) {
        for (address, a) in &a.transitions {
            let b = &b.transitions[address];
            assert_optional_info(&a.info, &b.info);
            assert_optional_info(&a.previous_info, &b.previous_info);
        }
    }
    assert_eq!(a.bundle_state, b.bundle_state);
    for (address, a) in &a.bundle_state.state {
        let b = &b.bundle_state.state[address];
        assert_optional_info(&a.info, &b.info);
        assert_optional_info(&a.original_info, &b.original_info);
    }
    for (hash, code) in &a.bundle_state.contracts {
        assert_code(code, &b.bundle_state.contracts[hash]);
    }
    for (a, b) in a
        .bundle_state
        .reverts
        .iter()
        .zip(b.bundle_state.reverts.iter())
    {
        for (address, a) in a {
            let b = &b.iter().find(|(other, _)| other == address).unwrap().1;
            if let (AccountInfoRevert::RevertTo(a), AccountInfoRevert::RevertTo(b)) =
                (&a.account, &b.account)
            {
                assert_info(a, b);
            }
        }
    }
    assert_eq!(a.bal_state, b.bal_state);
    if let (Some(a), Some(b)) = (&a.bal_state.bal_builder, &b.bal_state.bal_builder) {
        assert_bal(a, b);
    }
}

fn commit_pair(fast: &mut State<EmptyDB>, ordinary: &mut State<EmptyDB>, changes: EvmState) {
    commit(fast, changes.clone());
    ordinary.commit(changes);
    assert_state(fast, ordinary);
}

fn merge_pair(fast: &mut State<EmptyDB>, ordinary: &mut State<EmptyDB>) {
    fast.merge_transitions(BundleRetention::Reverts);
    ordinary.merge_transitions(BundleRetention::Reverts);
    assert_state(fast, ordinary);
}

fn update_probe(db: &State<EmptyDB>, address: Address, account: &Account) -> bool {
    let (mut probe, _) = state(false, true, false);
    probe.cache = db.cache.clone();
    probe.transition_state = db.transition_state.clone();
    update(&mut probe, address, account)
}

#[test]
fn changed_storage_commit_preserves_original_values_and_reverts() {
    let (mut fast, _) = state(true, true, false);
    let (mut ordinary, _) = state(true, true, false);
    let address = address(1);
    let info = info();
    for db in [&mut fast, &mut ordinary] {
        db.insert_account_with_storage(
            address,
            info.clone(),
            [(U256::from(1), U256::ZERO), (U256::from(2), U256::from(7))]
                .into_iter()
                .collect(),
        );
    }
    commit_pair(
        &mut fast,
        &mut ordinary,
        [(address, account(&info, &[(1, 0, 5), (2, 7, 11)], 1))]
            .into_iter()
            .collect(),
    );
    // Public transition state may retain destruction history. Changed updates preserve it.
    for db in [&mut fast, &mut ordinary] {
        db.transition_state
            .as_mut()
            .unwrap()
            .transitions
            .get_mut(&address)
            .unwrap()
            .storage_was_destroyed = true;
    }
    for (tx, slot) in [(1, 888, 9), (2, 11, 7), (1, 9, 0), (1, 0, 3)]
        .into_iter()
        .enumerate()
    {
        let changed = account(&info, &[slot, (99, 123, 123)], tx + 2);
        assert!(
            update_probe(&fast, address, &changed),
            "must exercise eligible update"
        );
        commit_pair(
            &mut fast,
            &mut ordinary,
            [(address, changed)].into_iter().collect(),
        );
        assert!(
            !fast.cache.accounts[&address]
                .account
                .as_ref()
                .unwrap()
                .storage
                .contains_key(&U256::from(99))
        );
    }
    let transition = &fast.transition_state.as_ref().unwrap().transitions[&address];
    assert_eq!(
        transition.storage[&U256::from(1)].original_value(),
        U256::ZERO
    );
    assert!(!transition.storage.contains_key(&U256::from(2)));
    merge_pair(&mut fast, &mut ordinary);
    // The first commit after merging must fall back; later changes are eligible again.
    for (tx, (original, present)) in [(3, 8), (8, 3)].into_iter().enumerate() {
        let changed = account(&info, &[(1, original, present)], tx + 6);
        assert_eq!(update_probe(&fast, address, &changed), tx != 0);
        commit_pair(
            &mut fast,
            &mut ordinary,
            [(address, changed)].into_iter().collect(),
        );
    }
    merge_pair(&mut fast, &mut ordinary);
    assert_eq!(fast.bundle_state.reverts.len(), 2);
}

#[test]
fn mixed_lifecycle_commits_match_revm() {
    let (mut fast, _) = state(true, true, true);
    let (mut ordinary, _) = state(true, true, true);
    let info = info();
    for db in [&mut fast, &mut ordinary] {
        for n in 1..=6 {
            db.insert_account(address(n), info.clone());
        }
    }
    let prime = (1..=6)
        .map(|n| (address(n), account(&info, &[(1, 0, 1)], 1)))
        .collect();
    commit_pair(&mut fast, &mut ordinary, prime);
    for db in [&mut fast, &mut ordinary] {
        db.bump_bal_index();
        db.cache.accounts.get_mut(&address(5)).unwrap().status = AccountStatus::Loaded;
        db.transition_state
            .as_mut()
            .unwrap()
            .transitions
            .remove(&address(6));
    }
    let eligible = account(&info, &[(1, 1, 2)], 2);
    let mut destroyed = eligible.clone();
    destroyed.mark_selfdestruct();
    let mut empty = eligible.clone();
    empty.info = AccountInfo::default();
    let mut created = eligible.clone();
    created.mark_created();
    let code = Bytecode::new_legacy(Bytes::from_static(&[0x60, 0x42, 0x00]));
    created.info.code_hash = code.hash_slow();
    created.info.code = Some(code);
    assert!(update_probe(&fast, address(1), &eligible));
    let changes = [
        (address(1), eligible.clone()),
        (address(2), destroyed),
        (address(3), empty),
        (address(4), created),
        (address(5), eligible.clone()),
        (address(6), eligible.clone()),
        (address(7), eligible),
    ]
    .into_iter()
    .collect::<EvmState>();
    for n in 2..=7 {
        assert!(!update_probe(&fast, address(n), &changes[&address(n)]));
    }
    commit_pair(&mut fast, &mut ordinary, changes);
    assert!(fast.cache.accounts[&address(2)].account.is_none());
    assert!(fast.cache.accounts[&address(3)].account.is_none());
    assert_eq!(fast.cache.contracts.len(), 1);
    merge_pair(&mut fast, &mut ordinary);

    // Revival after destruction and creation followed by destruction stay on revm's path.
    let mut revived = account(&info, &[(1, 0, 9)], 3);
    revived.mark_created();
    let mut removed = account(&info, &[], 3);
    removed.mark_selfdestruct();
    for db in [&mut fast, &mut ordinary] {
        db.bump_bal_index();
    }
    commit_pair(
        &mut fast,
        &mut ordinary,
        [(address(2), revived), (address(4), removed)]
            .into_iter()
            .collect(),
    );
    merge_pair(&mut fast, &mut ordinary);
}

#[test]
fn metadata_and_bytecode_changes_use_revm_fallback() {
    let delegation = Bytecode::new_eip7702(address(42));
    let legacy = Bytecode::new_legacy(delegation.original_bytes());
    assert_eq!(delegation, legacy);
    for reverse in [false, true] {
        let (before_code, after_code) = if reverse {
            (legacy.clone(), delegation.clone())
        } else {
            (delegation.clone(), legacy.clone())
        };
        for change in 0..7 {
            let (mut fast, _) = state(true, true, false);
            let (mut ordinary, _) = state(true, true, false);
            let mut info = info();
            info.code_hash = before_code.hash_slow();
            info.code = Some(before_code.clone());
            if change == 6 {
                info.code = None;
            }
            for db in [&mut fast, &mut ordinary] {
                db.insert_account(address(1), info.clone());
            }
            commit_pair(
                &mut fast,
                &mut ordinary,
                [(address(1), account(&info, &[(1, 0, 1)], 1))]
                    .into_iter()
                    .collect(),
            );
            let mut changed = account(&info, &[(1, 1, 2)], 2);
            match change {
                0 => changed.info.account_id = AccountId::new(4),
                1 => changed.info.code = None,
                2 => changed.info.code = Some(after_code.clone()),
                3 => changed.info.nonce += 1,
                4 => changed.info.balance += U256::from(1),
                5 => changed.info.code_hash = Default::default(),
                6 => changed.info.code = Some(before_code.clone()),
                _ => unreachable!(),
            }
            if change <= 2 || change == 6 {
                assert_eq!(
                    changed.info, info,
                    "ordinary AccountInfo equality misses this change"
                );
            }
            assert!(!update_probe(&fast, address(1), &changed));
            commit_pair(
                &mut fast,
                &mut ordinary,
                [(address(1), changed)].into_iter().collect(),
            );
            merge_pair(&mut fast, &mut ordinary);
        }
    }
}

#[test]
fn commit_preserves_full_hook_payload_and_bal_for_all_observer_modes() {
    for hook in [false, true] {
        for transitions in [false, true] {
            for bal in [false, true] {
                let (mut fast, fast_hooks) = state(hook, transitions, bal);
                let (mut ordinary, ordinary_hooks) = state(hook, transitions, bal);
                let info = info();
                for db in [&mut fast, &mut ordinary] {
                    db.insert_account(address(1), info.clone());
                    db.cache
                        .accounts
                        .insert(address(2), CacheAccount::new_loaded_not_existing());
                }
                let mut inputs = Vec::new();
                for tx in 1..=3 {
                    fast.bump_bal_index();
                    ordinary.bump_bal_index();
                    let changed = account(&info, &[(1, tx as u64 - 1, tx as u64), (2, 7, 7)], tx);
                    let mut untouched = account(&info, &[(3, 17, 17)], tx);
                    untouched.unmark_touch();
                    let mut absent = Account::new_not_existing(TransactionId::new(tx).unwrap());
                    absent.storage.insert(
                        U256::from(4),
                        EvmStorageSlot::new(U256::ZERO, absent.transaction_id),
                    );
                    let changes = [
                        (address(1), changed),
                        (address(2), absent),
                        (address(3), untouched),
                    ]
                    .into_iter()
                    .collect::<EvmState>();
                    inputs.push(changes.clone());
                    commit_pair(&mut fast, &mut ordinary, changes);
                    assert!(!fast.cache.accounts.contains_key(&address(3)));
                }
                let fast_hooks = fast_hooks.lock().unwrap();
                let ordinary_hooks = ordinary_hooks.lock().unwrap();
                assert_eq!(fast_hooks.len(), if hook { inputs.len() } else { 0 });
                assert_eq!(fast_hooks.len(), ordinary_hooks.len());
                for ((fast, ordinary), input) in
                    fast_hooks.iter().zip(ordinary_hooks.iter()).zip(&inputs)
                {
                    assert_changes(fast, ordinary);
                    assert_changes(fast, input);
                }
                if bal {
                    let built = fast.bal_state.bal_builder.as_ref().unwrap();
                    assert!(
                        built.accounts.contains_key(&address(3)),
                        "BAL must retain untouched observations"
                    );
                    assert!(
                        built.accounts[&address(1)]
                            .storage
                            .storage
                            .contains_key(&U256::from(2))
                    );
                    assert!(
                        built.accounts[&address(3)]
                            .storage
                            .storage
                            .contains_key(&U256::from(3))
                    );
                    assert_bal(
                        &fast.take_built_bal().unwrap(),
                        &ordinary.take_built_bal().unwrap(),
                    );
                }
                merge_pair(&mut fast, &mut ordinary);
            }
        }
    }
}
