use super::*;
use alloy_primitives::{Bytes, TxKind};
use revm::{
    Database as _,
    context::TxEnv,
    database::{CacheDB, EmptyDB, State},
    state::bal::Bal,
};

fn candidate<E: DBErrorMarker>(reads: Vec<(ReadKey, ReadValue)>) -> SpeculativeResult<E> {
    let (_, env) = crate::test_utils::test_evm_with_basefee(EmptyDB::default(), 0).finish();
    let tx = TempoTxEnv {
        inner: TxEnv {
            caller: Address::with_last_byte(201),
            kind: TxKind::Call(Address::with_last_byte(202)),
            gas_limit: 1_000_000,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut worker = PrewarmingExecutor::new(EmptyDB::default(), env);
    let mut candidate = worker
        .execute(tx.clone(), None)
        .unwrap()
        .into_candidate(&tx)
        .unwrap();
    candidate.reads = reads;
    candidate
}

fn fixture() -> (CacheDB<EmptyDB>, Address, B256, Vec<ReadKey>) {
    let address = Address::with_last_byte(211);
    let code = Bytecode::new_raw(Bytes::from_static(&[0x60, 0, 0]));
    let info = AccountInfo {
        nonce: 1,
        ..Default::default()
    }
    .with_code(code);
    let hash = info.code_hash;
    let mut db = CacheDB::<EmptyDB>::default();
    db.insert_account_info(address, info);
    db.insert_account_storage(address, U256::ONE, U256::from(7))
        .unwrap();
    (
        db,
        address,
        hash,
        vec![
            ReadKey::Account(address),
            ReadKey::Storage(address, U256::ONE),
            ReadKey::Storage(address, U256::from(2)),
            ReadKey::Code(hash),
            ReadKey::BlockHash(1),
        ],
    )
}

fn compare<P: Database>(
    canonical: &mut State<P>,
    cached: &mut State<P>,
    reads: &[(ReadKey, ReadValue)],
) -> Result<bool, String> {
    let mut normal = candidate(reads.to_vec());
    let mut fast = candidate(reads.to_vec());
    let expected = normal
        .validate(canonical)
        .map_err(|error| format!("{error:?}"));
    let actual = fast
        .validate_state(cached)
        .map_err(|error| format!("{error:?}"));
    assert_eq!(actual, expected);
    assert_eq!(
        format!("{:?}", fast.conflict),
        format!("{:?}", normal.conflict)
    );
    assert_eq!(fast.result.unwrap(), normal.result.unwrap());
    assert_eq!(fast.fees_rebased, normal.fees_rebased);
    assert_eq!(cached.cache, canonical.cache);
    assert_eq!(cached.bal_state, canonical.bal_state);
    actual
}

#[test]
fn canonical_cache_validation_tracks_cold_reads_and_direct_mutations() {
    let (parent, address, hash, keys) = fixture();
    let mut oracle = State::builder().with_database(parent.clone()).build();
    let reads = keys
        .into_iter()
        .map(|key| (key, read(&mut oracle, key).unwrap()))
        .collect::<Vec<_>>();
    for changed in ["none", "account", "storage", "code", "block_hash"] {
        let mut canonical = State::builder().with_database(parent.clone()).build();
        let mut cached = State::builder().with_database(parent.clone()).build();
        assert_eq!(compare(&mut canonical, &mut cached, &reads), Ok(true));
        for db in [&mut canonical, &mut cached] {
            match changed {
                "account" => {
                    db.cache
                        .accounts
                        .get_mut(&address)
                        .unwrap()
                        .account
                        .as_mut()
                        .unwrap()
                        .info
                        .balance = U256::ONE
                }
                "storage" => {
                    db.cache
                        .accounts
                        .get_mut(&address)
                        .unwrap()
                        .account
                        .as_mut()
                        .unwrap()
                        .storage
                        .insert(U256::ONE, U256::from(9));
                }
                "code" => {
                    db.cache
                        .contracts
                        .insert(hash, Bytecode::new_raw(Bytes::from_static(&[0])));
                }
                "block_hash" => {
                    db.block_hashes.insert(1, B256::repeat_byte(3));
                }
                _ => {}
            }
        }
        assert_eq!(
            compare(&mut canonical, &mut cached, &reads),
            Ok(changed == "none"),
            "{changed}"
        );
    }
}

#[test]
fn canonical_cache_validation_honors_absence_and_cleared_storage() {
    let (parent, address, _, _) = fixture();
    for created in [false, true] {
        let mut canonical = State::builder().with_database(parent.clone()).build();
        let mut cached = State::builder().with_database(parent.clone()).build();
        for db in [&mut canonical, &mut cached] {
            db.basic(address).unwrap();
            let mut account = reth_revm::state::Account::default();
            account.mark_touch();
            if created {
                account.mark_created();
                account.info.nonce = 1;
            } else {
                account.mark_selfdestruct();
            }
            db.commit(reth_revm::state::EvmState::from_iter([(address, account)]));
        }
        // Slot 1 was nonzero in the parent and has never been loaded into State.
        // A cleared account must produce zero without consulting that old value.
        let account = read(&mut canonical, ReadKey::Account(address)).unwrap();
        let reads = vec![
            (ReadKey::Account(address), account),
            (
                ReadKey::Storage(address, U256::ONE),
                ReadValue::Storage(U256::ZERO),
            ),
        ];
        assert_eq!(compare(&mut canonical, &mut cached, &reads), Ok(true));
        let stale = [(
            ReadKey::Storage(address, U256::ONE),
            ReadValue::Storage(U256::from(7)),
        )];
        assert_eq!(compare(&mut canonical, &mut cached, &stale), Ok(false));
    }
}

#[test]
fn canonical_cache_validation_preserves_known_zero_materialization() {
    let (parent, address, _, _) = fixture();
    let mut canonical = State::builder().with_database(parent.clone()).build();
    let mut cached = State::builder().with_database(parent).build();
    for db in [&mut canonical, &mut cached] {
        db.basic(address).unwrap();
        let mut account = reth_revm::state::Account::default();
        account.mark_touch();
        account.mark_created();
        account.info.nonce = 1;
        db.commit(reth_revm::state::EvmState::from_iter([(address, account)]));
    }
    let reads = [(
        ReadKey::Storage(address, U256::ONE),
        ReadValue::Storage(U256::ZERO),
    )];
    assert_eq!(compare(&mut canonical, &mut cached, &reads), Ok(true));
    // Canonical validation materializes the known zero. A later public status
    // change must not expose the old nonzero parent value on only one path.
    for db in [&mut canonical, &mut cached] {
        db.cache.accounts.get_mut(&address).unwrap().status = reth_revm::db::AccountStatus::Loaded;
    }
    assert_eq!(compare(&mut canonical, &mut cached, &reads), Ok(true));
}

#[test]
fn canonical_cache_validation_rechecks_bal_presence_each_time() {
    let (parent, address, _, _) = fixture();
    let mut canonical = State::builder().with_database(parent.clone()).build();
    let mut cached = State::builder().with_database(parent).build();
    let key = ReadKey::Account(address);
    let reads = [(key, read(&mut canonical, key).unwrap())];
    assert_eq!(compare(&mut canonical, &mut cached, &reads), Ok(true));
    for db in [&mut canonical, &mut cached] {
        db.set_bal(Some(Arc::new(Bal::new())));
        db.bump_bal_index();
    }
    // Warm entries cannot hide BAL's missing-account error.
    assert!(compare(&mut canonical, &mut cached, &reads).is_err());
    for db in [&mut canonical, &mut cached] {
        db.set_bal(None);
    }
    assert_eq!(compare(&mut canonical, &mut cached, &reads), Ok(true));
}

#[derive(Debug, thiserror::Error)]
#[error("provider unavailable")]
struct Unavailable;
impl DBErrorMarker for Unavailable {}

#[derive(Debug)]
struct FailingProvider;
impl revm::Database for FailingProvider {
    type Error = Unavailable;
    fn basic(&mut self, _: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Err(Unavailable)
    }
    fn storage(&mut self, _: Address, _: U256) -> Result<U256, Self::Error> {
        Err(Unavailable)
    }
    fn code_by_hash(&mut self, _: B256) -> Result<Bytecode, Self::Error> {
        Err(Unavailable)
    }
    fn block_hash(&mut self, _: u64) -> Result<B256, Self::Error> {
        Err(Unavailable)
    }
}

#[test]
fn canonical_cache_validation_preserves_cold_provider_errors() {
    let address = Address::with_last_byte(212);
    for reads in [
        vec![(ReadKey::Account(address), ReadValue::Account(None))],
        vec![(
            ReadKey::Storage(address, U256::ONE),
            ReadValue::Storage(U256::ZERO),
        )],
        vec![(
            ReadKey::Code(B256::repeat_byte(4)),
            ReadValue::Code(Bytecode::default()),
        )],
        vec![(ReadKey::BlockHash(1), ReadValue::BlockHash(B256::ZERO))],
    ] {
        let mut normal = candidate(reads.clone());
        let mut fast = candidate(reads);
        let mut canonical = State::builder().with_database(FailingProvider).build();
        let mut cached = State::builder().with_database(FailingProvider).build();
        // Keep storage cold while ensuring its account itself is warm.
        for db in [&mut canonical, &mut cached] {
            db.insert_account(
                address,
                AccountInfo {
                    nonce: 1,
                    ..Default::default()
                },
            );
        }
        // The account case must still exercise a missing provider account.
        normal
            .reads
            .iter_mut()
            .chain(fast.reads.iter_mut())
            .for_each(|(key, _)| {
                if let ReadKey::Account(value) = key {
                    *value = Address::with_last_byte(213);
                }
            });
        let expected = normal.validate(&mut canonical).unwrap_err();
        let actual = fast.validate_state(&mut cached).unwrap_err();
        assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
    }
}

#[test]
fn canonical_cache_validation_scans_warm_runs_across_cold_reads_and_revisits() {
    let (mut parent, address, hash, _) = fixture();
    let other = Address::with_last_byte(214);
    parent.insert_account_info(
        other,
        AccountInfo {
            nonce: 1,
            ..Default::default()
        },
    );
    parent
        .insert_account_storage(other, U256::ONE, U256::from(91))
        .unwrap();
    for slot in 2..=8 {
        parent
            .insert_account_storage(address, U256::from(slot), U256::from(slot + 10))
            .unwrap();
    }
    let mut keys = vec![ReadKey::Account(address)];
    keys.extend((1..=8).map(|slot| ReadKey::Storage(address, U256::from(slot))));
    keys.extend([
        ReadKey::Account(other),
        ReadKey::Storage(other, U256::ONE),
        ReadKey::Storage(address, U256::ONE),
        ReadKey::Storage(address, U256::from(9)),
        ReadKey::Storage(address, U256::from(2)),
        ReadKey::BlockHash(55),
        ReadKey::Storage(address, U256::from(3)),
        ReadKey::Code(hash),
    ]);
    let mut oracle = State::builder().with_database(parent.clone()).build();
    let reads = keys
        .into_iter()
        .map(|key| (key, read(&mut oracle, key).unwrap()))
        .collect::<Vec<_>>();
    let mut canonical = State::builder().with_database(parent.clone()).build();
    let mut cached = State::builder().with_database(parent).build();
    for db in [&mut canonical, &mut cached] {
        db.basic(address).unwrap();
        for slot in 1..=8 {
            db.storage(address, U256::from(slot)).unwrap();
        }
    }
    assert_eq!(compare(&mut canonical, &mut cached, &reads), Ok(true));
    for db in [&mut canonical, &mut cached] {
        assert!(db.cache.accounts.contains_key(&other));
        let storage = &mut db
            .cache
            .accounts
            .get_mut(&address)
            .unwrap()
            .account
            .as_mut()
            .unwrap()
            .storage;
        assert_eq!(storage.get(&U256::from(9)), Some(&U256::ZERO));
        storage.insert(U256::from(6), U256::MAX);
    }
    // A later validation must observe direct changes even in a previously
    // accepted warm run. No borrowed account survives the previous call.
    assert_eq!(compare(&mut canonical, &mut cached, &reads), Ok(false));
}

#[test]
fn canonical_cache_validation_stops_warm_runs_before_later_provider_errors() {
    let address = Address::with_last_byte(215);
    for conflict in [false, true] {
        let mut canonical = State::builder().with_database(FailingProvider).build();
        let mut cached = State::builder().with_database(FailingProvider).build();
        for db in [&mut canonical, &mut cached] {
            db.insert_account(
                address,
                AccountInfo {
                    nonce: 1,
                    ..Default::default()
                },
            );
            db.cache
                .accounts
                .get_mut(&address)
                .unwrap()
                .account
                .as_mut()
                .unwrap()
                .storage
                .extend([(U256::ONE, U256::from(7)), (U256::from(2), U256::from(8))]);
        }
        let reads = vec![
            (
                ReadKey::Storage(address, U256::ONE),
                ReadValue::Storage(U256::from(7)),
            ),
            (
                ReadKey::Storage(address, U256::from(2)),
                ReadValue::Storage(U256::from(if conflict { 9 } else { 8 })),
            ),
            (
                ReadKey::Storage(address, U256::from(3)),
                ReadValue::Storage(U256::ZERO),
            ),
        ];
        let mut normal = candidate(reads.clone());
        let mut fast = candidate(reads);
        let expected = normal
            .validate(&mut canonical)
            .map_err(|error| format!("{error:?}"));
        let actual = fast
            .validate_state(&mut cached)
            .map_err(|error| format!("{error:?}"));
        assert_eq!(actual, expected);
        if conflict {
            // The mismatching second warm slot must stop validation before
            // the third slot would consult the failing provider.
            assert_eq!(actual, Ok(false));
            assert!(matches!(fast.conflict, Some(ConflictKind::Storage)));
        } else {
            // With no conflict, a cold read inside the same account run must
            // still reach the provider and return its error.
            assert!(actual.is_err());
        }
    }
}

#[derive(Clone, Debug, Default)]
struct TracedProvider {
    reads: Vec<ReadKey>,
    failing_slot: Option<(Address, U256)>,
}

impl revm::Database for TracedProvider {
    type Error = Unavailable;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.reads.push(ReadKey::Account(address));
        Ok(Some(AccountInfo {
            nonce: 1,
            ..Default::default()
        }))
    }

    fn storage(&mut self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        self.reads.push(ReadKey::Storage(address, slot));
        if self.failing_slot == Some((address, slot)) {
            return Err(Unavailable);
        }
        Ok(slot + U256::from(10))
    }

    fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
        self.reads.push(ReadKey::Code(hash));
        Err(Unavailable)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.reads.push(ReadKey::BlockHash(number));
        Err(Unavailable)
    }
}

#[test]
fn canonical_cache_validation_materializes_cold_runs_in_provider_order() {
    let address = Address::with_last_byte(216);
    let other = Address::with_last_byte(217);
    let info = AccountInfo {
        nonce: 1,
        ..Default::default()
    };
    let storage = |address, slot| ReadKey::Storage(address, U256::from(slot));
    for scenario in ["success", "conflict", "error", "malformed"] {
        let provider = TracedProvider {
            // A conflict or malformed read must stop before the later error.
            failing_slot: match scenario {
                "error" => Some((address, U256::from(3))),
                "conflict" | "malformed" => Some((address, U256::from(4))),
                _ => None,
            },
            ..Default::default()
        };
        let mut canonical = State::builder().with_database(provider.clone()).build();
        let mut cached = State::builder().with_database(provider).build();
        for db in [&mut canonical, &mut cached] {
            db.insert_account_with_storage(
                address,
                info.clone(),
                HashMap::from_iter([(U256::ONE, U256::from(11))]),
            );
        }
        let reads = vec![
            (
                ReadKey::Account(address),
                ReadValue::Account(Some(info.clone())),
            ),
            (storage(address, 1), ReadValue::Storage(U256::from(11))),
            (storage(address, 2), ReadValue::Storage(U256::from(12))),
            (storage(address, 2), ReadValue::Storage(U256::from(12))),
            (
                storage(address, 3),
                match scenario {
                    "conflict" => ReadValue::Storage(U256::from(14)),
                    "malformed" => ReadValue::Account(None),
                    _ => ReadValue::Storage(U256::from(13)),
                },
            ),
            (storage(address, 4), ReadValue::Storage(U256::from(14))),
            (
                ReadKey::Account(other),
                ReadValue::Account(Some(info.clone())),
            ),
            (storage(other, 2), ReadValue::Storage(U256::from(12))),
            (storage(address, 4), ReadValue::Storage(U256::from(14))),
        ];
        let result = compare(&mut canonical, &mut cached, &reads);
        if scenario == "error" {
            assert!(result.is_err());
        } else {
            assert_eq!(result, Ok(scenario == "success"), "{scenario}");
        }
        let mut expected_calls = vec![storage(address, 2), storage(address, 3)];
        if scenario == "success" {
            expected_calls.extend([
                storage(address, 4),
                ReadKey::Account(other),
                storage(other, 2),
            ]);
        }
        assert_eq!(canonical.database.reads, expected_calls, "{scenario}");
        assert_eq!(cached.database.reads, expected_calls, "{scenario}");
        let slots = &cached.cache.accounts[&address]
            .account
            .as_ref()
            .unwrap()
            .storage;
        assert_eq!(slots.get(&U256::from(2)), Some(&U256::from(12)));
        // Successful reads are materialized even if they expose a conflict.
        // Failed reads insert nothing, and no later read is performed.
        assert_eq!(
            slots.get(&U256::from(3)).copied(),
            (scenario != "error").then_some(U256::from(13)),
            "{scenario}"
        );
        assert_eq!(slots.contains_key(&U256::from(4)), scenario == "success");
    }
}

#[test]
fn canonical_cache_validation_preserves_bundle_slots_and_bal_builder() {
    use revm::database::{AccountStatus, BundleAccount, BundleState, states::StorageSlot};

    let address = Address::with_last_byte(218);
    let info = AccountInfo {
        nonce: 2,
        ..Default::default()
    };
    for status in [AccountStatus::Loaded, AccountStatus::InMemoryChange] {
        let mut bundle = BundleState::default();
        bundle.state.insert(
            address,
            BundleAccount::new(
                Some(info.clone()),
                Some(info.clone()),
                HashMap::from_iter([(
                    U256::ONE,
                    StorageSlot::new_changed(U256::ZERO, U256::from(77)),
                )]),
                status,
            ),
        );
        let provider = TracedProvider::default();
        let mut canonical = State::builder()
            .with_database(provider.clone())
            .with_bundle_prestate(bundle.clone())
            .with_bal_builder()
            .build();
        let mut cached = State::builder()
            .with_database(provider)
            .with_bundle_prestate(bundle.clone())
            .with_bal_builder()
            .build();
        let bal_before = cached.bal_state.clone();
        assert!(!cached.has_bal());
        assert!(cached.bal_state.bal_builder.is_some());
        let mut reads = vec![
            (
                ReadKey::Account(address),
                ReadValue::Account(Some(info.clone())),
            ),
            (
                ReadKey::Storage(address, U256::ONE),
                ReadValue::Storage(U256::from(77)),
            ),
        ];
        for slot in [2, 3, 2] {
            reads.push((
                ReadKey::Storage(address, U256::from(slot)),
                ReadValue::Storage(if status.is_storage_known() {
                    U256::ZERO
                } else {
                    U256::from(slot + 10)
                }),
            ));
        }
        assert_eq!(compare(&mut canonical, &mut cached, &reads), Ok(true));
        let expected_calls = if status.is_storage_known() {
            vec![]
        } else {
            vec![
                ReadKey::Storage(address, U256::from(2)),
                ReadKey::Storage(address, U256::from(3)),
            ]
        };
        assert_eq!(canonical.database.reads, expected_calls);
        assert_eq!(cached.database.reads, expected_calls);
        assert_eq!(cached.bal_state, bal_before);
        assert_eq!(cached.bundle_state, bundle);
        assert_eq!(canonical.bundle_state, bundle);
        let account = &cached.cache.accounts[&address];
        assert_eq!(account.status, status);
        assert_eq!(account.account.as_ref().unwrap().storage.len(), 3);
    }
}
