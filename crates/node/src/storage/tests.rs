use super::*;
use crate::TempoNode;
use alloy::signers::{SignerSync, local::PrivateKeySigner};
use reth_db_api::{cursor::DbDupCursorRO, transaction::DbTxMut};
use reth_primitives_traits::RecoveredBlock;
use reth_provider::{
    BlockWriter, ProviderFactory, RocksDBProviderFactory, StageCheckpointWriter,
    StaticFileProviderFactory, StorageSettingsCache,
    test_utils::create_test_provider_factory_with_node_types,
};
use reth_stages_types::StageCheckpoint;
use tempo_chainspec::spec::DEV;
use tempo_primitives::{
    AASigned, Block, BlockBody, TempoHeader, TempoSignature, TempoTransaction, TempoTxEnvelope,
};

#[test]
fn reads_derive_from_blocks_and_writes_remain_native() {
    let chain = DEV.clone();
    let factory = create_test_provider_factory_with_node_types::<TempoNode>(chain.clone());
    let signer = PrivateKeySigner::from_bytes(&B256::repeat_byte(1)).unwrap();
    let transaction = TempoTransaction {
        nonce_key: U256::MAX,
        valid_before: Some(1200.try_into().unwrap()),
        ..Default::default()
    };
    let signature = signer
        .sign_hash_sync(&transaction.signature_hash())
        .unwrap();
    let signed = AASigned::new_unhashed(transaction, TempoSignature::from(signature));
    let hash = signed
        .recover_signer_with_expiring_nonce_hash()
        .unwrap()
        .1
        .unwrap();
    let make_block = |number, timestamp, transactions: Vec<TempoTxEnvelope>, parent_hash| {
        let senders = vec![signer.address(); transactions.len()];
        RecoveredBlock::new_unhashed(
            Block {
                header: TempoHeader {
                    inner: alloy::consensus::Header {
                        number,
                        timestamp,
                        parent_hash,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                body: BlockBody {
                    transactions,
                    ..Default::default()
                },
            },
            senders,
        )
    };
    let rw = factory.provider_rw().unwrap();
    rw.insert_block(&make_block(0, 999, vec![], B256::ZERO))
        .unwrap();
    rw.insert_block(&make_block(1, 1000, vec![signed.into()], B256::ZERO))
        .unwrap();
    rw.save_stage_checkpoint(reth_stages_types::StageId::Finish, StageCheckpoint::new(1))
        .unwrap();
    let address = EXPIRING_NONCE_PRECOMPILE_ADDRESS;
    let manager = tempo_precompiles::expiring_nonce::ExpiringNonceManager::new();
    let slot = B256::from(manager.seen[hash].slot());
    let hashed_address = keccak256(address);
    let hashed_slot = keccak256(slot);
    let wrong = StorageEntry {
        key: hashed_slot,
        value: U256::from(99999),
    };
    rw.tx_ref()
        .put::<tables::HashedStorages>(hashed_address, wrong)
        .unwrap();
    let ghost = B256::repeat_byte(0xff);
    rw.tx_ref()
        .put::<tables::HashedStorages>(
            hashed_address,
            StorageEntry {
                key: ghost,
                value: U256::from(123),
            },
        )
        .unwrap();
    let other = B256::with_last_byte(9);
    rw.tx_ref()
        .put::<tables::HashedStorages>(other, wrong)
        .unwrap();
    rw.commit().unwrap();
    let db = TempoDatabase::new(
        factory.db_ref().clone(),
        chain,
        factory.static_file_provider().directory().to_owned(),
    );
    let tx = db.tx().unwrap();
    // A lazy database read can occur inside another precompile's storage scope.
    use tempo_precompiles::storage::{
        PrecompileStorageProvider, StorageCtx, hashmap::HashMapStorageProvider,
    };
    let mut outer = HashMapStorageProvider::new_with_spec(1, tempo_chainspec::TempoHardfork::T1C);
    outer
        .sstore(
            address,
            U256::from_be_slice(slot.as_slice()),
            U256::from(42),
        )
        .unwrap();
    let mut hashed = StorageCtx::enter(&mut outer, || {
        let mut cursor = tx.cursor_dup_read::<tables::HashedStorages>().unwrap();
        cursor
            .seek_by_key_subkey(hashed_address, hashed_slot)
            .unwrap();
        assert_eq!(
            StorageCtx
                .sload(address, U256::from_be_slice(slot.as_slice()))
                .unwrap(),
            U256::from(42)
        );
        cursor
    });
    assert_eq!(
        hashed
            .seek_by_key_subkey(hashed_address, hashed_slot)
            .unwrap()
            .unwrap()
            .value,
        U256::from(1200)
    );
    assert_eq!(
        hashed.seek_by_key_subkey(other, hashed_slot).unwrap(),
        Some(wrong)
    );
    let rows: Vec<_> = hashed
        .walk_dup(Some(hashed_address), None)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        hashed.seek_by_key_subkey(hashed_address, ghost).unwrap(),
        None
    );
    assert_eq!(rows.len(), 5); // seen, bucket, count, maximum, oldest
    assert_eq!(
        tx.get_by_key_subkey::<tables::HashedStorages>(hashed_address, hashed_slot)
            .unwrap(),
        Some(StorageEntry {
            key: hashed_slot,
            value: U256::from(1200)
        })
    );
    for missing in [B256::ZERO, ghost] {
        assert_eq!(
            tx.get_by_key_subkey::<tables::HashedStorages>(hashed_address, missing)
                .unwrap(),
            None
        );
    }
    assert_eq!(
        tx.get_by_key_subkey::<tables::HashedStorages>(other, hashed_slot)
            .unwrap(),
        Some(wrong)
    );
    assert_eq!(
        tx.get_by_key_subkey::<tables::HashedStorages>(other, B256::ZERO)
            .unwrap(),
        None
    );
    assert_eq!(
        tx.get::<tables::HashedStorages>(hashed_address).unwrap(),
        Some(rows[0].1)
    );
    assert_eq!(
        tx.get_by_encoded_key::<tables::HashedStorages>(&hashed_address.encode())
            .unwrap(),
        Some(rows[0].1)
    );
    assert_eq!(tx.entries::<tables::HashedStorages>().unwrap(), 6);
    let mut expected_hashed: Vec<_> = tx
        .slots()
        .unwrap()
        .iter()
        .map(|(&key, &value)| StorageEntry { key, value })
        .collect();
    expected_hashed.sort();
    let actual_hashed: Vec<_> = hashed
        .walk_dup(Some(keccak256(address)), None)
        .unwrap()
        .map(|row| row.unwrap().1)
        .collect();
    assert_eq!(actual_hashed, expected_hashed);
    let injected =
        ProviderFactory::<reth_ethereum::node::api::NodeTypesWithDBAdapter<TempoNode, _>>::new(
            db.clone(),
            db.chain.clone(),
            factory.static_file_provider(),
            factory.rocksdb_provider(),
            reth_ethereum::tasks::Runtime::test(),
        )
        .unwrap();
    let mut settings = injected.cached_storage_settings();
    settings.storage_v2 = true;
    injected.set_storage_settings_cache(settings);
    let state = injected.latest().unwrap();
    assert_eq!(
        state.storage(address, slot).unwrap(),
        Some(U256::from(1200))
    );
    assert_eq!(
        state.storage_root(address, Default::default()).unwrap(),
        reth_ethereum::trie::root::storage_root_unsorted(
            expected_hashed.iter().map(|entry| (entry.key, entry.value))
        )
    );
    // Native write transactions still see the intentionally incorrect persisted value.
    let native = db.tx_mut().unwrap();
    assert_eq!(
        native
            .get::<tables::HashedStorages>(hashed_address)
            .unwrap(),
        Some(wrong)
    );
    native.abort();
    // Readers at one checkpoint share one computation, even when first accessed concurrently.
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    let reader = db.tx().unwrap();
                    reader.snapshot().unwrap().clone()
                })
            })
            .collect();
        for handle in handles {
            assert!(Arc::ptr_eq(&handle.join().unwrap(), tx.snapshot().unwrap()));
        }
    });
    assert_eq!(db.cache.published.lock().unwrap().computations, 1);
    let lazy = db.tx().unwrap();
    // Advancing persistence must not change the already-open transaction's derived snapshot.
    injected.set_storage_settings_cache(factory.cached_storage_settings());
    let block = make_block(2, 1200, vec![], tx.snapshot().unwrap().hash);
    // An aborted persistence task must not publish its prepared successor.
    drop(
        db.prepare_persistence(vec![Arc::new(block.clone())])
            .unwrap()
            .unwrap(),
    );
    assert_eq!(db.cache.published.lock().unwrap().computations, 1);
    let preparation = db
        .prepare_persistence(vec![Arc::new(block.clone())])
        .unwrap()
        .unwrap();
    assert_eq!(
        db.tx().unwrap().slots().unwrap().get(&hashed_slot),
        Some(&U256::from(1200))
    );
    let rw = injected.provider_rw().unwrap();
    rw.insert_block(&block).unwrap();
    rw.save_stage_checkpoint(reth_stages_types::StageId::Finish, StageCheckpoint::new(2))
        .unwrap();
    rw.commit().unwrap();
    // A reader opened between commit and publication waits for the one worker.
    std::thread::scope(|scope| {
        let (opened, started) = std::sync::mpsc::channel();
        let db = &db;
        let reader = scope.spawn(move || {
            let next = db.tx().unwrap();
            opened.send(()).unwrap();
            next.snapshot().unwrap().clone()
        });
        started.recv().unwrap();
        assert_eq!(db.cache.published.lock().unwrap().computations, 1);
        preparation.finish();
        assert_eq!(reader.join().unwrap().number, 2);
    });
    assert_eq!(
        tx.slots().unwrap().get(&hashed_slot),
        Some(&U256::from(1200))
    );
    let next = db.tx().unwrap();
    assert!(!next.slots().unwrap().contains_key(&hashed_slot));
    assert_eq!(next.slots().unwrap().len(), 1); // only oldest cursor survives
    assert_eq!(db.cache.published.lock().unwrap().computations, 2);
    assert_eq!(db.cache.published.lock().unwrap().replayed_blocks, 2);
    let old_lease = Arc::downgrade(tx.snapshot().unwrap());
    drop(hashed);
    drop(state);
    drop(injected);
    drop(tx);
    // The untouched transaction is now the only old lease. Its first nonce read
    // must reuse that state, rather than reconstructing a discarded checkpoint.
    assert_eq!(
        lazy.slots().unwrap().get(&hashed_slot),
        Some(&U256::from(1200))
    );
    assert_eq!(db.cache.published.lock().unwrap().computations, 2);
    // Fresh transactions reuse the newly advanced state.
    assert!(Arc::ptr_eq(
        db.tx().unwrap().snapshot().unwrap(),
        next.snapshot().unwrap()
    ));
    drop(lazy);
    drop(next);
    assert!(old_lease.upgrade().is_none());
    // Replace the canonical chain at the same Finish height. A height-only cache
    // would incorrectly return the old snapshot instead of replaying this fork.
    let rw = factory.provider_rw().unwrap();
    rw.remove_blocks_above(0).unwrap();
    rw.save_stage_checkpoint(reth_stages_types::StageId::Finish, StageCheckpoint::new(0))
        .unwrap();
    rw.commit().unwrap();
    let rw = factory.provider_rw().unwrap();
    rw.insert_block(&make_block(1, 1300, vec![], B256::ZERO))
        .unwrap();
    rw.insert_block(&make_block(2, 1301, vec![], B256::ZERO))
        .unwrap();
    rw.save_stage_checkpoint(reth_stages_types::StageId::Finish, StageCheckpoint::new(2))
        .unwrap();
    rw.commit().unwrap();
    let fork = db.tx().unwrap();
    assert_eq!(fork.slots().unwrap().len(), 1);
    assert_eq!(db.cache.published.lock().unwrap().computations, 3);
    assert_eq!(db.cache.published.lock().unwrap().replayed_blocks, 4);
}

#[test]
fn storage_cursor_matches_native_traversal() {
    let factory = create_test_provider_factory_with_node_types::<TempoNode>(DEV.clone());
    let rw = factory.provider_rw().unwrap();
    for owner in [1, 3, 7] {
        for slot in [2, 4, 8] {
            rw.tx_ref()
                .put::<tables::HashedStorages>(
                    B256::with_last_byte(owner),
                    StorageEntry {
                        key: B256::with_last_byte(slot),
                        value: U256::from(slot),
                    },
                )
                .unwrap();
        }
    }
    rw.commit().unwrap();
    let native_tx = factory.db_ref().tx().unwrap();
    let wrapper = TempoDatabase::new(
        factory.db_ref().clone(),
        DEV.clone(),
        factory.static_file_provider().directory().to_owned(),
    );
    let virtual_tx = wrapper.tx().unwrap();
    let mut native = native_tx
        .cursor_dup_read::<tables::HashedStorages>()
        .unwrap();
    let mut virtual_cursor = virtual_tx
        .cursor_dup_read::<tables::HashedStorages>()
        .unwrap();
    virtual_cursor
        .seek_by_key_subkey(B256::with_last_byte(1), B256::with_last_byte(2))
        .unwrap();
    assert_eq!(
        wrapper.cache.published.lock().unwrap().computations,
        0,
        "unrelated storage must not reconstruct nonces"
    );
    macro_rules! same { ($method:ident($($arg:expr),*)) => { assert_eq!(virtual_cursor.$method($($arg),*).unwrap(), native.$method($($arg),*).unwrap(), stringify!($method)); } }
    same!(first());
    same!(next());
    same!(next_dup());
    same!(next_dup());
    same!(current());
    same!(prev_dup());
    same!(last_dup());
    same!(next_no_dup());
    same!(prev());
    same!(last());
    same!(prev());
    same!(last());
    same!(next());
    for owner in [0, 1, 2, 3, 7, 9] {
        same!(seek(B256::with_last_byte(owner)));
        same!(seek_exact(B256::with_last_byte(owner)));
        for slot in [0, 2, 3, 4, 8, 9] {
            same!(seek_by_key_subkey(
                B256::with_last_byte(owner),
                B256::with_last_byte(slot)
            ));
        }
    }
    for owner in [0, 2, 9] {
        assert!(
            virtual_cursor
                .walk_dup(Some(B256::with_last_byte(owner)), None)
                .unwrap()
                .next()
                .is_none()
        );
    }
    assert!(
        virtual_cursor
            .walk_dup(Some(B256::with_last_byte(1)), Some(B256::with_last_byte(9)))
            .unwrap()
            .next()
            .is_none()
    );
    let forward: Vec<_> = virtual_cursor
        .walk(None)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let backward: Vec<_> = virtual_cursor
        .walk_back(None)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(forward, backward.into_iter().rev().collect::<Vec<_>>());
    let range = B256::with_last_byte(1)..B256::with_last_byte(7);
    assert_eq!(
        virtual_cursor
            .walk_range(range.clone())
            .unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>(),
        native
            .walk_range(range)
            .unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "expiring-nonce-no-persistence")]
#[test]
fn replay_writes_are_discarded_without_affecting_other_addresses() {
    use reth_db_api::cursor::{DbCursorRW, DbDupCursorRW};
    use reth_ethereum::trie::{Nibbles, PackedStorageTrieEntry, StorageTrieEntry};

    fn check<T: DupSort<Key = B256>>(value: T::Value)
    where
        T::Value: PartialEq + Clone,
    {
        let factory = create_test_provider_factory_with_node_types::<TempoNode>(DEV.clone());
        let db = TempoDatabase::new(
            factory.db_ref().clone(),
            DEV.clone(),
            factory.static_file_provider().directory().to_owned(),
        );
        let address = keccak256(EXPIRING_NONCE_PRECOMPILE_ADDRESS);
        let tx = db.tx_mut().unwrap();
        tx.put::<T>(address, value.clone()).unwrap();
        tx.append::<T>(address, value.clone()).unwrap();
        let mut cursor = tx.cursor_dup_write::<T>().unwrap();
        cursor.upsert(address, &value).unwrap();
        cursor.insert(address, &value).unwrap();
        cursor.append(address, &value).unwrap();
        cursor.append_dup(address, value.clone()).unwrap();
        tx.cursor_read::<T>()
            .unwrap()
            .upsert(address, &value)
            .unwrap();
        tx.cursor_dup_read::<T>()
            .unwrap()
            .append_dup(address, value.clone())
            .unwrap();
        assert_eq!(tx.get::<T>(address).unwrap(), None);
        assert_eq!(tx.entries::<T>().unwrap(), 0);

        let keys: Vec<_> = (1..=6).map(B256::with_last_byte).collect();
        tx.put::<T>(keys[0], value.clone()).unwrap();
        tx.append::<T>(keys[1], value.clone()).unwrap();
        cursor.upsert(keys[2], &value).unwrap();
        cursor.insert(keys[3], &value).unwrap();
        cursor.append(keys[4], &value).unwrap();
        cursor.append_dup(keys[5], value.clone()).unwrap();
        tx.put::<tables::CanonicalHeaders>(1, address).unwrap();
        drop(cursor);
        tx.commit().unwrap();
        let native = factory.db_ref().tx().unwrap();
        assert_eq!(native.get::<T>(address).unwrap(), None);
        assert_eq!(native.entries::<T>().unwrap(), 6);
        for key in &keys {
            assert_eq!(native.get::<T>(*key).unwrap(), Some(value.clone()));
        }
        assert_eq!(
            native.get::<tables::CanonicalHeaders>(1).unwrap(),
            Some(address)
        );
        drop(native);

        // Even deletions and table clears must leave a pre-existing filtered row untouched.
        let native = factory.db_ref().tx_mut().unwrap();
        native.put::<T>(address, value.clone()).unwrap();
        native.commit().unwrap();
        let tx = db.tx_mut().unwrap();
        assert!(!tx.delete::<T>(address, None).unwrap());
        assert!(tx.delete::<T>(keys[0], None).unwrap());
        let mut cursor = tx.cursor_dup_write::<T>().unwrap();
        cursor.seek_exact(address).unwrap();
        cursor.delete_current().unwrap();
        cursor.delete_current_duplicates().unwrap();
        cursor.seek_exact(keys[1]).unwrap();
        cursor.delete_current().unwrap();
        cursor.seek_exact(keys[2]).unwrap();
        cursor.delete_current_duplicates().unwrap();
        assert_eq!(tx.entries::<T>().unwrap(), 4);
        tx.clear::<T>().unwrap();
        tx.clear::<tables::CanonicalHeaders>().unwrap();
        drop(cursor);
        tx.commit().unwrap();
        let native = factory.db_ref().tx().unwrap();
        assert_eq!(native.entries::<T>().unwrap(), 1);
        assert_eq!(native.get::<T>(address).unwrap(), Some(value));
        assert_eq!(native.entries::<tables::CanonicalHeaders>().unwrap(), 0);
    }

    check::<tables::HashedStorages>(StorageEntry {
        key: B256::ZERO,
        value: U256::from(1),
    });
    check::<tables::StoragesTrie>(StorageTrieEntry {
        nibbles: Nibbles::default().into(),
        node: Default::default(),
    });
    check::<tables::PackedStoragesTrie>(PackedStorageTrieEntry {
        nibbles: Nibbles::default().into(),
        node: Default::default(),
    });
}

#[test]
fn merged_cursor_matches_native_storage() {
    let factory = create_test_provider_factory_with_node_types::<TempoNode>(DEV.clone());
    let target = keccak256(EXPIRING_NONCE_PRECOMPILE_ADDRESS);
    let owners = [B256::ZERO, target, B256::repeat_byte(0xff)];
    let rw = factory.provider_rw().unwrap();
    let slots: Slots = [2, 4, 8]
        .into_iter()
        .map(|slot| (B256::with_last_byte(slot), U256::from(slot)))
        .collect();
    for owner in owners {
        for (&key, &value) in &slots {
            rw.tx_ref()
                .put::<tables::HashedStorages>(owner, StorageEntry { key, value })
                .unwrap();
        }
    }
    rw.commit().unwrap();
    let tx = factory.db_ref().tx().unwrap();
    let snapshot = Arc::new(Snapshot {
        number: 0,
        hash: B256::ZERO,
        slots,
        deployed: true,
    });
    let mut merged = Cursor::<tables::HashedStorages, _>::new(
        tx.cursor_dup_read().unwrap(),
        Some(Arc::new(View {
            source: Source::new(&tx, 0).unwrap(),
            chain: DEV.clone(),
            cache: Arc::default(),
            static_files: factory.static_file_provider().directory().to_owned(),
            snapshot: OnceLock::from(Ok(snapshot)),
        })),
    );
    let mut native = tx.cursor_dup_read::<tables::HashedStorages>().unwrap();
    assert_eq!(
        merged
            .walk(None)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        native
            .walk(None)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    );
    assert_eq!(
        merged
            .walk_back(None)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        native
            .walk_back(None)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    );
    macro_rules! same { ($method:ident($($arg:expr),*)) => { assert_eq!(merged.$method($($arg),*).unwrap(), native.$method($($arg),*).unwrap(), stringify!($method)); } }
    for owner in owners {
        same!(seek(owner));
        same!(next_dup());
        same!(prev_dup());
        same!(last_dup());
        same!(next_no_dup());
        same!(seek(owner));
        same!(prev());
        for slot in [0, 2, 3, 4, 8, 9] {
            same!(seek_by_key_subkey(owner, B256::with_last_byte(slot)));
        }
    }
    same!(seek_exact(target));
    same!(next());
    same!(next());
    same!(next());
    same!(prev());
    same!(seek(B256::with_last_byte(1)));
}

#[test]
fn concurrent_cold_readers_compute_once() {
    let factory = create_test_provider_factory_with_node_types::<TempoNode>(DEV.clone());
    let db = TempoDatabase::new(
        factory.db_ref().clone(),
        DEV.clone(),
        factory.static_file_provider().directory().to_owned(),
    );
    let barrier = std::sync::Barrier::new(8);
    let states = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    let tx = db.tx().unwrap();
                    barrier.wait();
                    tx.snapshot().unwrap().clone()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(db.cache.published.lock().unwrap().computations, 1);
    for state in &states {
        assert!(Arc::ptr_eq(state, &states[0]));
    }
}

#[test]
fn published_reads_do_not_wait_for_computation() {
    let factory = create_test_provider_factory_with_node_types::<TempoNode>(DEV.clone());
    let db = TempoDatabase::new(
        factory.db_ref().clone(),
        DEV.clone(),
        factory.static_file_provider().directory().to_owned(),
    );
    let first = db.tx().unwrap().snapshot().unwrap().clone();
    let guard = db.cache.computation.lock().unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            send.send(db.tx().unwrap().snapshot().unwrap().clone())
                .unwrap()
        });
        let result = receive.recv_timeout(std::time::Duration::from_secs(2));
        drop(guard);
        assert!(Arc::ptr_eq(
            &result.expect("published reads blocked behind writer"),
            &first
        ));
    });
}
