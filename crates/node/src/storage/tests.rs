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
    let make_block = |number, timestamp, transactions: Vec<TempoTxEnvelope>| {
        let senders = vec![signer.address(); transactions.len()];
        RecoveredBlock::new_unhashed(
            Block {
                header: TempoHeader {
                    inner: alloy::consensus::Header {
                        number,
                        timestamp,
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
    rw.insert_block(&make_block(0, 999, vec![])).unwrap();
    rw.insert_block(&make_block(1, 1000, vec![signed.into()]))
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
        let cursor = tx.cursor_dup_read::<tables::HashedStorages>().unwrap();
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
        .map(|(&key, &value)| StorageEntry {
            key: keccak256(key),
            value,
        })
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
    let lazy = db.tx().unwrap();
    // Advancing persistence must not change the already-open transaction's derived snapshot.
    let rw = factory.provider_rw().unwrap();
    rw.insert_block(&make_block(2, 1200, vec![])).unwrap();
    rw.save_stage_checkpoint(reth_stages_types::StageId::Finish, StageCheckpoint::new(2))
        .unwrap();
    rw.commit().unwrap();
    assert_eq!(tx.slots().unwrap().get(&slot), Some(&U256::from(1200)));
    assert_eq!(lazy.slots().unwrap().get(&slot), Some(&U256::from(1200)));
    let next = db.tx().unwrap();
    assert!(!next.slots().unwrap().contains_key(&slot));
    assert_eq!(next.slots().unwrap().len(), 1); // only oldest cursor survives
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
