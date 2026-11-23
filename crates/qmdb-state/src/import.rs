//! Builds the QMDB state of the snapshot block from the hashed state tables.
//!
//! Every node must produce the same operation history, so the import is fully determined by the
//! state at the snapshot block. Each database takes its keys in ascending order, in chunks of
//! exactly [`CHUNK_KEYS`] keys (the last one shorter): first every account chunk, then every slot
//! chunk. The last slot chunk, empty when there are no slots, commits both databases with the
//! snapshot's block number as metadata.

use std::path::PathBuf;

use alloy_primitives::B256;
use reth_codecs::{Compress, Decompress, DecompressError};
use reth_db_api::DatabaseError;
use reth_etl::Collector;
use reth_primitives_traits::Account;
use reth_trie::hashed_cursor::{HashedCursor as _, HashedCursorFactory};
use tracing::info;

use crate::{
    Store,
    layout::{self, AccountRecord, AccountValue, Key, SLOT_LEN, SlotValue, Write, Writes},
    store,
};

/// Keys per import chunk. Part of the consensus definition of the migrated root.
pub const CHUNK_KEYS: usize = 1 << 20;

/// Memory the sort buffers before spilling to disk.
const SORT_BUFFER_BYTES: usize = 1 << 30;

/// Error of an import.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Reading the hashed state failed.
    #[error("reading the hashed state failed")]
    Database(#[from] DatabaseError),
    /// An account could not be encoded.
    #[error("account {hashed_address} could not be encoded")]
    Layout {
        /// Hashed address of the account.
        hashed_address: B256,
        /// Why it could not be encoded.
        #[source]
        source: layout::Error,
    },
    /// Sorting the keys failed.
    #[error("sorting the keys on disk failed")]
    Sort(#[from] std::io::Error),
    /// The store refused a chunk.
    #[error("the store refused an import chunk")]
    Store(#[from] store::Error),
}

/// Imports the state that `cursors` read into `store` as the state of block `snapshot` with hash
/// `snapshot_hash`, and returns the number of keys imported.
///
/// `cursors` must read the state at the end of block `snapshot`: on a node past it, the hashed
/// tables overlaid with the reverts of the later blocks. `sort_dir` holds the temporary files of
/// the sort.
pub fn import(
    cursors: &impl HashedCursorFactory,
    store: &Store,
    snapshot: u64,
    snapshot_hash: B256,
    sort_dir: Option<PathBuf>,
) -> Result<u64, Error> {
    // Account keys are the hashed addresses, so the cursor yields them in key order. Slot keys
    // hash the address and slot together and need sorting.
    let mut slots = Collector::<B256, SortValue>::new(SORT_BUFFER_BYTES, sort_dir);
    let mut chunk = Vec::with_capacity(CHUNK_KEYS);
    let mut account_keys = 0u64;
    let mut accounts = cursors.hashed_account_cursor()?;
    let mut entry = accounts.seek(B256::ZERO)?;
    while let Some((hashed_address, account)) = entry {
        let value = account_value(&account).map_err(|source| Error::Layout {
            hashed_address,
            source,
        })?;
        chunk.push(Write {
            key: layout::account_key(hashed_address),
            value: Some(value),
        });
        account_keys += 1;
        if chunk.len() == CHUNK_KEYS {
            store.import_chunk(
                Writes {
                    accounts: std::mem::take(&mut chunk),
                    slots: Vec::new(),
                },
                None,
            )?;
        }

        let mut storage = cursors.hashed_storage_cursor(hashed_address)?;
        let mut slot = storage.seek(B256::ZERO)?;
        while let Some((hashed_slot, value)) = slot {
            slots.insert(
                key_to_b256(layout::slot_key(hashed_address, hashed_slot)),
                SortValue(layout::slot_value(value)),
            )?;
            slot = storage.next()?;
        }
        entry = accounts.next()?;
    }
    if !chunk.is_empty() {
        store.import_chunk(
            Writes {
                accounts: chunk,
                slots: Vec::new(),
            },
            None,
        )?;
    }

    let slot_keys = slots.len() as u64;
    info!(
        accounts = account_keys,
        slots = slot_keys,
        snapshot,
        "importing slots into QMDB"
    );
    let end = (snapshot, snapshot_hash);
    let mut chunk = Vec::with_capacity(CHUNK_KEYS.min(slots.len()));
    let mut entries = slots.iter()?.peekable();
    while let Some(entry) = entries.next() {
        let (key, value) = entry?;
        chunk.push(Write {
            key: Key::new(
                <[u8; 32]>::try_from(key.as_slice())
                    .expect("ETL returns the 32-byte keys it was given"),
            ),
            value: Some(
                SortValue::decompress(&value)
                    .expect("ETL returns the values it was given")
                    .0,
            ),
        });
        let last = entries.peek().is_none();
        if chunk.len() == CHUNK_KEYS || last {
            store.import_chunk(
                Writes {
                    accounts: Vec::new(),
                    slots: std::mem::take(&mut chunk),
                },
                last.then_some(end),
            )?;
        }
    }
    if slot_keys == 0 {
        store.import_chunk(Writes::default(), Some(end))?;
    }
    Ok(account_keys + slot_keys)
}

fn account_value(account: &Account) -> Result<AccountValue, layout::Error> {
    AccountRecord::new(
        account.nonce,
        account.balance,
        account.bytecode_hash,
        account.extension.as_ref(),
    )
    .map(|record| record.encode())
}

fn key_to_b256(key: Key) -> B256 {
    B256::from_slice(key.as_ref())
}

/// A [`SlotValue`] stored raw in the sort's temporary files.
#[derive(Debug)]
struct SortValue(SlotValue);

impl Compress for SortValue {
    type Compressed = Vec<u8>;

    fn compress_to_buf<B: bytes::BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        buf.put_slice(self.0.as_ref());
    }
}

impl Decompress for SortValue {
    fn decompress(value: &[u8]) -> Result<Self, DecompressError> {
        let bytes = <[u8; SLOT_LEN]>::try_from(value)
            .map_err(|_| DecompressError::new(SortValueLength(value.len())))?;
        Ok(Self(SlotValue::new(bytes)))
    }
}

/// The ETL requires serializable values; the sort only ever compresses them.
impl serde::Serialize for SortValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0.as_ref())
    }
}

/// A sort file held a value of the wrong length.
#[derive(Debug, thiserror::Error)]
#[error("sorted value of {0} bytes, expected {SLOT_LEN}")]
struct SortValueLength(usize);

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{U256, keccak256};
    use reth_trie::{
        HashedPostState, HashedStorage,
        hashed_cursor::{HashedPostStateCursorFactory, noop::NoopHashedCursorFactory},
    };
    use std::num::NonZeroUsize;

    fn open(dir: &std::path::Path) -> Store {
        Store::open(store::Config {
            directory: dir.to_path_buf(),
            threads: NonZeroUsize::new(2).unwrap(),
            page_cache_pages: NonZeroUsize::new(64).unwrap(),
            max_pending: NonZeroUsize::new(8).unwrap(),
        })
        .unwrap()
    }

    fn state() -> HashedPostState {
        let mut state = HashedPostState::default();
        for i in 0..50u64 {
            let hashed_address = keccak256(i.to_be_bytes());
            state.accounts.insert(
                hashed_address,
                Some(Account {
                    nonce: i,
                    balance: U256::ZERO,
                    bytecode_hash: None,
                    ..Default::default()
                }),
            );
            let storage = HashedStorage::from_iter(
                (0..i % 4).map(|slot| (keccak256(slot.to_be_bytes()), U256::from(slot + 1))),
            );
            state.storages.insert(hashed_address, storage);
        }
        state
    }

    #[test]
    fn import_is_deterministic_and_sets_the_snapshot() {
        let sorted = state().into_sorted();
        let cursors =
            HashedPostStateCursorFactory::new(NoopHashedCursorFactory::default(), &sorted);
        let roots: Vec<_> = (0..2)
            .map(|_| {
                let dir = tempfile::tempdir().unwrap();
                let store = open(dir.path());
                // 50 accounts plus `i % 4` slots each: 12 * (0 + 1 + 2 + 3) + 0 + 1.
                assert_eq!(
                    import(
                        &cursors,
                        &store,
                        7,
                        B256::repeat_byte(7),
                        Some(dir.path().join("sort"))
                    )
                    .unwrap(),
                    123
                );
                let status = store.status().unwrap();
                assert_eq!(status.applied, Some(7));
                assert_eq!(status.base, Some(B256::repeat_byte(7)));
                status.root
            })
            .collect();
        assert_eq!(roots[0], roots[1]);
    }

    #[test]
    fn empty_state_still_commits_the_snapshot() {
        let sorted = HashedPostState::default().into_sorted();
        let cursors =
            HashedPostStateCursorFactory::new(NoopHashedCursorFactory::default(), &sorted);
        let dir = tempfile::tempdir().unwrap();
        let store = open(dir.path());
        assert_eq!(
            import(&cursors, &store, 3, B256::repeat_byte(3), None).unwrap(),
            0
        );
        assert_eq!(store.status().unwrap().applied, Some(3));
    }

    #[test]
    fn rejects_a_malformed_account_extension() {
        let mut state = HashedPostState::default();
        let hashed_address = keccak256([1]);
        state.accounts.insert(
            hashed_address,
            Some(Account {
                extension: vec![9u8; 3].into(),
                ..Default::default()
            }),
        );
        let sorted = state.into_sorted();
        let cursors =
            HashedPostStateCursorFactory::new(NoopHashedCursorFactory::default(), &sorted);
        let dir = tempfile::tempdir().unwrap();
        let store = open(dir.path());
        assert!(matches!(
            import(&cursors, &store, 0, B256::ZERO, None),
            Err(Error::Layout { hashed_address: h, source: layout::Error::InvalidExtension { len: 3, tag: Some(9) } }) if h == hashed_address
        ));
    }
}
