mod ceremony;
pub use ceremony::CeremonyStore;
mod dkg_outcome;
pub use dkg_outcome::DkgOutcomeStore;
mod epoch;
pub use epoch::DkgEpochStore;
mod validators;
pub use validators::ValidatorsStore;

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use alloy_primitives::keccak256;
use async_lock::RwLock;
use bytes::Bytes;
use commonware_codec::{EncodeSize, Read, Write as CodecWrite};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::metadata::Metadata;
use commonware_utils::sequence::FixedBytes;

type B256 = FixedBytes<32>;

/// Key used to store the node version that last wrote to the database.
const NODE_VERSION_KEY: &str = "_node_version";

/// A database wrapper around `Metadata<B256, Bytes>` that provides transactional operations.
///
/// The underlying [`Metadata`] storage always keeps all data in memory and persists
/// it to disk during commit/sync operations.
pub struct MetadataDatabase<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    /// The underlying metadata store.
    inner: Arc<RwLock<Metadata<TContext, B256, Bytes>>>,
    /// Atomic flag to ensure only one read-write transaction is active at a time.
    tx_active: Arc<AtomicBool>,
}

impl<TContext> MetadataDatabase<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    /// Create a new database wrapping the given metadata store.
    pub fn new(inner: Metadata<TContext, B256, Bytes>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(inner)),
            tx_active: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Begin a new read-write transaction.
    ///
    /// Returns an error if a read-write transaction is already active.
    /// Only one read-write transaction can be active at a time.
    pub fn read_write(&self) -> Result<Tx<TContext>, eyre::Error> {
        if self
            .tx_active
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(eyre::eyre!(
                "cannot create transaction: another read-write transaction is already active"
            ));
        }

        Ok(Tx::new(self.inner.clone(), self.tx_active.clone()))
    }
}

/// A read-write transaction that buffers writes to a `Metadata<B256, Bytes>` store.
///
/// This transaction provides ACID-like semantics by buffering all operations in memory
/// and applying them atomically when `commit()` is called.
///
/// # Features
/// - **Multiple value types**: Serialize different types to the same store
/// - **Read-through cache**: Reads check buffered writes before hitting storage
/// - **Deletions**: Support for removing entries via `remove()`
/// - **Atomic commit**: Single `commit()` call applies all changes
///
/// # Example
/// ```ignore
/// let mut tx = db.tx();
/// tx.insert("epoch", epoch_state)?;
/// tx.insert("ceremony_0", ceremony_state)?;
/// tx.remove("old_data");
/// tx.commit().await?;  // All changes applied atomically
/// ```
pub struct Tx<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    /// Arc to the underlying metadata store.
    /// The lock is acquired only during `commit()` to apply all buffered changes.
    store: Arc<RwLock<Metadata<TContext, B256, Bytes>>>,

    /// Flag indicating whether a read-write transaction is active.
    /// The flag is set to false when the transaction is committed or dropped.
    write_lock: Arc<AtomicBool>,

    /// In-memory write buffer that accumulates all operations before commit.
    /// - Key: `B256`
    /// - Value: `Some(Bytes)` for insert/update, `None` for delete
    ///
    /// This map provides both write buffering and serves as a read cache,
    /// ensuring that reads within a transaction see uncommitted writes.
    writes: HashMap<B256, Option<Bytes>>,
}

impl<TContext> Tx<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    /// Create a new transaction over the given store.
    fn new(
        store: Arc<RwLock<Metadata<TContext, B256, Bytes>>>,
        write_lock: Arc<AtomicBool>,
    ) -> Self {
        Self {
            store,
            write_lock,
            writes: HashMap::new(),
        }
    }

    /// Get raw bytes from the store without deserialization.
    async fn get_raw<K>(&mut self, key: K) -> Result<Option<Bytes>, eyre::Error>
    where
        K: AsRef<[u8]>,
    {
        let key_hash = key_to_b256(key.as_ref());

        // Check pending writes first
        if let Some(value_bytes_opt) = self.writes.get(&key_hash) {
            return Ok(value_bytes_opt.clone());
        }

        let store = self.store.read().await;
        Ok(store.get(&key_hash).cloned())
    }

    /// Get a value from the store, deserializing it.
    ///
    /// This checks pending writes first, then falls back to the store.
    pub async fn get<K, V>(&mut self, key: K) -> Result<Option<V>, eyre::Error>
    where
        K: AsRef<[u8]>,
        V: Read<Cfg = ()>,
    {
        let Some(value_bytes) = self.get_raw(key).await? else {
            return Ok(None);
        };

        Ok(Some(deserialize_from_bytes::<V>(&value_bytes)?))
    }

    /// Insert a key-value pair into the transaction's write buffer.
    ///
    /// This does not immediately write to the store.
    /// Call `commit()` to apply all buffered writes.
    pub fn insert<K, V>(&mut self, key: K, value: V) -> Result<(), eyre::Error>
    where
        K: AsRef<[u8]>,
        V: CodecWrite + EncodeSize,
    {
        let key_hash = key_to_b256(key.as_ref());
        let value_bytes = serialize_to_bytes(&value)?;
        self.writes.insert(key_hash, Some(value_bytes));
        Ok(())
    }

    /// Remove a key from the transaction's write buffer.
    ///
    /// This marks the key for deletion. The actual removal happens when `commit()` is called.
    pub fn remove<K>(&mut self, key: K)
    where
        K: AsRef<[u8]>,
    {
        let key_hash = key_to_b256(key.as_ref());
        self.writes.insert(key_hash, None);
    }

    /// Get the node version that last wrote to this database.
    ///
    /// Returns None if no version has been written yet (new database).
    pub async fn get_node_version(&mut self) -> Result<Option<String>, eyre::Error> {
        Ok(self
            .get_raw(NODE_VERSION_KEY)
            .await?
            .and_then(|bytes| String::from_utf8(bytes.to_vec()).ok()))
    }

    /// Set the current node version in the database.
    ///
    /// This should be called when the database schema is initialized or migrated
    /// to track which node version last modified the database.
    pub fn set_node_version(&mut self, version: String) -> Result<(), eyre::Error> {
        self.insert(NODE_VERSION_KEY, version.into_bytes())
    }

    /// Commit all buffered writes to the store and sync.
    pub async fn commit(mut self) -> Result<(), eyre::Error> {
        let mut store = self.store.write().await;

        for (key, value_opt) in self.writes.drain() {
            match value_opt {
                Some(value) => {
                    store.put(key, value);
                }
                None => {
                    store.remove(&key);
                }
            }
        }

        store
            .sync()
            .await
            .map_err(|e| eyre::eyre!("sync failed: {}", e))?;

        Ok(())
    }
}

impl<TContext> Drop for Tx<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    fn drop(&mut self) {
        self.write_lock.store(false, Ordering::SeqCst);
    }
}

/// Convert key to B256.
///
/// Zero-pads if key is <= 32 bytes, hashes with [`keccak256`] if > 32 bytes.
fn key_to_b256(key: &[u8]) -> B256 {
    if key.len() <= 32 {
        let mut bytes = [0u8; 32];
        bytes[..key.len()].copy_from_slice(key);
        B256::from(bytes)
    } else {
        let hash = keccak256(key);
        let hash_bytes: &[u8; 32] = hash.as_ref();
        B256::from(*hash_bytes)
    }
}

/// Serialize a value to Bytes.
fn serialize_to_bytes<T: CodecWrite + EncodeSize>(value: &T) -> Result<Bytes, eyre::Error> {
    let size = value.encode_size();
    let mut buf = Vec::with_capacity(size);
    value.write(&mut buf);
    Ok(Bytes::from(buf))
}

/// Deserialize a value from Bytes.
fn deserialize_from_bytes<T>(bytes: &Bytes) -> Result<T, eyre::Error>
where
    T: Read<Cfg = ()>,
{
    let slice: &[u8] = bytes.as_ref();
    let mut cursor: &[u8] = slice;
    T::read_cfg(&mut cursor, &()).map_err(|e| eyre::eyre!("deserialization failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{
        ContextCell, Runner,
        tokio::{self, Context},
    };

    #[test]
    fn test_insert_get_remove_commit() {
        let runtime_config = tokio::Config::default();
        let runner = tokio::Runner::new(runtime_config);

        runner
            .start(|context: Context| async move {
                let context = ContextCell::new(context);

                let metadata: Metadata<ContextCell<Context>, B256, Bytes> = Metadata::init(
                    context.with_label("test"),
                    commonware_storage::metadata::Config {
                        partition: "test_ops".into(),
                        codec_config: commonware_codec::RangeCfg::from(0..=usize::MAX),
                    },
                )
                .await
                .unwrap();

                let db = MetadataDatabase::new(metadata);
                let key1_hash = key_to_b256("key1".as_bytes());
                let key2_hash = key_to_b256("key2".as_bytes());

                // Insert and verify in transaction buffer before commit
                let mut tx = db.read_write().unwrap();
                tx.insert("key1", 100u64).unwrap();
                tx.insert("key2", 200u64).unwrap();
                assert_eq!(tx.get::<_, u64>(&"key1").await.unwrap(), Some(100));
                assert_eq!(tx.get::<_, u64>(&"key2").await.unwrap(), Some(200));
                tx.commit().await.unwrap();

                // Verify persisted to underlying store
                {
                    let store = db.inner.read().await;
                    assert!(store.get(&key1_hash).is_some());
                    assert!(store.get(&key2_hash).is_some());
                }

                // Test get reads from underlying store after commit
                let mut tx = db.read_write().unwrap();
                assert_eq!(tx.get::<_, u64>(&"key1").await.unwrap(), Some(100));
                assert_eq!(tx.get::<_, u64>(&"key2").await.unwrap(), Some(200));

                // Remove and verify in transaction buffer before commit
                tx.remove("key1");
                assert_eq!(tx.get::<_, u64>(&"key1").await.unwrap(), None);
                assert_eq!(tx.get::<_, u64>(&"key2").await.unwrap(), Some(200));
                tx.commit().await.unwrap();

                // Verify removal persisted to underlying store
                {
                    let store = db.inner.read().await;
                    assert!(store.get(&key1_hash).is_none());
                    assert!(store.get(&key2_hash).is_some());
                }

                Ok::<(), eyre::Error>(())
            })
            .expect("test should succeed");
    }

    #[test]
    fn test_transaction_exclusivity() {
        let runtime_config = tokio::Config::default();
        let runner = tokio::Runner::new(runtime_config);

        runner
            .start(|context: Context| async move {
                let context = ContextCell::new(context);

                let metadata: Metadata<ContextCell<Context>, B256, Bytes> = Metadata::init(
                    context.with_label("test"),
                    commonware_storage::metadata::Config {
                        partition: "test_excl".into(),
                        codec_config: commonware_codec::RangeCfg::from(0..=usize::MAX),
                    },
                )
                .await
                .unwrap();

                let db = MetadataDatabase::new(metadata);

                // Only one read-write transaction at a time
                let tx1 = db.read_write();
                assert!(tx1.is_ok());
                let tx2 = db.read_write();
                assert!(tx2.is_err());
                drop(tx1);
                assert!(db.read_write().is_ok());

                Ok::<(), eyre::Error>(())
            })
            .expect("test should succeed");
    }
}
