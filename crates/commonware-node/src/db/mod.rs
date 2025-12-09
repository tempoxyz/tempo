mod ceremony;
pub use ceremony::CeremonyStore;
mod dkg_outcome;
pub use dkg_outcome::DkgOutcomeStore;
mod epoch;
pub use epoch::DkgEpochStore;
mod validators;
pub use validators::ValidatorsStore;

use eyre::WrapErr;
use std::{any::Any, collections::HashMap, sync::Arc};

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

/// Inner state of the metadata database.
pub struct MetadataDatabaseInner<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    /// The underlying metadata store.
    pub store: Metadata<TContext, B256, Bytes>,
    /// Cache to avoid repeated deserialization.
    pub cache: HashMap<B256, Box<dyn CachedValue>>,
}

/// A database wrapper around `Metadata<B256, Bytes>` that provides transactional operations.
///
/// The underlying [`Metadata`] storage always keeps all data in memory and persists
/// it to disk during commit/sync operations.
#[derive(Clone)]
pub struct MetadataDatabase<TContext>(pub Arc<RwLock<MetadataDatabaseInner<TContext>>>)
where
    TContext: Clock + Metrics + Storage;

impl<TContext> MetadataDatabase<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    /// Create a new database wrapping the given metadata store.
    pub fn new(store: Metadata<TContext, B256, Bytes>) -> Self {
        Self(Arc::new(RwLock::new(MetadataDatabaseInner {
            store,
            cache: HashMap::new(),
        })))
    }

    /// Get a value from cache or storage.
    ///
    /// If the value exists in storage but not in cache, it will be deserialized
    /// and added to the cache for future access.
    pub async fn get<K, V>(&self, key: K) -> Result<Option<V>, eyre::Error>
    where
        K: AsRef<[u8]>,
        V: Read<Cfg = ()> + CodecWrite + EncodeSize + Clone + Send + Sync + 'static,
    {
        let key_hash = key_to_b256(key.as_ref());

        // Try read lock first for cache hit
        let inner = self.0.read().await;
        if let Some(cached) = inner.cache.get(&key_hash) {
            return match cached.as_any().downcast_ref::<V>() {
                Some(value) => Ok(Some(value.clone())),
                None => Err(eyre::eyre!(
                    "type mismatch: cached value cannot be downcast to requested type"
                )),
            };
        }

        // Check if exists in storage
        let Some(value_bytes) = inner.store.get(&key_hash).cloned() else {
            return Ok(None);
        };
        let value: V = deserialize_from_bytes(&value_bytes)?;
        drop(inner);

        // Upgrade to write lock to cache the value
        let mut inner = self.0.write().await;
        // Check again - another task may have cached it while we were waiting
        inner
            .cache
            .entry(key_hash)
            .or_insert_with(|| Box::new(value.clone()) as Box<dyn CachedValue>);

        Ok(Some(value))
    }

    /// Get raw bytes from storage without deserialization or caching.
    pub async fn get_raw<K>(&self, key: K) -> Option<Bytes>
    where
        K: AsRef<[u8]>,
    {
        let key_hash = key_to_b256(key.as_ref());
        let inner = self.0.read().await;
        inner.store.get(&key_hash).cloned()
    }

    /// Begin a new read-write transaction.
    pub fn read_write(&self) -> Tx<TContext> {
        Tx::new(self.clone())
    }
}

/// A read-write transaction that buffers writes to a `Metadata<B256, Bytes>` store.
///
/// This transaction provides ACID-like semantics by buffering all operations in memory
/// and applying them atomically when `commit()` is called.
///
/// # Features
/// - **Multiple value types**: Serialize different types to the same store
/// - **Read-through**: Reads check buffered writes before hitting cache/storage
/// - **Deletions**: Support for removing entries via `remove()`
/// - **Atomic commit**: Single `commit()` call applies all changes to both cache and storage.
///
/// # Example
/// ```ignore
/// let mut tx = db.read_write();
/// tx.insert("epoch", epoch_state);
/// tx.insert("ceremony_0", ceremony_state);
/// tx.remove("old_data");
/// tx.commit().await?;  // All changes serialized and applied atomically
/// ```
pub struct Tx<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    /// Reference to the database.
    db: MetadataDatabase<TContext>,

    /// In-memory write buffer that accumulates all operations before commit.
    /// - Key: `B256`
    /// - Value: `Some(Bytes)` for insert/update, `None` for delete
    ///
    /// This map provides both write buffering and serves as a read cache,
    /// ensuring that reads within a transaction see uncommitted writes.
    ///
    /// On commit, these are serialized to storage and merged into the shared cache.
    writes: HashMap<B256, Option<Box<dyn CachedValue>>>,
}

impl<TContext> Tx<TContext>
where
    TContext: Clock + Metrics + Storage,
{
    /// Create a new transaction over the given database.
    fn new(db: MetadataDatabase<TContext>) -> Self {
        Self {
            db,
            writes: HashMap::new(),
        }
    }

    /// Get a value from pending writes or the database (cache/storage).
    ///
    /// Lookup order: pending writes -> shared cache -> storage.
    ///
    /// # Type Safety
    /// The caller must ensure `V` matches the type that was inserted for this key.
    /// If the types don't match, this will return an error.
    pub async fn get<K, V>(&self, key: K) -> Result<Option<V>, eyre::Error>
    where
        K: AsRef<[u8]>,
        V: Read<Cfg = ()> + CodecWrite + EncodeSize + Clone + Send + Sync + 'static,
    {
        let key_hash = key_to_b256(key.as_ref());

        // Check pending writes first
        if let Some(value_opt) = self.writes.get(&key_hash) {
            return match value_opt {
                Some(cached) => match cached.as_any().downcast_ref::<V>() {
                    Some(value) => Ok(Some(value.clone())),
                    None => Err(eyre::eyre!(
                        "type mismatch: pending write cannot be downcast to requested type"
                    )),
                },
                None => Ok(None), // Marked for deletion
            };
        }

        self.db.get(key).await
    }

    /// Insert a key-value pair into the transaction's pending writes.
    ///
    /// The value is stored in its typed form and only serialized at commit time.
    /// This does not immediately write to the store - call `commit()` to persist.
    pub fn insert<K, V>(&mut self, key: K, value: V)
    where
        K: AsRef<[u8]>,
        V: CodecWrite + EncodeSize + Send + Sync + 'static,
    {
        let key_hash = key_to_b256(key.as_ref());
        self.writes
            .insert(key_hash, Some(Box::new(value) as Box<dyn CachedValue>));
    }

    /// Remove a key from the store.
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
    pub async fn get_node_version(&self) -> Result<Option<String>, eyre::Error> {
        let key_hash = key_to_b256(NODE_VERSION_KEY.as_bytes());

        // Check pending writes first
        if let Some(value_opt) = self.writes.get(&key_hash) {
            return match value_opt {
                Some(cached) => Ok(Some(
                    String::from_utf8(cached.serialize()?.to_vec())
                        .map_err(|e| eyre::eyre!("invalid utf8: {}", e))?,
                )),
                None => Ok(None),
            };
        }

        // Get raw bytes from storage (node version bypasses typed cache)
        Ok(self
            .db
            .get_raw(NODE_VERSION_KEY)
            .await
            .and_then(|b| String::from_utf8(b.to_vec()).ok()))
    }

    /// Set the current node version in the database.
    ///
    /// This should be called when the database schema is initialized or migrated
    /// to track which node version last modified the database.
    pub fn set_node_version(&mut self, version: String) {
        self.insert(NODE_VERSION_KEY, version.into_bytes())
    }

    /// Commit all buffered writes to the store and sync.
    ///
    /// This serializes all pending writes, persists them to storage,
    /// and updates the shared cache with the new values.
    pub async fn commit(self) -> Result<(), eyre::Error> {
        if self.writes.is_empty() {
            return Ok(());
        }

        let mut db = self.db.0.write().await;

        for (key, value_opt) in self.writes {
            match value_opt {
                Some(cached) => {
                    let bytes = cached.serialize()?;
                    db.store.put(key.clone(), bytes);
                    db.cache.insert(key, cached);
                }
                None => {
                    db.store.remove(&key);
                    db.cache.remove(&key);
                }
            }
        }

        db.store.sync().await.wrap_err("sync failed")?;

        Ok(())
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

/// Trait for values that can be cached in the transaction buffer.
///
/// This trait combines type erasure (via `Any`) with serialization capability,
/// allowing heterogeneous types to be stored in a single cache while still
/// supporting serialization at commit time.
pub trait CachedValue: Any + Send + Sync {
    /// Returns self as `&dyn Any` for downcasting.
    fn as_any(&self) -> &dyn Any;

    /// Serializes the value to bytes for persistence.
    fn serialize(&self) -> Result<Bytes, eyre::Error>;
}

impl<T> CachedValue for T
where
    T: CodecWrite + EncodeSize + Any + Send + Sync,
{
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn serialize(&self) -> Result<Bytes, eyre::Error> {
        serialize_to_bytes(self)
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
    use commonware_runtime::{ContextCell, Runner, tokio, tokio::Context};

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

                // Insert and verify pending writes before commit
                let mut tx = db.read_write();
                tx.insert("key1", 100u64);
                tx.insert("key2", 200u64);
                assert_eq!(tx.get::<_, u64>(&"key1").await.unwrap(), Some(100));
                assert_eq!(tx.get::<_, u64>(&"key2").await.unwrap(), Some(200));
                tx.commit().await.unwrap();

                // Verify persisted to storage and cached
                {
                    let inner = db.0.read().await;
                    assert!(inner.store.get(&key1_hash).is_some());
                    assert!(inner.store.get(&key2_hash).is_some());
                    assert!(inner.cache.contains_key(&key1_hash));
                    assert!(inner.cache.contains_key(&key2_hash));
                }

                // Test get reads from shared cache after commit
                let mut tx = db.read_write();
                assert_eq!(tx.get::<_, u64>(&"key1").await.unwrap(), Some(100));
                assert_eq!(tx.get::<_, u64>(&"key2").await.unwrap(), Some(200));

                // Remove and verify in pending writes before commit
                tx.remove("key1");
                assert_eq!(tx.get::<_, u64>(&"key1").await.unwrap(), None);
                assert_eq!(tx.get::<_, u64>(&"key2").await.unwrap(), Some(200));
                tx.commit().await.unwrap();

                // Verify removal persisted to storage and cache
                {
                    let inner = db.0.read().await;
                    assert!(inner.store.get(&key1_hash).is_none());
                    assert!(inner.store.get(&key2_hash).is_some());
                    assert!(!inner.cache.contains_key(&key1_hash));
                    assert!(inner.cache.contains_key(&key2_hash));
                }

                Ok::<(), eyre::Error>(())
            })
            .expect("test should succeed");
    }
}
