//! Small RocksDB wrapper for bounded bincode, crash-durable replay evidence.

use crate::state::ReplayIdentity;
use anyhow::{Context, Result, ensure};
use bincode::Options as _;
use metrics::{gauge, histogram};
use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, ColumnFamilyRef, CompactionPri, DB,
    DBCompressionType, IteratorMode, Options, WriteBatch, WriteBufferManager, WriteOptions,
};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

const SCHEMA_KEY: &[u8] = b"schema";
const IDENTITY_KEY: &[u8] = b"identity";
const BLOCK_CACHE_BYTES: usize = 32 << 20;
const WRITE_BUFFER_MANAGER_BYTES: usize = 64 << 20;
const WRITE_BUFFER_BYTES: usize = 16 << 20;
const MAX_TOTAL_WAL_BYTES: u64 = 64 << 20;
const MAX_ERROR_BYTES: usize = 1_024;
const MAX_RECORD_BYTES: u64 = 64 << 20;

/// RocksDB primary or live secondary with bounded binary value helpers.
pub struct Store {
    db: DB,
    path: PathBuf,
    secondary: Option<PathBuf>,
    columns: Vec<String>,
    max_bytes: u64,
    min_free_bytes: u64,
}

impl Store {
    pub fn open(
        path: &Path,
        columns: &[&str],
        schema: u32,
        identity: ReplayIdentity,
        max_bytes: u64,
        min_free_bytes: u64,
    ) -> Result<Self> {
        std::fs::create_dir_all(path)?;
        let db = open_db(path, columns, None)?;
        let store = Self {
            db,
            path: path.to_owned(),
            secondary: None,
            columns: columns.iter().map(|column| (*column).to_owned()).collect(),
            max_bytes,
            min_free_bytes,
        };
        match store.db.get(SCHEMA_KEY)? {
            Some(value) => {
                ensure!(
                    value.as_slice() == schema.to_be_bytes(),
                    "unsupported database schema"
                );
                ensure!(
                    store.get_default::<ReplayIdentity>(IDENTITY_KEY)? == Some(identity),
                    "database belongs to a different source or shadow checkpoint"
                );
            }
            None => {
                let mut batch = WriteBatch::default();
                batch.put(SCHEMA_KEY, schema.to_be_bytes());
                batch.put(IDENTITY_KEY, encode(&identity)?);
                store.commit(batch)?;
            }
        }
        store.check_disk()?;
        Ok(store)
    }

    pub fn open_secondary(path: &Path, columns: &[&str], schema: u32) -> Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        ensure!(path.join("CURRENT").exists(), "database does not exist");
        let secondary = std::env::temp_dir().join(format!(
            "tempo-replay-rocksdb-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&secondary)?;
        let db = open_db(path, columns, Some(&secondary))?;
        db.try_catch_up_with_primary()?;
        ensure!(
            db.get(SCHEMA_KEY)?
                .is_some_and(|value| value.as_slice() == schema.to_be_bytes()),
            "unsupported database schema"
        );
        Ok(Self {
            db,
            path: path.to_owned(),
            secondary: Some(secondary),
            columns: columns.iter().map(|column| (*column).to_owned()).collect(),
            max_bytes: u64::MAX,
            min_free_bytes: 0,
        })
    }

    pub fn get_default<T: DeserializeOwned>(&self, key: &[u8]) -> Result<Option<T>> {
        self.db.get(key)?.map(|value| decode(&value)).transpose()
    }

    pub fn get_raw_default(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.db.get(key).map_err(Into::into)
    }

    pub fn get<T: DeserializeOwned>(&self, column: &str, key: &[u8]) -> Result<Option<T>> {
        self.db
            .get_cf(self.column(column)?, key)?
            .map(|value| decode(&value))
            .transpose()
    }

    pub fn raw_prefix(&self, column: &str, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.raw_prefix_limit(column, prefix, usize::MAX)
    }

    pub fn raw_prefix_limit(
        &self,
        column: &str,
        prefix: &[u8],
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.raw_scan(column, prefix, limit, |key| key.starts_with(prefix))
    }

    pub fn raw_range(
        &self,
        column: &str,
        start: &[u8],
        end: &[u8],
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.raw_scan(column, start, limit, |key| key <= end)
    }

    fn raw_scan(
        &self,
        column: &str,
        start: &[u8],
        limit: usize,
        contains: impl Fn(&[u8]) -> bool,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut rows = Vec::new();
        for row in self.db.iterator_cf(
            self.column(column)?,
            IteratorMode::From(start, rocksdb::Direction::Forward),
        ) {
            let (key, value) = row?;
            if !contains(&key) || rows.len() == limit {
                break;
            }
            rows.push((key.into_vec(), value.into_vec()));
        }
        Ok(rows)
    }

    pub fn put_default<T: Serialize>(batch: &mut WriteBatch, key: &[u8], value: &T) {
        batch.put(key, encode(value).expect("bounded metadata serializes"));
    }

    pub fn put<T: Serialize>(
        &self,
        batch: &mut WriteBatch,
        column: &str,
        key: &[u8],
        value: &T,
    ) -> Result<()> {
        batch.put_cf(self.column(column)?, key, encode(value)?);
        Ok(())
    }

    pub fn put_raw(
        &self,
        batch: &mut WriteBatch,
        column: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<()> {
        batch.put_cf(self.column(column)?, key, value);
        Ok(())
    }

    pub fn delete(&self, batch: &mut WriteBatch, column: &str, key: &[u8]) -> Result<()> {
        batch.delete_cf(self.column(column)?, key);
        Ok(())
    }

    fn column<'a>(&'a self, name: &str) -> Result<ColumnFamilyRef<'a>> {
        self.db
            .cf_handle(name)
            .with_context(|| format!("missing {name} column"))
    }

    pub fn commit(&self, batch: WriteBatch) -> Result<()> {
        ensure!(
            self.secondary.is_none(),
            "cannot write through a secondary database"
        );
        let started = Instant::now();
        let mut options = WriteOptions::default();
        options.set_sync(true);
        self.db.write_opt(batch, &options)?;
        histogram!("tempo_replay_rocksdb_write_seconds").record(started.elapsed().as_secs_f64());
        Ok(())
    }

    pub fn check_disk(&self) -> Result<()> {
        self.record_metrics();
        ensure!(
            fs4::available_space(&self.path)? >= self.min_free_bytes,
            "database disk low-watermark reached"
        );
        ensure!(
            directory_size(&self.path)? < self.max_bytes,
            "database maximum size reached"
        );
        Ok(())
    }

    pub fn flush(&self) -> Result<()> {
        if self.secondary.is_none() {
            self.db.flush_wal(true)?;
            self.db.flush()?;
        }
        Ok(())
    }

    fn record_metrics(&self) {
        let mut sst = 0u64;
        let mut memtables = 0u64;
        let mut pending = 0u64;
        for name in &self.columns {
            let Some(cf) = self.db.cf_handle(name) else {
                continue;
            };
            let property = |property| {
                self.db
                    .property_int_value_cf(cf, property)
                    .ok()
                    .flatten()
                    .unwrap_or(0)
            };
            gauge!("tempo_replay_rocksdb_estimated_keys", "column" => name.clone())
                .set(property(rocksdb::properties::ESTIMATE_NUM_KEYS) as f64);
            sst += property(rocksdb::properties::LIVE_SST_FILES_SIZE);
            memtables += property(rocksdb::properties::SIZE_ALL_MEM_TABLES);
            pending += property(rocksdb::properties::ESTIMATE_PENDING_COMPACTION_BYTES);
        }
        gauge!("tempo_replay_rocksdb_sst_bytes").set(sst as f64);
        gauge!("tempo_replay_rocksdb_memtable_bytes").set(memtables as f64);
        gauge!("tempo_replay_rocksdb_pending_compaction_bytes").set(pending as f64);
        gauge!("tempo_replay_rocksdb_wal_bytes").set(wal_size(&self.path) as f64);
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        if self.secondary.is_none() {
            let _ = self.db.flush_wal(true);
        }
        self.db.cancel_all_background_work(true);
        if let Some(path) = self.secondary.take() {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    codec().serialize(value).map_err(Into::into)
}

pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    codec().deserialize(bytes).map_err(Into::into)
}

fn codec() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_varint_encoding()
        .with_little_endian()
        .reject_trailing_bytes()
        .with_limit(MAX_RECORD_BYTES)
}

pub fn bounded_error(message: impl AsRef<str>) -> String {
    let message = message.as_ref();
    if message.len() <= MAX_ERROR_BYTES {
        return message.to_owned();
    }
    let end = (0..=MAX_ERROR_BYTES)
        .rev()
        .find(|index| message.is_char_boundary(*index))
        .unwrap_or(0);
    message[..end].to_owned()
}

fn open_db(path: &Path, required: &[&str], secondary: Option<&Path>) -> Result<DB> {
    let cache = Cache::new_lru_cache(BLOCK_CACHE_BYTES);
    let mut options = db_options(&cache);
    options.create_if_missing(secondary.is_none());
    options.create_missing_column_families(secondary.is_none());
    if secondary.is_some() {
        options.set_max_open_files(-1);
    }

    let descriptors = required
        .iter()
        .copied()
        .map(|name| ColumnFamilyDescriptor::new(name, column_options(&cache)))
        .collect::<Vec<_>>();
    match secondary {
        Some(secondary) => {
            DB::open_cf_descriptors_as_secondary(&options, path, secondary, descriptors)
        }
        None => DB::open_cf_descriptors(&options, path, descriptors),
    }
    .map_err(Into::into)
}

fn db_options(cache: &Cache) -> Options {
    let mut options = column_options(cache);
    options.set_max_background_jobs(3);
    options.set_bytes_per_sync(1 << 20);
    options.set_max_open_files(256);
    options.set_max_total_wal_size(MAX_TOTAL_WAL_BYTES);
    options.set_wal_ttl_seconds(0);
    options.set_wal_size_limit_mb(0);
    options.set_compaction_pri(CompactionPri::MinOverlappingRatio);
    options.set_write_buffer_manager(&WriteBufferManager::new_write_buffer_manager(
        WRITE_BUFFER_MANAGER_BYTES,
        true,
    ));
    options
}

fn column_options(cache: &Cache) -> Options {
    let mut table = BlockBasedOptions::default();
    table.set_block_size(16 * 1024);
    table.set_cache_index_and_filter_blocks(true);
    table.set_pin_l0_filter_and_index_blocks_in_cache(true);
    table.set_block_cache(cache);
    let mut options = Options::default();
    options.set_block_based_table_factory(&table);
    options.set_level_compaction_dynamic_level_bytes(true);
    options.set_compression_type(DBCompressionType::Lz4);
    options.set_bottommost_compression_type(DBCompressionType::Zstd);
    options.set_bottommost_zstd_max_train_bytes(0, true);
    options.set_write_buffer_size(WRITE_BUFFER_BYTES);
    options
}

fn directory_size(path: &Path) -> Result<u64> {
    std::fs::read_dir(path)?.try_fold(0u64, |size, entry| {
        let metadata = entry?.metadata()?;
        Ok(size.saturating_add(if metadata.is_file() {
            metadata.len()
        } else {
            0
        }))
    })
}

fn wal_size(path: &Path) -> u64 {
    std::fs::read_dir(path)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "log")
        })
        .filter_map(|entry| entry.metadata().ok())
        .map(|metadata| metadata.len())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::B256;

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
    struct Value {
        number: u64,
        hash: B256,
    }

    fn identity() -> ReplayIdentity {
        ReplayIdentity {
            chain_id: 4217,
            checkpoint_height: 1,
            source_hash: B256::repeat_byte(1),
            target_hash: B256::repeat_byte(2),
        }
    }

    #[test]
    fn binary_values_and_secondary_roundtrip() {
        let directory = tempfile::tempdir().unwrap();
        let store =
            Store::open(directory.path(), &["records"], 1, identity(), u64::MAX, 0).unwrap();
        let value = Value {
            number: 7,
            hash: B256::repeat_byte(3),
        };
        let mut batch = WriteBatch::default();
        store.put(&mut batch, "records", b"key", &value).unwrap();
        store.commit(batch).unwrap();
        let secondary = Store::open_secondary(directory.path(), &["records"], 1).unwrap();
        assert_eq!(
            secondary.get::<Value>("records", b"key").unwrap(),
            Some(value)
        );
    }

    #[test]
    fn malformed_and_trailing_binary_values_are_rejected() {
        assert!(decode::<Value>(&[0xff]).is_err());
        let value = Value {
            number: 7,
            hash: B256::repeat_byte(3),
        };
        let mut encoded = encode(&value).unwrap();
        encoded.push(0);
        assert!(decode::<Value>(&encoded).is_err());
    }

    #[test]
    fn bounded_errors_end_on_a_utf8_boundary() {
        let message = format!("{}é", "a".repeat(MAX_ERROR_BYTES - 1));
        let bounded = bounded_error(&message);
        assert_eq!(bounded.len(), MAX_ERROR_BYTES - 1);
        assert!(message.starts_with(&bounded));
    }

    #[test]
    fn schema_and_identity_mismatches_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        Store::open(directory.path(), &["records"], 1, identity(), u64::MAX, 0).unwrap();
        assert!(Store::open(directory.path(), &["records"], 2, identity(), u64::MAX, 0).is_err());
        let mut other = identity();
        other.target_hash = B256::repeat_byte(4);
        assert!(Store::open(directory.path(), &["records"], 1, other, u64::MAX, 0).is_err());
    }
}
