//! Read-only replay-protection storage derived from canonical block data.
//!
//! Read transactions lease shared snapshots at their Finish checkpoint. Snapshots
//! advance by replaying missing blocks; unrelated forks rebuild from genesis.
//! Block bodies must remain available. `expiring-nonce-no-persistence` discards this precompile's
//! hashed storage and storage-trie writes. History remains unchanged.
mod backend;
mod cursor;
mod replay;
#[cfg(feature = "expiring-nonce-no-persistence")]
mod write;
#[cfg(feature = "expiring-nonce-no-persistence")]
pub use write::WriteTx;

#[cfg(test)]
use alloy_primitives::U256;
use alloy_primitives::{B256, keccak256};
pub use cursor::Cursor;
use replay::{Cache, Slots, Snapshot, Source};
use reth_chainspec::EthChainSpec;
use reth_db_api::{
    Database, DatabaseError,
    cursor::DbCursorRO,
    database_metrics::DatabaseMetrics,
    table::{Compress, Decode, Decompress, DupSort, Encode, Table},
    tables,
    transaction::DbTx,
};
use reth_ethereum::provider::db::DatabaseEnv;
use reth_primitives_traits::{AlloyBlockHeader, StorageEntry, ValueWithSubKey};
use std::{
    path::PathBuf,
    sync::{Arc, LazyLock, OnceLock},
};
use tempo_chainspec::TempoChainSpec;
use tempo_precompiles::EXPIRING_NONCE_PRECOMPILE_ADDRESS;

/// The node's database, with derived replay reads and optional write filtering.
#[derive(Clone, Debug)]
pub struct TempoDatabase<D = DatabaseEnv> {
    inner: D,
    chain: Arc<TempoChainSpec>,
    static_files: PathBuf,
    cache: Arc<Cache>,
}

impl<D: Database> TempoDatabase<D> {
    /// Wrap a database using its chain specification and static-file directory.
    pub fn new(inner: D, chain: Arc<TempoChainSpec>, static_files: PathBuf) -> Self {
        let cache = Arc::new(Cache::default());
        Self {
            inner,
            chain,
            static_files,
            cache,
        }
    }
}

impl<D: Database> Database for TempoDatabase<D> {
    type TX = ReplayTx<D::TX>;
    #[cfg(not(feature = "expiring-nonce-no-persistence"))]
    type TXMut = D::TXMut;
    #[cfg(feature = "expiring-nonce-no-persistence")]
    type TXMut = WriteTx<D::TXMut>;
    fn tx(&self) -> Result<Self::TX, DatabaseError> {
        // Pin the database and an available snapshot atomically with publication.
        // Otherwise a lazy reader can lose its old state before its first nonce read.
        let mut published = self.cache.published.lock().unwrap();
        let inner = self.inner.tx()?;
        let genesis = self.chain.genesis_header().number();
        let source = Source::new(&inner, genesis)?;
        let snapshot = published
            .find(&source, genesis)?
            .map_or_else(OnceLock::new, |state| OnceLock::from(Ok(state)));
        drop(published);
        Ok(ReplayTx {
            inner,
            view: Arc::new(View {
                source,
                chain: self.chain.clone(),
                static_files: self.static_files.clone(),
                snapshot,
                cache: self.cache.clone(),
            }),
        })
    }
    fn tx_mut(&self) -> Result<Self::TXMut, DatabaseError> {
        let tx = self.inner.tx_mut()?;
        #[cfg(feature = "expiring-nonce-no-persistence")]
        let tx = WriteTx(tx);
        Ok(tx)
    }
    fn prepare_persistence<B: reth_primitives_traits::Block + 'static>(
        &self,
        blocks: Vec<Arc<reth_primitives_traits::RecoveredBlock<B>>>,
    ) -> Result<Option<Box<dyn reth_db_api::database::PersistenceTask>>, DatabaseError> {
        if blocks.is_empty() {
            return Ok(None);
        }
        let blocks = (Box::new(blocks) as Box<dyn std::any::Any>)
            .downcast::<Vec<Arc<reth_primitives_traits::RecoveredBlock<tempo_primitives::Block>>>>()
            .map_err(|_| DatabaseError::Other("non-Tempo persistence blocks".into()))?;
        let source = Source::new(&self.inner.tx()?, self.chain.genesis_header().number())?;
        self.cache
            .prepare_blocks(
                source,
                self.chain.clone(),
                self.static_files.clone(),
                *blocks,
            )
            .map(|task| Some(Box::new(task) as Box<dyn reth_db_api::database::PersistenceTask>))
    }
    fn path(&self) -> PathBuf {
        self.inner.path()
    }
    fn oldest_reader_txnid(&self) -> Option<u64> {
        self.inner.oldest_reader_txnid()
    }
    fn last_txnid(&self) -> Option<u64> {
        self.inner.last_txnid()
    }
}
impl<D: DatabaseMetrics> DatabaseMetrics for TempoDatabase<D> {
    fn report_metrics(&self) {
        self.inner.report_metrics()
    }
    fn gauge_metrics(&self) -> Vec<(&'static str, f64, Vec<metrics::Label>)> {
        self.inner.gauge_metrics()
    }
    fn counter_metrics(&self) -> Vec<(&'static str, u64, Vec<metrics::Label>)> {
        self.inner.counter_metrics()
    }
    fn histogram_metrics(&self) -> Vec<(&'static str, f64, Vec<metrics::Label>)> {
        self.inner.histogram_metrics()
    }
}

/// A pinned read transaction with lazily reconstructed replay slots.
#[derive(Debug)]
pub struct ReplayTx<TX> {
    inner: TX,
    view: Arc<View>,
}

/// All cursors from a transaction share this lazily acquired snapshot lease.
#[derive(Debug)]
pub(super) struct View {
    source: Source,
    chain: Arc<TempoChainSpec>,
    static_files: PathBuf,
    cache: Arc<Cache>,
    snapshot: OnceLock<Result<Arc<Snapshot>, DatabaseError>>,
}
impl View {
    fn snapshot(&self) -> Result<&Arc<Snapshot>, DatabaseError> {
        self.snapshot
            .get_or_init(|| {
                self.cache
                    .get(&self.source, &self.chain, &self.static_files)
            })
            .as_ref()
            .map_err(Clone::clone)
    }
}

static HASHED_ADDRESS: LazyLock<B256> =
    LazyLock::new(|| keccak256(EXPIRING_NONCE_PRECOMPILE_ADDRESS));

fn address_key<T: Table>() -> Option<B256> {
    match T::NAME {
        tables::HashedStorages::NAME => Some(*HASHED_ADDRESS),
        _ => None,
    }
}

impl<TX: DbTx + 'static> ReplayTx<TX> {
    fn snapshot(&self) -> Result<&Arc<Snapshot>, DatabaseError> {
        self.view.snapshot()
    }
    fn slots(&self) -> Result<&Slots, DatabaseError> {
        Ok(&self.snapshot()?.slots)
    }
    fn storage_view<T: Table>(&self) -> Option<Arc<View>> {
        address_key::<T>().map(|_| self.view.clone())
    }
}

impl<TX: DbTx + 'static> DbTx for ReplayTx<TX> {
    type Cursor<T: Table> = Cursor<T, TX::Cursor<T>>;
    type DupCursor<T: DupSort> = Cursor<T, TX::DupCursor<T>>;
    fn get<T: Table>(&self, key: T::Key) -> Result<Option<T::Value>, DatabaseError> {
        if address_key::<T>()
            .is_some_and(|address| key.clone().encode().as_ref() == address.as_slice())
        {
            return self
                .slots()?
                .iter()
                .next()
                .map(|(&key, &value)| {
                    T::Value::decompress(StorageEntry { key, value }.compress().as_ref())
                        .map_err(Into::into)
                })
                .transpose();
        }
        self.inner.get::<T>(key)
    }
    fn get_by_encoded_key<T: Table>(
        &self,
        key: &<T::Key as Encode>::Encoded,
    ) -> Result<Option<T::Value>, DatabaseError> {
        if address_key::<T>().is_some_and(|address| key.as_ref() == address.as_slice()) {
            self.get::<T>(T::Key::decode(key.as_ref())?)
        } else {
            self.inner.get_by_encoded_key::<T>(key)
        }
    }
    fn commit(self) -> Result<(), DatabaseError> {
        self.inner.commit()
    }
    fn get_by_key_subkey<T: DupSort>(
        &self,
        key: T::Key,
        subkey: T::SubKey,
    ) -> Result<Option<T::Value>, DatabaseError>
    where
        T::Value: ValueWithSubKey<SubKey = T::SubKey>,
    {
        if address_key::<T>()
            .is_some_and(|address| key.clone().encode().as_ref() == address.as_slice())
        {
            let key = B256::from_slice(subkey.encode().as_ref());
            return self
                .slots()?
                .get(&key)
                .map(|&value| {
                    T::Value::decompress(StorageEntry { key, value }.compress().as_ref())
                        .map_err(Into::into)
                })
                .transpose();
        }
        self.inner.get_by_key_subkey::<T>(key, subkey)
    }
    fn abort(self) {
        self.inner.abort()
    }
    fn cursor_read<T: Table>(&self) -> Result<Self::Cursor<T>, DatabaseError> {
        Ok(Cursor::new(
            self.inner.cursor_read::<T>()?,
            self.storage_view::<T>(),
        ))
    }
    fn cursor_dup_read<T: DupSort>(&self) -> Result<Self::DupCursor<T>, DatabaseError> {
        Ok(Cursor::new(
            self.inner.cursor_dup_read::<T>()?,
            self.storage_view::<T>(),
        ))
    }
    fn entries<T: Table>(&self) -> Result<usize, DatabaseError> {
        let mut count = self.inner.entries::<T>()?;
        if let Some(address) = address_key::<T>() {
            let mut cursor = self.inner.cursor_read::<T>()?;
            let mut row = cursor.seek(T::Key::decode(address.as_slice())?)?;
            while row.is_some_and(|(key, _)| key.encode().as_ref() == address.as_slice()) {
                count -= 1;
                row = cursor.next()?;
            }
            count += self.slots()?.len();
        }
        Ok(count)
    }

    fn disable_long_read_transaction_safety(&mut self) {
        self.inner.disable_long_read_transaction_safety()
    }
}

#[cfg(test)]
mod tests;
