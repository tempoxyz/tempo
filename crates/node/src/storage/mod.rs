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
use reth_primitives_traits::{AlloyBlockHeader, StorageEntry};
use std::{
    path::PathBuf,
    sync::{Arc, LazyLock, OnceLock, mpsc},
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
    warm: mpsc::SyncSender<()>,
}

impl<D: Database + Clone + 'static> TempoDatabase<D> {
    /// Wrap a database using its chain specification and static-file directory.
    pub fn new(inner: D, chain: Arc<TempoChainSpec>, static_files: PathBuf) -> Self {
        let cache = Arc::new(Cache::default());
        let (warm, receiver) = mpsc::sync_channel(1);
        let worker_db = inner.clone();
        let worker_chain = chain.clone();
        let worker_path = static_files.clone();
        let worker_cache = cache.clone();
        std::thread::Builder::new()
            .name("replay-cache".into())
            .spawn(move || {
                while receiver.recv().is_ok() {
                    let result = worker_cache.warm(&worker_db, &worker_chain, &worker_path);
                    if let Err(error) = result {
                        tracing::warn!(%error, "Could not warm replay storage cache");
                    }
                }
            })
            .expect("spawn replay cache worker");
        Self {
            inner,
            chain,
            static_files,
            cache,
            warm,
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
        Ok(ReplayTx {
            inner: self.inner.tx()?,
            chain: self.chain.clone(),
            static_files: self.static_files.clone(),
            view: OnceLock::new(),
            cache: self.cache.clone(),
        })
    }
    fn tx_mut(&self) -> Result<Self::TXMut, DatabaseError> {
        let tx = self.inner.tx_mut()?;
        #[cfg(feature = "expiring-nonce-no-persistence")]
        let tx = WriteTx(tx);
        Ok(tx)
    }
    fn on_persisted(&self) {
        let _ = self.warm.try_send(());
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
    chain: Arc<TempoChainSpec>,
    static_files: PathBuf,
    cache: Arc<Cache>,
    view: OnceLock<Result<Arc<View>, DatabaseError>>,
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
    fn view(&self) -> Result<&Arc<View>, DatabaseError> {
        self.view
            .get_or_init(|| {
                Ok(Arc::new(View {
                    source: Source::new(&self.inner, self.chain.genesis_header().number())?,
                    chain: self.chain.clone(),
                    static_files: self.static_files.clone(),
                    cache: self.cache.clone(),
                    snapshot: OnceLock::new(),
                }))
            })
            .as_ref()
            .map_err(Clone::clone)
    }
    fn snapshot(&self) -> Result<&Arc<Snapshot>, DatabaseError> {
        self.view()?.snapshot()
    }
    fn slots(&self) -> Result<&Slots, DatabaseError> {
        Ok(&self.snapshot()?.slots)
    }
    fn storage_view<T: Table>(&self) -> Result<Option<Arc<View>>, DatabaseError> {
        if address_key::<T>().is_some() {
            Ok(Some(self.view()?.clone()))
        } else {
            Ok(None)
        }
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
        self.get::<T>(T::Key::decode(key.as_ref())?)
    }
    fn commit(self) -> Result<(), DatabaseError> {
        self.inner.commit()
    }
    fn abort(self) {
        self.inner.abort()
    }
    fn cursor_read<T: Table>(&self) -> Result<Self::Cursor<T>, DatabaseError> {
        Ok(Cursor::new(
            self.inner.cursor_read::<T>()?,
            self.storage_view::<T>()?,
        ))
    }
    fn cursor_dup_read<T: DupSort>(&self) -> Result<Self::DupCursor<T>, DatabaseError> {
        Ok(Cursor::new(
            self.inner.cursor_dup_read::<T>()?,
            self.storage_view::<T>()?,
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
