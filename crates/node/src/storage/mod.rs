//! Read-only replay-protection storage derived from canonical block data.
//!
//! This PoC scans blocks from genesis to the transaction's Finish checkpoint and
//! materializes storage tables for cursor reads. It requires those block bodies
//! to remain available. Writes, history, and trie persistence are unmodified.
mod cursor;
mod replay;

use alloy_primitives::{B256, U256, keccak256};
pub use cursor::Cursor;
use cursor::Rows;
use reth_db_api::{
    Database, DatabaseError,
    cursor::DbCursorRO,
    database_metrics::DatabaseMetrics,
    table::{Compress, Decode, Decompress, DupSort, Encode, Table},
    tables,
    transaction::DbTx,
};
use reth_ethereum::provider::db::DatabaseEnv;
use reth_primitives_traits::StorageEntry;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, OnceLock},
};
use tempo_chainspec::TempoChainSpec;
use tempo_precompiles::EXPIRING_NONCE_PRECOMPILE_ADDRESS;

/// The node's database. Write transactions are deliberately passed through unchanged.
#[derive(Clone, Debug)]
pub struct TempoDatabase<D = DatabaseEnv> {
    inner: D,
    chain: Arc<TempoChainSpec>,
    static_files: PathBuf,
}

impl<D> TempoDatabase<D> {
    /// Wrap a database using its chain specification and static-file directory.
    pub fn new(inner: D, chain: Arc<TempoChainSpec>, static_files: PathBuf) -> Self {
        Self {
            inner,
            chain,
            static_files,
        }
    }
}

impl<D: Database> Database for TempoDatabase<D> {
    type TX = ReplayTx<D::TX>;
    type TXMut = D::TXMut;
    fn tx(&self) -> Result<Self::TX, DatabaseError> {
        Ok(ReplayTx {
            inner: self.inner.tx()?,
            chain: self.chain.clone(),
            static_files: self.static_files.clone(),
            slots: OnceLock::new(),
        })
    }
    fn tx_mut(&self) -> Result<Self::TXMut, DatabaseError> {
        self.inner.tx_mut()
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
    slots: OnceLock<Result<BTreeMap<B256, U256>, DatabaseError>>,
}

fn address_key<T: Table>() -> Option<Vec<u8>> {
    match T::NAME {
        tables::PlainStorageState::NAME => Some(EXPIRING_NONCE_PRECOMPILE_ADDRESS.to_vec()),
        tables::HashedStorages::NAME => Some(keccak256(EXPIRING_NONCE_PRECOMPILE_ADDRESS).to_vec()),
        _ => None,
    }
}

impl<TX: DbTx> ReplayTx<TX> {
    fn slots(&self) -> Result<&BTreeMap<B256, U256>, DatabaseError> {
        self.slots
            .get_or_init(|| replay::reconstruct(&self.inner, &self.chain, &self.static_files))
            .as_ref()
            .map_err(Clone::clone)
    }

    // Materialize only the two storage tables. This intentionally favors a simple PoC
    // over memory usage; unrelated tables retain their native cursors.
    fn rows<T: Table>(&self) -> Result<Option<Rows>, DatabaseError> {
        let Some(address) = address_key::<T>() else {
            return Ok(None);
        };
        let mut rows = Vec::new();
        let mut cursor = self.inner.cursor_read::<T>()?;
        for row in cursor.walk(None)? {
            let (key, value) = row?;
            let key = key.encode().as_ref().to_vec();
            if key != address {
                rows.push((key, value.compress().as_ref().to_vec()));
            }
        }
        for (&slot, &value) in self.slots()? {
            let key = if T::NAME == tables::HashedStorages::NAME {
                keccak256(slot)
            } else {
                slot
            };
            rows.push((address.clone(), StorageEntry { key, value }.compress()));
        }
        rows.sort();
        Ok(Some(Arc::new(rows)))
    }
}

impl<TX: DbTx> DbTx for ReplayTx<TX> {
    type Cursor<T: Table> = Cursor<T, TX::Cursor<T>>;
    type DupCursor<T: DupSort> = Cursor<T, TX::DupCursor<T>>;
    fn get<T: Table>(&self, key: T::Key) -> Result<Option<T::Value>, DatabaseError> {
        if address_key::<T>().is_some_and(|address| key.clone().encode().as_ref() == address) {
            let mut entries: Vec<_> = self
                .slots()?
                .iter()
                .map(|(&slot, &value)| StorageEntry {
                    key: if T::NAME == tables::HashedStorages::NAME {
                        keccak256(slot)
                    } else {
                        slot
                    },
                    value,
                })
                .collect();
            entries.sort();
            return entries
                .first()
                .map(|entry| T::Value::decompress(entry.compress().as_ref()).map_err(Into::into))
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
            self.rows::<T>()?,
        ))
    }
    fn cursor_dup_read<T: DupSort>(&self) -> Result<Self::DupCursor<T>, DatabaseError> {
        Ok(Cursor::new(
            self.inner.cursor_dup_read::<T>()?,
            self.rows::<T>()?,
        ))
    }
    fn entries<T: Table>(&self) -> Result<usize, DatabaseError> {
        match self.rows::<T>()? {
            Some(rows) => Ok(rows.len()),
            None => self.inner.entries::<T>(),
        }
    }
    fn disable_long_read_transaction_safety(&mut self) {
        self.inner.disable_long_read_transaction_safety()
    }
}

#[cfg(test)]
mod tests;
