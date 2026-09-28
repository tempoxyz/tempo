use super::Cursor;
use alloy_primitives::keccak256;
use reth_db_api::{
    DatabaseError,
    cursor::{DbCursorRO, DbCursorRW, DbDupCursorRW},
    table::{DupSort, Encode, Table, TableImporter},
    tables,
    transaction::{DbTx, DbTxMut},
};
use tempo_precompiles::EXPIRING_NONCE_PRECOMPILE_ADDRESS;

fn filtered_table<T: Table>() -> bool {
    matches!(
        T::NAME,
        tables::HashedStorages::NAME | tables::StoragesTrie::NAME
    )
}

fn discard<T: Table>(key: &T::Key) -> bool {
    filtered_table::<T>()
        && key.clone().encode().as_ref() == keccak256(EXPIRING_NONCE_PRECOMPILE_ADDRESS).as_slice()
}

/// Native write transaction that drops the replay precompile's state and trie mutations.
/// Reads retain native transaction semantics; derived reads use `ReplayTx`.
#[derive(Debug)]
pub struct WriteTx<TX>(pub(super) TX);

impl<TX: DbTx + DbTxMut> TableImporter for WriteTx<TX> {}

impl<TX: DbTx> DbTx for WriteTx<TX> {
    type Cursor<T: Table> = Cursor<T, TX::Cursor<T>>;
    type DupCursor<T: DupSort> = Cursor<T, TX::DupCursor<T>>;

    fn get<T: Table>(&self, key: T::Key) -> Result<Option<T::Value>, DatabaseError> {
        self.0.get::<T>(key)
    }
    fn get_by_encoded_key<T: Table>(
        &self,
        key: &<T::Key as Encode>::Encoded,
    ) -> Result<Option<T::Value>, DatabaseError> {
        self.0.get_by_encoded_key::<T>(key)
    }
    fn commit(self) -> Result<(), DatabaseError> {
        self.0.commit()
    }
    fn abort(self) {
        self.0.abort()
    }
    fn cursor_read<T: Table>(&self) -> Result<Self::Cursor<T>, DatabaseError> {
        Ok(Cursor::new(self.0.cursor_read::<T>()?, None))
    }
    fn cursor_dup_read<T: DupSort>(&self) -> Result<Self::DupCursor<T>, DatabaseError> {
        Ok(Cursor::new(self.0.cursor_dup_read::<T>()?, None))
    }
    fn entries<T: Table>(&self) -> Result<usize, DatabaseError> {
        self.0.entries::<T>()
    }
    fn disable_long_read_transaction_safety(&mut self) {
        self.0.disable_long_read_transaction_safety()
    }
}

impl<TX: DbTx + DbTxMut> DbTxMut for WriteTx<TX> {
    type CursorMut<T: Table> = Cursor<T, TX::CursorMut<T>>;
    type DupCursorMut<T: DupSort> = Cursor<T, TX::DupCursorMut<T>>;

    fn put<T: Table>(&self, key: T::Key, value: T::Value) -> Result<(), DatabaseError> {
        if discard::<T>(&key) {
            return Ok(());
        }
        self.0.put::<T>(key, value)
    }
    fn append<T: Table>(&self, key: T::Key, value: T::Value) -> Result<(), DatabaseError> {
        if discard::<T>(&key) {
            return Ok(());
        }
        self.0.append::<T>(key, value)
    }
    fn delete<T: Table>(
        &self,
        key: T::Key,
        value: Option<T::Value>,
    ) -> Result<bool, DatabaseError> {
        if discard::<T>(&key) {
            return Ok(false);
        }
        self.0.delete::<T>(key, value)
    }
    fn clear<T: Table>(&self) -> Result<(), DatabaseError> {
        if !filtered_table::<T>() {
            return self.0.clear::<T>();
        }
        let mut cursor = self.0.cursor_write::<T>()?;
        let mut walker = cursor.walk(None)?;
        while let Some(row) = walker.next() {
            if !discard::<T>(&row?.0) {
                walker.delete_current()?;
            }
        }
        Ok(())
    }
    fn cursor_write<T: Table>(&self) -> Result<Self::CursorMut<T>, DatabaseError> {
        Ok(Cursor::new(self.0.cursor_write::<T>()?, None))
    }
    fn cursor_dup_write<T: DupSort>(&self) -> Result<Self::DupCursorMut<T>, DatabaseError> {
        Ok(Cursor::new(self.0.cursor_dup_write::<T>()?, None))
    }
}

impl<T: Table, C: DbCursorRO<T> + DbCursorRW<T>> DbCursorRW<T> for Cursor<T, C> {
    fn upsert(&mut self, key: T::Key, value: &T::Value) -> Result<(), DatabaseError> {
        if discard::<T>(&key) {
            return Ok(());
        }
        self.inner.upsert(key, value)
    }
    fn insert(&mut self, key: T::Key, value: &T::Value) -> Result<(), DatabaseError> {
        if discard::<T>(&key) {
            return Ok(());
        }
        self.inner.insert(key, value)
    }
    fn append(&mut self, key: T::Key, value: &T::Value) -> Result<(), DatabaseError> {
        if discard::<T>(&key) {
            return Ok(());
        }
        self.inner.append(key, value)
    }
    fn delete_current(&mut self) -> Result<(), DatabaseError> {
        if filtered_table::<T>()
            && self
                .inner
                .current()?
                .is_some_and(|(key, _)| discard::<T>(&key))
        {
            return Ok(());
        }
        self.inner.delete_current()
    }
}

impl<T: DupSort, C: DbCursorRO<T> + DbDupCursorRW<T>> DbDupCursorRW<T> for Cursor<T, C> {
    fn delete_current_duplicates(&mut self) -> Result<(), DatabaseError> {
        if filtered_table::<T>()
            && self
                .inner
                .current()?
                .is_some_and(|(key, _)| discard::<T>(&key))
        {
            return Ok(());
        }
        self.inner.delete_current_duplicates()
    }
    fn append_dup(&mut self, key: T::Key, value: T::Value) -> Result<(), DatabaseError> {
        if discard::<T>(&key) {
            return Ok(());
        }
        self.inner.append_dup(key, value)
    }
}
