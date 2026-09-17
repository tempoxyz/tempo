use reth_db_api::{
    DatabaseError,
    common::{PairResult, ValueOnlyResult},
    cursor::{DbCursorRO, DbDupCursorRO, DupWalker, RangeWalker, ReverseWalker, Walker},
    table::{Decode, Decompress, DupSort, Encode, Table},
};
use std::{
    marker::PhantomData,
    ops::{Bound, RangeBounds},
    sync::Arc,
};

pub(super) type Rows = Arc<Vec<(Vec<u8>, Vec<u8>)>>;

/// Native cursor for ordinary tables; an ordered snapshot for hashed storage.
#[derive(Debug)]
pub struct Cursor<T, C> {
    pub(super) inner: C,
    rows: Option<Rows>,
    position: Option<usize>,
    marker: PhantomData<T>,
}
impl<T: Table, C> Cursor<T, C> {
    pub(super) fn new(inner: C, rows: Option<Rows>) -> Self {
        Self {
            inner,
            rows,
            position: None,
            marker: PhantomData,
        }
    }
    fn at(&mut self, position: usize) -> PairResult<T> {
        self.position = Some(position);
        self.row()
    }
    fn row(&self) -> PairResult<T> {
        self.position
            .and_then(|i| self.rows.as_ref()?.get(i))
            .map(|(key, value)| Ok((T::Key::decode(key)?, T::Value::decompress(value)?)))
            .transpose()
    }
}
impl<T: Table, C: DbCursorRO<T>> DbCursorRO<T> for Cursor<T, C> {
    fn first(&mut self) -> PairResult<T> {
        if self.rows.is_none() {
            return self.inner.first();
        }
        self.at(0)
    }
    fn last(&mut self) -> PairResult<T> {
        let Some(rows) = &self.rows else {
            return self.inner.last();
        };
        self.at(rows.len().saturating_sub(1))
    }
    fn current(&mut self) -> PairResult<T> {
        if self.rows.is_none() {
            return self.inner.current();
        }
        self.row()
    }
    fn seek(&mut self, key: T::Key) -> PairResult<T> {
        let Some(rows) = &self.rows else {
            return self.inner.seek(key);
        };
        let key = key.encode();
        self.at(rows.partition_point(|(k, _)| k.as_slice() < key.as_ref()))
    }
    fn seek_exact(&mut self, key: T::Key) -> PairResult<T> {
        if self.rows.is_none() {
            return self.inner.seek_exact(key);
        }
        let row = self.seek(key.clone())?.filter(|(k, _)| *k == key);
        if row.is_none() {
            self.position = Some(self.rows.as_ref().unwrap().len());
        }
        Ok(row)
    }
    fn next(&mut self) -> PairResult<T> {
        if self.rows.is_none() {
            return self.inner.next();
        }
        self.at(self.position.map_or(0, |i| i.saturating_add(1)))
    }
    fn prev(&mut self) -> PairResult<T> {
        let Some(rows) = &self.rows else {
            return self.inner.prev();
        };
        match self.position {
            None => self.at(rows.len().saturating_sub(1)),
            Some(0) => Ok(None),
            Some(i) => self.at(i.saturating_sub(1).min(rows.len().saturating_sub(1))),
        }
    }
    fn walk(&mut self, start_key: Option<T::Key>) -> Result<Walker<'_, T, Self>, DatabaseError> {
        let start = match start_key {
            Some(k) => self.seek(k),
            None => self.first(),
        }?;
        Ok(Walker::new(self, start.map(Ok)))
    }
    fn walk_back(
        &mut self,
        start_key: Option<T::Key>,
    ) -> Result<ReverseWalker<'_, T, Self>, DatabaseError> {
        let start = match start_key {
            Some(k) => self.seek(k),
            None => self.last(),
        }?;
        Ok(ReverseWalker::new(self, start.map(Ok)))
    }
    fn walk_range(
        &mut self,
        range: impl RangeBounds<T::Key>,
    ) -> Result<RangeWalker<'_, T, Self>, DatabaseError> {
        let start = match range.start_bound() {
            Bound::Unbounded => self.first()?,
            Bound::Included(k) => self.seek(k.clone())?,
            Bound::Excluded(k) => {
                let mut row = self.seek(k.clone())?;
                while row.as_ref().is_some_and(|(key, _)| key == k) {
                    row = self.next()?;
                }
                row
            }
        };
        Ok(RangeWalker::new(
            self,
            start.map(Ok),
            range.end_bound().cloned(),
        ))
    }
}
impl<T: DupSort, C: DbDupCursorRO<T> + DbCursorRO<T>> DbDupCursorRO<T> for Cursor<T, C> {
    fn next_dup(&mut self) -> PairResult<T> {
        let Some(rows) = &self.rows else {
            return self.inner.next_dup();
        };
        let Some(i) = self.position else {
            return Ok(None);
        };
        if rows
            .get(i)
            .zip(rows.get(i + 1))
            .is_some_and(|(a, b)| a.0 == b.0)
        {
            self.at(i + 1)
        } else {
            Ok(None)
        }
    }
    fn prev_dup(&mut self) -> PairResult<T> {
        let Some(rows) = &self.rows else {
            return self.inner.prev_dup();
        };
        let Some(i) = self.position.filter(|i| *i > 0) else {
            return Ok(None);
        };
        if rows
            .get(i)
            .zip(rows.get(i - 1))
            .is_some_and(|(a, b)| a.0 == b.0)
        {
            self.at(i - 1)
        } else {
            Ok(None)
        }
    }
    fn last_dup(&mut self) -> ValueOnlyResult<T> {
        let Some(rows) = &self.rows else {
            return self.inner.last_dup();
        };
        let Some((key, _)) = self.position.and_then(|i| rows.get(i)) else {
            return Ok(None);
        };
        let i = rows.partition_point(|(k, _)| k <= key).saturating_sub(1);
        Ok(self.at(i)?.map(|(_, v)| v))
    }
    fn next_no_dup(&mut self) -> PairResult<T> {
        let Some(rows) = &self.rows else {
            return self.inner.next_no_dup();
        };
        let Some((key, _)) = self.position.and_then(|i| rows.get(i)) else {
            return if self.position.is_none() {
                self.first()
            } else {
                Ok(None)
            };
        };
        self.at(rows.partition_point(|(k, _)| k <= key))
    }
    fn next_dup_val(&mut self) -> ValueOnlyResult<T> {
        Ok(self.next_dup()?.map(|(_, v)| v))
    }
    fn seek_by_key_subkey(&mut self, key: T::Key, subkey: T::SubKey) -> ValueOnlyResult<T> {
        let Some(rows) = &self.rows else {
            return self.inner.seek_by_key_subkey(key, subkey);
        };
        let key = key.encode();
        let subkey = subkey.encode();
        // StorageEntry's encoding starts with its uncompressed 32-byte slot key.
        let i = rows.partition_point(|(k, v)| {
            k.as_slice() < key.as_ref()
                || (k.as_slice() == key.as_ref() && &v[..32] < subkey.as_ref())
        });
        self.position = Some(i);
        if rows
            .get(i)
            .is_some_and(|(k, _)| k.as_slice() == key.as_ref())
        {
            Ok(self.row()?.map(|(_, v)| v))
        } else {
            self.position = Some(rows.len());
            Ok(None)
        }
    }
    fn walk_dup(
        &mut self,
        key: Option<T::Key>,
        subkey: Option<T::SubKey>,
    ) -> Result<DupWalker<'_, T, Self>, DatabaseError> {
        let start = match (key, subkey) {
            (None, None) => self.first()?,
            (Some(k), None) => self.seek_exact(k)?,
            (Some(k), Some(s)) => self.seek_by_key_subkey(k.clone(), s)?.map(|v| (k, v)),
            (None, Some(s)) => match self.first()? {
                Some((k, _)) => self.seek_by_key_subkey(k.clone(), s)?.map(|v| (k, v)),
                None => None,
            },
        };
        Ok(DupWalker {
            cursor: self,
            start: start.map(Ok),
        })
    }
}
