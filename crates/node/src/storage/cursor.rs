use super::View;
use alloy_primitives::{B256, U256};
use reth_db_api::{
    DatabaseError,
    common::{PairResult, ValueOnlyResult},
    cursor::{DbCursorRO, DbDupCursorRO, DupWalker, RangeWalker, ReverseWalker, Walker},
    table::{Compress, Decode, Decompress, DupSort, Encode, Table},
};
use reth_primitives_traits::StorageEntry;
use std::{
    marker::PhantomData,
    ops::{Bound, RangeBounds},
    sync::Arc,
};

/// Merges the precompile's immutable snapshot with a native database cursor.
#[derive(Debug)]
pub struct Cursor<T, C> {
    pub(super) inner: C,
    view: Option<Arc<View>>,
    virtual_row: Option<(B256, U256)>,
    virtual_position: bool,
    marker: PhantomData<T>,
}
impl<T: Table, C> Cursor<T, C> {
    pub(super) fn new(inner: C, view: Option<Arc<View>>) -> Self {
        Self {
            inner,
            view,
            virtual_row: None,
            virtual_position: false,
            marker: PhantomData,
        }
    }
    fn address() -> B256 {
        *super::HASHED_ADDRESS
    }
    fn is_target(key: &T::Key) -> bool {
        key.clone().encode().as_ref() == Self::address().as_slice()
    }
    fn virtual_at(&mut self, row: Option<(B256, U256)>) -> PairResult<T> {
        self.virtual_position = true;
        self.virtual_row = row;
        row.map(|(key, value)| {
            Ok((
                T::Key::decode(Self::address().as_slice())?,
                T::Value::decompress(StorageEntry { key, value }.compress().as_ref())?,
            ))
        })
        .transpose()
    }
    fn edge(&self, first: bool) -> Result<Option<(B256, U256)>, DatabaseError> {
        let Some(view) = &self.view else {
            return Ok(None);
        };
        let slots = &view.snapshot()?.slots;
        Ok(if first {
            slots.iter().next()
        } else {
            slots.iter().next_back()
        }
        .map(|(&key, &value)| (key, value)))
    }
}
impl<T: Table, C: DbCursorRO<T>> Cursor<T, C> {
    fn after_virtual(&mut self) -> PairResult<T> {
        self.virtual_position = false;
        self.virtual_row = None;
        let mut address = Self::address();
        // This fixed address cannot overflow.
        address.0[31] += 1;
        self.inner.seek(T::Key::decode(address.as_slice())?)
    }
    fn before_virtual(&mut self) -> PairResult<T> {
        self.virtual_position = false;
        self.virtual_row = None;
        if self
            .inner
            .seek(T::Key::decode(Self::address().as_slice())?)?
            .is_some()
        {
            self.inner.prev()
        } else {
            self.inner.last()
        }
    }
    fn merge(&mut self, row: Option<(T::Key, T::Value)>, forward: bool) -> PairResult<T> {
        if self.view.is_none() {
            return Ok(row);
        }
        let beyond = row.as_ref().is_none_or(|(key, _)| {
            let key = key.clone().encode();
            if forward {
                key.as_ref() >= Self::address().as_slice()
            } else {
                key.as_ref() <= Self::address().as_slice()
            }
        });
        if beyond {
            if let Some(slot) = self.edge(forward)? {
                return self.virtual_at(Some(slot));
            }
            if row.as_ref().is_some_and(|(key, _)| Self::is_target(key)) {
                return if forward {
                    self.after_virtual()
                } else {
                    self.before_virtual()
                };
            }
        }
        self.virtual_position = false;
        self.virtual_row = None;
        Ok(row)
    }
}
impl<T: Table, C: DbCursorRO<T>> DbCursorRO<T> for Cursor<T, C> {
    fn first(&mut self) -> PairResult<T> {
        self.virtual_position = false;
        self.virtual_row = None;
        let row = self.inner.first()?;
        self.merge(row, true)
    }
    fn last(&mut self) -> PairResult<T> {
        self.virtual_position = false;
        self.virtual_row = None;
        let row = self.inner.last()?;
        self.merge(row, false)
    }
    fn current(&mut self) -> PairResult<T> {
        if self.virtual_position {
            self.virtual_at(self.virtual_row)
        } else {
            Ok(self
                .inner
                .current()?
                .filter(|(key, _)| self.view.is_none() || !Self::is_target(key)))
        }
    }
    fn seek(&mut self, key: T::Key) -> PairResult<T> {
        if self.view.is_none() {
            return self.inner.seek(key);
        }
        self.virtual_position = false;
        self.virtual_row = None;
        let can_cross = key.clone().encode().as_ref() <= Self::address().as_slice();
        let row = self.inner.seek(key)?;
        if can_cross {
            self.merge(row, true)
        } else {
            Ok(row)
        }
    }
    fn seek_exact(&mut self, key: T::Key) -> PairResult<T> {
        self.virtual_position = false;
        self.virtual_row = None;
        if self.view.is_some() && Self::is_target(&key) {
            return self.virtual_at(self.edge(true)?);
        }
        self.inner.seek_exact(key)
    }
    fn next(&mut self) -> PairResult<T> {
        if self.view.is_none() {
            return self.inner.next();
        }
        if self.virtual_position && self.virtual_row.is_none() {
            return self.after_virtual();
        }
        if let Some((slot, _)) = self.virtual_row {
            let next = self
                .view
                .as_ref()
                .unwrap()
                .snapshot()?
                .slots
                .range((Bound::Excluded(slot), Bound::Unbounded))
                .next()
                .map(|(&key, &value)| (key, value));
            return if next.is_some() {
                self.virtual_at(next)
            } else {
                self.after_virtual()
            };
        }
        let can_cross = self
            .inner
            .current()?
            .is_none_or(|(key, _)| key.encode().as_ref() <= Self::address().as_slice());
        let row = self.inner.next()?;
        if can_cross {
            self.merge(row, true)
        } else {
            Ok(row)
        }
    }
    fn prev(&mut self) -> PairResult<T> {
        if self.view.is_none() {
            return self.inner.prev();
        }
        if self.virtual_position && self.virtual_row.is_none() {
            let last = self.edge(false)?;
            return if last.is_some() {
                self.virtual_at(last)
            } else {
                self.before_virtual()
            };
        }
        if let Some((slot, _)) = self.virtual_row {
            let prev = self
                .view
                .as_ref()
                .unwrap()
                .snapshot()?
                .slots
                .range(..slot)
                .next_back()
                .map(|(&key, &value)| (key, value));
            return if prev.is_some() {
                self.virtual_at(prev)
            } else {
                self.before_virtual()
            };
        }
        let can_cross = self
            .inner
            .current()?
            .is_none_or(|(key, _)| key.encode().as_ref() >= Self::address().as_slice());
        let row = self.inner.prev()?;
        if can_cross {
            self.merge(row, false)
        } else {
            Ok(row)
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
        let Some((slot, _)) = self.virtual_row else {
            return if self.virtual_position {
                Ok(None)
            } else {
                self.inner.next_dup()
            };
        };
        let next = self
            .view
            .as_ref()
            .unwrap()
            .snapshot()?
            .slots
            .range((Bound::Excluded(slot), Bound::Unbounded))
            .next()
            .map(|(&key, &value)| (key, value));
        if next.is_some() {
            self.virtual_at(next)
        } else {
            Ok(None)
        }
    }
    fn prev_dup(&mut self) -> PairResult<T> {
        let Some((slot, _)) = self.virtual_row else {
            return if self.virtual_position {
                Ok(None)
            } else {
                self.inner.prev_dup()
            };
        };
        let prev = self
            .view
            .as_ref()
            .unwrap()
            .snapshot()?
            .slots
            .range(..slot)
            .next_back()
            .map(|(&key, &value)| (key, value));
        if prev.is_some() {
            self.virtual_at(prev)
        } else {
            Ok(None)
        }
    }
    fn last_dup(&mut self) -> ValueOnlyResult<T> {
        if self.virtual_position && self.virtual_row.is_none() {
            return Ok(None);
        }
        if self.virtual_row.is_some() {
            let last = self.edge(false)?;
            Ok(self.virtual_at(last)?.map(|(_, v)| v))
        } else {
            self.inner.last_dup()
        }
    }
    fn next_no_dup(&mut self) -> PairResult<T> {
        if self.view.is_none() {
            return self.inner.next_no_dup();
        }
        if self.virtual_position {
            return self.after_virtual();
        }
        let can_cross = self
            .inner
            .current()?
            .is_none_or(|(key, _)| key.encode().as_ref() <= Self::address().as_slice());
        let row = self.inner.next_no_dup()?;
        if can_cross {
            self.merge(row, true)
        } else {
            Ok(row)
        }
    }
    fn next_dup_val(&mut self) -> ValueOnlyResult<T> {
        Ok(self.next_dup()?.map(|(_, v)| v))
    }
    fn seek_by_key_subkey(&mut self, key: T::Key, subkey: T::SubKey) -> ValueOnlyResult<T> {
        self.virtual_position = false;
        self.virtual_row = None;
        if self.view.is_some() && Self::is_target(&key) {
            let subkey = B256::from_slice(subkey.encode().as_ref());
            let slot = self
                .view
                .as_ref()
                .unwrap()
                .snapshot()?
                .slots
                .range(subkey..)
                .next()
                .map(|(&key, &value)| (key, value));
            return Ok(self.virtual_at(slot)?.map(|(_, v)| v));
        }
        self.inner.seek_by_key_subkey(key, subkey)
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
