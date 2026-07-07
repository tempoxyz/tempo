//! reth `HashedCursorFactory` over the flat MPT — the adapter that lets
//! reth's state-root and sparse-trie machinery run directly on flat data.
//!
//! Stage A of the sparse-trie-as-overlay plan: with these cursors and a
//! `NoopTrieCursorFactory`, `reth_trie::StateRoot` performs a full walk over
//! the flat trie's leaves and must reproduce the flat engine's own root
//! exactly (see the parity test). Stage B adds a real `TrieCursorFactory`
//! surfacing our cached node hashes so incremental/sparse roots are fast.

use alloy_primitives::{B256, U256};
use mpt_flat_poc::{cursor, FlatMpt};
use reth_db_api::DatabaseError;
use reth_primitives_traits::Account;
use reth_trie::hashed_cursor::{HashedCursor, HashedCursorFactory, HashedStorageCursor};

fn db_err(e: anyhow::Error) -> DatabaseError {
    DatabaseError::Other(format!("flatmpt cursor: {e:#}"))
}

/// Factory over a borrowed flat trie (callers hold the shadow's read lock for
/// the factory's lifetime; the walks themselves are read-only).
pub struct FlatHashedCursorFactory<'m> {
    pub mpt: &'m FlatMpt,
}

impl<'m> HashedCursorFactory for FlatHashedCursorFactory<'m> {
    type AccountCursor<'a>
        = FlatHashedAccountCursor<'a>
    where
        Self: 'a;
    type StorageCursor<'a>
        = FlatHashedStorageCursor<'a>
    where
        Self: 'a;

    fn hashed_account_cursor(&self) -> Result<Self::AccountCursor<'_>, DatabaseError> {
        Ok(FlatHashedAccountCursor { inner: self.mpt.account_cursor() })
    }

    fn hashed_storage_cursor(
        &self,
        hashed_address: B256,
    ) -> Result<Self::StorageCursor<'_>, DatabaseError> {
        Ok(FlatHashedStorageCursor {
            mpt: self.mpt,
            hashed_address: hashed_address.0,
            inner: self.mpt.storage_cursor(&hashed_address.0),
        })
    }
}

pub struct FlatHashedAccountCursor<'a> {
    inner: cursor::AccountCursor<'a>,
}

fn to_reth_account(e: cursor::AccountEntry) -> Account {
    Account {
        nonce: e.nonce,
        balance: e.balance,
        bytecode_hash: (e.code_hash != mpt_flat_poc::eth::EMPTY_CODE_HASH.0)
            .then(|| B256::from(e.code_hash)),
    }
}

impl HashedCursor for FlatHashedAccountCursor<'_> {
    type Value = Account;

    fn seek(&mut self, key: B256) -> Result<Option<(B256, Account)>, DatabaseError> {
        Ok(self
            .inner
            .seek(&key.0)
            .map_err(db_err)?
            .map(|e| (B256::from(e.key), to_reth_account(e))))
    }

    fn next(&mut self) -> Result<Option<(B256, Account)>, DatabaseError> {
        Ok(self
            .inner
            .next()
            .map_err(db_err)?
            .map(|e| (B256::from(e.key), to_reth_account(e))))
    }

    fn reset(&mut self) {}
}

pub struct FlatHashedStorageCursor<'a> {
    mpt: &'a FlatMpt,
    hashed_address: [u8; 32],
    inner: cursor::StorageCursor<'a>,
}

fn decode_slot(v: Vec<u8>) -> Result<U256, DatabaseError> {
    use alloy_rlp::Decodable as _;
    let mut buf = v.as_slice();
    U256::decode(&mut buf).map_err(|e| DatabaseError::Other(format!("slot RLP: {e}")))
}

impl HashedCursor for FlatHashedStorageCursor<'_> {
    type Value = U256;

    fn seek(&mut self, key: B256) -> Result<Option<(B256, U256)>, DatabaseError> {
        match self.inner.seek(&key.0).map_err(db_err)? {
            Some((k, v)) => Ok(Some((B256::from(k), decode_slot(v)?))),
            None => Ok(None),
        }
    }

    fn next(&mut self) -> Result<Option<(B256, U256)>, DatabaseError> {
        match self.inner.next().map_err(db_err)? {
            Some((k, v)) => Ok(Some((B256::from(k), decode_slot(v)?))),
            None => Ok(None),
        }
    }

    fn reset(&mut self) {}
}

impl HashedStorageCursor for FlatHashedStorageCursor<'_> {
    fn is_storage_empty(&mut self) -> Result<bool, DatabaseError> {
        let mut probe = self.mpt.storage_cursor(&self.hashed_address);
        Ok(probe.seek(&[0u8; 32]).map_err(db_err)?.is_none())
    }

    fn set_hashed_address(&mut self, hashed_address: B256) {
        self.hashed_address = hashed_address.0;
        self.inner = self.mpt.storage_cursor(&hashed_address.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::keccak256;
    use mpt_flat_poc::{Config, Key, StateOp};
    use reth_trie::trie_cursor::noop::NoopTrieCursorFactory;
    use reth_trie::StateRoot;

    fn h(data: &[u8]) -> Key {
        keccak256(data).0
    }

    /// STAGE A GATE: reth's StateRoot over flat-backed hashed cursors (noop
    /// trie cursors = full walk) must equal the flat engine's own root.
    #[test]
    fn reth_state_root_matches_flat_root() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("g.flat");
        let mut db = FlatMpt::create(&path, Config::default()).unwrap();

        let mut ops: Vec<(Key, StateOp)> = Vec::new();
        for a in 0..500u64 {
            let key = h(&a.to_be_bytes());
            ops.push((key, StateOp::SetAccount {
                nonce: a,
                balance: U256::from(a * 31 + 7),
                code_hash: if a % 3 == 0 { h(b"code") } else { mpt_flat_poc::eth::EMPTY_CODE_HASH.0 },
            }));
            let nslots = match a % 5 {
                0 => 0,
                1 | 2 => a % 4 + 1,
                _ => 600, // multi-record storage
            };
            for s in 0..nslots {
                ops.push((key, StateOp::SetStorage {
                    slot: h(&(a * 1_000_000 + s).to_be_bytes()),
                    value: mpt_flat_poc::eth::storage_value_rlp(U256::from(s + 1)),
                }));
            }
        }
        let (flat_root, _) = db.apply_block(ops).unwrap();

        let factory = FlatHashedCursorFactory { mpt: &db };
        let reth_root = StateRoot::new(NoopTrieCursorFactory::default(), factory)
            .root()
            .unwrap();
        assert_eq!(reth_root.0, flat_root, "reth StateRoot != flat root");

        // Repeat after persist + reopen (all state in disk records).
        db.persist().unwrap();
        drop(db);
        let db = FlatMpt::open(&path).unwrap();
        let factory = FlatHashedCursorFactory { mpt: &db };
        let reth_root = StateRoot::new(NoopTrieCursorFactory::default(), factory)
            .root()
            .unwrap();
        assert_eq!(reth_root.0, flat_root, "reth StateRoot != flat root after reopen");
    }
}
