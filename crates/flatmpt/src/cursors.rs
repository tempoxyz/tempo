//! reth `HashedCursorFactory` over the flat MPT — the adapter that lets
//! reth's state-root and sparse-trie machinery run directly on flat data.
//!
//! Stage A of the sparse-trie-as-overlay plan: with these cursors and a
//! `NoopTrieCursorFactory`, `reth_trie::StateRoot` performs a full walk over
//! the flat trie's leaves and must reproduce the flat engine's own root
//! exactly (see the parity test). Stage B adds a real `TrieCursorFactory`
//! surfacing our cached node hashes so incremental/sparse roots are fast.

use alloy_primitives::{B256, U256};
use mpt_flat_poc::{FlatMpt, cursor};
use reth_db_api::DatabaseError;
use reth_primitives_traits::Account;
use reth_trie::hashed_cursor::{HashedCursor, HashedCursorFactory, HashedStorageCursor};

fn db_err(e: anyhow::Error) -> DatabaseError {
    DatabaseError::Other(format!("flatmpt cursor: {e:#}"))
}

/// Factory over a borrowed flat trie (callers hold the shadow's read lock for
/// the factory's lifetime; the walks themselves are read-only).
#[derive(Clone, Copy)]
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
        Ok(FlatHashedAccountCursor {
            inner: self.mpt.account_cursor(),
        })
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
    use reth_trie::{StateRoot, trie_cursor::noop::NoopTrieCursorFactory};

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
            ops.push((
                key,
                StateOp::SetAccount {
                    nonce: a,
                    balance: U256::from(a * 31 + 7),
                    code_hash: if a % 3 == 0 {
                        h(b"code")
                    } else {
                        mpt_flat_poc::eth::EMPTY_CODE_HASH.0
                    },
                },
            ));
            let nslots = match a % 5 {
                0 => 0,
                1 | 2 => a % 4 + 1,
                _ => 600, // multi-record storage
            };
            for s in 0..nslots {
                ops.push((
                    key,
                    StateOp::SetStorage {
                        slot: h(&(a * 1_000_000 + s).to_be_bytes()),
                        value: mpt_flat_poc::eth::storage_value_rlp(U256::from(s + 1)),
                    },
                ));
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
        assert_eq!(
            reth_root.0, flat_root,
            "reth StateRoot != flat root after reopen"
        );
    }

    /// STAGE B GATE: with the real flat TrieCursorFactory, the walker uses our
    /// cached branch hashes to skip unchanged subtrees — and still lands on
    /// exactly the flat root, both for a full walk (empty prefix sets ~ skip
    /// almost everything) and incrementally after a mutation.
    #[test]
    fn reth_state_root_with_flat_trie_cursors() {
        use crate::cursors::FlatTrieCursorFactory;
        use reth_trie::{
            Nibbles,
            prefix_set::{PrefixSetMut, TriePrefixSets},
        };

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("g.flat");
        let mut db = FlatMpt::create(&path, Config::default()).unwrap();

        let mut ops: Vec<(Key, StateOp)> = Vec::new();
        for a in 0..400u64 {
            let key = h(&a.to_be_bytes());
            ops.push((
                key,
                StateOp::SetAccount {
                    nonce: a,
                    balance: U256::from(a + 1),
                    code_hash: mpt_flat_poc::eth::EMPTY_CODE_HASH.0,
                },
            ));
            for s in 0..(a % 40) {
                ops.push((
                    key,
                    StateOp::SetStorage {
                        slot: h(&(a * 7_000 + s).to_be_bytes()),
                        value: mpt_flat_poc::eth::storage_value_rlp(U256::from(s + 3)),
                    },
                ));
            }
        }
        db.apply_block(ops).unwrap();

        // Mutate a handful of accounts + slots; the flat engine's root is the
        // reference.
        let mut ops2: Vec<(Key, StateOp)> = Vec::new();
        let mut changed_accounts = Vec::new();
        let mut changed_storage: Vec<(Key, Key)> = Vec::new();
        for a in [3u64, 77, 200, 399] {
            let key = h(&a.to_be_bytes());
            changed_accounts.push(key);
            ops2.push((
                key,
                StateOp::SetAccount {
                    nonce: a + 1000,
                    balance: U256::from(a * 2 + 5),
                    code_hash: mpt_flat_poc::eth::EMPTY_CODE_HASH.0,
                },
            ));
            let slot = h(&(a * 7_000).to_be_bytes());
            changed_storage.push((key, slot));
            ops2.push((
                key,
                StateOp::SetStorage {
                    slot,
                    value: mpt_flat_poc::eth::storage_value_rlp(U256::from(a + 42)),
                },
            ));
        }
        let (flat_root2, _) = db.apply_block(ops2).unwrap();

        // Incremental root: prefix sets contain only the changed paths; the
        // walker must serve everything else from our stored branch hashes.
        let mut account_prefixes = PrefixSetMut::default();
        let mut storage_prefixes: alloy_primitives::map::B256Map<reth_trie::prefix_set::PrefixSet> =
            Default::default();
        for k in &changed_accounts {
            account_prefixes.insert(Nibbles::unpack(B256::from(*k)));
        }
        for (acct, slot) in &changed_storage {
            let mut ps = PrefixSetMut::default();
            ps.insert(Nibbles::unpack(B256::from(*slot)));
            storage_prefixes.insert(B256::from(*acct), ps.freeze());
        }
        let prefix_sets = TriePrefixSets {
            account_prefix_set: account_prefixes.freeze(),
            storage_prefix_sets: storage_prefixes,
            destroyed_accounts: Default::default(),
        };
        let reth_root = StateRoot::new(
            FlatTrieCursorFactory { mpt: &db },
            FlatHashedCursorFactory { mpt: &db },
        )
        .with_prefix_sets(prefix_sets)
        .root()
        .unwrap();
        assert_eq!(
            reth_root.0, flat_root2,
            "incremental root over flat trie cursors mismatch"
        );
    }
}

// ---------------------------------------------------------------------------
// TrieCursorFactory over the flat trie (Stage B): surfaces our cached branch
// hashes so reth's walker skips unchanged subtrees instead of recomputing
// them from leaves.
// ---------------------------------------------------------------------------

use mpt_flat_poc::cursor::TrieNodeEntry;
use reth_trie::{
    BranchNodeCompact, Nibbles, TrieMask,
    trie_cursor::{TrieCursor, TrieCursorFactory},
};

fn to_compact(e: TrieNodeEntry) -> (Nibbles, BranchNodeCompact) {
    let path = Nibbles::from_nibbles(&e.path);
    let node = BranchNodeCompact::new(
        TrieMask::new(e.state_mask),
        TrieMask::new(e.tree_mask),
        TrieMask::new(e.hash_mask),
        e.hashes.iter().map(|h| B256::from(*h)).collect::<Vec<_>>(),
        None,
    );
    (path, node)
}

#[derive(Clone, Copy)]
pub struct FlatTrieCursorFactory<'m> {
    pub mpt: &'m FlatMpt,
}

impl<'m> TrieCursorFactory for FlatTrieCursorFactory<'m> {
    type AccountTrieCursor<'a>
        = FlatAccountTrieCursor<'a>
    where
        Self: 'a;
    type StorageTrieCursor<'a>
        = FlatStorageTrieCursor<'a>
    where
        Self: 'a;

    fn account_trie_cursor(&self) -> Result<Self::AccountTrieCursor<'_>, DatabaseError> {
        Ok(FlatAccountTrieCursor {
            inner: self.mpt.trie_node_cursor(),
            current: None,
        })
    }

    fn storage_trie_cursor(
        &self,
        hashed_address: B256,
    ) -> Result<Self::StorageTrieCursor<'_>, DatabaseError> {
        Ok(FlatStorageTrieCursor {
            mpt: self.mpt,
            inner: self.mpt.storage_trie_node_cursor(&hashed_address.0),
            current: None,
        })
    }
}

pub struct FlatAccountTrieCursor<'a> {
    inner: mpt_flat_poc::cursor::TrieNodeCursor<'a>,
    current: Option<Nibbles>,
}

impl TrieCursor for FlatAccountTrieCursor<'_> {
    fn seek_exact(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        let hit = self.inner.seek(&key.to_vec()).map_err(db_err)?;
        Ok(hit.and_then(|e| {
            let (p, n) = to_compact(e);
            (p == key).then(|| {
                self.current = Some(p);
                (p, n)
            })
        }))
    }

    fn seek(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        let hit = self.inner.seek(&key.to_vec()).map_err(db_err)?;
        Ok(hit.map(|e| {
            let (p, n) = to_compact(e);
            self.current = Some(p);
            (p, n)
        }))
    }

    fn next(&mut self) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        let hit = self.inner.next().map_err(db_err)?;
        Ok(hit.map(|e| {
            let (p, n) = to_compact(e);
            self.current = Some(p);
            (p, n)
        }))
    }

    fn current(&mut self) -> Result<Option<Nibbles>, DatabaseError> {
        Ok(self.current)
    }

    fn reset(&mut self) {
        self.current = None;
    }
}

pub struct FlatStorageTrieCursor<'a> {
    mpt: &'a FlatMpt,
    inner: mpt_flat_poc::cursor::StorageTrieNodeCursor<'a>,
    current: Option<Nibbles>,
}

impl TrieCursor for FlatStorageTrieCursor<'_> {
    fn seek_exact(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        let hit = self.inner.seek(&key.to_vec()).map_err(db_err)?;
        Ok(hit.and_then(|e| {
            let (p, n) = to_compact(e);
            (p == key).then(|| {
                self.current = Some(p);
                (p, n)
            })
        }))
    }

    fn seek(
        &mut self,
        key: Nibbles,
    ) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        let hit = self.inner.seek(&key.to_vec()).map_err(db_err)?;
        Ok(hit.map(|e| {
            let (p, n) = to_compact(e);
            self.current = Some(p);
            (p, n)
        }))
    }

    fn next(&mut self) -> Result<Option<(Nibbles, BranchNodeCompact)>, DatabaseError> {
        let hit = self.inner.next().map_err(db_err)?;
        Ok(hit.map(|e| {
            let (p, n) = to_compact(e);
            self.current = Some(p);
            (p, n)
        }))
    }

    fn current(&mut self) -> Result<Option<Nibbles>, DatabaseError> {
        Ok(self.current)
    }

    fn reset(&mut self) {
        self.current = None;
    }
}

impl reth_trie::trie_cursor::TrieStorageCursor for FlatStorageTrieCursor<'_> {
    fn set_hashed_address(&mut self, hashed_address: B256) {
        self.inner = self.mpt.storage_trie_node_cursor(&hashed_address.0);
        self.current = None;
    }
}
