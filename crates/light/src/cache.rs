//! Bounded, disposable raw-value cache; authentication precedes all publication.

use std::num::NonZeroU32;

use alloy_consensus::BlockHeader as _;
use alloy_primitives::{Address, B256};
use alloy_trie::TrieAccount;
use schnellru::{ByLength, LruMap};

use crate::{
    Snapshot,
    proof::{StorageReadKey, VerifiedBatch, account_storage_root},
};

/// Root-keyed cache for one light-client instance and its configured proof semantics.
///
/// Raw words are reusable across skipped heads only after an account proof authenticates the same
/// storage root against the selected snapshot's state root. Root and value caches are independently
/// bounded by entry count; neither is an archive or persistence mechanism. Dropping cache entries
/// does not invalidate snapshots or proof batches held by in-flight readers.
pub struct VerifiedCache {
    accounts: LruMap<(B256, Address), Option<TrieAccount>>,
    slots: LruMap<(StorageReadKey, B256), B256>,
}

impl VerifiedCache {
    pub fn new(account_capacity: NonZeroU32, slot_capacity: NonZeroU32) -> Self {
        Self {
            accounts: LruMap::new(ByLength::new(account_capacity.get())),
            slots: LruMap::new(ByLength::new(slot_capacity.get())),
        }
    }

    /// Publish a complete batch after validating its snapshot binding and all existing conflicts.
    /// On failure neither cache changes, including LRU order. Untrusted evidence cannot be passed
    /// to this method: only the pure proof verifier can construct a `VerifiedBatch`.
    pub fn commit(&mut self, snapshot: &Snapshot, batch: &VerifiedBatch) -> Result<(), Error> {
        if snapshot.header().state_root() != batch.state_root() {
            return Err(Error::WrongSnapshot);
        }
        for (&address, verified) in batch.accounts() {
            let account = verified.account().copied();
            if self
                .accounts
                .peek(&(batch.state_root(), address))
                .is_some_and(|cached| *cached != account)
            {
                return Err(Error::ConflictingAccount);
            }
            let root = verified.storage_root();
            for (&slot, &value) in verified.slots() {
                let key = (
                    StorageReadKey {
                        account: address,
                        slot,
                    },
                    root,
                );
                if self.slots.peek(&key).is_some_and(|cached| *cached != value) {
                    return Err(Error::ConflictingValue);
                }
            }
        }
        for (&address, verified) in batch.accounts() {
            self.accounts
                .insert((batch.state_root(), address), verified.account().copied());
            for (&slot, &value) in verified.slots() {
                self.slots.insert(
                    (
                        StorageReadKey {
                            account: address,
                            slot,
                        },
                        verified.storage_root(),
                    ),
                    value,
                );
            }
        }
        Ok(())
    }

    /// Outer None is a cache miss; inner None is proved complete account non-membership.
    pub fn account(
        &mut self,
        snapshot: &Snapshot,
        address: Address,
    ) -> Option<Option<TrieAccount>> {
        self.accounts
            .get(&(snapshot.header().state_root(), address))
            .copied()
    }

    pub fn get(&mut self, snapshot: &Snapshot, key: StorageReadKey) -> Option<B256> {
        let account = self
            .accounts
            .get(&(snapshot.header().state_root(), key.account))?;
        let root = account_storage_root(account.as_ref());
        self.slots.get(&(key, root)).copied()
    }

    /// Number of retained account-root mappings and raw slot values.
    pub fn entry_counts(&self) -> (usize, usize) {
        (self.accounts.len(), self.slots.len())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("proof batch is not bound to the selected authenticated snapshot")]
    WrongSnapshot,
    #[error("conflicting authenticated account metadata")]
    ConflictingAccount,
    #[error("conflicting authenticated raw storage values")]
    ConflictingValue,
}
