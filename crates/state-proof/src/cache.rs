use crate::{
    CompositionError, ProofTargets, StorageReadKey, VerifiedAccount, VerifiedBatch,
    proof::{check_account, check_word, storage_root},
};
use alloy_primitives::{Address, B256};
use alloy_trie::{EMPTY_ROOT_HASH, TrieAccount};
use schnellru::{ByLength, LruMap};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    num::NonZeroU32,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountKey {
    pub state_root: B256,
    pub account: Address,
}

impl AccountKey {
    pub const fn new(state_root: B256, account: Address) -> Self {
        Self {
            state_root,
            account,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheLimits {
    pub accounts: NonZeroU32,
    pub words: NonZeroU32,
    pub max_retained_accounts: u32,
    pub max_publication_batches: NonZeroU32,
    pub max_publication_accounts: NonZeroU32,
    pub max_publication_words: NonZeroU32,
    pub max_retention_updates: NonZeroU32,
}

impl CacheLimits {
    /// Single-batch publication bounded by capacity, without retention.
    pub const fn new(accounts: NonZeroU32, words: NonZeroU32) -> Self {
        Self {
            accounts,
            words,
            max_retained_accounts: 0,
            max_publication_batches: NonZeroU32::MIN,
            max_publication_accounts: accounts,
            max_publication_words: words,
            max_retention_updates: NonZeroU32::MIN,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheResource {
    Batches,
    Accounts,
    Words,
    RetentionUpdates,
}

/// One consumer coordinator owns retention. Keys alone cannot mint authenticated evidence.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RetentionDelta {
    pub retain: BTreeSet<AccountKey>,
    pub release: BTreeSet<AccountKey>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheStats {
    pub accounts: usize,
    pub retained_accounts: usize,
    pub words: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageRootChange {
    pub previous: Option<B256>,
    pub current: B256,
}

impl StorageRootChange {
    /// Missing predecessor evidence conservatively requires invalidation.
    pub fn is_changed(&self) -> bool {
        self.previous != Some(self.current)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("invalid authenticated cache limits")]
    InvalidLimits,
    #[error(transparent)]
    Composition(#[from] CompositionError),
    #[error("cache publication exceeds {0:?} budget")]
    PublicationLimit(CacheResource),
    #[error("account is both retained and released: {0:?}")]
    ConflictingRetention(AccountKey),
    #[error("retention has no authenticated account evidence: {0:?}")]
    MissingRetainedAccount(AccountKey),
    #[error("authenticated account retention capacity exceeded")]
    RetentionLimit,
}

type WordKey = (StorageReadKey, B256);

/// One disposable cache with disjoint retained/evictable mapping partitions. Synchronize outside.
#[derive(Debug)]
pub struct VerifiedCache {
    limits: CacheLimits,
    retained: HashMap<AccountKey, Option<TrieAccount>>,
    evictable: LruMap<AccountKey, Option<TrieAccount>>,
    words: LruMap<WordKey, B256>,
}

impl VerifiedCache {
    pub fn new(limits: CacheLimits) -> Result<Self, CacheError> {
        // u32 links index buckets, not entries. Validate the rounded 8/7-load bucket bound.
        for capacity in [limits.accounts, limits.words] {
            let buckets = (u64::from(capacity.get()) * 8 / 7 + 1).next_power_of_two();
            if buckets > u64::from(u32::MAX) {
                return Err(CacheError::InvalidLimits);
            }
        }
        if limits.max_retained_accounts > limits.accounts.get() {
            return Err(CacheError::InvalidLimits);
        }
        let mut evictable = LruMap::new(ByLength::new(limits.accounts.get()));
        evictable.reserve_or_panic(limits.accounts.get() as usize);
        let mut words = LruMap::new(ByLength::new(limits.words.get()));
        words.reserve_or_panic(limits.words.get() as usize);
        Ok(Self {
            limits,
            retained: HashMap::with_capacity(limits.max_retained_accounts as usize),
            evictable,
            words,
        })
    }

    pub fn stats(&self) -> CacheStats {
        CacheStats {
            accounts: self.retained.len() + self.evictable.len(),
            retained_accounts: self.retained.len(),
            words: self.words.len(),
        }
    }

    /// One root-bound lookup, returning borrowed full metadata and the copied raw word.
    /// A mapping lookup updates evictable recency even when the word is not retained.
    pub fn get(&mut self, root: B256, key: StorageReadKey) -> Option<(&Option<TrieAccount>, B256)> {
        let account_key = AccountKey::new(root, key.account);
        let account = match self.retained.get(&account_key) {
            Some(account) => account,
            None => self.evictable.get(&account_key)?,
        };
        let storage_root = storage_root(account.as_ref());
        let word = if storage_root == EMPTY_ROOT_HASH {
            B256::ZERO
        } else {
            *self.words.get(&(key, storage_root))?
        };
        Some((account, word))
    }

    pub fn peek_account(&self, key: AccountKey) -> Option<&Option<TrieAccount>> {
        self.retained
            .get(&key)
            .or_else(|| self.evictable.peek(&key))
    }

    /// Stage requested evidence without shared mutations; errors leave the batch unchanged.
    pub fn stage(
        &self,
        batch: &mut VerifiedBatch,
        targets: &ProofTargets,
    ) -> Result<ProofTargets, CompositionError> {
        let root = batch.state_root();
        let mut patch = VerifiedBatch::empty(root);
        let mut missing = ProofTargets::new();
        for (&address, requested) in targets {
            let owned = batch.accounts.get(&address);
            let cached = self.peek_account(AccountKey::new(root, address));
            if let (Some(owned), Some(cached)) = (owned, cached) {
                check_account(root, address, owned.account, *cached)?;
            }
            let Some(account) = owned.map(|owned| owned.account).or_else(|| cached.copied()) else {
                missing.insert(address, requested.clone());
                continue;
            };
            let storage_root = storage_root(account.as_ref());
            let mut slots = BTreeMap::new();
            for &slot in requested {
                let key = StorageReadKey::new(address, slot);
                let existing = owned.and_then(|owned| owned.slots.get(&slot));
                let cached = self.words.peek(&(key, storage_root));
                if let Some(&word) = existing {
                    check_word(key, storage_root, cached, word)?;
                    continue;
                }
                let word = cached
                    .copied()
                    .or_else(|| (storage_root == EMPTY_ROOT_HASH).then_some(B256::ZERO));
                match word {
                    Some(word) => {
                        slots.insert(slot, word);
                    }
                    None => {
                        missing.entry(address).or_default().insert(slot);
                    }
                }
            }
            if owned.is_none() || !slots.is_empty() {
                patch
                    .accounts
                    .insert(address, VerifiedAccount { account, slots });
            }
        }
        batch.merge(patch)?;
        Ok(missing)
    }

    /// Atomically publish multiple root-bound batches after consumer-specific acceptance.
    /// All semantic validation is read-only, including LRU order and retention/index state.
    /// Allocator failures are not recoverable transaction errors. Residency is bounded/best-effort
    /// except for explicitly retained mappings; operation-owned evidence always remains valid.
    pub fn publish(
        &mut self,
        batches: &[(B256, &VerifiedBatch)],
        retention: &RetentionDelta,
    ) -> Result<(), CacheError> {
        fn budget(
            total: &mut usize,
            amount: usize,
            limit: NonZeroU32,
            kind: CacheResource,
        ) -> Result<(), CacheError> {
            *total = total
                .checked_add(amount)
                .filter(|count| *count <= limit.get() as usize)
                .ok_or(CacheError::PublicationLimit(kind))?;
            Ok(())
        }
        budget(
            &mut 0,
            batches.len(),
            self.limits.max_publication_batches,
            CacheResource::Batches,
        )?;
        let mut updates = 0;
        for count in [retention.retain.len(), retention.release.len()] {
            budget(
                &mut updates,
                count,
                self.limits.max_retention_updates,
                CacheResource::RetentionUpdates,
            )?;
        }
        let (mut accounts, mut words) = (0, 0);
        for &(root, batch) in batches {
            if root != batch.state_root() {
                return Err(CompositionError::StateRoot {
                    expected: root,
                    actual: batch.state_root(),
                }
                .into());
            }
            budget(
                &mut accounts,
                batch.accounts.len(),
                self.limits.max_publication_accounts,
                CacheResource::Accounts,
            )?;
            for account in batch.accounts.values() {
                budget(
                    &mut words,
                    account.slots.len(),
                    self.limits.max_publication_words,
                    CacheResource::Words,
                )?;
            }
        }
        let mut pending_accounts = BTreeMap::new();
        let mut pending_words = BTreeMap::new();
        for &(root, batch) in batches {
            for (&address, account) in &batch.accounts {
                let key = AccountKey::new(root, address);
                if let Some(previous) = pending_accounts.insert(key, account.account) {
                    check_account(root, address, previous, account.account)?;
                }
                let storage_root = account.storage_root();
                if storage_root == EMPTY_ROOT_HASH {
                    continue;
                }
                for (&slot, &word) in &account.slots {
                    let key = StorageReadKey::new(address, slot);
                    if let Some(previous) = pending_words.insert((key, storage_root), word) {
                        check_word(key, storage_root, Some(&previous), word)?;
                    }
                }
            }
        }
        for (&key, &account) in &pending_accounts {
            if let Some(&existing) = self.peek_account(key) {
                check_account(key.state_root, key.account, existing, account)?;
            }
        }
        for (&(key, root), &word) in &pending_words {
            check_word(key, root, self.words.peek(&(key, root)), word)?;
        }
        for &key in &retention.retain {
            if retention.release.contains(&key) {
                return Err(CacheError::ConflictingRetention(key));
            }
            if !pending_accounts.contains_key(&key) && self.peek_account(key).is_none() {
                return Err(CacheError::MissingRetainedAccount(key));
            }
        }
        let released = retention
            .release
            .iter()
            .filter(|key| self.retained.contains_key(key))
            .count();
        let added = retention
            .retain
            .iter()
            .filter(|key| !self.retained.contains_key(key))
            .count();
        let retained_count = self.retained.len() - released;
        if added > self.limits.max_retained_accounts as usize - retained_count {
            return Err(CacheError::RetentionLimit);
        }

        // All fallible checks have finished. Capture/move pins before admitting anything that
        // could evict a to-be-retained mapping; no full-window scan or cloning.
        // A released mapping is immediately disposable. Drop it rather than accumulating
        // unused historical full metadata in Zones; old-root words remain independently retained.
        for key in &retention.release {
            self.retained.remove(key);
        }
        for &key in &retention.retain {
            if !self.retained.contains_key(&key) {
                let account = pending_accounts
                    .get(&key)
                    .copied()
                    .or_else(|| self.evictable.peek(&key).copied())
                    .expect("retention evidence checked before mutation");
                self.evictable.remove(&key);
                self.retained.insert(key, account);
            }
        }
        let evictable_capacity = self.limits.accounts.get() - self.retained.len() as u32;
        *self.evictable.limiter_mut() = ByLength::new(evictable_capacity);
        while self.evictable.len() > evictable_capacity as usize {
            self.evictable.pop_oldest();
        }
        for (key, account) in pending_accounts {
            if let Some(existing) = self.retained.get_mut(&key) {
                *existing = account;
            } else {
                self.evictable.insert(key, account);
            }
        }
        for (key, word) in pending_words {
            self.words.insert(key, word);
        }
        Ok(())
    }

    /// Compare storage (not full account equality) against the caller-selected predecessor.
    pub fn storage_root_changes(
        &self,
        previous: Option<B256>,
        current: &VerifiedBatch,
    ) -> BTreeMap<Address, StorageRootChange> {
        current
            .accounts()
            .iter()
            .map(|(&address, account)| {
                let previous = previous
                    .and_then(|root| self.peek_account(AccountKey::new(root, address)))
                    .map(|account| storage_root(account.as_ref()));
                (
                    address,
                    StorageRootChange {
                        previous,
                        current: account.storage_root(),
                    },
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    //! Private tests inject conflicts that public verified-evidence APIs cannot construct.
    use super::*;
    use alloy_primitives::U256;

    fn limits(accounts: u32, words: u32) -> CacheLimits {
        CacheLimits {
            accounts: accounts.try_into().unwrap(),
            words: words.try_into().unwrap(),
            max_retained_accounts: accounts,
            max_publication_batches: 32.try_into().unwrap(),
            max_publication_accounts: 100_000.try_into().unwrap(),
            max_publication_words: 100_000.try_into().unwrap(),
            max_retention_updates: 100_000.try_into().unwrap(),
        }
    }
    fn batch(
        global: u64,
        storage: u64,
        slots: impl IntoIterator<Item = (u64, u64)>,
    ) -> VerifiedBatch {
        let mut batch = VerifiedBatch::empty(B256::from(U256::from(global)));
        batch.accounts.insert(
            Address::ZERO,
            VerifiedAccount {
                account: Some(TrieAccount {
                    storage_root: B256::from(U256::from(storage)),
                    nonce: global,
                    ..Default::default()
                }),
                slots: slots
                    .into_iter()
                    .map(|(slot, value)| (read(slot).slot, B256::from(U256::from(value))))
                    .collect(),
            },
        );
        batch
    }
    fn key(batch: &VerifiedBatch) -> AccountKey {
        AccountKey::new(batch.state_root(), Address::ZERO)
    }
    fn read(slot: u64) -> StorageReadKey {
        StorageReadKey::new(Address::ZERO, B256::from(U256::from(slot)))
    }
    fn publish(cache: &mut VerifiedCache, batch: &VerifiedBatch) {
        cache
            .publish(&[(batch.state_root(), batch)], &RetentionDelta::default())
            .unwrap();
    }
    fn assert_bounds(cache: &VerifiedCache) {
        assert!(cache.words.len() <= cache.limits.words.get() as usize);
        assert!(cache.stats().accounts <= cache.limits.accounts.get() as usize);
        assert!(
            cache
                .retained
                .keys()
                .all(|key| cache.evictable.peek(key).is_none())
        );
    }

    #[test]
    fn staging_reuse_and_eviction() {
        let targets =
            ProofTargets::from([(Address::ZERO, BTreeSet::from([read(0).slot, read(1).slot]))]);
        let mut cache = VerifiedCache::new(limits(1, 4)).unwrap();
        let first = batch(1, 10, [(0, 42)]);
        publish(&mut cache, &first);
        let mut owned = batch(2, 10, []);
        assert!(cache.get(owned.state_root(), read(0)).is_none());
        assert!(
            !cache.storage_root_changes(Some(first.state_root()), &owned)[&Address::ZERO]
                .is_changed()
        );
        assert!(cache.storage_root_changes(None, &owned)[&Address::ZERO].is_changed());
        let before = format!("{cache:?}");
        let missing = cache.stage(&mut owned, &targets).unwrap();
        assert_eq!(missing[&Address::ZERO], BTreeSet::from([read(1).slot]));
        assert_eq!(owned.word(read(0)), first.word(read(0)));
        assert_eq!(format!("{cache:?}"), before);
        owned.merge(batch(2, 10, [(1, 43)])).unwrap();
        publish(&mut cache, &owned);
        assert!(cache.peek_account(key(&first)).is_none());
        assert!(cache.get(first.state_root(), read(0)).is_none());
        let mut orphan = batch(1, 10, []);
        assert!(cache.stage(&mut orphan, &targets).unwrap().is_empty());
        assert_eq!(orphan.word(read(0)), first.word(read(0))); // Owned evidence survives mapping eviction.
        let mut changed = batch(3, 11, []);
        assert!(
            cache.storage_root_changes(Some(owned.state_root()), &changed)[&Address::ZERO]
                .is_changed()
        );
        assert_eq!(cache.stage(&mut changed, &targets).unwrap(), targets);

        let word_count = cache.stats().words;
        for (index, account) in [
            None,
            Some(TrieAccount {
                storage_root: EMPTY_ROOT_HASH,
                ..Default::default()
            }),
        ]
        .into_iter()
        .enumerate()
        {
            let root = B256::with_last_byte(4 + index as u8);
            let mut empty = VerifiedBatch::empty(root);
            empty.accounts.insert(
                Address::ZERO,
                VerifiedAccount {
                    account,
                    slots: BTreeMap::new(),
                },
            );
            publish(&mut cache, &empty);
            let mut staged = VerifiedBatch::empty(root);
            assert!(cache.stage(&mut staged, &targets).unwrap().is_empty());
            assert_eq!(
                staged.accounts()[&Address::ZERO].account(),
                account.as_ref()
            );
            assert_eq!(staged.word(read(1)), Some(B256::ZERO));
            publish(&mut cache, &staged);
            assert_eq!(
                cache.get(root, read(2)).map(|(_, word)| word),
                Some(B256::ZERO)
            );
            assert_eq!(cache.stats().words, word_count);
            assert_bounds(&cache);
        }
    }

    #[test]
    fn retained_mappings_survive_churn_and_release_with_replacement() {
        let mut cache = VerifiedCache::new(limits(2, 4)).unwrap();
        let first = batch(1, 10, [(0, 42)]);
        let second = batch(2, 10, []);
        cache
            .publish(
                &[(first.state_root(), &first), (second.state_root(), &second)],
                &RetentionDelta {
                    retain: BTreeSet::from([key(&first), key(&second)]),
                    ..Default::default()
                },
            )
            .unwrap();
        for n in 3..20 {
            publish(&mut cache, &batch(n, 10, []));
        }
        assert_eq!(cache.stats().retained_accounts, 2);
        assert_eq!(
            cache.get(first.state_root(), read(0)).map(|(_, word)| word),
            first.word(read(0))
        );
        let next = batch(20, 10, []);
        cache
            .publish(
                &[(next.state_root(), &next)],
                &RetentionDelta {
                    release: BTreeSet::from([key(&first)]),
                    retain: BTreeSet::from([key(&next)]),
                },
            )
            .unwrap();
        assert!(cache.peek_account(key(&first)).is_none());
        assert!(cache.peek_account(key(&second)).is_some());
        assert!(cache.peek_account(key(&next)).is_some());
        assert_bounds(&cache);
    }

    #[test]
    fn conflicting_publication_staging_and_merge_are_atomic() {
        let mut cache = VerifiedCache::new(limits(2, 3)).unwrap();
        let first = batch(1, 10, [(0, 42)]);
        let second = batch(2, 11, [(0, 43)]);
        publish(&mut cache, &first);
        publish(&mut cache, &second);
        let fresh = batch(3, 12, [(0, 44)]);
        let before = format!("{cache:?}");
        for (root, bad) in [
            (second.state_root(), batch(2, 11, [(0, 99)])), // Existing word conflict.
            (second.state_root(), batch(2, 12, [])),        // Existing account conflict.
            (B256::with_last_byte(4), batch(4, 12, [(0, 99)])), // Conflict between pending roots.
            (B256::ZERO, second.clone()),                   // Wrong snapshot binding.
        ] {
            assert!(
                cache
                    .publish(
                        &[(fresh.state_root(), &fresh), (root, &bad)],
                        &RetentionDelta::default()
                    )
                    .is_err()
            );
            assert_eq!(format!("{cache:?}"), before); // Includes LRU order.
        }
        let targets = ProofTargets::from([(Address::ZERO, BTreeSet::from([read(0).slot]))]);
        for mut bad in [
            batch(1, 11, [(0, 44)]),
            batch(1, 10, [(0, 99)]),
            VerifiedBatch::empty(B256::ZERO),
        ] {
            let original = bad.clone();
            if !bad.accounts().is_empty() {
                assert!(cache.stage(&mut bad, &targets).is_err());
                assert_eq!(bad, original);
            }
            let mut dest = first.clone();
            assert!(dest.merge(bad).is_err());
            assert_eq!(dest, first);
        }
        assert_eq!(format!("{cache:?}"), before);
    }

    #[test]
    fn invalid_configuration_retention_and_publication_budgets_reject_without_mutation() {
        for (accounts, retained) in [(1, 2), (u32::MAX, 0)] {
            let mut bad = limits(accounts, 1);
            bad.max_retained_accounts = retained;
            assert!(matches!(
                VerifiedCache::new(bad),
                Err(CacheError::InvalidLimits)
            ));
        }
        let mut cache = VerifiedCache::new(limits(1, 2)).unwrap();
        let first = batch(1, 10, [(0, 42)]);
        let next = batch(2, 11, [(0, 43)]);
        publish(&mut cache, &first);
        let before = format!("{cache:?}");
        for delta in [
            RetentionDelta {
                retain: BTreeSet::from([key(&next)]),
                ..Default::default()
            },
            RetentionDelta {
                retain: BTreeSet::from([key(&first)]),
                release: BTreeSet::from([key(&first)]),
            },
        ] {
            assert!(cache.publish(&[], &delta).is_err());
            assert_eq!(format!("{cache:?}"), before);
        }
        let delta = RetentionDelta {
            retain: BTreeSet::from([key(&first), key(&next)]),
            ..Default::default()
        };
        assert!(matches!(
            cache.publish(&[(next.state_root(), &next)], &delta),
            Err(CacheError::RetentionLimit)
        ));
        assert_eq!(format!("{cache:?}"), before);
        for kind in [
            CacheResource::Batches,
            CacheResource::Accounts,
            CacheResource::Words,
            CacheResource::RetentionUpdates,
        ] {
            cache.limits = limits(1, 2);
            match kind {
                CacheResource::Batches => {
                    cache.limits.max_publication_batches = 1.try_into().unwrap()
                }
                CacheResource::Accounts => {
                    cache.limits.max_publication_accounts = 1.try_into().unwrap()
                }
                CacheResource::Words => cache.limits.max_publication_words = 1.try_into().unwrap(),
                CacheResource::RetentionUpdates => {
                    cache.limits.max_retention_updates = 1.try_into().unwrap()
                }
            }
            let before = format!("{cache:?}");
            assert!(
                matches!(cache.publish(&[(first.state_root(), &first), (next.state_root(), &next)], &delta), Err(CacheError::PublicationLimit(actual)) if actual == kind)
            );
            assert_eq!(format!("{cache:?}"), before);
        }
    }
}
