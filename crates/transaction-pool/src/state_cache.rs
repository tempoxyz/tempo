//! Tip-scoped concurrent cache of state reads shared across transaction validations.

use alloy_primitives::{
    Address, B256, U256,
    map::{AddressMap, DefaultHashBuilder, HashMap},
};
use dashmap::DashMap;
use revm::{Database, DatabaseRef, bytecode::Bytecode, state::AccountInfo};
use std::{
    cell::RefCell,
    sync::atomic::{AtomicUsize, Ordering},
};

/// Concurrent cache of raw state reads anchored to a specific tip.
///
/// Transaction validation repeatedly reads the same state (system contract configuration,
/// fee token slots, sender accounts) for every transaction. This cache shares those reads
/// across all concurrent validation calls so only the first access hits the underlying
/// state provider.
///
/// The validator replaces the cache whenever a new head block is processed, mirroring the
/// lifecycle of its cached EVM environment.
#[derive(Debug, Default)]
pub(crate) struct StateCache {
    /// Cached basic account info, including non-existent accounts (`None`).
    accounts: DashMap<Address, Option<AccountInfo>, DefaultHashBuilder>,
    /// Cached storage values keyed by account and slot.
    storage: DashMap<(Address, U256), U256, DefaultHashBuilder>,
    /// Cached bytecode keyed by code hash.
    contracts: DashMap<B256, Bytecode, DefaultHashBuilder>,
    /// Approximate entry counts for cap enforcement.
    counts: EntryCounts,
}

impl StateCache {
    /// Maximum number of cached accounts.
    ///
    /// The caps bound memory if a flood of unique accounts is validated within a single
    /// block interval; once reached, additional reads fall through to the state provider.
    const MAX_ACCOUNTS: usize = 1 << 17;
    /// Maximum number of cached storage slots.
    const MAX_STORAGE_SLOTS: usize = 1 << 18;
    /// Maximum number of cached contracts.
    const MAX_CONTRACTS: usize = 1 << 12;
}

/// Approximate entry counts of a [`StateCache`]; `DashMap::len` locks every shard and is too
/// expensive for the insert path. Racing inserts may overshoot the caps slightly.
///
/// Aligned to its own cache lines: misses increment these from every validation thread, and a
/// line shared with the map headers that every hit reads would make all other threads, including
/// those in other L3 domains, refetch it.
#[derive(Debug, Default)]
#[repr(align(128))]
struct EntryCounts {
    accounts: AtomicUsize,
    storage: AtomicUsize,
    contracts: AtomicUsize,
}

/// One thread's front cache over a [`StateCache`], holding the first accounts and storage slots
/// that thread reads through it.
///
/// Every validation reads the same system configuration and fee token slots. Each read from the
/// shared [`StateCache`] takes a `DashMap` shard lock, an atomic write that moves the lock's cache
/// line between all validation threads, and across L3 domains on hosts with several. The first
/// validation on a thread reads those hot slots, so they land here and later reads stay in the
/// thread's own caches. Only valid together with the [`StateCache`] it was filled from.
#[derive(Debug, Default)]
pub(crate) struct LocalStateCache {
    accounts: RefCell<AddressMap<Option<AccountInfo>>>,
    storage: RefCell<HashMap<(Address, U256), U256>>,
}

impl LocalStateCache {
    /// Maximum number of accounts held per thread.
    const MAX_ACCOUNTS: usize = 64;
    /// Maximum number of storage slots held per thread.
    const MAX_STORAGE_SLOTS: usize = 256;
}

/// A [`DatabaseRef`] adapter that serves reads from a shared [`StateCache`], falling back
/// to the wrapped database and populating the cache on miss.
#[derive(Debug)]
#[expect(unnameable_types)]
pub struct StateCacheDb<'a, DB> {
    /// The shared read cache.
    cache: &'a StateCache,
    /// The calling thread's front cache over `cache`, if any.
    local: Option<&'a LocalStateCache>,
    /// The underlying database.
    db: DB,
}

impl<'a, DB> StateCacheDb<'a, DB> {
    pub(crate) const fn new(
        cache: &'a StateCache,
        local: Option<&'a LocalStateCache>,
        db: DB,
    ) -> Self {
        Self { cache, local, db }
    }
}

impl<DB: DatabaseRef> StateCacheDb<'_, DB> {
    /// Reads an account through the shared cache, populating it on miss.
    fn shared_basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, DB::Error> {
        if let Some(account) = self.cache.accounts.get(&address) {
            return Ok(account.clone());
        }
        let account = self.db.basic_ref(address)?;
        if self.cache.counts.accounts.load(Ordering::Relaxed) < StateCache::MAX_ACCOUNTS
            && self
                .cache
                .accounts
                .insert(address, account.clone())
                .is_none()
        {
            self.cache.counts.accounts.fetch_add(1, Ordering::Relaxed);
        }
        Ok(account)
    }

    /// Reads a storage slot through the shared cache, populating it on miss.
    fn shared_storage_ref(&self, address: Address, index: U256) -> Result<U256, DB::Error> {
        if let Some(value) = self.cache.storage.get(&(address, index)) {
            return Ok(*value);
        }
        let value = self.db.storage_ref(address, index)?;
        if self.cache.counts.storage.load(Ordering::Relaxed) < StateCache::MAX_STORAGE_SLOTS
            && self.cache.storage.insert((address, index), value).is_none()
        {
            self.cache.counts.storage.fetch_add(1, Ordering::Relaxed);
        }
        Ok(value)
    }
}

impl<DB: DatabaseRef> DatabaseRef for StateCacheDb<'_, DB> {
    type Error = DB::Error;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let Some(local) = self.local else {
            return self.shared_basic_ref(address);
        };
        if let Some(account) = local.accounts.borrow().get(&address) {
            return Ok(account.clone());
        }
        let account = self.shared_basic_ref(address)?;
        let mut accounts = local.accounts.borrow_mut();
        if accounts.len() < LocalStateCache::MAX_ACCOUNTS {
            accounts.insert(address, account.clone());
        }
        Ok(account)
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        if let Some(code) = self.cache.contracts.get(&code_hash) {
            return Ok(code.clone());
        }
        let code = self.db.code_by_hash_ref(code_hash)?;
        if self.cache.counts.contracts.load(Ordering::Relaxed) < StateCache::MAX_CONTRACTS
            && self
                .cache
                .contracts
                .insert(code_hash, code.clone())
                .is_none()
        {
            self.cache.counts.contracts.fetch_add(1, Ordering::Relaxed);
        }
        Ok(code)
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let Some(local) = self.local else {
            return self.shared_storage_ref(address, index);
        };
        if let Some(value) = local.storage.borrow().get(&(address, index)) {
            return Ok(*value);
        }
        let value = self.shared_storage_ref(address, index)?;
        let mut storage = local.storage.borrow_mut();
        if storage.len() < LocalStateCache::MAX_STORAGE_SLOTS {
            storage.insert((address, index), value);
        }
        Ok(value)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.db.block_hash_ref(number)
    }
}

impl<DB: DatabaseRef> Database for StateCacheDb<'_, DB> {
    type Error = DB::Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.basic_ref(address)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.code_by_hash_ref(code_hash)
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.storage_ref(address, index)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.block_hash_ref(number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct CountingDb {
        reads: AtomicUsize,
    }

    impl DatabaseRef for CountingDb {
        type Error = core::convert::Infallible;

        fn basic_ref(&self, _address: Address) -> Result<Option<AccountInfo>, Self::Error> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            Ok(Some(AccountInfo {
                balance: U256::ONE,
                ..Default::default()
            }))
        }

        fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            Ok(Bytecode::default())
        }

        fn storage_ref(&self, _address: Address, _index: U256) -> Result<U256, Self::Error> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            Ok(U256::from(42))
        }

        fn block_hash_ref(&self, _number: u64) -> Result<B256, Self::Error> {
            Ok(B256::ZERO)
        }
    }

    #[test]
    fn caches_reads_across_instances() {
        let cache = StateCache::default();
        let inner = CountingDb::default();
        let address = Address::with_last_byte(1);
        let slot = U256::from(7);

        {
            let db = StateCacheDb::new(&cache, None, &inner);
            assert_eq!(db.storage_ref(address, slot).unwrap(), U256::from(42));
            assert!(db.basic_ref(address).unwrap().is_some());
        }
        assert_eq!(inner.reads.load(Ordering::Relaxed), 2);

        // A new adapter over the same cache serves all reads from memory.
        let db = StateCacheDb::new(&cache, None, &inner);
        assert_eq!(db.storage_ref(address, slot).unwrap(), U256::from(42));
        assert!(db.basic_ref(address).unwrap().is_some());
        assert_eq!(inner.reads.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn local_cache_serves_repeated_reads_up_to_cap() {
        let cache = StateCache::default();
        let local = LocalStateCache::default();
        let inner = CountingDb::default();
        let address = Address::with_last_byte(1);

        let db = StateCacheDb::new(&cache, Some(&local), &inner);
        for slot in 0..=LocalStateCache::MAX_STORAGE_SLOTS {
            assert_eq!(
                db.storage_ref(address, U256::from(slot)).unwrap(),
                U256::from(42)
            );
        }
        assert!(db.basic_ref(address).unwrap().is_some());
        assert_eq!(
            local.storage.borrow().len(),
            LocalStateCache::MAX_STORAGE_SLOTS
        );
        assert_eq!(local.accounts.borrow().len(), 1);
        let reads = inner.reads.load(Ordering::Relaxed);

        // An adapter over an empty shared cache still serves the thread's reads from memory.
        let empty = StateCache::default();
        let db = StateCacheDb::new(&empty, Some(&local), &inner);
        assert_eq!(db.storage_ref(address, U256::ZERO).unwrap(), U256::from(42));
        assert!(db.basic_ref(address).unwrap().is_some());
        assert_eq!(inner.reads.load(Ordering::Relaxed), reads);
    }
}
