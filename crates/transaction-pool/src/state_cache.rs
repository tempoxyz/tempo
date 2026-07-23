//! Tip-scoped concurrent cache of state reads shared across transaction validations.

use alloy_primitives::{Address, B256, U256, map::DefaultHashBuilder};
use dashmap::DashMap;
use reth_evm::{
    Database,
    cached::{AccountInfo, Bytecode},
};
use std::sync::atomic::{AtomicUsize, Ordering};

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
    /// Approximate entry counts for cap enforcement; `DashMap::len` locks every shard and is
    /// too expensive for the insert path. Racing inserts may overshoot the caps slightly.
    account_count: AtomicUsize,
    storage_count: AtomicUsize,
    contract_count: AtomicUsize,
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

/// A [`Database`] adapter that serves reads from a shared [`StateCache`], falling back
/// to the wrapped database and populating the cache on miss.
#[derive(Debug)]
pub(crate) struct StateCacheDb<'a, DB> {
    /// The shared read cache.
    cache: &'a StateCache,
    /// The underlying database.
    db: DB,
}

impl<'a, DB> StateCacheDb<'a, DB> {
    pub(crate) const fn new(cache: &'a StateCache, db: DB) -> Self {
        Self { cache, db }
    }
}

impl<DB: Database> Database for StateCacheDb<'_, DB> {
    type Error = DB::Error;

    fn get_account(&mut self, address: &Address) -> Result<Option<AccountInfo>, Self::Error> {
        if let Some(account) = self.cache.accounts.get(address) {
            return Ok(account.clone());
        }
        let account = self.db.get_account(address)?;
        if self.cache.account_count.load(Ordering::Relaxed) < StateCache::MAX_ACCOUNTS
            && self
                .cache
                .accounts
                .insert(*address, account.clone())
                .is_none()
        {
            self.cache.account_count.fetch_add(1, Ordering::Relaxed);
        }
        Ok(account)
    }

    fn get_code_by_hash(&mut self, code_hash: &B256) -> Result<Bytecode, Self::Error> {
        if let Some(code) = self.cache.contracts.get(code_hash) {
            return Ok(code.clone());
        }
        let code = self.db.get_code_by_hash(code_hash)?;
        if self.cache.contract_count.load(Ordering::Relaxed) < StateCache::MAX_CONTRACTS
            && self
                .cache
                .contracts
                .insert(*code_hash, code.clone())
                .is_none()
        {
            self.cache.contract_count.fetch_add(1, Ordering::Relaxed);
        }
        Ok(code)
    }

    fn get_storage(&mut self, address: &Address, index: &U256) -> Result<U256, Self::Error> {
        if let Some(value) = self.cache.storage.get(&(*address, *index)) {
            return Ok(*value);
        }
        let value = self.db.get_storage(address, index)?;
        if self.cache.storage_count.load(Ordering::Relaxed) < StateCache::MAX_STORAGE_SLOTS
            && self
                .cache
                .storage
                .insert((*address, *index), value)
                .is_none()
        {
            self.cache.storage_count.fetch_add(1, Ordering::Relaxed);
        }
        Ok(value)
    }

    fn get_block_hash(&mut self, number: &U256) -> Result<Option<B256>, Self::Error> {
        self.db.get_block_hash(number)
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

    impl Database for CountingDb {
        type Error = core::convert::Infallible;

        fn get_account(&mut self, _address: &Address) -> Result<Option<AccountInfo>, Self::Error> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            Ok(Some(AccountInfo {
                balance: U256::from(1),
                ..Default::default()
            }))
        }

        fn get_code_by_hash(&mut self, _code_hash: &B256) -> Result<Bytecode, Self::Error> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            Ok(Bytecode::default())
        }

        fn get_storage(&mut self, _address: &Address, _index: &U256) -> Result<U256, Self::Error> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            Ok(U256::from(42))
        }

        fn get_block_hash(&mut self, _number: &U256) -> Result<Option<B256>, Self::Error> {
            Ok(Some(B256::ZERO))
        }
    }

    #[test]
    fn caches_reads_across_instances() {
        let cache = StateCache::default();
        let mut inner = CountingDb::default();
        let address = Address::with_last_byte(1);
        let slot = U256::from(7);

        {
            let mut db = StateCacheDb::new(&cache, &mut inner);
            assert_eq!(db.get_storage(&address, &slot).unwrap(), U256::from(42));
            assert!(db.get_account(&address).unwrap().is_some());
        }
        assert_eq!(inner.reads.load(Ordering::Relaxed), 2);

        // A new adapter over the same cache serves all reads from memory.
        let mut db = StateCacheDb::new(&cache, &mut inner);
        assert_eq!(db.get_storage(&address, &slot).unwrap(), U256::from(42));
        assert!(db.get_account(&address).unwrap().is_some());
        assert_eq!(inner.reads.load(Ordering::Relaxed), 2);
    }
}
