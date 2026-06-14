//! Tip-scoped concurrent cache of state reads shared across transaction validations.

use alloy_primitives::{Address, B256, U256, map::DefaultHashBuilder};
use dashmap::DashMap;
use revm::{Database, DatabaseRef, bytecode::Bytecode, database::BundleState, state::AccountInfo};
use std::sync::atomic::{AtomicUsize, Ordering};
use tempo_precompiles::NONCE_PRECOMPILE_ADDRESS;

/// Concurrent cache of raw state reads anchored to a specific tip.
///
/// Transaction validation repeatedly reads the same state (system contract configuration,
/// fee token slots, sender accounts) for every transaction. This cache shares those reads
/// across all concurrent validation calls so only the first access hits the underlying
/// state provider.
///
/// On every new head block the validator replaces the cache with a fresh one seeded from that
/// block's post-execution state (see [`StateCache::from_post_state`]). The accounts, storage
/// slots and contracts a block touches during execution are the same fee-token, nonce-manager
/// and system-contract entries the next block's validations read, so seeding keeps those warm
/// across blocks instead of re-reading them from the state provider every block.
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

    /// Builds a cache seeded with the post-execution state of a committed block range.
    ///
    /// The cache starts empty and is populated only with the post-state values found in
    /// `bundle` (the accounts and storage slots the range touched, plus any contracts it
    /// deployed). Because it never carries over entries from the previous tip, it cannot
    /// serve stale reads: destroyed accounts and wiped storage slots simply stay absent and
    /// are re-read on demand, and the cache size is bounded by the size of the block range
    /// rather than growing without limit across blocks.
    ///
    /// Seeding runs once per block off the hot validation path, so it skips the per-entry cap
    /// checks the on-demand read path uses and instead sets the entry counters from the final
    /// map lengths. A large range (e.g. a deep reorg) may seed past the caps, but the counters
    /// then reflect that and the on-demand read path stops inserting until entries drain.
    pub(crate) fn from_post_state(bundle: &BundleState) -> Self {
        Self::from_post_state_with_parent(bundle, None)
    }

    /// Builds a cache seeded with post-state and selected hot entries from the parent cache.
    ///
    /// When the new tip's parent hash matches the currently cached tip, nonce-precompile entries
    /// remain valid unless the new block touches them. The child block's post-state is applied
    /// afterwards, so touched nonce-precompile slots overwrite the carried parent values.
    pub(crate) fn from_post_state_with_parent(
        bundle: &BundleState,
        parent: Option<&StateCache>,
    ) -> Self {
        let storage_len = bundle
            .state
            .values()
            .map(|a| a.storage.len())
            .sum::<usize>();
        let cache = Self {
            accounts: DashMap::with_capacity_and_hasher(bundle.state.len(), Default::default()),
            storage: DashMap::with_capacity_and_hasher(storage_len, Default::default()),
            contracts: DashMap::with_capacity_and_hasher(
                bundle.contracts.len(),
                Default::default(),
            ),
            ..Default::default()
        };

        if let Some(parent) = parent {
            // keep NONCE_PRECOMPILE_ADDRESS cached across blocks
            if let Some(account) = parent.accounts.get(&NONCE_PRECOMPILE_ADDRESS) {
                cache
                    .accounts
                    .insert(NONCE_PRECOMPILE_ADDRESS, account.clone());
            }

            for entry in parent.storage.iter() {
                let (address, slot) = *entry.key();
                if address == NONCE_PRECOMPILE_ADDRESS {
                    cache.storage.insert((address, slot), *entry.value());
                }
            }
        }

        // Contracts are keyed by code hash, which is immutable, so deployed bytecode is always
        // safe to cache.
        for (code_hash, code) in &bundle.contracts {
            cache.contracts.insert(*code_hash, code.clone());
        }

        for (address, account) in &bundle.state {
            cache.accounts.insert(*address, account.account_info());
            for (slot, value) in &account.storage {
                cache.storage.insert((*address, *slot), value.present_value);
            }
        }

        cache
            .account_count
            .store(cache.accounts.len(), Ordering::Relaxed);
        cache
            .storage_count
            .store(cache.storage.len(), Ordering::Relaxed);
        cache
            .contract_count
            .store(cache.contracts.len(), Ordering::Relaxed);

        cache
    }
}

/// A [`DatabaseRef`] adapter that serves reads from a shared [`StateCache`], falling back
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

impl<DB: DatabaseRef> DatabaseRef for StateCacheDb<'_, DB> {
    type Error = DB::Error;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        if let Some(account) = self.cache.accounts.get(&address) {
            return Ok(account.clone());
        }
        let account = self.db.basic_ref(address)?;
        if self.cache.account_count.load(Ordering::Relaxed) < StateCache::MAX_ACCOUNTS
            && self
                .cache
                .accounts
                .insert(address, account.clone())
                .is_none()
        {
            self.cache.account_count.fetch_add(1, Ordering::Relaxed);
        }
        Ok(account)
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        if let Some(code) = self.cache.contracts.get(&code_hash) {
            return Ok(code.clone());
        }
        let code = self.db.code_by_hash_ref(code_hash)?;
        if self.cache.contract_count.load(Ordering::Relaxed) < StateCache::MAX_CONTRACTS
            && self
                .cache
                .contracts
                .insert(code_hash, code.clone())
                .is_none()
        {
            self.cache.contract_count.fetch_add(1, Ordering::Relaxed);
        }
        Ok(code)
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        if let Some(value) = self.cache.storage.get(&(address, index)) {
            return Ok(*value);
        }
        let value = self.db.storage_ref(address, index)?;
        if self.cache.storage_count.load(Ordering::Relaxed) < StateCache::MAX_STORAGE_SLOTS
            && self.cache.storage.insert((address, index), value).is_none()
        {
            self.cache.storage_count.fetch_add(1, Ordering::Relaxed);
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
                balance: U256::from(1),
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
    fn seeds_from_post_state_without_hitting_db() {
        use alloy_primitives::map::{AddressMap, B256Map, HashMap};
        use revm::database::{AccountStatus, BundleAccount, BundleState, states::StorageSlot};

        let seeded_addr = Address::with_last_byte(1);
        let seeded_slot = U256::from(7);
        let seeded_value = U256::from(123);
        let unseeded_addr = Address::with_last_byte(2);
        let code_hash = B256::repeat_byte(0xab);

        let seeded_info = AccountInfo {
            balance: U256::from(999),
            nonce: 5,
            ..Default::default()
        };

        let mut storage = HashMap::default();
        storage.insert(
            seeded_slot,
            StorageSlot::new_changed(U256::ZERO, seeded_value),
        );
        let mut state = AddressMap::default();
        state.insert(
            seeded_addr,
            BundleAccount::new(None, Some(seeded_info), storage, AccountStatus::Changed),
        );
        let mut contracts = B256Map::default();
        contracts.insert(code_hash, Bytecode::default());
        let bundle = BundleState {
            state,
            contracts,
            ..Default::default()
        };

        let cache = StateCache::from_post_state(&bundle);
        assert_eq!(cache.account_count.load(Ordering::Relaxed), 1);
        assert_eq!(cache.storage_count.load(Ordering::Relaxed), 1);
        assert_eq!(cache.contract_count.load(Ordering::Relaxed), 1);

        let inner = CountingDb::default();
        let db = StateCacheDb::new(&cache, &inner);

        // Seeded entries are served from the cache, leaving the underlying db untouched.
        assert_eq!(
            db.basic_ref(seeded_addr).unwrap().unwrap().balance,
            U256::from(999)
        );
        assert_eq!(
            db.storage_ref(seeded_addr, seeded_slot).unwrap(),
            seeded_value
        );
        assert!(db.code_by_hash_ref(code_hash).unwrap().is_empty());
        assert_eq!(inner.reads.load(Ordering::Relaxed), 0);

        // An account the block did not touch still falls through to the db.
        assert!(db.basic_ref(unseeded_addr).unwrap().is_some());
        assert_eq!(inner.reads.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn carries_nonce_precompile_parent_state() {
        use alloy_primitives::map::{AddressMap, HashMap};
        use revm::database::{AccountStatus, BundleAccount, BundleState, states::StorageSlot};
        use tempo_precompiles::nonce::slots as nonce_slots;

        let carried_slot = U256::from(7);
        let carried_value = U256::from(123);
        let carried_zero_slot = U256::from(8);
        let overwritten_slot = U256::from(9);
        let old_overwritten_value = U256::from(333);
        let new_overwritten_value = U256::from(999);
        let other_addr = Address::with_last_byte(2);
        let other_slot = U256::from(10);

        let mut parent_nonce_storage = HashMap::default();
        parent_nonce_storage.insert(
            nonce_slots::EXPIRING_NONCE_RING_PTR,
            StorageSlot::new_changed(U256::from(1), U256::ZERO),
        );
        parent_nonce_storage.insert(
            carried_slot,
            StorageSlot::new_changed(U256::ZERO, carried_value),
        );
        parent_nonce_storage.insert(
            carried_zero_slot,
            StorageSlot::new_changed(U256::from(1), U256::ZERO),
        );
        parent_nonce_storage.insert(
            overwritten_slot,
            StorageSlot::new_changed(U256::ZERO, old_overwritten_value),
        );

        let mut parent_state = AddressMap::default();
        parent_state.insert(
            NONCE_PRECOMPILE_ADDRESS,
            BundleAccount::new(
                None,
                Some(AccountInfo {
                    balance: U256::from(777),
                    ..Default::default()
                }),
                parent_nonce_storage,
                AccountStatus::Changed,
            ),
        );

        let mut other_storage = HashMap::default();
        other_storage.insert(
            other_slot,
            StorageSlot::new_changed(U256::ZERO, U256::from(555)),
        );
        parent_state.insert(
            other_addr,
            BundleAccount::new(
                None,
                Some(AccountInfo::default()),
                other_storage,
                AccountStatus::Changed,
            ),
        );

        let parent_cache = StateCache::from_post_state(&BundleState {
            state: parent_state,
            ..Default::default()
        });

        let mut child_nonce_storage = HashMap::default();
        child_nonce_storage.insert(
            overwritten_slot,
            StorageSlot::new_changed(old_overwritten_value, new_overwritten_value),
        );
        let mut child_state = AddressMap::default();
        child_state.insert(
            NONCE_PRECOMPILE_ADDRESS,
            BundleAccount::new(
                None,
                Some(AccountInfo::default()),
                child_nonce_storage,
                AccountStatus::Changed,
            ),
        );

        let cache = StateCache::from_post_state_with_parent(
            &BundleState {
                state: child_state,
                ..Default::default()
            },
            Some(&parent_cache),
        );
        let inner = CountingDb::default();
        let db = StateCacheDb::new(&cache, &inner);

        assert_eq!(
            db.basic_ref(NONCE_PRECOMPILE_ADDRESS)
                .unwrap()
                .unwrap()
                .balance,
            U256::ZERO
        );
        assert_eq!(
            db.storage_ref(
                NONCE_PRECOMPILE_ADDRESS,
                nonce_slots::EXPIRING_NONCE_RING_PTR
            )
            .unwrap(),
            U256::ZERO
        );
        assert_eq!(
            db.storage_ref(NONCE_PRECOMPILE_ADDRESS, carried_slot)
                .unwrap(),
            carried_value
        );
        assert_eq!(
            db.storage_ref(NONCE_PRECOMPILE_ADDRESS, overwritten_slot)
                .unwrap(),
            new_overwritten_value
        );
        assert_eq!(inner.reads.load(Ordering::Relaxed), 0);

        assert_eq!(
            db.storage_ref(NONCE_PRECOMPILE_ADDRESS, carried_zero_slot)
                .unwrap(),
            U256::ZERO
        );
        assert_eq!(inner.reads.load(Ordering::Relaxed), 0);

        assert_eq!(
            db.storage_ref(other_addr, other_slot).unwrap(),
            U256::from(42)
        );
        assert_eq!(inner.reads.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn caches_reads_across_instances() {
        let cache = StateCache::default();
        let inner = CountingDb::default();
        let address = Address::with_last_byte(1);
        let slot = U256::from(7);

        {
            let db = StateCacheDb::new(&cache, &inner);
            assert_eq!(db.storage_ref(address, slot).unwrap(), U256::from(42));
            assert!(db.basic_ref(address).unwrap().is_some());
        }
        assert_eq!(inner.reads.load(Ordering::Relaxed), 2);

        // A new adapter over the same cache serves all reads from memory.
        let db = StateCacheDb::new(&cache, &inner);
        assert_eq!(db.storage_ref(address, slot).unwrap(), U256::from(42));
        assert!(db.basic_ref(address).unwrap().is_some());
        assert_eq!(inner.reads.load(Ordering::Relaxed), 2);
    }
}
