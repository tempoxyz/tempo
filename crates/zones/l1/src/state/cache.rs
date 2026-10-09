//! Block-versioned in-memory cache of Tempo L1 contract storage slots.
//!
//! The zone's `TempoState` precompile reads Tempo L1 storage at a **specific L1 block height**
//! (the `tempoBlockNumber` the zone committed to via `TempoState.finalizeTempo()` on Zone L2).
//! Because the L1 chain may advance several blocks ahead of the zone's committed height, the
//! cache must be able to serve historical values — not just "latest".
//!
//! ## Storage model
//!
//! Each `(contract_address, slot_key)` pair maps to a [`BTreeMap<u64, B256>`] of
//! `block_number → value`. Slot histories are bounded by both a weighted LRU and a per-slot limit.
//! A lookup for block N may inherit the most recent earlier value only when verified receipt
//! coverage and mutation barriers prove that it remained current.
//!
//! ## Write path
//!
//! - The [`L1Subscriber`](crate::l1::L1Subscriber) records mutation barriers from finalized L1
//!   receipts.
//! - The [`L1StateProvider`](super::provider::L1StateProvider) writes RPC-fetched values on
//!   cache miss, tagged with the block number that was requested.

use alloy_primitives::{Address, B256};
use derive_more::Deref;
use parking_lot::Mutex;
use schnellru::{Limiter, LruMap};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ops::RangeInclusive,
    sync::Arc,
};
use tracing::warn;

/// Maximum total number of block-versioned values retained by the L1 state cache.
const DEFAULT_VERSION_CAPACITY: usize = 100_000;

/// Maximum number of block-versioned values retained for any individual storage slot.
const MAX_VERSIONS_PER_SLOT: usize = 1_000;

/// Maximum number of mutation barriers retained before conservatively resetting the cache.
const DEFAULT_INVALIDATION_CAPACITY: usize = 100_000;

/// Thread-safe L1 state cache backed by an `Arc<RwLock<L1StateCacheInner>>`.
#[derive(Debug, Clone, Deref, Default)]
pub struct L1StateCache {
    #[deref]
    inner: Arc<Mutex<L1StateCacheInner>>,
}

impl L1StateCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(L1StateCacheInner::new())),
        }
    }
}

/// Block-versioned cache of Tempo L1 contract storage slots.
///
/// Each `(contract_address, slot_key)` pair maintains a history of values indexed by L1 block
/// number. Lookups for a given block return the most recent value at or before that block,
/// i.e. the value that was current at that height. This allows the zone to read L1 state at
/// the `tempoBlockNumber` it committed to, even if the L1 chain has since advanced.
///
/// Inherited values are valid only when the subscriber has processed every intervening L1 block
/// and no log from the owning contract indicates a possible mutation. The coverage range starts
/// at the current floor and ends at the latest finalized block whose receipts were processed.
#[derive(Debug)]
pub struct L1StateCacheInner {
    /// Bounded per-slot value histories, promoted as a unit on access.
    slots: LruMap<(Address, B256), BTreeMap<u64, B256>, ByVersionCount>,
    /// Per-address block heights that prevent reuse across possible mutations.
    invalidations: HashMap<Address, BTreeSet<u64>>,
    /// Total number of retained mutation barriers.
    invalidation_count: usize,
    /// Maximum number of mutation barriers retained before resetting.
    max_invalidations: usize,
    /// Contiguous receipt coverage: earliest usable value height through latest processed block.
    coverage: RangeInclusive<u64>,
}

impl Default for L1StateCacheInner {
    fn default() -> Self {
        Self::new()
    }
}

impl L1StateCacheInner {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_VERSION_CAPACITY, DEFAULT_INVALIDATION_CAPACITY)
    }

    fn with_limits(max_versions: usize, max_invalidations: usize) -> Self {
        Self {
            slots: LruMap::new(ByVersionCount::new(max_versions)),
            invalidations: HashMap::new(),
            invalidation_count: 0,
            max_invalidations,
            coverage: 0..=0,
        }
    }

    /// Returns whether receipt processing has established contiguous coverage at `block_number`.
    pub fn has_coverage_at(&self, block_number: u64) -> bool {
        self.coverage.contains(&block_number)
    }

    /// Returns the cached value for a storage slot at the given block number.
    ///
    /// An exact-height value is always valid. A value inherited from an earlier height is returned
    /// only when the subscriber has processed receipts through `block_number` and no mutation
    /// barrier exists after the value was populated.
    pub fn get(&mut self, address: Address, slot: B256, block_number: u64) -> Option<B256> {
        let (&cached_block, &value) = self
            .slots
            .get(&(address, slot))?
            .range(..=block_number)
            .next_back()?;

        // On exact match, just return the value
        if cached_block == block_number {
            return Some(value);
        }

        // If we didn't yet process the requested block, we can't use the cached value
        if block_number > *self.coverage.end() {
            return None;
        }

        // If there was an invalidation between cached and requested block, we can't use the cached value
        if self
            .invalidations
            .get(&address)
            .and_then(|blocks| blocks.range(..=block_number).next_back())
            .is_some_and(|&invalidated_at| invalidated_at > cached_block)
        {
            return None;
        }

        Some(value)
    }

    /// Sets a storage slot value in the forward cache at the given block number.
    ///
    /// Values below the current coverage floor are deliberately not admitted, so historical
    /// reads cannot later be inherited by canonical execution.
    pub fn set(&mut self, address: Address, slot: B256, block_number: u64, value: B256) {
        if block_number < *self.coverage.start() {
            return;
        }

        let key = (address, slot);
        let mut history = self.slots.remove(&key).unwrap_or_default();
        history.insert(block_number, value);

        // Bound eviction granularity and prevent one hot slot from monopolizing the cache.
        let max_history = MAX_VERSIONS_PER_SLOT.min(self.slots.limiter().max_versions());
        while history.len() > max_history {
            history.pop_first();
        }

        let inserted = self.slots.insert(key, history);
        debug_assert!(inserted, "trimmed slot history must fit cache capacity");
    }

    /// Clears cached state and establishes a new contiguous receipt-coverage baseline.
    fn reset(&mut self, floor: u64) {
        self.slots.clear();
        self.invalidations.clear();
        self.invalidation_count = 0;
        self.coverage = floor..=floor;
    }

    /// Records mutation barriers and publishes receipt coverage for one finalized block.
    ///
    /// Coverage only advances one block at a time. A duplicate, skipped, or out-of-order block
    /// invalidates the cache's continuity assumptions, so cached state is cleared and `anchor`
    /// becomes the new coverage floor.
    pub fn invalidate_and_set_anchor(
        &mut self,
        anchor: u64,
        invalidated_addresses: impl IntoIterator<Item = Address>,
    ) {
        if self.coverage.end().checked_add(1) != Some(anchor) {
            warn!(
                anchor,
                previous_anchor = *self.coverage.end(),
                "Non-contiguous L1 state cache update; resetting cache coverage"
            );
            self.reset(anchor);
            return;
        }

        for address in invalidated_addresses {
            let inserted = self
                .invalidations
                .entry(address)
                .or_default()
                .insert(anchor);
            self.invalidation_count += usize::from(inserted);

            if self.invalidation_count > self.max_invalidations {
                warn!(
                    anchor,
                    invalidation_capacity = self.max_invalidations,
                    "L1 state invalidation capacity reached; resetting cache coverage"
                );
                self.reset(anchor);
                return;
            }
        }

        self.coverage = *self.coverage.start()..=anchor;
    }
}

/// [`schnellru`] limiter which measures capacity by the number of versions in all slot histories.
#[derive(Debug, Clone)]
struct ByVersionCount {
    max_versions: usize,
    versions: usize,
}

impl ByVersionCount {
    fn new(max_versions: usize) -> Self {
        assert!(max_versions > 0, "L1 state cache capacity must be non-zero");
        Self {
            max_versions,
            versions: 0,
        }
    }

    const fn max_versions(&self) -> usize {
        self.max_versions
    }

    #[cfg(test)]
    const fn versions(&self) -> usize {
        self.versions
    }
}

impl<K> Limiter<K, BTreeMap<u64, B256>> for ByVersionCount {
    type KeyToInsert<'a> = K;
    type LinkType = u32;

    fn is_over_the_limit(&self, _length: usize) -> bool {
        self.versions > self.max_versions
    }

    fn on_insert(
        &mut self,
        _length: usize,
        key: Self::KeyToInsert<'_>,
        value: BTreeMap<u64, B256>,
    ) -> Option<(K, BTreeMap<u64, B256>)> {
        if value.len() > self.max_versions {
            return None;
        }
        self.versions += value.len();
        Some((key, value))
    }

    fn on_replace(
        &mut self,
        _length: usize,
        _old_key: &mut K,
        _new_key: Self::KeyToInsert<'_>,
        old_value: &mut BTreeMap<u64, B256>,
        new_value: &mut BTreeMap<u64, B256>,
    ) -> bool {
        if new_value.len() > self.max_versions {
            return false;
        }
        self.versions = self.versions - old_value.len() + new_value.len();
        true
    }

    fn on_removed(&mut self, _key: &mut K, value: &mut BTreeMap<u64, B256>) {
        self.versions -= value.len();
    }

    fn on_cleared(&mut self) {
        self.versions = 0;
    }

    fn on_grow(&mut self, _new_memory_usage: usize) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    const PORTAL: Address = address!("0x0000000000000000000000000000000000004242");

    fn cover_through(cache: &mut L1StateCacheInner, block_number: u64) {
        while *cache.coverage.end() < block_number {
            cache.invalidate_and_set_anchor(*cache.coverage.end() + 1, []);
        }
    }

    #[test]
    fn get_returns_none_for_missing_slot() {
        let mut cache = L1StateCacheInner::new();
        assert_eq!(cache.get(PORTAL, B256::ZERO, 100), None);
    }

    #[test]
    fn set_and_get_at_same_block() {
        let mut cache = L1StateCacheInner::new();
        let slot = B256::with_last_byte(1);
        let value = B256::with_last_byte(0xff);

        cache.set(PORTAL, slot, 10, value);
        assert_eq!(cache.get(PORTAL, slot, 10), Some(value));
    }

    #[test]
    fn get_returns_latest_value_at_or_before_requested_block() {
        let mut cache = L1StateCacheInner::new();
        let slot = B256::with_last_byte(1);

        cache.set(PORTAL, slot, 10, B256::with_last_byte(0x0a));
        cache.set(PORTAL, slot, 20, B256::with_last_byte(0x14));
        cover_through(&mut cache, 25);

        assert_eq!(
            cache.get(PORTAL, slot, 10),
            Some(B256::with_last_byte(0x0a))
        );
        assert_eq!(
            cache.get(PORTAL, slot, 15),
            Some(B256::with_last_byte(0x0a))
        );
        assert_eq!(
            cache.get(PORTAL, slot, 20),
            Some(B256::with_last_byte(0x14))
        );
        assert_eq!(
            cache.get(PORTAL, slot, 25),
            Some(B256::with_last_byte(0x14))
        );
    }

    #[test]
    fn get_returns_none_before_earliest_entry() {
        let mut cache = L1StateCacheInner::new();
        let slot = B256::with_last_byte(1);

        cache.set(PORTAL, slot, 10, B256::with_last_byte(0xff));
        assert_eq!(cache.get(PORTAL, slot, 9), None);
    }

    #[test]
    fn inherited_value_requires_receipt_coverage() {
        let mut cache = L1StateCacheInner::new();
        let slot = B256::with_last_byte(1);
        let value = B256::with_last_byte(0x0a);
        cache.set(PORTAL, slot, 10, value);

        assert_eq!(cache.get(PORTAL, slot, 11), None);
        cover_through(&mut cache, 11);
        assert_eq!(cache.get(PORTAL, slot, 11), Some(value));
    }

    #[test]
    fn invalidation_blocks_inheritance_until_refetched() {
        let mut cache = L1StateCacheInner::new();
        let slot = B256::with_last_byte(1);
        let old = B256::with_last_byte(0x0a);
        let new = B256::with_last_byte(0x0b);
        cache.set(PORTAL, slot, 10, old);
        cover_through(&mut cache, 10);
        cache.invalidate_and_set_anchor(11, [PORTAL]);
        cover_through(&mut cache, 12);

        assert_eq!(cache.get(PORTAL, slot, 11), None);
        assert_eq!(cache.get(PORTAL, slot, 12), None);

        cache.set(PORTAL, slot, 11, new);
        assert_eq!(cache.get(PORTAL, slot, 11), Some(new));
        assert_eq!(cache.get(PORTAL, slot, 12), Some(new));
    }

    #[test]
    fn floor_rejects_historical_cache_admission() {
        let mut cache = L1StateCacheInner::new();
        let slot = B256::with_last_byte(1);
        cache.reset(10);
        cache.set(PORTAL, slot, 9, B256::with_last_byte(9));
        cover_through(&mut cache, 11);

        assert_eq!(cache.get(PORTAL, slot, 9), None);
        assert_eq!(cache.get(PORTAL, slot, 11), None);

        let current = B256::with_last_byte(10);
        cache.set(PORTAL, slot, 10, current);
        assert_eq!(cache.get(PORTAL, slot, 11), Some(current));
    }

    #[test]
    fn coverage_defaults_to_zero() {
        let cache = L1StateCacheInner::new();
        assert_eq!(*cache.coverage.end(), 0);
    }

    #[test]
    fn contiguous_update_advances_coverage() {
        let mut cache = L1StateCacheInner::new();
        cache.invalidate_and_set_anchor(1, []);
        assert_eq!(*cache.coverage.end(), 1);
    }

    #[test]
    fn non_contiguous_update_resets_cache_at_new_floor() {
        let mut cache = L1StateCacheInner::new();
        let slot = B256::with_last_byte(1);
        cache.set(PORTAL, slot, 10, B256::with_last_byte(0x0a));

        cache.invalidate_and_set_anchor(10, [PORTAL]);

        assert_eq!(*cache.coverage.end(), 10);
        assert_eq!(*cache.coverage.start(), 10);
        assert!(cache.invalidations.is_empty());
        assert_eq!(cache.get(PORTAL, slot, 10), None);
    }

    #[test]
    fn different_addresses_same_slot_are_independent() {
        let mut cache = L1StateCacheInner::new();
        let addr_b = address!("0x0000000000000000000000000000000000004343");
        let slot = B256::with_last_byte(1);

        cache.set(PORTAL, slot, 10, B256::with_last_byte(0xaa));
        cache.set(addr_b, slot, 10, B256::with_last_byte(0xbb));

        assert_eq!(
            cache.get(PORTAL, slot, 10),
            Some(B256::with_last_byte(0xaa))
        );
        assert_eq!(
            cache.get(addr_b, slot, 10),
            Some(B256::with_last_byte(0xbb))
        );
    }

    #[test]
    fn lru_evicts_the_least_recently_used_slot_history_by_version_weight() {
        let mut cache = L1StateCacheInner::with_limits(3, 10);
        let slot_a = B256::with_last_byte(1);
        let slot_b = B256::with_last_byte(2);
        let slot_c = B256::with_last_byte(3);

        cache.set(PORTAL, slot_a, 10, B256::with_last_byte(0x0a));
        cache.set(PORTAL, slot_b, 10, B256::with_last_byte(0x0b));
        cover_through(&mut cache, 20);

        // Keep A hot, then insert a two-version history for C. B is the oldest history and is
        // evicted to keep the total version count at three.
        assert_eq!(
            cache.get(PORTAL, slot_a, 20),
            Some(B256::with_last_byte(0x0a))
        );
        cache.set(PORTAL, slot_c, 10, B256::with_last_byte(0x0c));
        cache.set(PORTAL, slot_c, 20, B256::with_last_byte(0x1c));

        assert_eq!(cache.slots.limiter().versions(), 3);
        assert_eq!(cache.get(PORTAL, slot_b, 20), None);
        assert_eq!(
            cache.get(PORTAL, slot_a, 20),
            Some(B256::with_last_byte(0x0a))
        );
        assert_eq!(
            cache.get(PORTAL, slot_c, 20),
            Some(B256::with_last_byte(0x1c))
        );
    }

    #[test]
    fn a_single_slot_history_cannot_exceed_the_version_capacity() {
        let mut cache = L1StateCacheInner::with_limits(2, 10);
        let slot = B256::with_last_byte(1);

        cache.set(PORTAL, slot, 10, B256::with_last_byte(0x0a));
        cache.set(PORTAL, slot, 20, B256::with_last_byte(0x14));
        cache.set(PORTAL, slot, 30, B256::with_last_byte(0x1e));
        cover_through(&mut cache, 30);

        assert_eq!(cache.slots.limiter().versions(), 2);
        assert_eq!(cache.get(PORTAL, slot, 10), None);
        assert_eq!(
            cache.get(PORTAL, slot, 20),
            Some(B256::with_last_byte(0x14))
        );
        assert_eq!(
            cache.get(PORTAL, slot, 30),
            Some(B256::with_last_byte(0x1e))
        );
    }

    #[test]
    fn slot_history_retains_only_the_newest_versions() {
        let mut cache = L1StateCacheInner::with_limits(MAX_VERSIONS_PER_SLOT + 1, 10);
        let slot = B256::with_last_byte(1);

        for block_number in 0..=MAX_VERSIONS_PER_SLOT as u64 {
            cache.set(
                PORTAL,
                slot,
                block_number,
                B256::with_last_byte((block_number % 256) as u8),
            );
        }
        cover_through(&mut cache, MAX_VERSIONS_PER_SLOT as u64);

        assert_eq!(cache.slots.limiter().versions(), MAX_VERSIONS_PER_SLOT);
        assert_eq!(cache.get(PORTAL, slot, 0), None);
        assert_eq!(cache.get(PORTAL, slot, 1), Some(B256::with_last_byte(1)));
        assert_eq!(
            cache.get(PORTAL, slot, MAX_VERSIONS_PER_SLOT as u64),
            Some(B256::with_last_byte((MAX_VERSIONS_PER_SLOT % 256) as u8))
        );
    }

    #[test]
    fn invalidation_capacity_resets_cache_at_the_new_coverage_floor() {
        let mut cache = L1StateCacheInner::with_limits(10, 1);
        let slot = B256::with_last_byte(1);

        cache.reset(10);
        cache.set(PORTAL, slot, 10, B256::with_last_byte(0x0a));
        cache.invalidate_and_set_anchor(11, [PORTAL]);
        cache.invalidate_and_set_anchor(12, [PORTAL]);

        assert_eq!(*cache.coverage.start(), 12);
        assert_eq!(cache.invalidation_count, 0);
        assert!(cache.invalidations.is_empty());
        assert_eq!(cache.get(PORTAL, slot, 10), None);

        cache.set(PORTAL, slot, 11, B256::with_last_byte(0x0b));
        assert_eq!(cache.get(PORTAL, slot, 11), None);

        cache.set(PORTAL, slot, 12, B256::with_last_byte(0x0c));
        cover_through(&mut cache, 13);
        assert_eq!(
            cache.get(PORTAL, slot, 13),
            Some(B256::with_last_byte(0x0c))
        );
    }
}
