//! Read-ahead of the expiring-nonce ring for the payload builder.
//!
//! Every expiring-nonce transaction hashes two keys that depend on the ring position it lands
//! on: the slot of `expiring_nonce_ring[ptr]` and the slot of `expiring_nonce_seen[old_hash]`
//! for the entry it evicts. Within one block the pointer only moves forward, so a worker can read
//! the ring from the parent state ahead of the builder and hash both keys off the executing
//! thread.
//!
//! A hint is a pure function of the ring index and of the hash stored there, so it is never
//! wrong: [`NonceManager::check_and_mark_expiring_nonce`](super::NonceManager) only uses the
//! seen slot when the hash it reads equals the hinted one, and falls back to hashing when a hint
//! is missing or not ready yet.

use super::expiring_nonce_seen_slot;
use alloy::primitives::{B256, U256, keccak256_uncached};
use std::{
    cell::RefCell,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

/// Base slot of `NonceManager::expiring_nonce_ring`.
const RING_BASE_SLOT: U256 = U256::from_limbs([2, 0, 0, 0]);
/// Slot of `NonceManager::expiring_nonce_ring_ptr`.
pub const RING_POINTER_SLOT: U256 = U256::from_limbs([3, 0, 0, 0]);

/// Returns the slot of `expiring_nonce_ring[index]` without the keccak cache.
pub fn ring_slot(index: u32) -> U256 {
    let mut buf = [0u8; 64];
    buf[28..32].copy_from_slice(&index.to_be_bytes());
    buf[32..].copy_from_slice(&RING_BASE_SLOT.to_be_bytes::<32>());
    keccak256_uncached(buf).into()
}

/// Precomputed keys for one ring index.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RingHint {
    /// Slot of `expiring_nonce_ring[index]`.
    pub(crate) ring_slot: U256,
    /// Hash stored at the index in the parent state.
    pub(crate) old_hash: B256,
    /// Slot of `expiring_nonce_seen[old_hash]`, when the entry is set.
    pub(crate) seen_slot: Option<U256>,
}

/// Hashed ring keys for a window of indices starting at the parent's ring pointer.
#[derive(Debug)]
pub struct RingHints {
    start: u32,
    capacity: u32,
    entries: Box<[OnceLock<RingHint>]>,
    cancelled: AtomicBool,
}

impl RingHints {
    /// Creates an empty window of `window` indices from `start` in a ring of `capacity`.
    pub fn new(start: u32, capacity: u32, window: usize) -> Arc<Self> {
        assert!(capacity > 0, "ring capacity must be positive");
        let window = window.min(capacity as usize);
        Arc::new(Self {
            start: start % capacity,
            capacity,
            entries: (0..window).map(|_| OnceLock::new()).collect(),
            cancelled: AtomicBool::new(false),
        })
    }

    /// Fills the window in ring order, reading each entry through `read_slot` (a storage read of
    /// the nonce precompile in the parent state, where an unset slot reads as `None`). Returns
    /// early once [`Self::cancel`] is called.
    pub fn fill(&self, read_slot: impl Fn(U256) -> Option<U256>) {
        for (offset, entry) in self.entries.iter().enumerate() {
            if self.cancelled.load(Ordering::Relaxed) {
                return;
            }
            let index = self.index_at(offset);
            let ring_slot = ring_slot(index);
            let old_hash = read_slot(ring_slot).map(B256::from).unwrap_or_default();
            let seen_slot = (!old_hash.is_zero()).then(|| expiring_nonce_seen_slot(old_hash));
            let _ = entry.set(RingHint {
                ring_slot,
                old_hash,
                seen_slot,
            });
        }
    }

    /// Stops a running [`Self::fill`].
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    fn index_at(&self, offset: usize) -> u32 {
        ((u64::from(self.start) + offset as u64) % u64::from(self.capacity)) as u32
    }

    fn get(&self, index: u32) -> Option<RingHint> {
        let offset = (u64::from(index) + u64::from(self.capacity) - u64::from(self.start))
            % u64::from(self.capacity);
        self.entries.get(offset as usize)?.get().copied()
    }
}

thread_local! {
    static ACTIVE: RefCell<Option<Arc<RingHints>>> = const { RefCell::new(None) };
}

/// Makes `hints` visible to expiring-nonce checks on the current thread until the returned
/// guard is dropped. Dropping the guard also cancels the fill.
pub fn activate(hints: Arc<RingHints>) -> ActiveRingHints {
    ACTIVE.with(|active| *active.borrow_mut() = Some(hints.clone()));
    ActiveRingHints { hints }
}

/// Guard returned by [`activate`].
#[derive(Debug)]
pub struct ActiveRingHints {
    hints: Arc<RingHints>,
}

impl Drop for ActiveRingHints {
    fn drop(&mut self) {
        self.hints.cancel();
        ACTIVE.with(|active| {
            let mut active = active.borrow_mut();
            if active
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &self.hints))
            {
                *active = None;
            }
        });
    }
}

/// Returns the hint for `index` on the current thread, if one is active and ready.
pub(crate) fn lookup(index: u32) -> Option<RingHint> {
    ACTIVE.with(|active| active.borrow().as_ref().and_then(|hints| hints.get(index)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        NONCE_PRECOMPILE_ADDRESS,
        nonce::NonceManager,
        storage::{Handler, StorageCtx, StorageKey, hashmap::HashMapStorageProvider},
    };

    #[test]
    fn ring_slot_matches_mapping_slot() {
        for index in [0u32, 1, 7, 299_999, 2_999_999, u32::MAX] {
            assert_eq!(ring_slot(index), index.mapping_slot(RING_BASE_SLOT));
        }
        let hash = B256::repeat_byte(0xab);
        assert_eq!(
            expiring_nonce_seen_slot(hash),
            hash.mapping_slot(U256::from(1))
        );
    }

    #[test]
    fn hint_window_wraps_around_the_ring() {
        let hints = RingHints::new(8, 10, 5);
        hints.fill(|_| None);
        for index in [8, 9, 0, 1, 2] {
            assert_eq!(hints.get(index).unwrap().ring_slot, ring_slot(index));
        }
        assert!(hints.get(3).is_none());
        assert!(hints.get(7).is_none());
    }

    /// Runs the same expiring-nonce transactions over a ring with expired entries, with and
    /// without hints, and returns the nonce manager's resulting storage.
    fn run(with_hints: bool) -> eyre::Result<Vec<U256>> {
        let mut storage = HashMapStorageProvider::new(1);
        storage.set_timestamp(U256::from(1_000));
        let old: Vec<B256> = (0..8u8).map(|i| B256::repeat_byte(0x10 + i)).collect();
        let new: Vec<B256> = (0..12u8).map(|i| B256::repeat_byte(0x80 + i)).collect();
        StorageCtx::enter(&mut storage, || {
            let mut nonces = NonceManager::new();
            // The ring holds expired entries at 5..13; the pointer is at 5.
            for (offset, hash) in old.iter().enumerate() {
                nonces.expiring_nonce_ring[5 + offset as u32].write(*hash)?;
                nonces.expiring_nonce_seen[*hash].write(900)?;
            }
            nonces.expiring_nonce_ring_ptr.write(5)?;

            let _active = with_hints.then(|| {
                let capacity = StorageCtx.spec().expiring_nonce_set_capacity();
                let hints = RingHints::new(5, capacity, 10);
                hints.fill(|slot| {
                    let value = StorageCtx.sload(NONCE_PRECOMPILE_ADDRESS, slot).unwrap();
                    (!value.is_zero()).then_some(value)
                });
                activate(hints)
            });
            for hash in &new {
                NonceManager::new().check_and_mark_expiring_nonce(*hash, 1_020)?;
            }

            let nonces = NonceManager::new();
            let mut values = vec![U256::from(nonces.expiring_nonce_ring_ptr.read()?)];
            for index in 0..20u32 {
                values.push(nonces.expiring_nonce_ring[index].read()?.into());
            }
            for hash in old.iter().chain(&new) {
                values.push(U256::from(nonces.expiring_nonce_seen[*hash].read()?));
            }
            Ok(values)
        })
    }

    #[test]
    fn hints_do_not_change_state() -> eyre::Result<()> {
        let plain = run(false)?;
        assert_eq!(plain, run(true)?);
        // The ring advanced over all old entries and evicted them.
        assert_eq!(plain[0], U256::from(17));
        Ok(())
    }

    #[test]
    fn hints_are_scoped_to_the_guard() {
        let hints = RingHints::new(0, 10, 2);
        hints.fill(|_| None);
        let guard = activate(hints);
        assert!(lookup(0).is_some());
        drop(guard);
        assert!(lookup(0).is_none());
    }
}
