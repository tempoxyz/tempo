//! Bounded per-thread memoization of Solidity mapping-slot derivations.
//!
//! Precompiles repeatedly derive the same balance, fee and policy slots. Keep the full
//! 64-byte preimage so collisions only evict entries and never change a storage key.

use alloy_primitives::{U256, keccak256, map::DefaultHashBuilder};
use std::{cell::RefCell, hash::BuildHasher};

const CACHE_ENTRIES: usize = 4096;

thread_local! {
    static SLOT_HASHES: RefCell<SlotHashCache> = RefCell::new(SlotHashCache::default());
}

#[derive(Clone, Copy)]
struct Entry {
    preimage: [u8; 64],
    slot: U256,
}

struct SlotHashCache {
    entries: Box<[Option<Entry>]>,
    hasher: DefaultHashBuilder,
}

impl Default for SlotHashCache {
    fn default() -> Self {
        Self {
            entries: vec![None; CACHE_ENTRIES].into_boxed_slice(),
            hasher: DefaultHashBuilder::default(),
        }
    }
}

impl SlotHashCache {
    #[inline]
    fn get(&mut self, preimage: [u8; 64]) -> U256 {
        let index = self.hasher.hash_one(preimage) as usize & (CACHE_ENTRIES - 1);
        if let Some(entry) = self.entries[index]
            && entry.preimage == preimage
        {
            return entry.slot;
        }

        let slot = U256::from_be_bytes(keccak256(preimage).0);
        self.entries[index] = Some(Entry { preimage, slot });
        slot
    }
}

#[inline]
pub(super) fn mapping_slot_hash(preimage: [u8; 64]) -> U256 {
    SLOT_HASHES.with(|cache| cache.borrow_mut().get(preimage))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn cold_hot_and_evicted_entries_match_keccak() {
        let mut cache = SlotHashCache::default();
        for round in 0..3 {
            for key in 0..20_000u64 {
                let mut preimage = [0u8; 64];
                preimage[..8].copy_from_slice(&key.to_be_bytes());
                preimage[32..40].copy_from_slice(&(key % 4).to_be_bytes());
                let expected = U256::from_be_bytes(keccak256(preimage).0);
                assert_eq!(cache.get(preimage), expected, "round {round}, key {key}");
                assert_eq!(cache.get(preimage), expected);
            }
        }
    }

    #[test]
    fn thread_caches_return_the_same_storage_keys() {
        let threads = (0..4)
            .map(|thread| {
                std::thread::spawn(move || {
                    for key in 0..1000u64 {
                        let mut preimage = [thread; 64];
                        preimage[..8].copy_from_slice(&key.to_be_bytes());
                        assert_eq!(
                            mapping_slot_hash(preimage),
                            U256::from_be_bytes(keccak256(preimage).0)
                        );
                    }
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap();
        }
    }

    proptest! {
        #[test]
        fn arbitrary_mapping_preimages_match_keccak(preimage in any::<[u8; 64]>()) {
            let expected = U256::from_be_bytes(keccak256(preimage).0);
            prop_assert_eq!(mapping_slot_hash(preimage), expected);
            prop_assert_eq!(mapping_slot_hash(preimage), expected);
        }
    }
}
