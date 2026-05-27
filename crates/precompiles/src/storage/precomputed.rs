//! Helpers for embedded precomputed mapping storage slots.

use alloy::primitives::U256;
use std::{fmt, marker::PhantomData};

/// Precomputed storage slots for a contiguous mapping key range.
pub struct PrecomputedMappingSlots<K> {
    start: usize,
    slots: &'static [u8],
    key_to_index: fn(&K) -> Option<usize>,
    _marker: PhantomData<fn(&K)>,
}

impl<K> Copy for PrecomputedMappingSlots<K> {}

impl<K> Clone for PrecomputedMappingSlots<K> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<K> PrecomputedMappingSlots<K> {
    /// Creates a precomputed mapping slot table.
    #[inline]
    pub const fn new(
        start: usize,
        slots: &'static [u8],
        key_to_index: fn(&K) -> Option<usize>,
    ) -> Self {
        Self {
            start,
            slots,
            key_to_index,
            _marker: PhantomData,
        }
    }

    /// Returns the precomputed storage slot for `key`, if it falls within the table range.
    #[inline]
    pub fn slot(&self, key: &K) -> Option<U256> {
        let index = (self.key_to_index)(key)?;
        let relative = index.checked_sub(self.start)?;
        let offset = relative.checked_mul(32)?;
        let end = offset.checked_add(32)?;
        let slot = self.slots.get(offset..end)?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slot);
        Some(U256::from_be_bytes(bytes))
    }
}

impl<K> fmt::Debug for PrecomputedMappingSlots<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrecomputedMappingSlots")
            .field("start", &self.start)
            .field("len", &(self.slots.len() / 32))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precomputed_mapping_slots_lookup() {
        fn key_to_index(key: &u32) -> Option<usize> {
            Some(*key as usize)
        }

        static SLOTS: [u8; 64] = {
            let mut slots = [0u8; 64];
            slots[31] = 11;
            slots[63] = 12;
            slots
        };

        let precomputed = PrecomputedMappingSlots::new(10, &SLOTS, key_to_index);
        assert_eq!(precomputed.slot(&10), Some(U256::from(11)));
        assert_eq!(precomputed.slot(&11), Some(U256::from(12)));
        assert_eq!(precomputed.slot(&12), None);
    }
}
