//! Bounded reuse of pure mapping-slot derivations across handler lifetimes.
//!
//! Entries contain only complete hash inputs and their outputs. No account,
//! storage value, gas warmth, or journal state survives a call through this cache.

use alloy::primitives::{U256, keccak256};
use std::cell::RefCell;

const SLOTS: usize = 4096;

#[derive(Clone, Copy)]
struct Entry {
    input: [u8; 64],
    output: U256,
}

struct Cache<const N: usize> {
    entries: Box<[Option<Entry>]>,
}

impl<const N: usize> Cache<N> {
    fn new() -> Self {
        assert!(N.is_power_of_two());
        Self {
            entries: vec![None; N].into_boxed_slice(),
        }
    }

    fn hash(&mut self, input: [u8; 64]) -> U256 {
        let mut tag = 0u64;
        for word in input.as_chunks::<8>().0 {
            tag = (tag ^ u64::from_ne_bytes(*word))
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .rotate_left(17);
        }
        let entry = &mut self.entries[tag as usize & (N - 1)];
        if let Some(entry) = entry
            && entry.input == input
        {
            return entry.output;
        }
        let output = U256::from_be_bytes(keccak256(input).0);
        *entry = Some(Entry { input, output });
        output
    }
}

thread_local! {
    static CACHE: RefCell<Cache<SLOTS>> = RefCell::new(Cache::new());
}

pub(super) fn hash(input: [u8; 64]) -> U256 {
    CACHE.with_borrow_mut(|cache| cache.hash(input))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collisions_and_every_input_byte_preserve_hashes() {
        let mut cache = Cache::<1>::new();
        let zero = [0u8; 64];
        for index in 0..64 {
            for value in [1, 0x80, 0xff] {
                let mut input = zero;
                input[index] = value;
                for key in [zero, input, input, zero] {
                    assert_eq!(cache.hash(key), U256::from_be_bytes(keccak256(key).0));
                }
            }
        }
        assert_eq!(cache.entries.len(), 1);
    }

    #[test]
    fn repeated_and_nested_mappings_match_uncached_derivation() {
        use crate::storage::StorageKey;
        use alloy::primitives::Address;

        for n in 0..8192u64 {
            let address = Address::from_word(U256::from(n).into());
            let base = U256::from(n % 31);
            let mut input = [0u8; 64];
            input[12..32].copy_from_slice(address.as_slice());
            input[32..].copy_from_slice(&base.to_be_bytes::<32>());
            let expected = U256::from_be_bytes(keccak256(input).0);
            assert_eq!(address.mapping_slot(base), expected);
            assert_eq!(address.mapping_slot(base), expected);
            input[..32].copy_from_slice(&U256::from(n).to_be_bytes::<32>());
            input[32..].copy_from_slice(&expected.to_be_bytes::<32>());
            assert_eq!(
                U256::from(n).mapping_slot(expected),
                U256::from_be_bytes(keccak256(input).0)
            );
        }
    }
}
