//! Bytes-like (`Bytes`, `String`) implementation for the `Storable` trait.
//!
//! # Storage Layout
//!
//! Bytes-like types use Solidity-compatible:
//! **Short strings (≤31 bytes)** are stored inline in a single slot:
//! - Bytes 0..len: UTF-8 string data (left-aligned)
//! - Byte 31 (LSB): length * 2 (bit 0 = 0 indicates short string)
//!
//! **Long strings (≥32 bytes)** use keccak256-based storage:
//! - Base slot: stores `length * 2 + 1` (bit 0 = 1 indicates long string)
//! - Data slots: stored at `keccak256(main_slot) + i` for each 32-byte chunk

use alloy::primitives::{Bytes, U256, keccak256};

use crate::{
    error::{Result, TempoPrecompileError},
    storage::{StorageOps, types::*},
};

impl StorableType for Bytes {
    const LAYOUT: Layout = Layout::Slots(1);
}

impl Storable<1> for Bytes {
    #[inline]
    fn load<S: StorageOps>(storage: &mut S, base_slot: U256, ctx: LayoutCtx) -> Result<Self> {
        debug_assert_eq!(ctx, LayoutCtx::FULL, "Bytes cannot be packed");
        load_bytes_like(storage, base_slot, |data| Ok(Self::from(data)))
    }

    #[inline]
    fn store<S: StorageOps>(&self, storage: &mut S, base_slot: U256, ctx: LayoutCtx) -> Result<()> {
        debug_assert_eq!(ctx, LayoutCtx::FULL, "Bytes cannot be packed");
        store_bytes_like(self.as_ref(), storage, base_slot)
    }

    #[inline]
    fn delete<S: StorageOps>(storage: &mut S, base_slot: U256, ctx: LayoutCtx) -> Result<()> {
        debug_assert_eq!(ctx, LayoutCtx::FULL, "Bytes cannot be packed");
        delete_bytes_like(storage, base_slot)
    }

    #[inline]
    fn to_evm_words(&self) -> Result<[U256; 1]> {
        to_evm_words_bytes_like(self.as_ref())
    }

    #[inline]
    fn from_evm_words(words: [U256; 1]) -> Result<Self> {
        from_evm_words_bytes_like(words, |data| Ok(Self::from(data)))
    }
}

impl StorableType for String {
    const LAYOUT: Layout = Layout::Slots(1);
}

impl Storable<1> for String {
    #[inline]
    fn load<S: StorageOps>(storage: &mut S, base_slot: U256, ctx: LayoutCtx) -> Result<Self> {
        debug_assert_eq!(ctx, LayoutCtx::FULL, "String cannot be packed");
        load_bytes_like(storage, base_slot, |data| {
            Self::from_utf8(data).map_err(|e| {
                TempoPrecompileError::Fatal(format!("Invalid UTF-8 in stored string: {e}"))
            })
        })
    }

    #[inline]
    fn store<S: StorageOps>(&self, storage: &mut S, base_slot: U256, ctx: LayoutCtx) -> Result<()> {
        debug_assert_eq!(ctx, LayoutCtx::FULL, "String cannot be packed");
        store_bytes_like(self.as_bytes(), storage, base_slot)
    }

    #[inline]
    fn delete<S: StorageOps>(storage: &mut S, base_slot: U256, ctx: LayoutCtx) -> Result<()> {
        debug_assert_eq!(ctx, LayoutCtx::FULL, "String cannot be packed");
        delete_bytes_like(storage, base_slot)
    }

    #[inline]
    fn to_evm_words(&self) -> Result<[U256; 1]> {
        to_evm_words_bytes_like(self.as_bytes())
    }

    #[inline]
    fn from_evm_words(words: [U256; 1]) -> Result<Self> {
        from_evm_words_bytes_like(words, |data| {
            Self::from_utf8(data).map_err(|e| {
                TempoPrecompileError::Fatal(format!("Invalid UTF-8 in stored string: {e}"))
            })
        })
    }
}

// -- HELPER FUNCTIONS ---------------------------------------------------------

/// Generic load implementation for string-like types (String, Bytes) using Solidity's encoding.
#[inline]
fn load_bytes_like<T, S, F>(storage: &mut S, base_slot: U256, into: F) -> Result<T>
where
    S: StorageOps,
    F: FnOnce(Vec<u8>) -> Result<T>,
{
    let base_value = storage.sload(base_slot)?;
    let is_long = is_long_string(base_value);
    let length = calc_string_length(base_value, is_long);

    if is_long {
        // Long string: read data from keccak256(base_slot) + i
        let slot_start = calc_data_slot(base_slot);
        let chunks = calc_chunks(length);
        let mut data = Vec::with_capacity(length);

        for i in 0..chunks {
            let slot = slot_start + U256::from(i);
            let chunk_value = storage.sload(slot)?;
            let chunk_bytes = chunk_value.to_be_bytes::<32>();

            // For the last chunk, only take the remaining bytes
            let bytes_to_take = if i == chunks - 1 {
                length - (i * 32)
            } else {
                32
            };
            data.extend_from_slice(&chunk_bytes[..bytes_to_take]);
        }

        into(data)
    } else {
        // Short string: data is inline in the main slot
        let bytes = base_value.to_be_bytes::<32>();
        into(bytes[..length].to_vec())
    }
}

/// Generic store implementation for byte-like types (String, Bytes) using Solidity's encoding.
#[inline]
fn store_bytes_like<S: StorageOps>(bytes: &[u8], storage: &mut S, base_slot: U256) -> Result<()> {
    let length = bytes.len();

    if length <= 31 {
        storage.sstore(base_slot, encode_short_string(bytes))
    } else {
        storage.sstore(base_slot, encode_long_string_length(length))?;

        // Store data in chunks at keccak256(base_slot) + i
        let slot_start = calc_data_slot(base_slot);
        let chunks = calc_chunks(length);

        for i in 0..chunks {
            let slot = slot_start + U256::from(i);
            let chunk_start = i * 32;
            let chunk_end = (chunk_start + 32).min(length);
            let chunk = &bytes[chunk_start..chunk_end];

            // Pad chunk to 32 bytes if it's the last chunk
            let mut chunk_bytes = [0u8; 32];
            chunk_bytes[..chunk.len()].copy_from_slice(chunk);

            storage.sstore(slot, U256::from_be_bytes(chunk_bytes))?;
        }

        Ok(())
    }
}

/// Generic delete implementation for byte-like types (String, Bytes) using Solidity's encoding.
///
/// Clears both the main slot and any keccak256-addressed data slots for long strings.
#[inline]
fn delete_bytes_like<S: StorageOps>(storage: &mut S, base_slot: U256) -> Result<()> {
    let base_value = storage.sload(base_slot)?;
    let is_long = is_long_string(base_value);

    if is_long {
        // Long string: need to clear data slots as well
        let length = calc_string_length(base_value, true);
        let slot_start = calc_data_slot(base_slot);
        let chunks = calc_chunks(length);

        // Clear all data slots
        for i in 0..chunks {
            let slot = slot_start + U256::from(i);
            storage.sstore(slot, U256::ZERO)?;
        }
    }

    // Clear the main slot
    storage.sstore(base_slot, U256::ZERO)
}

/// Returns the encoded length for long strings or the inline data for short strings.
#[inline]
fn to_evm_words_bytes_like(bytes: &[u8]) -> Result<[U256; 1]> {
    let length = bytes.len();

    if length <= 31 {
        Ok([encode_short_string(bytes)])
    } else {
        // Note: actual string data is in keccak256-addressed slots (not included here)
        Ok([encode_long_string_length(length)])
    }
}

/// The converter function transforms raw bytes into the target type.
/// Returns an error for long strings, which require storage access to reconstruct.
#[inline]
fn from_evm_words_bytes_like<T, F>(words: [U256; 1], into: F) -> Result<T>
where
    F: FnOnce(Vec<u8>) -> Result<T>,
{
    let slot_value = words[0];
    let is_long = is_long_string(slot_value);

    if is_long {
        // Long string: cannot reconstruct without storage access to keccak256-addressed data
        Err(TempoPrecompileError::Fatal(
            "Cannot reconstruct long string from single word. Use load() instead.".into(),
        ))
    } else {
        // Short string: data is inline in the word
        let length = calc_string_length(slot_value, false);
        let bytes = slot_value.to_be_bytes::<32>();
        into(bytes[..length].to_vec())
    }
}

/// Compute the storage slot where long string data begins.
///
/// For long strings (≥32 bytes), data is stored starting at `keccak256(base_slot)`.
#[inline]
fn calc_data_slot(base_slot: U256) -> U256 {
    U256::from_be_bytes(keccak256(base_slot.to_be_bytes::<32>()).0)
}

/// Check if a storage slot value represents a long string.
///
/// Solidity string encoding uses bit 0 of the LSB to distinguish:
/// - Bit 0 = 0: Short string (≤31 bytes)
/// - Bit 0 = 1: Long string (≥32 bytes)
#[inline]
fn is_long_string(slot_value: U256) -> bool {
    (slot_value.byte(0) & 1) != 0
}

/// Extract the string length from a storage slot value.
#[inline]
fn calc_string_length(slot_value: U256, is_long: bool) -> usize {
    if is_long {
        // Long string: slot stores (length * 2 + 1)
        // Extract length: (value - 1) / 2
        let length_times_two_plus_one: U256 = slot_value;
        let length_times_two: U256 = length_times_two_plus_one - U256::ONE;
        let length_u256: U256 = length_times_two >> 1;
        length_u256.to::<usize>()
    } else {
        // Short string: LSB stores (length * 2)
        // Extract length: LSB / 2
        let bytes = slot_value.to_be_bytes::<32>();
        (bytes[31] / 2) as usize
    }
}

/// Compute the number of 32-byte chunks needed to store a byte string.
#[inline]
fn calc_chunks(byte_length: usize) -> usize {
    byte_length.div_ceil(32)
}

/// Encode a short string (≤31 bytes) into a U256 for inline storage.
///
/// Format: bytes left-aligned, LSB contains (length * 2)
#[inline]
fn encode_short_string(bytes: &[u8]) -> U256 {
    let mut storage_bytes = [0u8; 32];
    storage_bytes[..bytes.len()].copy_from_slice(bytes);
    storage_bytes[31] = (bytes.len() * 2) as u8;
    U256::from_be_bytes(storage_bytes)
}

/// Encode the length metadata for a long string (≥32 bytes).
///
/// Returns `length * 2 + 1` where bit 0 = 1 indicates long string storage.
#[inline]
fn encode_long_string_length(byte_length: usize) -> U256 {
    U256::from(byte_length * 2 + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{PrecompileStorageProvider, StorageOps, hashmap::HashMapStorageProvider};
    use alloy::primitives::Address;
    use proptest::prelude::*;

    // -- TEST HELPERS -------------------------------------------------------------

    // Test helper that owns storage and implements StorageOps
    struct TestContract {
        address: Address,
        storage: HashMapStorageProvider,
    }

    impl StorageOps for TestContract {
        fn sstore(&mut self, slot: U256, value: U256) -> Result<()> {
            self.storage.sstore(self.address, slot, value)
        }

        fn sload(&mut self, slot: U256) -> Result<U256> {
            self.storage.sload(self.address, slot)
        }
    }

    /// Helper to create a test contract with fresh storage.
    fn setup_test_contract() -> TestContract {
        TestContract {
            address: Address::random(),
            storage: HashMapStorageProvider::new(1),
        }
    }

    // Strategy for generating random U256 slot values that won't overflow
    fn arb_safe_slot() -> impl Strategy<Value = U256> {
        any::<[u64; 4]>().prop_map(|limbs| {
            // Ensure we don't overflow by limiting to a reasonable range
            U256::from_limbs(limbs) % (U256::MAX - U256::from(10000))
        })
    }

    // Strategy for short strings (0-31 bytes) - uses inline storage
    fn arb_short_string() -> impl Strategy<Value = String> {
        prop_oneof![
            // Empty string
            Just(String::new()),
            // ASCII strings (1-31 bytes)
            "[a-zA-Z0-9]{1,31}",
            // Unicode strings (up to 31 bytes)
            "[\u{0041}-\u{005A}\u{4E00}-\u{4E19}]{1,10}",
        ]
    }

    // Strategy for exactly 32-byte strings - boundary between inline and heap storage
    fn arb_32byte_string() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9]{32}"
    }

    // Strategy for long strings (33-100 bytes) - uses heap storage
    fn arb_long_string() -> impl Strategy<Value = String> {
        prop_oneof![
            // ASCII strings (33-100 bytes)
            "[a-zA-Z0-9]{33,100}",
            // Unicode strings (>32 bytes)
            "[\u{0041}-\u{005A}\u{4E00}-\u{4E19}]{11,30}",
        ]
    }

    // Strategy for short byte arrays (0-31 bytes) - uses inline storage
    fn arb_short_bytes() -> impl Strategy<Value = Bytes> {
        prop::collection::vec(any::<u8>(), 0..=31).prop_map(Bytes::from)
    }

    // Strategy for exactly 32-byte arrays - boundary between inline and heap storage
    fn arb_32byte_bytes() -> impl Strategy<Value = Bytes> {
        prop::collection::vec(any::<u8>(), 32..=32).prop_map(Bytes::from)
    }

    // Strategy for long byte arrays (33-100 bytes) - uses heap storage
    fn arb_long_bytes() -> impl Strategy<Value = Bytes> {
        prop::collection::vec(any::<u8>(), 33..=100).prop_map(Bytes::from)
    }

    // -- STORAGE TESTS --------------------------------------------------------

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        #[test]
        fn test_short_strings(s in arb_short_string(), base_slot in arb_safe_slot()) {
            let mut contract = setup_test_contract();

            // Verify store → load roundtrip
            s.store(&mut contract, base_slot, LayoutCtx::FULL)?;
            let loaded = String::load(&mut contract, base_slot, LayoutCtx::FULL)?;
            assert_eq!(s, loaded, "Short string roundtrip failed for: {s:?}");

            // Verify delete works
            String::delete(&mut contract, base_slot, LayoutCtx::FULL)?;
            let after_delete = String::load(&mut contract, base_slot, LayoutCtx::FULL)?;
            assert_eq!(after_delete, String::new(), "Short string not empty after delete");

            // EVM words roundtrip (only works for short strings ≤31 bytes)
            let words = s.to_evm_words()?;
            let recovered = String::from_evm_words(words)?;
            assert_eq!(s, recovered, "Short string EVM words roundtrip failed");
        }

        #[test]
        fn test_32byte_strings(s in arb_32byte_string(), base_slot in arb_safe_slot()) {
            let mut contract = setup_test_contract();

            // Verify 32-byte boundary string is stored correctly
            assert_eq!(s.len(), 32, "Generated string should be exactly 32 bytes");

            // Verify store → load roundtrip
            s.store(&mut contract, base_slot, LayoutCtx::FULL)?;
            let loaded = String::load(&mut contract, base_slot, LayoutCtx::FULL)?;
            assert_eq!(s, loaded, "32-byte string roundtrip failed");

            // Verify delete works
            String::delete(&mut contract, base_slot, LayoutCtx::FULL)?;
            let after_delete = String::load(&mut contract, base_slot, LayoutCtx::FULL)?;
            assert_eq!(after_delete, String::new(), "32-byte string not empty after delete");

            // Note: 32-byte strings use long storage format and cannot be
            // reconstructed from a single word without storage access
            let words = s.to_evm_words()?;
            let result = String::from_evm_words(words);
            assert!(result.is_err(), "32-byte string should not be reconstructable from single word");
        }

        #[test]
        fn test_long_strings(s in arb_long_string(), base_slot in arb_safe_slot()) {
            let mut contract = setup_test_contract();

            // Verify store → load roundtrip
            s.store(&mut contract, base_slot, LayoutCtx::FULL)?;
            let loaded = String::load(&mut contract, base_slot, LayoutCtx::FULL)?;
            assert_eq!(s, loaded, "Long string roundtrip failed for length: {}", s.len());

            // Calculate how many data slots were used
            let chunks = calc_chunks(s.len());

            // Verify delete works (clears both main slot and keccak256-addressed data)
            String::delete(&mut contract, base_slot, LayoutCtx::FULL)?;
            let after_delete = String::load(&mut contract, base_slot, LayoutCtx::FULL)?;
            assert_eq!(after_delete, String::new(), "Long string not empty after delete");

            // Verify all keccak256-addressed data slots are actually zero
            let data_slot_start = calc_data_slot(base_slot);
            for i in 0..chunks {
                let slot = data_slot_start + U256::from(i);
                let value = contract.sload(slot)?;
                assert_eq!(value, U256::ZERO, "Data slot {i} not cleared after delete");
            }

            // Verify that strings >= 32 bytes cannot be reconstructed from single word
            // Note: arb_long_string() may occasionally generate strings < 32 bytes due to Unicode
            if s.len() >= 32 {
                let words = s.to_evm_words()?;
                let result = String::from_evm_words(words);
                assert!(result.is_err(), "Long string (>= 32 bytes) should not be reconstructable from single word");
            } else {
                // For strings < 32 bytes, verify roundtrip works
                let words = s.to_evm_words()?;
                let recovered = String::from_evm_words(words)?;
                assert_eq!(s, recovered, "String < 32 bytes EVM words roundtrip failed");
            }
        }

        #[test]
        fn test_short_bytes(b in arb_short_bytes(), base_slot in arb_safe_slot()) {
            let mut contract = setup_test_contract();

            // Verify store → load roundtrip
            b.store(&mut contract, base_slot, LayoutCtx::FULL)?;
            let loaded = Bytes::load(&mut contract, base_slot, LayoutCtx::FULL)?;
            assert_eq!(b, loaded, "Short bytes roundtrip failed for length: {}", b.len());

            // Verify delete works
            Bytes::delete(&mut contract, base_slot, LayoutCtx::FULL)?;
            let after_delete = Bytes::load(&mut contract, base_slot, LayoutCtx::FULL)?;
            assert_eq!(after_delete, Bytes::new(), "Short bytes not empty after delete");

            // EVM words roundtrip (only works for short bytes ≤31 bytes)
            let words = b.to_evm_words()?;
            let recovered = Bytes::from_evm_words(words)?;
            assert_eq!(b, recovered, "Short bytes EVM words roundtrip failed");
        }

        #[test]
        fn test_32byte_bytes(b in arb_32byte_bytes(), base_slot in arb_safe_slot()) {
            let mut contract = setup_test_contract();

            // Verify 32-byte boundary bytes is stored correctly
            assert_eq!(b.len(), 32, "Generated bytes should be exactly 32 bytes");

            // Verify store → load roundtrip
            b.store(&mut contract, base_slot, LayoutCtx::FULL)?;
            let loaded = Bytes::load(&mut contract, base_slot, LayoutCtx::FULL)?;
            assert_eq!(b, loaded, "32-byte bytes roundtrip failed");

            // Verify delete works
            Bytes::delete(&mut contract, base_slot, LayoutCtx::FULL)?;
            let after_delete = Bytes::load(&mut contract, base_slot, LayoutCtx::FULL)?;
            assert_eq!(after_delete, Bytes::new(), "32-byte bytes not empty after delete");

            // Note: 32-byte Bytes use long storage format and cannot be
            // reconstructed from a single word without storage access
            let words = b.to_evm_words()?;
            let result = Bytes::from_evm_words(words);
            assert!(result.is_err(), "32-byte Bytes should not be reconstructable from single word");
        }

        #[test]
        fn test_long_bytes(b in arb_long_bytes(), base_slot in arb_safe_slot()) {
            let mut contract = setup_test_contract();

            // Verify store → load roundtrip
            b.store(&mut contract, base_slot, LayoutCtx::FULL)?;
            let loaded = Bytes::load(&mut contract, base_slot, LayoutCtx::FULL)?;
            assert_eq!(b, loaded, "Long bytes roundtrip failed for length: {}", b.len());

            // Calculate how many data slots were used
            let chunks = calc_chunks(b.len());

            // Verify delete works (clears both main slot and keccak256-addressed data)
            Bytes::delete(&mut contract, base_slot, LayoutCtx::FULL)?;
            let after_delete = Bytes::load(&mut contract, base_slot, LayoutCtx::FULL)?;
            assert_eq!(after_delete, Bytes::new(), "Long bytes not empty after delete");

            // Verify all keccak256-addressed data slots are actually zero
            let data_slot_start = calc_data_slot(base_slot);
            for i in 0..chunks {
                let slot = data_slot_start + U256::from(i);
                let value = contract.sload(slot)?;
                assert_eq!(value, U256::ZERO, "Data slot {i} not cleared after delete");
            }

            // Verify that bytes >= 32 bytes cannot be reconstructed from single word
            if b.len() >= 32 {
                let words = b.to_evm_words()?;
                let result = Bytes::from_evm_words(words);
                assert!(result.is_err(), "Long bytes (>= 32 bytes) should not be reconstructable from single word");
            } else {
                // For bytes < 32 bytes, verify roundtrip works
                let words = b.to_evm_words()?;
                let recovered = Bytes::from_evm_words(words)?;
                assert_eq!(b, recovered, "Bytes < 32 bytes EVM words roundtrip failed");
            }
        }
    }
}
