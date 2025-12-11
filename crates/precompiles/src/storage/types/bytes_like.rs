//! Bytes-like (`Bytes`, `String`) implementation for the storage traits.
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

use crate::{
    error::{Result, TempoPrecompileError},
    storage::{StorageOps, types::*},
};
use alloy::primitives::{Address, Bytes, U256, keccak256};

impl StorableType for Bytes {
    const LAYOUT: Layout = Layout::Slots(1);
    const IS_DYNAMIC: bool = true;
    type Handler = Slot<Self>;

    fn handle(slot: U256, ctx: LayoutCtx, address: Address) -> Self::Handler {
        Slot::new_with_ctx(slot, ctx, address)
    }
}

impl StorableType for String {
    const LAYOUT: Layout = Layout::Slots(1);
    const IS_DYNAMIC: bool = true;
    type Handler = Slot<Self>;

    fn handle(slot: U256, ctx: LayoutCtx, address: Address) -> Self::Handler {
        Slot::new_with_ctx(slot, ctx, address)
    }
}

// -- STORABLE OPS IMPLEMENTATIONS ---------------------------------------------

impl Storable for Bytes {
    #[inline]
    fn load<S: StorageOps>(storage: &S, slot: U256, ctx: LayoutCtx) -> Result<Self> {
        debug_assert_eq!(ctx, LayoutCtx::FULL, "Bytes cannot be packed");
        load_bytes_like(storage, slot, |data| Ok(Self::from(data)))
    }

    #[inline]
    fn store<S: StorageOps>(&self, storage: &mut S, slot: U256, ctx: LayoutCtx) -> Result<()> {
        debug_assert_eq!(ctx, LayoutCtx::FULL, "Bytes cannot be packed");
        store_bytes_like(self.as_ref(), storage, slot)
    }

    /// Custom delete for bytes-like types: clears keccak256-addressed data slots for long values.
    #[inline]
    fn delete<S: StorageOps>(storage: &mut S, slot: U256, ctx: LayoutCtx) -> Result<()> {
        debug_assert_eq!(ctx, LayoutCtx::FULL, "Bytes cannot be packed");
        delete_bytes_like(storage, slot)
    }
}

impl Storable for String {
    #[inline]
    fn load<S: StorageOps>(storage: &S, slot: U256, ctx: LayoutCtx) -> Result<Self> {
        debug_assert_eq!(ctx, LayoutCtx::FULL, "String cannot be packed");
        load_bytes_like(storage, slot, |data| {
            Self::from_utf8(data).map_err(|e| {
                TempoPrecompileError::Fatal(format!("Invalid UTF-8 in stored string: {e}"))
            })
        })
    }

    #[inline]
    fn store<S: StorageOps>(&self, storage: &mut S, slot: U256, ctx: LayoutCtx) -> Result<()> {
        debug_assert_eq!(ctx, LayoutCtx::FULL, "String cannot be packed");
        store_bytes_like(self.as_bytes(), storage, slot)
    }

    /// Custom delete for bytes-like types: clears keccak256-addressed data slots for long values.
    #[inline]
    fn delete<S: StorageOps>(storage: &mut S, slot: U256, ctx: LayoutCtx) -> Result<()> {
        debug_assert_eq!(ctx, LayoutCtx::FULL, "String cannot be packed");
        delete_bytes_like(storage, slot)
    }
}

// -- HELPER FUNCTIONS ---------------------------------------------------------

/// Generic load implementation for string-like types (String, Bytes) using Solidity's encoding.
#[inline]
fn load_bytes_like<T, S, F>(storage: &S, base_slot: U256, into: F) -> Result<T>
where
    S: StorageOps,
    F: FnOnce(Vec<u8>) -> Result<T>,
{
    let base_value = storage.load(base_slot)?;
    let is_long = is_long_string(base_value);
    let length = calc_string_length(base_value, is_long);

    if is_long {
        // Long string: read data from keccak256(base_slot) + i
        let slot_start = calc_data_slot(base_slot);
        let chunks = calc_chunks(length);
        let mut data = Vec::with_capacity(length);

        for i in 0..chunks {
            let slot = slot_start + U256::from(i);
            let chunk_value = storage.load(slot)?;
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
        storage.store(base_slot, encode_short_string(bytes))
    } else {
        storage.store(base_slot, encode_long_string_length(length))?;

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

            storage.store(slot, U256::from_be_bytes(chunk_bytes))?;
        }

        Ok(())
    }
}

/// Generic delete implementation for byte-like types (String, Bytes) using Solidity's encoding.
///
/// Clears both the main slot and any keccak256-addressed data slots for long strings.
#[inline]
fn delete_bytes_like<S: StorageOps>(storage: &mut S, base_slot: U256) -> Result<()> {
    let base_value = storage.load(base_slot)?;
    let is_long = is_long_string(base_value);

    if is_long {
        // Long string: need to clear data slots as well
        let length = calc_string_length(base_value, true);
        let slot_start = calc_data_slot(base_slot);
        let chunks = calc_chunks(length);

        // Clear all data slots
        for i in 0..chunks {
            let slot = slot_start + U256::from(i);
            storage.store(slot, U256::ZERO)?;
        }
    }

    // Clear the main slot
    storage.store(base_slot, U256::ZERO)
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
    use crate::{
        storage::{Handler, StorageCtx},
        test_util::setup_storage,
    };
    use proptest::prelude::*;

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

    // -- UNIT TESTS FOR HELPER FUNCTIONS (NO STORAGE) ------------------------

    #[test]
    fn test_calc_data_slot_matches_manual_keccak() {
        let base_slot = U256::random();
        let data_slot = calc_data_slot(base_slot);

        // Manual computation
        let expected = U256::from_be_bytes(keccak256(base_slot.to_be_bytes::<32>()).0);

        assert_eq!(
            data_slot, expected,
            "calc_data_slot should match manual keccak256 computation"
        );
    }

    #[test]
    fn test_is_long_string_boundaries() {
        // Short string (31 bytes): length * 2 = 62 (0x3E), bit 0 = 0
        let short_31_bytes = encode_short_string(&[b'a'; 31]);
        assert!(
            !is_long_string(short_31_bytes),
            "31-byte string should be short"
        );

        // Long string (32 bytes): length * 2 + 1 = 65 (0x41), bit 0 = 1
        let long_32_bytes = encode_long_string_length(32);
        assert!(
            is_long_string(long_32_bytes),
            "32-byte string should be long"
        );

        // Edge case: empty string
        let empty = encode_short_string(&[]);
        assert!(!is_long_string(empty), "Empty string should be short");

        // Edge case: 1-byte string
        let one_byte = encode_short_string(b"x");
        assert!(!is_long_string(one_byte), "1-byte string should be short");
    }

    #[test]
    fn test_calc_string_length_short() {
        // Test short strings with various lengths
        for len in 0..=31 {
            let bytes = vec![b'a'; len];
            let encoded = encode_short_string(&bytes);
            let decoded_len = calc_string_length(encoded, false);
            assert_eq!(
                decoded_len, len,
                "Short string length mismatch for {len} bytes"
            );
        }
    }

    #[test]
    fn test_calc_string_length_long() {
        // Test long strings with various lengths
        for len in [32, 33, 63, 64, 65, 100, 1000, 10000] {
            let encoded = encode_long_string_length(len);
            let decoded_len = calc_string_length(encoded, true);
            assert_eq!(
                decoded_len, len,
                "Long string length mismatch for {len} bytes"
            );
        }
    }

    #[test]
    fn test_calc_chunks_boundaries() {
        assert_eq!(calc_chunks(0), 0, "0 bytes should require 0 chunks");
        assert_eq!(calc_chunks(1), 1, "1 byte should require 1 chunk");
        assert_eq!(calc_chunks(31), 1, "31 bytes should require 1 chunk");
        assert_eq!(calc_chunks(32), 1, "32 bytes should require 1 chunk");
        assert_eq!(calc_chunks(33), 2, "33 bytes should require 2 chunks");
        assert_eq!(calc_chunks(64), 2, "64 bytes should require 2 chunks");
        assert_eq!(calc_chunks(65), 3, "65 bytes should require 3 chunks");
        assert_eq!(calc_chunks(100), 4, "100 bytes should require 4 chunks");
    }

    #[test]
    fn test_encode_short_string_format() {
        let test_str = b"Hello";
        let encoded = encode_short_string(test_str);
        let bytes = encoded.to_be_bytes::<32>();

        // Verify data is left-aligned
        assert_eq!(&bytes[..5], test_str, "Data should be left-aligned");

        // Verify padding is zero
        assert_eq!(&bytes[5..31], &[0u8; 26], "Padding should be zero");

        // Verify LSB contains length * 2
        assert_eq!(
            bytes[31],
            (test_str.len() * 2) as u8,
            "LSB should be length * 2"
        );

        // Verify bit 0 is 0 (short string marker)
        assert_eq!(bytes[31] & 1, 0, "Bit 0 should be 0 for short strings");
    }

    #[test]
    fn test_encode_short_string_empty() {
        let encoded = encode_short_string(&[]);
        let bytes = encoded.to_be_bytes::<32>();

        // All bytes should be zero for empty string
        assert_eq!(bytes, [0u8; 32], "Empty string should encode to all zeros");
    }

    #[test]
    fn test_encode_long_string_length_formula() {
        for len in [32, 33, 100, 1000, 10000] {
            let encoded = encode_long_string_length(len);
            let expected = U256::from(len * 2 + 1);
            assert_eq!(
                encoded, expected,
                "Long string length encoding mismatch for {len} bytes"
            );

            // Verify bit 0 is 1 (long string marker)
            assert_eq!(encoded.byte(0) & 1, 1, "Bit 0 should be 1 for long strings");
        }
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        // Short strings roundtrip
        for len in [0, 1, 15, 30, 31] {
            let bytes = vec![b'x'; len];
            let encoded = encode_short_string(&bytes);
            let decoded_len = calc_string_length(encoded, false);
            assert_eq!(
                decoded_len, len,
                "Short string roundtrip failed for {len} bytes"
            );
        }

        // Long strings roundtrip
        for len in [32, 33, 64, 100] {
            let encoded = encode_long_string_length(len);
            let decoded_len = calc_string_length(encoded, true);
            assert_eq!(
                decoded_len, len,
                "Long string roundtrip failed for {len} bytes"
            );
        }
    }

    // -- PROPERTY TESTS FOR STORAGE INTERACTION -------------------------------

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        #[test]
        fn test_short_strings(s in arb_short_string(), base_slot in arb_safe_slot()) {
            let (mut storage, address) = setup_storage();
            StorageCtx::enter(&mut storage, || {
                let mut slot = Slot::<String>::new(base_slot, address);

                // Verify store → load roundtrip
                slot.write(s.clone()).unwrap();
                let loaded = slot.read().unwrap();
                prop_assert_eq!(&s, &loaded, "Short string roundtrip failed");

                // Verify delete works
                slot.delete().unwrap();
                let after_delete = slot.read().unwrap();
                prop_assert_eq!(after_delete, String::new(), "Short string not empty after delete");

                Ok(())
            }).unwrap();
        }

        #[test]
        #[allow(clippy::redundant_clone)]
        fn test_32byte_strings(s in arb_32byte_string(), base_slot in arb_safe_slot()) {
            let (mut storage, address) = setup_storage();
            StorageCtx::enter(&mut storage, || {
                // Verify 32-byte boundary string is stored correctly
                prop_assert_eq!(s.len(), 32, "Generated string should be exactly 32 bytes");

                let mut slot = Slot::<String>::new(base_slot, address);

                // Verify store → load roundtrip
                slot.write(s.clone()).unwrap();
                let loaded = slot.read().unwrap();
                prop_assert_eq!(s.clone(), loaded, "32-byte string roundtrip failed");

                // Verify delete works
                slot.delete().unwrap();
                let after_delete = slot.read().unwrap();
                prop_assert_eq!(after_delete, String::new(), "32-byte string not empty after delete");

                Ok(())
            }).unwrap();
        }

        #[test]
        fn test_long_strings(s in arb_long_string(), base_slot in arb_safe_slot()) {
            let (mut storage, address) = setup_storage();
            StorageCtx::enter(&mut storage, || {
                let mut slot = Slot::<String>::new(base_slot, address);

                // Verify store → load roundtrip
                slot.write(s.clone()).unwrap();
                let loaded = slot.read().unwrap();
                prop_assert_eq!(&s, &loaded, "Long string roundtrip failed for length: {}", s.len());

                // Calculate how many data slots were used
                let chunks = calc_chunks(s.len());

                // Verify delete works (clears both main slot and keccak256-addressed data)
                slot.delete().unwrap();
                let after_delete = slot.read().unwrap();
                prop_assert_eq!(after_delete, String::new(), "Long string not empty after delete");

                // Verify all keccak256-addressed data slots are actually zero
                let data_slot_start = calc_data_slot(base_slot);
                for i in 0..chunks {
                    let slot = Slot::<U256>::new_at_offset(data_slot_start, i, address);
                    let value = slot.read().unwrap();
                    prop_assert_eq!(value, U256::ZERO, "Data slot not cleared after delete");
                }

                Ok(())
            }).unwrap();
        }

        #[test]
        fn test_short_bytes(b in arb_short_bytes(), base_slot in arb_safe_slot()) {
            let (mut storage, address) = setup_storage();
            StorageCtx::enter(&mut storage, || {
                let mut slot = Slot::<Bytes>::new(base_slot, address);

                // Verify store → load roundtrip
                slot.write(b.clone()).unwrap();
                let loaded = slot.read().unwrap();
                prop_assert_eq!(&b, &loaded, "Short bytes roundtrip failed for length: {}", b.len());

                // Verify delete works
                slot.delete().unwrap();
                let after_delete = slot.read().unwrap();
                prop_assert_eq!(after_delete, Bytes::new(), "Short bytes not empty after delete");

                Ok(())
            }).unwrap();
        }

        #[test]
        fn test_32byte_bytes(b in arb_32byte_bytes(), base_slot in arb_safe_slot()) {
            let (mut storage, address) = setup_storage();
            StorageCtx::enter(&mut storage, || {
                // Verify 32-byte boundary bytes is stored correctly
                prop_assert_eq!(b.len(), 32, "Generated bytes should be exactly 32 bytes");

                let mut slot = Slot::<Bytes>::new(base_slot, address);

                // Verify store → load roundtrip
                slot.write(b.clone()).unwrap();
                let loaded = slot.read().unwrap();
                prop_assert_eq!(&b, &loaded, "32-byte bytes roundtrip failed");

                // Verify delete works
                slot.delete().unwrap();
                let after_delete = slot.read().unwrap();
                prop_assert_eq!(after_delete, Bytes::new(), "32-byte bytes not empty after delete");

                Ok(())
            }).unwrap();
        }

        #[test]
        fn test_long_bytes(b in arb_long_bytes(), base_slot in arb_safe_slot()) {
            let (mut storage, address) = setup_storage();
            StorageCtx::enter(&mut storage, || {
                let mut slot = Slot::<Bytes>::new(base_slot, address);

                // Verify store → load roundtrip
                slot.write(b.clone()).unwrap();
                let loaded = slot.read().unwrap();
                prop_assert_eq!(&b, &loaded, "Long bytes roundtrip failed for length: {}", b.len());

                // Calculate how many data slots were used
                let chunks = calc_chunks(b.len());

                // Verify delete works (clears both main slot and keccak256-addressed data)
                slot.delete().unwrap();
                let after_delete = slot.read().unwrap();
                prop_assert_eq!(after_delete, Bytes::new(), "Long bytes not empty after delete");

                // Verify all keccak256-addressed data slots are actually zero
                let data_slot_start = calc_data_slot(base_slot);
                for i in 0..chunks {
                    let slot = Slot::<U256>::new_at_offset(data_slot_start, i, address);
                    let value = slot.read().unwrap();
                    prop_assert_eq!(value, U256::ZERO, "Data slot not cleared after delete");
                }

                Ok(())
            }).unwrap();
        }
    }
}
