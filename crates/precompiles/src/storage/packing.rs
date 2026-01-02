//! Shared utilities for packing and unpacking values in EVM storage slots.
//!
//! This module provides helper functions for bit-level manipulation of storage slots,
//! enabling efficient packing of multiple small values into single 32-byte slots.
//!
//! Packing only applies to primitive types where `LAYOUT::Bytes(count) && count < 32`.
//! Non-primitives (structs, fixed-size arrays, dynamic types) have `LAYOUT = Layout::Slot`.
//!
//! ## Solidity Compatibility
//!
//! This implementation matches Solidity's value packing convention:
//! - Values are right-aligned within their byte range
//! - Types smaller than 32 bytes can pack multiple per slot when dimensions align

use alloy::primitives::U256;

use crate::{
    error::Result,
    storage::{FromWord, Layout, StorableType, StorageOps},
};

/// A helper struct to support packing elements into a single slot. Represents an
/// in-memory storage slot value.
///
/// We used it when we operate on elements that are guaranteed to be packable.
/// To avoid doing multiple storage reads/writes when packing those elements, we
/// use this as an intermediate [`StorageOps`] implementation that can be passed to
/// `Storable::store` and `Storable::load`.
pub struct PackedSlot(pub U256);

impl StorageOps for PackedSlot {
    fn load(&self, _slot: U256) -> Result<U256> {
        Ok(self.0)
    }

    fn store(&mut self, _slot: U256, value: U256) -> Result<()> {
        self.0 = value;
        Ok(())
    }
}

/// Location information for a packed field within a storage slot.
#[derive(Debug, Clone, Copy)]
pub struct FieldLocation {
    /// Offset in slots from the base slot
    pub offset_slots: usize,
    /// Offset in bytes within the target slot
    pub offset_bytes: usize,
    /// Size of the field in bytes
    pub size: usize,
}

impl FieldLocation {
    /// Create a new field location
    #[inline]
    pub const fn new(offset_slots: usize, offset_bytes: usize, size: usize) -> Self {
        Self {
            offset_slots,
            offset_bytes,
            size,
        }
    }
}

/// Create a bit mask for a value of the given byte size.
///
/// For values less than 32 bytes, returns a mask with the appropriate number of bits set.
/// For 32-byte values, returns U256::MAX.
#[inline]
pub fn create_element_mask(byte_count: usize) -> U256 {
    if byte_count >= 32 {
        U256::MAX
    } else {
        (U256::ONE << (byte_count * 8)) - U256::ONE
    }
}

/// Extract a packed value from a storage slot at a given byte offset.
#[inline]
pub fn extract_from_word<T: FromWord + StorableType>(
    slot_value: U256,
    offset: usize,
    bytes: usize,
) -> Result<T> {
    debug_assert!(
        matches!(T::LAYOUT, Layout::Bytes(..)),
        "Packing is only supported by primitive types"
    );

    // Validate that the value doesn't span slot boundaries
    if offset + bytes > 32 {
        return Err(crate::error::TempoPrecompileError::Fatal(format!(
            "Value of {} bytes at offset {} would span slot boundary (max offset: {})",
            bytes,
            offset,
            32 - bytes
        )));
    }

    // Calculate how many bits to shift right to align the value
    let shift_bits = offset * 8;
    let mask = create_element_mask(bytes);

    // Extract and right-align the value
    T::from_word((slot_value >> shift_bits) & mask)
}

/// Insert a packed value into a storage slot at a given byte offset.
#[inline]
pub fn insert_into_word<T: FromWord + StorableType>(
    current: U256,
    value: &T,
    offset: usize,
    bytes: usize,
) -> Result<U256> {
    debug_assert!(
        matches!(T::LAYOUT, Layout::Bytes(..)),
        "Packing is only supported by primitive types"
    );

    // Validate that the value doesn't span slot boundaries
    if offset + bytes > 32 {
        return Err(crate::error::TempoPrecompileError::Fatal(format!(
            "Value of {} bytes at offset {} would span slot boundary (max offset: {})",
            bytes,
            offset,
            32 - bytes
        )));
    }

    // Encode field to its canonical right-aligned U256 representation
    let field_value = value.to_word();

    // Calculate shift and mask
    let shift_bits = offset * 8;
    let mask = create_element_mask(bytes);

    // Clear the bits for this field in the current slot value
    let clear_mask = !(mask << shift_bits);
    let cleared = current & clear_mask;

    // Position the new value and combine with cleared slot
    let positioned = (field_value & mask) << shift_bits;
    Ok(cleared | positioned)
}

/// Zero out a packed value in a storage slot at a given byte offset.
///
/// This is the inverse operation to `insert_into_word`, clearing the bits
/// for a specific field while preserving other packed values in the slot.
#[inline]
pub fn delete_from_word(current: U256, offset: usize, bytes: usize) -> Result<U256> {
    // Validate that the value doesn't span slot boundaries
    if offset + bytes > 32 {
        return Err(crate::error::TempoPrecompileError::Fatal(format!(
            "Value of {} bytes at offset {} would span slot boundary (max offset: {})",
            bytes,
            offset,
            32 - bytes
        )));
    }

    let mask = create_element_mask(bytes);
    let shifted_mask = mask << (offset * 8);
    Ok(current & !shifted_mask)
}

/// Calculate which slot an array element at index `idx` starts in.
#[inline]
pub const fn calc_element_slot(idx: usize, elem_bytes: usize) -> usize {
    (idx * elem_bytes) / 32
}

/// Calculate the byte offset within a slot for an array element at index `idx`.
#[inline]
pub const fn calc_element_offset(idx: usize, elem_bytes: usize) -> usize {
    (idx * elem_bytes) % 32
}

/// Calculate the element location within a slot for an array element at index `idx`.
#[inline]
pub const fn calc_element_loc(idx: usize, elem_bytes: usize) -> FieldLocation {
    FieldLocation::new(
        calc_element_slot(idx, elem_bytes),
        calc_element_offset(idx, elem_bytes),
        elem_bytes,
    )
}

/// Calculate the total number of slots needed for an array.
#[inline]
pub const fn calc_packed_slot_count(n: usize, elem_bytes: usize) -> usize {
    (n * elem_bytes).div_ceil(32)
}

/// Test helper function for constructing EVM words from hex string literals.
///
/// Takes an array of hex strings (with or without "0x" prefix), concatenates
/// them left-to-right, left-pads with zeros to 32 bytes, and returns a U256.
///
/// # Example
/// ```ignore
/// let word = gen_word_from(&[
///     "0x2a",                                        // 1 byte
///     "0x1111111111111111111111111111111111111111",  // 20 bytes
///     "0x01",                                        // 1 byte
/// ]);
/// // Produces: [10 zeros] [0x2a] [20 bytes of 0x11] [0x01]
/// ```
#[cfg(any(test, feature = "test-utils"))]
pub fn gen_word_from(values: &[&str]) -> U256 {
    let mut bytes = Vec::new();

    for value in values {
        let hex_str = value.strip_prefix("0x").unwrap_or(value);

        // Parse hex string to bytes
        assert!(
            hex_str.len() % 2 == 0,
            "Hex string '{value}' has odd length"
        );

        for i in (0..hex_str.len()).step_by(2) {
            let byte_str = &hex_str[i..i + 2];
            let byte = u8::from_str_radix(byte_str, 16)
                .unwrap_or_else(|e| panic!("Invalid hex in '{value}': {e}"));
            bytes.push(byte);
        }
    }

    assert!(
        bytes.len() <= 32,
        "Total bytes ({}) exceed 32-byte slot limit",
        bytes.len()
    );

    // Left-pad with zeros to 32 bytes
    let mut slot_bytes = [0u8; 32];
    let start_idx = 32 - bytes.len();
    slot_bytes[start_idx..].copy_from_slice(&bytes);

    U256::from_be_bytes(slot_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::{
            Handler, StorageCtx,
            types::{LayoutCtx, Slot},
        },
        test_util::{gen_word_from, setup_storage},
    };
    use alloy::primitives::Address;

    // -- HELPER FUNCTION TESTS ----------------------------------------------------

    #[test]
    fn test_calc_element_slot() {
        // u8 array (1 byte per element)
        assert_eq!(calc_element_slot(0, 1), 0);
        assert_eq!(calc_element_slot(31, 1), 0);
        assert_eq!(calc_element_slot(32, 1), 1);
        assert_eq!(calc_element_slot(63, 1), 1);
        assert_eq!(calc_element_slot(64, 1), 2);

        // u16 array (2 bytes per element)
        assert_eq!(calc_element_slot(0, 2), 0);
        assert_eq!(calc_element_slot(15, 2), 0);
        assert_eq!(calc_element_slot(16, 2), 1);

        // Address array (20 bytes per element)
        assert_eq!(calc_element_slot(0, 20), 0);
        assert_eq!(calc_element_slot(1, 20), 0);
        assert_eq!(calc_element_slot(2, 20), 1); // 40 bytes = 2 slots
    }

    #[test]
    fn test_calc_element_offset() {
        // u8 array
        assert_eq!(calc_element_offset(0, 1), 0);
        assert_eq!(calc_element_offset(1, 1), 1);
        assert_eq!(calc_element_offset(31, 1), 31);
        assert_eq!(calc_element_offset(32, 1), 0);

        // u16 array
        assert_eq!(calc_element_offset(0, 2), 0);
        assert_eq!(calc_element_offset(1, 2), 2);
        assert_eq!(calc_element_offset(15, 2), 30);
        assert_eq!(calc_element_offset(16, 2), 0);

        // address array
        assert_eq!(calc_element_offset(0, 20), 0);
        assert_eq!(calc_element_offset(1, 20), 20);
        assert_eq!(calc_element_offset(2, 20), 8);
    }

    #[test]
    fn test_calc_packed_slot_count() {
        // u8 array
        assert_eq!(calc_packed_slot_count(10, 1), 1); // [u8; 10] = 10 bytes
        assert_eq!(calc_packed_slot_count(32, 1), 1); // [u8; 32] = 32 bytes
        assert_eq!(calc_packed_slot_count(33, 1), 2); // [u8; 33] = 33 bytes
        assert_eq!(calc_packed_slot_count(100, 1), 4); // [u8; 100] = 100 bytes

        // u16 array
        assert_eq!(calc_packed_slot_count(16, 2), 1); // [u16; 16] = 32 bytes
        assert_eq!(calc_packed_slot_count(17, 2), 2); // [u16; 17] = 34 bytes

        // address array
        assert_eq!(calc_packed_slot_count(1, 20), 1); // [Address; 1] = 20 bytes
        assert_eq!(calc_packed_slot_count(2, 20), 2); // [Address; 2] = 40 bytes
        assert_eq!(calc_packed_slot_count(3, 20), 2); // [Address; 3] = 60 bytes
    }

    #[test]
    fn test_create_element_mask() {
        // 1 byte mask
        assert_eq!(create_element_mask(1), U256::from(0xff));

        // 2 byte mask
        assert_eq!(create_element_mask(2), U256::from(0xffff));

        // 4 byte mask
        assert_eq!(create_element_mask(4), U256::from(0xffffffffu32));

        // 8 byte mask
        assert_eq!(create_element_mask(8), U256::from(u64::MAX));

        // 16 byte mask (u128::MAX)
        assert_eq!(create_element_mask(16), U256::from(u128::MAX));

        // 32 byte mask
        assert_eq!(create_element_mask(32), U256::MAX);

        // Greater than 32 bytes should also return MAX
        assert_eq!(create_element_mask(64), U256::MAX);
    }

    #[test]
    fn test_delete_from_word() {
        // Start with a slot containing multiple packed u8 values
        let slot = gen_word_from(&[
            "0xff", // offset 3 (1 byte)
            "0x56", // offset 2 (1 byte)
            "0x34", // offset 1 (1 byte)
            "0x12", // offset 0 (1 byte)
        ]);

        // Zero out the value at offset 1
        let cleared = delete_from_word(slot, 1, 1).unwrap();
        let expected = gen_word_from(&[
            "0xff", // offset 3 - unchanged
            "0x56", // offset 2 - unchanged
            "0x00", // offset 1 - cleared
            "0x12", // offset 0 - unchanged
        ]);
        assert_eq!(cleared, expected, "Should zero offset 1");

        // Zero out a u16 (2 bytes) at offset 0
        let slot = gen_word_from(&["0x5678", "0x1234"]);
        let cleared = delete_from_word(slot, 0, 2).unwrap();
        let expected = gen_word_from(&["0x5678", "0x0000"]);
        assert_eq!(cleared, expected, "Should zero u16 at offset 0");

        // Zero out the last byte in a slot
        let slot = gen_word_from(&["0xff"]);
        let cleared = delete_from_word(slot, 0, 1).unwrap();
        assert_eq!(cleared, U256::ZERO, "Should zero entire slot");
    }

    // -- BOUNDARY VALIDATION ------------------------------------------------------

    #[test]
    fn test_boundary_validation_rejects_spanning() {
        // Address (20 bytes) at offset 13 would span slot boundary (13 + 20 = 33 > 32)
        let addr = Address::random();
        let result = insert_into_word(U256::ZERO, &addr, 13, 20);
        assert!(
            result.is_err(),
            "Should reject address at offset 13 (would span slot)"
        );

        // u16 (2 bytes) at offset 31 would span slot boundary (31 + 2 = 33 > 32)
        let val: u16 = 42;
        let result = insert_into_word(U256::ZERO, &val, 31, 2);
        assert!(
            result.is_err(),
            "Should reject u16 at offset 31 (would span slot)"
        );

        // u32 (4 bytes) at offset 29 would span slot boundary (29 + 4 = 33 > 32)
        let val: u32 = 42;
        let result = insert_into_word(U256::ZERO, &val, 29, 4);
        assert!(
            result.is_err(),
            "Should reject u32 at offset 29 (would span slot)"
        );

        // Test extract as well
        let result = extract_from_word::<Address>(U256::ZERO, 13, 20);
        assert!(
            result.is_err(),
            "Should reject extracting address from offset 13"
        );
    }

    #[test]
    fn test_boundary_validation_accepts_valid() {
        // Address (20 bytes) at offset 12 is valid (12 + 20 = 32)
        let addr = Address::random();
        let result = insert_into_word(U256::ZERO, &addr, 12, 20);
        assert!(result.is_ok(), "Should accept address at offset 12");

        // u16 (2 bytes) at offset 30 is valid (30 + 2 = 32)
        let val: u16 = 42;
        let result = insert_into_word(U256::ZERO, &val, 30, 2);
        assert!(result.is_ok(), "Should accept u16 at offset 30");

        // u8 (1 byte) at offset 31 is valid (31 + 1 = 32)
        let val: u8 = 42;
        let result = insert_into_word(U256::ZERO, &val, 31, 1);
        assert!(result.is_ok(), "Should accept u8 at offset 31");

        // U256 (32 bytes) at offset 0 is valid (0 + 32 = 32)
        let val = U256::from(42);
        let result = insert_into_word(U256::ZERO, &val, 0, 32);
        assert!(result.is_ok(), "Should accept U256 at offset 0");
    }

    // -- PACKING VALIDATION ------------------------------------------------------

    #[test]
    fn test_bool() {
        // single bool
        let expected = gen_word_from(&[
            "0x01", // offset 0 (1 byte)
        ]);

        let slot = insert_into_word(U256::ZERO, &true, 0, 1).unwrap();
        assert_eq!(
            slot, expected,
            "Single bool [true] should match Solidity layout"
        );
        assert!(extract_from_word::<bool>(slot, 0, 1).unwrap());

        // two bools
        let expected = gen_word_from(&[
            "0x01", // offset 1 (1 byte)
            "0x01", // offset 0 (1 byte)
        ]);

        let mut slot = U256::ZERO;
        slot = insert_into_word(slot, &true, 0, 1).unwrap();
        slot = insert_into_word(slot, &true, 1, 1).unwrap();
        assert_eq!(slot, expected, "[true, true] should match Solidity layout");
        assert!(extract_from_word::<bool>(slot, 0, 1).unwrap());
        assert!(extract_from_word::<bool>(slot, 1, 1).unwrap());
    }

    #[test]
    fn test_u8_packing() {
        // Pack multiple u8 values
        let v1: u8 = 0x12;
        let v2: u8 = 0x34;
        let v3: u8 = 0x56;
        let v4: u8 = u8::MAX;

        let expected = gen_word_from(&[
            "0xff", // offset 3 (1 byte)
            "0x56", // offset 2 (1 byte)
            "0x34", // offset 1 (1 byte)
            "0x12", // offset 0 (1 byte)
        ]);

        let mut slot = U256::ZERO;
        slot = insert_into_word(slot, &v1, 0, 1).unwrap();
        slot = insert_into_word(slot, &v2, 1, 1).unwrap();
        slot = insert_into_word(slot, &v3, 2, 1).unwrap();
        slot = insert_into_word(slot, &v4, 3, 1).unwrap();

        assert_eq!(slot, expected, "u8 packing should match Solidity layout");
        assert_eq!(extract_from_word::<u8>(slot, 0, 1).unwrap(), v1);
        assert_eq!(extract_from_word::<u8>(slot, 1, 1).unwrap(), v2);
        assert_eq!(extract_from_word::<u8>(slot, 2, 1).unwrap(), v3);
        assert_eq!(extract_from_word::<u8>(slot, 3, 1).unwrap(), v4);
    }

    #[test]
    fn test_u16_packing() {
        // Pack u16 values including max
        let v1: u16 = 0x1234;
        let v2: u16 = 0x5678;
        let v3: u16 = u16::MAX;

        let expected = gen_word_from(&[
            "0xffff", // offset 4 (2 bytes)
            "0x5678", // offset 2 (2 bytes)
            "0x1234", // offset 0 (2 bytes)
        ]);

        let mut slot = U256::ZERO;
        slot = insert_into_word(slot, &v1, 0, 2).unwrap();
        slot = insert_into_word(slot, &v2, 2, 2).unwrap();
        slot = insert_into_word(slot, &v3, 4, 2).unwrap();

        assert_eq!(slot, expected, "u16 packing should match Solidity layout");
        assert_eq!(extract_from_word::<u16>(slot, 0, 2).unwrap(), v1);
        assert_eq!(extract_from_word::<u16>(slot, 2, 2).unwrap(), v2);
        assert_eq!(extract_from_word::<u16>(slot, 4, 2).unwrap(), v3);
    }

    #[test]
    fn test_u32_packing() {
        // Pack u32 values
        let v1: u32 = 0x12345678;
        let v2: u32 = u32::MAX;

        let expected = gen_word_from(&[
            "0xffffffff", // offset 4 (4 bytes)
            "0x12345678", // offset 0 (4 bytes)
        ]);

        let mut slot = U256::ZERO;
        slot = insert_into_word(slot, &v1, 0, 4).unwrap();
        slot = insert_into_word(slot, &v2, 4, 4).unwrap();

        assert_eq!(slot, expected, "u32 packing should match Solidity layout");
        assert_eq!(extract_from_word::<u32>(slot, 0, 4).unwrap(), v1);
        assert_eq!(extract_from_word::<u32>(slot, 4, 4).unwrap(), v2);
    }

    #[test]
    fn test_u64_packing() {
        // Pack u64 values
        let v1: u64 = 0x123456789abcdef0;
        let v2: u64 = u64::MAX;

        let expected = gen_word_from(&[
            "0xffffffffffffffff", // offset 8 (8 bytes)
            "0x123456789abcdef0", // offset 0 (8 bytes)
        ]);

        let mut slot = U256::ZERO;
        slot = insert_into_word(slot, &v1, 0, 8).unwrap();
        slot = insert_into_word(slot, &v2, 8, 8).unwrap();

        assert_eq!(slot, expected, "u64 packing should match Solidity layout");
        assert_eq!(extract_from_word::<u64>(slot, 0, 8).unwrap(), v1);
        assert_eq!(extract_from_word::<u64>(slot, 8, 8).unwrap(), v2);
    }

    #[test]
    fn test_u128_packing() {
        // Pack two u128 values (fills entire slot)
        let v1: u128 = 0x123456789abcdef0fedcba9876543210;
        let v2: u128 = u128::MAX;

        let expected = gen_word_from(&[
            "0xffffffffffffffffffffffffffffffff", // offset 16 (16 bytes)
            "0x123456789abcdef0fedcba9876543210", // offset 0 (16 bytes)
        ]);

        let mut slot = U256::ZERO;
        slot = insert_into_word(slot, &v1, 0, 16).unwrap();
        slot = insert_into_word(slot, &v2, 16, 16).unwrap();

        assert_eq!(slot, expected, "u128 packing should match Solidity layout");
        assert_eq!(extract_from_word::<u128>(slot, 0, 16).unwrap(), v1);
        assert_eq!(extract_from_word::<u128>(slot, 16, 16).unwrap(), v2);
    }

    #[test]
    fn test_u256_packing() {
        // u256 takes full slot
        let value = U256::from_be_bytes([
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            0xdd, 0xee, 0xff, 0x00,
        ]);

        let expected =
            gen_word_from(&["0x123456789abcdef0fedcba9876543210112233445566778899aabbccddeeff00"]);

        let slot = insert_into_word(U256::ZERO, &value, 0, 32).unwrap();
        assert_eq!(slot, expected, "u256 packing should match Solidity layout");
        assert_eq!(extract_from_word::<U256>(slot, 0, 32).unwrap(), value);

        // Test U256::MAX
        let slot = insert_into_word(U256::ZERO, &U256::MAX, 0, 32).unwrap();
        assert_eq!(extract_from_word::<U256>(slot, 0, 32).unwrap(), U256::MAX);
    }

    #[test]
    fn test_i8_packing() {
        // Pack signed i8 values including negative numbers
        let v1: i8 = -128; // i8::MIN
        let v2: i8 = 0;
        let v3: i8 = 127; // i8::MAX
        let v4: i8 = -1;

        let expected = gen_word_from(&[
            "0xff", // offset 3: -1 (two's complement)
            "0x7f", // offset 2: 127
            "0x00", // offset 1: 0
            "0x80", // offset 0: -128 (two's complement)
        ]);

        let mut slot = U256::ZERO;
        slot = insert_into_word(slot, &v1, 0, 1).unwrap();
        slot = insert_into_word(slot, &v2, 1, 1).unwrap();
        slot = insert_into_word(slot, &v3, 2, 1).unwrap();
        slot = insert_into_word(slot, &v4, 3, 1).unwrap();

        assert_eq!(slot, expected, "i8 packing should match Solidity layout");
        assert_eq!(extract_from_word::<i8>(slot, 0, 1).unwrap(), v1);
        assert_eq!(extract_from_word::<i8>(slot, 1, 1).unwrap(), v2);
        assert_eq!(extract_from_word::<i8>(slot, 2, 1).unwrap(), v3);
        assert_eq!(extract_from_word::<i8>(slot, 3, 1).unwrap(), v4);
    }

    #[test]
    fn test_i16_packing() {
        // Pack signed i16 values
        let v1: i16 = -32768; // i16::MIN
        let v2: i16 = 32767; // i16::MAX
        let v3: i16 = -1;

        let expected = gen_word_from(&[
            "0xffff", // offset 4: -1 (two's complement)
            "0x7fff", // offset 2: 32767
            "0x8000", // offset 0: -32768 (two's complement)
        ]);

        let mut slot = U256::ZERO;
        slot = insert_into_word(slot, &v1, 0, 2).unwrap();
        slot = insert_into_word(slot, &v2, 2, 2).unwrap();
        slot = insert_into_word(slot, &v3, 4, 2).unwrap();

        assert_eq!(slot, expected, "i16 packing should match Solidity layout");
        assert_eq!(extract_from_word::<i16>(slot, 0, 2).unwrap(), v1);
        assert_eq!(extract_from_word::<i16>(slot, 2, 2).unwrap(), v2);
        assert_eq!(extract_from_word::<i16>(slot, 4, 2).unwrap(), v3);
    }

    #[test]
    fn test_i32_packing() {
        // Pack signed i32 values
        let v1: i32 = -2147483648; // i32::MIN
        let v2: i32 = 2147483647; // i32::MAX

        let expected = gen_word_from(&[
            "0x7fffffff", // offset 4: i32::MAX
            "0x80000000", // offset 0: i32::MIN (two's complement)
        ]);

        let mut slot = U256::ZERO;
        slot = insert_into_word(slot, &v1, 0, 4).unwrap();
        slot = insert_into_word(slot, &v2, 4, 4).unwrap();

        assert_eq!(slot, expected, "i32 packing should match Solidity layout");
        assert_eq!(extract_from_word::<i32>(slot, 0, 4).unwrap(), v1);
        assert_eq!(extract_from_word::<i32>(slot, 4, 4).unwrap(), v2);
    }

    #[test]
    fn test_i64_packing() {
        // Pack signed i64 values
        let v1: i64 = -9223372036854775808; // i64::MIN
        let v2: i64 = 9223372036854775807; // i64::MAX

        let expected = gen_word_from(&[
            "0x7fffffffffffffff", // offset 8: i64::MAX
            "0x8000000000000000", // offset 0: i64::MIN (two's complement)
        ]);

        let mut slot = U256::ZERO;
        slot = insert_into_word(slot, &v1, 0, 8).unwrap();
        slot = insert_into_word(slot, &v2, 8, 8).unwrap();

        assert_eq!(slot, expected, "i64 packing should match Solidity layout");
        assert_eq!(extract_from_word::<i64>(slot, 0, 8).unwrap(), v1);
        assert_eq!(extract_from_word::<i64>(slot, 8, 8).unwrap(), v2);
    }

    #[test]
    fn test_i128_packing() {
        // Pack two i128 values (fills entire slot)
        let v1: i128 = -170141183460469231731687303715884105728; // i128::MIN
        let v2: i128 = 170141183460469231731687303715884105727; // i128::MAX

        let expected = gen_word_from(&[
            "0x7fffffffffffffffffffffffffffffff", // offset 16: i128::MAX
            "0x80000000000000000000000000000000", // offset 0: i128::MIN (two's complement)
        ]);

        let mut slot = U256::ZERO;
        slot = insert_into_word(slot, &v1, 0, 16).unwrap();
        slot = insert_into_word(slot, &v2, 16, 16).unwrap();

        assert_eq!(slot, expected, "i128 packing should match Solidity layout");
        assert_eq!(extract_from_word::<i128>(slot, 0, 16).unwrap(), v1);
        assert_eq!(extract_from_word::<i128>(slot, 16, 16).unwrap(), v2);
    }

    #[test]
    fn test_mixed_uint_packing() {
        // Pack various types together: u8 + u16 + u32 + u64
        let v1: u8 = 0xaa;
        let v2: u16 = 0xbbcc;
        let v3: u32 = 0xddeeff00;
        let v4: u64 = 0x1122334455667788;

        let expected = gen_word_from(&[
            "0x1122334455667788", // u64 at offset 7 (8 bytes)
            "0xddeeff00",         // u32 at offset 3 (4 bytes)
            "0xbbcc",             // u16 at offset 1 (2 bytes)
            "0xaa",               // u8 at offset 0 (1 byte)
        ]);

        let mut slot = U256::ZERO;
        slot = insert_into_word(slot, &v1, 0, 1).unwrap();
        slot = insert_into_word(slot, &v2, 1, 2).unwrap();
        slot = insert_into_word(slot, &v3, 3, 4).unwrap();
        slot = insert_into_word(slot, &v4, 7, 8).unwrap();

        assert_eq!(
            slot, expected,
            "Mixed types packing should match Solidity layout"
        );
        assert_eq!(extract_from_word::<u8>(slot, 0, 1).unwrap(), v1);
        assert_eq!(extract_from_word::<u16>(slot, 1, 2).unwrap(), v2);
        assert_eq!(extract_from_word::<u32>(slot, 3, 4).unwrap(), v3);
        assert_eq!(extract_from_word::<u64>(slot, 7, 8).unwrap(), v4);
    }

    #[test]
    fn test_mixed_type_packing() {
        let addr = Address::from([0x11; 20]);
        let number: u8 = 0x2a;

        let expected = gen_word_from(&[
            "0x2a",                                       // offset 21 (1 byte)
            "0x1111111111111111111111111111111111111111", // offset 1 (20 bytes)
            "0x01",                                       // offset 0 (1 byte)
        ]);

        let mut slot = U256::ZERO;
        slot = insert_into_word(slot, &true, 0, 1).unwrap();
        slot = insert_into_word(slot, &addr, 1, 20).unwrap();
        slot = insert_into_word(slot, &number, 21, 1).unwrap();
        assert_eq!(
            slot, expected,
            "[bool, address, u8] should match Solidity layout"
        );
        assert!(extract_from_word::<bool>(slot, 0, 1).unwrap());
        assert_eq!(extract_from_word::<Address>(slot, 1, 20).unwrap(), addr);
        assert_eq!(extract_from_word::<u8>(slot, 21, 1).unwrap(), number);
    }

    #[test]
    fn test_zero_values() {
        // Ensure zero values pack correctly and don't bleed bits
        let v1: u8 = 0;
        let v2: u16 = 0;
        let v3: u32 = 0;

        let expected = U256::ZERO;

        let mut slot = U256::ZERO;
        slot = insert_into_word(slot, &v1, 0, 1).unwrap();
        slot = insert_into_word(slot, &v2, 1, 2).unwrap();
        slot = insert_into_word(slot, &v3, 3, 4).unwrap();

        assert_eq!(slot, expected, "Zero values should produce zero slot");
        assert_eq!(extract_from_word::<u8>(slot, 0, 1).unwrap(), 0);
        assert_eq!(extract_from_word::<u16>(slot, 1, 2).unwrap(), 0);
        assert_eq!(extract_from_word::<u32>(slot, 3, 4).unwrap(), 0);

        // Test that zeros don't interfere with non-zero values
        let v4: u8 = 0xff;
        slot = insert_into_word(slot, &v4, 10, 1).unwrap();
        assert_eq!(extract_from_word::<u8>(slot, 0, 1).unwrap(), 0);
        assert_eq!(extract_from_word::<u8>(slot, 10, 1).unwrap(), 0xff);
    }

    // -- SLOT PACKED FIELD TESTS ------------------------------------------

    #[test]
    fn test_packed_at_multiple_types() -> Result<()> {
        let (mut storage, address) = setup_storage();
        StorageCtx::enter(&mut storage, || {
            let struct_base = U256::from(0x2000);

            // Pack multiple types in same slot: bool(1) + u64(8) + u128(16)
            let flag = true;
            let timestamp: u64 = 1234567890;
            let amount: u128 = 999888777666;

            let mut flag_slot =
                Slot::<bool>::new_with_ctx(struct_base, LayoutCtx::packed(0), address);
            flag_slot.write(flag)?;
            assert_eq!(flag_slot.read()?, flag);

            let mut ts_slot = Slot::<u64>::new_with_ctx(struct_base, LayoutCtx::packed(1), address);
            ts_slot.write(timestamp)?;
            assert_eq!(ts_slot.read()?, timestamp);

            let mut amount_slot =
                Slot::<u128>::new_with_ctx(struct_base, LayoutCtx::packed(9), address);
            amount_slot.write(amount)?;
            assert_eq!(amount_slot.read()?, amount);

            // Clear the middle one
            amount_slot.delete()?;
            assert_eq!(flag_slot.read()?, flag);
            assert_eq!(amount_slot.read()?, 0);
            assert_eq!(ts_slot.read()?, timestamp);

            Ok(())
        })
    }

    #[test]
    fn test_packed_at_different_slots() -> Result<()> {
        let (mut storage, address) = setup_storage();
        StorageCtx::enter(&mut storage, || {
            let struct_base = U256::from(0x4000);

            // Field in slot 0 (bool is 1 byte, packable)
            let flag = false;
            let mut flag_slot =
                Slot::<bool>::new_with_ctx(struct_base, LayoutCtx::packed(0), address);
            flag_slot.write(flag)?;
            assert_eq!(flag_slot.read()?, flag);

            // Field in slot 1 (u128 is 16 bytes, packable)
            let amount: u128 = 0xdeadbeef;
            let mut amount_slot = Slot::<u128>::new_with_ctx(
                struct_base + U256::from(1),
                LayoutCtx::packed(0),
                address,
            );
            amount_slot.write(amount)?;
            assert_eq!(amount_slot.read()?, amount);

            // Field in slot 2 (u64 is 8 bytes, packable)
            let value: u64 = 123456789;
            let mut value_slot = Slot::<u64>::new_with_ctx(
                struct_base + U256::from(2),
                LayoutCtx::packed(0),
                address,
            );
            value_slot.write(value)?;
            assert_eq!(value_slot.read()?, value);

            Ok(())
        })
    }

    // -- PROPERTY TESTS -----------------------------------------------------------

    use proptest::prelude::*;

    /// Strategy for generating random Address values
    fn arb_address() -> impl Strategy<Value = Address> {
        any::<[u8; 20]>().prop_map(Address::from)
    }

    /// Strategy for generating random U256 values
    fn arb_u256() -> impl Strategy<Value = U256> {
        any::<[u64; 4]>().prop_map(U256::from_limbs)
    }

    /// Strategy for generating valid offsets for a given byte size
    fn arb_offset(bytes: usize) -> impl Strategy<Value = usize> {
        0..=(32 - bytes)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        #[test]
        fn proptest_roundtrip_u8(value: u8, offset in arb_offset(1)) {
            let slot = insert_into_word(U256::ZERO, &value, offset, 1)?;
            let extracted: u8 = extract_from_word(slot, offset, 1)?;
            prop_assert_eq!(extracted, value);
        }

        #[test]
        fn proptest_roundtrip_u16(value: u16, offset in arb_offset(2)) {
            let slot = insert_into_word(U256::ZERO, &value, offset, 2)?;
            let extracted: u16 = extract_from_word(slot, offset, 2)?;
            prop_assert_eq!(extracted, value);
        }

        #[test]
        fn proptest_roundtrip_u32(value: u32, offset in arb_offset(4)) {
            let slot = insert_into_word(U256::ZERO, &value, offset, 4)?;
            let extracted: u32 = extract_from_word(slot, offset, 4)?;
            prop_assert_eq!(extracted, value);
        }

        #[test]
        fn proptest_roundtrip_u64(value: u64, offset in arb_offset(8)) {
            let slot = insert_into_word(U256::ZERO, &value, offset, 8)?;
            let extracted: u64 = extract_from_word(slot, offset, 8)?;
            prop_assert_eq!(extracted, value);
        }

        #[test]
        fn proptest_roundtrip_u128(value: u128, offset in arb_offset(16)) {
            let slot = insert_into_word(U256::ZERO, &value, offset, 16)?;
            let extracted: u128 = extract_from_word(slot, offset, 16)?;
            prop_assert_eq!(extracted, value);
        }

        #[test]
        fn proptest_roundtrip_address(addr in arb_address(), offset in arb_offset(20)) {
            let slot = insert_into_word(U256::ZERO, &addr, offset, 20)?;
            let extracted: Address = extract_from_word(slot, offset, 20)?;
            prop_assert_eq!(extracted, addr);
        }

        #[test]
        fn proptest_roundtrip_u256(value in arb_u256()) {
            // U256 takes the full 32 bytes, so offset must be 0
            let slot = insert_into_word(U256::ZERO, &value, 0, 32)?;
            let extracted: U256 = extract_from_word(slot, 0, 32)?;
            prop_assert_eq!(extracted, value);
        }

        #[test]
        fn proptest_roundtrip_bool(value: bool, offset in arb_offset(1)) {
            let slot = insert_into_word(U256::ZERO, &value, offset, 1)?;
            let extracted: bool = extract_from_word(slot, offset, 1)?;
            prop_assert_eq!(extracted, value);
        }

        #[test]
        fn proptest_roundtrip_i8(value: i8, offset in arb_offset(1)) {
            let slot = insert_into_word(U256::ZERO, &value, offset, 1)?;
            let extracted: i8 = extract_from_word(slot, offset, 1)?;
            prop_assert_eq!(extracted, value);
        }

        #[test]
        fn proptest_roundtrip_i16(value: i16, offset in arb_offset(2)) {
            let slot = insert_into_word(U256::ZERO, &value, offset, 2)?;
            let extracted: i16 = extract_from_word(slot, offset, 2)?;
            prop_assert_eq!(extracted, value);
        }

        #[test]
        fn proptest_roundtrip_i32(value: i32, offset in arb_offset(4)) {
            let slot = insert_into_word(U256::ZERO, &value, offset, 4)?;
            let extracted: i32 = extract_from_word(slot, offset, 4)?;
            prop_assert_eq!(extracted, value);
        }

        #[test]
        fn proptest_roundtrip_i64(value: i64, offset in arb_offset(8)) {
            let slot = insert_into_word(U256::ZERO, &value, offset, 8)?;
            let extracted: i64 = extract_from_word(slot, offset, 8)?;
            prop_assert_eq!(extracted, value);
        }

        #[test]
        fn proptest_roundtrip_i128(value: i128, offset in arb_offset(16)) {
            let slot = insert_into_word(U256::ZERO, &value, offset, 16)?;
            let extracted: i128 = extract_from_word(slot, offset, 16)?;
            prop_assert_eq!(extracted, value);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        #[test]
        fn proptest_multiple_values_no_interference(
            v1: u8,
            v2: u16,
            v3: u32,
        ) {
            // Pack three values at non-overlapping offsets
            // u8 at offset 0 (1 byte)
            // u16 at offset 1 (2 bytes)
            // u32 at offset 3 (4 bytes)
            let mut slot = U256::ZERO;
            slot = insert_into_word(slot, &v1, 0, 1)?;
            slot = insert_into_word(slot, &v2, 1, 2)?;
            slot = insert_into_word(slot, &v3, 3, 4)?;

            // Verify all values can be extracted correctly
            let e1: u8 = extract_from_word(slot, 0, 1)?;
            let e2: u16 = extract_from_word(slot, 1, 2)?;
            let e3: u32 = extract_from_word(slot, 3, 4)?;

            prop_assert_eq!(e1, v1);
            prop_assert_eq!(e2, v2);
            prop_assert_eq!(e3, v3);
        }

        #[test]
        fn proptest_overwrite_preserves_others(
            v1: u8,
            v2: u16,
            v1_new: u8,
        ) {
            // Pack two values
            let mut slot = U256::ZERO;
            slot = insert_into_word(slot, &v1, 0, 1)?;
            slot = insert_into_word(slot, &v2, 1, 2)?;

            // Overwrite the first value
            slot = insert_into_word(slot, &v1_new, 0, 1)?;

            // Verify the second value is unchanged
            let e1: u8 = extract_from_word(slot, 0, 1)?;
            let e2: u16 = extract_from_word(slot, 1, 2)?;

            prop_assert_eq!(e1, v1_new);
            prop_assert_eq!(e2, v2); // Should be unchanged
        }

        #[test]
        fn proptest_bool_with_mixed_types(
            flag1: bool,
            u16_val: u16,
            flag2: bool,
            u32_val: u32,
        ) {
            // Pack bools alongside other types: bool(1) | u16(2) | bool(1) | u32(4)
            let mut slot = U256::ZERO;
            slot = insert_into_word(slot, &flag1, 0, 1)?;
            slot = insert_into_word(slot, &u16_val, 1, 2)?;
            slot = insert_into_word(slot, &flag2, 3, 1)?;
            slot = insert_into_word(slot, &u32_val, 4, 4)?;

            // Extract and verify all values
            let e_flag1: bool = extract_from_word(slot, 0, 1)?;
            let e_u16: u16 = extract_from_word(slot, 1, 2)?;
            let e_flag2: bool = extract_from_word(slot, 3, 1)?;
            let e_u32: u32 = extract_from_word(slot, 4, 4)?;

            prop_assert_eq!(e_flag1, flag1);
            prop_assert_eq!(e_u16, u16_val);
            prop_assert_eq!(e_flag2, flag2);
            prop_assert_eq!(e_u32, u32_val);
        }

        #[test]
        fn proptest_multiple_bools_no_interference(
            flags in proptest::collection::vec(any::<bool>(), 1..=20)
        ) {
            // Pack multiple bools at consecutive offsets
            let mut slot = U256::ZERO;
            for (i, &flag) in flags.iter().enumerate() {
                slot = insert_into_word(slot, &flag, i, 1)?;
            }

            // Verify all flags can be extracted correctly
            for (i, &expected_flag) in flags.iter().enumerate() {
                let extracted: bool = extract_from_word(slot, i, 1)?;
                prop_assert_eq!(extracted, expected_flag, "Flag at offset {} mismatch", i);
            }
        }

        #[test]
        fn proptest_element_slot_offset_consistency_u8(
            idx in 0usize..1000,
        ) {
            // For u8 arrays (1 byte per element)
            let slot = calc_element_slot(idx, 1);
            let offset = calc_element_offset(idx, 1);

            // Verify consistency: slot * 32 + offset should equal total bytes
            prop_assert_eq!(slot * 32 + offset, idx);

            // Verify offset is in valid range
            prop_assert!(offset < 32);
        }

        #[test]
        fn proptest_element_slot_offset_consistency_u16(
            idx in 0usize..1000,
        ) {
            // For u16 arrays (2 bytes per element)
            let slot = calc_element_slot(idx, 2);
            let offset = calc_element_offset(idx, 2);

            prop_assert_eq!(slot * 32 + offset, idx * 2);
            prop_assert!(offset < 32);
        }

        #[test]
        fn proptest_element_slot_offset_consistency_address(
            idx in 0usize..100,
        ) {
            // For address arrays (20 bytes per element)
            let slot = calc_element_slot(idx, 20);
            let offset = calc_element_offset(idx, 20);

            prop_assert_eq!(slot * 32 + offset, idx * 20);
            prop_assert!(offset < 32);
        }

        #[test]
        fn proptest_packed_slot_count_sufficient(
            n in 1usize..100,
            elem_bytes in 1usize..=32,
        ) {
            let slot_count = calc_packed_slot_count(n, elem_bytes);
            let total_bytes = n * elem_bytes;
            let min_slots = total_bytes.div_ceil(32);

            // Verify the calculated slot count is correct
            prop_assert_eq!(slot_count, min_slots);

            // Verify it's sufficient to hold all bytes
            prop_assert!(slot_count * 32 >= total_bytes);

            // Verify it's not over-allocated (no more than 31 wasted bytes)
            if slot_count > 0 {
                prop_assert!(slot_count * 32 - total_bytes < 32);
            }
        }
    }
}
