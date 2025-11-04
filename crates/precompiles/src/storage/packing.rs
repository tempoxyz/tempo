//! Shared utilities for packing and unpacking values in EVM storage slots.
//!
//! This module provides helper functions for bit-level manipulation of storage slots,
//! enabling efficient packing of multiple small values into single 32-byte slots.
//!
//! Packing only applies to primitive types where `BYTE_COUNT < 32`. Non-primitives
//! (structs, fixed-size arrays, dynamic types) have `BYTE_COUNT = SLOT_COUNT * 32`.
//!
//! These utilities are used by both:
//! - The `#[derive(Storable)]` macro for struct field packing
//! - Array implementations for packing array elements

use alloy::primitives::U256;

use crate::{error::Result, storage::Storable};

/// Extract a packed value from a storage slot at a given byte offset.
#[inline]
pub fn extract_packed_value<T: Storable<1>>(
    slot_value: U256,
    offset: usize,
    bytes: usize,
) -> Result<T> {
    // Calculate how many bits to shift right to align the value
    let shift_bits = (32 - offset - bytes) * 8;

    // Create mask for the value's bit width
    let mask = if bytes == 32 {
        U256::MAX
    } else {
        (U256::from(1) << (bytes * 8)) - U256::from(1)
    };

    // Extract and right-align the value
    let extracted = (slot_value >> shift_bits) & mask;

    // Use the type's existing decoding logic
    T::from_evm_words([extracted])
}

/// Insert a packed value into a storage slot at a given byte offset.
#[inline]
pub fn insert_packed_value<T: Storable<1>>(
    current: U256,
    value: &T,
    offset: usize,
    bytes: usize,
) -> Result<U256> {
    // Encode field to its canonical right-aligned U256 representation
    let field_value = value.to_evm_words()?[0];

    // Calculate shift and mask
    let shift_bits = (32 - offset - bytes) * 8;
    let mask = if bytes == 32 {
        U256::MAX
    } else {
        (U256::from(1) << (bytes * 8)) - U256::from(1)
    };

    // Clear the bits for this field in the current slot value
    let clear_mask = !(mask << shift_bits);
    let cleared = current & clear_mask;

    // Position the new value and combine with cleared slot
    let positioned = (field_value & mask) << shift_bits;
    let new_value = cleared | positioned;

    Ok(new_value)
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

/// Calculate the total number of slots needed for an array.
#[inline]
pub const fn calc_packed_slot_count(n: usize, elem_bytes: usize) -> usize {
    (n * elem_bytes + 31) / 32
}

/// Verify that a packed field in a storage slot matches an expected value.
///
/// This is a testing utility that extracts a value from a slot at the given offset
/// and compares it with the expected value, providing a clear error message on mismatch.
pub fn verify_packed_field<T: Storable<1> + PartialEq + std::fmt::Debug>(
    slot_value: U256,
    expected: &T,
    offset: usize,
    bytes: usize,
    field_name: &str,
) -> Result<()> {
    let actual: T = extract_packed_value(slot_value, offset, bytes)?;
    if actual != *expected {
        return Err(crate::error::TempoPrecompileError::Fatal(format!(
            "Field '{}' at offset {} ({}bytes) mismatch:\n  Expected: {:?}\n  Actual: {:?}\n  Slot: {}",
            field_name, offset, bytes, expected, actual, slot_value
        )));
    }
    Ok(())
}

/// Extract a field value from a storage slot for testing purposes.
///
/// This is a convenience wrapper around `extract_packed_value` that's more
/// ergonomic for use in test assertions.
pub fn extract_field<T: Storable<1>>(slot_value: U256, offset: usize, bytes: usize) -> Result<T> {
    extract_packed_value(slot_value, offset, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::Address;

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
    fn test_extract_insert_roundtrip_u8() {
        let original: u8 = 42;
        let empty_slot = U256::ZERO;

        // Insert at offset 0
        let slot = insert_packed_value(empty_slot, &original, 0, 1).unwrap();
        let extracted: u8 = extract_packed_value(slot, 0, 1).unwrap();
        assert_eq!(extracted, original);

        // Insert at offset 10
        let slot = insert_packed_value(empty_slot, &original, 10, 1).unwrap();
        let extracted: u8 = extract_packed_value(slot, 10, 1).unwrap();
        assert_eq!(extracted, original);

        // Insert at offset 31 (last byte)
        let slot = insert_packed_value(empty_slot, &original, 31, 1).unwrap();
        let extracted: u8 = extract_packed_value(slot, 31, 1).unwrap();
        assert_eq!(extracted, original);
    }

    #[test]
    fn test_extract_insert_roundtrip_u16() {
        let original: u16 = 1234;
        let empty_slot = U256::ZERO;

        // Insert at offset 0
        let slot = insert_packed_value(empty_slot, &original, 0, 2).unwrap();
        let extracted: u16 = extract_packed_value(slot, 0, 2).unwrap();
        assert_eq!(extracted, original);

        // Insert at offset 15
        let slot = insert_packed_value(empty_slot, &original, 15, 2).unwrap();
        let extracted: u16 = extract_packed_value(slot, 15, 2).unwrap();
        assert_eq!(extracted, original);

        // Insert at offset 30 (last 2 bytes)
        let slot = insert_packed_value(empty_slot, &original, 30, 2).unwrap();
        let extracted: u16 = extract_packed_value(slot, 30, 2).unwrap();
        assert_eq!(extracted, original);
    }

    #[test]
    fn test_extract_insert_roundtrip_address() {
        let original = Address::random();
        let empty_slot = U256::ZERO;

        // Insert at offset 0
        let slot = insert_packed_value(empty_slot, &original, 0, 20).unwrap();
        let extracted: Address = extract_packed_value(slot, 0, 20).unwrap();
        assert_eq!(extracted, original);

        // Insert at offset 12 (fits in one slot)
        let slot = insert_packed_value(empty_slot, &original, 12, 20).unwrap();
        let extracted: Address = extract_packed_value(slot, 12, 20).unwrap();
        assert_eq!(extracted, original);
    }

    #[test]
    fn test_multiple_packed_values() {
        // Pack multiple values into one slot
        let u8_val: u8 = 42;
        let u16_val: u16 = 1000;
        let u32_val: u32 = 100000;

        let mut slot = U256::ZERO;

        // Insert u8 at offset 0 (1 byte)
        slot = insert_packed_value(slot, &u8_val, 0, 1).unwrap();

        // Insert u16 at offset 1 (2 bytes)
        slot = insert_packed_value(slot, &u16_val, 1, 2).unwrap();

        // Insert u32 at offset 3 (4 bytes)
        slot = insert_packed_value(slot, &u32_val, 3, 4).unwrap();

        // Extract and verify
        let extracted_u8: u8 = extract_packed_value(slot, 0, 1).unwrap();
        let extracted_u16: u16 = extract_packed_value(slot, 1, 2).unwrap();
        let extracted_u32: u32 = extract_packed_value(slot, 3, 4).unwrap();

        assert_eq!(extracted_u8, u8_val);
        assert_eq!(extracted_u16, u16_val);
        assert_eq!(extracted_u32, u32_val);
    }

    #[test]
    fn test_insert_overwrites_correctly() {
        let first: u8 = 255;
        let second: u8 = 128;

        let mut slot = U256::ZERO;

        // Insert first value
        slot = insert_packed_value(slot, &first, 5, 1).unwrap();
        assert_eq!(extract_packed_value::<u8>(slot, 5, 1).unwrap(), first);

        // Overwrite with second value
        slot = insert_packed_value(slot, &second, 5, 1).unwrap();
        assert_eq!(extract_packed_value::<u8>(slot, 5, 1).unwrap(), second);
    }

    #[test]
    fn test_verify_packed_field_success() {
        // Pack multiple values
        let u8_val: u8 = 42;
        let u16_val: u16 = 1000;
        let u32_val: u32 = 100000;

        let mut slot = U256::ZERO;
        slot = insert_packed_value(slot, &u8_val, 0, 1).unwrap();
        slot = insert_packed_value(slot, &u16_val, 1, 2).unwrap();
        slot = insert_packed_value(slot, &u32_val, 3, 4).unwrap();

        // Verify each field
        verify_packed_field(slot, &u8_val, 0, 1, "u8_field").unwrap();
        verify_packed_field(slot, &u16_val, 1, 2, "u16_field").unwrap();
        verify_packed_field(slot, &u32_val, 3, 4, "u32_field").unwrap();
    }

    #[test]
    fn test_verify_packed_field_failure() {
        let u8_val: u8 = 42;
        let mut slot = U256::ZERO;
        slot = insert_packed_value(slot, &u8_val, 0, 1).unwrap();

        // Verify with wrong expected value should fail
        let wrong_val: u8 = 99;
        let result = verify_packed_field(slot, &wrong_val, 0, 1, "u8_field");
        assert!(
            result.is_err(),
            "Expected verification to fail for mismatched value"
        );
    }

    #[test]
    fn test_extract_field_wrapper() {
        let address = Address::random();
        let mut slot = U256::ZERO;
        slot = insert_packed_value(slot, &address, 0, 20).unwrap();

        // Use extract_field wrapper
        let extracted: Address = extract_field(slot, 0, 20).unwrap();
        assert_eq!(extracted, address);
    }
}
