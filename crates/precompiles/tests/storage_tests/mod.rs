//! Shared test utilities for storage testing.

use crate::storage::{
    Handler, LayoutCtx, Slot, Storable, hashmap::HashMapStorageProvider,
    packing::extract_packed_value,
};
use alloy::primitives::{Address, U256, keccak256};
use proptest::prelude::*;
use tempo_precompiles::error;
use tempo_precompiles_macros::{Storable, contract};

mod arrays;
mod layouts;
mod mappings;
mod packing;
mod roundtrip;
mod solidity;
mod strings;
mod structs;

// -- TEST HELPERS ---------------------------------------------------------------------------------

fn setup_storage() -> (HashMapStorageProvider, Address) {
    (HashMapStorageProvider::new(1), Address::random())
}

/// Test struct with 3 slots: U256, U256, u64
#[derive(Default, Debug, Clone, PartialEq, Eq, Storable)]
pub(crate) struct TestBlock {
    pub(crate) field1: U256,
    pub(crate) field2: U256,
    pub(crate) field3: u64,
}

/// Test struct with 2 slots: Address + bool (packed), U256
#[derive(Default, Debug, Clone, PartialEq, Eq, Storable)]
pub(crate) struct UserProfile {
    pub(crate) owner: Address,
    pub(crate) active: bool,
    pub(crate) balance: U256,
}

/// Test struct for multi-slot array tests (2 slots with inner packing)
/// Layout: slot 0 = [U256], slot 1 = [u64, u32, address]
#[derive(Debug, Clone, Default, PartialEq, Eq, Storable)]
pub(crate) struct PackedTwoSlot {
    pub(crate) value: U256,
    pub(crate) timestamp: u64,
    pub(crate) nonce: u32,
    pub(crate) owner: Address,
}

/// Test struct for multi-slot array tests (3 slots with inner packing)
/// Layout: slot 0 = [U256], slot 1 = [u64, u64, u64, u64], slot 2 = [address, bool]
#[derive(Debug, Clone, Default, PartialEq, Eq, Storable)]
pub(crate) struct PackedThreeSlot {
    pub(crate) value: U256,
    pub(crate) timestamp: u64,
    pub(crate) start_time: u64,
    pub(crate) end_time: u64,
    pub(crate) nonce: u64,
    pub(crate) owner: Address,
    pub(crate) active: bool,
}

/// Helper to generate test addresses
pub(crate) fn test_address(byte: u8) -> Address {
    let mut bytes = [0u8; 20];
    bytes[19] = byte;
    Address::from(bytes)
}

/// Helper to test store + load roundtrip
pub(crate) fn test_store_load<T>(
    address: &Address,
    base_slot: U256,
    original: &T,
) -> error::Result<()>
where
    T: Storable + Clone + PartialEq + std::fmt::Debug,
{
    // Create a slot and use it for storage operations
    let mut slot = Slot::<T>::new(base_slot, address.clone());

    // Write and read using the new API
    slot.write(original.clone())?;
    let loaded = slot.read()?;
    assert_eq!(&loaded, original, "Store/load roundtrip failed");
    Ok(())
}

/// Helper to test update operation
pub(crate) fn test_update<T>(
    address: &Address,
    base_slot: U256,
    initial: &T,
    updated: &T,
) -> error::Result<()>
where
    T: Storable + Clone + PartialEq + std::fmt::Debug,
{
    // Create a slot and use it for storage operations
    let mut slot = Slot::<T>::new(base_slot, address.clone());

    // Test initial write and read
    slot.write(initial.clone())?;
    let loaded1 = slot.read()?;
    assert_eq!(&loaded1, initial, "Initial store/load failed");

    // Test update
    slot.write(updated.clone())?;
    let loaded2 = slot.read()?;
    assert_eq!(&loaded2, updated, "Update failed");
    Ok(())
}

/// Helper to test delete operation
pub(crate) fn test_delete<T>(address: &Address, base_slot: U256, data: &T) -> error::Result<()>
where
    T: Storable + Clone + PartialEq + Default + std::fmt::Debug,
{
    // Create a slot and use it for storage operations
    let mut slot = Slot::<T>::new(base_slot, address.clone());

    // Write and verify
    slot.write(data.clone())?;
    let loaded = slot.read()?;
    assert_eq!(&loaded, data, "Initial store/load failed");

    // Delete and verify it's zeroed
    slot.delete()?;
    let after_delete = slot.read()?;
    let expected_zero = T::default();
    assert_eq!(&after_delete, &expected_zero, "Delete did not zero values");
    Ok(())
}

// -- PROPTEST STRATEGIES --------------------------------------------------------------------------

/// Strategy for generating random Address values
pub(crate) fn arb_address() -> impl Strategy<Value = Address> {
    any::<[u8; 20]>().prop_map(Address::from)
}

/// Strategy for generating random U256 values
pub(crate) fn arb_u256() -> impl Strategy<Value = U256> {
    any::<[u64; 4]>().prop_map(U256::from_limbs)
}

/// Strategy for generating random strings of various sizes
pub(crate) fn arb_string() -> impl Strategy<Value = String> {
    prop_oneof![
        // Empty string
        Just(String::new()),
        // Short strings (1-31 bytes) - inline storage
        "[a-zA-Z0-9]{1,31}",
        // Boundary: exactly 31 bytes (last short string)
        "[a-zA-Z0-9]{31}",
        // Boundary: exactly 32 bytes (first long string)
        "[a-zA-Z0-9]{32}",
        // Long strings (33-100 bytes)
        "[a-zA-Z0-9]{33,100}",
        // Unicode strings
        "[\u{0041}-\u{005A}\u{4E00}-\u{9FFF}]{1,20}",
    ]
}

/// Strategy for generating arbitrary [u8; 32] arrays
pub(crate) fn arb_small_array() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
}

/// Strategy for generating arbitrary [U256; 5] arrays
pub(crate) fn arb_large_u256_array() -> impl Strategy<Value = [U256; 5]> {
    prop::array::uniform5(arb_u256())
}

/// Generate arbitrary UserProfile structs
pub(crate) fn arb_user_profile() -> impl Strategy<Value = UserProfile> {
    (arb_address(), any::<bool>(), arb_u256()).prop_map(|(owner, active, balance)| UserProfile {
        owner,
        active,
        balance,
    })
}

/// Generate arbitrary TestBlock structs
pub(crate) fn arb_test_block() -> impl Strategy<Value = TestBlock> {
    (arb_u256(), arb_u256(), any::<u64>()).prop_map(|(field1, field2, field3)| TestBlock {
        field1,
        field2,
        field3,
    })
}

/// Generate arbitrary PackedTwoSlot structs
pub(crate) fn arb_packed_two_slot() -> impl Strategy<Value = PackedTwoSlot> {
    (arb_u256(), any::<u64>(), any::<u32>(), arb_address()).prop_map(
        |(value, timestamp, nonce, owner)| PackedTwoSlot {
            value,
            timestamp,
            nonce,
            owner,
        },
    )
}

/// Generate arbitrary PackedThreeSlot structs
pub(crate) fn arb_packed_three_slot() -> impl Strategy<Value = PackedThreeSlot> {
    (
        arb_u256(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        arb_address(),
        any::<bool>(),
    )
        .prop_map(
            |(value, timestamp, start_time, end_time, nonce, owner, active)| PackedThreeSlot {
                value,
                timestamp,
                start_time,
                end_time,
                nonce,
                owner,
                active,
            },
        )
}
