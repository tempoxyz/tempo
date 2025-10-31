//! Storage-related test for the #[contract] macro. Also validates getters and setters.

// Re-export `tempo_precompiles::storage` as a local module so `crate::storage` works
mod storage {
    pub(super) use tempo_precompiles::storage::*;
}

use alloy::primitives::{Address, U256, keccak256};
use storage::{PrecompileStorageProvider, hashmap::HashMapStorageProvider};
use tempo_precompiles::error;
use tempo_precompiles_macros::contract;

// Helper to generate addresses
fn test_address(byte: u8) -> Address {
    let mut bytes = [0u8; 20];
    bytes[19] = byte;
    Address::from(bytes)
}

#[test]
fn test_mixed_slot_allocation() {
    #[contract]
    pub struct Layout {
        pub field_a: U256, // Auto: slot 0
        #[slot(5)]
        pub field_b: U256, // Explicit: slot 5 (decimal)
        pub field_c: U256, // Auto: slot 1
        #[slot(0x10)]
        pub field_d: U256, // Explicit: slot 16 (hex)
    }

    let mut storage = HashMapStorageProvider::new(1);
    let addr = test_address(1);

    let mut mixed = Layout::_new(addr, &mut storage);

    // Set all fields
    mixed._set_field_a(U256::from(100)).unwrap();
    mixed._set_field_b(U256::from(200)).unwrap();
    mixed._set_field_c(U256::from(300)).unwrap();
    mixed._set_field_d(U256::from(400)).unwrap();

    // Verify values
    assert_eq!(mixed._get_field_a().unwrap(), U256::from(100));
    assert_eq!(mixed._get_field_b().unwrap(), U256::from(200));
    assert_eq!(mixed._get_field_c().unwrap(), U256::from(300));
    assert_eq!(mixed._get_field_d().unwrap(), U256::from(400));

    // Verify actual slot assignments
    assert_eq!(storage.sload(addr, U256::from(0)), Ok(U256::from(100))); // field_a
    assert_eq!(storage.sload(addr, U256::from(5)), Ok(U256::from(200))); // field_b
    assert_eq!(storage.sload(addr, U256::from(1)), Ok(U256::from(300))); // field_c
    assert_eq!(storage.sload(addr, U256::from(0x10)), Ok(U256::from(400))); // field_d (hex slot)
}

#[test]
fn test_string_storage() {
    #[contract]
    pub struct Layout {
        pub short_string: String,
        pub another_string: String,
    }

    let mut storage = HashMapStorageProvider::new(1);
    let addr = test_address(1);

    let mut str_storage = Layout::_new(addr, &mut storage);

    // Test short string
    let test_str = "Hello, Tempo!".to_string();
    str_storage._set_short_string(test_str.clone()).unwrap();
    assert_eq!(str_storage._get_short_string().unwrap(), test_str);

    // Test empty string
    str_storage._set_another_string(String::new()).unwrap();
    assert_eq!(str_storage._get_another_string().unwrap(), "");

    // Test max length (31 bytes)
    let max_str = "a".repeat(31);
    str_storage._set_short_string(max_str.clone()).unwrap();
    assert_eq!(str_storage._get_short_string().unwrap(), max_str);
}

#[test]
fn test_default_values() {
    #[contract]
    pub struct Layout {
        pub counter: u64,
        pub flag: bool,
        pub amount: U256,
    }

    let mut storage = HashMapStorageProvider::new(1);
    let addr = test_address(1);

    let mut defaults = Layout::_new(addr, &mut storage);

    // Reading uninitialized storage returns zero/default
    assert_eq!(defaults._get_counter().unwrap(), 0);
    assert!(!defaults._get_flag().unwrap());
    assert_eq!(defaults._get_amount().unwrap(), U256::ZERO);
}

#[test]
fn test_slots_module_generation() {
    #[contract]
    pub struct Layout {
        pub field_a: U256, // Auto: slot 0
        #[slot(5)]
        pub field_b: U256, // Explicit: slot 5
        pub field_c: U256, // Auto: slot 1
        #[slot(10)]
        pub mapping_field: storage::Mapping<Address, U256>, // Explicit: slot 10
    }

    // Verify the slots module was generated with correct values
    assert_eq!(slots::FIELD_A, U256::from(0));
    assert_eq!(slots::FIELD_B, U256::from(5));
    assert_eq!(slots::FIELD_C, U256::from(1));
    assert_eq!(slots::MAPPING_FIELD, U256::from(10));
}

#[test]
fn test_base_slots() {
    #[contract]
    pub struct Layout {
        pub field_a: U256, // Auto: slot 0
        #[base_slot(100)]
        pub field_b: U256, // base_slot: slot 100, counter -> 101
        pub field_c: U256, // Auto: slot 101
        #[base_slot(200)]
        pub field_d: U256, // base_slot: slot 200, counter -> 201
        pub field_e: U256, // Auto: slot 201
        #[base_slot(50)]
        pub field_f: U256, // base_slot: slot 50, counter -> 51 (goes backwards)
        pub field_g: U256, // Auto: slot 51
    }

    let mut storage = HashMapStorageProvider::new(1);
    let addr = test_address(1);

    let mut layout = Layout::_new(addr, &mut storage);

    // Set values to verify slot assignments
    layout._set_field_a(U256::from(1)).unwrap();
    layout._set_field_b(U256::from(2)).unwrap();
    layout._set_field_c(U256::from(3)).unwrap();
    layout._set_field_d(U256::from(4)).unwrap();
    layout._set_field_e(U256::from(5)).unwrap();
    layout._set_field_f(U256::from(6)).unwrap();
    layout._set_field_g(U256::from(7)).unwrap();

    // Verify actual slot assignments
    assert_eq!(storage.sload(addr, U256::from(0)), Ok(U256::from(1))); // field_a
    assert_eq!(storage.sload(addr, U256::from(100)), Ok(U256::from(2))); // field_b
    assert_eq!(storage.sload(addr, U256::from(101)), Ok(U256::from(3))); // field_c
    assert_eq!(storage.sload(addr, U256::from(200)), Ok(U256::from(4))); // field_d
    assert_eq!(storage.sload(addr, U256::from(201)), Ok(U256::from(5))); // field_e
    assert_eq!(storage.sload(addr, U256::from(50)), Ok(U256::from(6))); // field_f
    assert_eq!(storage.sload(addr, U256::from(51)), Ok(U256::from(7))); // field_g

    // Verify slots module
    assert_eq!(slots::FIELD_A, U256::from(0));
    assert_eq!(slots::FIELD_B, U256::from(100));
    assert_eq!(slots::FIELD_C, U256::from(101));
    assert_eq!(slots::FIELD_D, U256::from(200));
    assert_eq!(slots::FIELD_E, U256::from(201));
    assert_eq!(slots::FIELD_F, U256::from(50));
    assert_eq!(slots::FIELD_G, U256::from(51));
}

#[test]
fn test_base_slot_with_regular_slot() {
    #[contract]
    pub struct Layout {
        pub field_a: U256, // Auto: slot 0
        #[base_slot(100)]
        pub field_b: U256, // base_slot: slot 100, counter -> 101
        pub field_c: U256, // Auto: slot 101
        #[slot(50)]
        pub field_d: U256, // Explicit: slot 50, counter stays at 102
        pub field_e: U256, // Auto: slot 102
    }

    let mut storage = HashMapStorageProvider::new(1);
    let addr = test_address(1);

    let mut layout = Layout::_new(addr, &mut storage);

    layout._set_field_a(U256::from(1)).unwrap();
    layout._set_field_b(U256::from(2)).unwrap();
    layout._set_field_c(U256::from(3)).unwrap();
    layout._set_field_d(U256::from(4)).unwrap();
    layout._set_field_e(U256::from(5)).unwrap();

    // Verify slot assignments
    assert_eq!(storage.sload(addr, U256::from(0)), Ok(U256::from(1))); // field_a
    assert_eq!(storage.sload(addr, U256::from(100)), Ok(U256::from(2))); // field_b
    assert_eq!(storage.sload(addr, U256::from(101)), Ok(U256::from(3))); // field_c
    assert_eq!(storage.sload(addr, U256::from(50)), Ok(U256::from(4))); // field_d
    assert_eq!(storage.sload(addr, U256::from(102)), Ok(U256::from(5))); // field_e

    // Verify slots module
    assert_eq!(slots::FIELD_A, U256::from(0));
    assert_eq!(slots::FIELD_B, U256::from(100));
    assert_eq!(slots::FIELD_C, U256::from(101));
    assert_eq!(slots::FIELD_D, U256::from(50));
    assert_eq!(slots::FIELD_E, U256::from(102));
}

#[test]
fn test_string_literal_slots() {
    #[contract]
    pub struct Layout {
        #[slot("id")]
        pub field: U256, // slot: keccak256("id")
    }

    let mut storage = HashMapStorageProvider::new(1);
    let addr = test_address(1);

    let mut layout = Layout::_new(addr, &mut storage);

    // Set value
    layout._set_field(U256::from(1)).unwrap();

    // Verify
    let slot: U256 = keccak256("id").into();
    assert_eq!(storage.sload(addr, slot), Ok(U256::from(1))); // field
    assert_eq!(slots::FIELD, slot);
}
