//! Storage Layout-related test for the #[contract] macro. Also validates getters and setters.

// Re-export `tempo_precompiles::storage` as a local module so `crate::storage` works
mod storage {
    pub(super) use tempo_precompiles::storage::*;
}

use storage::Storable;

use alloy::primitives::{Address, U256, keccak256};
use storage::{PrecompileStorageProvider, hashmap::HashMapStorageProvider};
use tempo_precompiles::error;
use tempo_precompiles_macros::{Storable, contract};

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
    mixed.sstore_field_a(U256::from(100)).unwrap();
    mixed.sstore_field_b(U256::from(200)).unwrap();
    mixed.sstore_field_c(U256::from(300)).unwrap();
    mixed.sstore_field_d(U256::from(400)).unwrap();

    // Verify values
    assert_eq!(mixed.sload_field_a().unwrap(), U256::from(100));
    assert_eq!(mixed.sload_field_b().unwrap(), U256::from(200));
    assert_eq!(mixed.sload_field_c().unwrap(), U256::from(300));
    assert_eq!(mixed.sload_field_d().unwrap(), U256::from(400));

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
    str_storage.sstore_short_string(test_str.clone()).unwrap();
    assert_eq!(str_storage.sload_short_string().unwrap(), test_str);

    // Test empty string
    str_storage.sstore_another_string(String::new()).unwrap();
    assert_eq!(str_storage.sload_another_string().unwrap(), "");

    // Test max length (31 bytes)
    let max_str = "a".repeat(31);
    str_storage.sstore_short_string(max_str.clone()).unwrap();
    assert_eq!(str_storage.sload_short_string().unwrap(), max_str);
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
    assert_eq!(defaults.sload_counter().unwrap(), 0);
    assert!(!defaults.sload_flag().unwrap());
    assert_eq!(defaults.sload_amount().unwrap(), U256::ZERO);
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
    layout.sstore_field_a(U256::from(1)).unwrap();
    layout.sstore_field_b(U256::from(2)).unwrap();
    layout.sstore_field_c(U256::from(3)).unwrap();
    layout.sstore_field_d(U256::from(4)).unwrap();
    layout.sstore_field_e(U256::from(5)).unwrap();
    layout.sstore_field_f(U256::from(6)).unwrap();
    layout.sstore_field_g(U256::from(7)).unwrap();

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

    layout.sstore_field_a(U256::from(1)).unwrap();
    layout.sstore_field_b(U256::from(2)).unwrap();
    layout.sstore_field_c(U256::from(3)).unwrap();
    layout.sstore_field_d(U256::from(4)).unwrap();
    layout.sstore_field_e(U256::from(5)).unwrap();

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
    layout.sstore_field(U256::from(1)).unwrap();

    // Verify
    let slot: U256 = keccak256("id").into();
    assert_eq!(storage.sload(addr, slot), Ok(U256::from(1))); // field
    assert_eq!(slots::FIELD, slot);
}

// SLOT_COUNT = 3
#[derive(Debug, Clone, PartialEq, Eq, Storable)]
pub(crate) struct TestBlock {
    pub field1: U256,
    pub field2: U256,
    pub field3: u64,
}

#[test]
fn test_struct_storage() {
    #[contract]
    pub struct Layout {
        pub field_a: U256, // Auto: slot 0
        #[slot(10)]
        pub block: TestBlock, // Explicit: slots 10-12
        pub field_b: U256, // Auto: slot 1 (skips 10-12)
        pub address_mapping: storage::Mapping<Address, U256>, // Auto: slot 2
        pub block_mapping: storage::Mapping<u64, TestBlock>, // Auto: slot 3
    }

    let mut storage = HashMapStorageProvider::new(1);
    let addr = test_address(1);

    let block = TestBlock {
        field1: U256::from(1000),
        field2: U256::from(2000),
        field3: 3000,
    };

    // Scope the layout to ensure it's dropped before we access storage directly
    {
        let mut layout = Layout::_new(addr, &mut storage);
        layout.sstore_field_a(U256::from(100)).unwrap();
        layout.sstore_field_b(U256::from(200)).unwrap();
        layout.sstore_block(block.clone()).unwrap();

        // Verify fields
        assert_eq!(layout.sload_field_a().unwrap(), U256::from(100));
        assert_eq!(layout.sload_field_b().unwrap(), U256::from(200));
        assert_eq!(layout.sload_block().unwrap(), block);
    }

    // Verify actual slot assignments
    assert_eq!(storage.sload(addr, U256::from(0)), Ok(U256::from(100))); // field_a
    assert_eq!(storage.sload(addr, U256::from(10)), Ok(U256::from(1000))); // block.field1
    assert_eq!(storage.sload(addr, U256::from(11)), Ok(U256::from(2000))); // block.field2
    assert_eq!(storage.sload(addr, U256::from(12)), Ok(U256::from(3000))); // block.field3
    assert_eq!(storage.sload(addr, U256::from(1)), Ok(U256::from(200))); // field_b

    // Verify slots module
    assert_eq!(slots::FIELD_A, U256::from(0));
    assert_eq!(slots::BLOCK, U256::from(10));
    assert_eq!(slots::FIELD_B, U256::from(1));
    assert_eq!(slots::ADDRESS_MAPPING, U256::from(2));
    assert_eq!(slots::BLOCK_MAPPING, U256::from(3));

    // Test address_mapping and block_mapping
    {
        let mut layout = Layout::_new(addr, &mut storage);

        // Test address_mapping with multiple addresses
        let addr1 = test_address(10);
        let addr2 = test_address(20);
        let addr3 = test_address(30);

        layout
            .sstore_address_mapping(addr1, U256::from(1000))
            .unwrap();
        layout
            .sstore_address_mapping(addr2, U256::from(2000))
            .unwrap();
        layout
            .sstore_address_mapping(addr3, U256::from(3000))
            .unwrap();

        assert_eq!(
            layout.sload_address_mapping(addr1).unwrap(),
            U256::from(1000)
        );
        assert_eq!(
            layout.sload_address_mapping(addr2).unwrap(),
            U256::from(2000)
        );
        assert_eq!(
            layout.sload_address_mapping(addr3).unwrap(),
            U256::from(3000)
        );

        // Test block_mapping with TestBlock values
        let block1 = TestBlock {
            field1: U256::from(111),
            field2: U256::from(222),
            field3: 333,
        };
        let block2 = TestBlock {
            field1: U256::from(444),
            field2: U256::from(555),
            field3: 666,
        };

        layout.sstore_block_mapping(1u64, block1.clone()).unwrap();
        layout.sstore_block_mapping(2u64, block2.clone()).unwrap();

        assert_eq!(layout.sload_block_mapping(1u64).unwrap(), block1);
        assert_eq!(layout.sload_block_mapping(2u64).unwrap(), block2);

        // Verify non-existent keys return default values
        assert_eq!(
            layout.sload_address_mapping(test_address(99)).unwrap(),
            U256::ZERO
        );
        assert_eq!(
            layout.sload_block_mapping(999u64).unwrap(),
            TestBlock {
                field1: U256::ZERO,
                field2: U256::ZERO,
                field3: 0,
            }
        );
    }
}

// NOTE: Collision detection tests
//
// The overlapping layouts are prevented at compile/debug-time by the macro:
//    ```rust
//    #[contract]
//    pub struct Layout {
//        #[slot(10)]
//        pub block: TestBlock,  // Occupies slots 10-12 (SLOT_COUNT = 3)
//        #[slot(11)]
//        pub field: U256,       // DEBUG ASSERTION: slot 11 overlaps with block!
//    }
//    ```

// SLOT_COUNT = 3
#[derive(Debug, Clone, PartialEq, Eq, Storable)]
pub(crate) struct UserProfile {
    pub owner: Address,
    pub active: bool,
    pub balance: U256,
}

#[test]
fn test_delete_struct_field_in_contract() {
    #[contract]
    pub struct Layout {
        pub field_a: U256, // Auto: slot 0
        #[slot(10)]
        pub block: TestBlock, // Explicit: slots 10-12
        pub field_b: U256, // Auto: slot 1
    }

    let mut storage = HashMapStorageProvider::new(1);
    let addr = test_address(1);

    let block = TestBlock {
        field1: U256::from(1000),
        field2: U256::from(2000),
        field3: 3000,
    };

    // Scope the layout to store data
    {
        let mut layout = Layout::_new(addr, &mut storage);
        layout.sstore_field_a(U256::from(100)).unwrap();
        layout.sstore_field_b(U256::from(200)).unwrap();
        layout.sstore_block(block.clone()).unwrap();

        // Verify data is stored
        assert_eq!(layout.sload_field_a().unwrap(), U256::from(100));
        assert_eq!(layout.sload_field_b().unwrap(), U256::from(200));
        assert_eq!(layout.sload_block().unwrap(), block);
    }

    // Verify storage slots before delete
    assert_eq!(storage.sload(addr, U256::from(0)), Ok(U256::from(100))); // field_a
    assert_eq!(storage.sload(addr, U256::from(10)), Ok(U256::from(1000))); // block.field1
    assert_eq!(storage.sload(addr, U256::from(11)), Ok(U256::from(2000))); // block.field2
    assert_eq!(storage.sload(addr, U256::from(12)), Ok(U256::from(3000))); // block.field3
    assert_eq!(storage.sload(addr, U256::from(1)), Ok(U256::from(200))); // field_b

    // Delete the block field using the generated delete method
    {
        let mut layout = Layout::_new(addr, &mut storage);
        layout.clear_block().unwrap();
    }

    // Verify block slots are zeroed (10, 11, 12)
    assert_eq!(storage.sload(addr, U256::from(10)), Ok(U256::ZERO));
    assert_eq!(storage.sload(addr, U256::from(11)), Ok(U256::ZERO));
    assert_eq!(storage.sload(addr, U256::from(12)), Ok(U256::ZERO));

    // Verify other fields are untouched
    assert_eq!(storage.sload(addr, U256::from(0)), Ok(U256::from(100))); // field_a
    assert_eq!(storage.sload(addr, U256::from(1)), Ok(U256::from(200))); // field_b

    // Verify loading the block returns default values
    {
        let mut layout = Layout::_new(addr, &mut storage);
        assert_eq!(
            layout.sload_block().unwrap(),
            TestBlock {
                field1: U256::ZERO,
                field2: U256::ZERO,
                field3: 0,
            }
        );
    }
}

#[test]
fn test_user_profile_struct_in_contract() {
    #[contract]
    pub struct Layout {
        pub counter: U256, // Auto: slot 0
        #[slot(20)]
        pub profile: UserProfile, // Explicit: slots 20-21
        pub flag: bool,    // Auto: slot 1
    }

    let mut storage = HashMapStorageProvider::new(1);
    let addr = test_address(1);

    let profile = UserProfile {
        owner: test_address(42),
        active: true,
        balance: U256::from(999_999),
    };

    // Store data
    {
        let mut layout = Layout::_new(addr, &mut storage);
        layout.sstore_counter(U256::from(5)).unwrap();
        layout.sstore_profile(profile.clone()).unwrap();
        layout.sstore_flag(true).unwrap();

        // Verify getters
        assert_eq!(layout.sload_counter().unwrap(), U256::from(5));
        assert_eq!(layout.sload_profile().unwrap(), profile);
        assert!(layout.sload_flag().unwrap());
    }

    // Verify actual slot assignments
    assert_eq!(storage.sload(addr, U256::from(0)), Ok(U256::from(5))); // counter
    assert_eq!(
        storage.sload(addr, U256::from(20)),
        // 0x                                       (packed: owner + active)
        // 000000000000000000000000000000000000002A (addr(42))
        // 00                                       (true)
        // 0000000000000000000000                   (unused)
        Ok(
            "0x000000000000000000000000000000000000002A010000000000000000000000"
                .parse::<U256>()
                .unwrap()
        )
    );
    assert_eq!(storage.sload(addr, U256::from(21)), Ok(U256::from(999_999))); // profile.balance
    assert_eq!(storage.sload(addr, U256::from(1)), Ok(U256::from(1))); // flag

    // Verify slots module
    assert_eq!(slots::COUNTER, U256::from(0));
    assert_eq!(slots::PROFILE, U256::from(20));
    assert_eq!(slots::FLAG, U256::from(1));

    // Test delete
    {
        let mut layout = Layout::_new(addr, &mut storage);
        layout.clear_profile().unwrap();
    }

    // Verify profile slots are zeroed (only 2 slots: 20 and 21)
    assert_eq!(storage.sload(addr, U256::from(20)), Ok(U256::ZERO)); // owner + active (packed)
    assert_eq!(storage.sload(addr, U256::from(21)), Ok(U256::ZERO)); // balance

    // Verify other fields unchanged
    assert_eq!(storage.sload(addr, U256::from(0)), Ok(U256::from(5)));
    assert_eq!(storage.sload(addr, U256::from(1)), Ok(U256::from(1)));

    // Verify loading returns defaults
    {
        let mut layout = Layout::_new(addr, &mut storage);
        assert_eq!(
            layout.sload_profile().unwrap(),
            UserProfile {
                owner: Address::ZERO,
                active: false,
                balance: U256::ZERO,
            }
        );
    }
}

#[test]
fn test_delete_struct_in_mapping() {
    #[contract]
    pub struct Layout {
        pub block_mapping: storage::Mapping<u64, TestBlock>, // Auto: slot 0
        pub profile_mapping: storage::Mapping<Address, UserProfile>, // Auto: slot 1
    }

    let mut storage = HashMapStorageProvider::new(1);
    let addr = test_address(1);

    let block1 = TestBlock {
        field1: U256::from(111),
        field2: U256::from(222),
        field3: 333,
    };
    let block2 = TestBlock {
        field1: U256::from(444),
        field2: U256::from(555),
        field3: 666,
    };

    let profile1 = UserProfile {
        owner: test_address(10),
        active: true,
        balance: U256::from(1000),
    };
    let profile2 = UserProfile {
        owner: test_address(20),
        active: false,
        balance: U256::from(2000),
    };

    // Store multiple entries
    {
        let mut layout = Layout::_new(addr, &mut storage);
        layout.sstore_block_mapping(1u64, block1.clone()).unwrap();
        layout.sstore_block_mapping(2u64, block2.clone()).unwrap();
        layout
            .sstore_profile_mapping(test_address(10), profile1.clone())
            .unwrap();
        layout
            .sstore_profile_mapping(test_address(20), profile2.clone())
            .unwrap();

        // Verify all entries
        assert_eq!(layout.sload_block_mapping(1u64).unwrap(), block1);
        assert_eq!(layout.sload_block_mapping(2u64).unwrap(), block2);
        assert_eq!(
            layout.sload_profile_mapping(test_address(10)).unwrap(),
            profile1
        );
        assert_eq!(
            layout.sload_profile_mapping(test_address(20)).unwrap(),
            profile2
        );
    }

    // Delete specific entries
    {
        let mut layout = Layout::_new(addr, &mut storage);
        layout.clear_block_mapping(1u64).unwrap();
        layout.clear_profile_mapping(test_address(10)).unwrap();
    }

    // Verify deleted entries return defaults
    {
        let mut layout = Layout::_new(addr, &mut storage);
        assert_eq!(
            layout.sload_block_mapping(1u64).unwrap(),
            TestBlock {
                field1: U256::ZERO,
                field2: U256::ZERO,
                field3: 0,
            }
        );
        assert_eq!(
            layout.sload_profile_mapping(test_address(10)).unwrap(),
            UserProfile {
                owner: Address::ZERO,
                active: false,
                balance: U256::ZERO,
            }
        );

        // Verify non-deleted entries are intact
        assert_eq!(layout.sload_block_mapping(2u64).unwrap(), block2);
        assert_eq!(
            layout.sload_profile_mapping(test_address(20)).unwrap(),
            profile2
        );
    }
}

#[test]
fn test_round_trip_operations_in_contract() {
    #[contract]
    pub struct Layout {
        #[slot(100)]
        pub block: TestBlock,
        #[slot(200)]
        pub profile: UserProfile,
    }

    let mut storage = HashMapStorageProvider::new(1);
    let addr = test_address(1);

    let original_block = TestBlock {
        field1: U256::from(789),
        field2: U256::from(987),
        field3: 555,
    };
    let original_profile = UserProfile {
        owner: test_address(99),
        active: true,
        balance: U256::from(12345),
    };

    // Round 1: Store and load
    {
        let mut layout = Layout::_new(addr, &mut storage);
        layout.sstore_block(original_block.clone()).unwrap();
        layout.sstore_profile(original_profile.clone()).unwrap();
    }

    {
        let mut layout = Layout::_new(addr, &mut storage);
        assert_eq!(layout.sload_block().unwrap(), original_block);
        assert_eq!(layout.sload_profile().unwrap(), original_profile);
    }

    // Round 2: Delete and verify defaults
    {
        let mut layout = Layout::_new(addr, &mut storage);
        layout.clear_block().unwrap();
        layout.clear_profile().unwrap();
    }

    {
        let mut layout = Layout::_new(addr, &mut storage);
        assert_eq!(
            layout.sload_block().unwrap(),
            TestBlock {
                field1: U256::ZERO,
                field2: U256::ZERO,
                field3: 0,
            }
        );
        assert_eq!(
            layout.sload_profile().unwrap(),
            UserProfile {
                owner: Address::ZERO,
                active: false,
                balance: U256::ZERO,
            }
        );
    }

    // Round 3: Store new values
    let new_block = TestBlock {
        field1: U256::from(111),
        field2: U256::from(222),
        field3: 333,
    };
    let new_profile = UserProfile {
        owner: test_address(88),
        active: false,
        balance: U256::from(54321),
    };

    {
        let mut layout = Layout::_new(addr, &mut storage);
        layout.sstore_block(new_block.clone()).unwrap();
        layout.sstore_profile(new_profile.clone()).unwrap();
    }

    {
        let mut layout = Layout::_new(addr, &mut storage);
        assert_eq!(layout.sload_block().unwrap(), new_block);
        assert_eq!(layout.sload_profile().unwrap(), new_profile);
    }
}

#[test]
fn test_slot_id_naming_matches_actual_slots() {
    // Test that SlotId type names reflect actual slot numbers, not field indices
    #[contract]
    pub struct Layout {
        pub field_a: U256, // auto → slot 0
        #[slot(100)]
        pub field_b: U256, // explicit → slot 100
        pub field_c: U256, // auto → slot 1
        #[base_slot(200)]
        pub field_d: U256, // base → slot 200
        pub field_e: U256, // auto → slot 201
        #[slot(0x10)]
        pub field_f: U256, // hex → slot 16
    }

    // Verify slot assignments via the slots module constants
    assert_eq!(slots::FIELD_A, U256::from(0));
    assert_eq!(slots::FIELD_B, U256::from(100));
    assert_eq!(slots::FIELD_C, U256::from(1));
    assert_eq!(slots::FIELD_D, U256::from(200));
    assert_eq!(slots::FIELD_E, U256::from(201));
    assert_eq!(slots::FIELD_F, U256::from(16));

    // Verify the types exist and have correct SLOT values
    use tempo_precompiles::storage::SlotId;
    assert_eq!(<Slot0 as SlotId>::SLOT, U256::from(0));
    assert_eq!(<Slot100 as SlotId>::SLOT, U256::from(100));
    assert_eq!(<Slot1 as SlotId>::SLOT, U256::from(1));
    assert_eq!(<Slot200 as SlotId>::SLOT, U256::from(200));
    assert_eq!(<Slot201 as SlotId>::SLOT, U256::from(201));
    assert_eq!(<Slot16 as SlotId>::SLOT, U256::from(16));
}

#[test]
fn test_array_storage() {
    use alloy::primitives::address;

    #[contract]
    pub struct Layout {
        pub field_a: U256, // Auto: slot 0
        #[slot(10)]
        pub small_array: [u8; 32], // Explicit: slot 10 (single-slot, packed)
        pub field_b: U256, // Auto: slot 1
        #[slot(20)]
        pub large_array: [U256; 5], // Explicit: slots 20-24 (multi-slot)
        pub field_c: U256, // Auto: slot 2
        pub auto_array: [Address; 3], // Auto: slots 3-5 (multi-slot)
        pub field_d: U256, // Auto: slot 6 (after multi-slot array)
    }

    let mut storage = HashMapStorageProvider::new(1);
    let addr = test_address(1);

    let small_array = [42u8; 32];
    let large_array = [
        U256::from(100),
        U256::from(200),
        U256::from(300),
        U256::from(400),
        U256::from(500),
    ];
    let auto_array = [
        address!("0x0000000000000000000000000000000000000011"),
        address!("0x0000000000000000000000000000000000000022"),
        address!("0x0000000000000000000000000000000000000033"),
    ];

    // Store data
    {
        let mut layout = Layout::_new(addr, &mut storage);
        layout.sstore_field_a(U256::from(1)).unwrap();
        layout.sstore_small_array(small_array).unwrap();
        layout.sstore_field_b(U256::from(2)).unwrap();
        layout.sstore_large_array(large_array).unwrap();
        layout.sstore_field_c(U256::from(3)).unwrap();
        layout.sstore_auto_array(auto_array).unwrap();
        layout.sstore_field_d(U256::from(4)).unwrap();

        // Verify getters
        assert_eq!(layout.sload_field_a().unwrap(), U256::from(1));
        assert_eq!(layout.sload_small_array().unwrap(), small_array);
        assert_eq!(layout.sload_field_b().unwrap(), U256::from(2));
        assert_eq!(layout.sload_large_array().unwrap(), large_array);
        assert_eq!(layout.sload_field_c().unwrap(), U256::from(3));
        assert_eq!(layout.sload_auto_array().unwrap(), auto_array);
        assert_eq!(layout.sload_field_d().unwrap(), U256::from(4));
    }

    // Verify actual slot assignments
    assert_eq!(storage.sload(addr, U256::from(0)), Ok(U256::from(1))); // field_a

    // small_array is packed into slot 10
    let expected_small = U256::from_be_bytes(small_array);
    assert_eq!(storage.sload(addr, U256::from(10)), Ok(expected_small));

    assert_eq!(storage.sload(addr, U256::from(1)), Ok(U256::from(2))); // field_b

    // large_array occupies slots 20-24
    assert_eq!(storage.sload(addr, U256::from(20)), Ok(U256::from(100)));
    assert_eq!(storage.sload(addr, U256::from(21)), Ok(U256::from(200)));
    assert_eq!(storage.sload(addr, U256::from(22)), Ok(U256::from(300)));
    assert_eq!(storage.sload(addr, U256::from(23)), Ok(U256::from(400)));
    assert_eq!(storage.sload(addr, U256::from(24)), Ok(U256::from(500)));

    assert_eq!(storage.sload(addr, U256::from(2)), Ok(U256::from(3))); // field_c

    // auto_array occupies slots 3-5
    assert_eq!(storage.sload(addr, U256::from(3)), Ok(U256::from(0x11)));
    assert_eq!(storage.sload(addr, U256::from(4)), Ok(U256::from(0x22)));
    assert_eq!(storage.sload(addr, U256::from(5)), Ok(U256::from(0x33)));

    assert_eq!(storage.sload(addr, U256::from(6)), Ok(U256::from(4))); // field_d

    // Verify slots module
    assert_eq!(slots::FIELD_A, U256::from(0));
    assert_eq!(slots::SMALL_ARRAY, U256::from(10));
    assert_eq!(slots::FIELD_B, U256::from(1));
    assert_eq!(slots::LARGE_ARRAY, U256::from(20));
    assert_eq!(slots::FIELD_C, U256::from(2));
    assert_eq!(slots::AUTO_ARRAY, U256::from(3));
    assert_eq!(slots::FIELD_D, U256::from(6));

    // Test delete
    {
        let mut layout = Layout::_new(addr, &mut storage);
        layout.clear_large_array().unwrap();
        layout.clear_auto_array().unwrap();
    }

    // Verify array slots are zeroed
    for slot in 20..=24 {
        assert_eq!(storage.sload(addr, U256::from(slot)), Ok(U256::ZERO));
    }
    for slot in 3..=5 {
        assert_eq!(storage.sload(addr, U256::from(slot)), Ok(U256::ZERO));
    }

    // Verify other fields unchanged
    assert_eq!(storage.sload(addr, U256::from(0)), Ok(U256::from(1))); // field_a
    assert_eq!(storage.sload(addr, U256::from(10)), Ok(expected_small)); // small_array
    assert_eq!(storage.sload(addr, U256::from(1)), Ok(U256::from(2))); // field_b
    assert_eq!(storage.sload(addr, U256::from(2)), Ok(U256::from(3))); // field_c
    assert_eq!(storage.sload(addr, U256::from(6)), Ok(U256::from(4))); // field_d
}
