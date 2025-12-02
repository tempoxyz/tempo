//! Tests for struct storage, multi-slot structs, and struct deletion.
//!
//! This module tests the storage of structs (both as direct fields and in mappings),
//! verifying that multi-slot structs are correctly handled and that deletion works.

use super::*;

#[test]
fn test_struct_storage() {
    #[contract]
    pub struct Layout {
        pub field_a: U256, // Auto: slot 0
        #[slot(10)]
        pub block: TestBlock, // Explicit: slots 10-12
        pub field_b: U256, // Auto: slot 1 (skips 10-12)
        pub address_mapping: crate::storage::Mapping<Address, U256>, // Auto: slot 2
        pub block_mapping: crate::storage::Mapping<u64, TestBlock>, // Auto: slot 3
    }

    let mut s = setup_storage();

    let block = TestBlock { field1: U256::from(1000), field2: U256::from(2000), field3: 3000 };

    // Scope the layout to ensure it's dropped before we access storage directly
    {
        let mut layout = Layout::_new(s.address, s.storage());
        layout.sstore_field_a(U256::from(100)).unwrap();
        layout.sstore_field_b(U256::from(200)).unwrap();
        layout.sstore_block(block.clone()).unwrap();

        // Verify fields
        assert_eq!(layout.sload_field_a().unwrap(), U256::from(100));
        assert_eq!(layout.sload_field_b().unwrap(), U256::from(200));
        assert_eq!(layout.sload_block().unwrap(), block);
    }

    // Verify actual slot assignments
    assert_eq!(s.storage.sload(s.address, U256::from(0)), Ok(U256::from(100))); // field_a
    assert_eq!(s.storage.sload(s.address, U256::from(10)), Ok(U256::from(1000))); // block.field1
    assert_eq!(s.storage.sload(s.address, U256::from(11)), Ok(U256::from(2000))); // block.field2
    assert_eq!(s.storage.sload(s.address, U256::from(12)), Ok(U256::from(3000))); // block.field3
    assert_eq!(s.storage.sload(s.address, U256::ONE), Ok(U256::from(200))); // field_b

    // Verify slots module
    assert_eq!(slots::FIELD_A, U256::from(0));
    assert_eq!(slots::BLOCK, U256::from(10));
    assert_eq!(slots::FIELD_B, U256::ONE);
    assert_eq!(slots::ADDRESS_MAPPING, U256::from(2));
    assert_eq!(slots::BLOCK_MAPPING, U256::from(3));

    // Test address_mapping and block_mapping
    {
        let mut layout = Layout::_new(s.address, s.storage());

        // Test address_mapping with multiple addresses
        let addr1 = test_address(10);
        let addr2 = test_address(20);
        let addr3 = test_address(30);

        layout.sstore_address_mapping(addr1, U256::from(1000)).unwrap();
        layout.sstore_address_mapping(addr2, U256::from(2000)).unwrap();
        layout.sstore_address_mapping(addr3, U256::from(3000)).unwrap();

        assert_eq!(layout.sload_address_mapping(addr1).unwrap(), U256::from(1000));
        assert_eq!(layout.sload_address_mapping(addr2).unwrap(), U256::from(2000));
        assert_eq!(layout.sload_address_mapping(addr3).unwrap(), U256::from(3000));

        // Test block_mapping with TestBlock values
        let block1 = TestBlock { field1: U256::from(111), field2: U256::from(222), field3: 333 };
        let block2 = TestBlock { field1: U256::from(444), field2: U256::from(555), field3: 666 };

        layout.sstore_block_mapping(1u64, block1.clone()).unwrap();
        layout.sstore_block_mapping(2u64, block2.clone()).unwrap();

        assert_eq!(layout.sload_block_mapping(1u64).unwrap(), block1);
        assert_eq!(layout.sload_block_mapping(2u64).unwrap(), block2);

        // Verify non-existent keys return default values
        assert_eq!(layout.sload_address_mapping(test_address(99)).unwrap(), U256::ZERO);
        assert_eq!(
            layout.sload_block_mapping(999u64).unwrap(),
            TestBlock { field1: U256::ZERO, field2: U256::ZERO, field3: 0 }
        );
    }
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

    let mut s = setup_storage();

    let block = TestBlock { field1: U256::from(1000), field2: U256::from(2000), field3: 3000 };

    // Scope the layout to store data
    {
        let mut layout = Layout::_new(s.address, s.storage());
        layout.sstore_field_a(U256::from(100)).unwrap();
        layout.sstore_field_b(U256::from(200)).unwrap();
        layout.sstore_block(block.clone()).unwrap();

        // Verify data is stored
        assert_eq!(layout.sload_field_a().unwrap(), U256::from(100));
        assert_eq!(layout.sload_field_b().unwrap(), U256::from(200));
        assert_eq!(layout.sload_block().unwrap(), block);
    }

    // Verify storage slots before delete
    assert_eq!(s.storage.sload(s.address, U256::from(0)), Ok(U256::from(100))); // field_a
    assert_eq!(s.storage.sload(s.address, U256::from(10)), Ok(U256::from(1000))); // block.field1
    assert_eq!(s.storage.sload(s.address, U256::from(11)), Ok(U256::from(2000))); // block.field2
    assert_eq!(s.storage.sload(s.address, U256::from(12)), Ok(U256::from(3000))); // block.field3
    assert_eq!(s.storage.sload(s.address, U256::ONE), Ok(U256::from(200))); // field_b

    // Delete the block field using the generated delete method
    {
        let mut layout = Layout::_new(s.address, s.storage());
        layout.clear_block().unwrap();
    }

    // Verify block slots are zeroed (10, 11, 12)
    assert_eq!(s.storage.sload(s.address, U256::from(10)), Ok(U256::ZERO));
    assert_eq!(s.storage.sload(s.address, U256::from(11)), Ok(U256::ZERO));
    assert_eq!(s.storage.sload(s.address, U256::from(12)), Ok(U256::ZERO));

    // Verify other fields are untouched
    assert_eq!(s.storage.sload(s.address, U256::from(0)), Ok(U256::from(100))); // field_a
    assert_eq!(s.storage.sload(s.address, U256::ONE), Ok(U256::from(200))); // field_b

    // Verify loading the block returns default values
    {
        let mut layout = Layout::_new(s.address, s.storage());
        assert_eq!(
            layout.sload_block().unwrap(),
            TestBlock { field1: U256::ZERO, field2: U256::ZERO, field3: 0 }
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

    let mut s = setup_storage();

    let profile =
        UserProfile { owner: test_address(42), active: true, balance: U256::from(999_999) };

    // Store data
    {
        let mut layout = Layout::_new(s.address, s.storage());
        layout.sstore_counter(U256::from(5)).unwrap();
        layout.sstore_profile(profile.clone()).unwrap();
        layout.sstore_flag(true).unwrap();

        // Verify getters
        assert_eq!(layout.sload_counter().unwrap(), U256::from(5));
        assert_eq!(layout.sload_profile().unwrap(), profile);
        assert!(layout.sload_flag().unwrap());
    }

    // Verify actual slot assignments
    assert_eq!(s.storage.sload(s.address, U256::from(0)), Ok(U256::from(5))); // counter
    assert_eq!(
        s.storage.sload(s.address, U256::from(20)),
        // Packed: owner (20 bytes) + active (1 byte)
        Ok("0x000000000000000000000001000000000000000000000000000000000000002A"
            .parse::<U256>()
            .unwrap())
    );
    assert_eq!(s.storage.sload(s.address, U256::from(21)), Ok(U256::from(999_999))); // profile.balance

    // Verify slots module
    assert_eq!(slots::COUNTER, U256::from(0));
    assert_eq!(slots::PROFILE, U256::from(20));
    assert_eq!(slots::FLAG, U256::ONE);

    // Test delete
    {
        let mut layout = Layout::_new(s.address, s.storage());
        layout.clear_profile().unwrap();
    }

    // Verify profile slots are zeroed (only 2 slots: 20 and 21)
    assert_eq!(s.storage.sload(s.address, U256::from(20)), Ok(U256::ZERO)); // owner + active (packed)
    assert_eq!(s.storage.sload(s.address, U256::from(21)), Ok(U256::ZERO)); // balance

    // Verify other fields unchanged
    assert_eq!(s.storage.sload(s.address, U256::from(0)), Ok(U256::from(5)));
    assert_eq!(s.storage.sload(s.address, U256::ONE), Ok(U256::ONE));

    // Verify loading returns defaults
    {
        let mut layout = Layout::_new(s.address, s.storage());
        assert_eq!(
            layout.sload_profile().unwrap(),
            UserProfile { owner: Address::ZERO, active: false, balance: U256::ZERO }
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Property test for struct storage with random TestBlock values
    #[test]
    fn proptest_struct_storage(
        field_a_val in arb_u256(),
        field_b_val in arb_u256(),
        block in arb_test_block(),
    ) {
        #[contract]
        pub struct Layout {
            pub field_a: U256, // Auto: slot 0
            #[slot(10)]
            pub block: TestBlock, // Explicit: slots 10-12
            pub field_b: U256, // Auto: slot 1
        }

        let mut s = setup_storage();

        {
            let mut layout = Layout::_new(s.address, s.storage());

            // Store random values
            layout.sstore_field_a(field_a_val)?;
            layout.sstore_block(block.clone())?;
            layout.sstore_field_b(field_b_val)?;

            // Roundtrip property
            prop_assert_eq!(layout.sload_field_a()?, field_a_val);
            prop_assert_eq!(layout.sload_block()?, block);
            prop_assert_eq!(layout.sload_field_b()?, field_b_val);

            // Delete property for struct
            layout.clear_block()?;
            let default_block = TestBlock {
                field1: U256::ZERO,
                field2: U256::ZERO,
                field3: 0,
            };
            prop_assert_eq!(layout.sload_block()?, default_block);

            // Isolation: other fields unchanged
            prop_assert_eq!(layout.sload_field_a()?, field_a_val);
            prop_assert_eq!(layout.sload_field_b()?, field_b_val);
        }

        // Verify slots 10, 11, 12 are zeroed after delete
        prop_assert_eq!(s.storage.sload(s.address, U256::from(10))?, U256::ZERO);
        prop_assert_eq!(s.storage.sload(s.address, U256::from(11))?, U256::ZERO);
        prop_assert_eq!(s.storage.sload(s.address, U256::from(12))?, U256::ZERO);
    }

    /// Property test for UserProfile struct storage
    #[test]
    fn proptest_user_profile_storage(
        counter_val in arb_u256(),
        profile in arb_user_profile(),
        flag_val in any::<bool>(),
    ) {
        #[contract]
        pub struct Layout {
            pub counter: U256, // Auto: slot 0
            #[slot(20)]
            pub profile: UserProfile, // Explicit: slots 20-21
            pub flag: bool,    // Auto: slot 1
        }

        let mut s = setup_storage();

        {
            let mut layout = Layout::_new(s.address, s.storage());

            // Store random values
            layout.sstore_counter(counter_val)?;
            layout.sstore_profile(profile.clone())?;
            layout.sstore_flag(flag_val)?;

            // Roundtrip property
            prop_assert_eq!(layout.sload_counter()?, counter_val);
            prop_assert_eq!(layout.sload_profile()?, profile);
            prop_assert_eq!(layout.sload_flag()?, flag_val);

            // Delete property
            layout.clear_profile()?;
            let default_profile = UserProfile {
                owner: Address::ZERO,
                active: false,
                balance: U256::ZERO,
            };
            prop_assert_eq!(layout.sload_profile()?, default_profile);

            // Isolation: other fields unchanged
            prop_assert_eq!(layout.sload_counter()?, counter_val);
            prop_assert_eq!(layout.sload_flag()?, flag_val);
        }

        // Verify profile slots are zeroed
        prop_assert_eq!(s.storage.sload(s.address, U256::from(20))?, U256::ZERO);
        prop_assert_eq!(s.storage.sload(s.address, U256::from(21))?, U256::ZERO);
    }
}
