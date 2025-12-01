//! Tests for struct storage, multi-slot structs, and struct deletion.
//!
//! This module tests the storage of structs (both as direct fields and in mappings),
//! verifying that multi-slot structs are correctly handled and that deletion works.

use super::*;
use tempo_precompiles::storage::{Mapping, StorageContext};

#[test]
fn test_struct_storage() {
    #[contract]
    pub struct Layout {
        pub field_a: U256, // Auto: slot 0
        #[slot(10)]
        pub block: TestBlock, // Explicit: slots 10-12
        pub field_b: U256, // Auto: slot 1 (skips 10-12)
        pub address_mapping: Mapping<Address, U256>, // Auto: slot 2
        pub block_mapping: Mapping<u64, TestBlock>, // Auto: slot 3
    }

    let (mut storage, address) = setup_storage();
    let mut layout = Layout::__new(address);
    StorageContext::enter(&mut storage, || {
        // Verify actual slot assignments
        assert_eq!(layout.field_a.slot(), U256::ZERO);
        assert_eq!(layout.field_b.slot(), U256::ONE);
        assert_eq!(layout.address_mapping.slot(), U256::from(2));
        assert_eq!(layout.block_mapping.slot(), U256::from(3));

        assert_eq!(layout.block.base_slot(), U256::from(10));
        assert_eq!(layout.block.field1.slot(), U256::from(10));
        assert_eq!(layout.block.field2.slot(), U256::from(11));
        assert_eq!(layout.block.field3.slot(), U256::from(12));

        // Verify slots module
        assert_eq!(slots::FIELD_A, U256::from(0));
        assert_eq!(slots::BLOCK, U256::from(10));
        assert_eq!(slots::FIELD_B, U256::ONE);
        assert_eq!(slots::ADDRESS_MAPPING, U256::from(2));
        assert_eq!(slots::BLOCK_MAPPING, U256::from(3));

        // Test direct fields
        let block = TestBlock {
            field1: U256::from(1000),
            field2: U256::from(2000),
            field3: 3000,
        };

        layout.field_a.write(U256::from(100)).unwrap();
        layout.field_b.write(U256::from(200)).unwrap();
        layout.block.write(block.clone()).unwrap();

        assert_eq!(layout.field_a.read().unwrap(), U256::from(100));
        assert_eq!(layout.field_b.read().unwrap(), U256::from(200));
        assert_eq!(layout.block.read().unwrap(), block);

        // Test address_mapping with multiple addresses
        let addr1 = test_address(10);
        let addr2 = test_address(20);
        let addr3 = test_address(30);

        let addr_map = layout.address_mapping;
        addr_map.at(addr1).write(U256::from(1000)).unwrap();
        addr_map.at(addr2).write(U256::from(2000)).unwrap();
        addr_map.at(addr3).write(U256::from(3000)).unwrap();

        assert_eq!(addr_map.at(addr1).read().unwrap(), U256::from(1000));
        assert_eq!(addr_map.at(addr2).read().unwrap(), U256::from(2000));
        assert_eq!(addr_map.at(addr3).read().unwrap(), U256::from(3000));

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

        layout.block_mapping.at(1).write(block1.clone()).unwrap();
        layout.block_mapping.at(2).write(block2.clone()).unwrap();
        assert_eq!(layout.block_mapping.at(1).read().unwrap(), block1);
        assert_eq!(layout.block_mapping.at(2).read().unwrap(), block2);

        // Verify non-existent keys return default values
        assert_eq!(addr_map.at(test_address(99)).read().unwrap(), U256::ZERO);
        assert_eq!(
            layout.block_mapping.at(99).read().unwrap(),
            TestBlock::default()
        );
    });
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

    let (mut storage, address) = setup_storage();
    let mut layout = Layout::__new(address);
    StorageContext::enter(&mut storage, || {
        let block = TestBlock {
            field1: U256::from(1000),
            field2: U256::from(2000),
            field3: 3000,
        };

        // Write and verify data
        layout.field_a.write(U256::from(100)).unwrap();
        layout.field_b.write(U256::from(200)).unwrap();
        layout.block.write(block.clone()).unwrap();

        assert_eq!(layout.field_a.read().unwrap(), U256::from(100));
        assert_eq!(layout.field_b.read().unwrap(), U256::from(200));
        assert_eq!(layout.block.read().unwrap(), block);

        // Delete the block field
        layout.block.delete().unwrap();

        // Verify block returns default values after deletion
        assert_eq!(
            layout.block.read().unwrap(),
            TestBlock {
                field1: U256::ZERO,
                field2: U256::ZERO,
                field3: 0,
            }
        );

        // Verify other fields remain unchanged
        assert_eq!(layout.field_a.read().unwrap(), U256::from(100));
        assert_eq!(layout.field_b.read().unwrap(), U256::from(200));
    });
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

    let (mut storage, address) = setup_storage();
    let mut layout = Layout::__new(address);
    StorageContext::enter(&mut storage, || {
        let profile = UserProfile {
            owner: test_address(42),
            active: true,
            balance: U256::from(999_999),
        };

        // Write and verify data
        layout.counter.write(U256::from(5)).unwrap();
        layout.profile.write(profile.clone()).unwrap();
        layout.flag.write(true).unwrap();

        assert_eq!(layout.counter.read().unwrap(), U256::from(5));
        assert_eq!(layout.profile.read().unwrap(), profile);
        assert!(layout.flag.read().unwrap());

        // Delete the profile
        layout.profile.delete().unwrap();

        // Verify profile returns default values after deletion
        assert_eq!(
            layout.profile.read().unwrap(),
            UserProfile {
                owner: Address::ZERO,
                active: false,
                balance: U256::ZERO,
            }
        );

        // Verify other fields remain unchanged
        assert_eq!(layout.counter.read().unwrap(), U256::from(5));
        assert!(layout.flag.read().unwrap());
    });
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

        let (mut storage, address) = setup_storage();
        let mut layout = Layout::__new(address);
        StorageContext::enter(&mut storage, || {
            // Store random values
            layout.field_a.write(field_a_val)?;
            layout.block.write(block.clone())?;
            layout.field_b.write(field_b_val)?;

            // Roundtrip property
            prop_assert_eq!(layout.field_a.read()?, field_a_val);
            prop_assert_eq!(layout.block.read()?, block);
            prop_assert_eq!(layout.field_b.read()?, field_b_val);

            // Delete property for struct
            layout.block.delete()?;
            let default_block = TestBlock {
                field1: U256::ZERO,
                field2: U256::ZERO,
                field3: 0,
            };
            prop_assert_eq!(layout.block.read()?, default_block);

            // Isolation: other fields unchanged
            prop_assert_eq!(layout.field_a.read()?, field_a_val);
            prop_assert_eq!(layout.field_b.read()?, field_b_val);
            Ok(())
        })?;
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

        let (mut storage, address) = setup_storage();
        let mut layout = Layout::__new(address);
        StorageContext::enter(&mut storage, || {
            // Store random values
            layout.counter.write(counter_val)?;
            layout.profile.write(profile.clone())?;
            layout.flag.write(flag_val)?;

            // Roundtrip property
            prop_assert_eq!(layout.counter.read()?, counter_val);
            prop_assert_eq!(layout.profile.read()?, profile);
            prop_assert_eq!(layout.flag.read()?, flag_val);

            // Delete property
            layout.profile.delete()?;
            let default_profile = UserProfile {
                owner: Address::ZERO,
                active: false,
                balance: U256::ZERO,
            };
            prop_assert_eq!(layout.profile.read()?, default_profile);

            // Isolation: other fields unchanged
            prop_assert_eq!(layout.counter.read()?, counter_val);
            prop_assert_eq!(layout.flag.read()?, flag_val);
            Ok(())
        })?;
    }
}
