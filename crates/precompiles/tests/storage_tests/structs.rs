//! Tests for struct storage, multi-slot structs, and struct deletion.
//!
//! This module tests the storage of structs (both as direct fields and in mappings),
//! verifying that multi-slot structs are correctly handled and that deletion works.

use super::*;
use tempo_precompiles::storage::{Mapping, StorableType, StorageCtx};

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
    StorageCtx::enter(&mut storage, || {
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

        let mut addr_map = layout.address_mapping;
        addr_map[addr1].write(U256::from(1000)).unwrap();
        addr_map[addr2].write(U256::from(2000)).unwrap();
        addr_map[addr3].write(U256::from(3000)).unwrap();

        assert_eq!(addr_map[addr1].read().unwrap(), U256::from(1000));
        assert_eq!(addr_map[addr2].read().unwrap(), U256::from(2000));
        assert_eq!(addr_map[addr3].read().unwrap(), U256::from(3000));

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

        layout.block_mapping[1].write(block1.clone()).unwrap();
        layout.block_mapping[2].write(block2.clone()).unwrap();
        assert_eq!(layout.block_mapping[1].read().unwrap(), block1);
        assert_eq!(layout.block_mapping[2].read().unwrap(), block2);

        // Verify non-existent keys return default values
        assert_eq!(addr_map[test_address(99)].read().unwrap(), U256::ZERO);
        assert_eq!(
            layout.block_mapping[99].read().unwrap(),
            TestBlock::default()
        );
    });
}

#[test]
fn test_multi_slot_last_field_slot_count() {
    #[derive(Storable)]
    struct MultiSlotLast {
        flag: bool,     // slot 0
        arr: [U256; 2], // slot 1-2
    }

    assert_eq!(MultiSlotLast::SLOTS, 3);
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
    StorageCtx::enter(&mut storage, || {
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
    StorageCtx::enter(&mut storage, || {
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
        StorageCtx::enter(&mut storage, || {
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
        StorageCtx::enter(&mut storage, || {
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

mod nested_struct_sload_tests {
    use super::*;
    use tempo_precompiles::storage::Mapping;

    #[derive(Debug, Clone, Default, PartialEq, Eq, Storable)]
    pub struct BaseData {
        pub policy_type: u8,
        pub admin: Address,
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq, Storable)]
    pub struct CompoundData {
        pub sender_policy_id: u64,
        pub recipient_policy_id: u64,
        pub mint_recipient_policy_id: u64,
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq, Storable)]
    pub struct NestedRecord {
        pub base: BaseData,
        pub compound: CompoundData,
    }

    #[contract]
    pub struct NestedLayout {
        pub records: Mapping<u64, NestedRecord>,
    }

    /// This test demonstrates the root cause of the gas regression:
    /// Mappings always occupy exactly 1 slot for their base, regardless of value type.
    /// The nested struct approach does NOT cause slot calculation differences.
    #[test]
    fn test_mapping_base_slots_unaffected_by_value_type() {
        mod flat {
            use super::*;

            #[contract]
            pub struct FlatLayout {
                pub policy_id_counter: u64,
                pub policy_data: Mapping<u64, BaseData>,
                pub policy_set: Mapping<u64, Mapping<Address, bool>>,
            }
        }

        mod nested {
            use super::*;

            #[contract]
            pub struct NestedLayoutWithFollowing {
                pub policy_id_counter: u64,
                pub policy_records: Mapping<u64, NestedRecord>,
                pub policy_set: Mapping<u64, Mapping<Address, bool>>,
            }
        }

        // Flat layout: policy_id_counter at slot 0, policy_data at slot 1, policy_set at slot 2
        assert_eq!(
            flat::slots::POLICY_ID_COUNTER,
            U256::from(0),
            "FlatLayout: policy_id_counter should be at slot 0"
        );
        assert_eq!(
            flat::slots::POLICY_DATA,
            U256::from(1),
            "FlatLayout: policy_data should be at slot 1"
        );
        assert_eq!(
            flat::slots::POLICY_SET,
            U256::from(2),
            "FlatLayout: policy_set should be at slot 2"
        );

        // Nested layout: same slot assignments
        assert_eq!(
            nested::slots::POLICY_ID_COUNTER,
            U256::from(0),
            "NestedLayoutWithFollowing: policy_id_counter should be at slot 0"
        );
        assert_eq!(
            nested::slots::POLICY_RECORDS,
            U256::from(1),
            "NestedLayoutWithFollowing: policy_records should be at slot 1"
        );
        assert_eq!(
            nested::slots::POLICY_SET,
            U256::from(2),
            "NestedLayoutWithFollowing: policy_set should be at slot 2"
        );
        
        // Both layouts have identical slot assignments!
        // This is because Mapping<K, V>::SLOTS = 1 regardless of V's size
    }

    /// Test that the actual keccak hash for mapping lookups is identical
    /// when using flat vs nested value types, since the base slot is the same.
    #[test]
    fn test_mapping_lookup_slot_hash_identical() {
        use alloy::primitives::keccak256;

        mod flat {
            use super::*;

            #[contract]
            pub struct FlatLayout {
                pub policy_id_counter: u64,
                pub policy_data: Mapping<u64, BaseData>,
                pub policy_set: Mapping<u64, Mapping<Address, bool>>,
            }
        }

        mod nested {
            use super::*;

            #[contract]
            pub struct NestedLayoutWithFollowing {
                pub policy_id_counter: u64,
                pub policy_records: Mapping<u64, NestedRecord>,
                pub policy_set: Mapping<u64, Mapping<Address, bool>>,
            }
        }

        // Both should have policy_set at slot 2
        assert_eq!(flat::slots::POLICY_SET, U256::from(2));
        assert_eq!(nested::slots::POLICY_SET, U256::from(2));
        assert_eq!(flat::slots::POLICY_SET, nested::slots::POLICY_SET);

        // Compute the actual slot hash for policy_set[42]
        let key: u64 = 42;
        let flat_base = flat::slots::POLICY_SET;
        let nested_base = nested::slots::POLICY_SET;

        // Slot hash = keccak256(key || base_slot)
        let mut flat_input = [0u8; 64];
        flat_input[24..32].copy_from_slice(&key.to_be_bytes());
        flat_input[32..64].copy_from_slice(&flat_base.to_be_bytes::<32>());
        let flat_slot = keccak256(&flat_input);

        let mut nested_input = [0u8; 64];
        nested_input[24..32].copy_from_slice(&key.to_be_bytes());
        nested_input[32..64].copy_from_slice(&nested_base.to_be_bytes::<32>());
        let nested_slot = keccak256(&nested_input);

        assert_eq!(
            flat_slot, nested_slot,
            "The slot hash for policy_set[42] should be identical in both layouts"
        );
    }

    /// Demonstrates SLOAD behavior for nested structs in mappings.
    ///
    /// This test shows that when accessing a nested field like `mapping[key].base.read()`,
    /// the storage system correctly loads ONLY the slots for the `.base` field, not the
    /// entire parent struct.
    ///
    /// This is critical for gas efficiency: if we read the entire `PolicyRecord` struct
    /// (which includes both `base` and `compound` data), we would incur extra SLOADs
    /// for data we don't need.
    #[test]
    fn test_nested_struct_partial_read_sload_count() {
        let (mut storage, address) = setup_storage();
        let mut layout = NestedLayout::__new(address);

        StorageCtx::enter(&mut storage, || {
            let record = NestedRecord {
                base: BaseData {
                    policy_type: 1,
                    admin: test_address(0x42),
                },
                compound: CompoundData {
                    sender_policy_id: 100,
                    recipient_policy_id: 200,
                    mint_recipient_policy_id: 300,
                },
            };

            layout.records[1].write(record).unwrap();
        });

        storage.reset_sload_count();

        StorageCtx::enter(&mut storage, || {
            let base_data = layout.records[1].base.read().unwrap();
            assert_eq!(base_data.policy_type, 1);
            assert_eq!(base_data.admin, test_address(0x42));
        });

        let sload_count = storage.sload_count();

        assert_eq!(
            sload_count, 1,
            "Reading only .base should perform 1 SLOAD (BaseData fits in one slot). \
             Got {} SLOADs - if this is 2, the macro is loading the entire NestedRecord!",
            sload_count
        );
    }

    /// Demonstrates that reading the full nested struct loads all slots.
    #[test]
    fn test_nested_struct_full_read_sload_count() {
        let (mut storage, address) = setup_storage();
        let mut layout = NestedLayout::__new(address);

        StorageCtx::enter(&mut storage, || {
            let record = NestedRecord {
                base: BaseData {
                    policy_type: 1,
                    admin: test_address(0x42),
                },
                compound: CompoundData {
                    sender_policy_id: 100,
                    recipient_policy_id: 200,
                    mint_recipient_policy_id: 300,
                },
            };

            layout.records[1].write(record).unwrap();
        });

        storage.reset_sload_count();

        StorageCtx::enter(&mut storage, || {
            let full_record = layout.records[1].read().unwrap();
            assert_eq!(full_record.base.policy_type, 1);
            assert_eq!(full_record.compound.sender_policy_id, 100);
        });

        let sload_count = storage.sload_count();

        assert_eq!(
            sload_count, 2,
            "Reading full NestedRecord should perform 2 SLOADs (one per struct field slot). \
             BaseData = 1 slot, CompoundData = 1 slot. Got {} SLOADs.",
            sload_count
        );
    }
}
