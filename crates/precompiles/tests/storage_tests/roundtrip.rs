//! Tests for store/load/delete roundtrip operations.
//!
//! This module tests the full lifecycle of storage operations: store, load, delete, and re-store.

use super::*;

#[test]
fn test_round_trip_operations_in_contract() {
    #[contract]
    pub struct Layout {
        #[slot(100)]
        pub block: TestBlock,
        #[slot(200)]
        pub profile: UserProfile,
    }

    let (mut storage, address) = setup_storage();
    let mut layout = Layout::_new(*address);
    let _guard = storage.enter().unwrap();

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
    layout.block.write(original_block.clone()).unwrap();
    layout.profile.write(original_profile.clone()).unwrap();
    assert_eq!(layout.block.read().unwrap(), original_block);
    assert_eq!(layout.profile.read().unwrap(), original_profile);

    // Round 2: Delete and verify defaults
    layout.block.delete().unwrap();
    layout.profile.delete().unwrap();

    assert_eq!(layout.block.read().unwrap(), TestBlock::default());
    assert_eq!(layout.profile.read().unwrap(), UserProfile::default());

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

    layout.block.write(new_block.clone()).unwrap();
    layout.profile.write(new_profile.clone()).unwrap();

    assert_eq!(layout.block.read().unwrap(), new_block);
    assert_eq!(layout.profile.read().unwrap(), new_profile);

    // Round 4: Individual field operations
    let modified_owner = test_address(77);
    layout.profile.owner.write(modified_owner).unwrap();
    layout.profile.active.delete().unwrap();

    // Verify individual field reads
    assert_eq!(layout.profile.owner.read().unwrap(), modified_owner);
    assert_eq!(layout.profile.active.read().unwrap(), bool::default());
    assert_eq!(layout.profile.balance.read().unwrap(), new_profile.balance);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Universal roundtrip property test
    #[test]
    fn proptest_roundtrip_operations(
        block_val in arb_test_block(),
        profile_val in arb_user_profile(),
    ) {
        #[contract]
        pub struct Layout {
            #[slot(100)]
            pub block: TestBlock,
            #[slot(200)]
            pub profile: UserProfile,
        }

        let (mut storage, address) = setup_storage();
        let mut layout = Layout::_new(*address);
        let _guard = storage.enter().unwrap();

        // Round 1: Store and load
        layout.block.write(block_val.clone())?;
        layout.profile.write(profile_val.clone())?;

        prop_assert_eq!(layout.block.read()?, block_val);
        prop_assert_eq!(layout.profile.read()?, profile_val);

        // Round 2: Delete and verify defaults
        layout.block.delete()?;
        layout.profile.delete()?;

        prop_assert_eq!(layout.block.read()?, TestBlock::default());
        prop_assert_eq!(layout.profile.read()?, UserProfile::default());

        // Round 3: Store new values (different from original)
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

        layout.block.write(new_block.clone())?;
        layout.profile.write(new_profile.clone())?;
        prop_assert_eq!(layout.block.read()?, new_block);

        // Round 4: Individual field operations
        let expected_balance = new_profile.balance;
        prop_assert_eq!(layout.profile.read()?, new_profile);
        let modified_owner = test_address(77);
        layout.profile.owner.write(modified_owner)?;
        layout.profile.active.delete()?;

        // Verify individual field reads
        prop_assert_eq!(layout.profile.owner.read()?, modified_owner);
        prop_assert_eq!(layout.profile.active.read()?, bool::default());
        prop_assert_eq!(layout.profile.balance.read()?, expected_balance);
    }
}
