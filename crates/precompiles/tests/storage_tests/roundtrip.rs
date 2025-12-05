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

    let mut s = setup_storage();

    let original_block =
        TestBlock { field1: U256::from(789), field2: U256::from(987), field3: 555 };
    let original_profile =
        UserProfile { owner: test_address(99), active: true, balance: U256::from(12345) };

    // Round 1: Store and load
    {
        let mut layout = Layout::_new(s.address, s.storage());
        layout.sstore_block(original_block.clone()).unwrap();
        layout.sstore_profile(original_profile.clone()).unwrap();
    }

    {
        let mut layout = Layout::_new(s.address, s.storage());
        assert_eq!(layout.sload_block().unwrap(), original_block);
        assert_eq!(layout.sload_profile().unwrap(), original_profile);
    }

    // Round 2: Delete and verify defaults
    {
        let mut layout = Layout::_new(s.address, s.storage());
        layout.clear_block().unwrap();
        layout.clear_profile().unwrap();
    }

    {
        let mut layout = Layout::_new(s.address, s.storage());
        assert_eq!(
            layout.sload_block().unwrap(),
            TestBlock { field1: U256::ZERO, field2: U256::ZERO, field3: 0 }
        );
        assert_eq!(
            layout.sload_profile().unwrap(),
            UserProfile { owner: Address::ZERO, active: false, balance: U256::ZERO }
        );
    }

    // Round 3: Store new values
    let new_block = TestBlock { field1: U256::from(111), field2: U256::from(222), field3: 333 };
    let new_profile =
        UserProfile { owner: test_address(88), active: false, balance: U256::from(54321) };

    {
        let mut layout = Layout::_new(s.address, s.storage());
        layout.sstore_block(new_block.clone()).unwrap();
        layout.sstore_profile(new_profile.clone()).unwrap();
    }

    {
        let mut layout = Layout::_new(s.address, s.storage());
        assert_eq!(layout.sload_block().unwrap(), new_block);
        assert_eq!(layout.sload_profile().unwrap(), new_profile);
    }
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

        let mut s = setup_storage();

        // Round 1: Store and load
        {
            let mut layout = Layout::_new(s.address, s.storage());
            layout.sstore_block(block_val.clone())?;
            layout.sstore_profile(profile_val.clone())?;
        }

        {
            let mut layout = Layout::_new(s.address, s.storage());
            prop_assert_eq!(layout.sload_block()?, block_val);
            prop_assert_eq!(layout.sload_profile()?, profile_val);
        }

        // Round 2: Delete and verify defaults
        {
            let mut layout = Layout::_new(s.address, s.storage());
            layout.clear_block()?;
            layout.clear_profile()?;
        }

        {
            let mut layout = Layout::_new(s.address, s.storage());
            let default_block = TestBlock {
                field1: U256::ZERO,
                field2: U256::ZERO,
                field3: 0,
            };
            let default_profile = UserProfile {
                owner: Address::ZERO,
                active: false,
                balance: U256::ZERO,
            };
            prop_assert_eq!(layout.sload_block()?, default_block);
            prop_assert_eq!(layout.sload_profile()?, default_profile);
        }

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

        {
            let mut layout = Layout::_new(s.address, s.storage());
            layout.sstore_block(new_block.clone())?;
            layout.sstore_profile(new_profile.clone())?;
        }

        {
            let mut layout = Layout::_new(s.address, s.storage());
            prop_assert_eq!(layout.sload_block()?, new_block);
            prop_assert_eq!(layout.sload_profile()?, new_profile);
        }
    }
}
