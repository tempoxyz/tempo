//! Mapping storage tests.

use super::*;

#[test]
fn test_mapping() {
    #[contract]
    pub struct Layout {
        pub block_mapping: Mapping<u64, TestBlock>, // Auto: slot 0
        pub profile_mapping: Mapping<Address, UserProfile>, // Auto: slot 1
    }

    let mut s = setup_storage();

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
        let mut layout = Layout::_new(s.address, s.storage());
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
        let mut layout = Layout::_new(s.address, s.storage());
        layout.clear_block_mapping(1u64).unwrap();
        layout.clear_profile_mapping(test_address(10)).unwrap();
    }

    // Verify deleted entries return defaults
    {
        let mut layout = Layout::_new(s.address, s.storage());
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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Property test for mapping isolation with random keys
    #[test]
    #[allow(clippy::redundant_clone)]
    fn proptest_mapping(
        addr1 in arb_address(),
        addr2 in arb_address(),
        val1 in arb_u256(),
        val2 in arb_u256(),
        block1 in arb_test_block(),
        block2 in arb_test_block(),
    ) {
        // Skip if keys are the same
        prop_assume!(addr1 != addr2);

        #[contract]
        pub struct Layout {
            pub address_mapping: crate::storage::Mapping<Address, U256>, // Auto: slot 0
            pub block_mapping: crate::storage::Mapping<u64, TestBlock>, // Auto: slot 1
        }

        let mut s = setup_storage();

        {
            let mut layout = Layout::_new(s.address, s.storage());

            // Store to different keys
            layout.sstore_address_mapping(addr1, val1)?;
            layout.sstore_address_mapping(addr2, val2)?;
            layout.sstore_block_mapping(100u64, block1.clone())?;
            layout.sstore_block_mapping(200u64, block2.clone())?;

            // Isolation property: each key has independent storage
            prop_assert_eq!(layout.sload_address_mapping(addr1)?, val1);
            prop_assert_eq!(layout.sload_address_mapping(addr2)?, val2);
            prop_assert_eq!(layout.sload_block_mapping(100u64)?, block1);
            prop_assert_eq!(layout.sload_block_mapping(200u64)?, block2.clone());

            // Delete one key doesn't affect others
            layout.clear_address_mapping(addr1)?;
            prop_assert_eq!(layout.sload_address_mapping(addr1)?, U256::ZERO);
            prop_assert_eq!(layout.sload_address_mapping(addr2)?, val2);

            layout.clear_block_mapping(100u64)?;
            let default_block = TestBlock {
                field1: U256::ZERO,
                field2: U256::ZERO,
                field3: 0,
            };
            prop_assert_eq!(layout.sload_block_mapping(100u64)?, default_block);
            prop_assert_eq!(layout.sload_block_mapping(200u64)?, block2.clone());
        }
    }
}
