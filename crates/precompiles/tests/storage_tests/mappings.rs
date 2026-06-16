//! Mapping storage tests.

use super::*;
use tempo_precompiles::storage::{Mapping, StorageCtx, domains, raw_address_slot};

#[test]
fn test_mapping() {
    #[contract]
    pub struct Layout {
        pub block_mapping: Mapping<u64, TestBlock>, // Auto: slot 0
        pub profile_mapping: Mapping<Address, UserProfile>, // Auto: slot 1
    }

    let (mut storage, address) = setup_storage();
    let mut layout = Layout::__new(address);

    StorageCtx::enter(&mut storage, || {
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
        layout.block_mapping[1u64].write(block1.clone()).unwrap();
        layout.block_mapping[2u64].write(block2.clone()).unwrap();
        layout.profile_mapping[test_address(10)]
            .write(profile1.clone())
            .unwrap();
        layout.profile_mapping[test_address(20)]
            .write(profile2.clone())
            .unwrap();

        // Verify all entries
        assert_eq!(layout.block_mapping[1u64].read().unwrap(), block1);
        assert_eq!(layout.block_mapping[2u64].read().unwrap(), block2);
        assert_eq!(
            layout.profile_mapping[test_address(10)].read().unwrap(),
            profile1
        );
        assert_eq!(
            layout.profile_mapping[test_address(20)].read().unwrap(),
            profile2
        );

        // Delete specific entries
        layout.block_mapping[1u64].delete().unwrap();
        layout.profile_mapping[test_address(10)].delete().unwrap();

        // Verify deleted entries return defaults
        assert_eq!(
            layout.block_mapping[1u64].read().unwrap(),
            TestBlock {
                field1: U256::ZERO,
                field2: U256::ZERO,
                field3: 0,
            }
        );
        assert_eq!(
            layout.profile_mapping[test_address(10)].read().unwrap(),
            UserProfile {
                owner: Address::ZERO,
                active: false,
                balance: U256::ZERO,
            }
        );

        // Verify non-deleted entries are intact
        assert_eq!(layout.block_mapping[2u64].read().unwrap(), block2);
        assert_eq!(
            layout.profile_mapping[test_address(20)].read().unwrap(),
            profile2
        );

        Ok::<(), tempo_precompiles::error::TempoPrecompileError>(())
    })
    .unwrap();
}

#[test]
fn test_raw_address_mapping() {
    #[contract]
    pub struct Layout {
        #[raw_map(domain = crate::storage::domains::TIP20_BALANCES)]
        pub balances: Mapping<Address, U256>,
        #[raw_map(domain = crate::storage::domains::TIP20_PERMIT_NONCES)]
        pub nonces: Mapping<Address, U256>,
    }

    let (mut storage, address) = setup_storage();
    let mut layout = Layout::__new(address);
    let account = test_address(42);

    assert_eq!(
        layout.balances[account].slot(),
        raw_address_slot::<{ domains::TIP20_BALANCES }>(account)
    );
    assert_eq!(
        layout.nonces[account].slot(),
        raw_address_slot::<{ domains::TIP20_PERMIT_NONCES }>(account)
    );
    assert_ne!(
        layout.balances[account].slot(),
        layout.nonces[account].slot()
    );

    StorageCtx::enter(&mut storage, || {
        layout.balances[account].write(U256::from(123))?;
        layout.nonces[account].write(U256::from(7))?;

        assert_eq!(layout.balances[account].read()?, U256::from(123));
        assert_eq!(layout.nonces[account].read()?, U256::from(7));

        Ok::<(), tempo_precompiles::error::TempoPrecompileError>(())
    })
    .unwrap();
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
            pub address_mapping: Mapping<Address, U256>, // Auto: slot 0
            pub block_mapping: Mapping<u64, TestBlock>, // Auto: slot 1
        }

        let (mut storage, address) = setup_storage();
        let mut layout = Layout::__new(address);

        StorageCtx::enter(&mut storage, || {
            // Store to different keys
            layout.address_mapping[addr1].write(val1)?;
            layout.address_mapping[addr2].write(val2)?;
            layout.block_mapping[100u64].write(block1.clone())?;
            layout.block_mapping[200u64].write(block2.clone())?;

            // Isolation property: each key has independent storage
            prop_assert_eq!(layout.address_mapping[addr1].read()?, val1);
            prop_assert_eq!(layout.address_mapping[addr2].read()?, val2);
            prop_assert_eq!(layout.block_mapping[100u64].read()?, block1);
            prop_assert_eq!(layout.block_mapping[200u64].read()?, block2.clone());

            // Delete one key doesn't affect others
            layout.address_mapping[addr1].delete()?;
            prop_assert_eq!(layout.address_mapping[addr1].read()?, U256::ZERO);
            prop_assert_eq!(layout.address_mapping[addr2].read()?, val2);

            layout.block_mapping[100u64].delete()?;
            let default_block = TestBlock {
                field1: U256::ZERO,
                field2: U256::ZERO,
                field3: 0,
            };
            prop_assert_eq!(layout.block_mapping[100u64].read()?, default_block);
            prop_assert_eq!(layout.block_mapping[200u64].read()?, block2.clone());

            Ok(())
        })?;
    }
}
