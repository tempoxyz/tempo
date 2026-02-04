//! Tests for EnumerableSet storage type.
//!
//! Tests mirror OpenZeppelin's EnumerableSet.behavior.js test suite:
//! https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/test/utils/structs/EnumerableSet.behavior.js

use super::*;
use alloy::primitives::B256;
use tempo_precompiles::storage::{Mapping, Set, StorageCtx};

fn expect_members_match<T>(
    set: &mut tempo_precompiles::storage::SetHandler<T>,
    expected: &[T],
) -> eyre::Result<()>
where
    T: tempo_precompiles::storage::Storable
        + tempo_precompiles::storage::StorageKey
        + std::hash::Hash
        + Eq
        + Clone
        + std::fmt::Debug,
    T::Handler: tempo_precompiles::storage::Handler<T>,
{
    // Check length
    assert_eq!(
        set.len()?,
        expected.len(),
        "length mismatch: expected {}, got {}",
        expected.len(),
        set.len()?
    );

    // Check contains for all expected values
    for value in expected {
        assert!(
            set.contains(value)?,
            "expected value {value:?} not found in set"
        );
    }

    // Check at() returns all expected values
    let at_values: Vec<T> = (0..expected.len())
        .map(|i| set.at(i).unwrap().unwrap())
        .collect();
    for value in expected {
        assert!(
            at_values.contains(value),
            "at() did not return expected value {value:?}"
        );
    }

    // Check values() returns all expected values
    let all_values = set.read()?;
    assert_eq!(all_values.len(), expected.len());
    for value in expected {
        assert!(
            all_values.contains(value),
            "values() did not contain {value:?}"
        );
    }

    Ok(())
}

#[test]
fn test_oz_starts_empty() -> eyre::Result<()> {
    let (mut storage, address) = setup_storage();

    StorageCtx::enter(&mut storage, || {
        let mut set = tempo_precompiles::storage::SetHandler::<Address>::new(U256::ZERO, address);

        let value_a = test_address(1);

        // Should not contain any value
        assert!(!set.contains(&value_a)?);

        // Should match empty set
        expect_members_match(&mut set, &[])?;

        Ok(())
    })
}

#[test]
fn test_oz_add_adds_a_value() -> eyre::Result<()> {
    let (mut storage, address) = setup_storage();

    StorageCtx::enter(&mut storage, || {
        let mut set = tempo_precompiles::storage::SetHandler::<Address>::new(U256::ZERO, address);

        let value_a = test_address(1);

        // Add returns true when value is added
        assert!(set.insert(value_a)?);

        expect_members_match(&mut set, &[value_a])?;

        Ok(())
    })
}

#[test]
fn test_oz_add_adds_several_values() -> eyre::Result<()> {
    let (mut storage, address) = setup_storage();

    StorageCtx::enter(&mut storage, || {
        let mut set = tempo_precompiles::storage::SetHandler::<Address>::new(U256::ZERO, address);

        let value_a = test_address(1);
        let value_b = test_address(2);
        let value_c = test_address(3);

        set.insert(value_a)?;
        set.insert(value_b)?;

        expect_members_match(&mut set, &[value_a, value_b])?;

        // C is not in the set
        assert!(!set.contains(&value_c)?);

        Ok(())
    })
}

#[test]
fn test_oz_add_returns_false_when_adding_values_already_in_set() -> eyre::Result<()> {
    let (mut storage, address) = setup_storage();

    StorageCtx::enter(&mut storage, || {
        let mut set = tempo_precompiles::storage::SetHandler::<Address>::new(U256::ZERO, address);

        let value_a = test_address(1);

        set.insert(value_a)?;

        // Adding again returns false
        assert!(!set.insert(value_a)?);

        // Set still has only one element
        expect_members_match(&mut set, &[value_a])?;

        Ok(())
    })
}

#[test]
fn test_oz_at_returns_none_for_nonexistent_elements() -> eyre::Result<()> {
    let (mut storage, address) = setup_storage();

    StorageCtx::enter(&mut storage, || {
        let set = tempo_precompiles::storage::SetHandler::<Address>::new(U256::ZERO, address);

        // Note: OZ reverts with panic, we return None for safe access
        assert!(set.at(0)?.is_none());

        Ok(())
    })
}

#[test]
fn test_oz_at_retrieves_existing_element() -> eyre::Result<()> {
    let (mut storage, address) = setup_storage();

    StorageCtx::enter(&mut storage, || {
        let mut set = tempo_precompiles::storage::SetHandler::<Address>::new(U256::ZERO, address);

        let value_a = test_address(1);

        set.insert(value_a)?;

        assert_eq!(set.at(0)?.unwrap(), value_a);

        Ok(())
    })
}

#[test]
fn test_oz_remove_removes_added_values() -> eyre::Result<()> {
    let (mut storage, address) = setup_storage();

    StorageCtx::enter(&mut storage, || {
        let mut set = tempo_precompiles::storage::SetHandler::<Address>::new(U256::ZERO, address);

        let value_a = test_address(1);

        set.insert(value_a)?;

        // Remove returns true
        assert!(set.remove(&value_a)?);

        // No longer contains the value
        assert!(!set.contains(&value_a)?);

        expect_members_match(&mut set, &[])?;

        Ok(())
    })
}

#[test]
fn test_oz_remove_returns_false_when_removing_values_not_in_set() -> eyre::Result<()> {
    let (mut storage, address) = setup_storage();

    StorageCtx::enter(&mut storage, || {
        let mut set = tempo_precompiles::storage::SetHandler::<Address>::new(U256::ZERO, address);

        let value_a = test_address(1);

        // Remove returns false for non-existent value
        assert!(!set.remove(&value_a)?);

        // Still doesn't contain the value
        assert!(!set.contains(&value_a)?);

        Ok(())
    })
}

#[test]
fn test_oz_remove_adds_and_removes_multiple_values() -> eyre::Result<()> {
    let (mut storage, address) = setup_storage();

    StorageCtx::enter(&mut storage, || {
        let mut set = tempo_precompiles::storage::SetHandler::<Address>::new(U256::ZERO, address);

        let value_a = test_address(1);
        let value_b = test_address(2);
        let value_c = test_address(3);

        // []
        set.insert(value_a)?;
        set.insert(value_c)?;
        // [A, C]

        set.remove(&value_a)?;
        set.remove(&value_b)?; // B not in set, returns false
        // [C]

        set.insert(value_b)?;
        // [C, B]

        set.insert(value_a)?;
        set.remove(&value_c)?;
        // [A, B] (order may vary due to swap-and-pop)

        set.insert(value_a)?; // Already in set, returns false
        set.insert(value_b)?; // Already in set, returns false
        // [A, B]

        set.insert(value_c)?;
        set.remove(&value_a)?;
        // [B, C] (order may vary)

        set.insert(value_a)?;
        set.remove(&value_b)?;
        // [A, C] (order may vary)

        expect_members_match(&mut set, &[value_a, value_c])?;
        assert!(!set.contains(&value_b)?);

        Ok(())
    })
}

#[test]
fn test_oz_clear_clears_a_single_value() -> eyre::Result<()> {
    let (mut storage, address) = setup_storage();

    StorageCtx::enter(&mut storage, || {
        let mut set = tempo_precompiles::storage::SetHandler::<Address>::new(U256::ZERO, address);

        let value_a = test_address(1);

        set.insert(value_a)?;
        set.delete()?;

        assert!(!set.contains(&value_a)?);
        expect_members_match(&mut set, &[])?;

        Ok(())
    })
}

#[test]
fn test_oz_clear_clears_multiple_values() -> eyre::Result<()> {
    let (mut storage, address) = setup_storage();

    StorageCtx::enter(&mut storage, || {
        let mut set = tempo_precompiles::storage::SetHandler::<Address>::new(U256::ZERO, address);

        let value_a = test_address(1);
        let value_b = test_address(2);
        let value_c = test_address(3);

        set.insert(value_a)?;
        set.insert(value_b)?;
        set.insert(value_c)?;

        set.delete()?;

        assert!(!set.contains(&value_a)?);
        assert!(!set.contains(&value_b)?);
        assert!(!set.contains(&value_c)?);
        expect_members_match(&mut set, &[])?;

        Ok(())
    })
}

#[test]
fn test_oz_clear_does_not_revert_on_empty_set() -> eyre::Result<()> {
    let (mut storage, address) = setup_storage();

    StorageCtx::enter(&mut storage, || {
        let mut set = tempo_precompiles::storage::SetHandler::<Address>::new(U256::ZERO, address);

        // Should not panic/error
        set.delete()?;

        Ok(())
    })
}

#[test]
fn test_oz_clear_then_add_value() -> eyre::Result<()> {
    let (mut storage, address) = setup_storage();

    StorageCtx::enter(&mut storage, || {
        let mut set = tempo_precompiles::storage::SetHandler::<Address>::new(U256::ZERO, address);

        let value_a = test_address(1);
        let value_b = test_address(2);
        let value_c = test_address(3);

        set.insert(value_a)?;
        set.insert(value_b)?;
        set.insert(value_c)?;

        set.delete()?;

        set.insert(value_a)?;

        assert!(set.contains(&value_a)?);
        assert!(!set.contains(&value_b)?);
        assert!(!set.contains(&value_c)?);
        expect_members_match(&mut set, &[value_a])?;

        Ok(())
    })
}

#[test]
fn test_oz_values_full_and_paginated() -> eyre::Result<()> {
    let (mut storage, address) = setup_storage();

    StorageCtx::enter(&mut storage, || {
        let mut set = tempo_precompiles::storage::SetHandler::<U256>::new(U256::ZERO, address);

        let value_a = U256::from(1);
        let value_b = U256::from(2);
        let value_c = U256::from(3);
        let values = vec![value_a, value_b, value_c];

        set.insert(value_a)?;
        set.insert(value_b)?;
        set.insert(value_c)?;

        // Try pagination with various begin/end combinations
        for begin in 0..=4 {
            for end in 0..=4 {
                let page = set.read_range(begin, end)?;
                let expected: Vec<U256> = values
                    .iter()
                    .skip(begin)
                    .take(end.saturating_sub(begin))
                    .cloned()
                    .collect();
                assert_eq!(page, expected, "values_range({begin}, {end}) mismatch");
            }
        }

        // Get all values - should match (order preserved for sequential adds)
        let all_values = set.read()?;
        assert_eq!(all_values, values.into());

        Ok(())
    })
}

#[test]
fn test_set_in_contract() -> eyre::Result<()> {
    #[contract]
    pub struct Layout {
        pub counter: U256,
        pub holders: Set<Address>,
        pub ids: Set<U256>,
    }

    let (mut storage, address) = setup_storage();
    let mut layout = Layout::__new(address);

    StorageCtx::enter(&mut storage, || {
        // Verify slot assignments
        assert_eq!(layout.counter.slot(), U256::ZERO);
        // Set occupies 2 slots: Vec length at slot 1, Mapping at slot 2
        assert_eq!(layout.holders.base_slot(), U256::from(1));
        assert_eq!(layout.ids.base_slot(), U256::from(3));

        // Test counter
        layout.counter.write(U256::from(100))?;
        assert_eq!(layout.counter.read()?, U256::from(100));

        // Test holders set
        let addr1 = test_address(1);
        let addr2 = test_address(2);
        let addr3 = test_address(3);

        assert!(layout.holders.is_empty()?);

        layout.holders.insert(addr1)?;
        layout.holders.insert(addr2)?;
        layout.holders.insert(addr3)?;

        assert_eq!(layout.holders.len()?, 3);
        assert!(layout.holders.contains(&addr1)?);
        assert!(layout.holders.contains(&addr2)?);
        assert!(layout.holders.contains(&addr3)?);
        assert!(!layout.holders.contains(&test_address(99))?);

        // Remove an element
        layout.holders.remove(&addr2)?;
        assert_eq!(layout.holders.len()?, 2);
        assert!(!layout.holders.contains(&addr2)?);

        // Test ids set with U256
        layout.ids.insert(U256::from(1000))?;
        layout.ids.insert(U256::from(2000))?;

        assert_eq!(layout.ids.len()?, 2);
        assert!(layout.ids.contains(&U256::from(1000))?);
        assert!(layout.ids.contains(&U256::from(2000))?);

        // Counter should still be intact
        assert_eq!(layout.counter.read()?, U256::from(100));

        Ok(())
    })
}

#[test]
fn test_set_with_mapping() -> eyre::Result<()> {
    #[contract]
    pub struct Layout {
        pub user_roles: Mapping<Address, Set<B256>>,
    }

    let (mut storage, address) = setup_storage();
    let mut layout = Layout::__new(address);

    StorageCtx::enter(&mut storage, || {
        let user1 = test_address(1);
        let user2 = test_address(2);

        let role_admin = keccak256(b"ADMIN_ROLE");
        let role_minter = keccak256(b"MINTER_ROLE");
        let role_pauser = keccak256(b"PAUSER_ROLE");

        // Add roles to user1
        layout.user_roles[user1].insert(role_admin)?;
        layout.user_roles[user1].insert(role_minter)?;

        // Add roles to user2
        layout.user_roles[user2].insert(role_pauser)?;

        // Verify
        assert_eq!(layout.user_roles[user1].len()?, 2);
        assert!(layout.user_roles[user1].contains(&role_admin)?);
        assert!(layout.user_roles[user1].contains(&role_minter)?);
        assert!(!layout.user_roles[user1].contains(&role_pauser)?);

        assert_eq!(layout.user_roles[user2].len()?, 1);
        assert!(layout.user_roles[user2].contains(&role_pauser)?);

        // Remove a role
        layout.user_roles[user1].remove(&role_admin)?;
        assert_eq!(layout.user_roles[user1].len()?, 1);
        assert!(!layout.user_roles[user1].contains(&role_admin)?);

        Ok(())
    })
}

#[test]
fn test_set_with_b256() -> eyre::Result<()> {
    let (mut storage, address) = setup_storage();

    StorageCtx::enter(&mut storage, || {
        let mut set = tempo_precompiles::storage::SetHandler::<B256>::new(U256::ZERO, address);

        let val1 = B256::random();
        let val2 = B256::random();

        set.insert(val1)?;
        set.insert(val2)?;

        assert_eq!(set.len()?, 2);
        assert!(set.contains(&val1)?);
        assert!(set.contains(&val2)?);

        Ok(())
    })
}
