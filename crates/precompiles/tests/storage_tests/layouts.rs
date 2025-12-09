//! Tests for storage layout and slot assignment.
//!
//! This module tests the #[contract] macro's ability to correctly assign storage slots,
//! including auto-assignment, explicit slots, base_slot, and string literal slots.

use super::*;
use tempo_precompiles::storage::{Mapping, UserMapping};

#[test]
fn test_mixed_slot_allocation() {
    #[contract]
    pub struct Layout {
        field_a: U256, // Auto: slot 0
        #[slot(5)]
        field_b: U256, // Explicit: slot 5 (decimal)
        field_c: U256, // Auto: slot 1
        #[slot(0x10)]
        field_d: U256, // Explicit: slot 16 (hex)
        #[slot(10)]
        field_e: Mapping<Address, U256>, // Explicit: slot 10 (decimal)
    }

    let (mut storage, address) = setup_storage();
    let mut mixed = Layout::__new(address);

    StorageContext::enter(&mut storage, || {
        // Set all fields
        mixed.field_a.write(U256::from(1)).unwrap();
        mixed.field_b.write(U256::from(2)).unwrap();
        mixed.field_c.write(U256::from(3)).unwrap();
        mixed.field_d.write(U256::from(4)).unwrap();

        let addr_at = Address::random();
        mixed.field_e.at(addr_at).write(U256::from(5)).unwrap();

        // Verify values
        assert_eq!(mixed.field_a.read().unwrap(), U256::from(1));
        assert_eq!(mixed.field_b.read().unwrap(), U256::from(2));
        assert_eq!(mixed.field_c.read().unwrap(), U256::from(3));
        assert_eq!(mixed.field_d.read().unwrap(), U256::from(4));
        assert_eq!(mixed.field_e.at(addr_at).read().unwrap(), U256::from(5));

        // Verify actual slot assignments
        assert_eq!(mixed.field_a.slot(), U256::ZERO);
        assert_eq!(mixed.field_b.slot(), U256::from(5));
        assert_eq!(mixed.field_c.slot(), U256::ONE);
        assert_eq!(mixed.field_d.slot(), U256::from(16));
        assert_eq!(mixed.field_e.slot(), U256::from(10));

        // Verify the slots module was generated with correct values
        assert_eq!(slots::FIELD_A, U256::ZERO);
        assert_eq!(slots::FIELD_B, U256::from(5));
        assert_eq!(slots::FIELD_C, U256::ONE);
        assert_eq!(slots::FIELD_D, U256::from(16));
        assert_eq!(slots::FIELD_E, U256::from(10));

        Ok::<(), tempo_precompiles::error::TempoPrecompileError>(())
    })
    .unwrap();
}

#[test]
fn test_default_values() {
    #[contract]
    pub struct Layout {
        pub counter: u64,
        pub flag: bool,
        pub amount: U256,
    }

    let (mut storage, address) = setup_storage();
    let defaults = Layout::__new(address);

    StorageContext::enter(&mut storage, || {
        // Reading uninitialized storage returns zero/default
        assert_eq!(defaults.counter.read().unwrap(), 0);
        assert!(!defaults.flag.read().unwrap());
        assert_eq!(defaults.amount.read().unwrap(), U256::ZERO);

        // Verify actual slot assignments
        assert_eq!(defaults.counter.slot(), U256::ZERO);
        assert_eq!(defaults.counter.offset(), Some(0));
        assert_eq!(defaults.flag.slot(), U256::ZERO);
        assert_eq!(defaults.flag.offset(), Some(8));
        assert_eq!(defaults.amount.slot(), U256::ONE);
        // NOTE(rusowsky): we use the inefficient version for backwards compatibility.
        assert_eq!(defaults.amount.offset(), Some(0));

        Ok::<(), tempo_precompiles::error::TempoPrecompileError>(())
    })
    .unwrap();
}

#[test]
fn test_base_slots() {
    #[contract]
    pub struct Layout {
        pub field_a: U256, // Auto: slot 0
        #[base_slot(100)]
        pub field_b: U256, // base_slot: slot 100
        pub field_c: U256, // Auto: slot 101
        #[base_slot(200)]
        pub field_d: U256, // base_slot: slot 200
        pub field_e: U256, // Auto: slot 201
        #[base_slot(50)]
        pub field_f: U256, // base_slot: slot 50
        pub field_g: U256, // Auto: slot 51
    }

    let (mut storage, address) = setup_storage();
    let mut layout = Layout::__new(address);

    StorageContext::enter(&mut storage, || {
        // Set values to verify slot assignments
        layout.field_a.write(U256::ONE).unwrap();
        layout.field_b.write(U256::from(2)).unwrap();
        layout.field_c.write(U256::from(3)).unwrap();
        layout.field_d.write(U256::from(4)).unwrap();
        layout.field_e.write(U256::from(5)).unwrap();
        layout.field_f.write(U256::from(6)).unwrap();
        layout.field_g.write(U256::from(7)).unwrap();

        // Verify values
        assert_eq!(layout.field_a.read().unwrap(), U256::ONE);
        assert_eq!(layout.field_b.read().unwrap(), U256::from(2));
        assert_eq!(layout.field_c.read().unwrap(), U256::from(3));
        assert_eq!(layout.field_d.read().unwrap(), U256::from(4));
        assert_eq!(layout.field_e.read().unwrap(), U256::from(5));
        assert_eq!(layout.field_f.read().unwrap(), U256::from(6));
        assert_eq!(layout.field_g.read().unwrap(), U256::from(7));

        // Verify actual slot assignments
        assert_eq!(layout.field_a.slot(), U256::ZERO);
        assert_eq!(layout.field_b.slot(), U256::from(100));
        assert_eq!(layout.field_c.slot(), U256::from(101));
        assert_eq!(layout.field_d.slot(), U256::from(200));
        assert_eq!(layout.field_e.slot(), U256::from(201));
        assert_eq!(layout.field_f.slot(), U256::from(50));
        assert_eq!(layout.field_g.slot(), U256::from(51));

        // Verify slots module
        assert_eq!(slots::FIELD_A, U256::from(0));
        assert_eq!(slots::FIELD_B, U256::from(100));
        assert_eq!(slots::FIELD_C, U256::from(101));
        assert_eq!(slots::FIELD_D, U256::from(200));
        assert_eq!(slots::FIELD_E, U256::from(201));
        assert_eq!(slots::FIELD_F, U256::from(50));
        assert_eq!(slots::FIELD_G, U256::from(51));

        Ok::<(), tempo_precompiles::error::TempoPrecompileError>(())
    })
    .unwrap();
}

#[test]
fn test_base_slot_with_regular_slot() {
    #[contract]
    pub struct Layout {
        pub field_a: U256, // Auto: slot 0
        #[base_slot(100)]
        pub field_b: U256, // base_slot: slot 100
        pub field_c: U256, // Auto: slot 101
        #[slot(50)]
        pub field_d: U256, // Explicit: slot 50
        pub field_e: U256, // Auto: slot 102
    }

    let (mut storage, address) = setup_storage();
    let mut layout = Layout::__new(address);

    StorageContext::enter(&mut storage, || {
        layout.field_a.write(U256::ONE).unwrap();
        layout.field_b.write(U256::from(2)).unwrap();
        layout.field_c.write(U256::from(3)).unwrap();
        layout.field_d.write(U256::from(4)).unwrap();
        layout.field_e.write(U256::from(5)).unwrap();

        // Verify values
        assert_eq!(layout.field_a.read().unwrap(), U256::ONE);
        assert_eq!(layout.field_b.read().unwrap(), U256::from(2));
        assert_eq!(layout.field_c.read().unwrap(), U256::from(3));
        assert_eq!(layout.field_d.read().unwrap(), U256::from(4));
        assert_eq!(layout.field_e.read().unwrap(), U256::from(5));

        // Verify actual slot assignments
        assert_eq!(layout.field_a.slot(), U256::ZERO);
        assert_eq!(layout.field_b.slot(), U256::from(100));
        assert_eq!(layout.field_c.slot(), U256::from(101));
        assert_eq!(layout.field_d.slot(), U256::from(50));
        assert_eq!(layout.field_e.slot(), U256::from(102));

        // Verify slots module
        assert_eq!(slots::FIELD_A, U256::from(0));
        assert_eq!(slots::FIELD_B, U256::from(100));
        assert_eq!(slots::FIELD_C, U256::from(101));
        assert_eq!(slots::FIELD_D, U256::from(50));
        assert_eq!(slots::FIELD_E, U256::from(102));

        Ok::<(), tempo_precompiles::error::TempoPrecompileError>(())
    })
    .unwrap();
}

#[test]
fn test_string_literal_slots() {
    #[contract]
    pub struct Layout {
        #[slot("id")]
        pub field: U256, // slot: keccak256("id")
    }

    let (mut storage, address) = setup_storage();
    let mut layout = Layout::__new(address);

    StorageContext::enter(&mut storage, || {
        // Set value
        layout.field.write(U256::ONE).unwrap();

        // Verify value
        assert_eq!(layout.field.read().unwrap(), U256::ONE);

        // Verify slot assignment
        let slot: U256 = keccak256("id").into();
        assert_eq!(layout.field.slot(), slot);
        assert_eq!(slots::FIELD, slot);

        Ok::<(), tempo_precompiles::error::TempoPrecompileError>(())
    })
    .unwrap();
}

#[test]
#[should_panic(expected = "Storage slot collision")]
fn test_collision_same_slot() {
    // Two fields with identical slot assignments should panic in debug builds
    #[contract]
    pub struct Layout {
        #[slot(5)]
        pub field_a: U256,
        #[slot(5)]
        pub field_b: U256,
    }

    let (_, address) = setup_storage();
    let _layout = Layout::__new(address);
}

#[test]
#[should_panic(expected = "Storage slot collision")]
fn test_collision_overlapping_slots_manual() {
    // A multi-slot field overlapping with another field should panic in debug builds
    #[contract]
    pub struct Layout {
        #[slot(5)]
        pub large_field: [U256; 3], // occupies slots 5,6,7
        #[slot(6)]
        pub colliding_field: U256, // overlaps with large_field
    }

    let (_, address) = setup_storage();
    let _layout = Layout::__new(address);
}

#[test]
#[should_panic(expected = "Storage slot collision")]
fn test_collision_overlapping_slots_auto() {
    // A multi-slot field overlapping with another field should panic in debug builds
    #[contract]
    pub struct Layout {
        pub large_field: [U256; 3], // occupies slots 0,1,2
        #[slot(2)]
        pub colliding_field: U256, // overlaps with large_field
    }

    let (_, address) = setup_storage();
    let _layout = Layout::__new(address);
}

// -- USER MAPPING TESTS -------------------------------------------------------

#[test]
fn test_user_mapping_in_contract() -> eyre::Result<()> {
    #[contract]
    pub struct Layout {
        pub counter: U256,               // slot 0
        pub balances: UserMapping<U256>, // slot 1 (occupies 1 slot in layout)
        pub flag: bool,                  // slot 2
    }

    let (mut storage, address) = setup_storage();
    let mut layout = Layout::__new(address);

    StorageContext::enter(&mut storage, || {
        let (counter, user, balance) = (U256::random(), Address::random(), U256::random());

        // Write to regular fields
        layout.counter.write(counter)?;
        layout.flag.write(true)?;

        // Write to UserMapping
        layout.balances.at(user).write(balance)?;

        // Read back
        assert_eq!(layout.counter.read()?, counter);
        assert!(layout.flag.read()?);
        assert_eq!(layout.balances.at(user).read()?, balance);

        // Verify slot assignments
        assert_eq!(layout.counter.slot(), U256::ZERO);
        assert_eq!(layout.flag.slot(), U256::from(2));

        // Verify slots module
        assert_eq!(slots::COUNTER, U256::ZERO);
        assert_eq!(slots::BALANCES, U256::ONE);
        assert_eq!(slots::FLAG, U256::from(2));

        Ok(())
    })
}

#[test]
fn test_user_mapping_slot_is_direct() -> eyre::Result<()> {
    #[contract]
    pub struct Layout {
        pub balances: UserMapping<U256>,
    }

    let (mut storage, address) = setup_storage();
    let layout = Layout::__new(address);

    StorageContext::enter(&mut storage, || {
        let (user, balance) = (Address::random(), U256::random());
        layout.balances.at(user).write(balance)?;

        // Verify the slot is directly derived from address (left-padded, no hash)
        let handler = layout.balances.at(user);
        let expected_slot = U256::from_be_slice(user.as_slice()) << 96;
        assert_eq!(handler.slot(), expected_slot);

        // Verify read works with the direct slot
        assert_eq!(handler.read()?, balance);

        Ok(())
    })
}

#[test]
fn test_user_mapping_with_struct_value() -> eyre::Result<()> {
    #[contract]
    pub struct Layout {
        pub users: UserMapping<UserProfile>,
    }

    let (mut storage, address) = setup_storage();
    let layout = Layout::__new(address);

    StorageContext::enter(&mut storage, || {
        let (user, owner, balance) = (Address::random(), Address::random(), U256::random());

        // Write struct fields
        layout.users.at(user).owner.write(owner)?;
        layout.users.at(user).active.write(true)?;
        layout.users.at(user).balance.write(balance)?;

        // Read back
        assert_eq!(layout.users.at(user).owner.read()?, owner);
        assert!(layout.users.at(user).active.read()?);
        assert_eq!(layout.users.at(user).balance.read()?, balance);

        // Different user has independent storage
        let user2 = Address::random();
        assert_eq!(layout.users.at(user2).owner.read()?, Address::ZERO);
        assert!(!layout.users.at(user2).active.read()?);
        assert_eq!(layout.users.at(user2).balance.read()?, U256::ZERO);

        Ok(())
    })
}

// -- USER MAPPING COMPILE-TIME CONSTRAINTS ------------------------------------
//
// The following tests verify compile-time constraints on UserMapping.
// They are commented out because they intentionally fail to compile.

// #[test]
// fn test_multiple_user_mappings_forbidden() {
//     #[contract]
//     pub struct Layout {
//         pub balances: UserMapping<U256>,
//         pub allowances: UserMapping<U256>, // multiple `UserMapping`
//     }
// }

// #[test]
// fn test_nested_user_mapping_in_user_mapping_forbidden() {
//     #[contract]
//     pub struct Layout {
//         pub nested: UserMapping<UserMapping<U256>>, // nested `UserMapping`
//     }
// }

// #[test]
// fn test_user_mapping_in_mapping_forbidden() {
//     #[contract]
//     pub struct Layout {
//         pub nested: Mapping<Address, UserMapping<U256>>, // `UserMapping` as `Mapping` value
//     }
// }

// #[test]
// fn test_mapping_in_user_mapping_forbidden() {
//     #[contract]
//     pub struct Layout {
//         pub nested: UserMapping<Mapping<Address, U256>>, // `Mapping` as `UserMapping` value
//     }
// }
