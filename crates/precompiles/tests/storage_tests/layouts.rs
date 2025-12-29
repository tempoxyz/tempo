//! Tests for storage layout and slot assignment.
//!
//! This module tests the #[contract] macro's ability to correctly assign storage slots,
//! including auto-assignment, explicit slots, base_slot, and string literal slots.

use super::*;
use tempo_precompiles::storage::Mapping;

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

    StorageCtx::enter(&mut storage, || {
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

    StorageCtx::enter(&mut storage, || {
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

    StorageCtx::enter(&mut storage, || {
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

    StorageCtx::enter(&mut storage, || {
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

    StorageCtx::enter(&mut storage, || {
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

#[test]
fn test_no_collision_when_using_manual_slot_with_packing() {
    #[contract]
    pub struct Layout {
        a: u128, // assigned to slot 0 with 0 offset
        b: u128, // assigned to slot 0 with 16 offset
        c: u128, // assigned to slot 1 with 0 offset
        #[slot(100)]
        d: U256, // manually assigned to slot 100
        e: u128, // assigned to slot 1 with 16 offset.
    }

    let (_, address) = setup_storage();
    let _layout = Layout::__new(address);
    assert_eq!(slots::A, U256::ZERO);
    assert_eq!(slots::B, U256::ZERO);
    assert_eq!(slots::A_OFFSET, 0);
    assert_eq!(slots::B_OFFSET, 16);

    assert_eq!(slots::C, U256::ONE);
    assert_eq!(slots::E, U256::ONE);
    assert_eq!(slots::C_OFFSET, 0);
    assert_eq!(slots::E_OFFSET, 16);

    assert_eq!(slots::D, U256::from(100));
}

#[test]
#[should_panic(
    expected = "Storage slot collision: field `c` (slot 1, offset 0) overlaps with field `d` (slot 1, offset 0)"
)]
fn test_collision_when_using_base_slot() {
    #[contract]
    pub struct Layout {
        a: u128, // assigned to slot 0 with 0 offset
        b: u128, // assigned to slot 0 with 16 offset
        c: u128, // assigned to slot 1 with 0 offset
        #[base_slot(1)]
        d: u128, // manually assigned to slot 1
        e: u128, // assigned to slot 1 with 16 offset.
    }

    let (_, address) = setup_storage();
    let _layout = Layout::__new(address);
}
