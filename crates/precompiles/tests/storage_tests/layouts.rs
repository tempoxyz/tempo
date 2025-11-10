//! Tests for storage layout and slot assignment.
//!
//! This module tests the #[contract] macro's ability to correctly assign storage slots,
//! including auto-assignment, explicit slots, base_slot, and string literal slots.

use super::*;

#[test]
fn test_mixed_slot_allocation() {
    #[contract]
    pub struct Layout {
        pub field_a: U256, // Auto: slot 0
        #[slot(5)]
        pub field_b: U256, // Explicit: slot 5 (decimal)
        pub field_c: U256, // Auto: slot 1
        #[slot(0x10)]
        pub field_d: U256, // Explicit: slot 16 (hex)
    }

    let mut s = setup_storage();
    let mut mixed = Layout::_new(s.address, s.storage());

    // Set all fields
    mixed.sstore_field_a(U256::from(100)).unwrap();
    mixed.sstore_field_b(U256::from(200)).unwrap();
    mixed.sstore_field_c(U256::from(300)).unwrap();
    mixed.sstore_field_d(U256::from(400)).unwrap();

    // Verify values
    assert_eq!(mixed.sload_field_a().unwrap(), U256::from(100));
    assert_eq!(mixed.sload_field_b().unwrap(), U256::from(200));
    assert_eq!(mixed.sload_field_c().unwrap(), U256::from(300));
    assert_eq!(mixed.sload_field_d().unwrap(), U256::from(400));

    // Verify actual slot assignments
    assert_eq!(
        s.storage.sload(s.address, U256::from(0)),
        Ok(U256::from(100))
    ); // field_a
    assert_eq!(
        s.storage.sload(s.address, U256::from(5)),
        Ok(U256::from(200))
    ); // field_b
    assert_eq!(s.storage.sload(s.address, U256::ONE), Ok(U256::from(300))); // field_c
    assert_eq!(
        s.storage.sload(s.address, U256::from(0x10)),
        Ok(U256::from(400))
    ); // field_d (hex slot)
}

#[test]
fn test_default_values() {
    #[contract]
    pub struct Layout {
        pub counter: u64,
        pub flag: bool,
        pub amount: U256,
    }

    let mut s = setup_storage();
    let mut defaults = Layout::_new(s.address, s.storage());

    // Reading uninitialized storage returns zero/default
    assert_eq!(defaults.sload_counter().unwrap(), 0);
    assert!(!defaults.sload_flag().unwrap());
    assert_eq!(defaults.sload_amount().unwrap(), U256::ZERO);
}

#[test]
fn test_slots_module_generation() {
    #[contract]
    pub struct Layout {
        pub field_a: U256, // Auto: slot 0
        #[slot(5)]
        pub field_b: U256, // Explicit: slot 5
        pub field_c: U256, // Auto: slot 1
        #[slot(10)]
        pub mapping_field: Mapping<Address, U256>, // Explicit: slot 10
    }

    // Verify the slots module was generated with correct values
    assert_eq!(slots::FIELD_A, U256::from(0));
    assert_eq!(slots::FIELD_B, U256::from(5));
    assert_eq!(slots::FIELD_C, U256::ONE);
    assert_eq!(slots::MAPPING_FIELD, U256::from(10));
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

    let mut s = setup_storage();
    let mut layout = Layout::_new(s.address, s.storage());

    // Set values to verify slot assignments
    layout.sstore_field_a(U256::ONE).unwrap();
    layout.sstore_field_b(U256::from(2)).unwrap();
    layout.sstore_field_c(U256::from(3)).unwrap();
    layout.sstore_field_d(U256::from(4)).unwrap();
    layout.sstore_field_e(U256::from(5)).unwrap();
    layout.sstore_field_f(U256::from(6)).unwrap();
    layout.sstore_field_g(U256::from(7)).unwrap();

    // Verify actual slot assignments
    assert_eq!(s.storage.sload(s.address, U256::from(0)), Ok(U256::ONE)); // field_a
    assert_eq!(
        s.storage.sload(s.address, U256::from(100)),
        Ok(U256::from(2))
    ); // field_b
    assert_eq!(
        s.storage.sload(s.address, U256::from(101)),
        Ok(U256::from(3))
    ); // field_c
    assert_eq!(
        s.storage.sload(s.address, U256::from(200)),
        Ok(U256::from(4))
    ); // field_d
    assert_eq!(
        s.storage.sload(s.address, U256::from(201)),
        Ok(U256::from(5))
    ); // field_e
    assert_eq!(
        s.storage.sload(s.address, U256::from(50)),
        Ok(U256::from(6))
    ); // field_f
    assert_eq!(
        s.storage.sload(s.address, U256::from(51)),
        Ok(U256::from(7))
    ); // field_g

    // Verify slots module
    assert_eq!(slots::FIELD_A, U256::from(0));
    assert_eq!(slots::FIELD_B, U256::from(100));
    assert_eq!(slots::FIELD_C, U256::from(101));
    assert_eq!(slots::FIELD_D, U256::from(200));
    assert_eq!(slots::FIELD_E, U256::from(201));
    assert_eq!(slots::FIELD_F, U256::from(50));
    assert_eq!(slots::FIELD_G, U256::from(51));
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

    let mut s = setup_storage();
    let mut layout = Layout::_new(s.address, s.storage());

    layout.sstore_field_a(U256::ONE).unwrap();
    layout.sstore_field_b(U256::from(2)).unwrap();
    layout.sstore_field_c(U256::from(3)).unwrap();
    layout.sstore_field_d(U256::from(4)).unwrap();
    layout.sstore_field_e(U256::from(5)).unwrap();

    // Verify slot assignments
    assert_eq!(s.storage.sload(s.address, U256::from(0)), Ok(U256::ONE)); // field_a
    assert_eq!(
        s.storage.sload(s.address, U256::from(100)),
        Ok(U256::from(2))
    ); // field_b
    assert_eq!(
        s.storage.sload(s.address, U256::from(101)),
        Ok(U256::from(3))
    ); // field_c
    assert_eq!(
        s.storage.sload(s.address, U256::from(50)),
        Ok(U256::from(4))
    ); // field_d
    assert_eq!(
        s.storage.sload(s.address, U256::from(102)),
        Ok(U256::from(5))
    ); // field_e

    // Verify slots module
    assert_eq!(slots::FIELD_A, U256::from(0));
    assert_eq!(slots::FIELD_B, U256::from(100));
    assert_eq!(slots::FIELD_C, U256::from(101));
    assert_eq!(slots::FIELD_D, U256::from(50));
    assert_eq!(slots::FIELD_E, U256::from(102));
}

#[test]
fn test_string_literal_slots() {
    #[contract]
    pub struct Layout {
        #[slot("id")]
        pub field: U256, // slot: keccak256("id")
    }

    let mut s = setup_storage();
    let mut layout = Layout::_new(s.address, s.storage());

    // Set value
    layout.sstore_field(U256::ONE).unwrap();

    // Verify
    let slot: U256 = keccak256("id").into();
    assert_eq!(s.storage.sload(s.address, slot), Ok(U256::ONE)); // field
    assert_eq!(slots::FIELD, slot);
}

#[test]
fn test_slot_id_naming_matches_actual_slots() {
    // Test SlotId type naming: manual slots use SlotN, auto-assigned use SlotForFieldN
    #[contract]
    pub struct Layout {
        pub field_a: U256, // auto → slot 0
        #[slot(100)]
        pub field_b: U256, // explicit → slot 100
        pub field_c: U256, // auto → slot 1
        #[base_slot(200)]
        pub field_d: U256, // base → slot 200
        pub field_e: U256, // auto → slot 201
        #[slot(0x10)]
        pub field_f: U256, // hex → slot 16
    }

    // Verify slot assignments via the slots module constants
    assert_eq!(slots::FIELD_A, U256::from(0));
    assert_eq!(slots::FIELD_B, U256::from(100));
    assert_eq!(slots::FIELD_C, U256::ONE);
    assert_eq!(slots::FIELD_D, U256::from(200));
    assert_eq!(slots::FIELD_E, U256::from(201));
    assert_eq!(slots::FIELD_F, U256::from(16));

    // Verify the SlotId types exist and have correct SLOT values
    use tempo_precompiles::storage::SlotId;
    assert_eq!(<FieldASlot as SlotId>::SLOT, U256::from(0)); // field_a (auto)
    assert_eq!(<FieldBSlot as SlotId>::SLOT, U256::from(100)); // field_b (manual)
    assert_eq!(<FieldCSlot as SlotId>::SLOT, U256::ONE); // field_c (auto)
    assert_eq!(<FieldDSlot as SlotId>::SLOT, U256::from(200)); // field_d (manual)
    assert_eq!(<FieldESlot as SlotId>::SLOT, U256::from(201)); // field_e (auto)
    assert_eq!(<FieldFSlot as SlotId>::SLOT, U256::from(16)); // field_f (manual)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Property test for mixed slot allocation with random values
    #[test]
    fn proptest_mixed_slot_allocation(
        val_a in arb_u256(),
        val_b in arb_u256(),
        val_c in arb_u256(),
        val_d in arb_u256(),
    ) {
        #[contract]
        pub struct Layout {
            pub field_a: U256, // Auto: slot 0
            #[slot(5)]
            pub field_b: U256, // Explicit: slot 5
            pub field_c: U256, // Auto: slot 1
            #[slot(0x10)]
            pub field_d: U256, // Explicit: slot 16 (hex)
        }

        let mut s = setup_storage();

        {
            let mut layout = Layout::_new(s.address, s.storage());

            // Store random values
            layout.sstore_field_a(val_a)?;
            layout.sstore_field_b(val_b)?;
            layout.sstore_field_c(val_c)?;
            layout.sstore_field_d(val_d)?;

            // Roundtrip property: verify getters return stored values
            prop_assert_eq!(layout.sload_field_a()?, val_a);
            prop_assert_eq!(layout.sload_field_b()?, val_b);
            prop_assert_eq!(layout.sload_field_c()?, val_c);
            prop_assert_eq!(layout.sload_field_d()?, val_d);
        }

        // Isolation property: verify actual slot assignments
        prop_assert_eq!(s.storage.sload(s.address, U256::from(0))?, val_a); // field_a
        prop_assert_eq!(s.storage.sload(s.address, U256::from(5))?, val_b); // field_b
        prop_assert_eq!(s.storage.sload(s.address, U256::ONE)?, val_c); // field_c
        prop_assert_eq!(s.storage.sload(s.address, U256::from(0x10))?, val_d); // field_d
    }

    /// Property test for base_slot functionality
    #[test]
    fn proptest_base_slots(
        val_a in arb_u256(),
        val_b in arb_u256(),
        val_c in arb_u256(),
        val_d in arb_u256(),
        val_e in arb_u256(),
    ) {
        #[contract]
        pub struct Layout {
            pub field_a: U256, // Auto: slot 0
            #[base_slot(100)]
            pub field_b: U256, // base_slot: slot 100, counter -> 101
            pub field_c: U256, // Auto: slot 101
            #[base_slot(200)]
            pub field_d: U256, // base_slot: slot 200, counter -> 201
            pub field_e: U256, // Auto: slot 201
        }

        let mut s = setup_storage();

        {
            let mut layout = Layout::_new(s.address, s.storage());

            // Store random values
            layout.sstore_field_a(val_a)?;
            layout.sstore_field_b(val_b)?;
            layout.sstore_field_c(val_c)?;
            layout.sstore_field_d(val_d)?;
            layout.sstore_field_e(val_e)?;

            // Roundtrip property
            prop_assert_eq!(layout.sload_field_a()?, val_a);
            prop_assert_eq!(layout.sload_field_b()?, val_b);
            prop_assert_eq!(layout.sload_field_c()?, val_c);
            prop_assert_eq!(layout.sload_field_d()?, val_d);
            prop_assert_eq!(layout.sload_field_e()?, val_e);
        }

        // Isolation property: verify slot assignments
        prop_assert_eq!(s.storage.sload(s.address, U256::from(0))?, val_a); // field_a
        prop_assert_eq!(s.storage.sload(s.address, U256::from(100))?, val_b); // field_b
        prop_assert_eq!(s.storage.sload(s.address, U256::from(101))?, val_c); // field_c
        prop_assert_eq!(s.storage.sload(s.address, U256::from(200))?, val_d); // field_d
        prop_assert_eq!(s.storage.sload(s.address, U256::from(201))?, val_e); // field_e
    }
}
