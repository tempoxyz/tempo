//! Tests for storage layout and slot assignment.
//!
//! This module tests the #[contract] macro's ability to correctly assign storage slots,
//! including auto-assignment, explicit slots, base_slot, string literal slots, and
//! transient storage fields.

use super::*;
use alloy::primitives::B256;
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
        mixed.field_e[addr_at].write(U256::from(5)).unwrap();

        // Verify values
        assert_eq!(mixed.field_a.read().unwrap(), U256::from(1));
        assert_eq!(mixed.field_b.read().unwrap(), U256::from(2));
        assert_eq!(mixed.field_c.read().unwrap(), U256::from(3));
        assert_eq!(mixed.field_d.read().unwrap(), U256::from(4));
        assert_eq!(mixed.field_e[addr_at].read().unwrap(), U256::from(5));

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
        assert_eq!(defaults.amount.offset(), None);

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

// -- TRANSIENT STORAGE LAYOUT TESTS ---------------------------------------------------------------

#[test]
fn test_transient_independent_slot_allocation() {
    #[contract]
    pub struct Layout {
        persistent_a: U256, // persistent slot 0
        persistent_b: U256, // persistent slot 1
        #[transient]
        transient_a: U256, // transient slot 0
        #[transient]
        transient_b: U256, // transient slot 1
    }

    let (mut storage, address) = setup_storage();
    let layout = Layout::__new(address);

    StorageCtx::enter(&mut storage, || {
        // Persistent and transient counters are independent — both start from 0
        assert_eq!(slots::PERSISTENT_A, U256::ZERO);
        assert_eq!(slots::PERSISTENT_B, U256::ONE);
        assert_eq!(transient_slots::TRANSIENT_A, U256::ZERO);
        assert_eq!(transient_slots::TRANSIENT_B, U256::ONE);

        // Verify runtime slot values match
        assert_eq!(layout.persistent_a.slot(), U256::ZERO);
        assert_eq!(layout.persistent_b.slot(), U256::ONE);
        assert_eq!(layout.transient_a.slot(), U256::ZERO);
        assert_eq!(layout.transient_b.slot(), U256::ONE);

        Ok::<(), error::TempoPrecompileError>(())
    })
    .unwrap();
}

#[test]
fn test_transient_read_write_delete() {
    #[contract]
    pub struct Layout {
        #[transient]
        counter: u64,
        #[transient]
        flag: bool,
        #[transient]
        amount: U256,
    }

    let (mut storage, address) = setup_storage();
    let mut layout = Layout::__new(address);

    StorageCtx::enter(&mut storage, || {
        // Default values are zero
        assert_eq!(layout.counter.read()?, 0u64);
        assert!(!layout.flag.read()?);
        assert_eq!(layout.amount.read()?, U256::ZERO);

        // Write values
        layout.counter.write(42u64)?;
        layout.flag.write(true)?;
        layout.amount.write(U256::from(1000))?;

        // Read back
        assert_eq!(layout.counter.read()?, 42u64);
        assert!(layout.flag.read()?);
        assert_eq!(layout.amount.read()?, U256::from(1000));

        // Overwrite
        layout.counter.write(99u64)?;
        assert_eq!(layout.counter.read()?, 99u64);

        // Delete
        layout.amount.delete()?;
        assert_eq!(layout.amount.read()?, U256::ZERO);

        Ok::<(), error::TempoPrecompileError>(())
    })
    .unwrap();
}

#[test]
fn test_transient_persistent_isolation() {
    #[contract]
    pub struct Layout {
        persistent_val: U256,
        #[transient]
        transient_val: U256,
    }

    let (mut storage, address) = setup_storage();
    let mut layout = Layout::__new(address);

    let p_value = U256::from(111);
    let t_value = U256::from(222);

    StorageCtx::enter(&mut storage, || {
        // Both share slot 0 but in different storage spaces
        assert_eq!(layout.persistent_val.slot(), U256::ZERO);
        assert_eq!(layout.transient_val.slot(), U256::ZERO);

        // Write different values — no interference
        layout.persistent_val.write(p_value)?;
        layout.transient_val.write(t_value)?;
        assert_eq!(layout.persistent_val.read()?, p_value);
        assert_eq!(layout.transient_val.read()?, t_value);

        // Delete transient, persistent remains
        layout.transient_val.delete()?;
        assert_eq!(layout.persistent_val.read()?, p_value);
        assert_eq!(layout.transient_val.read()?, U256::ZERO);

        Ok::<(), error::TempoPrecompileError>(())
    })
    .unwrap();
}

#[test]
fn test_transient_cleared_between_blocks() {
    #[contract]
    pub struct Layout {
        persistent_val: U256,
        #[transient]
        transient_val: U256,
    }

    let (mut storage, address) = setup_storage();
    let mut layout = Layout::__new(address);

    let p_value = U256::from(111);
    let t_value = U256::from(222);

    // Block 1: write to both
    StorageCtx::enter(&mut storage, || {
        layout.persistent_val.write(p_value)?;
        layout.transient_val.write(t_value)?;
        assert_eq!(layout.persistent_val.read()?, p_value);
        assert_eq!(layout.transient_val.read()?, t_value);
        Ok::<(), error::TempoPrecompileError>(())
    })
    .unwrap();

    // Simulate new block
    storage.clear_transient();

    // Block 2: transient is cleared, persistent remains
    StorageCtx::enter(&mut storage, || {
        assert_eq!(layout.persistent_val.read()?, p_value);
        assert_eq!(layout.transient_val.read()?, U256::ZERO);
        Ok::<(), error::TempoPrecompileError>(())
    })
    .unwrap();
}

#[test]
fn test_transient_mapping() {
    #[contract]
    pub struct Layout {
        #[transient]
        balances: Mapping<Address, U256>,
    }

    let (mut storage, address) = setup_storage();
    let mut layout = Layout::__new(address);
    let user = Address::random();

    StorageCtx::enter(&mut storage, || {
        // Default is zero
        assert_eq!(layout.balances[user].read()?, U256::ZERO);

        // Write and read
        layout.balances[user].write(U256::from(500))?;
        assert_eq!(layout.balances[user].read()?, U256::from(500));

        // Different key is independent
        let user2 = Address::random();
        assert_eq!(layout.balances[user2].read()?, U256::ZERO);

        Ok::<(), error::TempoPrecompileError>(())
    })
    .unwrap();

    // Verify cleared between blocks
    storage.clear_transient();
    StorageCtx::enter(&mut storage, || {
        assert_eq!(layout.balances[user].read()?, U256::ZERO);
        Ok::<(), error::TempoPrecompileError>(())
    })
    .unwrap();
}

#[test]
fn test_transient_nested_mapping() {
    #[contract]
    pub struct Layout {
        #[transient]
        allowances: Mapping<Address, Mapping<Address, U256>>,
    }

    let (mut storage, address) = setup_storage();
    let mut layout = Layout::__new(address);
    let owner = Address::random();
    let spender = Address::random();

    StorageCtx::enter(&mut storage, || {
        // Default
        assert_eq!(layout.allowances[owner][spender].read()?, U256::ZERO);

        // Write and read through nested mapping
        layout.allowances[owner][spender].write(U256::from(1000))?;
        assert_eq!(layout.allowances[owner][spender].read()?, U256::from(1000));

        // Different spender is independent
        let spender2 = Address::random();
        assert_eq!(layout.allowances[owner][spender2].read()?, U256::ZERO);

        // Different owner is independent
        let owner2 = Address::random();
        assert_eq!(layout.allowances[owner2][spender].read()?, U256::ZERO);

        Ok::<(), error::TempoPrecompileError>(())
    })
    .unwrap();

    // Cleared between blocks
    storage.clear_transient();
    StorageCtx::enter(&mut storage, || {
        assert_eq!(layout.allowances[owner][spender].read()?, U256::ZERO);
        Ok::<(), error::TempoPrecompileError>(())
    })
    .unwrap();
}

#[test]
fn test_transient_with_explicit_slots() {
    #[contract]
    pub struct Layout {
        persistent_a: U256,
        #[transient]
        #[slot(5)]
        transient_a: U256,
        #[transient]
        transient_b: U256, // auto: transient slot 0
        #[transient]
        #[slot(10)]
        transient_c: Mapping<Address, U256>,
    }

    let (mut storage, address) = setup_storage();
    let layout = Layout::__new(address);

    StorageCtx::enter(&mut storage, || {
        // Persistent uses persistent counter
        assert_eq!(slots::PERSISTENT_A, U256::ZERO);

        // Transient slots: explicit and auto are independent
        assert_eq!(transient_slots::TRANSIENT_A, U256::from(5));
        assert_eq!(transient_slots::TRANSIENT_B, U256::ZERO);
        assert_eq!(transient_slots::TRANSIENT_C, U256::from(10));

        assert_eq!(layout.transient_a.slot(), U256::from(5));
        assert_eq!(layout.transient_b.slot(), U256::ZERO);
        assert_eq!(layout.transient_c.slot(), U256::from(10));

        Ok::<(), error::TempoPrecompileError>(())
    })
    .unwrap();
}

#[test]
fn test_transient_packing() {
    #[contract]
    pub struct Layout {
        #[transient]
        flag: bool, // transient slot 0, offset 0 (1 byte)
        #[transient]
        count: u64, // transient slot 0, offset 1 (8 bytes)
        #[transient]
        addr: Address, // transient slot 0, offset 9 (20 bytes)
    }

    let (mut storage, address) = setup_storage();
    let mut layout = Layout::__new(address);

    StorageCtx::enter(&mut storage, || {
        // All packed into transient slot 0
        assert_eq!(layout.flag.slot(), U256::ZERO);
        assert_eq!(layout.count.slot(), U256::ZERO);
        assert_eq!(layout.addr.slot(), U256::ZERO);

        // Offsets within the slot
        assert_eq!(layout.flag.offset(), Some(0));
        assert_eq!(layout.count.offset(), Some(1));
        assert_eq!(layout.addr.offset(), Some(9));

        // Write and read packed transient fields
        let test_addr = Address::random();
        layout.flag.write(true)?;
        layout.count.write(42u64)?;
        layout.addr.write(test_addr)?;

        assert!(layout.flag.read()?);
        assert_eq!(layout.count.read()?, 42u64);
        assert_eq!(layout.addr.read()?, test_addr);

        Ok::<(), error::TempoPrecompileError>(())
    })
    .unwrap();

    // Cleared between blocks
    storage.clear_transient();
    StorageCtx::enter(&mut storage, || {
        assert!(!layout.flag.read()?);
        assert_eq!(layout.count.read()?, 0u64);
        assert_eq!(layout.addr.read()?, Address::ZERO);
        Ok::<(), error::TempoPrecompileError>(())
    })
    .unwrap();
}

#[test]
fn test_transient_packed_fields_preserve_neighbors() {
    #[contract]
    pub struct Layout {
        #[transient]
        a: u64, // transient slot 0, offset 0
        #[transient]
        b: u64, // transient slot 0, offset 8
        #[transient]
        c: bool, // transient slot 0, offset 16
    }

    let (mut storage, address) = setup_storage();
    let mut layout = Layout::__new(address);

    StorageCtx::enter(&mut storage, || {
        // Write all three packed fields
        layout.a.write(111u64)?;
        layout.b.write(222u64)?;
        layout.c.write(true)?;

        // Verify all values preserved after writing neighbors
        assert_eq!(layout.a.read()?, 111u64);
        assert_eq!(layout.b.read()?, 222u64);
        assert!(layout.c.read()?);

        // Overwrite middle field, verify neighbors preserved
        layout.b.write(333u64)?;
        assert_eq!(layout.a.read()?, 111u64);
        assert_eq!(layout.b.read()?, 333u64);
        assert!(layout.c.read()?);

        // Delete first field, verify neighbors preserved
        layout.a.delete()?;
        assert_eq!(layout.a.read()?, 0u64);
        assert_eq!(layout.b.read()?, 333u64);
        assert!(layout.c.read()?);

        Ok::<(), error::TempoPrecompileError>(())
    })
    .unwrap();
}

#[test]
fn test_mixed_persistent_transient_contract() {
    /// Mirrors real-world usage like AccountKeychain
    #[contract]
    pub struct Layout {
        // Persistent fields
        data: Mapping<Address, Mapping<Address, U256>>,
        limits: Mapping<B256, Mapping<Address, U256>>,

        // Transient fields
        #[transient]
        current_key: Address,
        #[transient]
        origin: Address,
    }

    let (mut storage, address) = setup_storage();
    let mut layout = Layout::__new(address);
    let user = Address::random();
    let spender = Address::random();
    let token = Address::random();
    let key = B256::random();

    StorageCtx::enter(&mut storage, || {
        // Persistent: nested mapping read/write
        layout.data[user][spender].write(U256::from(500))?;
        assert_eq!(layout.data[user][spender].read()?, U256::from(500));

        layout.limits[key][token].write(U256::from(1000))?;
        assert_eq!(layout.limits[key][token].read()?, U256::from(1000));

        // Transient: read/write
        layout.current_key.write(user)?;
        layout.origin.write(spender)?;
        assert_eq!(layout.current_key.read()?, user);
        assert_eq!(layout.origin.read()?, spender);

        Ok::<(), error::TempoPrecompileError>(())
    })
    .unwrap();

    // Simulate new block
    storage.clear_transient();

    StorageCtx::enter(&mut storage, || {
        // Persistent data survives
        assert_eq!(layout.data[user][spender].read()?, U256::from(500));
        assert_eq!(layout.limits[key][token].read()?, U256::from(1000));

        // Transient data is cleared
        assert_eq!(layout.current_key.read()?, Address::ZERO);
        assert_eq!(layout.origin.read()?, Address::ZERO);

        Ok::<(), error::TempoPrecompileError>(())
    })
    .unwrap();
}

#[test]
fn test_transient_mapping_with_persistent_mapping_no_interference() {
    #[contract]
    pub struct Layout {
        persistent_map: Mapping<Address, U256>,
        #[transient]
        transient_map: Mapping<Address, U256>,
    }

    let (mut storage, address) = setup_storage();
    let mut layout = Layout::__new(address);
    let key = Address::random();

    StorageCtx::enter(&mut storage, || {
        // Both share slot 0 in their respective storage spaces
        assert_eq!(layout.persistent_map.slot(), U256::ZERO);
        assert_eq!(layout.transient_map.slot(), U256::ZERO);

        // Write different values to same key in both spaces
        layout.persistent_map[key].write(U256::from(100))?;
        layout.transient_map[key].write(U256::from(200))?;

        assert_eq!(layout.persistent_map[key].read()?, U256::from(100));
        assert_eq!(layout.transient_map[key].read()?, U256::from(200));

        Ok::<(), error::TempoPrecompileError>(())
    })
    .unwrap();

    // Simulate new block
    storage.clear_transient();

    StorageCtx::enter(&mut storage, || {
        assert_eq!(layout.persistent_map[key].read()?, U256::from(100));
        assert_eq!(layout.transient_map[key].read()?, U256::ZERO);
        Ok::<(), error::TempoPrecompileError>(())
    })
    .unwrap();
}
