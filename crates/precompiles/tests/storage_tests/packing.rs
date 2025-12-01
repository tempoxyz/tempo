//! Tests for slot packing rules and field packing correctness.
//!
//! This module tests the Storable derive macro's implementation of storage packing,
//! verifying that fields are correctly packed into slots according to Solidity's rules.

use tempo_precompiles::storage::{Layout, packing::gen_slot_from};

use super::*;

// Rule 1: Structs Always Start New Slots
#[derive(Default, Debug, Clone, PartialEq, Eq, Storable)]
struct Rule1Test {
    pub a: u8,             // 1 byte    (slot 0, offset 0)
    pub nested: PackedTwo, // 28 bytes  (slot 1, offset 0)
}

fn arb_rule1_test() -> impl Strategy<Value = Rule1Test> {
    (any::<u8>(), arb_packed_two()).prop_map(|(a, nested)| Rule1Test { a, nested })
}

// Rule 2: Value Types Pack Sequentially
#[derive(Default, Debug, Clone, PartialEq, Eq, Storable)]
struct Rule2Test {
    pub a: u8,  // 1 byte  (slot 0, offset 0)
    pub b: u16, // 2 bytes (slot 0, offset 1)
    pub c: u32, // 4 bytes (slot 0, offset 3)
    pub d: u64, // 8 bytes (slot 0, offset 7)
}

fn arb_rule2_test() -> impl Strategy<Value = Rule2Test> {
    (any::<u8>(), any::<u16>(), any::<u32>(), any::<u64>()).prop_map(|(a, b, c, d)| Rule2Test {
        a,
        b,
        c,
        d,
    })
}

// Rule 3: Overflow moves to next slot (full slot case)
#[derive(Default, Debug, Clone, PartialEq, Eq, Storable)]
struct Rule3TestFull {
    pub a: U256, // 32 bytes (slot 0)
    pub b: u8,   // 1 byte   (slot 1, offset 0)
}

fn arb_rule3_test_full() -> impl Strategy<Value = Rule3TestFull> {
    (arb_u256(), any::<u8>()).prop_map(|(a, b)| Rule3TestFull { a, b })
}

// Rule 3: Overflow moves to next slot (partial slot case)
#[derive(Default, Debug, Clone, PartialEq, Eq, Storable)]
struct Rule3TestPartial {
    pub a: u128, // 16 bytes (slot 0, offset 0)
    pub b: u128, // 16 bytes (slot 0, offset 16)
    pub c: u8,   // 1 byte   (slot 1, offset 0)
}

fn arb_rule3_test_partial() -> impl Strategy<Value = Rule3TestPartial> {
    (any::<u128>(), any::<u128>(), any::<u8>()).prop_map(|(a, b, c)| Rule3TestPartial { a, b, c })
}

// Rule 4: Fields after structs start new slots
#[derive(Default, Debug, Clone, PartialEq, Eq, Storable)]
struct Rule4Test {
    pub before: u8,        // 1 byte    (slot 0, offset 0)
    pub nested: PackedTwo, // 28 bytes  (slot 1, offset 0)
    pub after: u8,         // 1 byte    (slot 2, offset 0)
}

fn arb_rule4_test() -> impl Strategy<Value = Rule4Test> {
    (any::<u8>(), arb_packed_two(), any::<u8>()).prop_map(|(before, nested, after)| Rule4Test {
        before,
        nested,
        after,
    })
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Storable)]
struct PackedTwo {
    pub addr: Address, // 20 bytes   (slot 0)
    pub count: u64,    // 8 bytes    (slot 0)
}

fn arb_packed_two() -> impl Strategy<Value = PackedTwo> {
    (arb_address(), any::<u64>()).prop_map(|(addr, count)| PackedTwo { addr, count })
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Storable)]
struct PackedThree {
    pub a: u64, // 8 bytes (slot 0)
    pub b: u64, // 8 bytes (slot 0)
    pub c: u64, // 8 bytes (slot 0)
}

fn arb_packed_three() -> impl Strategy<Value = PackedThree> {
    (any::<u64>(), any::<u64>(), any::<u64>()).prop_map(|(a, b, c)| PackedThree { a, b, c })
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Storable)]
struct PartiallyPacked {
    pub addr1: Address, // 20 bytes (slot 0)
    pub flag: bool,     // 1 byte   (slot 0)
    pub value: U256,    // 32 bytes (slot 1)
    pub addr2: Address, // 20 bytes (slot 2)
}

fn arb_partially_packed() -> impl Strategy<Value = PartiallyPacked> {
    (arb_address(), any::<bool>(), arb_u256(), arb_address()).prop_map(
        |(addr1, flag, value, addr2)| PartiallyPacked {
            addr1,
            flag,
            value,
            addr2,
        },
    )
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Storable)]
struct WithNestedStruct {
    pub id: i16,           // 2 bytes    (slot 0)
    pub nested: PackedTwo, // 28 bytes   (slot 1)
    pub active: bool,      // 1 byte     (slot 2)
    pub value: U256,       // 32 bytes   (slot 3)
}

fn arb_with_nested_struct() -> impl Strategy<Value = WithNestedStruct> {
    (any::<i16>(), arb_packed_two(), any::<bool>(), arb_u256()).prop_map(
        |(id, nested, active, value)| WithNestedStruct {
            id,
            nested,
            active,
            value,
        },
    )
}

// Multi-level nesting
#[derive(Default, Debug, Clone, PartialEq, Eq, Storable)]
struct DeepNested {
    pub flag: bool,               // 1 byte     (slot 0)
    pub nested: WithNestedStruct, // 4 slots    (slots 1-5)
    pub counter: u64,             // 8 bytes    (slot 6)
}

fn arb_deep_nested() -> impl Strategy<Value = DeepNested> {
    (any::<bool>(), arb_with_nested_struct(), any::<u64>()).prop_map(|(flag, nested, counter)| {
        DeepNested {
            flag,
            nested,
            counter,
        }
    })
}

// Struct to test slot boundary at exactly 32 bytes
#[derive(Storable, Debug, PartialEq)]
struct ExactFit {
    pub data: U256,
    pub flag: bool,
}

#[test]
fn test_slot_and_byte_counts() {
    // Rule verification
    Rule1Test::validate_layout();
    assert_eq!(Rule1Test::LAYOUT, Layout::Slots(2));

    Rule2Test::validate_layout();
    assert_eq!(Rule2Test::LAYOUT, Layout::Slots(1));

    Rule3TestFull::validate_layout();
    assert_eq!(Rule3TestFull::LAYOUT, Layout::Slots(2));

    Rule3TestPartial::validate_layout();
    assert_eq!(Rule3TestPartial::LAYOUT, Layout::Slots(2));

    Rule4Test::validate_layout();
    assert_eq!(Rule4Test::LAYOUT, Layout::Slots(3));

    // Basic packed types
    PackedTwo::validate_layout();
    assert_eq!(PackedTwo::LAYOUT, Layout::Slots(1));

    // Partially packed types
    PartiallyPacked::validate_layout();
    assert_eq!(PartiallyPacked::LAYOUT, Layout::Slots(3));

    // Nested structs
    WithNestedStruct::validate_layout();
    assert_eq!(WithNestedStruct::LAYOUT, Layout::Slots(4));

    // Multi-level nesting
    DeepNested::validate_layout();
    assert_eq!(DeepNested::LAYOUT, Layout::Slots(6));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn test_structs_always_start_new_slots(
        value1 in arb_rule1_test(),
        value2 in arb_rule1_test(),
        base_slot in arb_u256().prop_map(|v| {
            // Rule1Test uses 2 slots, max offset is 2000, prevent overflow
            v % (U256::MAX - U256::from(2000 + 2))
        })
    ) {
        let mut storage = setup_storage();

        test_store_load::<Rule1Test, _, 2>(&mut storage, base_slot, &value1)?;
        test_update::<Rule1Test, _, 2>(&mut storage, base_slot + U256::from(1000), &value1, &value2)?;
        test_delete::<Rule1Test, _, 2>(&mut storage, base_slot + U256::from(2000), &value1)?;
    }

    #[test]
    fn test_value_types_pack_sequentially(
        value1 in arb_rule2_test(),
        value2 in arb_rule2_test(),
        base_slot in arb_u256().prop_map(|v| {
            // Rule2Test uses 1 slot, max offset is 2000, prevent overflow
            v % (U256::MAX - U256::from(2000 + 1))
        })
    ) {
        let mut storage = setup_storage();

        test_store_load::<Rule2Test, _, 1>(&mut storage, base_slot, &value1)?;
        test_update::<Rule2Test, _, 1>(&mut storage, base_slot + U256::from(1000), &value1, &value2)?;
        test_delete::<Rule2Test, _, 1>(&mut storage, base_slot + U256::from(2000), &value1)?;
    }

    #[test]
    fn test_overflow_full_slot(
        value1 in arb_rule3_test_full(),
        value2 in arb_rule3_test_full(),
        base_slot in arb_u256().prop_map(|v| {
            // Rule3TestFull uses 2 slots, max offset is 2000, prevent overflow
            v % (U256::MAX - U256::from(2000 + 2))
        })
    ) {
        let mut storage = setup_storage();

        test_store_load::<Rule3TestFull, _, 2>(&mut storage, base_slot, &value1)?;
        test_update::<Rule3TestFull, _, 2>(&mut storage, base_slot + U256::from(1000), &value1, &value2)?;
        test_delete::<Rule3TestFull, _, 2>(&mut storage, base_slot + U256::from(2000), &value1)?;
    }

    #[test]
    fn test_overflow_partial_slot(
        value1 in arb_rule3_test_partial(),
        value2 in arb_rule3_test_partial(),
        base_slot in arb_u256().prop_map(|v| {
            // Rule3TestPartial uses 2 slots, max offset is 2000, prevent overflow
            v % (U256::MAX - U256::from(2000 + 2))
        })
    ) {
        let mut storage = setup_storage();

        test_store_load::<Rule3TestPartial, _, 2>(&mut storage, base_slot, &value1)?;
        test_update::<Rule3TestPartial, _, 2>(&mut storage, base_slot + U256::from(1000), &value1, &value2)?;
        test_delete::<Rule3TestPartial, _, 2>(&mut storage, base_slot + U256::from(2000), &value1)?;
    }

    #[test]
    fn test_fields_after_structs_start_new_slots(
        value1 in arb_rule4_test(),
        value2 in arb_rule4_test(),
        base_slot in arb_u256().prop_map(|v| {
            // Rule4Test uses 3 slots, max offset is 2000, prevent overflow
            v % (U256::MAX - U256::from(2000 + 3))
        })
    ) {
        let mut storage = setup_storage();

        test_store_load::<Rule4Test, _, 3>(&mut storage, base_slot, &value1)?;
        test_update::<Rule4Test, _, 3>(&mut storage, base_slot + U256::from(1000), &value1, &value2)?;
        test_delete::<Rule4Test, _, 3>(&mut storage, base_slot + U256::from(2000), &value1)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn test_basic_packing_packed_two(
        value1 in arb_packed_two(),
        value2 in arb_packed_two(),
        base_slot in arb_u256().prop_map(|v| {
            // PackedTwo uses 1 slot, max offset is 2000, prevent overflow
            v % (U256::MAX - U256::from(2000 + 1))
        })
    ) {
        let mut storage = setup_storage();

        test_store_load::<PackedTwo, _, 1>(&mut storage, base_slot, &value1)?;
        test_update::<PackedTwo, _, 1>(&mut storage, base_slot + U256::from(1000), &value1, &value2)?;
        test_delete::<PackedTwo, _, 1>(&mut storage, base_slot + U256::from(2000), &value1)?;
    }

    #[test]
    fn test_basic_packing_packed_three(
        value1 in arb_packed_three(),
        value2 in arb_packed_three(),
        base_slot in arb_u256().prop_map(|v| {
            // PackedThree uses 1 slot, max offset is 2000, prevent overflow
            v % (U256::MAX - U256::from(2000 + 1))
        })
    ) {
        let mut storage = setup_storage();

        test_store_load::<PackedThree, _, 1>(&mut storage, base_slot, &value1)?;
        test_update::<PackedThree, _, 1>(&mut storage, base_slot + U256::from(1000), &value1, &value2)?;
        test_delete::<PackedThree, _, 1>(&mut storage, base_slot + U256::from(2000), &value1)?;
    }

    #[test]
    fn test_basic_packing_partially_packed(
        value1 in arb_partially_packed(),
        value2 in arb_partially_packed(),
        base_slot in arb_u256().prop_map(|v| {
            // PartiallyPacked uses 3 slots, max offset is 2000, prevent overflow
            v % (U256::MAX - U256::from(2000 + 3))
        })
    ) {
        let mut storage = setup_storage();

        test_store_load::<PartiallyPacked, _, 3>(&mut storage, base_slot, &value1)?;
        test_update::<PartiallyPacked, _, 3>(&mut storage, base_slot + U256::from(1000), &value1, &value2)?;
        test_delete::<PartiallyPacked, _, 3>(&mut storage, base_slot + U256::from(2000), &value1)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn test_nested_struct_single_level(
        value1 in arb_with_nested_struct(),
        value2 in arb_with_nested_struct(),
        base_slot in arb_u256().prop_map(|v| {
            // WithNestedStruct uses 4 slots, max offset is 2000, prevent overflow
            v % (U256::MAX - U256::from(2000 + 4))
        })
    ) {
        let mut storage = setup_storage();

        test_store_load::<WithNestedStruct, _, 4>(&mut storage, base_slot, &value1)?;
        test_update::<WithNestedStruct, _, 4>(&mut storage, base_slot + U256::from(1000), &value1, &value2)?;
        test_delete::<WithNestedStruct, _, 4>(&mut storage, base_slot + U256::from(2000), &value1)?;
    }

    #[test]
    fn test_nested_struct_multi_level(
        value1 in arb_deep_nested(),
        value2 in arb_deep_nested(),
        base_slot in arb_u256().prop_map(|v| {
            // DeepNested uses 6 slots, max offset is 2000, prevent overflow
            v % (U256::MAX - U256::from(2000 + 6))
        })
    ) {
        let mut storage = setup_storage();

        test_store_load::<DeepNested, _, 6>(&mut storage, base_slot, &value1)?;
        test_update::<DeepNested, _, 6>(&mut storage, base_slot + U256::from(1000), &value1, &value2)?;
        test_delete::<DeepNested, _, 6>(&mut storage, base_slot + U256::from(2000), &value1)?;
    }
}

#[test]
fn test_packed_two_slot_contents() {
    let mut storage = setup_storage();
    let base_slot = U256::from(100);

    let value = PackedTwo {
        addr: Address::from([0x12; 20]),
        count: 0x1234567890ABCDEF,
    };

    value
        .store(&mut storage, base_slot, LayoutCtx::FULL)
        .unwrap();

    // PackedTwo should occupy 1 slot with addr (20 bytes) + count (8 bytes)
    let addr = storage.address();
    let slot0 = storage.storage().sload(addr, base_slot).unwrap();

    // Verify each field at its correct position
    let expected = gen_slot_from(&[
        "0x1234567890ABCDEF",                         // offset 20 (8 bytes)
        "0x1212121212121212121212121212121212121212", // offset 0 (20 bytes)
    ]);
    assert_eq!(slot0, expected);
}

#[test]
fn test_packed_three_slot_contents() {
    let mut storage = setup_storage();
    let base_slot = U256::from(200);

    let value = PackedThree {
        a: 0x1111111111111111,
        b: 0x2222222222222222,
        c: 0x3333333333333333,
    };

    value
        .store(&mut storage, base_slot, LayoutCtx::FULL)
        .unwrap();

    // PackedThree should occupy exactly 1 slot with three u64s (24 bytes total)
    let addr = storage.address();
    let slot0 = storage.storage().sload(addr, base_slot).unwrap();

    // Verify each field at its correct position
    // a: offset 0, 8 bytes
    // b: offset 8, 8 bytes
    // c: offset 16, 8 bytes
    let expected = gen_slot_from(&[
        "0x3333333333333333", // offset 16 (8 bytes)
        "0x2222222222222222", // offset 8 (8 bytes)
        "0x1111111111111111", // offset 0 (8 bytes)
    ]);
    assert_eq!(slot0, expected);
}

#[test]
fn test_rule2_slot_contents() {
    let mut storage = setup_storage();
    let base_slot = U256::from(300);

    let value = Rule2Test {
        a: 0x42,               // 1 byte
        b: 0x1234,             // 2 bytes
        c: 0xABCDEF01,         // 4 bytes
        d: 0x123456789ABCDEF0, // 8 bytes
    };

    value
        .store(&mut storage, base_slot, LayoutCtx::FULL)
        .unwrap();

    // Rule2Test packs all fields into slot 0 (15 bytes total)
    let addr = storage.address();
    let slot0 = storage.storage().sload(addr, base_slot).unwrap();

    // Verify each field at its correct position
    // a: offset 0, 1 byte
    // b: offset 1, 2 bytes
    // c: offset 3, 4 bytes
    // d: offset 7, 8 bytes
    let expected = gen_slot_from(&[
        "0x123456789ABCDEF0", // offset 7 (8 bytes)
        "0xABCDEF01",         // offset 3 (4 bytes)
        "0x1234",             // offset 1 (2 bytes)
        "0x42",               // offset 0 (1 byte)
    ]);
    assert_eq!(slot0, expected);
}

#[test]
fn test_partially_packed_slot_contents() {
    let mut storage = setup_storage();
    let base_slot = U256::from(400);

    let value = PartiallyPacked {
        addr1: Address::from([0xAA; 20]),
        flag: true,
        value: U256::from(0x123456789ABCDEF0u64),
        addr2: Address::from([0xBB; 20]),
    };

    value
        .store(&mut storage, base_slot, LayoutCtx::FULL)
        .unwrap();

    // PartiallyPacked layout:
    // Slot 0: addr1 (20 bytes) + flag (1 byte) = 21 bytes (packed)
    // Slot 1: value (32 bytes) - fills entire slot
    // Slot 2: addr2 (20 bytes) - alone in slot, right-aligned

    let addr = storage.address();
    let slot0 = storage.storage().sload(addr, base_slot).unwrap();
    let slot1 = storage
        .storage()
        .sload(addr, base_slot + U256::ONE)
        .unwrap();
    let slot2 = storage
        .storage()
        .sload(addr, base_slot + U256::from(2))
        .unwrap();

    // Verify slot 0 fields
    let expected = gen_slot_from(&[
        "0x01",                                       // offset 20 (1 byte)
        "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // offset 0 (20 bytes)
    ]);
    assert_eq!(slot0, expected);

    // Verify slot 1: value should be directly stored (not packed)
    assert_eq!(slot1, value.value, "value field mismatch in slot 1");

    // Verify slot 2: addr2 is alone in its slot, so it's stored right-aligned (natural storage)
    assert_eq!(
        Address::from_word(slot2.into()),
        value.addr2,
        "addr2 field mismatch in slot 2"
    );
}

#[test]
fn test_partial_update_preserves_adjacent_fields() {
    let mut storage = setup_storage();
    let base_slot = U256::from(500);

    // Store initial value with all fields set
    let initial = PackedThree {
        a: 0x1111111111111111,
        b: 0x2222222222222222,
        c: 0x3333333333333333,
    };
    initial
        .store(&mut storage, base_slot, LayoutCtx::FULL)
        .unwrap();

    // Update only field b
    let updated = PackedThree {
        a: 0x1111111111111111,
        b: 0x9999999999999999, // changed
        c: 0x3333333333333333,
    };
    updated
        .store(&mut storage, base_slot, LayoutCtx::FULL)
        .unwrap();

    // Verify that fields a and c are unchanged
    let addr = storage.address();
    let slot0 = storage.storage().sload(addr, base_slot).unwrap();

    let extracted_a: u64 = extract_field(slot0, 0, 8).unwrap();
    let extracted_b: u64 = extract_field(slot0, 8, 8).unwrap();
    let extracted_c: u64 = extract_field(slot0, 16, 8).unwrap();

    assert_eq!(extracted_a, 0x1111111111111111, "field a was corrupted");
    assert_eq!(extracted_b, 0x9999999999999999, "field b was not updated");
    assert_eq!(extracted_c, 0x3333333333333333, "field c was corrupted");
}

#[test]
fn test_delete_zeros_all_slots() {
    let mut storage = setup_storage();
    let base_slot = U256::from(600);

    let value = PartiallyPacked {
        addr1: Address::from([0xAA; 20]),
        flag: true,
        value: U256::from(0x123456789ABCDEF0u64),
        addr2: Address::from([0xBB; 20]),
    };

    // Store the value (uses 3 slots)
    value
        .store(&mut storage, base_slot, LayoutCtx::FULL)
        .unwrap();

    // Verify slots are non-zero
    let addr = storage.address();
    let slot0_before = storage.storage().sload(addr, base_slot).unwrap();
    let slot1_before = storage
        .storage()
        .sload(addr, base_slot + U256::ONE)
        .unwrap();
    let slot2_before = storage
        .storage()
        .sload(addr, base_slot + U256::from(2))
        .unwrap();

    assert_ne!(
        slot0_before,
        U256::ZERO,
        "slot 0 should be non-zero before delete"
    );
    assert_ne!(
        slot1_before,
        U256::ZERO,
        "slot 1 should be non-zero before delete"
    );
    assert_ne!(
        slot2_before,
        U256::ZERO,
        "slot 2 should be non-zero before delete"
    );

    // Delete the value
    PartiallyPacked::delete(&mut storage, base_slot, LayoutCtx::FULL).unwrap();

    // Verify all slots are now zero
    let slot0_after = storage.storage().sload(addr, base_slot).unwrap();
    let slot1_after = storage
        .storage()
        .sload(addr, base_slot + U256::ONE)
        .unwrap();
    let slot2_after = storage
        .storage()
        .sload(addr, base_slot + U256::from(2))
        .unwrap();

    assert_eq!(slot0_after, U256::ZERO, "slot 0 not zeroed after delete");
    assert_eq!(slot1_after, U256::ZERO, "slot 1 not zeroed after delete");
    assert_eq!(slot2_after, U256::ZERO, "slot 2 not zeroed after delete");
}

#[test]
fn test_slot_boundary_at_32_bytes() {
    let mut storage = setup_storage();
    let base_slot = U256::from(800);

    let value = ExactFit {
        data: U256::from(0x123456789ABCDEFu64),
        flag: true,
    };

    value
        .store(&mut storage, base_slot, LayoutCtx::FULL)
        .unwrap();

    // Slot 0: data (32 bytes) - fills entire slot
    // Slot 1: flag (1 byte)
    let addr = storage.address();
    let slot0 = storage.storage().sload(addr, base_slot).unwrap();
    let slot1 = storage
        .storage()
        .sload(addr, base_slot + U256::ONE)
        .unwrap();

    assert_eq!(slot0, value.data, "data field mismatch in slot 0");
    assert_eq!(slot1, U256::from(value.flag), "flag");
}
