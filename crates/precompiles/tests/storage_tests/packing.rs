//! Tests for slot packing rules and field packing correctness.
//!
//! This module tests the Storable derive macro's implementation of storage packing,
//! verifying that fields are correctly packed into slots according to Solidity's rules.

use alloy::primitives::FixedBytes;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{
    storage::{FromWord, Layout, StorableType, StorageCtx, packing::insert_into_word},
    test_util::gen_word_from,
};

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
#[derive(Storable, Debug, PartialEq, Clone)]
struct ExactFit {
    pub data: U256,
    pub flag: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Storable)]
#[repr(u8)]
enum PackedStatus {
    Pending,
    Active,
    Frozen,
}

#[derive(Debug, Clone, PartialEq, Eq, Storable)]
struct EnumPacked {
    pub status: PackedStatus,       // 1 byte (slot 0, offset 0)
    pub retries: u16,               // 2 bytes (slot 0, offset 1)
    pub enabled: bool,              // 1 byte (slot 0, offset 3)
    pub other_status: PackedStatus, // 1 byte (slot 0, offset 4)
}

#[test]
fn test_slot_and_byte_counts() {
    // Rule verification
    assert_eq!(Rule1Test::LAYOUT, Layout::Slots(2));

    assert_eq!(Rule2Test::LAYOUT, Layout::Slots(1));

    assert_eq!(Rule3TestFull::LAYOUT, Layout::Slots(2));

    assert_eq!(Rule3TestPartial::LAYOUT, Layout::Slots(2));

    assert_eq!(Rule4Test::LAYOUT, Layout::Slots(3));

    // Basic packed types
    assert_eq!(PackedTwo::LAYOUT, Layout::Slots(1));

    // Partially packed types
    assert_eq!(PartiallyPacked::LAYOUT, Layout::Slots(3));

    // Nested structs
    assert_eq!(WithNestedStruct::LAYOUT, Layout::Slots(4));

    // Multi-level nesting
    assert_eq!(DeepNested::LAYOUT, Layout::Slots(6));

    // Unit enums derive as a single packed byte
    assert_eq!(PackedStatus::LAYOUT, Layout::Bytes(1));
    assert_eq!(EnumPacked::LAYOUT, Layout::Slots(1));
}

#[test]
fn test_unit_enum_storage_roundtrip_and_packing() {
    let (mut storage, address) = setup_storage();
    let base_slot = U256::from(1234);
    let value = EnumPacked {
        status: PackedStatus::Frozen,
        retries: 0x0201,
        enabled: true,
        other_status: PackedStatus::Active,
    };

    StorageCtx::enter(&mut storage, || {
        let mut packed_slot = Slot::<EnumPacked>::new(base_slot, address);
        packed_slot.write(value.clone()).unwrap();
        assert_eq!(packed_slot.read().unwrap(), value);

        let raw_word = Slot::<U256>::new(base_slot, address).read().unwrap();
        let stored_status: u8 = extract_from_word(raw_word, 0, 1).unwrap();
        let stored_retries: u16 = extract_from_word(raw_word, 1, 2).unwrap();
        let stored_enabled: bool = extract_from_word(raw_word, 3, 1).unwrap();
        let stored_other_status: u8 = extract_from_word(raw_word, 4, 1).unwrap();

        assert_eq!(stored_status, 2);
        assert_eq!(stored_retries, value.retries);
        assert!(stored_enabled);
        assert_eq!(stored_other_status, 1);

        let mut enum_slot = Slot::<PackedStatus>::new(base_slot + U256::from(1), address);
        enum_slot.write(PackedStatus::Active).unwrap();
        assert_eq!(enum_slot.read().unwrap(), PackedStatus::Active);

        enum_slot.delete().unwrap();
        assert_eq!(enum_slot.read().unwrap(), PackedStatus::Pending);
    });
}

#[test]
fn test_unit_enum_storage_rejects_invalid_discriminant() {
    let (mut storage, address) = setup_storage();
    let base_slot = U256::from(5678);

    StorageCtx::enter(&mut storage, || {
        Slot::<u8>::new(base_slot, address).write(99).unwrap();

        let enum_slot = Slot::<PackedStatus>::new(base_slot, address);
        assert_eq!(
            enum_slot.read().unwrap_err(),
            error::TempoPrecompileError::enum_conversion_error()
        );
    });
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
        let (mut storage, address) = setup_storage();
        StorageCtx::enter(&mut storage, || {
            test_store_load::<Rule1Test>(&address, base_slot, &value1)?;
            test_update::<Rule1Test>(&address, base_slot + U256::from(1000), &value1, &value2)?;
            test_delete::<Rule1Test>(&address, base_slot + U256::from(2000), &value1)
        })?;
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
        let (mut storage, address) = setup_storage();
        StorageCtx::enter(&mut storage, || {
            test_store_load::<Rule2Test>(&address, base_slot, &value1)?;
            test_update::<Rule2Test>(&address, base_slot + U256::from(1000), &value1, &value2)?;
            test_delete::<Rule2Test>(&address, base_slot + U256::from(2000), &value1)
        })?;
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
        let (mut storage, address) = setup_storage();
        StorageCtx::enter(&mut storage, || {
            test_store_load::<Rule3TestFull>(&address, base_slot, &value1)?;
            test_update::<Rule3TestFull>(&address, base_slot + U256::from(1000), &value1, &value2)?;
            test_delete::<Rule3TestFull>(&address, base_slot + U256::from(2000), &value1)
        })?;
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
        let (mut storage, address) = setup_storage();
        StorageCtx::enter(&mut storage, || {
            test_store_load::<Rule3TestPartial>(&address, base_slot, &value1)?;
            test_update::<Rule3TestPartial>(&address, base_slot + U256::from(1000), &value1, &value2)?;
            test_delete::<Rule3TestPartial>(&address, base_slot + U256::from(2000), &value1)
        })?;
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
        let (mut storage, address) = setup_storage();
        StorageCtx::enter(&mut storage, || {
            test_store_load::<Rule4Test>(&address, base_slot, &value1)?;
            test_update::<Rule4Test>(&address, base_slot + U256::from(1000), &value1, &value2)?;
            test_delete::<Rule4Test>(&address, base_slot + U256::from(2000), &value1)
        })?;
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
        let (mut storage, address) = setup_storage();
        StorageCtx::enter(&mut storage, || {
            test_store_load::<PackedTwo>(&address, base_slot, &value1)?;
            test_update::<PackedTwo>(&address, base_slot + U256::from(1000), &value1, &value2)?;
            test_delete::<PackedTwo>(&address, base_slot + U256::from(2000), &value1)
        })?;
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
        let (mut storage, address) = setup_storage();
        StorageCtx::enter(&mut storage, || {
            test_store_load::<PackedThree>(&address, base_slot, &value1)?;
            test_update::<PackedThree>(&address, base_slot + U256::from(1000), &value1, &value2)?;
            test_delete::<PackedThree>(&address, base_slot + U256::from(2000), &value1)
        })?;
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
        let (mut storage, address) = setup_storage();
        StorageCtx::enter(&mut storage, || {
            test_store_load::<PartiallyPacked>(&address, base_slot, &value1)?;
            test_update::<PartiallyPacked>(&address, base_slot + U256::from(1000), &value1, &value2)?;
            test_delete::<PartiallyPacked>(&address, base_slot + U256::from(2000), &value1)
        })?;
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
        let (mut storage, address) = setup_storage();
        StorageCtx::enter(&mut storage, || {
            test_store_load::<WithNestedStruct>(&address, base_slot, &value1)?;
            test_update::<WithNestedStruct>(&address, base_slot + U256::from(1000), &value1, &value2)?;
            test_delete::<WithNestedStruct>(&address, base_slot + U256::from(2000), &value1)
        })?;
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
        let (mut storage, address) = setup_storage();
        StorageCtx::enter(&mut storage, || {
            test_store_load::<DeepNested>(&address, base_slot, &value1)?;
            test_update::<DeepNested>(&address, base_slot + U256::from(1000), &value1, &value2)?;
            test_delete::<DeepNested>(&address, base_slot + U256::from(2000), &value1)
        })?;
    }
}

#[test]
fn test_packed_two_slot_contents() {
    let (mut storage, address) = setup_storage();
    StorageCtx::enter(&mut storage, || {
        let base_slot = U256::random();

        // Write the struct to storage
        PackedTwo::handle(base_slot, LayoutCtx::FULL, address)
            .write(PackedTwo {
                addr: Address::from([0x12; 20]),
                count: 0x1234567890ABCDEF,
            })
            .unwrap();

        // PackedTwo should occupy 1 slot with addr (20 bytes) + count (8 bytes)
        let slot = U256::handle(base_slot, LayoutCtx::FULL, address)
            .read()
            .unwrap();

        // Verify each field at its correct position
        let expected = gen_word_from(&[
            "0x1234567890ABCDEF",                         // offset 20 (8 bytes)
            "0x1212121212121212121212121212121212121212", // offset 0 (20 bytes)
        ]);
        assert_eq!(slot, expected);
        Ok::<(), error::TempoPrecompileError>(())
    })
    .unwrap();
}

#[test]
fn test_packed_three_slot_contents() {
    let (mut storage, address) = setup_storage();
    StorageCtx::enter(&mut storage, || {
        let base_slot = U256::random();

        let value = PackedThree {
            a: 0x1111111111111111,
            b: 0x2222222222222222,
            c: 0x3333333333333333,
        };

        PackedThree::handle(base_slot, LayoutCtx::FULL, address)
            .write(value)
            .unwrap();

        // PackedThree should occupy exactly 1 slot with three u64s (24 bytes total)
        let slot0 = U256::handle(base_slot, LayoutCtx::FULL, address)
            .read()
            .unwrap();

        // Verify each field at its correct position
        // a: offset 0, 8 bytes
        // b: offset 8, 8 bytes
        // c: offset 16, 8 bytes
        let expected = gen_word_from(&[
            "0x3333333333333333", // offset 16 (8 bytes)
            "0x2222222222222222", // offset 8 (8 bytes)
            "0x1111111111111111", // offset 0 (8 bytes)
        ]);
        assert_eq!(slot0, expected);
        Ok::<(), error::TempoPrecompileError>(())
    })
    .unwrap();
}

#[test]
fn test_rule2_slot_contents() {
    let (mut storage, address) = setup_storage();
    StorageCtx::enter(&mut storage, || {
        let base_slot = U256::random();

        let value = Rule2Test {
            a: 0x42,               // 1 byte
            b: 0x1234,             // 2 bytes
            c: 0xABCDEF01,         // 4 bytes
            d: 0x123456789ABCDEF0, // 8 bytes
        };

        Rule2Test::handle(base_slot, LayoutCtx::FULL, address)
            .write(value)
            .unwrap();

        // Rule2Test packs all fields into slot 0 (15 bytes total)
        let slot0 = U256::handle(base_slot, LayoutCtx::FULL, address)
            .read()
            .unwrap();

        // Verify each field at its correct position
        // a: offset 0, 1 byte
        // b: offset 1, 2 bytes
        // c: offset 3, 4 bytes
        // d: offset 7, 8 bytes
        let expected = gen_word_from(&[
            "0x123456789ABCDEF0", // offset 7 (8 bytes)
            "0xABCDEF01",         // offset 3 (4 bytes)
            "0x1234",             // offset 1 (2 bytes)
            "0x42",               // offset 0 (1 byte)
        ]);
        assert_eq!(slot0, expected);
        Ok::<(), error::TempoPrecompileError>(())
    })
    .unwrap();
}

#[test]
fn test_partially_packed_slot_contents() {
    let (mut storage, address) = setup_storage();
    StorageCtx::enter(&mut storage, || {
        let base_slot = U256::random();

        let value = PartiallyPacked {
            addr1: Address::from([0xAA; 20]),
            flag: true,
            value: U256::from(0x123456789ABCDEF0u64),
            addr2: Address::from([0xBB; 20]),
        };

        PartiallyPacked::handle(base_slot, LayoutCtx::FULL, address)
            .write(value.clone())
            .unwrap();

        // PartiallyPacked layout:
        // Slot 0: addr1 (20 bytes) + flag (1 byte) = 21 bytes (packed)
        // Slot 1: value (32 bytes) - fills entire slot
        // Slot 2: addr2 (20 bytes) - alone in slot, right-aligned

        let slot0 = U256::handle(base_slot, LayoutCtx::FULL, address)
            .read()
            .unwrap();
        let slot1 = U256::handle(base_slot + U256::ONE, LayoutCtx::FULL, address)
            .read()
            .unwrap();
        let slot2 = U256::handle(base_slot + U256::from(2), LayoutCtx::FULL, address)
            .read()
            .unwrap();

        // Verify slot 0 fields
        let expected = gen_word_from(&[
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
        Ok::<(), error::TempoPrecompileError>(())
    })
    .unwrap();
}

#[test]
fn test_partial_update_preserves_adjacent_fields() {
    let (mut storage, address) = setup_storage();
    StorageCtx::enter(&mut storage, || {
        let base_slot = U256::random();

        // Store initial value with all fields set
        let initial = PackedThree {
            a: 0x1111111111111111,
            b: 0x2222222222222222,
            c: 0x3333333333333333,
        };
        PackedThree::handle(base_slot, LayoutCtx::FULL, address)
            .write(initial)
            .unwrap();

        // Update only field b
        let updated = PackedThree {
            a: 0x1111111111111111,
            b: 0x9999999999999999, // changed
            c: 0x3333333333333333,
        };
        PackedThree::handle(base_slot, LayoutCtx::FULL, address)
            .write(updated)
            .unwrap();

        // Verify that fields a and c are unchanged
        let slot0 = U256::handle(base_slot, LayoutCtx::FULL, address)
            .read()
            .unwrap();

        let extracted_a: u64 = extract_from_word(slot0, 0, 8).unwrap();
        let extracted_b: u64 = extract_from_word(slot0, 8, 8).unwrap();
        let extracted_c: u64 = extract_from_word(slot0, 16, 8).unwrap();

        assert_eq!(extracted_a, 0x1111111111111111, "field a was corrupted");
        assert_eq!(extracted_b, 0x9999999999999999, "field b was not updated");
        assert_eq!(extracted_c, 0x3333333333333333, "field c was corrupted");
        Ok::<(), error::TempoPrecompileError>(())
    })
    .unwrap();
}

#[test]
fn test_delete_zeros_all_slots() {
    let (mut storage, address) = setup_storage();
    StorageCtx::enter(&mut storage, || {
        let base_slot = U256::random();

        let value = PartiallyPacked {
            addr1: Address::from([0xAA; 20]),
            flag: true,
            value: U256::from(0x123456789ABCDEF0u64),
            addr2: Address::from([0xBB; 20]),
        };

        // Store the value (uses 3 slots)
        PartiallyPacked::handle(base_slot, LayoutCtx::FULL, address)
            .write(value)
            .unwrap();

        // Verify slots are non-zero
        let slot0_before = U256::handle(base_slot, LayoutCtx::FULL, address)
            .read()
            .unwrap();
        let slot1_before = U256::handle(base_slot + U256::ONE, LayoutCtx::FULL, address)
            .read()
            .unwrap();
        let slot2_before = U256::handle(base_slot + U256::from(2), LayoutCtx::FULL, address)
            .read()
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
        PartiallyPacked::handle(base_slot, LayoutCtx::FULL, address)
            .delete()
            .unwrap();

        // Verify all slots are now zero
        let slot0_after = U256::handle(base_slot, LayoutCtx::FULL, address)
            .read()
            .unwrap();
        let slot1_after = U256::handle(base_slot + U256::ONE, LayoutCtx::FULL, address)
            .read()
            .unwrap();
        let slot2_after = U256::handle(base_slot + U256::from(2), LayoutCtx::FULL, address)
            .read()
            .unwrap();

        assert_eq!(slot0_after, U256::ZERO, "slot 0 not zeroed after delete");
        assert_eq!(slot1_after, U256::ZERO, "slot 1 not zeroed after delete");
        assert_eq!(slot2_after, U256::ZERO, "slot 2 not zeroed after delete");
        Ok::<(), error::TempoPrecompileError>(())
    })
    .unwrap();
}

#[test]
fn test_slot_boundary_at_32_bytes() {
    let (mut storage, address) = setup_storage();
    StorageCtx::enter(&mut storage, || {
        let base_slot = U256::random();

        let value = ExactFit {
            data: U256::from(0x123456789ABCDEFu64),
            flag: true,
        };

        ExactFit::handle(base_slot, LayoutCtx::FULL, address)
            .write(value.clone())
            .unwrap();

        // Slot 0: data (32 bytes) - fills entire slot
        // Slot 1: flag (1 byte)
        let slot0 = U256::handle(base_slot, LayoutCtx::FULL, address)
            .read()
            .unwrap();
        let slot1 = U256::handle(base_slot + U256::ONE, LayoutCtx::FULL, address)
            .read()
            .unwrap();

        assert_eq!(slot0, value.data, "data field mismatch in slot 0");
        assert_eq!(slot1, U256::from(value.flag), "flag");
        Ok::<(), error::TempoPrecompileError>(())
    })
    .unwrap();
}

/// Verifies that `to_word()` produces right-aligned U256 (data in low bytes).
/// This is the key invariant required for packing to work correctly.
#[test]
fn test_fixed_bytes_to_word_alignment() {
    // FixedBytes<11> should be right-aligned at bytes[21..32] (32 - 11 = 21)
    let value = FixedBytes::<11>::from([0xAA; 11]);
    let word = value.to_word();
    let bytes = word.to_be_bytes::<32>();

    // First 21 bytes should be zero padding
    assert_eq!(&bytes[0..21], &[0u8; 21], "padding should be zeros");
    // Last 11 bytes should be the data
    assert_eq!(&bytes[21..32], &[0xAA; 11], "data should be right-aligned");
}

/// Verifies that insert_into_word + extract_from_word roundtrip works for FixedBytes.
/// This would fail with left-aligned to_word() because the mask extracts wrong bytes.
#[test]
fn test_fixed_bytes_packing_roundtrip() {
    let value = FixedBytes::<7>::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);

    // Insert at offset 5
    let slot = insert_into_word(U256::ZERO, &value, 5, 7).unwrap();

    // Extract back
    let extracted: FixedBytes<7> = extract_from_word(slot, 5, 7).unwrap();

    assert_eq!(value, extracted, "packing roundtrip should preserve value");
}

/// Verifies that multiple FixedBytes fields packed in one slot don't corrupt each other.
/// This catches the bug where left-aligned data would be masked to zeros during packing.
#[test]
fn test_fixed_bytes_multi_field_packing() {
    let fb4 = FixedBytes::<4>::from([0x11, 0x22, 0x33, 0x44]);
    let fb8 = FixedBytes::<8>::from([0xAA; 8]);

    // Pack fb4 at offset 0, fb8 at offset 4
    let mut slot = U256::ZERO;
    slot = insert_into_word(slot, &fb4, 0, 4).unwrap();
    slot = insert_into_word(slot, &fb8, 4, 8).unwrap();

    // Both values should be recoverable
    let extracted_fb4: FixedBytes<4> = extract_from_word(slot, 0, 4).unwrap();
    let extracted_fb8: FixedBytes<8> = extract_from_word(slot, 4, 8).unwrap();

    assert_eq!(fb4, extracted_fb4, "fb4 should be preserved after packing");
    assert_eq!(fb8, extracted_fb8, "fb8 should be preserved after packing");

    // Also verify the raw slot layout matches expected bit pattern
    let expected = gen_word_from(&[
        "0xAAAAAAAAAAAAAAAA", // offset 4 (8 bytes)
        "0x11223344",         // offset 0 (4 bytes)
    ]);
    assert_eq!(slot, expected, "slot layout should match expected pattern");
}

/// On T4, storing a struct with packed fields skips the SLOAD for the first packed slot
/// (starts from `U256::ZERO` instead). This verifies both:
/// - The SLOAD counter: T4 issues 0 SLOADs for the store, pre-T4 issues 1.
/// - The slot contents: T4 zeroes unused bytes, pre-T4 preserves them from the SLOAD.
#[test]
fn test_t4_store_packed_struct_skips_sload() -> eyre::Result<()> {
    let garbage = U256::MAX;
    let base_slot = U256::from(42);
    let address = Address::random();

    let packed = PackedTwo {
        addr: Address::from([0x11; 20]),
        count: 0x1234567890ABCDEF,
    };

    // PackedTwo uses 28 bytes (addr: 20 + count: 8), leaving 4 unused bytes in the slot.
    let expected_field_bytes = gen_word_from(&[
        "0x1234567890ABCDEF",                         // offset 20 (8 bytes)
        "0x1111111111111111111111111111111111111111", // offset 0 (20 bytes)
    ]);

    // -- Pre-T4: SLOAD is performed, so unused bytes retain the garbage --
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T0);
    StorageCtx::enter(&mut storage, || {
        // Pre-fill the slot with garbage
        U256::handle(base_slot, LayoutCtx::FULL, address).write(garbage)?;
        StorageCtx.reset_counters();

        // Store the packed struct (SLOAD reads back the garbage first)
        PackedTwo::handle(base_slot, LayoutCtx::FULL, address).write(packed.clone())?;

        // 1 SLOAD (reads existing slot), 1 SSTORE
        assert_eq!(StorageCtx.counter_sload(), 1);
        assert_eq!(StorageCtx.counter_sstore(), 1);

        // Unused 4 bytes at the top must retain the garbage — proves SLOAD happened
        let slot = U256::handle(base_slot, LayoutCtx::FULL, address).read()?;
        let expected_with_garbage = expected_field_bytes | (U256::MAX << 224);
        assert_eq!(slot, expected_with_garbage);

        Ok::<(), error::TempoPrecompileError>(())
    })?;

    // -- T4: SLOAD is skipped, so unused bytes are zero (not garbage) --
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T4);
    StorageCtx::enter(&mut storage, || {
        // Pre-fill the slot with garbage
        U256::handle(base_slot, LayoutCtx::FULL, address).write(garbage)?;
        StorageCtx.reset_counters();

        // Store the packed struct (should NOT read back the garbage)
        PackedTwo::handle(base_slot, LayoutCtx::FULL, address).write(packed.clone())?;

        // 0 SLOADs (the optimization), 1 SSTORE for the single packed slot
        assert_eq!(StorageCtx.counter_sload(), 0,);
        assert_eq!(StorageCtx.counter_sstore(), 1,);

        // Unused 4 bytes at the top must be zero — proves no SLOAD happened
        let slot = U256::handle(base_slot, LayoutCtx::FULL, address).read()?;
        assert_eq!(slot, expected_field_bytes);

        Ok(())
    })
}

/// Verifies that on T4, the SLOAD elision for packed struct fields doesn't corrupt neighbor slots.
///
/// Even though `Rule4Test { before: u8, nested: PackedTwo, after: u8 }` has:
///   - `before` (1 byte) + `nested` (28 bytes) = 29 bytes < 32 (could theoretically pack)
///   - `nested` (28 bytes) + `after` (1 byte)  = 29 bytes < 32 (could theoretically pack)
///
/// Structs always start a new slot, so neighbors are isolated. Starting from `U256::ZERO`
/// on T4 doesn't bleed into adjacent slots.
#[test]
fn test_t4_struct_store_preserves_neighbor_slots() -> eyre::Result<()> {
    let address = Address::random();
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T4);

    StorageCtx::enter(&mut storage, || {
        let base_slot = U256::from(100);

        // Store the full struct with known neighbor values
        let original = Rule4Test {
            before: 0x42,
            nested: PackedTwo {
                addr: Address::from([0xAA; 20]),
                count: 0x1111111111111111,
            },
            after: 0xFF,
        };
        Rule4Test::handle(base_slot, LayoutCtx::FULL, address).write(original)?;

        // Snapshot neighbor slot values
        let slot0 = U256::handle(base_slot, LayoutCtx::FULL, address).read()?;
        let slot2 = U256::handle(base_slot + U256::from(2), LayoutCtx::FULL, address).read()?;
        assert_ne!(slot0, U256::ZERO, "before-slot should be non-zero");
        assert_ne!(slot2, U256::ZERO, "after-slot should be non-zero");

        // Overwrite the full struct with different nested values
        let updated = Rule4Test {
            before: 0x42, // same
            nested: PackedTwo {
                // different
                addr: Address::from([0xBB; 20]),
                count: 0x2222222222222222,
            },
            after: 0xFF, // same
        };
        Rule4Test::handle(base_slot, LayoutCtx::FULL, address).write(updated)?;

        // Verify neighbor slots are untouched
        let slot0_after = U256::handle(base_slot, LayoutCtx::FULL, address).read()?;
        let slot2_after =
            U256::handle(base_slot + U256::from(2), LayoutCtx::FULL, address).read()?;
        assert_eq!(slot0_after, slot0,);
        assert_eq!(slot2_after, slot2,);

        // Verify the nested struct slot was actually updated
        let slot1 = U256::handle(base_slot + U256::ONE, LayoutCtx::FULL, address).read()?;
        let expected_nested = gen_word_from(&[
            "0x2222222222222222",                         // offset 20 (8 bytes)
            "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", // offset 0 (20 bytes)
        ]);
        assert_eq!(slot1, expected_nested,);

        Ok(())
    })
}

/// On T4, storing a multi-slot struct with packed fields in *different* slots
/// skips the SLOAD for each new packed slot (the "else if IS_PACKABLE" branch).
///
/// `Rule3TestPartial { a: u128, b: u128, c: u8 }` packs `a` and `b` in slot 0,
/// then `c` starts a new slot 1. The T4 optimisation should skip the SLOAD for
/// both slot 0 (first-field branch) *and* slot 1 (new-slot-but-packable branch).
#[test]
fn test_t4_store_multi_slot_packed_skips_sload() -> eyre::Result<()> {
    let garbage = U256::MAX;
    let base_slot = U256::from(50);
    let address = Address::random();

    let value = Rule3TestPartial {
        a: 0x1111_2222_3333_4444_5555_6666_7777_8888,
        b: 0xAAAA_BBBB_CCCC_DDDD_EEEE_FFFF_0000_1111,
        c: 0x42,
    };

    // -- Pre-T4: SLOADs are performed for each packed slot --
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T0);
    StorageCtx::enter(&mut storage, || {
        // Pre-fill both slots with garbage
        U256::handle(base_slot, LayoutCtx::FULL, address).write(garbage)?;
        U256::handle(base_slot + U256::from(1), LayoutCtx::FULL, address).write(garbage)?;
        StorageCtx.reset_counters();

        Rule3TestPartial::handle(base_slot, LayoutCtx::FULL, address).write(value.clone())?;

        // Pre-T4: 2 SLOADs (one per packed slot), 2 SSTOREs
        assert_eq!(
            StorageCtx.counter_sload(),
            2,
            "pre-T4 should SLOAD both packed slots"
        );
        assert_eq!(StorageCtx.counter_sstore(), 2);

        // Slot 1 unused bytes (31 bytes unused) should retain garbage from the SLOAD
        let slot1 = U256::handle(base_slot + U256::from(1), LayoutCtx::FULL, address).read()?;
        assert_ne!(
            slot1,
            U256::from(0x42u8),
            "pre-T4 should preserve garbage in unused bytes"
        );

        Ok::<(), error::TempoPrecompileError>(())
    })?;

    // -- T4: SLOADs are skipped for both packed slots --
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T4);
    StorageCtx::enter(&mut storage, || {
        // Pre-fill both slots with garbage
        U256::handle(base_slot, LayoutCtx::FULL, address).write(garbage)?;
        U256::handle(base_slot + U256::from(1), LayoutCtx::FULL, address).write(garbage)?;
        StorageCtx.reset_counters();

        Rule3TestPartial::handle(base_slot, LayoutCtx::FULL, address).write(value)?;

        // T4: 0 SLOADs (elided for both slots), 2 SSTOREs
        assert_eq!(
            StorageCtx.counter_sload(),
            0,
            "T4 should elide SLOADs for all packed slots"
        );
        assert_eq!(StorageCtx.counter_sstore(), 2);

        // Slot 1 unused bytes should be zero — proves SLOAD was skipped
        let slot1 = U256::handle(base_slot + U256::from(1), LayoutCtx::FULL, address).read()?;
        assert_eq!(
            slot1,
            U256::from(0x42u8),
            "T4 should zero unused bytes in new packed slot"
        );

        Ok(())
    })
}

/// Verifies that on T4, the SLOAD elision on non-first packed slots doesn't corrupt
/// neighbor slots. Uses `PackedThreeSlot` which spans 3 slots with packing on slots 1 and 2.
#[test]
fn test_t4_multi_slot_packed_preserves_neighbor_slots() -> eyre::Result<()> {
    let address = Address::random();
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T4);

    StorageCtx::enter(&mut storage, || {
        let base_slot = U256::from(200);

        let original = PackedThreeSlot {
            value: U256::from(0xDEAD_u64),
            timestamp: 0x1111111111111111,
            start_time: 0x2222222222222222,
            end_time: 0x3333333333333333,
            nonce: 0x4444444444444444,
            owner: Address::from([0xAA; 20]),
            active: true,
        };
        PackedThreeSlot::handle(base_slot, LayoutCtx::FULL, address).write(original)?;

        // Snapshot all three slot values
        let slot0 = U256::handle(base_slot, LayoutCtx::FULL, address).read()?;
        let slot1 = U256::handle(base_slot + U256::from(1), LayoutCtx::FULL, address).read()?;
        let slot2 = U256::handle(base_slot + U256::from(2), LayoutCtx::FULL, address).read()?;

        // Overwrite with different packed fields in slots 1 and 2
        let updated = PackedThreeSlot {
            value: U256::from(0xDEAD_u64),    // slot 0, same
            timestamp: 0xAAAAAAAAAAAAAAAA,    // slot 1, different
            start_time: 0xBBBBBBBBBBBBBBBB,   // slot 1, different
            end_time: 0xCCCCCCCCCCCCCCCC,     // slot 1, different
            nonce: 0xDDDDDDDDDDDDDDDD,        // slot 1, different
            owner: Address::from([0xBB; 20]), // slot 2, different
            active: false,                    // slot 2, different
        };
        PackedThreeSlot::handle(base_slot, LayoutCtx::FULL, address).write(updated)?;

        // Slot 0 should be unchanged (non-packable U256, direct store)
        let slot0_after = U256::handle(base_slot, LayoutCtx::FULL, address).read()?;
        assert_eq!(slot0_after, slot0, "slot 0 should be unchanged");

        // Slots 1 and 2 should be updated (not equal to original snapshots)
        let slot1_after =
            U256::handle(base_slot + U256::from(1), LayoutCtx::FULL, address).read()?;
        let slot2_after =
            U256::handle(base_slot + U256::from(2), LayoutCtx::FULL, address).read()?;
        assert_ne!(slot1_after, slot1, "slot 1 should be updated");
        assert_ne!(slot2_after, slot2, "slot 2 should be updated");

        // Roundtrip: read back and verify all fields are correct
        let loaded = PackedThreeSlot::handle(base_slot, LayoutCtx::FULL, address).read()?;
        assert_eq!(loaded.value, U256::from(0xDEAD_u64));
        assert_eq!(loaded.timestamp, 0xAAAAAAAAAAAAAAAA);
        assert_eq!(loaded.start_time, 0xBBBBBBBBBBBBBBBB);
        assert_eq!(loaded.end_time, 0xCCCCCCCCCCCCCCCC);
        assert_eq!(loaded.nonce, 0xDDDDDDDDDDDDDDDD);
        assert_eq!(loaded.owner, Address::from([0xBB; 20]));
        assert!(!loaded.active);

        Ok(())
    })
}
