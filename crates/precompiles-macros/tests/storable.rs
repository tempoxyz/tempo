//! Unit tests for the #[derive(Storable)] macro in isolation.
//! These tests verify that user-defined structs properly implement store, load, and delete operations.

// Re-export `tempo_precompiles::storage` as a local module so `crate::storage` works
mod storage {
    pub(super) use tempo_precompiles::storage::*;
}

use alloy::primitives::{Address, U256};
use proptest::prelude::*;
use storage::{
    ContractStorage, PrecompileStorageProvider, Storable, StorableType,
    hashmap::HashMapStorageProvider,
};
use tempo_precompiles::error;
use tempo_precompiles_macros::Storable;

// Test wrapper that combines address + storage provider to implement ContractStorage
struct TestStorage<S> {
    address: Address,
    storage: S,
}

impl<S: PrecompileStorageProvider> ContractStorage for TestStorage<S> {
    type Storage = S;
    fn address(&self) -> Address {
        self.address
    }
    fn storage(&mut self) -> &mut Self::Storage {
        &mut self.storage
    }
}

// Helper to create a test storage instance
fn create_storage() -> TestStorage<HashMapStorageProvider> {
    TestStorage {
        address: Address::ZERO,
        storage: HashMapStorageProvider::new(1),
    }
}

// Helper to test store + load roundtrip
fn test_store_load<T, S, const N: usize>(
    storage: &mut S,
    base_slot: U256,
    original: &T,
) -> error::Result<()>
where
    T: Storable<N> + PartialEq + std::fmt::Debug,
    S: ContractStorage,
{
    original.store(storage, base_slot)?;
    let loaded = T::load(storage, base_slot)?;
    assert_eq!(&loaded, original, "Store/load roundtrip failed");
    Ok(())
}

// Helper to test update operation
fn test_update<T, S, const N: usize>(
    storage: &mut S,
    base_slot: U256,
    initial: &T,
    updated: &T,
) -> error::Result<()>
where
    T: Storable<N> + PartialEq + std::fmt::Debug,
    S: ContractStorage,
{
    initial.store(storage, base_slot)?;
    let loaded1 = T::load(storage, base_slot)?;
    assert_eq!(&loaded1, initial, "Initial store/load failed");

    updated.store(storage, base_slot)?;
    let loaded2 = T::load(storage, base_slot)?;
    assert_eq!(&loaded2, updated, "Update failed");
    Ok(())
}

// Helper to test delete operation
fn test_delete<T, S, const N: usize>(
    storage: &mut S,
    base_slot: U256,
    data: &T,
) -> error::Result<()>
where
    T: Storable<N> + PartialEq + std::fmt::Debug + Default,
    S: ContractStorage,
{
    data.store(storage, base_slot)?;
    let loaded = T::load(storage, base_slot)?;
    assert_eq!(&loaded, data, "Initial store/load failed");

    T::delete(storage, base_slot)?;
    let after_delete = T::load(storage, base_slot)?;
    let expected_zero = T::default();
    assert_eq!(&after_delete, &expected_zero, "Delete did not zero values");
    Ok(())
}

// -- PROPTEST STRATEGIES ------------------------------------------------------

// Strategy for generating random Address values
fn arb_address() -> impl Strategy<Value = Address> {
    any::<[u8; 20]>().prop_map(Address::from)
}

// Strategy for generating random U256 values
fn arb_u256() -> impl Strategy<Value = U256> {
    any::<[u64; 4]>().prop_map(U256::from_limbs)
}

// -- TEST STRUCTS -------------------------------------------------------------

// Golden Rule 1: Structs Always Start New Slots
#[derive(Default, Debug, Clone, PartialEq, Eq, Storable)]
struct Rule1Test {
    pub a: u8,             // 1 byte    (slot 0, offset 0)
    pub nested: PackedTwo, // 28 bytes  (slot 1, offset 0)
}

fn arb_rule1_test() -> impl Strategy<Value = Rule1Test> {
    (any::<u8>(), arb_packed_two()).prop_map(|(a, nested)| Rule1Test { a, nested })
}

//  Rule 2: Value Types Pack Sequentially
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

//  Rule 3: Overflow moves to next slot
#[derive(Default, Debug, Clone, PartialEq, Eq, Storable)]
struct Rule3TestFull {
    pub a: U256, // 32 bytes (slot 0)
    pub b: u8,   // 1 byte   (slot 1, offset 0)
}

fn arb_rule3_test_full() -> impl Strategy<Value = Rule3TestFull> {
    (arb_u256(), any::<u8>()).prop_map(|(a, b)| Rule3TestFull { a, b })
}

//  Rule 3: Overflow moves to next slot
#[derive(Default, Debug, Clone, PartialEq, Eq, Storable)]
struct Rule3TestPartial {
    pub a: u128, // 16 bytes (slot 0, offset 0)
    pub b: u128, // 16 bytes (slot 0, offset 16)
    pub c: u8,   // 1 byte   (slot 1, offset 0)
}

fn arb_rule3_test_partial() -> impl Strategy<Value = Rule3TestPartial> {
    (any::<u128>(), any::<u128>(), any::<u8>()).prop_map(|(a, b, c)| Rule3TestPartial { a, b, c })
}

//  Rule 4: Fields after structs start new slots
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

// -- SLOT COUNT VERIFICATION --------------------------------------------------

#[test]
fn test_slot_and_byte_counts() {
    //  Rule verification
    assert_eq!(Rule1Test::SLOT_COUNT, 2,);
    assert_eq!(Rule1Test::BYTE_COUNT, 32 + 28);

    assert_eq!(Rule2Test::SLOT_COUNT, 1,);
    assert_eq!(Rule2Test::BYTE_COUNT, 15);

    assert_eq!(Rule3TestFull::SLOT_COUNT, 2,);
    assert_eq!(Rule3TestFull::BYTE_COUNT, 33);

    assert_eq!(Rule3TestPartial::SLOT_COUNT, 2,);
    assert_eq!(Rule3TestPartial::BYTE_COUNT, 33);

    assert_eq!(Rule4Test::SLOT_COUNT, 3,);
    assert_eq!(Rule4Test::BYTE_COUNT, 65);

    // Basic packed types
    assert_eq!(PackedTwo::SLOT_COUNT, 1);
    assert_eq!(PackedTwo::BYTE_COUNT, 28);
    assert_eq!(PackedThree::SLOT_COUNT, 1);
    assert_eq!(PackedThree::BYTE_COUNT, 24);

    // Partially packed types
    assert_eq!(PartiallyPacked::SLOT_COUNT, 3);
    assert_eq!(PartiallyPacked::BYTE_COUNT, 84);

    // Nested structs
    assert_eq!(WithNestedStruct::SLOT_COUNT, 4);
    assert_eq!(WithNestedStruct::BYTE_COUNT, 128);

    // Multi-level nesting
    assert_eq!(DeepNested::SLOT_COUNT, 6);
}

// -- TEST SLOT PACKING --------------------------------------------------------

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
        let mut storage = create_storage();

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
        let mut storage = create_storage();

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
        let mut storage = create_storage();

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
        let mut storage = create_storage();

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
        let mut storage = create_storage();

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
        let mut storage = create_storage();

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
        let mut storage = create_storage();

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
        let mut storage = create_storage();

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
        let mut storage = create_storage();

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
        let mut storage = create_storage();

        test_store_load::<DeepNested, _, 6>(&mut storage, base_slot, &value1)?;
        test_update::<DeepNested, _, 6>(&mut storage, base_slot + U256::from(1000), &value1, &value2)?;
        test_delete::<DeepNested, _, 6>(&mut storage, base_slot + U256::from(2000), &value1)?;
    }
}
