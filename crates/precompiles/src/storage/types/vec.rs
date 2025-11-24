//! Dynamic array (`Vec<T>`) implementation for the `Storable` trait.
//!
//! # Storage Layout
//!
//! Vec uses Solidity-compatible dynamic array storage:
//! - **Base slot**: Stores the array length (number of elements)
//! - **Data slots**: Start at `keccak256(base_slot)`, elements packed efficiently
//!
//! ## Limitations
//!
//! - Only supports `Storable<1>` element types (single-slot types)
//! - Multi-slot structs are not currently supported in Vec

use alloy::primitives::U256;

use crate::{
    error::{Result, TempoPrecompileError},
    storage::{
        Storable, StorableType, StorageKey, StorageOps,
        packing::{
            calc_element_offset, calc_element_slot, calc_packed_slot_count, extract_packed_value,
            insert_packed_value, is_packable, zero_packed_value,
        },
        types::{Slot, SlotId, mapping::mapping_slot},
    },
};

impl<T: StorableType> StorableType for Vec<T> {
    /// Vec base slot is always 32 bytes (stores length).
    const BYTE_COUNT: usize = 32;
}

impl<T> Storable<1> for Vec<T>
where
    T: Storable<1> + StorableType,
{
    const SLOT_COUNT: usize = 1;

    fn load<S: StorageOps>(storage: &mut S, base_slot: U256) -> Result<Self> {
        // Read length from base slot
        let length_value = storage.sload(base_slot)?;
        let length = length_value.to::<usize>();

        if length == 0 {
            return Ok(Self::new());
        }

        let data_start = calc_data_slot(base_slot);

        // Pack elements if necessary
        if is_packable(T::BYTE_COUNT) {
            load_packed_elements(storage, data_start, length, T::BYTE_COUNT)
        } else {
            load_unpacked_elements(storage, data_start, length)
        }
    }

    fn store<S: StorageOps>(&self, storage: &mut S, base_slot: U256) -> Result<()> {
        // Write length to base slot
        storage.sstore(base_slot, U256::from(self.len()))?;

        if self.is_empty() {
            return Ok(());
        }

        let data_start = calc_data_slot(base_slot);

        // Pack elements if necessary
        if is_packable(T::BYTE_COUNT) {
            store_packed_elements(self, storage, data_start, T::BYTE_COUNT)
        } else {
            store_unpacked_elements(self, storage, data_start)
        }
    }

    fn delete<S: StorageOps>(storage: &mut S, base_slot: U256) -> Result<()> {
        // Read length from base slot to determine how many slots to clear
        let length_value = storage.sload(base_slot)?;
        let length = length_value.to::<usize>();

        // Clear base slot (length)
        storage.sstore(base_slot, U256::ZERO)?;

        if length == 0 {
            return Ok(());
        }

        let data_start = calc_data_slot(base_slot);
        if is_packable(T::BYTE_COUNT) {
            // Clear packed element slots
            let slot_count = calc_packed_slot_count(length, T::BYTE_COUNT);
            for slot_idx in 0..slot_count {
                storage.sstore(data_start + U256::from(slot_idx), U256::ZERO)?;
            }
        } else {
            // Clear unpacked element slots
            for elem_idx in 0..length {
                let elem_slot = data_start + U256::from(elem_idx);
                T::delete(storage, elem_slot)?;
            }
        }

        Ok(())
    }

    fn to_evm_words(&self) -> Result<[U256; 1]> {
        // Vec base slot representation: just the length
        Ok([U256::from(self.len())])
    }

    fn from_evm_words(_words: [U256; 1]) -> Result<Self> {
        Err(TempoPrecompileError::Fatal(
            "Cannot reconstruct `Vec` from base slot alone. Use `load()` with storage access."
                .into(),
        ))
    }
}

/// Extension trait providing efficient single-element operations for `Slot<Vec<T>, Id>`.
///
/// This trait adds methods for reading, writing, pushing, and popping individual
/// elements in a storage-backed vector without requiring a full vector load/store cycle.
pub trait VecSlotExt<T, Id>
where
    T: Storable<1> + StorableType,
    Id: SlotId,
{
    /// Returns the length of the vector.
    fn len<S: StorageOps>(storage: &mut S) -> Result<usize>;

    /// Reads a single element at the specified index.
    fn read_at<S: StorageOps>(storage: &mut S, index: usize) -> Result<T>;

    /// Writes a single element at the specified index.
    ///
    /// If the index is >= the current length, the vector is automatically expanded
    /// and the length is updated. Intermediate elements remain zero.
    fn write_at<S: StorageOps>(storage: &mut S, index: usize, value: T) -> Result<()>;

    /// Pushes a new element to the end of the vector.
    ///
    /// Automatically increments the length and handles packing for small types.
    fn push<S: StorageOps>(storage: &mut S, value: T) -> Result<()>;

    /// Pops the last element from the vector.
    ///
    /// Returns `None` if the vector is empty. Automatically decrements the length
    /// and zeros out the popped element's storage slot.
    fn pop<S: StorageOps>(storage: &mut S) -> Result<Option<T>>;
}

impl<T, Id> VecSlotExt<T, Id> for Slot<Vec<T>, Id>
where
    T: Storable<1> + StorableType,
    Id: SlotId,
{
    fn len<S: StorageOps>(storage: &mut S) -> Result<usize> {
        read_length(storage, Id::SLOT)
    }

    fn read_at<S: StorageOps>(storage: &mut S, index: usize) -> Result<T> {
        vec_read_at(storage, Id::SLOT, index)
    }

    fn write_at<S: StorageOps>(storage: &mut S, index: usize, value: T) -> Result<()> {
        vec_write_at(storage, Id::SLOT, index, value)
    }

    fn push<S: StorageOps>(storage: &mut S, value: T) -> Result<()> {
        vec_push(storage, Id::SLOT, value)
    }

    fn pop<S: StorageOps>(storage: &mut S) -> Result<Option<T>> {
        vec_pop(storage, Id::SLOT)
    }
}

// -- VEC MAPPING EXTENSION ----------------------------------------------------

/// Extension trait for efficient vector operations on `Mapping<K, Vec<V>, Id>`.
///
/// This trait adds methods for reading, writing, pushing, and popping individual
/// elements in a storage-backed vector without requiring a full vector load/store cycle.
pub trait VecMappingExt<K, V, Id>
where
    K: StorageKey,
    V: Storable<1> + StorableType,
    Id: SlotId,
{
    /// Returns the length of the vector for the given key.
    fn len<S: StorageOps>(storage: &mut S, key: K) -> Result<usize>;

    /// Reads a single element at the specified index for the given key.
    fn read_at<S: StorageOps>(storage: &mut S, key: K, index: usize) -> Result<V>;

    /// Writes a single element at the specified index for the given key.
    ///
    /// If the index is >= the current length, the vector is automatically expanded
    /// and the length is updated. Intermediate elements remain zero.
    fn write_at<S: StorageOps>(storage: &mut S, key: K, index: usize, value: V) -> Result<()>;

    /// Pushes a new element to the end of the vector for the given key.
    ///
    /// Automatically increments the length and handles packing for small types.
    fn push<S: StorageOps>(storage: &mut S, key: K, value: V) -> Result<()>;

    /// Pops the last element from the vector for the given key.
    ///
    /// Returns `None` if the vector is empty. Automatically decrements the length
    /// and zeros out the popped element's storage slot.
    fn pop<S: StorageOps>(storage: &mut S, key: K) -> Result<Option<V>>;
}

impl<K, V, Id> VecMappingExt<K, V, Id> for crate::storage::types::mapping::Mapping<K, Vec<V>, Id>
where
    K: StorageKey,
    V: Storable<1> + StorableType,
    Id: SlotId,
{
    fn len<S: StorageOps>(storage: &mut S, key: K) -> Result<usize> {
        read_length(storage, mapping_slot(key.as_storage_bytes(), Id::SLOT))
    }

    fn read_at<S: StorageOps>(storage: &mut S, key: K, index: usize) -> Result<V> {
        vec_read_at(
            storage,
            mapping_slot(key.as_storage_bytes(), Id::SLOT),
            index,
        )
    }

    fn write_at<S: StorageOps>(storage: &mut S, key: K, index: usize, value: V) -> Result<()> {
        vec_write_at(
            storage,
            mapping_slot(key.as_storage_bytes(), Id::SLOT),
            index,
            value,
        )
    }

    fn push<S: StorageOps>(storage: &mut S, key: K, value: V) -> Result<()> {
        vec_push(
            storage,
            mapping_slot(key.as_storage_bytes(), Id::SLOT),
            value,
        )
    }

    fn pop<S: StorageOps>(storage: &mut S, key: K) -> Result<Option<V>> {
        vec_pop(storage, mapping_slot(key.as_storage_bytes(), Id::SLOT))
    }
}

/// Calculate the starting slot for dynamic array data.
///
/// For Solidity compatibility, dynamic array data is stored at `keccak256(base_slot)`.
#[inline]
pub(crate) fn calc_data_slot(base_slot: U256) -> U256 {
    U256::from_be_bytes(alloy::primitives::keccak256(base_slot.to_be_bytes::<32>()).0)
}

/// Load packed elements from storage.
///
/// Used when `T::BYTE_COUNT < 32` and evenly divides 32, allowing multiple elements per slot.
fn load_packed_elements<T, S>(
    storage: &mut S,
    data_start: U256,
    length: usize,
    byte_count: usize,
) -> Result<Vec<T>>
where
    T: Storable<1> + StorableType,
    S: StorageOps,
{
    let elements_per_slot = 32 / byte_count;
    let slot_count = calc_packed_slot_count(length, byte_count);

    let mut result = Vec::with_capacity(length);
    let mut current_offset = 0;

    for slot_idx in 0..slot_count {
        let slot_addr = data_start + U256::from(slot_idx);
        let slot_value = storage.sload(slot_addr)?;

        // How many elements in this slot?
        let elements_in_this_slot = if slot_idx == slot_count - 1 {
            // Last slot might be partially filled
            length - (slot_idx * elements_per_slot)
        } else {
            elements_per_slot
        };

        // Extract each element from this slot
        for _ in 0..elements_in_this_slot {
            let elem = extract_packed_value::<T>(slot_value, current_offset, byte_count)?;
            result.push(elem);

            // Move to next element position
            current_offset += byte_count;
            if current_offset >= 32 {
                current_offset = 0;
            }
        }

        // Reset offset for next slot
        current_offset = 0;
    }

    Ok(result)
}

/// Store packed elements to storage.
///
/// Packs multiple small elements into each 32-byte slot using bit manipulation.
fn store_packed_elements<T, S>(
    elements: &[T],
    storage: &mut S,
    data_start: U256,
    byte_count: usize,
) -> Result<()>
where
    T: Storable<1> + StorableType,
    S: StorageOps,
{
    let elements_per_slot = 32 / byte_count;
    let slot_count = calc_packed_slot_count(elements.len(), byte_count);

    for slot_idx in 0..slot_count {
        let slot_addr = data_start + U256::from(slot_idx);
        let start_elem = slot_idx * elements_per_slot;
        let end_elem = (start_elem + elements_per_slot).min(elements.len());

        let slot_value = build_packed_slot(&elements[start_elem..end_elem], byte_count)?;
        storage.sstore(slot_addr, slot_value)?;
    }

    Ok(())
}

/// Build a packed storage slot from multiple elements.
///
/// Takes a slice of elements and packs them into a single U256 word.
fn build_packed_slot<T>(elements: &[T], byte_count: usize) -> Result<U256>
where
    T: Storable<1> + StorableType,
{
    let mut slot_value = U256::ZERO;
    let mut current_offset = 0;

    for elem in elements {
        slot_value = insert_packed_value(slot_value, elem, current_offset, byte_count)?;
        current_offset += byte_count;
    }

    Ok(slot_value)
}

/// Load unpacked elements from storage.
///
/// Used when elements don't pack efficiently (32 bytes or multi-slot types).
/// Each element occupies `T::SLOT_COUNT` consecutive slots.
fn load_unpacked_elements<T, S>(storage: &mut S, data_start: U256, length: usize) -> Result<Vec<T>>
where
    T: Storable<1>,
    S: StorageOps,
{
    let mut result = Vec::with_capacity(length);
    for index in 0..length {
        let elem = read_single_unpacked_element(storage, data_start, index)?;
        result.push(elem);
    }
    Ok(result)
}

/// Store unpacked elements to storage.
///
/// Each element uses its full `T::SLOT_COUNT` consecutive slots.
fn store_unpacked_elements<T, S>(elements: &[T], storage: &mut S, data_start: U256) -> Result<()>
where
    T: Storable<1>,
    S: StorageOps,
{
    for (elem_idx, elem) in elements.iter().enumerate() {
        let elem_slot = data_start + U256::from(elem_idx);
        elem.store(storage, elem_slot)?;
    }

    Ok(())
}

// -- SINGLE-ELEMENT HELPER FUNCTIONS ------------------------------------------

/// Read the length of a vector from its base slot.
#[inline]
pub(crate) fn read_length<S: StorageOps>(storage: &mut S, base_slot: U256) -> Result<usize> {
    let length_value = storage.sload(base_slot)?;
    Ok(length_value.to::<usize>())
}

/// Read a single packed element from storage.
pub(crate) fn read_single_packed_element<T, S>(
    storage: &mut S,
    data_start: U256,
    index: usize,
    byte_count: usize,
) -> Result<T>
where
    T: Storable<1> + StorableType,
    S: StorageOps,
{
    let slot_idx = calc_element_slot(index, byte_count);
    let offset = calc_element_offset(index, byte_count);

    let slot_addr = data_start + U256::from(slot_idx);
    let slot_value = storage.sload(slot_addr)?;

    extract_packed_value::<T>(slot_value, offset, byte_count)
}

/// Write a single packed element to storage.
pub(crate) fn write_single_packed_element<T, S>(
    storage: &mut S,
    data_start: U256,
    index: usize,
    byte_count: usize,
    value: T,
) -> Result<()>
where
    T: Storable<1> + StorableType,
    S: StorageOps,
{
    let offset = calc_element_offset(index, byte_count);
    modify_packed_element(storage, data_start, index, byte_count, |slot_value| {
        insert_packed_value(slot_value, &value, offset, byte_count)
    })
}

/// Zero out a single packed element in storage.
fn zero_single_packed_element<S: StorageOps>(
    storage: &mut S,
    data_start: U256,
    index: usize,
    byte_count: usize,
) -> Result<()> {
    let offset = calc_element_offset(index, byte_count);
    modify_packed_element(storage, data_start, index, byte_count, |slot_value| {
        zero_packed_value(slot_value, offset, byte_count)
    })
}

/// Helper to modify a single element within a packed storage slot.
fn modify_packed_element<S, F>(
    storage: &mut S,
    data_start: U256,
    index: usize,
    byte_count: usize,
    modify_fn: F,
) -> Result<()>
where
    S: StorageOps,
    F: FnOnce(U256) -> Result<U256>,
{
    let slot_idx = calc_element_slot(index, byte_count);
    let slot_addr = data_start + U256::from(slot_idx);
    let slot_value = storage.sload(slot_addr)?;
    let new_slot_value = modify_fn(slot_value)?;
    storage.sstore(slot_addr, new_slot_value)?;
    Ok(())
}

/// Read a single unpacked element from storage.
pub(crate) fn read_single_unpacked_element<T, S>(
    storage: &mut S,
    data_start: U256,
    index: usize,
) -> Result<T>
where
    T: Storable<1>,
    S: StorageOps,
{
    let elem_slot = data_start + U256::from(index);
    T::load(storage, elem_slot)
}

/// Write a single unpacked element to storage.
pub(crate) fn write_single_unpacked_element<T, S>(
    storage: &mut S,
    data_start: U256,
    index: usize,
    value: T,
) -> Result<()>
where
    T: Storable<1>,
    S: StorageOps,
{
    let elem_slot = data_start + U256::from(index);
    value.store(storage, elem_slot)
}

/// Zero out a single unpacked element in storage.
fn zero_single_unpacked_element<S: StorageOps>(
    storage: &mut S,
    data_start: U256,
    index: usize,
) -> Result<()> {
    let elem_slot = data_start + U256::from(index);
    storage.sstore(elem_slot, U256::ZERO)
}

// -- VEC OPERATION HELPERS ----------------------------------------------------

/// Generic helper to read a single element at the specified index from a vec.
fn vec_read_at<S, T>(storage: &mut S, base_slot: U256, index: usize) -> Result<T>
where
    S: StorageOps,
    T: Storable<1> + StorableType,
{
    let byte_count = T::BYTE_COUNT;
    let data_start = calc_data_slot(base_slot);

    if is_packable(byte_count) {
        read_single_packed_element(storage, data_start, index, byte_count)
    } else {
        read_single_unpacked_element(storage, data_start, index)
    }
}

/// Generic helper to write a single element at the specified index in a vec.
///
/// If the index is >= the current length, the vector is automatically expanded
/// and the length is updated.
fn vec_write_at<S, T>(storage: &mut S, base_slot: U256, index: usize, value: T) -> Result<()>
where
    S: StorageOps,
    T: Storable<1> + StorableType,
{
    let byte_count = T::BYTE_COUNT;
    let data_start = calc_data_slot(base_slot);
    let length = read_length(storage, base_slot)?;

    // Write the element
    if is_packable(byte_count) {
        write_single_packed_element(storage, data_start, index, byte_count, value)?;
    } else {
        write_single_unpacked_element(storage, data_start, index, value)?;
    }

    // Update length if necessary
    if index >= length {
        storage.sstore(base_slot, U256::from(index + 1))?;
    }

    Ok(())
}

/// Generic helper to push a new element to the end of a vec.
///
/// Automatically increments the length.
fn vec_push<S, T>(storage: &mut S, base_slot: U256, value: T) -> Result<()>
where
    S: StorageOps,
    T: Storable<1> + StorableType,
{
    let byte_count = T::BYTE_COUNT;
    let data_start = calc_data_slot(base_slot);
    let length = read_length(storage, base_slot)?;

    // Write at the end
    if is_packable(byte_count) {
        write_single_packed_element(storage, data_start, length, byte_count, value)?;
    } else {
        write_single_unpacked_element(storage, data_start, length, value)?;
    }

    // Increment length
    storage.sstore(base_slot, U256::from(length + 1))
}

/// Generic helper to pop the last element from a vec.
///
/// Returns `None` if the vector is empty. Automatically decrements the length
/// and zeros out the popped element's storage.
fn vec_pop<S, T>(storage: &mut S, base_slot: U256) -> Result<Option<T>>
where
    S: StorageOps,
    T: Storable<1> + StorableType,
{
    let byte_count = T::BYTE_COUNT;
    let data_start = calc_data_slot(base_slot);

    // Read current length
    let length = read_length(storage, base_slot)?;
    if length == 0 {
        return Ok(None);
    }
    let last_index = length - 1;

    // Read the last element
    let element = if is_packable(byte_count) {
        read_single_packed_element(storage, data_start, last_index, byte_count)?
    } else {
        read_single_unpacked_element(storage, data_start, last_index)?
    };

    // Zero out the element's storage
    if is_packable(byte_count) {
        zero_single_packed_element(storage, data_start, last_index, byte_count)?;
    } else {
        zero_single_unpacked_element(storage, data_start, last_index)?;
    }

    // Decrement length
    storage.sstore(base_slot, U256::from(last_index))?;

    Ok(Some(element))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{
        PrecompileStorageProvider, StorageOps, hashmap::HashMapStorageProvider,
        packing::gen_slot_from,
    };
    use alloy::primitives::Address;
    use proptest::prelude::*;
    use tempo_precompiles_macros::Storable;

    // -- TEST HELPERS -------------------------------------------------------------

    /// Test helper that owns storage and implements StorageOps.
    struct TestContract {
        address: Address,
        storage: HashMapStorageProvider,
    }

    impl StorageOps for TestContract {
        fn sstore(&mut self, slot: U256, value: U256) -> Result<()> {
            self.storage.sstore(self.address, slot, value)
        }

        fn sload(&mut self, slot: U256) -> Result<U256> {
            self.storage.sload(self.address, slot)
        }
    }

    /// Helper to create a test contract with fresh storage.
    fn setup_test_contract() -> TestContract {
        TestContract {
            address: Address::random(),
            storage: HashMapStorageProvider::new(1),
        }
    }

    /// Helper to extract and verify a packed value from a specific slot at a given offset.
    fn verify_packed_element<T>(
        contract: &mut TestContract,
        slot_addr: U256,
        expected: T,
        offset: usize,
        byte_count: usize,
        elem_name: &str,
    ) where
        T: Storable<1> + StorableType + PartialEq + std::fmt::Debug,
    {
        let slot_value = contract.sload(slot_addr).unwrap();
        let actual = extract_packed_value::<T>(slot_value, offset, byte_count).unwrap();
        assert_eq!(
            actual, expected,
            "{elem_name} at offset {offset} in slot {slot_addr:?} mismatch"
        );
    }

    // Strategy for generating random U256 slot values that won't overflow
    fn arb_safe_slot() -> impl Strategy<Value = U256> {
        any::<[u64; 4]>().prop_map(|limbs| {
            // Ensure we don't overflow by limiting to a reasonable range
            U256::from_limbs(limbs) % (U256::MAX - U256::from(10000))
        })
    }

    // Helper: Generate a single-slot struct for testing
    #[derive(Debug, Clone, PartialEq, Eq, Storable)]
    struct TestStruct {
        a: u128, // 16 bytes (slot 0)
        b: u128, // 16 bytes (slot 0)
    }

    #[test]
    fn test_vec_empty() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(400);

        let data: Vec<u8> = vec![];
        data.store(&mut contract, base_slot).unwrap();

        let loaded: Vec<u8> = Storable::load(&mut contract, base_slot).unwrap();
        assert_eq!(loaded, data, "Empty vec roundtrip failed");
        assert!(loaded.is_empty(), "Loaded vec should be empty");
    }

    #[test]
    fn test_vec_nested() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(800);

        // Nested Vec<Vec<u8>>
        let data = vec![vec![1u8, 2, 3], vec![4, 5], vec![6, 7, 8, 9]];
        data.store(&mut contract, base_slot).unwrap();

        let loaded: Vec<Vec<u8>> = Storable::load(&mut contract, base_slot).unwrap();
        assert_eq!(loaded, data, "Nested Vec<Vec<u8>> roundtrip failed");
    }

    #[test]
    fn test_vec_bool_packing() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(900);

        // Test 1: Exactly 32 bools (fills exactly 1 slot: 32 * 1 byte = 32 bytes)
        let data_exact: Vec<bool> = (0..32).map(|i| i % 2 == 0).collect();
        data_exact.store(&mut contract, base_slot).unwrap();

        // Verify length stored in base slot
        let length_value = contract.sload(base_slot).unwrap();
        assert_eq!(length_value, U256::from(32), "Length not stored correctly");

        let loaded: Vec<bool> = Storable::load(&mut contract, base_slot).unwrap();
        assert_eq!(
            loaded, data_exact,
            "Vec<bool> with 32 elements failed roundtrip"
        );

        // Test 2: 35 bools (requires 2 slots: 32 + 3)
        let data_overflow: Vec<bool> = (0..35).map(|i| i % 3 == 0).collect();
        data_overflow.store(&mut contract, base_slot).unwrap();

        let loaded: Vec<bool> = Storable::load(&mut contract, base_slot).unwrap();
        assert_eq!(
            loaded, data_overflow,
            "Vec<bool> with 35 elements failed roundtrip"
        );
    }

    // -- SLOT-LEVEL VALIDATION TESTS ----------------------------------------------

    #[test]
    fn test_vec_u8_explicit_slot_packing() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(2000);

        // Store exactly 5 u8 elements (should fit in 1 slot with 27 unused bytes)
        let data = vec![10u8, 20, 30, 40, 50];
        data.store(&mut contract, base_slot).unwrap();

        // Verify length stored in base slot
        let length_value = contract.sload(base_slot).unwrap();
        assert_eq!(length_value, U256::from(5), "Length not stored correctly");

        let data_start = calc_data_slot(base_slot);
        let slot_value = contract.sload(data_start).unwrap();

        // Expected byte layout: 5 u8 elements packed at rightmost positions
        let expected = gen_slot_from(&[
            "0x32", // elem[4] = 50
            "0x28", // elem[3] = 40
            "0x1e", // elem[2] = 30
            "0x14", // elem[1] = 20
            "0x0a", // elem[0] = 10
        ]);
        assert_eq!(
            slot_value, expected,
            "Slot should match Solidity byte layout"
        );

        // Also verify each element can be extracted correctly
        let byte_count = u8::BYTE_COUNT;
        verify_packed_element(&mut contract, data_start, 10u8, 0, byte_count, "elem[0]");
        verify_packed_element(&mut contract, data_start, 20u8, 1, byte_count, "elem[1]");
        verify_packed_element(&mut contract, data_start, 30u8, 2, byte_count, "elem[2]");
        verify_packed_element(&mut contract, data_start, 40u8, 3, byte_count, "elem[3]");
        verify_packed_element(&mut contract, data_start, 50u8, 4, byte_count, "elem[4]");
    }

    #[test]
    fn test_vec_u16_slot_boundary() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(2100);

        // Test 1: Exactly 16 u16 elements (fills exactly 1 slot: 16 * 2 bytes = 32 bytes)
        let data_exact: Vec<u16> = (0..16).map(|i| i * 100).collect();
        data_exact.store(&mut contract, base_slot).unwrap();

        let data_start = calc_data_slot(base_slot);
        let slot0_value = contract.sload(data_start).unwrap();

        let expected_slot0 = gen_slot_from(&[
            "0x05dc", // elem[15] = 1500
            "0x0578", // elem[14] = 1400
            "0x0514", // elem[13] = 1300
            "0x04b0", // elem[12] = 1200
            "0x044c", // elem[11] = 1100
            "0x03e8", // elem[10] = 1000
            "0x0384", // elem[9] = 900
            "0x0320", // elem[8] = 800
            "0x02bc", // elem[7] = 700
            "0x0258", // elem[6] = 600
            "0x01f4", // elem[5] = 500
            "0x0190", // elem[4] = 400
            "0x012c", // elem[3] = 300
            "0x00c8", // elem[2] = 200
            "0x0064", // elem[1] = 100
            "0x0000", // elem[0] = 0
        ]);
        assert_eq!(
            slot0_value, expected_slot0,
            "Slot 0 should match Solidity byte layout"
        );

        // Also verify each element can be extracted
        let byte_count = u16::BYTE_COUNT;
        for (i, &expected) in data_exact.iter().enumerate() {
            verify_packed_element(
                &mut contract,
                data_start,
                expected,
                i * byte_count,
                byte_count,
                &format!("elem[{i}]"),
            );
        }

        // Test 2: 17 u16 elements (requires 2 slots)
        let data_overflow: Vec<u16> = (0..17).map(|i| i * 100).collect();
        data_overflow.store(&mut contract, base_slot).unwrap();

        // Verify slot 0 still matches (first 16 elements)
        let slot0_value = contract.sload(data_start).unwrap();
        assert_eq!(
            slot0_value, expected_slot0,
            "Slot 0 should still match after overflow"
        );

        // Verify slot 1 has the 17th element (1600 = 0x0640)
        let slot1_addr = data_start + U256::ONE;
        let slot1_value = contract.sload(slot1_addr).unwrap();

        let expected_slot1 = gen_slot_from(&[
            "0x0640", // elem[16] = 1600
        ]);
        assert_eq!(
            slot1_value, expected_slot1,
            "Slot 1 should match Solidity byte layout"
        );

        // Also verify the 17th element can be extracted
        verify_packed_element(
            &mut contract,
            slot1_addr,
            1600u16,
            0,
            byte_count,
            "slot1_elem[0]",
        );
    }

    #[test]
    fn test_vec_u8_partial_slot_fill() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(2200);

        // Store 35 u8 elements (values 1-35):
        // - Slot 0: 32 elements (full) - elements 1-32
        // - Slot 1: 3 elements (elements 33-35) + 29 zeros
        let data: Vec<u8> = (0..35).map(|i| (i + 1) as u8).collect();
        data.store(&mut contract, base_slot).unwrap();
        let data_start = calc_data_slot(base_slot);
        let slot0_value = contract.sload(data_start).unwrap();

        let expected_slot0 = gen_slot_from(&[
            "0x20", // elem[31] = 32
            "0x1f", // elem[30] = 31
            "0x1e", // elem[29] = 30
            "0x1d", // elem[28] = 29
            "0x1c", // elem[27] = 28
            "0x1b", // elem[26] = 27
            "0x1a", // elem[25] = 26
            "0x19", // elem[24] = 25
            "0x18", // elem[23] = 24
            "0x17", // elem[22] = 23
            "0x16", // elem[21] = 22
            "0x15", // elem[20] = 21
            "0x14", // elem[19] = 20
            "0x13", // elem[18] = 19
            "0x12", // elem[17] = 18
            "0x11", // elem[16] = 17
            "0x10", // elem[15] = 16
            "0x0f", // elem[14] = 15
            "0x0e", // elem[13] = 14
            "0x0d", // elem[12] = 13
            "0x0c", // elem[11] = 12
            "0x0b", // elem[10] = 11
            "0x0a", // elem[9] = 10
            "0x09", // elem[8] = 9
            "0x08", // elem[7] = 8
            "0x07", // elem[6] = 7
            "0x06", // elem[5] = 6
            "0x05", // elem[4] = 5
            "0x04", // elem[3] = 4
            "0x03", // elem[2] = 3
            "0x02", // elem[1] = 2
            "0x01", // elem[0] = 1
        ]);
        assert_eq!(
            slot0_value, expected_slot0,
            "Slot 0 should match Solidity byte layout"
        );

        // Verify slot 1 has exactly 3 elements at rightmost positions
        let slot1_addr = data_start + U256::ONE;
        let slot1_value = contract.sload(slot1_addr).unwrap();

        let expected_slot1 = gen_slot_from(&[
            "0x23", // elem[2] = 35
            "0x22", // elem[1] = 34
            "0x21", // elem[0] = 33
        ]);
        assert_eq!(
            slot1_value, expected_slot1,
            "Slot 1 should match Solidity byte layout"
        );

        // Also verify each element in slot 1 can be extracted
        let byte_count = u8::BYTE_COUNT;
        verify_packed_element(
            &mut contract,
            slot1_addr,
            33u8,
            0,
            byte_count,
            "slot1_elem[0]",
        );
        verify_packed_element(
            &mut contract,
            slot1_addr,
            34u8,
            1,
            byte_count,
            "slot1_elem[1]",
        );
        verify_packed_element(
            &mut contract,
            slot1_addr,
            35u8,
            2,
            byte_count,
            "slot1_elem[2]",
        );
    }

    #[test]
    fn test_vec_u256_individual_slots() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(2300);

        // Store 3 U256 values (each should occupy its own slot)
        let data = vec![
            U256::from(0x1111111111111111u64),
            U256::from(0x2222222222222222u64),
            U256::from(0x3333333333333333u64),
        ];
        data.store(&mut contract, base_slot).unwrap();

        let data_start = calc_data_slot(base_slot);

        // Verify each U256 occupies its own sequential slot
        for (i, &expected) in data.iter().enumerate() {
            let slot_addr = data_start + U256::from(i);
            let stored_value = contract.sload(slot_addr).unwrap();
            assert_eq!(
                stored_value, expected,
                "U256 element {i} at slot {slot_addr:?} incorrect"
            );
        }

        // Verify there's no data in slot 3 (should be empty)
        let slot3_addr = data_start + U256::from(3);
        let slot3_value = contract.sload(slot3_addr).unwrap();
        assert_eq!(slot3_value, U256::ZERO, "Slot 3 should be empty");
    }

    #[test]
    fn test_vec_address_unpacked_slots() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(2400);

        // Store 3 addresses (each 20 bytes, but 32 % 20 != 0, so unpacked)
        let data = vec![
            Address::repeat_byte(0xAA),
            Address::repeat_byte(0xBB),
            Address::repeat_byte(0xCC),
        ];
        data.store(&mut contract, base_slot).unwrap();

        let data_start = calc_data_slot(base_slot);

        // Verify slot 0: Address(0xAA...) right-aligned with 12-byte padding
        let slot0_value = contract.sload(data_start).unwrap();
        let expected_slot0 = gen_slot_from(&["0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]);
        assert_eq!(
            slot0_value, expected_slot0,
            "Slot 0 should match Solidity byte layout"
        );

        // Verify slot 1: Address(0xBB...) right-aligned with 12-byte padding
        let slot1_addr = data_start + U256::ONE;
        let slot1_value = contract.sload(slot1_addr).unwrap();
        let expected_slot1 = gen_slot_from(&["0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"]);
        assert_eq!(
            slot1_value, expected_slot1,
            "Slot 1 should match Solidity byte layout"
        );

        // Verify slot 2: Address(0xCC...) right-aligned with 12-byte padding
        let slot2_addr = data_start + U256::from(2);
        let slot2_value = contract.sload(slot2_addr).unwrap();
        let expected_slot2 = gen_slot_from(&["0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"]);
        assert_eq!(
            slot2_value, expected_slot2,
            "Slot 2 should match Solidity byte layout"
        );

        // Also verify addresses can be loaded back
        for (i, &expected_addr) in data.iter().enumerate() {
            let slot_addr = data_start + U256::from(i);
            let stored_value = contract.sload(slot_addr).unwrap();
            let expected_u256 = U256::from_be_slice(expected_addr.as_slice());
            assert_eq!(
                stored_value, expected_u256,
                "Address element {i} should match"
            );
        }
    }

    #[test]
    fn test_vec_struct_slot_allocation() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(2500);

        // Store Vec<TestStruct> with 3 single-slot structs
        // Each TestStruct has two u128 fields (a, b) packed into one 32-byte slot
        let data = vec![
            TestStruct { a: 100, b: 1 },
            TestStruct { a: 200, b: 2 },
            TestStruct { a: 300, b: 3 },
        ];
        data.store(&mut contract, base_slot).unwrap();

        let data_start = calc_data_slot(base_slot);

        // Verify slot 0: TestStruct { a: 100, b: 1 }
        // Note: Solidity packs struct fields right-to-left (declaration order reversed in memory)
        // So field b (declared second) goes in bytes 0-15, field a (declared first) goes in bytes 16-31
        let slot0_value = contract.sload(data_start).unwrap();
        let expected_slot0 = gen_slot_from(&[
            "0x00000000000000000000000000000001", // field b = 1
            "0x00000000000000000000000000000064", // field a = 100
        ]);
        assert_eq!(
            slot0_value, expected_slot0,
            "Slot 0 should match Solidity byte layout"
        );

        // Verify slot 1: TestStruct { a: 200, b: 2 }
        let slot1_addr = data_start + U256::ONE;
        let slot1_value = contract.sload(slot1_addr).unwrap();
        let expected_slot1 = gen_slot_from(&[
            "0x00000000000000000000000000000002", // field b = 2
            "0x000000000000000000000000000000C8", // field a = 200
        ]);
        assert_eq!(
            slot1_value, expected_slot1,
            "Slot 1 should match Solidity byte layout"
        );

        // Verify slot 2: TestStruct { a: 300, b: 3 }
        let slot2_addr = data_start + U256::from(2);
        let slot2_value = contract.sload(slot2_addr).unwrap();
        let expected_slot2 = gen_slot_from(&[
            "0x00000000000000000000000000000003", // field b = 3
            "0x0000000000000000000000000000012C", // field a = 300
        ]);
        assert_eq!(
            slot2_value, expected_slot2,
            "Slot 2 should match Solidity byte layout"
        );

        // Verify slot 3 is empty (no 4th element)
        let slot3_addr = data_start + U256::from(3);
        let slot3_value = contract.sload(slot3_addr).unwrap();
        assert_eq!(slot3_value, U256::ZERO, "Slot 3 should be empty");

        // Also verify each struct can be loaded back correctly
        for (i, expected_struct) in data.iter().enumerate() {
            let struct_slot = data_start + U256::from(i);
            let loaded_struct = TestStruct::load(&mut contract, struct_slot).unwrap();
            assert_eq!(
                loaded_struct, *expected_struct,
                "TestStruct at slot {i} should match"
            );
        }
    }

    #[test]
    fn test_vec_small_struct_storage() {
        // Test that single-slot structs are stored correctly in Vec
        // NOTE: Structs always have BYTE_COUNT = 32 (even if they only use part of the slot),
        // so they DON'T pack - each struct uses its own full slot. Only primitives pack.
        #[derive(Debug, Clone, PartialEq, Eq, Storable)]
        struct SmallStruct {
            flag1: bool, // offset 0 (1 byte)
            flag2: bool, // offset 1 (1 byte)
            value: u16,  // offset 2 (2 bytes)
        }

        let mut contract = setup_test_contract();
        let base_slot = U256::from(2550);

        // Store 3 SmallStruct elements
        // Each struct uses 1 full slot (even though it only occupies 4 bytes)
        let data = vec![
            SmallStruct {
                flag1: true,
                flag2: false,
                value: 100,
            },
            SmallStruct {
                flag1: false,
                flag2: true,
                value: 200,
            },
            SmallStruct {
                flag1: true,
                flag2: true,
                value: 300,
            },
        ];
        data.store(&mut contract, base_slot).unwrap();

        // Verify length stored in base slot
        let length_value = contract.sload(base_slot).unwrap();
        assert_eq!(length_value, U256::from(3), "Length not stored correctly");

        let data_start = calc_data_slot(base_slot);

        // Verify slot 0: first struct (fields packed within the struct)
        let slot0_value = contract.sload(data_start).unwrap();
        let expected_slot0 = gen_slot_from(&[
            "0x0064", // value = 100 (offset 2-3, 2 bytes)
            "0x00",   // flag2 = false (offset 1, 1 byte)
            "0x01",   // flag1 = true (offset 0, 1 byte)
        ]);
        assert_eq!(
            slot0_value, expected_slot0,
            "Slot 0 should match Solidity layout for struct[0]"
        );

        // Verify slot 1: second struct
        let slot1_addr = data_start + U256::ONE;
        let slot1_value = contract.sload(slot1_addr).unwrap();
        let expected_slot1 = gen_slot_from(&[
            "0x00c8", // value = 200 (offset 2-3, 2 bytes)
            "0x01",   // flag2 = true (offset 1, 1 byte)
            "0x00",   // flag1 = false (offset 0, 1 byte)
        ]);
        assert_eq!(
            slot1_value, expected_slot1,
            "Slot 1 should match Solidity layout for struct[1]"
        );

        // Verify slot 2: third struct
        let slot2_addr = data_start + U256::from(2);
        let slot2_value = contract.sload(slot2_addr).unwrap();
        let expected_slot2 = gen_slot_from(&[
            "0x012c", // value = 300 (offset 2-3, 2 bytes)
            "0x01",   // flag2 = true (offset 1, 1 byte)
            "0x01",   // flag1 = true (offset 0, 1 byte)
        ]);
        assert_eq!(
            slot2_value, expected_slot2,
            "Slot 2 should match Solidity layout for struct[2]"
        );

        // Verify roundtrip
        let loaded: Vec<SmallStruct> = Storable::load(&mut contract, base_slot).unwrap();
        assert_eq!(loaded, data, "Vec<SmallStruct> roundtrip failed");
    }

    #[test]
    fn test_vec_length_slot_isolation() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(2600);

        // Store a vec with 3 u8 elements
        let data = vec![100u8, 200, 250];
        data.store(&mut contract, base_slot).unwrap();

        // Verify base slot contains length
        let length_value = contract.sload(base_slot).unwrap();
        assert_eq!(length_value, U256::from(3), "Length slot incorrect");

        // Verify data starts at keccak256(base_slot), not base_slot + 1
        let data_start = calc_data_slot(base_slot);
        assert_ne!(
            data_start,
            base_slot + U256::ONE,
            "Data should not start immediately after base slot"
        );

        // Verify data slot matches expected Solidity byte layout
        let data_slot_value = contract.sload(data_start).unwrap();

        let expected = gen_slot_from(&[
            "0xfa", // elem[2] = 250
            "0xc8", // elem[1] = 200
            "0x64", // elem[0] = 100
        ]);
        assert_eq!(
            data_slot_value, expected,
            "Data slot should match Solidity byte layout"
        );

        // Also verify each element can be extracted
        verify_packed_element(&mut contract, data_start, 100u8, 0, 1, "elem[0]");
        verify_packed_element(&mut contract, data_start, 200u8, 1, 1, "elem[1]");
        verify_packed_element(&mut contract, data_start, 250u8, 2, 1, "elem[2]");
    }

    #[test]
    fn test_vec_overwrite_cleanup() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(2700);

        // Store a vec with 5 u8 elements (requires 1 slot)
        let data_long = vec![1u8, 2, 3, 4, 5];
        data_long.store(&mut contract, base_slot).unwrap();

        let data_start = calc_data_slot(base_slot);

        // Verify initial storage
        let slot0_before = contract.sload(data_start).unwrap();
        assert_ne!(slot0_before, U256::ZERO, "Initial data should be stored");

        // Overwrite with a shorter vec (3 elements)
        let data_short = vec![10u8, 20, 30];
        data_short.store(&mut contract, base_slot).unwrap();

        // Verify length updated
        let length_value = contract.sload(base_slot).unwrap();
        assert_eq!(length_value, U256::from(3), "Length should be updated");

        // Verify new data can be extracted correctly (even though old data might remain)
        verify_packed_element(&mut contract, data_start, 10u8, 0, 1, "new_elem[0]");
        verify_packed_element(&mut contract, data_start, 20u8, 1, 1, "new_elem[1]");
        verify_packed_element(&mut contract, data_start, 30u8, 2, 1, "new_elem[2]");

        let loaded: Vec<u8> = Storable::load(&mut contract, base_slot).unwrap();
        assert_eq!(loaded, data_short, "Loaded vec should match short version");
        assert_eq!(loaded.len(), 3, "Length should be 3");

        // For full cleanup, delete first, then store
        Vec::<u8>::delete(&mut contract, base_slot).unwrap();
        data_short.store(&mut contract, base_slot).unwrap();

        // Verify slot matches expected Solidity byte layout after delete+store
        let slot0_after_delete = contract.sload(data_start).unwrap();

        let expected = gen_slot_from(&[
            "0x1e", // elem[2] = 30
            "0x14", // elem[1] = 20
            "0x0a", // elem[0] = 10
        ]);
        assert_eq!(
            slot0_after_delete, expected,
            "Slot should match Solidity byte layout after delete+store"
        );

        // Also verify each element can still be extracted
        verify_packed_element(&mut contract, data_start, 10u8, 0, 1, "elem[0]");
        verify_packed_element(&mut contract, data_start, 20u8, 1, 1, "elem[1]");
        verify_packed_element(&mut contract, data_start, 30u8, 2, 1, "elem[2]");
    }

    // TODO(rusowsky): Implement and test multi-slot support
    // fn test_multi_slot_array() {
    //     #[derive(Storable)]
    //     struct MultiSlotStruct {
    //         field1: U256, // slot 0
    //         field2: U256, // slot 1
    //         field3: U256, // slot 2
    //     }

    //     let mut contract = setup_test_contract();
    //     let base_slot = U256::from(2700);

    //     let data: Vec<MultiSlotStruct> = vec![MultiSlotStruct {
    //         field1: U256::ONE,
    //         field2: U256::from(2),
    //         field3: U256::from(3),
    //     }];

    //     data.store(&mut contract, base_slot).unwrap();

    //     let data_start = calc_data_slot(base_slot);
    // }

    // -- PROPTEST STRATEGIES ------------------------------------------------------

    prop_compose! {
        fn arb_u8_vec(max_len: usize) (vec in prop::collection::vec(any::<u8>(), 0..=max_len)) -> Vec<u8> {
            vec
        }
    }

    prop_compose! {
        fn arb_u16_vec(max_len: usize) (vec in prop::collection::vec(any::<u16>(), 0..=max_len)) -> Vec<u16> {
            vec
        }
    }

    prop_compose! {
        fn arb_u32_vec(max_len: usize) (vec in prop::collection::vec(any::<u32>(), 0..=max_len)) -> Vec<u32> {
            vec
        }
    }

    prop_compose! {
        fn arb_u64_vec(max_len: usize) (vec in prop::collection::vec(any::<u64>(), 0..=max_len)) -> Vec<u64> {
            vec
        }
    }

    prop_compose! {
        fn arb_u128_vec(max_len: usize) (vec in prop::collection::vec(any::<u128>(), 0..=max_len)) -> Vec<u128> {
            vec
        }
    }

    prop_compose! {
        fn arb_u256_vec(max_len: usize) (vec in prop::collection::vec(any::<u64>(), 0..=max_len)) -> Vec<U256> {
            vec.into_iter().map(U256::from).collect()
        }
    }

    prop_compose! {
        fn arb_address_vec(max_len: usize) (vec in prop::collection::vec(any::<[u8; 20]>(), 0..=max_len)) -> Vec<Address> {
            vec.into_iter().map(Address::from).collect()
        }
    }

    prop_compose! {
        fn arb_test_struct() (a in any::<u64>(), b in any::<u64>()) -> TestStruct {
            TestStruct {
                a: a as u128,
                b: b as u128,
            }
        }
    }

    prop_compose! {
        fn arb_test_struct_vec(max_len: usize)
                              (vec in prop::collection::vec(arb_test_struct(), 0..=max_len))
                              -> Vec<TestStruct> {
            vec
        }
    }

    // -- PROPERTY TESTS -----------------------------------------------------------

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]
        #[test]
        fn proptest_vec_u8_roundtrip(data in arb_u8_vec(100), base_slot in arb_safe_slot()) {
            let mut contract = setup_test_contract();
            let data_len = data.len();

            // Store → Load roundtrip
            data.store(&mut contract, base_slot)?;
            let loaded: Vec<u8> = Storable::load(&mut contract, base_slot)?;
            prop_assert_eq!(&loaded, &data, "Vec<u8> roundtrip failed");

            // Delete + verify cleanup
            Vec::<u8>::delete(&mut contract, base_slot)?;
            let after_delete: Vec<u8> = Storable::load(&mut contract, base_slot)?;
            prop_assert!(after_delete.is_empty(), "Vec not empty after delete");

            // Verify data slots are cleared (if length > 0)
            if data_len > 0 {
                let data_start = calc_data_slot(base_slot);
                let byte_count = u8::BYTE_COUNT;
                let slot_count = calc_packed_slot_count(data_len, byte_count);

                for i in 0..slot_count {
                    let slot_value = contract.sload(data_start + U256::from(i))?;
                    prop_assert_eq!(slot_value, U256::ZERO, "Data slot {} not cleared", i);
                }
            }

            // EVM words roundtrip (should error)
            let words = data.to_evm_words()?;
            let result = Vec::<u8>::from_evm_words(words);
            prop_assert!(result.is_err(), "Vec should not be reconstructable from base slot alone");
        }

        #[test]
        fn proptest_vec_u16_roundtrip(data in arb_u16_vec(100), base_slot in arb_safe_slot()) {
            let mut contract = setup_test_contract();
            let data_len = data.len();

            // Store → Load roundtrip
            data.store(&mut contract, base_slot)?;
            let loaded: Vec<u16> = Storable::load(&mut contract, base_slot)?;
            prop_assert_eq!(&loaded, &data, "Vec<u16> roundtrip failed");

            // Delete + verify cleanup
            Vec::<u16>::delete(&mut contract, base_slot)?;
            let after_delete: Vec<u16> = Storable::load(&mut contract, base_slot)?;
            prop_assert!(after_delete.is_empty(), "Vec not empty after delete");

            // Verify data slots are cleared (if length > 0)
            if data_len > 0 {
                let data_start = calc_data_slot(base_slot);
                let byte_count = u16::BYTE_COUNT;
                let slot_count = calc_packed_slot_count(data_len, byte_count);

                for i in 0..slot_count {
                    let slot_value = contract.sload(data_start + U256::from(i))?;
                    prop_assert_eq!(slot_value, U256::ZERO, "Data slot {} not cleared", i);
                }
            }

            // EVM words roundtrip (should error)
            let words = data.to_evm_words()?;
            let result = Vec::<u16>::from_evm_words(words);
            prop_assert!(result.is_err(), "Vec should not be reconstructable from base slot alone");
        }

        #[test]
        fn proptest_vec_u32_roundtrip(data in arb_u32_vec(100), base_slot in arb_safe_slot()) {
            let mut contract = setup_test_contract();
            let data_len = data.len();

            // Store → Load roundtrip
            data.store(&mut contract, base_slot)?;
            let loaded: Vec<u32> = Storable::load(&mut contract, base_slot)?;
            prop_assert_eq!(&loaded, &data, "Vec<u32> roundtrip failed");

            // Delete + verify cleanup
            Vec::<u32>::delete(&mut contract, base_slot)?;
            let after_delete: Vec<u32> = Storable::load(&mut contract, base_slot)?;
            prop_assert!(after_delete.is_empty(), "Vec not empty after delete");

            // Verify data slots are cleared (if length > 0)
            if data_len > 0 {
                let data_start = calc_data_slot(base_slot);
                let byte_count = u32::BYTE_COUNT;
                let slot_count = calc_packed_slot_count(data_len, byte_count);

                for i in 0..slot_count {
                    let slot_value = contract.sload(data_start + U256::from(i))?;
                    prop_assert_eq!(slot_value, U256::ZERO, "Data slot {} not cleared", i);
                }
            }
        }

        #[test]
        fn proptest_vec_u64_roundtrip(data in arb_u64_vec(100), base_slot in arb_safe_slot()) {
            let mut contract = setup_test_contract();
            let data_len = data.len();

            // Store → Load roundtrip
            data.store(&mut contract, base_slot)?;
            let loaded: Vec<u64> = Storable::load(&mut contract, base_slot)?;
            prop_assert_eq!(&loaded, &data, "Vec<u64> roundtrip failed");

            // Delete + verify cleanup
            Vec::<u64>::delete(&mut contract, base_slot)?;
            let after_delete: Vec<u64> = Storable::load(&mut contract, base_slot)?;
            prop_assert!(after_delete.is_empty(), "Vec not empty after delete");

            // Verify data slots are cleared (if length > 0)
            if data_len > 0 {
                let data_start = calc_data_slot(base_slot);
                let byte_count = u64::BYTE_COUNT;
                let slot_count = calc_packed_slot_count(data_len, byte_count);

                for i in 0..slot_count {
                    let slot_value = contract.sload(data_start + U256::from(i))?;
                    prop_assert_eq!(slot_value, U256::ZERO, "Data slot {} not cleared", i);
                }
            }
        }

        #[test]
        fn proptest_vec_u128_roundtrip(data in arb_u128_vec(50), base_slot in arb_safe_slot()) {
            let mut contract = setup_test_contract();
            let data_len = data.len();

            // Store → Load roundtrip
            data.store(&mut contract, base_slot)?;
            let loaded: Vec<u128> = Storable::load(&mut contract, base_slot)?;
            prop_assert_eq!(&loaded, &data, "Vec<u128> roundtrip failed");

            // Delete + verify cleanup
            Vec::<u128>::delete(&mut contract, base_slot)?;
            let after_delete: Vec<u128> = Storable::load(&mut contract, base_slot)?;
            prop_assert!(after_delete.is_empty(), "Vec not empty after delete");

            // Verify data slots are cleared (if length > 0)
            if data_len > 0 {
                let data_start = calc_data_slot(base_slot);
                let byte_count = u128::BYTE_COUNT;
                let slot_count = calc_packed_slot_count(data_len, byte_count);

                for i in 0..slot_count {
                    let slot_value = contract.sload(data_start + U256::from(i))?;
                    prop_assert_eq!(slot_value, U256::ZERO, "Data slot {} not cleared", i);
                }
            }
        }

        #[test]
        fn proptest_vec_u256_roundtrip(data in arb_u256_vec(50), base_slot in arb_safe_slot()) {
            let mut contract = setup_test_contract();
            let data_len = data.len();

            // Store → Load roundtrip
            data.store(&mut contract, base_slot)?;
            let loaded: Vec<U256> = Storable::load(&mut contract, base_slot)?;
            prop_assert_eq!(&loaded, &data, "Vec<U256> roundtrip failed");

            // Delete + verify cleanup
            Vec::<U256>::delete(&mut contract, base_slot)?;
            let after_delete: Vec<U256> = Storable::load(&mut contract, base_slot)?;
            prop_assert!(after_delete.is_empty(), "Vec not empty after delete");

            // Verify data slots are cleared (if length > 0)
            if data_len > 0 {
                let data_start = calc_data_slot(base_slot);

                for i in 0..data_len {
                    let slot_value = contract.sload(data_start + U256::from(i))?;
                    prop_assert_eq!(slot_value, U256::ZERO, "Data slot {} not cleared", i);
                }
            }

            // EVM words roundtrip (should error)
            let words = data.to_evm_words()?;
            let result = Vec::<U256>::from_evm_words(words);
            prop_assert!(result.is_err(), "Vec should not be reconstructable from base slot alone");
        }

        #[test]
        fn proptest_vec_address_roundtrip(data in arb_address_vec(50), base_slot in arb_safe_slot()) {
            let mut contract = setup_test_contract();
            let data_len = data.len();

            // Store → Load roundtrip
            data.store(&mut contract, base_slot)?;
            let loaded: Vec<Address> = Storable::load(&mut contract, base_slot)?;
            prop_assert_eq!(&loaded, &data, "Vec<Address> roundtrip failed");

            // Delete + verify cleanup
            Vec::<Address>::delete(&mut contract, base_slot)?;
            let after_delete: Vec<Address> = Storable::load(&mut contract, base_slot)?;
            prop_assert!(after_delete.is_empty(), "Vec not empty after delete");

            // Verify data slots are cleared (if length > 0)
            // Address is 20 bytes, but 32 % 20 != 0, so they don't pack and each uses one slot
            if data_len > 0 {
                let data_start = calc_data_slot(base_slot);

                for i in 0..data_len {
                    let slot_value = contract.sload(data_start + U256::from(i))?;
                    prop_assert_eq!(slot_value, U256::ZERO, "Data slot {} not cleared", i);
                }
            }

            // EVM words roundtrip (should error)
            let words = data.to_evm_words()?;
            let result = Vec::<Address>::from_evm_words(words);
            prop_assert!(result.is_err(), "Vec should not be reconstructable from base slot alone");
        }

        #[test]
        fn proptest_vec_delete(data in arb_u8_vec(100), base_slot in arb_safe_slot()) {
            let mut contract = setup_test_contract();

            // Store data
            data.store(&mut contract, base_slot)?;

            // Delete
            Vec::<u8>::delete(&mut contract, base_slot)?;

            // Verify empty after delete
            let loaded: Vec<u8> = Storable::load(&mut contract, base_slot)?;
            prop_assert!(loaded.is_empty(), "Vec not empty after delete");

            // Verify data slots are cleared (if length > 0)
            if !data.is_empty() {
                let data_start = calc_data_slot(base_slot);
                let byte_count = u8::BYTE_COUNT;
                let slot_count = calc_packed_slot_count(data.len(), byte_count);

                for i in 0..slot_count {
                    let slot_value = contract.sload(data_start + U256::from(i))?;
                    prop_assert_eq!(slot_value, U256::ZERO, "Data slot {} not cleared", i);
                }
            }
        }

        #[test]
        fn proptest_vec_struct_roundtrip(data in arb_test_struct_vec(50), base_slot in arb_safe_slot()) {
            let mut contract = setup_test_contract();
            let data_len = data.len();

            // Store → Load roundtrip
            data.store(&mut contract, base_slot)?;
            let loaded: Vec<TestStruct> = Storable::load(&mut contract, base_slot)?;
            prop_assert_eq!(&loaded, &data, "Vec<TestStruct> roundtrip failed");

            // Delete + verify cleanup
            Vec::<TestStruct>::delete(&mut contract, base_slot)?;
            let after_delete: Vec<TestStruct> = Storable::load(&mut contract, base_slot)?;
            prop_assert!(after_delete.is_empty(), "Vec not empty after delete");

            // Verify data slots are cleared (if length > 0)
            if data_len > 0 {
                let data_start = calc_data_slot(base_slot);

                for i in 0..data_len {
                    let slot_value = contract.sload(data_start + U256::from(i))?;
                    prop_assert_eq!(slot_value, U256::ZERO, "Data slot {} not cleared", i);
                }
            }

            // EVM words roundtrip (should error)
            let words = data.to_evm_words()?;
            let result = Vec::<TestStruct>::from_evm_words(words);
            prop_assert!(result.is_err(), "Vec should not be reconstructable from base slot alone");
        }
    }

    // Additional test SlotId for VecSlotExt tests
    struct TestVecSlot2;
    impl SlotId for TestVecSlot2 {
        const SLOT: U256 = U256::from_limbs([5000, 0, 0, 0]);
    }

    // -- UNIT TESTS: PACKED TYPES (u8, u16) ----------------------------------

    #[test]
    fn test_vecext_push_and_read_at_u8() {
        let mut contract = setup_test_contract();
        type VecSlot = Slot<Vec<u8>, TestVecSlot2>;

        // Push 5 elements
        for i in 0..5 {
            VecSlot::push(&mut contract, i * 10).unwrap();
        }

        // Read each element
        for i in 0..5 {
            let value = VecSlot::read_at(&mut contract, i).unwrap();
            assert_eq!(value, i as u8 * 10, "Element {i} mismatch");
        }

        // Verify length
        let length = read_length(&mut contract, TestVecSlot2::SLOT).unwrap();
        assert_eq!(length, 5, "Length should be 5");
    }

    #[test]
    fn test_vecext_write_at_existing() {
        let mut contract = setup_test_contract();
        type VecSlot = Slot<Vec<u8>, TestVecSlot2>;

        // Push 3 elements
        VecSlot::push(&mut contract, 10).unwrap();
        VecSlot::push(&mut contract, 20).unwrap();
        VecSlot::push(&mut contract, 30).unwrap();

        // Update middle element
        VecSlot::write_at(&mut contract, 1, 99).unwrap();

        // Verify all elements
        assert_eq!(VecSlot::read_at(&mut contract, 0).unwrap(), 10);
        assert_eq!(VecSlot::read_at(&mut contract, 1).unwrap(), 99);
        assert_eq!(VecSlot::read_at(&mut contract, 2).unwrap(), 30);

        // Length should still be 3
        let length = read_length(&mut contract, TestVecSlot2::SLOT).unwrap();
        assert_eq!(length, 3);
    }

    #[test]
    fn test_vecext_write_at_auto_expand() {
        let mut contract = setup_test_contract();
        type VecSlot = Slot<Vec<u8>, TestVecSlot2>;

        // Write at index 10 (vec is empty, so this expands)
        VecSlot::write_at(&mut contract, 10, 42).unwrap();

        // Length should be 11
        let length = read_length(&mut contract, TestVecSlot2::SLOT).unwrap();
        assert_eq!(length, 11);

        // Element at index 10 should be 42
        assert_eq!(VecSlot::read_at(&mut contract, 10).unwrap(), 42);

        // Intermediate elements should be 0 (default)
        for i in 0..10 {
            assert_eq!(
                VecSlot::read_at(&mut contract, i).unwrap(),
                0,
                "Intermediate element {i} should be 0"
            );
        }
    }

    #[test]
    fn test_vecext_pop_u8() {
        let mut contract = setup_test_contract();
        type VecSlot = Slot<Vec<u8>, TestVecSlot2>;

        // Push 3 elements
        VecSlot::push(&mut contract, 10).unwrap();
        VecSlot::push(&mut contract, 20).unwrap();
        VecSlot::push(&mut contract, 30).unwrap();

        // Pop and verify
        assert_eq!(VecSlot::pop(&mut contract).unwrap(), Some(30));
        assert_eq!(VecSlot::pop(&mut contract).unwrap(), Some(20));
        assert_eq!(VecSlot::pop(&mut contract).unwrap(), Some(10));
        assert_eq!(VecSlot::pop(&mut contract).unwrap(), None);

        // Length should be 0
        let length = read_length(&mut contract, TestVecSlot2::SLOT).unwrap();
        assert_eq!(length, 0);
    }

    #[test]
    fn test_vecext_len() {
        let mut contract = setup_test_contract();
        type VecSlot = Slot<Vec<u8>, TestVecSlot2>;

        // Initial length should be 0
        assert_eq!(VecSlot::len(&mut contract).unwrap(), 0);

        // Push 3 elements
        VecSlot::push(&mut contract, 10).unwrap();
        assert_eq!(VecSlot::len(&mut contract).unwrap(), 1);

        VecSlot::push(&mut contract, 20).unwrap();
        assert_eq!(VecSlot::len(&mut contract).unwrap(), 2);

        VecSlot::push(&mut contract, 30).unwrap();
        assert_eq!(VecSlot::len(&mut contract).unwrap(), 3);

        // Pop and verify length decreases
        VecSlot::pop(&mut contract).unwrap();
        assert_eq!(VecSlot::len(&mut contract).unwrap(), 2);

        VecSlot::pop(&mut contract).unwrap();
        assert_eq!(VecSlot::len(&mut contract).unwrap(), 1);

        VecSlot::pop(&mut contract).unwrap();
        assert_eq!(VecSlot::len(&mut contract).unwrap(), 0);
    }

    #[test]
    fn test_vecext_u8_packing_multiple_per_slot() {
        let mut contract = setup_test_contract();
        type VecSlot = Slot<Vec<u8>, TestVecSlot2>;

        // Push 33 elements (should use 2 slots: 32 + 1)
        for i in 0..33 {
            VecSlot::push(&mut contract, i as u8).unwrap();
        }

        // Verify all elements
        for i in 0..33 {
            assert_eq!(VecSlot::read_at(&mut contract, i).unwrap(), i as u8);
        }

        // Update element 31 (last in first slot)
        VecSlot::write_at(&mut contract, 31, 255).unwrap();
        assert_eq!(VecSlot::read_at(&mut contract, 31).unwrap(), 255);

        // Update element 32 (first in second slot)
        VecSlot::write_at(&mut contract, 32, 254).unwrap();
        assert_eq!(VecSlot::read_at(&mut contract, 32).unwrap(), 254);
    }

    #[test]
    fn test_vecext_u16_packing() {
        let mut contract = setup_test_contract();
        type VecSlot = Slot<Vec<u16>, TestVecSlot2>;

        // u16 packs 16 per slot
        // Push 17 elements (should use 2 slots)
        for i in 0..17 {
            VecSlot::push(&mut contract, (i * 100) as u16).unwrap();
        }

        // Verify all elements
        for i in 0..17 {
            assert_eq!(
                VecSlot::read_at(&mut contract, i).unwrap(),
                (i * 100) as u16
            );
        }

        // Update element across slot boundary
        VecSlot::write_at(&mut contract, 15, 9999).unwrap();
        assert_eq!(VecSlot::read_at(&mut contract, 15).unwrap(), 9999);
    }

    // -- UNIT TESTS: UNPACKED TYPES (U256, Address) --------------------------

    #[test]
    fn test_vecext_push_and_read_at_u256() {
        let mut contract = setup_test_contract();
        type VecSlot = Slot<Vec<U256>, TestVecSlot2>;

        // Push 3 U256 values
        VecSlot::push(&mut contract, U256::from(111)).unwrap();
        VecSlot::push(&mut contract, U256::from(222)).unwrap();
        VecSlot::push(&mut contract, U256::from(333)).unwrap();

        // Read each
        assert_eq!(VecSlot::read_at(&mut contract, 0).unwrap(), U256::from(111));
        assert_eq!(VecSlot::read_at(&mut contract, 1).unwrap(), U256::from(222));
        assert_eq!(VecSlot::read_at(&mut contract, 2).unwrap(), U256::from(333));
    }

    #[test]
    fn test_vecext_write_at_u256_auto_expand() {
        let mut contract = setup_test_contract();
        type VecSlot = Slot<Vec<U256>, TestVecSlot2>;

        // Write at index 5 (auto-expand)
        VecSlot::write_at(&mut contract, 5, U256::from(999)).unwrap();

        // Length should be 6
        let length = read_length(&mut contract, TestVecSlot2::SLOT).unwrap();
        assert_eq!(length, 6);

        // Element at index 5 should be 999
        assert_eq!(VecSlot::read_at(&mut contract, 5).unwrap(), U256::from(999));

        // Intermediate elements should be 0
        for i in 0..5 {
            assert_eq!(VecSlot::read_at(&mut contract, i).unwrap(), U256::ZERO);
        }
    }

    #[test]
    fn test_vecext_pop_u256() {
        let mut contract = setup_test_contract();
        type VecSlot = Slot<Vec<U256>, TestVecSlot2>;

        VecSlot::push(&mut contract, U256::from(100)).unwrap();
        VecSlot::push(&mut contract, U256::from(200)).unwrap();

        assert_eq!(VecSlot::pop(&mut contract).unwrap(), Some(U256::from(200)));
        assert_eq!(VecSlot::pop(&mut contract).unwrap(), Some(U256::from(100)));
        assert_eq!(VecSlot::pop(&mut contract).unwrap(), None);
    }

    #[test]
    fn test_vecext_address_unpacked() {
        let mut contract = setup_test_contract();
        type VecSlot = Slot<Vec<Address>, TestVecSlot2>;

        let addr1 = Address::repeat_byte(0xAA);
        let addr2 = Address::repeat_byte(0xBB);

        VecSlot::push(&mut contract, addr1).unwrap();
        VecSlot::push(&mut contract, addr2).unwrap();

        assert_eq!(VecSlot::read_at(&mut contract, 0).unwrap(), addr1);
        assert_eq!(VecSlot::read_at(&mut contract, 1).unwrap(), addr2);

        // Update
        let addr3 = Address::repeat_byte(0xCC);
        VecSlot::write_at(&mut contract, 0, addr3).unwrap();
        assert_eq!(VecSlot::read_at(&mut contract, 0).unwrap(), addr3);
    }

    // -- PROPERTY TESTS -------------------------------------------------------

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn proptest_vecext_push_pop_u8(data in arb_u8_vec(50)) {
            let mut contract = setup_test_contract();
            type VecSlot = Slot<Vec<u8>, TestVecSlot2>;

            // Push all elements
            for &val in &data {
                VecSlot::push(&mut contract, val)?;
            }

            // Verify length
            let length = read_length(&mut contract, TestVecSlot2::SLOT)?;
            prop_assert_eq!(length, data.len());

            // Pop all elements (in reverse order)
            let mut popped = Vec::new();
            while let Some(val) = VecSlot::pop(&mut contract)? {
                popped.push(val);
            }

            popped.reverse();
            prop_assert_eq!(popped, data);

            // Verify length is 0
            let final_length = read_length(&mut contract, TestVecSlot2::SLOT)?;
            prop_assert_eq!(final_length, 0);
        }

        #[test]
        fn proptest_vecext_read_write_at_u8(data in arb_u8_vec(30)) {
            let mut contract = setup_test_contract();
            type VecSlot = Slot<Vec<u8>, TestVecSlot2>;

            // Push all elements
            for &val in &data {
                VecSlot::push(&mut contract, val)?;
            }

            // Read all elements back
            for (i, &expected) in data.iter().enumerate() {
                let actual = VecSlot::read_at(&mut contract, i)?;
                prop_assert_eq!(actual, expected, "Mismatch at index {}", i);
            }

            // Update all elements
            for (i, &val) in data.iter().enumerate() {
                let new_val = val.wrapping_add(1);
                VecSlot::write_at(&mut contract, i, new_val)?;
            }

            // Verify updates
            for (i, &original) in data.iter().enumerate() {
                let actual = VecSlot::read_at(&mut contract, i)?;
                let expected = original.wrapping_add(1);
                prop_assert_eq!(actual, expected, "Update mismatch at index {}", i);
            }
        }

        #[test]
        fn proptest_vecext_push_pop_u256(data in arb_u256_vec(20)) {
            let mut contract = setup_test_contract();
            type VecSlot = Slot<Vec<U256>, TestVecSlot2>;

            // Push all elements
            for &val in &data {
                VecSlot::push(&mut contract, val)?;
            }

            // Pop all elements
            let mut popped = Vec::new();
            while let Some(val) = VecSlot::pop(&mut contract)? {
                popped.push(val);
            }

            popped.reverse();
            prop_assert_eq!(popped, data);
        }

        #[test]
        fn proptest_vecext_auto_expand_writes(indices in prop::collection::vec(0usize..20, 1..10)) {
            let mut contract = setup_test_contract();
            type VecSlot = Slot<Vec<u8>, TestVecSlot2>;

            // Write at random indices (auto-expand)
            for &idx in &indices {
                VecSlot::write_at(&mut contract, idx, idx as u8)?;
            }

            // Find max index
            let max_idx = indices.iter().copied().max().unwrap_or(0);

            // Verify length
            let length = read_length(&mut contract, TestVecSlot2::SLOT)?;
            prop_assert_eq!(length, max_idx + 1);

            // Verify written values
            for &idx in &indices {
                let actual = VecSlot::read_at(&mut contract, idx)?;
                prop_assert_eq!(actual, idx as u8);
            }
        }
    }
}
