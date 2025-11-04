//! Dynamic array (`Vec<T>`) implementation for the `Storable` trait.
//!
//! # Storage Layout
//!
//! Vec uses Solidity-compatible dynamic array storage:
//! - **Base slot**: Stores the array length (number of elements)
//! - **Data slots**: Start at `keccak256(base_slot)`, elements packed efficiently

use alloy::primitives::U256;

use crate::{
    error::{Result, TempoPrecompileError},
    storage::{
        Storable, StorableType, StorageOps,
        packing::{calc_packed_slot_count, extract_packed_value, insert_packed_value},
    },
};

/// Calculate the starting slot for dynamic array data.
///
/// For Solidity compatibility, dynamic array data is stored at `keccak256(base_slot)`.
#[inline]
fn calc_data_slot(base_slot: U256) -> U256 {
    U256::from_be_bytes(alloy::primitives::keccak256(base_slot.to_be_bytes::<32>()).0)
}

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
            return Ok(Vec::new());
        }

        let data_start = calc_data_slot(base_slot);

        // Determine if elements should be packed
        let byte_count = T::BYTE_COUNT;
        if byte_count < 32 && 32 % byte_count == 0 {
            // Elements can be packed multiple per slot
            load_packed_elements(storage, data_start, length, byte_count)
        } else {
            // Elements use full slots (either 32 bytes or multi-slot)
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

        // Determine if elements should be packed
        let byte_count = T::BYTE_COUNT;
        if byte_count < 32 && 32 % byte_count == 0 {
            // Pack multiple elements per slot
            store_packed_elements(self, storage, data_start, byte_count)
        } else {
            // Each element uses full slots
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
        let byte_count = T::BYTE_COUNT;

        if byte_count < 32 && 32 % byte_count == 0 {
            // Clear packed element slots
            let slot_count = calc_packed_slot_count(length, byte_count);
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

        // Build the slot value by packing multiple elements
        let mut slot_value = U256::ZERO;
        let mut current_offset = 0;

        for elem in &elements[start_elem..end_elem] {
            slot_value = insert_packed_value(slot_value, elem, current_offset, byte_count)?;
            current_offset += byte_count;
        }

        storage.sstore(slot_addr, slot_value)?;
    }

    Ok(())
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

    for elem_idx in 0..length {
        let elem_slot = data_start + U256::from(elem_idx);
        let elem = T::load(storage, elem_slot)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::Address;
    use proptest::prelude::*;
    use crate::storage::{
        PrecompileStorageProvider, StorageOps,
        hashmap::HashMapStorageProvider,
    };

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

    // Strategy for generating random U256 slot values that won't overflow
    fn arb_safe_slot() -> impl Strategy<Value = U256> {
        any::<[u64; 4]>().prop_map(|limbs| {
            // Ensure we don't overflow by limiting to a reasonable range
            U256::from_limbs(limbs) % (U256::MAX - U256::from(10000))
        })
    }

    // Helper: Generate a multi-slot struct for testing
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestStruct {
        a: U256,
        b: U256,
    }

    impl StorableType for TestStruct {
        const BYTE_COUNT: usize = 64; // 2 slots
    }

    impl Storable<1> for TestStruct {
        const SLOT_COUNT: usize = 1;

        fn load<S: StorageOps>(storage: &mut S, base_slot: U256) -> Result<Self> {
            let a = storage.sload(base_slot)?;
            let b = storage.sload(base_slot + U256::from(1))?;
            Ok(TestStruct { a, b })
        }

        fn store<S: StorageOps>(&self, storage: &mut S, base_slot: U256) -> Result<()> {
            storage.sstore(base_slot, self.a)?;
            storage.sstore(base_slot + U256::from(1), self.b)?;
            Ok(())
        }

        fn delete<S: StorageOps>(storage: &mut S, base_slot: U256) -> Result<()> {
            storage.sstore(base_slot, U256::ZERO)?;
            storage.sstore(base_slot + U256::from(1), U256::ZERO)?;
            Ok(())
        }

        fn to_evm_words(&self) -> Result<[U256; 1]> {
            Ok([self.a])
        }

        fn from_evm_words(words: [U256; 1]) -> Result<Self> {
            Ok(TestStruct {
                a: words[0],
                b: U256::ZERO,
            })
        }
    }

    #[test]
    fn test_vec_u8_roundtrip() {
        let mut contract = setup_test_contract();
        let base_slot = U256::ZERO;

        let data = vec![1u8, 2, 3, 4, 5];
        data.store(&mut contract, base_slot).unwrap();

        let loaded: Vec<u8> = Storable::load(&mut contract, base_slot).unwrap();
        assert_eq!(loaded, data, "Vec<u8> roundtrip failed");
    }

    #[test]
    fn test_vec_u16_roundtrip() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(100);

        let data = vec![100u16, 200, 300, 400, 500];
        data.store(&mut contract, base_slot).unwrap();

        let loaded: Vec<u16> = Storable::load(&mut contract, base_slot).unwrap();
        assert_eq!(loaded, data, "Vec<u16> roundtrip failed");
    }

    #[test]
    fn test_vec_u256_roundtrip() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(200);

        let data = vec![U256::from(12345), U256::from(67890), U256::from(111111)];
        data.store(&mut contract, base_slot).unwrap();

        let loaded: Vec<U256> = Storable::load(&mut contract, base_slot).unwrap();
        assert_eq!(loaded, data, "Vec<U256> roundtrip failed");
    }

    #[test]
    fn test_vec_address_roundtrip() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(300);

        let data = vec![
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x22),
            Address::repeat_byte(0x33),
        ];
        data.store(&mut contract, base_slot).unwrap();

        let loaded: Vec<Address> = Storable::load(&mut contract, base_slot).unwrap();
        assert_eq!(loaded, data, "Vec<Address> roundtrip failed");
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
    fn test_vec_delete() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(500);

        // Store data
        let data = vec![1u8, 2, 3, 4, 5];
        data.store(&mut contract, base_slot).unwrap();

        // Verify stored
        let loaded: Vec<u8> = Storable::load(&mut contract, base_slot).unwrap();
        assert_eq!(loaded, data, "Vec not stored correctly before delete");

        // Delete (static method)
        Vec::<u8>::delete(&mut contract, base_slot).unwrap();

        // Verify empty
        let loaded_after: Vec<u8> = Storable::load(&mut contract, base_slot).unwrap();
        assert!(loaded_after.is_empty(), "Vec not empty after delete");

        // Verify all data slots are cleared
        let data_start = calc_data_slot(base_slot);
        let byte_count = u8::BYTE_COUNT;
        let slot_count = calc_packed_slot_count(data.len(), byte_count);

        for i in 0..slot_count {
            let slot_value = contract.sload(data_start + U256::from(i)).unwrap();
            assert_eq!(slot_value, U256::ZERO, "Data slot {} not cleared after delete", i);
        }
    }

    #[test]
    fn test_vec_boundary_32_elements() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(600);

        // Exactly 32 u8 elements fit in one slot
        let data: Vec<u8> = (0..32).collect();
        data.store(&mut contract, base_slot).unwrap();

        let loaded: Vec<u8> = Storable::load(&mut contract, base_slot).unwrap();
        assert_eq!(loaded, data, "Vec with exactly 32 u8 elements failed roundtrip");
    }

    #[test]
    fn test_vec_boundary_33_elements() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(700);

        // 33 u8 elements require 2 slots
        let data: Vec<u8> = (0..33).collect();
        data.store(&mut contract, base_slot).unwrap();

        let loaded: Vec<u8> = Storable::load(&mut contract, base_slot).unwrap();
        assert_eq!(loaded, data, "Vec with 33 u8 elements (2 slots) failed roundtrip");
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

    // -- PROPTEST STRATEGIES ------------------------------------------------------

    prop_compose! {
        fn arb_u8_vec(max_len: usize)
                     (vec in prop::collection::vec(any::<u8>(), 0..=max_len))
                     -> Vec<u8> {
            vec
        }
    }

    prop_compose! {
        fn arb_u16_vec(max_len: usize)
                      (vec in prop::collection::vec(any::<u16>(), 0..=max_len))
                      -> Vec<u16> {
            vec
        }
    }

    prop_compose! {
        fn arb_u256_vec(max_len: usize)
                       (vec in prop::collection::vec(any::<u64>(), 0..=max_len))
                       -> Vec<U256> {
            vec.into_iter().map(U256::from).collect()
        }
    }

    prop_compose! {
        fn arb_address_vec(max_len: usize)
                          (vec in prop::collection::vec(any::<[u8; 20]>(), 0..=max_len))
                          -> Vec<Address> {
            vec.into_iter().map(Address::from).collect()
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
            // U256 elements are not packed, each uses one full slot
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
    }
}
