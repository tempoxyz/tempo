//! Dynamic array (`Vec<T>`) implementation for the storage traits.
//!
//! # Storage Layout
//!
//! Vec uses Solidity-compatible dynamic array storage:
//! - **Base slot**: Stores the array length (number of elements)
//! - **Data slots**: Start at `keccak256(len_slot)`, elements packed efficiently
//!
//! ## Multi-Slot Support
//!
//! - Supports both single-slot primitives and multi-slot types (structs, arrays)
//! - Element at index `i` starts at slot `data_start + i * T::SLOTS`

use alloy::primitives::{Address, U256};
use std::{
    marker::PhantomData,
    ops::{Index, IndexMut},
};

use crate::{
    error::{Result, TempoPrecompileError},
    storage::{
        Handler, Layout, LayoutCtx, Storable, StorableType, StorageOps,
        packing::{PackedSlot, calc_element_loc, calc_packed_slot_count},
        types::{HandlerCache, Slot},
    },
};

impl<T> StorableType for Vec<T>
where
    T: Storable,
{
    /// Vec base slot occupies one full storage slot (stores length).
    const LAYOUT: Layout = Layout::Slots(1);
    const IS_DYNAMIC: bool = true;
    type Handler = VecHandler<T>;

    fn handle(slot: U256, _ctx: LayoutCtx, address: Address) -> Self::Handler {
        VecHandler::new(slot, address)
    }
}

impl<T> Storable for Vec<T>
where
    T: Storable,
{
    fn load<S: StorageOps>(storage: &S, len_slot: U256, ctx: LayoutCtx) -> Result<Self> {
        debug_assert_eq!(ctx, LayoutCtx::FULL, "Dynamic arrays cannot be packed");

        // Read length from base slot
        let length_value = storage.load(len_slot)?;
        let length = length_value.to::<usize>();

        if length == 0 {
            return Ok(Self::new());
        }

        // Pack elements if necessary. Vec elements can't be split across slots.
        let data_start = calc_data_slot(len_slot);
        if T::BYTES <= 16 {
            load_packed_elements(storage, data_start, length, T::BYTES)
        } else {
            load_unpacked_elements(storage, data_start, length)
        }
    }

    fn store<S: StorageOps>(&self, storage: &mut S, len_slot: U256, ctx: LayoutCtx) -> Result<()> {
        debug_assert_eq!(ctx, LayoutCtx::FULL, "Dynamic arrays cannot be packed");

        // Write length to base slot
        storage.store(len_slot, U256::from(self.len()))?;

        if self.is_empty() {
            return Ok(());
        }

        // Pack elements if necessary. Vec elements can't be split across slots.
        let data_start = calc_data_slot(len_slot);
        if T::BYTES <= 16 {
            store_packed_elements(self, storage, data_start, T::BYTES)
        } else {
            store_unpacked_elements(self, storage, data_start)
        }
    }

    /// Custom delete for Vec: clears both length slot and all data slots.
    fn delete<S: StorageOps>(storage: &mut S, len_slot: U256, ctx: LayoutCtx) -> Result<()> {
        debug_assert_eq!(ctx, LayoutCtx::FULL, "Dynamic arrays cannot be packed");

        // Read length from base slot to determine how many slots to clear
        let length_value = storage.load(len_slot)?;
        let length = length_value.to::<usize>();

        // Clear base slot (length)
        storage.store(len_slot, U256::ZERO)?;

        if length == 0 {
            return Ok(());
        }

        let data_start = calc_data_slot(len_slot);
        if T::BYTES <= 16 {
            // Clear packed element slots. Vec elements can't be split across slots.
            let slot_count = calc_packed_slot_count(length, T::BYTES);
            for slot_idx in 0..slot_count {
                storage.store(data_start + U256::from(slot_idx), U256::ZERO)?;
            }
        } else {
            // Clear unpacked element slots (multi-slot aware)
            for elem_idx in 0..length {
                let elem_slot = data_start + U256::from(elem_idx * T::SLOTS);
                T::delete(storage, elem_slot, LayoutCtx::FULL)?;
            }
        }

        Ok(())
    }
}

/// Type-safe handler for accessing `Vec<T>` in storage.
///
/// Provides both full-vector operations (read/write/delete) and individual element access.
/// The handler is a thin wrapper around a storage slot number and delegates full-vector
/// operations to `Slot<Vec<T>>`.
///
/// # Element Access
///
/// Use `at(index)` to get a `Slot<T>` for individual element operations with OOB guarantees.
/// Use `[index]` for its efficient counterpart without the check.
/// - For packed elements (T::BYTES ≤ 16): returns a packed `Slot<T>` with byte offsets
/// - For unpacked elements: returns a full `Slot<T>` for the element's dedicated slot
///
/// # Example
///
/// ```ignore
/// let handler = <Vec<u8> as StorableType>::handle(len_slot, LayoutCtx::FULL);
///
/// // Full vector operations
/// let vec = handler.read()?;
/// handler.write(&mut storage, vec![1, 2, 3])?;
///
/// // Individual element operations
/// if let Some(slot) = handler[0]? {
///     let elem = slot.read()?;
///     slot.write(42)?;
/// }
/// ```
///
/// # Capacity
///
/// Vectors have a maximum capacity of `u32::MAX / element_size` to prevent
/// arithmetic overflow in storage slot calculations.
pub struct VecHandler<T>
where
    T: Storable,
{
    len_slot: U256,
    address: Address,
    cache: HandlerCache<usize, T::Handler>,
    _ty: PhantomData<T>,
}

impl<T> Handler<Vec<T>> for VecHandler<T>
where
    T: Storable,
{
    /// Reads the entire vector from storage.
    #[inline]
    fn read(&self) -> Result<Vec<T>> {
        self.as_slot().read()
    }

    /// Writes the entire vector to storage.
    #[inline]
    fn write(&mut self, value: Vec<T>) -> Result<()> {
        self.as_slot().write(value)
    }

    /// Deletes the entire vector from storage (clears length and all elements).
    #[inline]
    fn delete(&mut self) -> Result<()> {
        self.as_slot().delete()
    }

    /// Reads the entire vector from transient storage.
    #[inline]
    fn t_read(&self) -> Result<Vec<T>> {
        self.as_slot().t_read()
    }

    /// Writes the entire vector to transient storage.
    #[inline]
    fn t_write(&mut self, value: Vec<T>) -> Result<()> {
        self.as_slot().t_write(value)
    }

    /// Deletes the entire vector from transient storage.
    #[inline]
    fn t_delete(&mut self) -> Result<()> {
        self.as_slot().t_delete()
    }
}

impl<T> VecHandler<T>
where
    T: Storable,
{
    /// Creates a new handler for the vector at the given base slot and address.
    #[inline]
    pub fn new(len_slot: U256, address: Address) -> Self {
        Self {
            len_slot,
            address,
            cache: HandlerCache::new(),
            _ty: PhantomData,
        }
    }

    /// Max valid index to prevent arithmetic overflow in slot calculations.
    const fn max_index() -> usize {
        if T::BYTES <= 16 {
            u32::MAX as usize / T::BYTES
        } else {
            u32::MAX as usize / T::SLOTS
        }
    }

    /// Returns the slot that stores the length of the dynamic array.
    #[inline]
    pub fn len_slot(&self) -> ::alloy::primitives::U256 {
        self.len_slot
    }

    /// Returns the base storage slot where this array's data is stored.
    ///
    /// Single-slot vectors pack all fields into this slot.
    /// Multi-slot vectors use consecutive slots starting from this base.
    #[inline]
    pub fn data_slot(&self) -> ::alloy::primitives::U256 {
        calc_data_slot(self.len_slot)
    }

    /// Returns a `Slot` accessor for full-vector operations.
    #[inline]
    fn as_slot(&self) -> Slot<Vec<T>> {
        Slot::new(self.len_slot, self.address)
    }

    /// Returns the length of the vector.
    #[inline]
    pub fn len(&self) -> Result<usize> {
        let slot = Slot::<U256>::new(self.len_slot, self.address);
        Ok(slot.read()?.to::<usize>())
    }

    /// Returns whether the vector is empty.
    #[inline]
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    #[inline]
    fn compute_handler(data_start: U256, address: Address, index: usize) -> T::Handler {
        // Pack small elements into shared slots, use T::SLOTS for multi-slot types
        let (slot, layout_ctx) = if T::BYTES <= 16 {
            let location = calc_element_loc(index, T::BYTES);
            (
                data_start + U256::from(location.offset_slots),
                LayoutCtx::packed(location.offset_bytes),
            )
        } else {
            (data_start + U256::from(index * T::SLOTS), LayoutCtx::FULL)
        };

        T::handle(slot, layout_ctx, address)
    }

    /// Returns a `Handler` for the element at the given index with bounds checking.
    ///
    /// The handler is computed on first access and cached for subsequent accesses.
    ///
    /// # Returns
    /// - If the SLOAD to read the length fails, returns an error.
    /// - If the index is OOB, returns `Ok(None)`.
    /// - Otherwise, returns `Ok(Some(&T::Handler))`.
    pub fn at(&self, index: usize) -> Result<Option<&T::Handler>> {
        if index >= self.len()? {
            return Ok(None);
        }

        let (data_start, address) = (self.data_slot(), self.address);
        Ok(Some(self.cache.get_or_insert(index, || {
            Self::compute_handler(data_start, address, index)
        })))
    }

    /// Pushes a new element to the end of the vector.
    ///
    /// Automatically increments the length and handles packing for small types.
    ///
    /// Returns `Err` if the vector has reached its maximum capacity.
    #[inline]
    pub fn push(&self, value: T) -> Result<()>
    where
        T: Storable,
        T::Handler: Handler<T>,
    {
        // Read current length
        let length = self.len()?;
        if length >= Self::max_index() {
            return Err(TempoPrecompileError::Fatal("Vec is at max capacity".into()));
        }

        // Write element at the end
        let mut elem_slot = Self::compute_handler(self.data_slot(), self.address, length);
        elem_slot.write(value)?;

        // Increment length
        let mut length_slot = Slot::<U256>::new(self.len_slot, self.address);
        length_slot.write(U256::from(length + 1))
    }

    /// Pops the last element from the vector.
    ///
    /// Returns `None` if the vector is empty. Automatically decrements the length
    /// and zeros out the popped element's storage slot.
    #[inline]
    pub fn pop(&self) -> Result<Option<T>>
    where
        T: Storable,
        T::Handler: Handler<T>,
    {
        // Read current length
        let length = self.len()?;
        if length == 0 {
            return Ok(None);
        }
        let last_index = length - 1;

        // Read the last element
        let mut elem_slot = Self::compute_handler(self.data_slot(), self.address, last_index);
        let element = elem_slot.read()?;

        // Zero out the element's storage
        elem_slot.delete()?;

        // Decrement length
        let mut length_slot = Slot::<U256>::new(self.len_slot, self.address);
        length_slot.write(U256::from(last_index))?;

        Ok(Some(element))
    }
}

impl<T> Index<usize> for VecHandler<T>
where
    T: Storable,
{
    type Output = T::Handler;

    /// Returns a reference to the cached handler for the given index (unchecked).
    ///
    /// **WARNING:** Does not check bounds. Caller must ensure that the index is valid.
    /// For checked access use `.at(index)` instead.
    fn index(&self, index: usize) -> &Self::Output {
        let (data_start, address) = (self.data_slot(), self.address);
        self.cache
            .get_or_insert(index, || Self::compute_handler(data_start, address, index))
    }
}

impl<T> IndexMut<usize> for VecHandler<T>
where
    T: Storable,
{
    /// Returns a mutable reference to the cached handler for the given index (unchecked).
    ///
    /// **WARNING:** Does not check bounds. Caller must ensure that the index is valid.
    /// For checked access use `.at(index)` instead.
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        let (data_start, address) = (self.data_slot(), self.address);
        self.cache
            .get_or_insert_mut(index, || Self::compute_handler(data_start, address, index))
    }
}

/// Calculate the starting slot for dynamic array data.
///
/// For Solidity compatibility, dynamic array data is stored at `keccak256(len_slot)`.
#[inline]
pub(crate) fn calc_data_slot(len_slot: U256) -> U256 {
    U256::from_be_bytes(alloy::primitives::keccak256(len_slot.to_be_bytes::<32>()).0)
}

/// Load packed elements from storage.
///
/// Used when `T::BYTES <= 16`, allowing multiple elements per slot.
fn load_packed_elements<T, S>(
    storage: &S,
    data_start: U256,
    length: usize,
    byte_count: usize,
) -> Result<Vec<T>>
where
    T: Storable,
    S: StorageOps,
{
    debug_assert!(
        T::BYTES <= 16,
        "load_packed_elements requires T::BYTES <= 16"
    );
    let elements_per_slot = 32 / byte_count;
    let slot_count = calc_packed_slot_count(length, byte_count);

    let mut result = Vec::with_capacity(length);
    let mut current_offset = 0;

    for slot_idx in 0..slot_count {
        let slot_addr = data_start + U256::from(slot_idx);
        let slot_value = storage.load(slot_addr)?;
        let slot_packed = PackedSlot(slot_value);

        // How many elements in this slot?
        let elements_in_this_slot = if slot_idx == slot_count - 1 {
            // Last slot might be partially filled
            length - (slot_idx * elements_per_slot)
        } else {
            elements_per_slot
        };

        // Extract each element from this slot
        for _ in 0..elements_in_this_slot {
            let elem = T::load(&slot_packed, slot_addr, LayoutCtx::packed(current_offset))?;
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
    T: Storable,
    S: StorageOps,
{
    debug_assert!(
        T::BYTES <= 16,
        "store_packed_elements requires T::BYTES <= 16"
    );
    let elements_per_slot = 32 / byte_count;
    let slot_count = calc_packed_slot_count(elements.len(), byte_count);

    for slot_idx in 0..slot_count {
        let slot_addr = data_start + U256::from(slot_idx);
        let start_elem = slot_idx * elements_per_slot;
        let end_elem = (start_elem + elements_per_slot).min(elements.len());

        let slot_value = build_packed_slot(&elements[start_elem..end_elem], byte_count)?;
        storage.store(slot_addr, slot_value)?;
    }

    Ok(())
}

/// Build a packed storage slot from multiple elements.
///
/// Takes a slice of elements and packs them into a single U256 word.
fn build_packed_slot<T>(elements: &[T], byte_count: usize) -> Result<U256>
where
    T: Storable,
{
    debug_assert!(T::BYTES <= 16, "build_packed_slot requires T::BYTES <= 16");
    let mut slot_value = PackedSlot(U256::ZERO);
    let mut current_offset = 0;

    for elem in elements {
        elem.store(
            &mut slot_value,
            U256::ZERO,
            LayoutCtx::packed(current_offset),
        )?;
        current_offset += byte_count;
    }

    Ok(slot_value.0)
}

/// Load unpacked elements from storage.
///
/// Used when elements don't pack efficiently (32 bytes or multi-slot types).
/// Each element occupies `T::SLOTS` consecutive slots.
fn load_unpacked_elements<T, S>(storage: &S, data_start: U256, length: usize) -> Result<Vec<T>>
where
    T: Storable,
    S: StorageOps,
{
    let mut result = Vec::with_capacity(length);
    for index in 0..length {
        // Use T::SLOTS for proper multi-slot element addressing
        let elem_slot = data_start + U256::from(index * T::SLOTS);
        let elem = T::load(storage, elem_slot, LayoutCtx::FULL)?;
        result.push(elem);
    }
    Ok(result)
}

/// Store unpacked elements to storage.
///
/// Each element uses `T::SLOTS` consecutive slots.
fn store_unpacked_elements<T, S>(elements: &[T], storage: &mut S, data_start: U256) -> Result<()>
where
    T: Storable,
    S: StorageOps,
{
    for (elem_idx, elem) in elements.iter().enumerate() {
        // Use T::SLOTS for proper multi-slot element addressing
        let elem_slot = data_start + U256::from(elem_idx * T::SLOTS);
        elem.store(storage, elem_slot, LayoutCtx::FULL)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::{Handler, StorageCtx},
        test_util::{gen_word_from, setup_storage},
    };
    use alloy::primitives::Address;
    use proptest::prelude::*;
    use tempo_precompiles_macros::Storable;

    // -- TEST HELPERS -------------------------------------------------------------

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

    // -- SLOT COMPUTATION TESTS ---------------------------------------------------
    // Tests that verify handlers compute correct slots WITHOUT storage interaction

    #[test]
    fn test_vec_handler_slot_computation() {
        let len_slot = U256::random();
        let address = Address::random();
        let handler = VecHandler::<u8>::new(len_slot, address);

        // Verify base slot is stored correctly
        assert_eq!(handler.len_slot, len_slot);

        // Verify address is stored correctly
        assert_eq!(*handler.address, *address);
    }

    #[test]
    fn test_vec_data_slot_derivation() {
        let len_slot = U256::random();

        // Verify data slot matches keccak256(len_slot)
        let data_slot = calc_data_slot(len_slot);
        let expected =
            U256::from_be_bytes(alloy::primitives::keccak256(len_slot.to_be_bytes::<32>()).0);

        assert_eq!(
            data_slot, expected,
            "Data slot should be keccak256(len_slot)"
        );
    }

    #[test]
    fn test_vec_at_element_slot_packed() {
        let len_slot = U256::random();
        let address = Address::random();
        let handler = VecHandler::<u8>::new(len_slot, address);

        let data_start = calc_data_slot(len_slot);

        // For packed types (u8: 1 byte), elements pack 32 per slot
        // Element at index 5 should be in slot 0, offset 5
        let elem_slot = &handler[5];
        let expected_loc = calc_element_loc(5, u8::BYTES);
        assert_eq!(
            elem_slot.slot(),
            data_start + U256::from(expected_loc.offset_slots)
        );
        assert_eq!(elem_slot.offset(), Some(expected_loc.offset_bytes));

        // Element at index 35 should be in slot 1, offset 3 (35 % 32 = 3)
        let elem_slot = &handler[35];
        let expected_loc = calc_element_loc(35, u8::BYTES);
        assert_eq!(
            elem_slot.slot(),
            data_start + U256::from(expected_loc.offset_slots)
        );
        assert_eq!(elem_slot.offset(), Some(expected_loc.offset_bytes));
    }

    #[test]
    fn test_vec_at_element_slot_unpacked() {
        let len_slot = U256::random();
        let address = Address::random();
        let handler = VecHandler::<U256>::new(len_slot, address);

        let data_start = calc_data_slot(len_slot);

        // For unpacked types (U256: 32 bytes), each element uses a full slot
        // Element at index 0 should be at data_start + 0
        let elem_slot = &handler[0];
        assert_eq!(elem_slot.slot(), data_start);
        assert_eq!(elem_slot.offset(), None); // Full slot, no offset

        // Element at index 5 should be at data_start + 5
        let elem_slot = &handler[5];
        assert_eq!(elem_slot.slot(), data_start + U256::from(5));
        assert_eq!(elem_slot.offset(), None);
    }

    #[test]
    fn test_vec_at_determinism() {
        let len_slot = U256::random();
        let address = Address::random();
        let handler = VecHandler::<u16>::new(len_slot, address);

        // Same index should always produce same slot
        let slot1 = &handler[10];
        let slot2 = &handler[10];

        assert_eq!(
            slot1.slot(),
            slot2.slot(),
            "Same index should produce same slot"
        );
        assert_eq!(
            slot1.offset(),
            slot2.offset(),
            "Same index should produce same offset"
        );
    }

    #[test]
    fn test_vec_at_different_indices() {
        let len_slot = U256::random();
        let address = Address::random();
        let handler = VecHandler::<u16>::new(len_slot, address);

        // Different indices should produce different slot/offset combinations
        let slot5 = &handler[5];
        let slot10 = &handler[10];

        // u16 is 2 bytes, so 16 elements per slot
        // Index 5 is in slot 0, offset 10
        // Index 10 is in slot 0, offset 20
        assert_eq!(slot5.slot(), slot10.slot(), "Both should be in same slot");
        assert_ne!(slot5.offset(), slot10.offset(), "But different offsets");

        // Index 16 should be in different slot
        let slot16 = &handler[16];
        assert_ne!(
            slot5.slot(),
            slot16.slot(),
            "Different slot for index >= 16"
        );
    }

    // -- STORABLE TRAIT TESTS -----------------------------------------------------

    #[test]
    fn test_vec_empty() {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let len_slot = U256::random();

            let data: Vec<u8> = vec![];
            let mut slot = Slot::<Vec<u8>>::new(len_slot, address);
            slot.write(data.clone()).unwrap();

            let loaded: Vec<u8> = slot.read().unwrap();
            assert_eq!(loaded, data, "Empty vec roundtrip failed");
            assert!(loaded.is_empty(), "Loaded vec should be empty");
        });
    }

    #[test]
    fn test_vec_nested() {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let len_slot = U256::random();

            // Nested Vec<Vec<u8>>
            let data = vec![vec![1u8, 2, 3], vec![4, 5], vec![6, 7, 8, 9]];
            let mut slot = Slot::<Vec<Vec<u8>>>::new(len_slot, address);
            slot.write(data.clone()).unwrap();

            let loaded: Vec<Vec<u8>> = slot.read().unwrap();
            assert_eq!(loaded, data, "Nested Vec<Vec<u8>> roundtrip failed");
        });
    }

    #[test]
    fn test_vec_bool_packing() {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let len_slot = U256::random();
            let mut slot = Slot::<Vec<bool>>::new(len_slot, address);

            // Test 1: Exactly 32 bools (fills exactly 1 slot: 32 * 1 byte = 32 bytes)
            let data_exact: Vec<bool> = (0..32).map(|i| i % 2 == 0).collect();
            slot.write(data_exact.clone()).unwrap();

            // Verify length stored in base slot
            let length_value = U256::handle(len_slot, LayoutCtx::FULL, address)
                .read()
                .unwrap();
            assert_eq!(length_value, U256::from(32), "Length not stored correctly");

            let loaded: Vec<bool> = slot.read().unwrap();
            assert_eq!(
                loaded, data_exact,
                "Vec<bool> with 32 elements failed roundtrip"
            );

            // Test 2: 35 bools (requires 2 slots: 32 + 3)
            let data_overflow: Vec<bool> = (0..35).map(|i| i % 3 == 0).collect();
            slot.write(data_overflow.clone()).unwrap();

            let loaded: Vec<bool> = slot.read().unwrap();
            assert_eq!(
                loaded, data_overflow,
                "Vec<bool> with 35 elements failed roundtrip"
            );
        });
    }

    // -- SLOT-LEVEL VALIDATION TESTS ----------------------------------------------

    #[test]
    fn test_vec_u8_explicit_slot_packing() {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let len_slot = U256::from(2000);
            let data = vec![10u8, 20, 30, 40, 50];

            // Store exactly 5 u8 elements (should fit in 1 slot with 27 unused bytes)
            <Vec<u8>>::handle(len_slot, LayoutCtx::FULL, address)
                .write(data.clone())
                .unwrap();

            // Verify length stored in base slot
            let length = U256::handle(len_slot, LayoutCtx::FULL, address)
                .read()
                .unwrap();
            assert_eq!(
                length,
                U256::from(data.len()),
                "Length not stored correctly"
            );

            let data_start = calc_data_slot(len_slot);
            let slot_data = U256::handle(data_start, LayoutCtx::FULL, address)
                .read()
                .unwrap();

            // Expected byte layout: 5 u8 elements packed at rightmost positions
            let expected = gen_word_from(&[
                "0x32", // elem[4] = 50
                "0x28", // elem[3] = 40
                "0x1e", // elem[2] = 30
                "0x14", // elem[1] = 20
                "0x0a", // elem[0] = 10
            ]);
            assert_eq!(
                slot_data, expected,
                "Slot data should match Solidity byte layout"
            );

            // Also verify each element can be extracted correctly
            for (i, &expected) in data.iter().enumerate() {
                let offset = i; // equivalent to: `i * u8::BYTES`
                let actual =
                    Slot::<u8>::new_with_ctx(data_start, LayoutCtx::packed(offset), address)
                        .read()
                        .unwrap();
                assert_eq!(actual, expected, "mismatch: elem[{i}] at offset {offset}");
            }
        });
    }

    #[test]
    fn test_vec_u16_slot_boundary() {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let len_slot = U256::from(2100);
            let mut vec_slot = Slot::<Vec<u16>>::new(len_slot, address);

            // Test 1: Exactly 16 u16 elements (fills exactly 1 slot: 16 * 2 bytes = 32 bytes)
            let data_exact: Vec<u16> = (0..16).map(|i| i * 100).collect();
            vec_slot.write(data_exact.clone()).unwrap();

            let data_start = calc_data_slot(len_slot);
            let slot0_value = U256::handle(data_start, LayoutCtx::FULL, address)
                .read()
                .unwrap();

            let expected_slot0 = gen_word_from(&[
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
            for (i, &expected) in data_exact.iter().enumerate() {
                let offset = i * u16::BYTES;
                let actual =
                    Slot::<u16>::new_with_ctx(data_start, LayoutCtx::packed(offset), address)
                        .read()
                        .unwrap();
                assert_eq!(actual, expected, "mismatch: elem[{i}] at offset {offset}");
            }

            // Test 2: 17 u16 elements (requires 2 slots)
            let data_overflow: Vec<u16> = (0..17).map(|i| i * 100).collect();
            vec_slot.write(data_overflow).unwrap();

            // Verify slot 0 still matches (first 16 elements)
            let slot0_value = U256::handle(data_start, LayoutCtx::FULL, address)
                .read()
                .unwrap();
            assert_eq!(
                slot0_value, expected_slot0,
                "Slot 0 should still match after overflow"
            );

            // Verify slot 1 has the 17th element (1600 = 0x0640)
            let slot1_addr = data_start + U256::ONE;
            let slot1_value = U256::handle(slot1_addr, LayoutCtx::FULL, address)
                .read()
                .unwrap();

            let expected_slot1 = gen_word_from(&[
                "0x0640", // elem[16] = 1600
            ]);
            assert_eq!(
                slot1_value, expected_slot1,
                "Slot 1 should match Solidity byte layout"
            );

            // Also verify the 17th element can be extracted
            let actual = Slot::<u16>::new_with_ctx(slot1_addr, LayoutCtx::packed(0), address)
                .read()
                .unwrap();
            assert_eq!(actual, 1600u16, "mismatch: slot1_elem[0] at offset 0");
        });
    }

    #[test]
    fn test_vec_u8_partial_slot_fill() {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let len_slot = U256::from(2200);

            // Store 35 u8 elements (values 1-35):
            // - Slot 0: 32 elements (full) - elements 1-32
            // - Slot 1: 3 elements (elements 33-35) + 29 zeros
            let data: Vec<u8> = (0..35).map(|i| (i + 1) as u8).collect();
            let mut vec_slot = Slot::<Vec<u8>>::new(len_slot, address);
            vec_slot.write(data).unwrap();
            let data_start = calc_data_slot(len_slot);
            let slot0_value = U256::handle(data_start, LayoutCtx::FULL, address)
                .read()
                .unwrap();

            let expected_slot0 = gen_word_from(&[
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
            let slot1_value = U256::handle(slot1_addr, LayoutCtx::FULL, address)
                .read()
                .unwrap();

            let expected_slot1 = gen_word_from(&[
                "0x23", // elem[2] = 35
                "0x22", // elem[1] = 34
                "0x21", // elem[0] = 33
            ]);
            assert_eq!(
                slot1_value, expected_slot1,
                "Slot 1 should match Solidity byte layout"
            );

            // Also verify each element in slot 1 can be extracted
            let slot1_data = [33u8, 34u8, 35u8];
            for (i, &expected) in slot1_data.iter().enumerate() {
                let offset = i; // equivalent to: `i * u8::BYTES`
                let actual =
                    Slot::<u8>::new_with_ctx(slot1_addr, LayoutCtx::packed(offset), address)
                        .read()
                        .unwrap();
                assert_eq!(
                    actual, expected,
                    "mismatch: slot1_elem[{i}] at offset {offset}"
                );
            }
        });
    }

    #[test]
    fn test_vec_u256_individual_slots() {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let len_slot = U256::from(2300);

            // Store 3 U256 values (each should occupy its own slot)
            let data = vec![
                U256::from(0x1111111111111111u64),
                U256::from(0x2222222222222222u64),
                U256::from(0x3333333333333333u64),
            ];
            let mut vec_slot = Slot::<Vec<U256>>::new(len_slot, address);
            vec_slot.write(data.clone()).unwrap();

            let data_start = calc_data_slot(len_slot);

            // Verify each U256 occupies its own sequential slot
            for (i, &expected) in data.iter().enumerate() {
                let stored_value =
                    U256::handle(data_start + U256::from(i), LayoutCtx::FULL, address)
                        .read()
                        .unwrap();
                assert_eq!(stored_value, expected, "incorrect U256 element {i}");
            }

            // Verify there's no data in slot 3 (should be empty)
            let no_slot_value = U256::handle(data_start + U256::from(3), LayoutCtx::FULL, address)
                .read()
                .unwrap();
            assert_eq!(no_slot_value, U256::ZERO, "Slot 3 should be empty");
        });
    }

    #[test]
    fn test_vec_address_unpacked_slots() {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let len_slot = U256::from(2400);

            // Store 3 addresses (each 20 bytes, but 32 % 20 != 0, so unpacked)
            let data = vec![
                Address::repeat_byte(0xAA),
                Address::repeat_byte(0xBB),
                Address::repeat_byte(0xCC),
            ];
            let mut vec_slot = Slot::<Vec<Address>>::new(len_slot, address);
            vec_slot.write(data.clone()).unwrap();

            let data_start = calc_data_slot(len_slot);

            // Verify slot 0: Address(0xAA...) right-aligned with 12-byte padding
            let slot0_value = U256::handle(data_start, LayoutCtx::FULL, address)
                .read()
                .unwrap();
            let expected_slot0 = gen_word_from(&["0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]);
            assert_eq!(
                slot0_value, expected_slot0,
                "Slot 0 should match Solidity byte layout"
            );

            // Verify slot 1: Address(0xBB...) right-aligned with 12-byte padding
            let slot1_addr = data_start + U256::ONE;
            let slot1_value = U256::handle(slot1_addr, LayoutCtx::FULL, address)
                .read()
                .unwrap();
            let expected_slot1 = gen_word_from(&["0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"]);
            assert_eq!(
                slot1_value, expected_slot1,
                "Slot 1 should match Solidity byte layout"
            );

            // Verify slot 2: Address(0xCC...) right-aligned with 12-byte padding
            let slot2_addr = data_start + U256::from(2);
            let slot2_value = U256::handle(slot2_addr, LayoutCtx::FULL, address)
                .read()
                .unwrap();
            let expected_slot2 = gen_word_from(&["0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"]);
            assert_eq!(
                slot2_value, expected_slot2,
                "Slot 2 should match Solidity byte layout"
            );

            // Also verify addresses can be loaded back
            for (i, &expected_addr) in data.iter().enumerate() {
                let slot_addr = data_start + U256::from(i);
                let stored_value = U256::handle(slot_addr, LayoutCtx::FULL, address)
                    .read()
                    .unwrap();
                let expected_u256 = U256::from_be_slice(expected_addr.as_slice());
                assert_eq!(
                    stored_value, expected_u256,
                    "Address element {i} should match"
                );
            }
        });
    }

    #[test]
    fn test_vec_struct_slot_allocation() {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let len_slot = U256::from(2500);

            // Store Vec<TestStruct> with 3 single-slot structs
            // Each TestStruct has two u128 fields (a, b) packed into one 32-byte slot
            let data = vec![
                TestStruct { a: 100, b: 1 },
                TestStruct { a: 200, b: 2 },
                TestStruct { a: 300, b: 3 },
            ];
            let mut vec_slot = Slot::<Vec<TestStruct>>::new(len_slot, address);
            vec_slot.write(data.clone()).unwrap();

            let data_start = calc_data_slot(len_slot);

            // Verify slot 0: TestStruct { a: 100, b: 1 }
            // Note: Solidity packs struct fields right-to-left (declaration order reversed in memory)
            // So field b (declared second) goes in bytes 0-15, field a (declared first) goes in bytes 16-31
            let slot0_value = U256::handle(data_start, LayoutCtx::FULL, address)
                .read()
                .unwrap();
            let expected_slot0 = gen_word_from(&[
                "0x00000000000000000000000000000001", // field b = 1
                "0x00000000000000000000000000000064", // field a = 100
            ]);
            assert_eq!(
                slot0_value, expected_slot0,
                "Slot 0 should match Solidity byte layout"
            );

            // Verify slot 1: TestStruct { a: 200, b: 2 }
            let slot1_addr = data_start + U256::ONE;
            let slot1_value = U256::handle(slot1_addr, LayoutCtx::FULL, address)
                .read()
                .unwrap();
            let expected_slot1 = gen_word_from(&[
                "0x00000000000000000000000000000002", // field b = 2
                "0x000000000000000000000000000000C8", // field a = 200
            ]);
            assert_eq!(
                slot1_value, expected_slot1,
                "Slot 1 should match Solidity byte layout"
            );

            // Verify slot 2: TestStruct { a: 300, b: 3 }
            let slot2_addr = data_start + U256::from(2);
            let slot2_value = U256::handle(slot2_addr, LayoutCtx::FULL, address)
                .read()
                .unwrap();
            let expected_slot2 = gen_word_from(&[
                "0x00000000000000000000000000000003", // field b = 3
                "0x0000000000000000000000000000012C", // field a = 300
            ]);
            assert_eq!(
                slot2_value, expected_slot2,
                "Slot 2 should match Solidity byte layout"
            );

            // Verify slot 3 is empty (no 4th element)
            let slot3_addr = data_start + U256::from(3);
            let slot3_value = U256::handle(slot3_addr, LayoutCtx::FULL, address)
                .read()
                .unwrap();
            assert_eq!(slot3_value, U256::ZERO, "Slot 3 should be empty");

            // Also verify each struct can be loaded back correctly
            for (i, expected_struct) in data.iter().enumerate() {
                let struct_slot_addr = data_start + U256::from(i);
                let struct_slot = Slot::<TestStruct>::new(struct_slot_addr, address);
                let loaded_struct = struct_slot.read().unwrap();
                assert_eq!(
                    loaded_struct, *expected_struct,
                    "TestStruct at slot {i} should match"
                );
            }
        });
    }

    #[test]
    fn test_vec_small_struct_storage() {
        // Test that single-slot structs are stored correctly in Vec
        #[derive(Debug, Clone, PartialEq, Eq, Storable)]
        struct SmallStruct {
            flag1: bool, // offset 0 (1 byte)
            flag2: bool, // offset 1 (1 byte)
            value: u16,  // offset 2 (2 bytes)
        }

        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let len_slot = U256::from(2550);

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
            let mut vec_slot = Slot::<Vec<SmallStruct>>::new(len_slot, address);
            vec_slot.write(data.clone()).unwrap();

            // Verify length stored in base slot
            let length_value = U256::handle(len_slot, LayoutCtx::FULL, address)
                .read()
                .unwrap();
            assert_eq!(length_value, U256::from(3), "Length not stored correctly");

            let data_start = calc_data_slot(len_slot);

            // Verify slot 0: first struct (fields packed within the struct)
            let slot0_value = U256::handle(data_start, LayoutCtx::FULL, address)
                .read()
                .unwrap();
            let expected_slot0 = gen_word_from(&[
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
            let slot1_value = U256::handle(slot1_addr, LayoutCtx::FULL, address)
                .read()
                .unwrap();
            let expected_slot1 = gen_word_from(&[
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
            let slot2_value = U256::handle(slot2_addr, LayoutCtx::FULL, address)
                .read()
                .unwrap();
            let expected_slot2 = gen_word_from(&[
                "0x012c", // value = 300 (offset 2-3, 2 bytes)
                "0x01",   // flag2 = true (offset 1, 1 byte)
                "0x01",   // flag1 = true (offset 0, 1 byte)
            ]);
            assert_eq!(
                slot2_value, expected_slot2,
                "Slot 2 should match Solidity layout for struct[2]"
            );

            // Verify roundtrip
            let loaded: Vec<SmallStruct> = vec_slot.read().unwrap();
            assert_eq!(loaded, data, "Vec<SmallStruct> roundtrip failed");
        });
    }

    #[test]
    fn test_vec_length_slot_isolation() {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let len_slot = U256::from(2600);

            // Store a vec with 3 u8 elements
            let data = vec![100u8, 200, 250];
            let mut vec_slot = Slot::<Vec<u8>>::new(len_slot, address);
            vec_slot.write(data.clone()).unwrap();

            // Verify base slot contains length
            let length_value = U256::handle(len_slot, LayoutCtx::FULL, address)
                .read()
                .unwrap();
            assert_eq!(length_value, U256::from(3), "Length slot incorrect");

            // Verify data starts at keccak256(len_slot), not len_slot + 1
            let data_start = calc_data_slot(len_slot);
            assert_ne!(
                data_start,
                len_slot + U256::ONE,
                "Data should not start immediately after base slot"
            );

            // Verify data slot matches expected Solidity byte layout
            let data_slot_value = U256::handle(data_start, LayoutCtx::FULL, address)
                .read()
                .unwrap();

            let expected = gen_word_from(&[
                "0xfa", // elem[2] = 250
                "0xc8", // elem[1] = 200
                "0x64", // elem[0] = 100
            ]);
            assert_eq!(
                data_slot_value, expected,
                "Data slot should match Solidity byte layout"
            );

            // Also verify each element can be extracted
            for (i, &expected) in data.iter().enumerate() {
                let offset = i; // equivalent to: `i * u8::BYTES`
                let actual =
                    Slot::<u8>::new_with_ctx(data_start, LayoutCtx::packed(offset), address)
                        .read()
                        .unwrap();
                assert_eq!(actual, expected, "mismatch: elem[{i}] at offset {offset}");
            }
        });
    }

    #[test]
    fn test_vec_overwrite_cleanup() {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let len_slot = U256::from(2700);
            let mut vec_slot = Slot::<Vec<u8>>::new(len_slot, address);

            // Store a vec with 5 u8 elements (requires 1 slot)
            let data_long = vec![1u8, 2, 3, 4, 5];
            vec_slot.write(data_long).unwrap();

            let data_start = calc_data_slot(len_slot);

            // Verify initial storage
            let slot0_before = U256::handle(data_start, LayoutCtx::FULL, address)
                .read()
                .unwrap();
            assert_ne!(slot0_before, U256::ZERO, "Initial data should be stored");

            // Overwrite with a shorter vec (3 elements)
            let data_short = vec![10u8, 20, 30];
            vec_slot.write(data_short.clone()).unwrap();

            // Verify length updated
            let length_value = U256::handle(len_slot, LayoutCtx::FULL, address)
                .read()
                .unwrap();
            assert_eq!(length_value, U256::from(3), "Length should be updated");

            // Verify new data can be extracted correctly (even though old data might remain)
            for (i, &expected) in data_short.iter().enumerate() {
                let offset = i; // equivalent to: `i * u8::BYTES`
                let actual =
                    Slot::<u8>::new_with_ctx(data_start, LayoutCtx::packed(offset), address)
                        .read()
                        .unwrap();
                assert_eq!(
                    actual, expected,
                    "mismatch: new_elem[{i}] at offset {offset}"
                );
            }

            let loaded: Vec<u8> = vec_slot.read().unwrap();
            assert_eq!(loaded, data_short, "Loaded vec should match short version");
            assert_eq!(loaded.len(), 3, "Length should be 3");

            // For full cleanup, delete first, then store
            vec_slot.delete().unwrap();
            vec_slot.write(data_short.clone()).unwrap();

            // Verify slot matches expected Solidity byte layout after delete+store
            let slot0_after_delete = U256::handle(data_start, LayoutCtx::FULL, address)
                .read()
                .unwrap();

            let expected = gen_word_from(&[
                "0x1e", // elem[2] = 30
                "0x14", // elem[1] = 20
                "0x0a", // elem[0] = 10
            ]);
            assert_eq!(
                slot0_after_delete, expected,
                "Slot should match Solidity byte layout after delete+store"
            );

            // Also verify each element can still be extracted
            for (i, &expected) in data_short.iter().enumerate() {
                let offset = i; // equivalent to: `i * u8::BYTES`
                let actual =
                    Slot::<u8>::new_with_ctx(data_start, LayoutCtx::packed(offset), address)
                        .read()
                        .unwrap();
                assert_eq!(actual, expected, "mismatch: elem[{i}] at offset {offset}");
            }
        });
    }

    // TODO(rusowsky): Implement and test multi-slot support
    // fn test_multi_slot_array() {
    //     #[derive(Storable)]
    //     struct MultiSlotStruct {
    //         field1: U256, // slot 0
    //         field2: U256, // slot 1
    //         field3: U256, // slot 2
    //     }

    //     let (mut storage, address) = setup_storage();
    //     // MIGRATION TODO: This test needs to be migrated to StorageCtx::enter pattern

    //     let len_slot = U256::from(2700);

    //     let data: Vec<MultiSlotStruct> = vec![MultiSlotStruct {
    //         field1: U256::ONE,
    //         field2: U256::from(2),
    //         field3: U256::from(3),
    //     }];

    //     data.store(storage, len_slot, 0).unwrap();

    //     let data_start = calc_data_slot(len_slot);
    // }

    // -- VEC HANDLER TESTS --------------------------------------------------------
    // Tests that verify VecHandler API methods

    #[test]
    fn test_vec_handler_read_write() {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let len_slot = U256::random();
            let mut handler = VecHandler::<U256>::new(len_slot, address);

            // Test write and read
            let data = vec![U256::random(), U256::random(), U256::random()];
            handler.write(data.clone()).unwrap();

            let loaded = handler.read().unwrap();
            assert_eq!(loaded, data, "Vec read/write roundtrip failed");
        });
    }

    #[test]
    fn test_vec_handler_delete() {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let len_slot = U256::random();
            let mut handler = VecHandler::<u8>::new(len_slot, address);

            // Write some data
            handler.write(vec![1, 2, 3, 4, 5]).unwrap();
            assert_eq!(handler.read().unwrap().len(), 5);

            // Delete
            handler.delete().unwrap();

            // Verify empty
            let loaded = handler.read().unwrap();
            assert!(loaded.is_empty(), "Vec should be empty after delete");

            // Verify length slot is cleared
            let length = U256::handle(len_slot, LayoutCtx::FULL, address)
                .read()
                .unwrap();
            assert_eq!(length, U256::ZERO, "Length slot should be zero");
        });
    }

    #[test]
    fn test_vec_handler_at_read_write() {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let len_slot = U256::random();
            let mut handler = VecHandler::<U256>::new(len_slot, address);

            // Write full vector first
            let data = vec![U256::from(10), U256::from(20), U256::from(30)];
            let mut vec_slot = Slot::<Vec<U256>>::new(len_slot, address);
            vec_slot.write(data).unwrap();

            // Test reading individual elements via at()
            let elem0 = handler[0].read().unwrap();
            let elem1 = handler[1].read().unwrap();
            let elem2 = handler[2].read().unwrap();

            assert_eq!(elem0, U256::from(10));
            assert_eq!(elem1, U256::from(20));
            assert_eq!(elem2, U256::from(30));

            // Test writing individual elements via at()
            handler[1].write(U256::from(99)).unwrap();

            // Verify via read
            let updated = handler.read().unwrap();
            assert_eq!(
                updated,
                vec![U256::from(10), U256::from(99), U256::from(30)]
            );
        });
    }

    #[test]
    fn test_vec_handler_push_pop() {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let len_slot = U256::random();
            let handler = VecHandler::<U256>::new(len_slot, address);

            let val1 = U256::random();
            let val2 = U256::random();
            let val3 = U256::random();

            // Test push
            handler.push(val1).unwrap();
            handler.push(val2).unwrap();
            handler.push(val3).unwrap();

            assert_eq!(handler.len().unwrap(), 3);

            // Test pop
            assert_eq!(handler.pop().unwrap(), Some(val3));
            assert_eq!(handler.pop().unwrap(), Some(val2));
            assert_eq!(handler.pop().unwrap(), Some(val1));
            assert_eq!(handler.pop().unwrap(), None);

            assert_eq!(handler.len().unwrap(), 0);
        });
    }

    #[test]
    fn test_vec_handler_len() {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let len_slot = U256::random();
            let handler = VecHandler::<Address>::new(len_slot, address);

            // Initial length should be 0
            assert_eq!(handler.len().unwrap(), 0);

            // Push elements and verify length
            handler.push(Address::random()).unwrap();
            assert_eq!(handler.len().unwrap(), 1);

            handler.push(Address::random()).unwrap();
            assert_eq!(handler.len().unwrap(), 2);

            handler.push(Address::random()).unwrap();
            assert_eq!(handler.len().unwrap(), 3);

            // Pop and verify length decreases
            handler.pop().unwrap();
            assert_eq!(handler.len().unwrap(), 2);
        });
    }

    #[test]
    fn test_vec_handler_push_pop_packed_types() {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let len_slot = U256::random();
            let handler = VecHandler::<u8>::new(len_slot, address);

            // Push 35 elements (crosses slot boundary: 32 in slot 0, 3 in slot 1)
            for i in 0..35 {
                handler.push(i as u8).unwrap();
            }

            assert_eq!(handler.len().unwrap(), 35);

            // Verify values
            for i in 0..35 {
                let val = handler[i].read().unwrap();
                assert_eq!(val, i as u8);
            }

            // Pop all and verify
            for i in (0..35).rev() {
                let popped = handler.pop().unwrap();
                assert_eq!(popped, Some(i as u8));
            }

            assert_eq!(handler.len().unwrap(), 0);
        });
    }

    #[test]
    fn test_vec_handler_at_oob_check() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let len_slot = U256::random();
            let handler = VecHandler::<U256>::new(len_slot, address);

            // Empty vec - any index should return None
            assert!(handler.at(0)?.is_none());

            // Push 2 elements
            handler.push(U256::from(10))?;
            handler.push(U256::from(20))?;

            // Valid indices should return Some and read the correct values
            assert!(handler.at(0)?.is_some());
            assert!(handler.at(1)?.is_some());
            assert_eq!(handler.at(0)?.unwrap().read()?, U256::from(10));
            assert_eq!(handler.at(1)?.unwrap().read()?, U256::from(20));

            // OOB indices should return None
            assert!(handler.at(3)?.is_none());

            Ok(())
        })
    }

    #[test]
    fn test_vec_push_at_max_capacity() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut len_slot = Slot::<U256>::new(U256::ZERO, address);

            // Test packed type
            let handler = VecHandler::<u32>::new(U256::ZERO, address);
            let max_index = u32::MAX as usize / u32::BYTES;

            // Manually write max_index - 1 to length slot
            len_slot.write(U256::from(max_index - 1))?;

            // Push should succeed once (length becomes max_index)
            handler.push(1)?;
            assert_eq!(handler.len()?, max_index);

            // Can read element at len - 1
            let elem = handler.at(max_index - 1)?;
            assert_eq!(elem.unwrap().read()?, 1);

            // Next push should fail
            let result = handler.push(1);
            assert!(result.is_err());

            // Test unpacked type (U256: 32 bytes, max_index = u32::MAX / 1)
            let handler = VecHandler::<U256>::new(U256::ZERO, address);
            let max_index = u32::MAX as usize;
            let value = U256::random();

            // Manually write max_index - 1 to length slot
            len_slot.write(U256::from(max_index - 1))?;

            // Push should succeed once (length becomes max_index)
            handler.push(value)?;
            assert_eq!(handler.len()?, max_index);

            // Can read element at len - 1
            let elem = handler.at(max_index - 1)?;
            assert!(elem.is_some());
            assert_eq!(elem.unwrap().read()?, value);

            // Next push should fail
            let result = handler.push(value);
            assert!(result.is_err());

            Ok(())
        })
    }

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
        fn proptest_vec_u8_roundtrip(data in arb_u8_vec(100), len_slot in arb_safe_slot()) {
            let (mut storage, address) = setup_storage();

            StorageCtx::enter(&mut storage, || {
                let data_len = data.len();
            let mut vec_slot = Slot::<Vec<u8>>::new(len_slot, address);

            // Store → Load roundtrip
            vec_slot.write(data.clone())?;
            let loaded: Vec<u8> = vec_slot.read()?;
            prop_assert_eq!(&loaded, &data, "Vec<u8> roundtrip failed");

            // Delete + verify cleanup
            vec_slot.delete()?;
            let after_delete: Vec<u8> = vec_slot.read()?;
            prop_assert!(after_delete.is_empty(), "Vec not empty after delete");

            // Verify data slots are cleared (if length > 0)
            if data_len > 0 {
                let data_start = calc_data_slot(len_slot);
                let byte_count = u8::BYTES;
                let slot_count = calc_packed_slot_count(data_len, byte_count);

                for i in 0..slot_count {
                    let slot_value = U256::handle(data_start + U256::from(i), LayoutCtx::FULL, address).read()?;
                    prop_assert_eq!(slot_value, U256::ZERO, "Data slot {} not cleared", i);
                }
            }

                Ok(())
            }).unwrap();
        }

        #[test]
        fn proptest_vec_u16_roundtrip(data in arb_u16_vec(100), len_slot in arb_safe_slot()) {
            let (mut storage, address) = setup_storage();

            StorageCtx::enter(&mut storage, || {
                let data_len = data.len();
            let mut vec_slot = Slot::<Vec<u16>>::new(len_slot, address);

            // Store → Load roundtrip
            vec_slot.write(data.clone())?;
            let loaded: Vec<u16> = vec_slot.read()?;
            prop_assert_eq!(&loaded, &data, "Vec<u16> roundtrip failed");

            // Delete + verify cleanup
            vec_slot.delete()?;
            let after_delete: Vec<u16> = vec_slot.read()?;
            prop_assert!(after_delete.is_empty(), "Vec not empty after delete");

            // Verify data slots are cleared (if length > 0)
            if data_len > 0 {
                let data_start = calc_data_slot(len_slot);
                let byte_count = u16::BYTES;
                let slot_count = calc_packed_slot_count(data_len, byte_count);

                for i in 0..slot_count {
                    let slot_value = U256::handle(data_start + U256::from(i), LayoutCtx::FULL, address).read()?;
                    prop_assert_eq!(slot_value, U256::ZERO, "Data slot {} not cleared", i);
                }
            }

                Ok(())
            }).unwrap();
        }

        #[test]
        fn proptest_vec_u32_roundtrip(data in arb_u32_vec(100), len_slot in arb_safe_slot()) {
            let (mut storage, address) = setup_storage();

            StorageCtx::enter(&mut storage, || {
                let data_len = data.len();
            let mut vec_slot = Slot::<Vec<u32>>::new(len_slot, address);

            // Store → Load roundtrip
            vec_slot.write(data.clone())?;
            let loaded: Vec<u32> = vec_slot.read()?;
            prop_assert_eq!(&loaded, &data, "Vec<u32> roundtrip failed");

            // Delete + verify cleanup
            vec_slot.delete()?;
            let after_delete: Vec<u32> = vec_slot.read()?;
            prop_assert!(after_delete.is_empty(), "Vec not empty after delete");

            // Verify data slots are cleared (if length > 0)
            if data_len > 0 {
                let data_start = calc_data_slot(len_slot);
                let byte_count = u32::BYTES;
                let slot_count = calc_packed_slot_count(data_len, byte_count);

                for i in 0..slot_count {
                    let slot_value = U256::handle(data_start + U256::from(i), LayoutCtx::FULL, address).read()?;
                    prop_assert_eq!(slot_value, U256::ZERO, "Data slot {} not cleared", i);
                }
            }

                Ok(())
            }).unwrap();
        }

        #[test]
        fn proptest_vec_u64_roundtrip(data in arb_u64_vec(100), len_slot in arb_safe_slot()) {
            let (mut storage, address) = setup_storage();

            StorageCtx::enter(&mut storage, || {
                let data_len = data.len();
            let mut vec_slot = Slot::<Vec<u64>>::new(len_slot, address);

            // Store → Load roundtrip
            vec_slot.write(data.clone())?;
            let loaded: Vec<u64> = vec_slot.read()?;
            prop_assert_eq!(&loaded, &data, "Vec<u64> roundtrip failed");

            // Delete + verify cleanup
            vec_slot.delete()?;
            let after_delete: Vec<u64> = vec_slot.read()?;
            prop_assert!(after_delete.is_empty(), "Vec not empty after delete");

            // Verify data slots are cleared (if length > 0)
            if data_len > 0 {
                let data_start = calc_data_slot(len_slot);
                let byte_count = u64::BYTES;
                let slot_count = calc_packed_slot_count(data_len, byte_count);

                for i in 0..slot_count {
                    let slot_value = U256::handle(data_start + U256::from(i), LayoutCtx::FULL, address).read()?;
                    prop_assert_eq!(slot_value, U256::ZERO, "Data slot {} not cleared", i);
                }
            }

                Ok(())
            }).unwrap();
        }

        #[test]
        fn proptest_vec_u128_roundtrip(data in arb_u128_vec(50), len_slot in arb_safe_slot()) {
            let (mut storage, address) = setup_storage();

            StorageCtx::enter(&mut storage, || {
                let data_len = data.len();
            let mut vec_slot = Slot::<Vec<u128>>::new(len_slot, address);

            // Store → Load roundtrip
            vec_slot.write(data.clone())?;
            let loaded: Vec<u128> = vec_slot.read()?;
            prop_assert_eq!(&loaded, &data, "Vec<u128> roundtrip failed");

            // Delete + verify cleanup
            vec_slot.delete()?;
            let after_delete: Vec<u128> = vec_slot.read()?;
            prop_assert!(after_delete.is_empty(), "Vec not empty after delete");

            // Verify data slots are cleared (if length > 0)
            if data_len > 0 {
                let data_start = calc_data_slot(len_slot);
                let byte_count = u128::BYTES;
                let slot_count = calc_packed_slot_count(data_len, byte_count);

                for i in 0..slot_count {
                    let slot_value = U256::handle(data_start + U256::from(i), LayoutCtx::FULL, address).read()?;
                    prop_assert_eq!(slot_value, U256::ZERO, "Data slot {} not cleared", i);
                }
            }

                Ok(())
            }).unwrap();
        }

        #[test]
        fn proptest_vec_u256_roundtrip(data in arb_u256_vec(50), len_slot in arb_safe_slot()) {
            let (mut storage, address) = setup_storage();

            StorageCtx::enter(&mut storage, || {
                let data_len = data.len();
            let mut vec_slot = Slot::<Vec<U256>>::new(len_slot, address);

            // Store → Load roundtrip
            vec_slot.write(data.clone())?;
            let loaded: Vec<U256> = vec_slot.read()?;
            prop_assert_eq!(&loaded, &data, "Vec<U256> roundtrip failed");

            // Delete + verify cleanup
            vec_slot.delete()?;
            let after_delete: Vec<U256> = vec_slot.read()?;
            prop_assert!(after_delete.is_empty(), "Vec not empty after delete");

            // Verify data slots are cleared (if length > 0)
            if data_len > 0 {
                let data_start = calc_data_slot(len_slot);

                for i in 0..data_len {
                    let slot_value = U256::handle(data_start + U256::from(i), LayoutCtx::FULL, address).read()?;
                    prop_assert_eq!(slot_value, U256::ZERO, "Data slot {} not cleared", i);
                }
            }

                Ok(())
            }).unwrap();
        }

        #[test]
        fn proptest_vec_address_roundtrip(data in arb_address_vec(50), len_slot in arb_safe_slot()) {
            let (mut storage, address) = setup_storage();

            StorageCtx::enter(&mut storage, || {
                let data_len = data.len();
            let mut vec_slot = Slot::<Vec<Address>>::new(len_slot, address);

            // Store → Load roundtrip
            vec_slot.write(data.clone())?;
            let loaded: Vec<Address> = vec_slot.read()?;
            prop_assert_eq!(&loaded, &data, "Vec<Address> roundtrip failed");

            // Delete + verify cleanup
            vec_slot.delete()?;
            let after_delete: Vec<Address> = vec_slot.read()?;
            prop_assert!(after_delete.is_empty(), "Vec not empty after delete");

                // Verify data slots are cleared (if length > 0)
                // Address is 20 bytes, but 32 % 20 != 0, so they don't pack and each uses one slot
                if data_len > 0 {
                    let data_start = calc_data_slot(len_slot);

                    for i in 0..data_len {
                        let slot_value = U256::handle(data_start + U256::from(i), LayoutCtx::FULL, address).read()?;
                        prop_assert_eq!(slot_value, U256::ZERO, "Data slot {} not cleared", i);
                    }
                }

                Ok(())
            }).unwrap();
        }

        #[test]
        fn proptest_vec_delete(data in arb_u8_vec(100), len_slot in arb_safe_slot()) {
            let (mut storage, address) = setup_storage();

            StorageCtx::enter(&mut storage, || {
                let mut vec_slot = Slot::<Vec<u8>>::new(len_slot, address);

            // Store data
            vec_slot.write(data.clone())?;

            // Delete
            vec_slot.delete()?;

            // Verify empty after delete
            let loaded: Vec<u8> = vec_slot.read()?;
            prop_assert!(loaded.is_empty(), "Vec not empty after delete");

                // Verify data slots are cleared (if length > 0)
                if !data.is_empty() {
                    let data_start = calc_data_slot(len_slot);
                    let byte_count = u8::BYTES;
                    let slot_count = calc_packed_slot_count(data.len(), byte_count);

                    for i in 0..slot_count {
                        let slot_value = U256::handle(data_start + U256::from(i), LayoutCtx::FULL, address).read()?;
                        prop_assert_eq!(slot_value, U256::ZERO, "Data slot {} not cleared", i);
                    }
                }

                Ok(())
            }).unwrap();
        }

        #[test]
        fn proptest_vec_struct_roundtrip(data in arb_test_struct_vec(50), len_slot in arb_safe_slot()) {
            let (mut storage, address) = setup_storage();

            StorageCtx::enter(&mut storage, || {
                let data_len = data.len();
            let mut vec_slot = Slot::<Vec<TestStruct>>::new(len_slot, address);

            // Store → Load roundtrip
            vec_slot.write(data.clone())?;
            let loaded: Vec<TestStruct> = vec_slot.read()?;
            prop_assert_eq!(&loaded, &data, "Vec<TestStruct> roundtrip failed");

            // Delete + verify cleanup
            vec_slot.delete()?;
            let after_delete: Vec<TestStruct> = vec_slot.read()?;
            prop_assert!(after_delete.is_empty(), "Vec not empty after delete");

                // Verify data slots are cleared (if length > 0)
                if data_len > 0 {
                    let data_start = calc_data_slot(len_slot);

                    for i in 0..data_len {
                        let slot_value = U256::handle(data_start + U256::from(i), LayoutCtx::FULL, address).read()?;
                        prop_assert_eq!(slot_value, U256::ZERO, "Data slot {} not cleared", i);
                    }
                }

                Ok(())
            }).unwrap();
        }
    }
}
