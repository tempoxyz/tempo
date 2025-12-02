//! Fixed-size array handler for the storage traits.
//!
//! # Storage Layout
//!
//! Fixed-size arrays `[T; N]` use Solidity-compatible array storage:
//! - **Base slot**: Arrays start directly at `base_slot` (not at keccak256)
//! - **Data slots**: Elements are stored sequentially, either packed or unpacked
//!
//! ## Packing Strategy
//!
//! - **Packed**: When `T::BYTES <= 16`, multiple elements fit in one slot
//! - **Unpacked**: When `T::BYTES > 16` or doesn't divide 32, each element uses full slot(s)

use alloy::primitives::{Address, U256};
use std::marker::PhantomData;
use tempo_precompiles_macros;

use crate::{
    error::Result,
    storage::{Handler, LayoutCtx, Storable, StorableType, packing, types::Slot},
};

// fixed-size arrays: [T; N] for primitive types T and sizes 1-32
tempo_precompiles_macros::storable_arrays!();
// nested arrays: [[T; M]; N] for small primitive types
tempo_precompiles_macros::storable_nested_arrays!();

/// Type-safe handler for accessing fixed-size arrays `[T; N]` in storage.
///
/// Unlike `VecHandler`, arrays have a fixed compile-time size and store elements
/// directly at the base slot (not at `keccak256(base_slot)`).
///
/// # Element Access
///
/// Use `at(index)` to get a `Slot<T>` for individual element operations:
/// - For packed elements (T::BYTES ≤ 16): returns a packed `Slot<T>` with byte offsets
/// - For unpacked elements: returns a full `Slot<T>` for the element's dedicated slot
/// - Returns `None` if index is out of bounds
///
/// # Example
///
/// ```ignore
/// let handler = <[u8; 32] as StorableType>::handle(base_slot, LayoutCtx::FULL);
///
/// // Full array operations
/// let array = handler.read(&mut storage)?;
/// handler.write(&mut storage, [1; 32])?;
///
/// // Individual element operations
/// if let Some(slot) = handler.at(0) {
///     let elem = slot.read(&mut storage)?;
///     slot.write(&mut storage, 42)?;
/// }
/// ```
pub struct ArrayHandler<T, const N: usize>
where
    T: StorableType,
{
    base_slot: U256,
    address: Address,
    _phantom: PhantomData<T>,
}

impl<T, const N: usize> ArrayHandler<T, N>
where
    T: StorableType,
{
    /// Creates a new handler for the array at the given base slot and address.
    #[inline]
    pub fn new(base_slot: U256, address: Address) -> Self {
        Self {
            base_slot,
            address,
            _phantom: PhantomData,
        }
    }

    /// Returns a `Slot` accessor for full-array operations.
    #[inline]
    fn as_slot(&self) -> Slot<[T; N]> {
        Slot::new(self.base_slot, self.address)
    }

    /// Returns the base storage slot where this array's data is stored.
    ///
    /// Single-slot arrays pack all fields into this slot.
    /// Multi-slot arrays use consecutive slots starting from this base.
    #[inline]
    pub fn base_slot(&self) -> ::alloy::primitives::U256 {
        self.base_slot
    }

    /// Returns the array size (known at compile time).
    #[inline]
    pub const fn len(&self) -> usize {
        N
    }

    /// Returns whether the array is empty (always false for N > 0).
    #[inline]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Returns a `Slot<T>` accessor for the element at the given index.
    ///
    /// The returned `Slot` automatically handles packing based on `T::BYTES`.
    ///
    /// Returns `None` if the index is out of bounds (>= N).
    #[inline]
    pub fn at(&self, index: usize) -> Option<T::Handler>
    where
        T: StorableType,
    {
        if index >= N {
            return None;
        }

        // Pack small elements into shared slots, use T::SLOTS for multi-slot types
        let (base_slot, layout_ctx) = if T::BYTES <= 16 {
            let location = packing::calc_element_loc(index, T::BYTES);
            (
                self.base_slot + U256::from(location.offset_slots),
                LayoutCtx::packed(location.offset_bytes),
            )
        } else {
            (
                self.base_slot + U256::from(index * T::SLOTS),
                LayoutCtx::FULL,
            )
        };

        Some(T::handle(base_slot, layout_ctx, self.address))
    }
}

impl<T, const N: usize> Handler<[T; N]> for ArrayHandler<T, N>
where
    T: StorableType,
    [T; N]: Storable,
{
    /// Reads the entire array from storage.
    #[inline]
    fn read(&self) -> Result<[T; N]> {
        self.as_slot().read()
    }

    /// Writes the entire array to storage.
    #[inline]
    fn write(&mut self, value: [T; N]) -> Result<()> {
        self.as_slot().write(value)
    }

    /// Deletes the entire array from storage (clears all elements).
    #[inline]
    fn delete(&mut self) -> Result<()> {
        self.as_slot().delete()
    }

    /// Reads the entire array from transient storage.
    #[inline]
    fn t_read(&self) -> Result<[T; N]> {
        self.as_slot().t_read()
    }

    /// Writes the entire array to transient storage.
    #[inline]
    fn t_write(&mut self, value: [T; N]) -> Result<()> {
        self.as_slot().t_write(value)
    }

    /// Deletes the entire array from transient storage (clears all elements).
    #[inline]
    fn t_delete(&mut self) -> Result<()> {
        self.as_slot().t_delete()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{
        Layout, LayoutCtx, PrecompileStorageProvider, StorageContext,
        hashmap::HashMapStorageProvider,
    };
    use proptest::prelude::*;

    // Strategy for generating random U256 slot values that won't overflow
    fn arb_safe_slot() -> impl Strategy<Value = U256> {
        any::<[u64; 4]>().prop_map(|limbs| {
            // Ensure we don't overflow by limiting to a reasonable range
            U256::from_limbs(limbs) % (U256::MAX - U256::from(10000))
        })
    }

    fn setup_storage() -> (HashMapStorageProvider, Address) {
        (HashMapStorageProvider::new(1), Address::random())
    }

    #[test]
    fn test_array_u8_32_single_slot() {
        let (mut storage, address) = setup_storage();
        let base_slot = U256::ZERO;

        // [u8; 32] should pack into exactly 1 slot
        let data: [u8; 32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];

        // Verify LAYOUT
        assert_eq!(<[u8; 32] as StorableType>::LAYOUT, Layout::Slots(1));

        // Store and load
        StorageContext::enter(&mut storage, || {
            let mut slot = <[u8; 32]>::handle(base_slot, LayoutCtx::FULL, address);
            slot.write(data).unwrap();
            let loaded = slot.read().unwrap();
            assert_eq!(loaded, data, "[u8; 32] roundtrip failed");

            // Verify delete
            slot.delete().unwrap();
        });
        let slot_value = storage.sload(address, base_slot).unwrap();
        assert_eq!(slot_value, U256::ZERO, "Slot not cleared after delete");
    }

    #[test]
    fn test_array_u64_5_multi_slot() {
        let (mut storage, address) = setup_storage();
        let base_slot = U256::from(100);

        // [u64; 5] should require 2 slots (5 * 8 = 40 bytes > 32)
        let data: [u64; 5] = [1, 2, 3, 4, 5];

        // Verify slot count
        assert_eq!(<[u64; 5] as StorableType>::LAYOUT, Layout::Slots(2));

        // Store and load
        StorageContext::enter(&mut storage, || {
            let mut slot = <[u64; 5]>::handle(base_slot, LayoutCtx::FULL, address);
            slot.write(data).unwrap();
            let loaded = slot.read().unwrap();
            assert_eq!(loaded, data, "[u64; 5] roundtrip failed");
        });

        // Verify both slots are used
        let slot0 = storage.sload(address, base_slot).unwrap();
        let slot1 = storage.sload(address, base_slot + U256::ONE).unwrap();
        assert_ne!(slot0, U256::ZERO, "Slot 0 should be non-zero");
        assert_ne!(slot1, U256::ZERO, "Slot 1 should be non-zero");

        // Verify delete clears both slots
        StorageContext::enter(&mut storage, || {
            let mut slot = <[u64; 5]>::handle(base_slot, LayoutCtx::FULL, address);
            slot.delete().unwrap();
        });
        let slot0_after = storage.sload(address, base_slot).unwrap();
        let slot1_after = storage.sload(address, base_slot + U256::ONE).unwrap();
        assert_eq!(slot0_after, U256::ZERO, "Slot 0 not cleared");
        assert_eq!(slot1_after, U256::ZERO, "Slot 1 not cleared");
    }

    #[test]
    fn test_array_u16_packing() {
        let (mut storage, address) = setup_storage();
        let base_slot = U256::from(200);

        // [u16; 16] should pack into exactly 1 slot (16 * 2 = 32 bytes)
        let data: [u16; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        // Verify slot count
        assert_eq!(<[u16; 16] as StorableType>::LAYOUT, Layout::Slots(1));

        // Store and load
        StorageContext::enter(&mut storage, || {
            let mut slot = <[u16; 16]>::handle(base_slot, LayoutCtx::FULL, address);
            slot.write(data).unwrap();
            let loaded = slot.read().unwrap();
            assert_eq!(loaded, data, "[u16; 16] roundtrip failed");
        });
    }

    #[test]
    fn test_array_u256_no_packing() {
        let (mut storage, address) = setup_storage();
        let base_slot = U256::from(300);

        // [U256; 3] should use 3 slots (no packing for 32-byte types)
        let data: [U256; 3] = [U256::from(12345), U256::from(67890), U256::from(111111)];

        // Verify slot count
        assert_eq!(<[U256; 3] as StorableType>::LAYOUT, Layout::Slots(3));

        // Store and load
        StorageContext::enter(&mut storage, || {
            let mut slot = <[U256; 3]>::handle(base_slot, LayoutCtx::FULL, address);
            slot.write(data).unwrap();
            let loaded = slot.read().unwrap();
            assert_eq!(loaded, data, "[U256; 3] roundtrip failed");
        });

        // Verify each element is in its own slot
        for (i, expected_value) in data.iter().enumerate() {
            let slot_value = storage.sload(address, base_slot + U256::from(i)).unwrap();
            assert_eq!(slot_value, *expected_value, "Slot {i} mismatch");
        }
    }

    #[test]
    fn test_array_address_no_packing() {
        let (mut storage, address) = setup_storage();
        let base_slot = U256::from(400);

        // [Address; 3] should use 3 slots (20 bytes doesn't divide 32 evenly)
        let data: [Address; 3] = [
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x22),
            Address::repeat_byte(0x33),
        ];

        // Verify slot count
        assert_eq!(<[Address; 3] as StorableType>::LAYOUT, Layout::Slots(3));

        // Store and load
        StorageContext::enter(&mut storage, || {
            let mut slot = <[Address; 3]>::handle(base_slot, LayoutCtx::FULL, address);
            slot.write(data).unwrap();
            let loaded = slot.read().unwrap();
            assert_eq!(loaded, data, "[Address; 3] roundtrip failed");
        });
    }

    #[test]
    fn test_array_empty_single_element() {
        let (mut storage, address) = setup_storage();
        let base_slot = U256::from(500);

        // [u8; 1] should use 1 slot
        let data: [u8; 1] = [42];

        // Verify slot count
        assert_eq!(<[u8; 1] as StorableType>::LAYOUT, Layout::Slots(1));

        // Store and load
        StorageContext::enter(&mut storage, || {
            let mut slot = <[u8; 1]>::handle(base_slot, LayoutCtx::FULL, address);
            slot.write(data).unwrap();
            let loaded = slot.read().unwrap();
            assert_eq!(loaded, data, "[u8; 1] roundtrip failed");
        });
    }

    #[test]
    fn test_nested_array_u8_4x8() {
        let (mut storage, address) = setup_storage();
        let base_slot = U256::from(600);

        // [[u8; 4]; 8] uses 8 slots (one per inner array)
        // Each inner [u8; 4] gets a full 32-byte slot, even though it only uses 4 bytes
        // This follows EVM's rule: nested arrays don't pack tightly across boundaries
        let data: [[u8; 4]; 8] = [
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            [9, 10, 11, 12],
            [13, 14, 15, 16],
            [17, 18, 19, 20],
            [21, 22, 23, 24],
            [25, 26, 27, 28],
            [29, 30, 31, 32],
        ];

        // Verify LAYOUT: 8 slots (one per inner array)
        assert_eq!(<[[u8; 4]; 8] as StorableType>::LAYOUT, Layout::Slots(8));

        // Store and load
        StorageContext::enter(&mut storage, || {
            let mut slot = <[[u8; 4]; 8]>::handle(base_slot, LayoutCtx::FULL, address);
            slot.write(data).unwrap();
            let loaded = slot.read().unwrap();
            assert_eq!(loaded, data, "[[u8; 4]; 8] roundtrip failed");

            // Verify delete clears all 8 slots
            slot.delete().unwrap();
        });
        for i in 0..8 {
            let slot_value = storage.sload(address, base_slot + U256::from(i)).unwrap();
            assert_eq!(slot_value, U256::ZERO, "Slot {i} not cleared after delete");
        }
    }

    #[test]
    fn test_nested_array_u16_2x8() {
        let (mut storage, address) = setup_storage();
        let base_slot = U256::from(700);

        // [[u16; 2]; 8] uses 8 slots (one per inner array)
        // Each inner [u16; 2] gets a full 32-byte slot, even though it only uses 4 bytes
        // Compare: flat [u16; 16] would pack into 1 slot (16 × 2 = 32 bytes)
        // But nested arrays don't pack across boundaries in EVM
        let data: [[u16; 2]; 8] = [
            [100, 101],
            [200, 201],
            [300, 301],
            [400, 401],
            [500, 501],
            [600, 601],
            [700, 701],
            [800, 801],
        ];

        // Verify LAYOUT: 8 slots (one per inner array)
        assert_eq!(<[[u16; 2]; 8] as StorableType>::LAYOUT, Layout::Slots(8));

        // Store and load
        StorageContext::enter(&mut storage, || {
            let mut slot = <[[u16; 2]; 8]>::handle(base_slot, LayoutCtx::FULL, address);
            slot.write(data).unwrap();
            let loaded = slot.read().unwrap();
            assert_eq!(loaded, data, "[[u16; 2]; 8] roundtrip failed");

            // Verify delete clears all 8 slots
            slot.delete().unwrap();
        });
        for i in 0..8 {
            let slot_value = storage.sload(address, base_slot + U256::from(i)).unwrap();
            assert_eq!(slot_value, U256::ZERO, "Slot {i} not cleared after delete");
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        #[test]
        fn test_array_u8_32(
            data in prop::array::uniform32(any::<u8>()),
            base_slot in arb_safe_slot()
        ) {
            let (mut storage, address) = setup_storage();

            // Store and load
            StorageContext::enter(&mut storage, || {
                let mut slot = <[u8; 32]>::handle(base_slot, LayoutCtx::FULL, address);
                slot.write(data).unwrap();
                let loaded = slot.read().unwrap();
                prop_assert_eq!(&loaded, &data, "[u8; 32] roundtrip failed");

                // Delete
                slot.delete().unwrap();
                Ok(())
            })?;
            let slot_value = storage.sload(address, base_slot).unwrap();
            prop_assert_eq!(slot_value, U256::ZERO, "Slot not cleared after delete");
        }

        #[test]
        fn test_array_u16_16(
            data in prop::array::uniform16(any::<u16>()),
            base_slot in arb_safe_slot()
        ) {
            let (mut storage, address) = setup_storage();

            // Store and load
            StorageContext::enter(&mut storage, || {
                let mut slot = <[u16; 16]>::handle(base_slot, LayoutCtx::FULL, address);
                slot.write(data).unwrap();
                let loaded = slot.read().unwrap();
                prop_assert_eq!(&loaded, &data, "[u16; 16] roundtrip failed");
                Ok(())
            })?;
        }

        #[test]
        fn test_array_u256_5(
            data in prop::array::uniform5(any::<u64>()).prop_map(|arr| arr.map(U256::from)),
            base_slot in arb_safe_slot()
        ) {
            let (mut storage, address) = setup_storage();

            // Store and load
            StorageContext::enter(&mut storage, || {
                let mut slot = <[U256; 5]>::handle(base_slot, LayoutCtx::FULL, address);
                slot.write(data).unwrap();
                let loaded = slot.read().unwrap();
                prop_assert_eq!(&loaded, &data, "[U256; 5] roundtrip failed");
                Ok(())
            })?;

            // Verify each element is in its own slot
            for (i, expected_value) in data.iter().enumerate() {
                let slot_value = storage.sload(address, base_slot + U256::from(i)).unwrap();
                prop_assert_eq!(slot_value, *expected_value, "Slot {} mismatch", i);
            }

            // Delete
            StorageContext::enter(&mut storage, || {
                let mut slot = <[U256; 5]>::handle(base_slot, LayoutCtx::FULL, address);
                slot.delete().unwrap();
                Ok::<(), proptest::test_runner::TestCaseError>(())
            })?;
            for i in 0..5 {
                let slot_value = storage.sload(address, base_slot + U256::from(i)).unwrap();
                prop_assert_eq!(slot_value, U256::ZERO, "Slot {} not cleared", i);
            }
        }
    }
}
