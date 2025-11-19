//! Fixed-size array handler for the `Storable` trait.
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

use alloy::primitives::U256;
use std::marker::PhantomData;

use crate::{
    error::Result,
    storage::{Storable, StorableType, StorageOps, packing::calc_element_loc, types::Slot},
};

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
    T: Storable<1> + StorableType,
{
    base_slot: U256,
    _phantom: PhantomData<T>,
}

impl<T, const N: usize> ArrayHandler<T, N>
where
    T: Storable<1> + StorableType,
{
    /// Creates a new handler for the array at the given base slot.
    #[inline]
    pub const fn new(base_slot: U256) -> Self {
        Self {
            base_slot,
            _phantom: PhantomData,
        }
    }

    /// Reads the entire array from storage.
    ///
    /// The `SLOTS` parameter must match the array's actual slot count.
    #[inline]
    pub fn read<S: StorageOps, const SLOTS: usize>(&self, storage: &mut S) -> Result<[T; N]>
    where
        [T; N]: Storable<SLOTS>,
    {
        <[T; N]>::load(storage, self.base_slot, crate::storage::LayoutCtx::FULL)
    }

    /// Writes the entire array to storage.
    ///
    /// The `SLOTS` parameter must match the array's actual slot count.
    #[inline]
    pub fn write<S: StorageOps, const SLOTS: usize>(
        &self,
        storage: &mut S,
        value: [T; N],
    ) -> Result<()>
    where
        [T; N]: Storable<SLOTS>,
    {
        value.store(storage, self.base_slot, crate::storage::LayoutCtx::FULL)
    }

    /// Deletes the entire array from storage (clears all elements).
    ///
    /// The `SLOTS` parameter must match the array's actual slot count.
    #[inline]
    pub fn delete<S: StorageOps, const SLOTS: usize>(&self, storage: &mut S) -> Result<()>
    where
        [T; N]: Storable<SLOTS>,
    {
        <[T; N]>::delete(storage, self.base_slot, crate::storage::LayoutCtx::FULL)
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
    pub fn at(&self, index: usize) -> Option<Slot<T>> {
        if index >= N {
            return None;
        }

        // Pack elements if they fit efficiently
        if T::BYTES <= 16 {
            Some(Slot::<T>::new_at_loc(
                self.base_slot,
                calc_element_loc(index, T::BYTES),
            ))
        } else {
            Some(Slot::<T>::new(self.base_slot + U256::from(index)))
        }
    }
}
