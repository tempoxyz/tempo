//! OpenZeppelin's EnumerableSet implementation for EVM storage using Rust primitives.
//! <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/structs/EnumerableSet.sol>
//!
//! # Storage Layout
//!
//! EnumerableSet uses two storage structures:
//! - **Values Vec**: A `Vec<T>` storing all set elements at `keccak256(base_slot)`
//! - **Positions Mapping**: A `Mapping<T, u32>` at `base_slot + 1` storing 1-indexed positions
//!   - Position 0 means the value is not in the set
//!   - Position N means the value is at index N-1 in the values array
//!
//! # Design
//!
//! Two complementary types:
//! - `Set<T>`: Read-only in-memory snapshot. `Vec<T>` wrapper. Ordered like storage.
//! - `SetHandler<T>`: Storage operations.
//!
//! # Usage Patterns
//!
//! ## Single Operations (O(1) each)
//! ```ignore
//! handler.insert(addr)?;   // Direct storage write
//! handler.remove(&addr)?;  // Direct storage write
//! handler.contains(&addr)?; // Direct storage read
//! ```
//!
//! ## Bulk Read
//! ```ignore
//! let set: Set<Address> = handler.read()?;
//! for addr in &set {
//!     // Iteration preserves storage order
//!     // set[i] == handler.at(i)
//! }
//! ```
//!
//! ## Bulk Mutation
//! ```ignore
//! let mut vec: Vec<_> = handler.read()?.into();
//! vec.push(new_addr);
//! vec.retain(|a| a != &old_addr);
//! handler.write(vec.into())?;  // `Set::from(vec)` deduplicates
//! ```

use alloy::primitives::{Address, U256};
use std::{
    fmt,
    hash::Hash,
    ops::{Deref, Index},
};

use crate::{
    error::{Result, TempoPrecompileError},
    storage::{
        Handler, Layout, LayoutCtx, Storable, StorableType, StorageKey, StorageOps,
        types::{Mapping, Slot, vec::VecHandler},
    },
};

/// An ordered set that preserves insertion order.
///
/// This is a read-only snapshot of set data. To mutate:
/// 1. Convert to `Vec<T>` with `.into()`
/// 2. Modify the Vec
/// 3. Convert back with `Set::from(vec)` (deduplicates)
/// 4. Write with `handler.write(set)`
///
/// For single-element mutations, use `SetHandler` methods directly.
///
/// Implements `Deref<Target = [T]>`, so all slice methods are available:
/// `len()`, `is_empty()`, `iter()`, `get()`, `contains()`, indexing, etc.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Set<T>(Vec<T>);

impl<T> Set<T> {
    /// Creates a new empty set.
    #[inline]
    pub fn new() -> Self {
        Self(Vec::new())
    }
}

impl<T> Deref for Set<T> {
    type Target = [T];

    #[inline]
    fn deref(&self) -> &[T] {
        &self.0
    }
}

impl<T> From<Set<T>> for Vec<T> {
    #[inline]
    fn from(set: Set<T>) -> Self {
        set.0
    }
}

impl<T: Eq + Clone> From<Vec<T>> for Set<T> {
    /// Creates a set from a vector, removing duplicates.
    ///
    /// Preserves the order of first occurrences.
    fn from(vec: Vec<T>) -> Self {
        let mut seen = Vec::new();
        for item in vec {
            if !seen.contains(&item) {
                seen.push(item);
            }
        }
        Self(seen)
    }
}

impl<T: Eq + Clone> FromIterator<T> for Set<T> {
    /// Creates a set from an iterator, removing duplicates.
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let vec: Vec<T> = iter.into_iter().collect();
        Self::from(vec)
    }
}

impl<T> IntoIterator for Set<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a Set<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// Type-safe handler for accessing `Set<T>` in storage.
///
/// Provides the OZ storage operations but following the naming convention of `HashSet`:
///
/// | Method         | OZ equivalent    |
/// |----------------|------------------|
/// | `insert()`     | `add()`          |
/// | `remove()`     | `remove()`       |
/// | `contains()`   | `contains()`     |
/// | `len()`        | `length()`       |
/// | `at()`         | `at()`           |
/// | `read()`       | `values()`       |
/// | `read_range()` | `values_range()` |
///
/// Also implements `Handler<Set<T>>` for bulk operations:
/// - `read`: Load all elements as `Set<T>`
/// - `write`: Replace entire set
/// - `delete`: Remove all elements
pub struct SetHandler<T>
where
    T: Storable + StorageKey + Hash + Eq + Clone,
{
    /// Handler for the values vector (stores actual elements).
    values: VecHandler<T>,
    /// Handler for the positions mapping (value -> 1-indexed position).
    positions: Mapping<T, u32>,
    /// The base slot for the set.
    base_slot: U256,
    /// Contract address.
    address: Address,
}

/// Set occupies 2 slots:
///
/// - Slot 0: `Vec` length slot, with data at `keccak256(slot)`
/// - Slot 1: `Mapping` base slot for positions
impl<T> StorableType for Set<T>
where
    T: Storable + StorageKey + Hash + Eq + Clone,
{
    const LAYOUT: Layout = Layout::Slots(2);
    const IS_DYNAMIC: bool = true;
    type Handler = SetHandler<T>;

    fn handle(slot: U256, _ctx: LayoutCtx, address: Address) -> Self::Handler {
        SetHandler::new(slot, address)
    }
}

/// Storable implementation for `Set<T>`.
impl<T> Storable for Set<T>
where
    T: Storable + StorageKey + Hash + Eq + Clone,
    T::Handler: Handler<T>,
{
    fn load<S: StorageOps>(storage: &S, slot: U256, _ctx: LayoutCtx) -> Result<Self> {
        let values: Vec<T> = Vec::load(storage, slot, LayoutCtx::FULL)?;
        Ok(Self(values))
    }

    fn store<S: StorageOps>(&self, _storage: &mut S, _slot: U256, _ctx: LayoutCtx) -> Result<()> {
        Err(TempoPrecompileError::Fatal(
            "Set must be stored via SetHandler::write() to maintain position invariants".into(),
        ))
    }

    fn delete<S: StorageOps>(storage: &mut S, slot: U256, ctx: LayoutCtx) -> Result<()> {
        let values: Vec<T> = Vec::load(storage, slot, LayoutCtx::FULL)?;

        for value in values {
            let pos_slot = value.mapping_slot(slot + U256::ONE);
            <U256 as Storable>::delete(storage, pos_slot, LayoutCtx::FULL)?;
        }

        <Vec<T> as Storable>::delete(storage, slot, ctx)
    }
}

impl<T> SetHandler<T>
where
    T: Storable + StorageKey + Hash + Eq + Clone,
{
    /// Creates a new handler for the set at the given base slot.
    ///
    /// - `base_slot`: Used as the Vec's length slot
    /// - `base_slot + 1`: Used as the Mapping's base slot
    pub fn new(base_slot: U256, address: Address) -> Self {
        Self {
            values: VecHandler::new(base_slot, address),
            positions: Mapping::new(base_slot + U256::ONE, address),
            base_slot,
            address,
        }
    }

    /// Returns the base storage slot for this set.
    #[inline]
    pub fn base_slot(&self) -> U256 {
        self.base_slot
    }

    /// Returns the number of elements in the set.
    #[inline]
    pub fn len(&self) -> Result<usize> {
        self.values.len()
    }

    /// Returns whether the set is empty.
    #[inline]
    pub fn is_empty(&self) -> Result<bool> {
        self.values.is_empty()
    }

    /// Returns true if the value is in the set.
    pub fn contains(&self, value: &T) -> Result<bool>
    where
        T: StorageKey + Hash + Eq + Clone,
    {
        self.positions.at(value).read().map(|pos| pos != 0)
    }

    /// Inserts a value into the set.
    ///
    /// Returns `true` if the value was inserted (not already present).
    /// Returns `false` if the value was already in the set.
    #[inline]
    pub fn insert(&mut self, value: T) -> Result<bool>
    where
        T: StorageKey + Hash + Eq + Clone,
        T::Handler: Handler<T>,
    {
        // Check if already present
        if self.contains(&value)? {
            return Ok(false);
        }

        // Store position (1-indexed: position N means index N-1)
        let length = self.values.len()?;
        self.positions.at_mut(&value).write(length as u32 + 1)?;

        // Push value to the array
        self.values.push(value)?;

        Ok(true)
    }

    /// Removes a value from the set.
    ///
    /// Returns `true` if the value was removed. Otherwise, returns `false`.
    #[inline]
    pub fn remove(&mut self, value: &T) -> Result<bool>
    where
        T: StorageKey + Hash + Eq + Clone,
        T::Handler: Handler<T>,
    {
        // Get position (1-indexed, 0 means not present)
        let position = self.positions.at(value).read()?;
        if position == 0 {
            return Ok(false);
        }

        let len = self.values.len()?;
        // Validate invariants
        debug_assert!(
            len != 0 && (position as usize) <= len,
            "Set invariant violation: position exceeds length"
        );

        // Convert to 0-indexed
        let last_index = len - 1;
        let index = (position - 1) as usize;

        // Swap with last element if not already last
        if index != last_index {
            let last_value = self.values[last_index].read()?;
            self.positions.at_mut(&last_value).write(position)?;
            self.values[index].write(last_value)?;
        }

        // Delete the last element and decrement its length.
        // Equivalent to `self.values.pop()`, but without the OOB checks.
        self.values[last_index].delete()?;
        Slot::<U256>::new(self.values.len_slot(), self.address).write(U256::from(last_index))?;

        // Clear removed value's position
        self.positions.at_mut(value).delete()?;

        Ok(true)
    }

    /// Returns the value at the given index with bounds checking.
    ///
    /// # Returns
    /// - If the SLOAD to read the length fails, returns an error.
    /// - If the index is OOB, returns `Ok(None)`.
    /// - Otherwise, returns `Ok(Some(T))`.
    pub fn at(&self, index: usize) -> Result<Option<T>>
    where
        T::Handler: Handler<T>,
    {
        if index >= self.len()? {
            return Ok(None);
        }
        Ok(Some(self.values[index].read()?))
    }

    /// Reads a range of values from the set.
    ///
    /// This is a partial version of `read()` for when you only need a subset.
    pub fn read_range(&self, start: usize, end: usize) -> Result<Vec<T>>
    where
        T::Handler: Handler<T>,
    {
        let len = self.len()?;
        let end = end.min(len);
        let start = start.min(end);

        let mut result = Vec::with_capacity(end - start);
        for i in start..end {
            result.push(self.values[i].read()?);
        }
        Ok(result)
    }
}

impl<T> Handler<Set<T>> for SetHandler<T>
where
    T: Storable + StorageKey + Hash + Eq + Clone,
    T::Handler: Handler<T>,
{
    /// Reads all elements from storage as a `Set<T>`.
    ///
    /// The returned `Set` preserves storage order: `set[i] == handler.at(i)`.
    fn read(&self) -> Result<Set<T>> {
        let len = self.len()?;
        let mut vec = Vec::with_capacity(len);

        for i in 0..len {
            vec.push(self.values[i].read()?);
        }

        Ok(Set(vec))
    }

    /// Replaces the entire set with new contents.
    ///
    /// The input Set is deduplicated by the `From<Vec<T>>` conversion.
    fn write(&mut self, value: Set<T>) -> Result<()> {
        let old_len = self.values.len()?;
        let new_len = value.0.len();

        // Clear old positions
        for i in 0..old_len {
            let old_value = self.values[i].read()?;
            self.positions.at_mut(&old_value).delete()?;
        }

        // Write new values and positions (1-indexed)
        for (index, new_value) in value.0.into_iter().enumerate() {
            self.positions.at_mut(&new_value).write(index as u32 + 1)?;
            self.values[index].write(new_value)?;
        }

        // Update length
        Slot::<U256>::new(self.values.len_slot(), self.address).write(U256::from(new_len))?;

        // Clear leftover value slots if shrinking
        for i in new_len..old_len {
            self.values[i].delete()?;
        }

        Ok(())
    }

    /// Deletes all elements from the set.
    ///
    /// Clears both the values array and all position entries.
    fn delete(&mut self) -> Result<()> {
        let len = self.len()?;

        // Clear all position entries
        for i in 0..len {
            let value = self.values[i].read()?;
            self.positions.at_mut(&value).delete()?;
        }

        // Delete the underlying vector (clears length and data slots)
        self.values.delete()
    }

    fn t_read(&self) -> Result<Set<T>> {
        Err(TempoPrecompileError::Fatal(
            "Set types don't support transient storage".into(),
        ))
    }

    fn t_write(&mut self, _value: Set<T>) -> Result<()> {
        Err(TempoPrecompileError::Fatal(
            "Set types don't support transient storage".into(),
        ))
    }

    fn t_delete(&mut self) -> Result<()> {
        Err(TempoPrecompileError::Fatal(
            "Set types don't support transient storage".into(),
        ))
    }
}

impl<T> fmt::Debug for SetHandler<T>
where
    T: Storable + StorageKey + Hash + Eq + Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetHandler")
            .field("base_slot", &self.base_slot)
            .field("address", &self.address)
            .finish()
    }
}

impl<T> Clone for SetHandler<T>
where
    T: Storable + StorageKey + Hash + Eq + Clone,
{
    fn clone(&self) -> Self {
        Self::new(self.base_slot, self.address)
    }
}

impl<T> Index<usize> for SetHandler<T>
where
    T: Storable + StorageKey + Hash + Eq + Clone,
{
    type Output = T::Handler;

    /// Returns a reference to the cached handler for the given index (unchecked).
    ///
    /// **WARNING:** Does not check bounds. Caller must ensure that the index is valid.
    /// For checked access use `.at(index)` instead.
    fn index(&self, index: usize) -> &Self::Output {
        &self.values[index]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{storage::StorageCtx, test_util::setup_storage};
    use alloy::primitives::Address;
    use proptest::prelude::*;

    // -- SET TYPE TESTS -------------------------------------------------------

    #[test]
    fn test_set_from_vec_deduplicates() {
        let vec = vec![1, 2, 3, 2, 1, 4];
        let set = Set::from(vec);

        assert_eq!(set.len(), 4);
        assert_eq!(&set[..], &[1, 2, 3, 4]); // Order preserved
    }

    #[test]
    fn test_set_from_iter_deduplicates() {
        let set: Set<i32> = [1, 2, 3, 2, 1, 4].into_iter().collect();

        assert_eq!(set.len(), 4);
        assert!(set.contains(&1));
        assert!(set.contains(&4));
    }

    #[test]
    fn test_set_preserves_first_occurrence_order() {
        let vec = vec!['a', 'b', 'c', 'b', 'a', 'd'];
        let set = Set::from(vec);

        assert_eq!(&set[..], &['a', 'b', 'c', 'd']);
    }

    #[test]
    fn test_set_into_vec() {
        let set = Set::from(vec![1, 2, 3]);
        let vec: Vec<i32> = set.into();

        assert_eq!(vec, vec![1, 2, 3]);
    }

    #[test]
    fn test_set_iteration() {
        let set = Set::from(vec![10, 20, 30]);

        let collected: Vec<_> = set.iter().copied().collect();
        assert_eq!(collected, vec![10, 20, 30]);

        let collected2: Vec<_> = (&set).into_iter().copied().collect();
        assert_eq!(collected2, vec![10, 20, 30]);
    }

    #[test]
    fn test_set_get() {
        let set = Set::from(vec!['a', 'b', 'c']);

        assert_eq!(set.first(), Some(&'a'));
        assert_eq!(set.get(1), Some(&'b'));
        assert_eq!(set.get(2), Some(&'c'));
        assert_eq!(set.get(3), None);
    }

    #[test]
    fn test_set_deref_to_slice() {
        let set = Set::from(vec![1, 2, 3]);

        assert_eq!(set[0], 1);
        assert_eq!(set[1], 2);
        assert_eq!(set.len(), 3);
    }

    // -- HANDLER TESTS --------------------------------------------------------

    /// Tests the read -> Vec -> mutate -> write pattern documented in the module.
    #[test]
    fn test_set_write_via_vec_mutation() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut handler = SetHandler::<U256>::new(U256::ZERO, address);

            handler.insert(U256::ONE)?;
            handler.insert(U256::from(2))?;
            handler.insert(U256::from(3))?;

            // Read, convert to Vec, mutate, convert back, write
            let mut vec: Vec<U256> = handler.read()?.into();
            vec.push(U256::from(4));
            vec.push(U256::from(5));
            vec.retain(|&x| x != U256::from(2));

            handler.write(vec.into())?;

            assert_eq!(handler.len()?, 4);
            assert!(handler.contains(&U256::ONE)?);
            assert!(!handler.contains(&U256::from(2))?);
            assert!(handler.contains(&U256::from(3))?);
            assert!(handler.contains(&U256::from(4))?);
            assert!(handler.contains(&U256::from(5))?);

            Ok(())
        })
    }

    #[test]
    fn test_set_constructors_and_edge_cases() {
        assert!(Set::<i32>::new().is_empty());
        assert!(Set::<i32>::default().is_empty());
        assert!(Set::from(Vec::<i32>::new()).is_empty());

        let set = Set::from(vec![5, 5, 5, 5]);
        assert_eq!(set.len(), 1);
        assert_eq!(&set[..], &[5]);

        let collected: Vec<i32> = Set::from(vec![1, 2, 3]).into_iter().collect();
        assert_eq!(collected, vec![1, 2, 3]);

        assert_eq!(Set::from(vec![1, 2, 3]), Set::from(vec![1, 2, 3]));
        assert_ne!(Set::from(vec![1, 2, 3]), Set::from(vec![3, 2, 1]));
    }

    // -- HANDLER TESTS --------------------------------------------------------

    #[test]
    fn test_handler_empty_state() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut handler = SetHandler::<U256>::new(U256::ZERO, address);

            assert!(handler.is_empty()?);
            assert_eq!(handler.len()?, 0);
            assert!(!handler.contains(&U256::ONE)?);
            assert!(!handler.remove(&U256::ONE)?);
            assert_eq!(handler.at(0)?, None);
            assert_eq!(handler.at(100)?, None);
            assert!(handler.read()?.is_empty());
            assert!(handler.read_range(0, 10)?.is_empty());

            Ok(())
        })
    }

    #[test]
    fn test_handler_insert_remove_basics() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut handler = SetHandler::<U256>::new(U256::ZERO, address);

            assert!(handler.insert(U256::ONE)?);
            assert!(!handler.insert(U256::ONE)?);
            assert_eq!(handler.len()?, 1);

            assert!(handler.remove(&U256::ONE)?);
            assert!(handler.is_empty()?);
            assert!(!handler.contains(&U256::ONE)?);

            handler.insert(U256::from(1))?;
            handler.insert(U256::from(2))?;
            handler.remove(&U256::from(1))?;
            handler.insert(U256::from(3))?;
            assert_eq!(handler.len()?, 2);
            assert!(handler.contains(&U256::from(2))?);
            assert!(handler.contains(&U256::from(3))?);
            assert!(!handler.contains(&U256::from(1))?);

            Ok(())
        })
    }

    #[test]
    fn test_handler_remove_swap_semantics() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut handler = SetHandler::<U256>::new(U256::ZERO, address);

            handler.insert(U256::from(10))?;
            handler.insert(U256::from(20))?;
            handler.insert(U256::from(30))?;

            // Remove last: no swap needed
            assert!(handler.remove(&U256::from(30))?);
            assert_eq!(&handler.read()?[..], &[U256::from(10), U256::from(20)]);

            // Re-add and remove first: last swaps into position 0
            handler.insert(U256::from(30))?;
            assert!(handler.remove(&U256::from(10))?);
            assert_eq!(&handler.read()?[..], &[U256::from(30), U256::from(20)]);

            // Remove first of two
            assert!(handler.remove(&U256::from(30))?);
            assert_eq!(handler.len()?, 1);
            assert!(handler.contains(&U256::from(20))?);

            Ok(())
        })
    }

    #[test]
    fn test_handler_at_and_index() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut handler = SetHandler::<U256>::new(U256::ZERO, address);

            handler.insert(U256::from(10))?;
            handler.insert(U256::from(20))?;
            handler.insert(U256::from(30))?;

            assert_eq!(handler.at(0)?, Some(U256::from(10)));
            assert_eq!(handler.at(1)?, Some(U256::from(20)));
            assert_eq!(handler.at(2)?, Some(U256::from(30)));
            assert_eq!(handler.at(3)?, None);

            assert_eq!(handler[0].read()?, U256::from(10));
            assert_eq!(handler[1].read()?, U256::from(20));

            Ok(())
        })
    }

    #[test]
    fn test_handler_read_range() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut handler = SetHandler::<U256>::new(U256::ZERO, address);

            for i in 0..5 {
                handler.insert(U256::from(i))?;
            }

            assert_eq!(
                handler.read_range(1, 4)?,
                vec![U256::from(1), U256::from(2), U256::from(3)]
            );
            // end > len clamps
            assert_eq!(handler.read_range(0, 100)?.len(), 5);
            // start > end returns empty
            assert!(handler.read_range(5, 3)?.is_empty());

            Ok(())
        })
    }

    #[test]
    fn test_handler_write() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut handler = SetHandler::<U256>::new(U256::ZERO, address);

            // Write to grow (1 → 3)
            handler.insert(U256::from(1))?;
            handler.write(Set::from(vec![
                U256::from(10),
                U256::from(20),
                U256::from(30),
            ]))?;
            assert_eq!(handler.len()?, 3);
            assert!(!handler.contains(&U256::from(1))?);
            assert!(handler.contains(&U256::from(10))?);

            // Write to shrink (3 → 2)
            handler.write(Set::from(vec![U256::from(40), U256::from(50)]))?;
            assert_eq!(handler.len()?, 2);
            assert!(!handler.contains(&U256::from(10))?);

            // Write empty
            handler.write(Set::new())?;
            assert!(handler.is_empty()?);

            Ok(())
        })
    }

    #[test]
    fn test_handler_delete() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut handler = SetHandler::<U256>::new(U256::ZERO, address);

            for i in 1..=3 {
                handler.insert(U256::from(i))?;
            }

            handler.delete()?;
            assert!(handler.is_empty()?);
            for i in 1..=3 {
                assert!(!handler.contains(&U256::from(i))?);
            }

            // Re-insert after delete: positions were properly cleared
            handler.insert(U256::from(2))?;
            assert_eq!(handler.at(0)?, Some(U256::from(2)));
            assert_eq!(handler.len()?, 1);

            Ok(())
        })
    }

    #[test]
    fn test_handler_transient_storage_errors() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut handler = SetHandler::<U256>::new(U256::ZERO, address);
            assert!(handler.t_read().is_err());
            assert!(handler.t_write(Set::new()).is_err());
            assert!(handler.t_delete().is_err());
            Ok(())
        })
    }

    #[test]
    fn test_handler_metadata() {
        let address = Address::ZERO;
        let handler = SetHandler::<U256>::new(U256::from(42), address);
        assert_eq!(handler.base_slot(), U256::from(42));

        let debug_str = format!("{handler:?}");
        assert!(debug_str.contains("SetHandler"));

        let cloned = handler.clone();
        assert_eq!(cloned.base_slot(), handler.base_slot());
    }

    #[test]
    fn test_handler_address_set() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut handler = SetHandler::<Address>::new(U256::ZERO, address);

            let [a1, a2, a3] = [[1u8; 20], [2u8; 20], [3u8; 20]].map(Address::from);

            for a in [a1, a2, a3] {
                handler.insert(a)?;
            }
            assert_eq!(handler.len()?, 3);

            handler.remove(&a2)?;
            assert_eq!(handler.len()?, 2);
            assert!(!handler.contains(&a2)?);
            assert_eq!(handler.at(0)?, Some(a1));
            assert_eq!(handler.at(1)?, Some(a3));

            Ok(())
        })
    }

    #[test]
    fn test_handler_multiple_remove_insert_cycles() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut handler = SetHandler::<U256>::new(U256::ZERO, address);

            for i in 0..5 {
                handler.insert(U256::from(i))?;
            }
            for i in 0..5 {
                assert!(handler.remove(&U256::from(i))?);
            }
            assert!(handler.is_empty()?);

            for i in 10..15 {
                handler.insert(U256::from(i))?;
            }
            assert_eq!(handler.len()?, 5);
            for i in 10..15 {
                assert!(handler.contains(&U256::from(i))?);
            }

            Ok(())
        })
    }

    // -- PROPERTY TESTS -------------------------------------------------------

    fn arb_address() -> impl Strategy<Value = Address> {
        any::<[u8; 20]>().prop_map(Address::from)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn proptest_set_order_alignment(addresses in prop::collection::vec(arb_address(), 1..20)) {
            let (mut storage, address) = setup_storage();

            StorageCtx::enter(&mut storage, || -> std::result::Result<(), TestCaseError> {
                let mut handler = SetHandler::<Address>::new(U256::ZERO, address);

                for addr in &addresses {
                    handler.insert(*addr)?;
                }

                let set = handler.read()?;

                for i in 0..set.len() {
                    prop_assert_eq!(set.get(i).cloned(), handler.at(i)?, "Order mismatch at index {}", i);
                }

                Ok(())
            }).unwrap();
        }

        #[test]
        fn proptest_insert_remove_contains(
            ops in prop::collection::vec(
                (any::<u64>(), any::<bool>()),
                1..50
            )
        ) {
            let (mut storage, address) = setup_storage();

            StorageCtx::enter(&mut storage, || -> std::result::Result<(), TestCaseError> {
                let mut handler = SetHandler::<U256>::new(U256::ZERO, address);
                let mut reference: Vec<U256> = Vec::new();

                for (val, insert) in ops {
                    let value = U256::from(val % 20); // keep key space small for collisions
                    if insert {
                        let was_new = !reference.contains(&value);
                        let result = handler.insert(value)?;
                        prop_assert_eq!(result, was_new);
                        if was_new {
                            reference.push(value);
                        }
                    } else {
                        let existed = reference.contains(&value);
                        let result = handler.remove(&value)?;
                        prop_assert_eq!(result, existed);
                        if existed {
                            reference.retain(|v| v != &value);
                        }
                    }
                }

                prop_assert_eq!(handler.len()?, reference.len());
                for v in &reference {
                    prop_assert!(handler.contains(v)?);
                }

                Ok(())
            }).unwrap();
        }
    }
}
