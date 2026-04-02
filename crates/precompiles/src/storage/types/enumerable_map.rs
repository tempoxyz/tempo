//! OpenZeppelin's EnumerableMap implementation for EVM storage using Rust primitives.
//! <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/structs/EnumerableMap.sol>
//!
//! # Storage Layout
//!
//! EnumerableMap uses three storage structures (OZ-compatible):
//! - **Keys Vec**: A `Vec<K>` storing all map keys at `keccak256(base_slot)`
//! - **Positions Mapping**: A `Mapping<K, u32>` at `base_slot + 1` storing 1-indexed positions
//!   - Position 0 means the key is not in the map
//!   - Position N means the key is at index N-1 in the keys array
//! - **Values Mapping**: A `Mapping<K, V>` at `base_slot + 2` storing mapped values
//!
//! # Design
//!
//! Two complementary types:
//! - `EnumerableMap<K, V>`: Read-only in-memory snapshot. `Vec<(K, V)>` wrapper.
//! - `EnumerableMapHandler<K, V>`: Storage operations with a unified handler cache.
//!
//! Unlike a naive composition of `Set<K>` + `Mapping<K, V>`, the handler uses a single
//! `HandlerCache` for key-based lookups. This avoids redundant `HashMap` lookups and
//! `keccak256` slot derivations that would occur with two separate caches (one for the
//! set's positions mapping and one for the values mapping).
//!
//! # Usage Patterns
//!
//! ## Single Operations (O(1) each)
//! ```ignore
//! handler.insert(key, value)?;   // Direct storage write
//! handler.remove(&key)?;         // Direct storage write
//! handler.contains(&key)?;       // Direct storage read
//! handler.get(&key)?;            // Direct storage read
//! ```
//!
//! ## Bulk Read
//! ```ignore
//! let map: EnumerableMap<K, V> = handler.read()?;
//! for (key, value) in &map {
//!     // Iteration preserves storage order
//! }
//! ```

use alloy::primitives::{Address, U256};
use std::{fmt, hash::Hash, ops::Deref};

use crate::{
    error::{Result, TempoPrecompileError},
    storage::{
        Handler, Layout, LayoutCtx, Storable, StorableType, StorageKey, StorageOps,
        types::{HandlerCache, Slot, vec::VecHandler},
    },
};

/// An ordered map that preserves storage order of keys.
///
/// Note: order is **not stable across removals** due to swap-and-pop.
///
/// This is a read-only snapshot of map data. For single-element mutations,
/// use `EnumerableMapHandler` methods directly.
///
/// Implements `Deref<Target = [(K, V)]>`, so all slice methods are available.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnumerableMap<K, V>(Vec<(K, V)>);

impl<K, V> EnumerableMap<K, V> {
    /// Creates a new empty map.
    #[inline]
    pub fn new() -> Self {
        Self(Vec::new())
    }
}

impl<K, V> Deref for EnumerableMap<K, V> {
    type Target = [(K, V)];

    #[inline]
    fn deref(&self) -> &[(K, V)] {
        &self.0
    }
}

impl<K, V> From<EnumerableMap<K, V>> for Vec<(K, V)> {
    #[inline]
    fn from(map: EnumerableMap<K, V>) -> Self {
        map.0
    }
}

impl<K: Eq + Clone, V: Clone> From<Vec<(K, V)>> for EnumerableMap<K, V> {
    /// Creates a map from a vector of key-value pairs, removing duplicate keys.
    ///
    /// Preserves the order and value of first occurrences.
    fn from(vec: Vec<(K, V)>) -> Self {
        let mut seen = Vec::new();
        for (key, value) in vec {
            if !seen.iter().any(|(k, _)| k == &key) {
                seen.push((key, value));
            }
        }
        Self(seen)
    }
}

impl<K, V> IntoIterator for EnumerableMap<K, V> {
    type Item = (K, V);
    type IntoIter = std::vec::IntoIter<(K, V)>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, K, V> IntoIterator for &'a EnumerableMap<K, V> {
    type Item = &'a (K, V);
    type IntoIter = std::slice::Iter<'a, (K, V)>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// Cached handler pair for a single key: (value handler, position slot).
///
/// This struct combines both the value handler and position slot into a single
/// cache entry, avoiding separate cache lookups for the same key.
struct CachedHandlers<V: StorableType> {
    value: V::Handler,
    position: Slot<u32>,
}

/// Type-safe handler for accessing `EnumerableMap<K, V>` in storage.
///
/// Uses a unified `HandlerCache` to derive both value and position handlers
/// from a single key lookup, avoiding the redundant caches that would arise
/// from composing `SetHandler<K>` + `Mapping<K, V>`.
///
/// | Method       | OZ equivalent  |
/// |--------------|----------------|
/// | `insert()`   | `set()`        |
/// | `remove()`   | `remove()`     |
/// | `contains()` | `contains()`   |
/// | `get()`      | `get()`        |
/// | `try_get()`  | `tryGet()`     |
/// | `len()`      | `length()`     |
/// | `at()`       | `at()`         |
/// | `keys()`     | `keys()`       |
/// | `read()`     | N/A            |
pub struct EnumerableMapHandler<K, V>
where
    K: Storable + StorageKey + Hash + Eq + Clone,
    V: Storable,
{
    /// Handler for the keys vector (stores actual keys).
    keys: VecHandler<K>,
    /// Unified cache for key-based lookups: value handler + position slot.
    cache: HandlerCache<K, CachedHandlers<V>>,
    /// Base slot for the positions mapping (base_slot + 1).
    position_base_slot: U256,
    /// Base slot for the values mapping (base_slot + 2).
    value_base_slot: U256,
    /// The base slot for the map.
    base_slot: U256,
    /// Contract address.
    address: Address,
}

/// EnumerableMap occupies 3 slots:
///
/// - Slot 0: `Vec` length slot, with data at `keccak256(slot)`
/// - Slot 1: `Mapping` base slot for positions (key -> 1-indexed position)
/// - Slot 2: `Mapping` base slot for values (key -> value)
impl<K, V> StorableType for EnumerableMap<K, V>
where
    K: Storable + StorageKey + Hash + Eq + Clone,
    V: Storable,
    V::Handler: Handler<V>,
{
    const LAYOUT: Layout = Layout::Slots(3);
    const IS_DYNAMIC: bool = true;
    type Handler = EnumerableMapHandler<K, V>;

    fn handle(slot: U256, _ctx: LayoutCtx, address: Address) -> Self::Handler {
        EnumerableMapHandler::new(slot, address)
    }
}

impl<K, V> Storable for EnumerableMap<K, V>
where
    K: Storable + StorageKey + Hash + Eq + Clone,
    K::Handler: Handler<K>,
    V: Storable,
    V::Handler: Handler<V>,
{
    fn load<S: StorageOps>(storage: &S, slot: U256, _ctx: LayoutCtx) -> Result<Self> {
        let keys: Vec<K> = Vec::load(storage, slot, LayoutCtx::FULL)?;
        let value_base_slot = slot + U256::from(2);

        let mut entries = Vec::new();
        for key in keys {
            let value_slot = key.mapping_slot(value_base_slot);
            let value = V::load(storage, value_slot, LayoutCtx::FULL)?;
            entries.push((key, value));
        }
        Ok(Self(entries))
    }

    fn store<S: StorageOps>(&self, _storage: &mut S, _slot: U256, _ctx: LayoutCtx) -> Result<()> {
        Err(TempoPrecompileError::Fatal(
            "EnumerableMap must be stored via EnumerableMapHandler::write() to maintain invariants"
                .into(),
        ))
    }

    fn delete<S: StorageOps>(storage: &mut S, slot: U256, ctx: LayoutCtx) -> Result<()> {
        let keys: Vec<K> = Vec::load(storage, slot, LayoutCtx::FULL)?;
        let position_base_slot = slot + U256::ONE;
        let value_base_slot = slot + U256::from(2);

        for key in keys {
            let pos_slot = key.mapping_slot(position_base_slot);
            <U256 as Storable>::delete(storage, pos_slot, LayoutCtx::FULL)?;

            let val_slot = key.mapping_slot(value_base_slot);
            V::delete(storage, val_slot, LayoutCtx::FULL)?;
        }

        <Vec<K> as Storable>::delete(storage, slot, ctx)
    }
}

impl<K, V> EnumerableMapHandler<K, V>
where
    K: Storable + StorageKey + Hash + Eq + Clone,
    V: Storable,
{
    /// Creates a new handler for the map at the given base slot.
    ///
    /// - `base_slot`: Used as the Vec's length slot
    /// - `base_slot + 1`: Used as the positions Mapping's base slot
    /// - `base_slot + 2`: Used as the values Mapping's base slot
    pub fn new(base_slot: U256, address: Address) -> Self {
        Self {
            keys: VecHandler::new(base_slot, address),
            cache: HandlerCache::new(),
            position_base_slot: base_slot + U256::ONE,
            value_base_slot: base_slot + U256::from(2),
            base_slot,
            address,
        }
    }

    /// Returns the base storage slot for this map.
    #[inline]
    pub fn base_slot(&self) -> U256 {
        self.base_slot
    }

    /// Returns the number of key-value pairs in the map.
    #[inline]
    pub fn len(&self) -> Result<usize> {
        self.keys.len()
    }

    /// Returns whether the map is empty.
    #[inline]
    pub fn is_empty(&self) -> Result<bool> {
        self.keys.is_empty()
    }

    /// Returns the cached handlers (value + position) for the given key.
    #[inline]
    fn cached(&self, key: &K) -> &CachedHandlers<V> {
        let (pos_base, val_base, address) =
            (self.position_base_slot, self.value_base_slot, self.address);
        self.cache.get_or_insert(key, || CachedHandlers {
            value: V::handle(key.mapping_slot(val_base), LayoutCtx::FULL, address),
            position: Slot::new(key.mapping_slot(pos_base), address),
        })
    }

    /// Returns the cached handlers (value + position) for the given key (mutable).
    #[inline]
    fn cached_mut(&mut self, key: &K) -> &mut CachedHandlers<V> {
        let (pos_base, val_base, address) =
            (self.position_base_slot, self.value_base_slot, self.address);
        self.cache.get_or_insert_mut(key, || CachedHandlers {
            value: V::handle(key.mapping_slot(val_base), LayoutCtx::FULL, address),
            position: Slot::new(key.mapping_slot(pos_base), address),
        })
    }

    /// Returns true if the key is in the map.
    pub fn contains(&self, key: &K) -> Result<bool> {
        self.cached(key).position.read().map(|pos| pos != 0)
    }

    /// Returns the value for the given key, or `None` if not present.
    pub fn try_get(&self, key: &K) -> Result<Option<V>>
    where
        V::Handler: Handler<V>,
    {
        if !self.contains(key)? {
            return Ok(None);
        }
        Ok(Some(self.cached(key).value.read()?))
    }

    /// Returns the value for the given key.
    ///
    /// Returns an error if the key is not in the map.
    pub fn get(&self, key: &K) -> Result<V>
    where
        V::Handler: Handler<V>,
    {
        self.try_get(key)?
            .ok_or_else(|| TempoPrecompileError::Fatal("EnumerableMap: nonexistent key".into()))
    }

    /// Inserts a key-value pair into the map, or updates the value for an existing key.
    ///
    /// Returns `true` if the key was newly inserted (not already present).
    /// Returns `false` if the key already existed (value was updated).
    #[inline]
    pub fn insert(&mut self, key: K, value: V) -> Result<bool>
    where
        K::Handler: Handler<K>,
        V::Handler: Handler<V>,
    {
        // Read position first to check existence, before taking &mut self
        let position = self.cached(&key).position.read()?;

        let handlers = self.cached_mut(&key);

        // Write the value regardless (insert or update)
        handlers.value.write(value)?;

        // Already present: value updated, not newly inserted
        if position != 0 {
            return Ok(false);
        }

        // New key: read length, write position, push key
        let length = self.keys.len()?;
        self.cached_mut(&key).position.write(length as u32 + 1)?;

        // Push key to the array
        self.keys.push(key)?;

        Ok(true)
    }

    /// Removes a key-value pair from the map.
    ///
    /// Returns `true` if the key was removed. Otherwise, returns `false`.
    #[inline]
    pub fn remove(&mut self, key: &K) -> Result<bool>
    where
        K::Handler: Handler<K>,
        V::Handler: Handler<V>,
    {
        // Get position (1-indexed, 0 means not present)
        let position = self.cached(key).position.read()?;
        if position == 0 {
            return Ok(false);
        }

        let len = self.keys.len()?;
        if len == 0 || (position as usize) > len {
            return Err(TempoPrecompileError::Fatal(
                "EnumerableMap invariant violation: position exceeds length".into(),
            ));
        }

        let last_index = len - 1;
        let index = (position - 1) as usize;

        // Swap with last element if not already last
        if index != last_index {
            let last_key = self.keys[last_index].read()?;
            self.cached_mut(&last_key).position.write(position)?;
            self.keys[index].write(last_key)?;
        }

        // Delete the last key slot and decrement length
        self.keys[last_index].delete()?;
        Slot::<U256>::new(self.keys.len_slot(), self.address).write(U256::from(last_index))?;

        // Clear removed key's position and value
        let handlers = self.cached_mut(key);
        handlers.position.delete()?;
        handlers.value.delete()?;

        Ok(true)
    }

    /// Returns the key-value pair at the given index with bounds checking.
    ///
    /// # Returns
    /// - If the index is OOB, returns `Ok(None)`.
    /// - Otherwise, returns `Ok(Some((K, V)))`.
    pub fn at(&self, index: usize) -> Result<Option<(K, V)>>
    where
        K::Handler: Handler<K>,
        V::Handler: Handler<V>,
    {
        if index >= self.len()? {
            return Ok(None);
        }
        let key = self.keys[index].read()?;
        let value = self.cached(&key).value.read()?;
        Ok(Some((key, value)))
    }

    /// Reads all keys from the map.
    pub fn keys(&self) -> Result<Vec<K>>
    where
        K::Handler: Handler<K>,
    {
        let len = self.len()?;
        let mut result = Vec::new();
        for i in 0..len {
            result.push(self.keys[i].read()?);
        }
        Ok(result)
    }
}

impl<K, V> Handler<EnumerableMap<K, V>> for EnumerableMapHandler<K, V>
where
    K: Storable + StorageKey + Hash + Eq + Clone,
    K::Handler: Handler<K>,
    V: Storable,
    V::Handler: Handler<V>,
{
    /// Reads all key-value pairs from storage as an `EnumerableMap<K, V>`.
    fn read(&self) -> Result<EnumerableMap<K, V>> {
        let len = self.len()?;
        let mut entries = Vec::new();

        for i in 0..len {
            let key = self.keys[i].read()?;
            let value = self.cached(&key).value.read()?;
            entries.push((key, value));
        }

        Ok(EnumerableMap(entries))
    }

    /// Replaces the entire map with new contents.
    fn write(&mut self, value: EnumerableMap<K, V>) -> Result<()> {
        let old_len = self.keys.len()?;

        // Clear old positions and values
        for i in 0..old_len {
            let old_key = self.keys[i].read()?;
            let handlers = self.cached_mut(&old_key);
            handlers.position.delete()?;
            handlers.value.delete()?;
        }

        let new_len = value.0.len();

        // Write new entries
        for (index, (key, val)) in value.0.into_iter().enumerate() {
            let handlers = self.cached_mut(&key);
            handlers.position.write(index as u32 + 1)?;
            handlers.value.write(val)?;
            self.keys[index].write(key)?;
        }

        // Update length
        Slot::<U256>::new(self.keys.len_slot(), self.address).write(U256::from(new_len))?;

        // Clear leftover key slots if shrinking
        for i in new_len..old_len {
            self.keys[i].delete()?;
        }

        Ok(())
    }

    /// Deletes all key-value pairs from the map.
    fn delete(&mut self) -> Result<()> {
        let len = self.len()?;

        // Clear all positions and values
        for i in 0..len {
            let key = self.keys[i].read()?;
            let handlers = self.cached_mut(&key);
            handlers.position.delete()?;
            handlers.value.delete()?;
        }

        // Delete the underlying keys vector
        self.keys.delete()
    }

    fn t_read(&self) -> Result<EnumerableMap<K, V>> {
        Err(TempoPrecompileError::Fatal(
            "EnumerableMap types don't support transient storage".into(),
        ))
    }

    fn t_write(&mut self, _value: EnumerableMap<K, V>) -> Result<()> {
        Err(TempoPrecompileError::Fatal(
            "EnumerableMap types don't support transient storage".into(),
        ))
    }

    fn t_delete(&mut self) -> Result<()> {
        Err(TempoPrecompileError::Fatal(
            "EnumerableMap types don't support transient storage".into(),
        ))
    }
}

impl<K, V> fmt::Debug for EnumerableMapHandler<K, V>
where
    K: Storable + StorageKey + Hash + Eq + Clone,
    V: Storable,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnumerableMapHandler")
            .field("base_slot", &self.base_slot)
            .field("address", &self.address)
            .finish()
    }
}

impl<K, V> Clone for EnumerableMapHandler<K, V>
where
    K: Storable + StorageKey + Hash + Eq + Clone,
    V: Storable,
{
    fn clone(&self) -> Self {
        Self::new(self.base_slot, self.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{storage::StorageCtx, test_util::setup_storage};
    use alloy::primitives::Address;
    use proptest::prelude::*;

    // -- MAP TYPE TESTS -------------------------------------------------------

    #[test]
    fn test_map_from_vec_deduplicates() {
        let vec = vec![
            (U256::from(1), U256::from(10)),
            (U256::from(2), U256::from(20)),
            (U256::from(1), U256::from(99)),
        ];
        let map = EnumerableMap::from(vec);

        assert_eq!(map.len(), 2);
        // Keeps first occurrence
        assert_eq!(map[0], (U256::from(1), U256::from(10)));
        assert_eq!(map[1], (U256::from(2), U256::from(20)));
    }

    #[test]
    fn test_map_empty() {
        let map = EnumerableMap::<U256, U256>::new();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn test_map_into_vec() {
        let map = EnumerableMap(vec![
            (U256::from(1), U256::from(10)),
            (U256::from(2), U256::from(20)),
        ]);
        let vec: Vec<(U256, U256)> = map.into();
        assert_eq!(vec.len(), 2);
    }

    // -- HANDLER TESTS --------------------------------------------------------

    #[test]
    fn test_handler_insert_and_get() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut handler = EnumerableMapHandler::<Address, U256>::new(U256::ZERO, address);

            let key = Address::from([1u8; 20]);
            assert!(handler.insert(key, U256::from(42))?);
            assert_eq!(handler.get(&key)?, U256::from(42));
            assert_eq!(handler.len()?, 1);

            Ok(())
        })
    }

    #[test]
    fn test_handler_insert_updates_existing() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut handler = EnumerableMapHandler::<Address, U256>::new(U256::ZERO, address);

            let key = Address::from([1u8; 20]);
            assert!(handler.insert(key, U256::from(42))?);
            assert!(!handler.insert(key, U256::from(99))?);

            assert_eq!(handler.get(&key)?, U256::from(99));
            assert_eq!(handler.len()?, 1);

            Ok(())
        })
    }

    #[test]
    fn test_handler_contains() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut handler = EnumerableMapHandler::<Address, U256>::new(U256::ZERO, address);

            let key = Address::from([1u8; 20]);
            assert!(!handler.contains(&key)?);

            handler.insert(key, U256::from(42))?;
            assert!(handler.contains(&key)?);

            Ok(())
        })
    }

    #[test]
    fn test_handler_try_get() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut handler = EnumerableMapHandler::<Address, U256>::new(U256::ZERO, address);

            let key = Address::from([1u8; 20]);
            assert_eq!(handler.try_get(&key)?, None);

            handler.insert(key, U256::from(42))?;
            assert_eq!(handler.try_get(&key)?, Some(U256::from(42)));

            Ok(())
        })
    }

    #[test]
    fn test_handler_remove() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut handler = EnumerableMapHandler::<Address, U256>::new(U256::ZERO, address);

            let [k1, k2, k3] = [[1u8; 20], [2u8; 20], [3u8; 20]].map(Address::from);

            handler.insert(k1, U256::from(10))?;
            handler.insert(k2, U256::from(20))?;
            handler.insert(k3, U256::from(30))?;
            assert_eq!(handler.len()?, 3);

            // Remove middle element
            assert!(handler.remove(&k2)?);
            assert_eq!(handler.len()?, 2);
            assert!(!handler.contains(&k2)?);

            // k3 should have been swapped into k2's position
            assert!(handler.contains(&k1)?);
            assert!(handler.contains(&k3)?);
            assert_eq!(handler.get(&k1)?, U256::from(10));
            assert_eq!(handler.get(&k3)?, U256::from(30));

            Ok(())
        })
    }

    #[test]
    fn test_handler_remove_nonexistent() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut handler = EnumerableMapHandler::<Address, U256>::new(U256::ZERO, address);

            let key = Address::from([1u8; 20]);
            assert!(!handler.remove(&key)?);

            Ok(())
        })
    }

    #[test]
    fn test_handler_at() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut handler = EnumerableMapHandler::<U256, U256>::new(U256::ZERO, address);

            handler.insert(U256::from(10), U256::from(100))?;
            handler.insert(U256::from(20), U256::from(200))?;
            handler.insert(U256::from(30), U256::from(300))?;

            assert_eq!(handler.at(0)?, Some((U256::from(10), U256::from(100))));
            assert_eq!(handler.at(1)?, Some((U256::from(20), U256::from(200))));
            assert_eq!(handler.at(2)?, Some((U256::from(30), U256::from(300))));
            assert_eq!(handler.at(3)?, None);

            Ok(())
        })
    }

    #[test]
    fn test_handler_keys() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut handler = EnumerableMapHandler::<U256, U256>::new(U256::ZERO, address);

            handler.insert(U256::from(10), U256::from(100))?;
            handler.insert(U256::from(20), U256::from(200))?;

            let keys = handler.keys()?;
            assert_eq!(keys, vec![U256::from(10), U256::from(20)]);

            Ok(())
        })
    }

    #[test]
    fn test_handler_read() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut handler = EnumerableMapHandler::<U256, U256>::new(U256::ZERO, address);

            handler.insert(U256::from(1), U256::from(10))?;
            handler.insert(U256::from(2), U256::from(20))?;

            let map = handler.read()?;
            assert_eq!(map.len(), 2);
            assert_eq!(map[0], (U256::from(1), U256::from(10)));
            assert_eq!(map[1], (U256::from(2), U256::from(20)));

            Ok(())
        })
    }

    #[test]
    fn test_handler_write() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut handler = EnumerableMapHandler::<U256, U256>::new(U256::ZERO, address);

            handler.insert(U256::from(1), U256::from(10))?;
            handler.write(EnumerableMap::from(vec![
                (U256::from(10), U256::from(100)),
                (U256::from(20), U256::from(200)),
                (U256::from(30), U256::from(300)),
            ]))?;

            assert_eq!(handler.len()?, 3);
            assert!(!handler.contains(&U256::from(1))?);
            assert!(handler.contains(&U256::from(10))?);
            assert_eq!(handler.get(&U256::from(20))?, U256::from(200));

            // Write to shrink
            handler.write(EnumerableMap::from(vec![(U256::from(40), U256::from(400))]))?;
            assert_eq!(handler.len()?, 1);
            assert!(!handler.contains(&U256::from(10))?);

            // Write empty
            handler.write(EnumerableMap::new())?;
            assert!(handler.is_empty()?);

            Ok(())
        })
    }

    #[test]
    fn test_handler_delete() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut handler = EnumerableMapHandler::<U256, U256>::new(U256::ZERO, address);

            for i in 1..=3 {
                handler.insert(U256::from(i), U256::from(i * 10))?;
            }

            handler.delete()?;
            assert!(handler.is_empty()?);
            for i in 1..=3 {
                assert!(!handler.contains(&U256::from(i))?);
            }

            // Re-insert after delete
            handler.insert(U256::from(2), U256::from(20))?;
            assert_eq!(handler.at(0)?, Some((U256::from(2), U256::from(20))));
            assert_eq!(handler.len()?, 1);

            Ok(())
        })
    }

    #[test]
    fn test_handler_transient_storage_errors() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut handler = EnumerableMapHandler::<U256, U256>::new(U256::ZERO, address);
            assert!(handler.t_read().is_err());
            assert!(handler.t_write(EnumerableMap::new()).is_err());
            assert!(handler.t_delete().is_err());
            Ok(())
        })
    }

    #[test]
    fn test_handler_metadata() {
        let address = Address::ZERO;
        let handler = EnumerableMapHandler::<U256, U256>::new(U256::from(42), address);
        assert_eq!(handler.base_slot(), U256::from(42));

        let debug_str = format!("{handler:?}");
        assert!(debug_str.contains("EnumerableMapHandler"));

        let cloned = handler.clone();
        assert_eq!(cloned.base_slot(), handler.base_slot());
    }

    #[test]
    fn test_handler_multiple_remove_insert_cycles() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut handler = EnumerableMapHandler::<U256, U256>::new(U256::ZERO, address);

            for i in 0..5 {
                handler.insert(U256::from(i), U256::from(i * 10))?;
            }
            for i in 0..5 {
                assert!(handler.remove(&U256::from(i))?);
            }
            assert!(handler.is_empty()?);

            for i in 10..15 {
                handler.insert(U256::from(i), U256::from(i * 10))?;
            }
            assert_eq!(handler.len()?, 5);
            for i in 10..15 {
                assert!(handler.contains(&U256::from(i))?);
                assert_eq!(handler.get(&U256::from(i))?, U256::from(i * 10));
            }

            Ok(())
        })
    }

    #[test]
    fn test_handler_remove_first() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut handler = EnumerableMapHandler::<U256, U256>::new(U256::ZERO, address);

            handler.insert(U256::from(1), U256::from(10))?;
            handler.insert(U256::from(2), U256::from(20))?;
            handler.insert(U256::from(3), U256::from(30))?;

            // Remove first element — last element (3) should swap into position 0
            assert!(handler.remove(&U256::from(1))?);
            assert_eq!(handler.len()?, 2);
            assert_eq!(handler.at(0)?, Some((U256::from(3), U256::from(30))));
            assert_eq!(handler.at(1)?, Some((U256::from(2), U256::from(20))));

            Ok(())
        })
    }

    #[test]
    fn test_handler_remove_last() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut handler = EnumerableMapHandler::<U256, U256>::new(U256::ZERO, address);

            handler.insert(U256::from(1), U256::from(10))?;
            handler.insert(U256::from(2), U256::from(20))?;
            handler.insert(U256::from(3), U256::from(30))?;

            // Remove last element — no swap needed
            assert!(handler.remove(&U256::from(3))?);
            assert_eq!(handler.len()?, 2);
            assert_eq!(handler.at(0)?, Some((U256::from(1), U256::from(10))));
            assert_eq!(handler.at(1)?, Some((U256::from(2), U256::from(20))));

            Ok(())
        })
    }

    #[test]
    fn test_handler_remove_singleton() -> eyre::Result<()> {
        let (mut storage, address) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut handler = EnumerableMapHandler::<U256, U256>::new(U256::ZERO, address);

            handler.insert(U256::from(42), U256::from(420))?;

            assert!(handler.remove(&U256::from(42))?);
            assert!(handler.is_empty()?);
            assert!(!handler.contains(&U256::from(42))?);

            // Re-insert works after removing the only element
            handler.insert(U256::from(99), U256::from(990))?;
            assert_eq!(handler.len()?, 1);
            assert_eq!(handler.get(&U256::from(99))?, U256::from(990));

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
        fn proptest_insert_remove_contains(
            ops in prop::collection::vec(
                (any::<u64>(), any::<u64>(), any::<bool>()),
                1..50
            )
        ) {
            let (mut storage, address) = setup_storage();

            StorageCtx::enter(&mut storage, || -> std::result::Result<(), TestCaseError> {
                let mut handler = EnumerableMapHandler::<U256, U256>::new(U256::ZERO, address);
                let mut reference: Vec<(U256, U256)> = Vec::new();

                for (key_val, value_val, insert) in ops {
                    let key = U256::from(key_val % 20); // keep key space small for collisions
                    let value = U256::from(value_val);
                    if insert {
                        let existed = reference.iter().any(|(k, _)| k == &key);
                        let result = handler.insert(key, value)?;
                        prop_assert_eq!(result, !existed);
                        if existed {
                            // Update value
                            for (k, v) in &mut reference {
                                if *k == key {
                                    *v = value;
                                    break;
                                }
                            }
                        } else {
                            reference.push((key, value));
                        }
                    } else {
                        let existed = reference.iter().any(|(k, _)| k == &key);
                        let result = handler.remove(&key)?;
                        prop_assert_eq!(result, existed);
                        if existed {
                            reference.retain(|(k, _)| k != &key);
                        }
                    }
                }

                prop_assert_eq!(handler.len()?, reference.len());
                for (k, v) in &reference {
                    prop_assert!(handler.contains(k)?);
                    prop_assert_eq!(handler.get(k)?, *v);
                }

                Ok(())
            }).unwrap();
        }

        #[test]
        fn proptest_order_alignment(entries in prop::collection::vec(
            (arb_address(), any::<u64>().prop_map(U256::from)), 1..20
        )) {
            let (mut storage, address) = setup_storage();

            StorageCtx::enter(&mut storage, || -> std::result::Result<(), TestCaseError> {
                let mut handler = EnumerableMapHandler::<Address, U256>::new(U256::ZERO, address);

                for (key, value) in &entries {
                    handler.insert(*key, *value)?;
                }

                let map = handler.read()?;

                for i in 0..map.len() {
                    let (at_key, at_val) = handler.at(i)?.unwrap();
                    prop_assert_eq!(&map[i].0, &at_key, "Key mismatch at index {}", i);
                    prop_assert_eq!(&map[i].1, &at_val, "Value mismatch at index {}", i);
                }

                Ok(())
            }).unwrap();
        }
    }
}
