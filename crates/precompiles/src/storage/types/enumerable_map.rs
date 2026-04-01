//! OpenZeppelin's EnumerableMap implementation for EVM storage using Rust primitives.
//! <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/structs/EnumerableMap.sol>
//!
//! # Storage Layout
//!
//! EnumerableMap uses two storage structures:
//! - **Keys Set**: a `Set<K>` at `base_slot`, implemented as `Vec<K> + Mapping<K, u32>`
//! - **Values Mapping**: a `Mapping<K, V>` at `base_slot + 2`
//!
//! # Design
//!
//! - Keys are the authoritative membership source, just like OpenZeppelin's `EnumerableSet`
//! - Key membership, insertion, and removal are O(1)
//! - Removal uses swap-and-pop through the underlying set, so enumeration order is not stable

use alloy::primitives::{Address, U256};
use std::{
    fmt,
    hash::Hash,
    ops::{Index, IndexMut},
};

use crate::{
    error::{Result, TempoPrecompileError},
    storage::{
        Handler, Layout, LayoutCtx, Mapping, Set, SetHandler, Storable, StorableType, StorageKey,
        StorageOps,
    },
};

/// Enumerable map storage primitive backed by `Set<K> + Mapping<K, V>`.
pub struct EnumerableMap<K, V>
where
    K: Storable + StorageKey + Hash + Eq + Clone,
    V: StorableType,
{
    keys: SetHandler<K>,
    values: Mapping<K, V>,
    base_slot: U256,
    address: Address,
}

impl<K, V> EnumerableMap<K, V>
where
    K: Storable + StorageKey + Hash + Eq + Clone,
    V: StorableType,
{
    /// Creates a new enumerable map handler for the given base slot.
    #[inline]
    pub fn new(base_slot: U256, address: Address) -> Self {
        Self {
            keys: SetHandler::new(base_slot, address),
            values: Mapping::new(base_slot + U256::from(2), address),
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

    /// Returns whether the key is present in the map.
    #[inline]
    pub fn contains(&self, key: &K) -> Result<bool> {
        self.keys.contains(key)
    }

    /// Returns all keys in the map.
    #[inline]
    pub fn keys(&self) -> Result<Vec<K>>
    where
        K::Handler: Handler<K>,
    {
        self.keys.read().map(Into::into)
    }

    /// Returns the key-value pair at `index`.
    #[inline]
    pub fn at(&self, index: usize) -> Result<Option<(K, V)>>
    where
        K::Handler: Handler<K>,
        V: Storable,
        V::Handler: Handler<V>,
    {
        let Some(key) = self.keys.at(index)? else {
            return Ok(None);
        };

        let value = self.values.at(&key).read()?;
        Ok(Some((key, value)))
    }

    /// Adds or updates a key-value pair.
    ///
    /// Returns `true` if the key was added to the map.
    #[inline]
    pub fn set(&mut self, key: K, value: V) -> Result<bool>
    where
        K::Handler: Handler<K>,
        V: Storable,
        V::Handler: Handler<V>,
    {
        self.values.at_mut(&key).write(value)?;
        self.keys.insert(key)
    }

    /// Adds or updates a key-value pair by mutating the value handler in place.
    ///
    /// This mirrors `set` while avoiding the need to materialize a whole `V` value
    /// for structured storage types that are typically updated field-by-field.
    /// Returns `true` if the key was added to the map.
    #[inline]
    pub fn set_with<F>(&mut self, key: K, update: F) -> Result<bool>
    where
        K::Handler: Handler<K>,
        F: FnOnce(&mut V::Handler) -> Result<()>,
    {
        let inserted = self.keys.insert(key.clone())?;
        update(self.values.at_mut(&key))?;
        Ok(inserted)
    }

    /// Removes a key-value pair from the map.
    ///
    /// Returns `true` if the key was removed from the map.
    #[inline]
    pub fn remove(&mut self, key: &K) -> Result<bool>
    where
        K::Handler: Handler<K>,
        V: Storable,
        V::Handler: Handler<V>,
    {
        self.values.at_mut(key).delete()?;
        self.keys.remove(key)
    }

    /// Removes all key-value pairs from the map.
    #[inline]
    pub fn clear(&mut self) -> Result<()>
    where
        K::Handler: Handler<K>,
        V: Storable,
        V::Handler: Handler<V>,
    {
        let keys: Vec<K> = self.keys.read()?.into();
        for key in keys {
            self.values.at_mut(&key).delete()?;
        }

        self.keys.delete()
    }

    /// Returns the value handler for the given key.
    #[inline]
    pub fn value(&self, key: &K) -> &V::Handler {
        self.values.at(key)
    }

    /// Returns the mutable value handler for the given key.
    #[inline]
    pub fn value_mut(&mut self, key: &K) -> &mut V::Handler {
        self.values.at_mut(key)
    }
}

impl<K, V> Default for EnumerableMap<K, V>
where
    K: Storable + StorageKey + Hash + Eq + Clone,
    V: StorableType,
{
    fn default() -> Self {
        Self::new(U256::ZERO, Address::ZERO)
    }
}

impl<K, V> Storable for EnumerableMap<K, V>
where
    K: Storable + StorageKey + Hash + Eq + Clone,
    K::Handler: Handler<K>,
    V: Storable,
    V::Handler: Handler<V>,
{
    fn load<S: StorageOps>(_storage: &S, _slot: U256, _ctx: LayoutCtx) -> Result<Self> {
        Err(TempoPrecompileError::Fatal(
            "EnumerableMap must be accessed through its generated handler".into(),
        ))
    }

    fn store<S: StorageOps>(&self, _storage: &mut S, _slot: U256, _ctx: LayoutCtx) -> Result<()> {
        Err(TempoPrecompileError::Fatal(
            "EnumerableMap must be accessed through its generated handler".into(),
        ))
    }

    fn delete<S: StorageOps>(storage: &mut S, slot: U256, _ctx: LayoutCtx) -> Result<()> {
        let keys = Set::<K>::load(storage, slot, LayoutCtx::FULL)?;
        let values_slot = slot + U256::from(2);

        for key in &keys {
            V::delete(storage, key.mapping_slot(values_slot), LayoutCtx::FULL)?;
        }

        Set::<K>::delete(storage, slot, LayoutCtx::FULL)
    }
}

impl<K, V> Index<K> for EnumerableMap<K, V>
where
    K: Storable + StorageKey + Hash + Eq + Clone,
    V: StorableType,
{
    type Output = V::Handler;

    #[inline]
    fn index(&self, key: K) -> &Self::Output {
        &self.values[key]
    }
}

impl<K, V> IndexMut<K> for EnumerableMap<K, V>
where
    K: Storable + StorageKey + Hash + Eq + Clone,
    V: StorableType,
{
    #[inline]
    fn index_mut(&mut self, key: K) -> &mut Self::Output {
        &mut self.values[key]
    }
}

impl<K, V> StorableType for EnumerableMap<K, V>
where
    K: Storable + StorageKey + Hash + Eq + Clone,
    V: StorableType,
{
    const LAYOUT: Layout = Layout::Slots(3);
    const IS_DYNAMIC: bool = true;
    type Handler = Self;

    fn handle(slot: U256, _ctx: LayoutCtx, address: Address) -> Self::Handler {
        Self::new(slot, address)
    }
}

impl<K, V> fmt::Debug for EnumerableMap<K, V>
where
    K: Storable + StorageKey + Hash + Eq + Clone,
    V: StorableType,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnumerableMap")
            .field("base_slot", &self.base_slot)
            .field("address", &self.address)
            .finish()
    }
}

impl<K, V> Clone for EnumerableMap<K, V>
where
    K: Storable + StorageKey + Hash + Eq + Clone,
    V: StorableType,
{
    fn clone(&self) -> Self {
        Self::new(self.base_slot, self.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::{Handler, LayoutCtx, StorableType, StorageCtx},
        test_util::setup_storage,
    };
    use tempo_precompiles_macros::Storable;

    #[derive(Debug, Clone, Default, PartialEq, Eq, Storable)]
    struct TestScope {
        mode: u8,
        payload: u64,
    }

    #[derive(Debug, Clone, Storable, Default)]
    struct TestContainer {
        marker: u8,
        entries: EnumerableMap<Address, TestScope>,
        tail: u8,
    }

    #[test]
    fn test_enumerable_map_set_updates_existing_key_without_duplication() {
        let (mut storage, address) = setup_storage();
        StorageCtx::enter(&mut storage, || -> Result<()> {
            let mut map = EnumerableMap::<Address, u8>::new(U256::ZERO, address);
            let key = Address::repeat_byte(0x11);

            assert!(map.set(key, 7)?);
            assert!(!map.set(key, 9)?);

            assert_eq!(map.len()?, 1);
            assert!(map.contains(&key)?);
            assert_eq!(map[key].read()?, 9);

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_enumerable_map_remove_deletes_value_and_updates_index() {
        let (mut storage, address) = setup_storage();
        StorageCtx::enter(&mut storage, || -> Result<()> {
            let mut map = EnumerableMap::<Address, u8>::new(U256::ZERO, address);
            let key = Address::repeat_byte(0x33);

            assert!(map.set(key, 7)?);
            assert!(map.remove(&key)?);

            assert!(!map.contains(&key)?);
            assert!(map.keys()?.is_empty());
            assert_eq!(map[key].read()?, 0);

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_enumerable_map_at_reads_key_value_pairs() {
        let (mut storage, address) = setup_storage();
        StorageCtx::enter(&mut storage, || -> Result<()> {
            let mut map = EnumerableMap::<Address, u8>::new(U256::ZERO, address);
            let first = Address::repeat_byte(0x44);
            let second = Address::repeat_byte(0x55);

            assert!(map.set(first, 1)?);
            assert!(map.set(second, 2)?);

            assert_eq!(map.at(0)?, Some((first, 1)));
            assert_eq!(map.at(1)?, Some((second, 2)));
            assert_eq!(map.at(2)?, None);

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_enumerable_map_embedded_layout_and_persistence() {
        let (mut storage, address) = setup_storage();
        StorageCtx::enter(&mut storage, || -> Result<()> {
            let first = Address::repeat_byte(0x66);
            let second = Address::repeat_byte(0x77);

            let mut container = TestContainer::handle(U256::ZERO, LayoutCtx::FULL, address);

            assert_eq!(container.marker.slot(), U256::ZERO);
            assert_eq!(container.entries.base_slot(), U256::ONE);
            assert_eq!(container.tail.slot(), U256::from(4));

            container.marker.write(9)?;
            container.tail.write(7)?;

            container.entries.set_with(first, |scope| {
                scope.mode.write(2)?;
                scope.payload.write(11)
            })?;
            container.entries.set_with(second, |scope| {
                scope.mode.write(1)?;
                scope.payload.write(22)
            })?;

            let container = TestContainer::handle(U256::ZERO, LayoutCtx::FULL, address);
            assert_eq!(container.marker.read()?, 9);
            assert_eq!(container.tail.read()?, 7);
            assert_eq!(container.entries.keys()?, vec![first, second]);
            assert_eq!(container.entries[first].payload.read()?, 11);
            assert_eq!(container.entries[second].payload.read()?, 22);

            let mut container = TestContainer::handle(U256::ZERO, LayoutCtx::FULL, address);
            assert!(container.entries.remove(&first)?);

            let container = TestContainer::handle(U256::ZERO, LayoutCtx::FULL, address);
            assert_eq!(container.entries.keys()?, vec![second]);
            assert_eq!(container.entries[first].payload.read()?, 0);
            assert_eq!(container.marker.read()?, 9);
            assert_eq!(container.tail.read()?, 7);

            Ok(())
        })
        .unwrap();
    }
}
