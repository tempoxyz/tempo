//! Type-safe wrapper for EVM storage mappings (hash-based key-value storage).

use alloy::primitives::{U256, keccak256};
use std::marker::PhantomData;

use crate::{
    error::Result,
    storage::{Storable, StorableType, StorageKey, StorageOps, types::slot::SlotId},
};

/// Type-safe wrapper for EVM storage mappings (hash-based key-value storage).
///
/// # Type Parameters
///
/// - `K`: Key type (must implement `StorageKey`)
/// - `V`: Value type (must implement `Storable<N>`)
/// - `Base`: Zero-sized marker type identifying the base slot (implements `SlotId`)
///
/// # Storage Layout
///
/// Mappings use Solidity's storage layout:
/// - Base slot: `Base::SLOT`
/// - Actual slot for key `k`: `keccak256(k || base_slot)`
///
/// # Compile-Time Guarantees
///
/// - Different mappings have distinct types even with same K,V
/// - Base slot encoded in type system via `Base::SLOT`
#[derive(Debug, Clone, Copy)]
pub struct Mapping<K, V, Base: SlotId> {
    _phantom: PhantomData<(K, V, Base)>,
}

impl<K, V, Base: SlotId> Mapping<K, V, Base> {
    /// Creates a new `Mapping` marker.
    ///
    /// This is typically not called directly; instead, mappings are declared
    /// as struct fields and accessed via macro-generated methods.
    #[inline]
    pub const fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }

    /// Returns the U256 base storage slot number for this mapping.
    ///
    /// Returns the slot number from the `SlotId` associated const.
    #[inline]
    pub const fn slot() -> U256 {
        Base::SLOT
    }

    /// Reads a value from the mapping at the given key.
    ///
    /// This method:
    /// 1. Computes the storage slot via keccak256(key || base_slot)
    /// 2. Delegates to `Storable::load`, which reads `N` consecutive slots
    ///
    /// # Example
    ///
    /// ```ignore
    /// type NamedMapping = Mapping<Address, U256, BalancesSlotId>;
    /// let name = NamedMapping::read(&mut contract, user_address)?;
    /// ```
    #[inline]
    pub fn read<S: StorageOps, const N: usize>(storage: &mut S, key: K) -> Result<V>
    where
        K: StorageKey,
        V: Storable<N>,
    {
        let slot = mapping_slot(key.as_storage_bytes(), Base::SLOT);
        V::load(storage, slot)
    }

    /// Writes a value to the mapping at the given key.
    ///
    /// This method:
    /// 1. Computes the storage slot via keccak256(key || base_slot)
    /// 2. Delegates to `Storable::store`, which writes to `N` consecutive slots
    ///
    /// # Example
    ///
    /// ```ignore
    /// type NamedMapping = Mapping<Address, U256, BalancesSlotId>;
    /// NamedMapping::write(&mut contract, user_address, U256::from(100))?;
    /// ```
    #[inline]
    pub fn write<S: StorageOps, const N: usize>(storage: &mut S, key: K, value: V) -> Result<()>
    where
        K: StorageKey,
        V: Storable<N>,
    {
        let slot = mapping_slot(key.as_storage_bytes(), Base::SLOT);
        value.store(storage, slot)
    }

    /// Deletes the value from the mapping at the given key (sets all slots to zero).
    ///
    /// This method:
    /// 1. Computes the storage slot via keccak256(key || base_slot)
    /// 2. Delegates to `Storable::delete`, which sets `N` consecutive slots to zero
    ///
    /// # Example
    ///
    /// ```ignore
    /// type NamedMapping = Mapping<Address, U256, BalancesSlotId>;
    /// NamedMapping::delete(&mut contract, user_address)?;
    /// ```
    #[inline]
    pub fn delete<S: StorageOps, const N: usize>(storage: &mut S, key: K) -> Result<()>
    where
        K: StorageKey,
        V: Storable<N>,
    {
        let slot = mapping_slot(key.as_storage_bytes(), Base::SLOT);
        V::delete(storage, slot)
    }

    /// Reads a value from a mapping field within a struct at a given base slot.
    ///
    /// This method enables accessing mapping fields within structs when you have
    /// the struct's base slot at runtime and know the field's offset.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // For: mapping(bytes32 => Orderbook) books, where Orderbook.bids is at field offset 1
    /// let orderbook_base = mapping_slot(pair_key, BooksSlot::SLOT);
    /// let bid = Mapping::<i16, TickLevel, DummySlot>::read_at_offset(
    ///     &mut contract,
    ///     orderbook_base,
    ///     1,  // field offset
    ///     tick
    /// )?;
    /// ```
    #[inline]
    pub fn read_at_offset<S: StorageOps, const N: usize>(
        storage: &mut S,
        struct_base_slot: U256,
        field_offset_slots: usize,
        key: K,
    ) -> Result<V>
    where
        K: StorageKey,
        V: Storable<N>,
    {
        let field_slot = struct_base_slot + U256::from(field_offset_slots);
        let slot = mapping_slot(key.as_storage_bytes(), field_slot);
        V::load(storage, slot)
    }

    /// Reads a packed field from within a value stored in a mapping field at a given base slot.
    ///
    /// Use this when you have a mapping field within a struct, and the VALUES in that mapping
    /// are themselves structs with packed fields. This method computes the mapping slot and reads
    /// a specific packed field from the mapped value.
    #[inline]
    pub fn read_at_offset_packed<S: StorageOps>(
        storage: &mut S,
        value_field_offset_slots: usize,
        value_field_offset_bytes: usize,
        value_field_size_bytes: usize,
        key: K,
    ) -> Result<V>
    where
        K: StorageKey,
        V: Storable<1>,
    {
        let mapped_value_slot = mapping_slot(key.as_storage_bytes(), Base::SLOT);
        crate::storage::packing::read_packed_at(
            storage,
            mapped_value_slot,
            value_field_offset_slots,
            value_field_offset_bytes,
            value_field_size_bytes,
        )
    }

    /// Writes a value to a mapping field within a struct at a given base slot.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let orderbook_base = mapping_slot(pair_key, BooksSlot::SLOT);
    /// Mapping::<i16, TickLevel, DummySlot>::write_at_offset(
    ///     &mut contract,
    ///     orderbook_base,
    ///     1,  // field offset
    ///     tick,
    ///     tick_level
    /// )?;
    /// ```
    #[inline]
    pub fn write_at_offset<S: StorageOps, const N: usize>(
        storage: &mut S,
        struct_base_slot: U256,
        field_offset_slots: usize,
        key: K,
        value: V,
    ) -> Result<()>
    where
        K: StorageKey,
        V: Storable<N>,
    {
        let field_slot = struct_base_slot + U256::from(field_offset_slots);
        let slot = mapping_slot(key.as_storage_bytes(), field_slot);
        value.store(storage, slot)
    }

    /// Writes a packed field within a value stored in a mapping.
    ///
    /// Use this when you have a mapping and the VALUES in that mapping are structs with packed fields.
    /// This method computes the mapping slot and writes a specific packed field, preserving other
    /// fields in the same slot.
    #[inline]
    pub fn write_at_offset_packed<S: StorageOps>(
        storage: &mut S,
        value_field_offset_slots: usize,
        value_field_offset_bytes: usize,
        value_field_size_bytes: usize,
        key: K,
        value: V,
    ) -> Result<()>
    where
        K: StorageKey,
        V: Storable<1>,
    {
        let mapped_value_slot = mapping_slot(key.as_storage_bytes(), Base::SLOT);
        crate::storage::packing::write_packed_at(
            storage,
            mapped_value_slot,
            value_field_offset_slots,
            value_field_offset_bytes,
            value_field_size_bytes,
            &value,
        )
    }

    /// Deletes a packed field within a value stored in a mapping (sets bytes to zero).
    ///
    /// Use this when you have a mapping and the VALUES in that mapping are structs with packed fields.
    /// This method computes the mapping slot and clears a specific packed field, preserving other
    /// fields in the same slot.
    #[inline]
    pub fn delete_at_offset_packed<S: StorageOps>(
        storage: &mut S,
        value_field_offset_slots: usize,
        value_field_offset_bytes: usize,
        value_field_size_bytes: usize,
        key: K,
    ) -> Result<()>
    where
        K: StorageKey,
        V: Storable<1>,
    {
        let mapped_value_slot = mapping_slot(key.as_storage_bytes(), Base::SLOT);
        crate::storage::packing::clear_packed_at(
            storage,
            mapped_value_slot,
            value_field_offset_slots,
            value_field_offset_bytes,
            value_field_size_bytes,
        )
    }

    /// Deletes a value from a mapping field within a struct at a given base slot.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let orderbook_base = mapping_slot(pair_key, BooksSlot::SLOT);
    /// Mapping::<i16, TickLevel, DummySlot>::delete_at_offset(
    ///     &mut contract,
    ///     orderbook_base,
    ///     1,  // field offset
    ///     tick
    /// )?;
    /// ```
    #[inline]
    pub fn delete_at_offset<S: StorageOps, const N: usize>(
        storage: &mut S,
        struct_base_slot: U256,
        field_offset_slots: usize,
        key: K,
    ) -> Result<()>
    where
        K: StorageKey,
        V: Storable<N>,
    {
        let field_slot = struct_base_slot + U256::from(field_offset_slots);
        let slot = mapping_slot(key.as_storage_bytes(), field_slot);
        V::delete(storage, slot)
    }
}

impl<K1, K2, V, Base: SlotId, DummyId: SlotId> Mapping<K1, Mapping<K2, V, DummyId>, Base> {
    /// Reads a value from a nested mapping at the given keys.
    ///
    /// This method:
    /// 1. Computes the storage slot using: `keccak256(k2 || keccak256(k1 || base_slot))`
    /// 2. Delegates to `Storable::load`, which may read one or more consecutive slots
    ///
    /// # Example
    ///
    /// ```ignore
    /// type NestedMapping = Mapping<Address, Mapping<Address, U256, DummySlotId>, AllowancesSlotId>;
    /// let nested = NestedMapping::read_nested(
    ///     &mut contract,
    ///     owner_address,
    ///     spender_address
    /// )?;
    /// ```
    #[inline]
    pub fn read_nested<S: StorageOps, const N: usize>(
        storage: &mut S,
        key1: K1,
        key2: K2,
    ) -> Result<V>
    where
        K1: StorageKey,
        K2: StorageKey,
        V: Storable<N>,
    {
        let slot =
            double_mapping_slot(key1.as_storage_bytes(), key2.as_storage_bytes(), Base::SLOT);
        V::load(storage, slot)
    }

    /// Writes a value to a nested mapping at the given keys.
    ///
    /// This method:
    /// 1. Computes the storage slot using: `keccak256(k2 || keccak256(k1 || base_slot))`
    /// 2. Delegates to `Storable::store`, which may write one or more consecutive slots
    ///
    /// # Example
    ///
    /// ```ignore
    /// type NestedMapping = Mapping<Address, Mapping<Address, U256, DummySlotId>, AllowancesSlotId>;
    /// NestedMapping::write_nested(
    ///     &mut contract,
    ///     owner_address,
    ///     spender_address,
    ///     U256::from(1000)
    /// )?;
    /// ```
    #[inline]
    pub fn write_nested<S: StorageOps, const N: usize>(
        storage: &mut S,
        key1: K1,
        key2: K2,
        value: V,
    ) -> Result<()>
    where
        K1: StorageKey,
        K2: StorageKey,
        V: Storable<N>,
    {
        let slot =
            double_mapping_slot(key1.as_storage_bytes(), key2.as_storage_bytes(), Base::SLOT);
        value.store(storage, slot)
    }

    /// Deletes a value from a nested mapping at the given keys (sets all slots to zero).
    ///
    /// This method:
    /// 1. Computes the storage slot using: `keccak256(k2 || keccak256(k1 || base_slot))`
    /// 2. Delegates to `Storable::delete`, which sets `N` consecutive slots to zero
    ///
    /// # Example
    ///
    /// ```ignore
    /// type NestedMapping = Mapping<Address, Mapping<Address, U256, DummySlotId>, AllowancesSlotId>;
    /// NestedMapping::delete_nested(
    ///     &mut contract,
    ///     owner_address,
    ///     spender_address
    /// )?;
    /// ```
    #[inline]
    pub fn delete_nested<S: StorageOps, const N: usize>(
        storage: &mut S,
        key1: K1,
        key2: K2,
    ) -> Result<()>
    where
        K1: StorageKey,
        K2: StorageKey,
        V: Storable<N>,
    {
        let slot =
            double_mapping_slot(key1.as_storage_bytes(), key2.as_storage_bytes(), Base::SLOT);
        V::delete(storage, slot)
    }

    /// Reads a value from a nested mapping field within a struct at a runtime base slot.
    ///
    /// This enables accessing nested mapping fields within structs when you have
    /// the struct's base slot at runtime and know the field's offset.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // For a struct with nested mapping at field offset 3
    /// let struct_base = mapping_slot(key, StructSlot::SLOT);
    /// let value = Mapping::<Address, Mapping<Address, U256, DummySlot>, DummySlot>::read_nested_at_offset(
    ///     &mut storage,
    ///     struct_base,
    ///     3,  // field offset
    ///     owner,
    ///     spender
    /// )?;
    /// ```
    #[inline]
    pub fn read_nested_at_offset<S: StorageOps, const N: usize>(
        storage: &mut S,
        struct_base_slot: U256,
        field_offset_slots: usize,
        key1: K1,
        key2: K2,
    ) -> Result<V>
    where
        K1: StorageKey,
        K2: StorageKey,
        V: Storable<N>,
    {
        let field_slot = struct_base_slot + U256::from(field_offset_slots);
        let slot =
            double_mapping_slot(key1.as_storage_bytes(), key2.as_storage_bytes(), field_slot);
        V::load(storage, slot)
    }

    /// Writes a value to a nested mapping field within a struct at a runtime base slot.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let struct_base = mapping_slot(key, StructSlot::SLOT);
    /// Mapping::<Address, Mapping<Address, U256, DummySlot>, DummySlot>::write_nested_at_offset(
    ///     &mut storage,
    ///     struct_base,
    ///     3,  // field offset
    ///     owner,
    ///     spender,
    ///     allowance
    /// )?;
    /// ```
    #[inline]
    pub fn write_nested_at_offset<S: StorageOps, const N: usize>(
        storage: &mut S,
        struct_base_slot: U256,
        field_offset_slots: usize,
        key1: K1,
        key2: K2,
        value: V,
    ) -> Result<()>
    where
        K1: StorageKey,
        K2: StorageKey,
        V: Storable<N>,
    {
        let field_slot = struct_base_slot + U256::from(field_offset_slots);
        let slot =
            double_mapping_slot(key1.as_storage_bytes(), key2.as_storage_bytes(), field_slot);
        value.store(storage, slot)
    }

    /// Deletes a value from a nested mapping field within a struct at a runtime base slot.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let struct_base = mapping_slot(key, StructSlot::SLOT);
    /// Mapping::<Address, Mapping<Address, U256, DummySlot>, DummySlot>::delete_nested_at_offset(
    ///     &mut storage,
    ///     struct_base,
    ///     3,  // field offset
    ///     owner,
    ///     spender
    /// )?;
    /// ```
    #[inline]
    pub fn delete_nested_at_offset<S: StorageOps, const N: usize>(
        storage: &mut S,
        struct_base_slot: U256,
        field_offset_slots: usize,
        key1: K1,
        key2: K2,
    ) -> Result<()>
    where
        K1: StorageKey,
        K2: StorageKey,
        V: Storable<N>,
    {
        let field_slot = struct_base_slot + U256::from(field_offset_slots);
        let slot =
            double_mapping_slot(key1.as_storage_bytes(), key2.as_storage_bytes(), field_slot);
        V::delete(storage, slot)
    }

    /// Reads a packed field from within a value stored in a nested mapping.
    ///
    /// Use this when you have a nested mapping and the VALUES in that mapping are structs
    /// with packed fields. This method computes the double mapping slot and reads a specific
    /// packed field from the mapped value.
    #[inline]
    pub fn read_nested_at_offset_packed<S: StorageOps>(
        storage: &mut S,
        value_field_offset_slots: usize,
        value_field_offset_bytes: usize,
        value_field_size_bytes: usize,
        key1: K1,
        key2: K2,
    ) -> Result<V>
    where
        K1: StorageKey,
        K2: StorageKey,
        V: Storable<1>,
    {
        let mapped_value_slot =
            double_mapping_slot(key1.as_storage_bytes(), key2.as_storage_bytes(), Base::SLOT);
        crate::storage::packing::read_packed_at(
            storage,
            mapped_value_slot,
            value_field_offset_slots,
            value_field_offset_bytes,
            value_field_size_bytes,
        )
    }

    /// Writes a packed field within a value stored in a nested mapping.
    ///
    /// Use this when you have a nested mapping and the VALUES in that mapping are structs
    /// with packed fields. This method computes the double mapping slot and writes a specific
    /// packed field, preserving other fields in the same slot.
    #[inline]
    pub fn write_nested_at_offset_packed<S: StorageOps>(
        storage: &mut S,
        value_field_offset_slots: usize,
        value_field_offset_bytes: usize,
        value_field_size_bytes: usize,
        key1: K1,
        key2: K2,
        value: V,
    ) -> Result<()>
    where
        K1: StorageKey,
        K2: StorageKey,
        V: Storable<1>,
    {
        let mapped_value_slot =
            double_mapping_slot(key1.as_storage_bytes(), key2.as_storage_bytes(), Base::SLOT);
        crate::storage::packing::write_packed_at(
            storage,
            mapped_value_slot,
            value_field_offset_slots,
            value_field_offset_bytes,
            value_field_size_bytes,
            &value,
        )
    }

    /// Deletes a packed field within a value stored in a nested mapping (sets bytes to zero).
    ///
    /// Use this when you have a nested mapping and the VALUES in that mapping are structs
    /// with packed fields. This method computes the double mapping slot and clears a specific
    /// packed field, preserving other fields in the same slot.
    #[inline]
    pub fn delete_nested_at_offset_packed<S: StorageOps>(
        storage: &mut S,
        value_field_offset_slots: usize,
        value_field_offset_bytes: usize,
        value_field_size_bytes: usize,
        key1: K1,
        key2: K2,
    ) -> Result<()>
    where
        K1: StorageKey,
        K2: StorageKey,
        V: Storable<1>,
    {
        let mapped_value_slot =
            double_mapping_slot(key1.as_storage_bytes(), key2.as_storage_bytes(), Base::SLOT);
        crate::storage::packing::clear_packed_at(
            storage,
            mapped_value_slot,
            value_field_offset_slots,
            value_field_offset_bytes,
            value_field_size_bytes,
        )
    }
}

impl<K, V, Base: SlotId> Default for Mapping<K, V, Base> {
    fn default() -> Self {
        Self::new()
    }
}

// Mappings occupy a full 32-byte slot in the layout (used as a base for hashing),
// even though they don't store data in that slot directly.
//
// **NOTE:** Necessary to allow it to participate in struct layout calculations.
impl<K, V, Base: SlotId> StorableType for Mapping<K, V, Base> {
    const BYTE_COUNT: usize = 32;
}

pub struct DummySlot;
impl SlotId for DummySlot {
    const SLOT: U256 = U256::ZERO;
}

// -- HELPER FUNCTIONS ---------------------------------------------------------

fn left_pad_to_32(data: &[u8]) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[32 - data.len()..].copy_from_slice(data);
    buf
}

/// Compute storage slot for a mapping
#[inline]
pub fn mapping_slot<T: AsRef<[u8]>>(key: T, mapping_slot: U256) -> U256 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&left_pad_to_32(key.as_ref()));
    buf[32..].copy_from_slice(&mapping_slot.to_be_bytes::<32>());
    U256::from_be_bytes(keccak256(buf).0)
}

/// Compute storage slot for a double mapping (mapping\[key1\]\[key2\])
#[inline]
pub fn double_mapping_slot<T: AsRef<[u8]>, U: AsRef<[u8]>>(
    key1: T,
    key2: U,
    base_slot: U256,
) -> U256 {
    let intermediate_slot = mapping_slot(key1, base_slot);
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&left_pad_to_32(key2.as_ref()));
    buf[32..].copy_from_slice(&intermediate_slot.to_be_bytes::<32>());
    U256::from_be_bytes(keccak256(buf).0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{PrecompileStorageProvider, hashmap::HashMapStorageProvider};
    use alloy::primitives::{Address, B256, address, uint};
    use proptest::prelude::*;

    // Test helper that implements StorageOps
    struct TestContract<'a, S> {
        address: Address,
        storage: &'a mut S,
    }

    impl<'a, S: PrecompileStorageProvider> StorageOps for TestContract<'a, S> {
        fn sstore(&mut self, slot: U256, value: U256) -> Result<()> {
            self.storage.sstore(self.address, slot, value)
        }

        fn sload(&mut self, slot: U256) -> Result<U256> {
            self.storage.sload(self.address, slot)
        }
    }

    /// Helper to create a test contract with fresh storage.
    fn setup_test_contract<'a>(
        storage: &'a mut HashMapStorageProvider,
    ) -> TestContract<'a, HashMapStorageProvider> {
        TestContract {
            address: Address::random(),
            storage,
        }
    }

    // Test SlotId implementations
    struct TestSlot0;
    impl SlotId for TestSlot0 {
        const SLOT: U256 = U256::ZERO;
    }

    struct TestSlot1;
    impl SlotId for TestSlot1 {
        const SLOT: U256 = U256::ONE;
    }

    struct TestSlot2;
    impl SlotId for TestSlot2 {
        const SLOT: U256 = uint!(2_U256);
    }

    struct TestSlotMax;
    impl SlotId for TestSlotMax {
        const SLOT: U256 = U256::MAX;
    }

    // Property test strategies
    fn arb_address() -> impl Strategy<Value = Address> {
        any::<[u8; 20]>().prop_map(Address::from)
    }

    fn arb_u256() -> impl Strategy<Value = U256> {
        any::<[u64; 4]>().prop_map(U256::from_limbs)
    }

    #[test]
    fn test_mapping_slot_deterministic() {
        let key: B256 = U256::from(123).into();
        let slot1 = mapping_slot(key, U256::ZERO);
        let slot2 = mapping_slot(key, U256::ZERO);

        assert_eq!(slot1, slot2);
    }

    #[test]
    fn test_different_keys_different_slots() {
        let key1: B256 = U256::from(123).into();
        let key2: B256 = U256::from(456).into();

        let slot1 = mapping_slot(key1, U256::ZERO);
        let slot2 = mapping_slot(key2, U256::ZERO);

        assert_ne!(slot1, slot2);
    }

    #[test]
    fn test_tip20_balance_slots() {
        // Test balance slot calculation for TIP20 tokens (slot 10)
        let alice = address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        let bob = address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");

        let alice_balance_slot = mapping_slot(alice, U256::from(10));
        let bob_balance_slot = mapping_slot(bob, U256::from(10));

        println!("Alice balance slot: 0x{alice_balance_slot:064x}");
        println!("Bob balance slot: 0x{bob_balance_slot:064x}");

        // Verify they're different
        assert_ne!(alice_balance_slot, bob_balance_slot);
    }

    #[test]
    fn test_tip20_allowance_slots() {
        // Test allowance slot calculation for TIP20 tokens (slot 11)
        let alice = address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        let tip_fee_mgr = address!("0xfeec000000000000000000000000000000000000");

        let allowance_slot = double_mapping_slot(alice, tip_fee_mgr, U256::from(11));

        println!("Alice->TipFeeManager allowance slot: 0x{allowance_slot:064x}");

        // Just verify it's calculated consistently
        let allowance_slot2 = double_mapping_slot(alice, tip_fee_mgr, U256::from(11));
        assert_eq!(allowance_slot, allowance_slot2);
    }

    #[test]
    fn test_double_mapping_different_keys() {
        let alice = address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        let bob = address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
        let spender = address!("0xfeec000000000000000000000000000000000000");

        let alice_allowance = double_mapping_slot(alice, spender, U256::from(11));
        let bob_allowance = double_mapping_slot(bob, spender, U256::from(11));

        assert_ne!(alice_allowance, bob_allowance);
    }

    #[test]
    fn test_left_padding_correctness() {
        let addr = address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        let bytes: &[u8] = addr.as_ref();
        let padded = left_pad_to_32(bytes);

        // First 12 bytes should be zeros (left padding)
        assert_eq!(&padded[..12], &[0u8; 12]);
        // Last 20 bytes should be the address
        assert_eq!(&padded[12..], bytes);
    }

    #[test]
    fn test_mapping_slot_encoding() {
        let key = address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        let base_slot = U256::from(10);

        // Manual computation to validate
        let mut buf = [0u8; 64];
        // Left-pad the address to 32 bytes
        buf[12..32].copy_from_slice(key.as_ref());
        // Slot in big-endian
        buf[32..].copy_from_slice(&base_slot.to_be_bytes::<32>());

        let expected = U256::from_be_bytes(keccak256(buf).0);
        let computed = mapping_slot(key, base_slot);

        assert_eq!(computed, expected, "mapping_slot encoding mismatch");
    }

    #[test]
    fn test_double_mapping_account_role() {
        let account = address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        let role: B256 = U256::ONE.into();
        let base_slot = U256::ONE;

        let slot = double_mapping_slot(account, role, base_slot);

        // Verify deterministic
        let slot2 = double_mapping_slot(account, role, base_slot);
        assert_eq!(slot, slot2);

        // Verify different role yields different slot
        let different_role: B256 = U256::from(2).into();
        let different_slot = double_mapping_slot(account, different_role, base_slot);
        assert_ne!(slot, different_slot);
    }

    #[test]
    fn test_mapping_is_zero_sized() {
        assert_eq!(std::mem::size_of::<Mapping<Address, U256, TestSlot1>>(), 0);
        assert_eq!(std::mem::size_of::<Mapping<U256, Address, TestSlot2>>(), 0);
        // Nested mapping
        type NestedMapping = Mapping<Address, Mapping<Address, U256, DummySlot>, TestSlotMax>;
        assert_eq!(std::mem::size_of::<NestedMapping>(), 0);
    }

    #[test]
    fn test_mapping_creation() {
        let _simple: Mapping<Address, U256, TestSlot1> = Mapping::new();
        let _another: Mapping<U256, bool, TestSlot2> = Mapping::default();
    }

    #[test]
    fn test_mapping_slot_extraction() {
        assert_eq!(Mapping::<Address, U256, TestSlot1>::slot(), U256::ONE);
        assert_eq!(Mapping::<U256, Address, TestSlot2>::slot(), U256::from(2));

        // Test with larger slot number
        assert_eq!(Mapping::<Address, U256, TestSlotMax>::slot(), U256::MAX);
    }

    #[test]
    fn test_mapping_edge_case_zero() {
        // Explicit test for U256::ZERO base slot
        assert_eq!(Mapping::<Address, U256, TestSlot0>::slot(), U256::ZERO);

        let mut storage = HashMapStorageProvider::new(1);
        let mut contract = setup_test_contract(&mut storage);
        let user = Address::random();

        type ZeroMapping = Mapping<Address, U256, TestSlot0>;
        let value = U256::from(1000u64);

        _ = ZeroMapping::write(&mut contract, user, value);
        let loaded = ZeroMapping::read(&mut contract, user).unwrap();
        assert_eq!(loaded, value);
    }

    #[test]
    fn test_mapping_edge_case_max() {
        // Explicit test for U256::MAX base slot
        type MaxMapping = Mapping<Address, U256, TestSlotMax>;
        assert_eq!(MaxMapping::slot(), U256::MAX);

        let mut storage = HashMapStorageProvider::new(1);
        let mut contract = setup_test_contract(&mut storage);
        let user = Address::random();

        let value = U256::from(999u64);
        _ = MaxMapping::write(&mut contract, user, value);
        let loaded = MaxMapping::read(&mut contract, user).unwrap();
        assert_eq!(loaded, value);
    }

    #[test]
    fn test_mapping_read_write_balances() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut contract = setup_test_contract(&mut storage);
        let user1 = Address::random();
        let user2 = Address::random();

        type NamedMapping = Mapping<Address, U256, TestSlot1>;

        let balance1 = U256::from(1000u64);
        let balance2 = U256::from(2000u64);

        // Write balances
        _ = NamedMapping::write(&mut contract, user1, balance1);
        _ = NamedMapping::write(&mut contract, user2, balance2);

        // Read balances
        let loaded1 = NamedMapping::read(&mut contract, user1).unwrap();
        let loaded2 = NamedMapping::read(&mut contract, user2).unwrap();

        assert_eq!(loaded1, balance1);
        assert_eq!(loaded2, balance2);
    }

    #[test]
    fn test_mapping_read_default_is_zero() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut contract = setup_test_contract(&mut storage);
        let user = Address::random();

        type NamedMapping = Mapping<Address, U256, TestSlot1>;

        // Reading uninitialized mapping slot should return zero
        let balance = NamedMapping::read(&mut contract, user).unwrap();
        assert_eq!(balance, U256::ZERO);
    }

    #[test]
    fn test_mapping_overwrite() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut contract = setup_test_contract(&mut storage);
        let user = Address::random();

        type NamedMapping = Mapping<Address, U256, TestSlot1>;

        // Write initial balance
        _ = NamedMapping::write(&mut contract, user, U256::from(100));
        assert_eq!(NamedMapping::read(&mut contract, user), Ok(U256::from(100)));

        // Overwrite with new balance
        _ = NamedMapping::write(&mut contract, user, U256::from(200));
        assert_eq!(NamedMapping::read(&mut contract, user), Ok(U256::from(200)));
    }

    #[test]
    fn test_nested_mapping_read_write_allowances() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut contract = setup_test_contract(&mut storage);
        let owner = Address::random();
        let spender1 = Address::random();
        let spender2 = Address::random();

        // Nested mapping: outer slot is 11, inner slot is dummy (unused)
        type NestedMapping = Mapping<Address, Mapping<Address, U256, DummySlot>, TestSlot2>;

        let allowance1 = U256::from(500u64);
        let allowance2 = U256::from(1500u64);

        // Write allowances using nested API
        _ = NestedMapping::write_nested(&mut contract, owner, spender1, allowance1);
        _ = NestedMapping::write_nested(&mut contract, owner, spender2, allowance2);

        // Read allowances using nested API
        let loaded1 = NestedMapping::read_nested(&mut contract, owner, spender1).unwrap();
        let loaded2 = NestedMapping::read_nested(&mut contract, owner, spender2).unwrap();

        assert_eq!(loaded1, allowance1);
        assert_eq!(loaded2, allowance2);
    }

    #[test]
    fn test_nested_mapping_default_is_zero() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut contract = setup_test_contract(&mut storage);
        let owner = Address::random();
        let spender = Address::random();

        type NestedMapping = Mapping<Address, Mapping<Address, U256, DummySlot>, TestSlot1>;

        // Reading uninitialized nested mapping should return zero
        let allowance = NestedMapping::read_nested(&mut contract, owner, spender).unwrap();
        assert_eq!(allowance, U256::ZERO);
    }

    #[test]
    fn test_nested_mapping_independence() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut contract = setup_test_contract(&mut storage);
        let owner1 = Address::random();
        let owner2 = Address::random();
        let spender = Address::random();

        type NestedMapping = Mapping<Address, Mapping<Address, U256, DummySlot>, TestSlot2>;

        // Set allowance for owner1 -> spender
        _ = NestedMapping::write_nested(&mut contract, owner1, spender, U256::from(100));

        // Verify owner2 -> spender is still zero (independent slot)
        let allowance2 = NestedMapping::read_nested(&mut contract, owner2, spender).unwrap();
        assert_eq!(allowance2, U256::ZERO);

        // Verify owner1 -> spender is unchanged
        let allowance1 = NestedMapping::read_nested(&mut contract, owner1, spender).unwrap();
        assert_eq!(allowance1, U256::from(100));
    }

    #[test]
    fn test_mapping_with_different_key_types() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut contract = setup_test_contract(&mut storage);

        // Mapping with U256 key
        type NoncesMapping = Mapping<Address, U256, TestSlot2>;
        let user = Address::random();
        let nonce = U256::from(42);

        _ = NoncesMapping::write(&mut contract, user, nonce);
        let loaded_nonce = NoncesMapping::read(&mut contract, user).unwrap();
        assert_eq!(loaded_nonce, nonce);

        // Mapping with bool value
        type FlagsMapping = Mapping<Address, bool, TestSlotMax>;
        _ = FlagsMapping::write(&mut contract, user, true);
        let loaded_flag = FlagsMapping::read(&mut contract, user).unwrap();
        assert!(loaded_flag);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        #[test]
        fn proptest_mapping_read_write(
            key in arb_address(),
            value in arb_u256()
        ) {
            let mut storage = HashMapStorageProvider::new(1);
            let mut contract = setup_test_contract(&mut storage);

            // Test with TestSlot10
            type TestMapping = Mapping<Address, U256, TestSlot0>;

            // Write and read back
            TestMapping::write(&mut contract, key, value)?;
            let loaded = TestMapping::read(&mut contract, key)?;
            prop_assert_eq!(loaded, value, "roundtrip failed");

            // Delete and verify
            TestMapping::delete(&mut contract, key)?;
            let after_delete = TestMapping::read(&mut contract, key)?;
            prop_assert_eq!(after_delete, U256::ZERO, "not zero after delete");
        }

        #[test]
        fn proptest_mapping_key_isolation(
            key1 in arb_address(),
            key2 in arb_address(),
            value1 in arb_u256(),
            value2 in arb_u256()
        ) {
            // Skip if keys are the same
            prop_assume!(key1 != key2);

            let mut storage = HashMapStorageProvider::new(1);
            let mut contract = setup_test_contract(&mut storage);

            type TestMapping = Mapping<Address, U256, TestSlot0>;

            // Write different values to different keys
            TestMapping::write(&mut contract, key1, value1)?;
            TestMapping::write(&mut contract, key2, value2)?;

            // Verify both keys retain their independent values
            let loaded1 = TestMapping::read(&mut contract, key1)?;
            let loaded2 = TestMapping::read(&mut contract, key2)?;

            prop_assert_eq!(loaded1, value1, "key1 value changed");
            prop_assert_eq!(loaded2, value2, "key2 value changed");

            // Delete key1, verify key2 unaffected
            TestMapping::delete(&mut contract, key1)?;
            let after_delete1 = TestMapping::read(&mut contract, key1)?;
            let after_delete2 = TestMapping::read(&mut contract, key2)?;

            prop_assert_eq!(after_delete1, U256::ZERO, "key1 not deleted");
            prop_assert_eq!(after_delete2, value2, "key2 affected by key1 delete");
        }

        #[test]
        fn proptest_nested_mapping_isolation(
            owner1 in arb_address(),
            owner2 in arb_address(),
            spender in arb_address(),
            allowance1 in arb_u256(),
            allowance2 in arb_u256()
        ) {
            // Skip if owners are the same
            prop_assume!(owner1 != owner2);

            let mut storage = HashMapStorageProvider::new(1);
            let mut contract = setup_test_contract(&mut storage);

            type NestedMapping =
                Mapping<Address, Mapping<Address, U256, DummySlot>, TestSlot1>;

            // Write different allowances for different owners
            NestedMapping::write_nested(&mut contract, owner1, spender, allowance1)?;
            NestedMapping::write_nested(&mut contract, owner2, spender, allowance2)?;

            // Verify both owners' allowances are independent
            let loaded1 = NestedMapping::read_nested(&mut contract, owner1, spender)?;
            let loaded2 = NestedMapping::read_nested(&mut contract, owner2, spender)?;

            prop_assert_eq!(loaded1, allowance1, "owner1 allowance changed");
            prop_assert_eq!(loaded2, allowance2, "owner2 allowance changed");

            // Delete owner1's allowance, verify owner2 unaffected
            NestedMapping::delete_nested(&mut contract, owner1, spender)?;
            let after_delete1 = NestedMapping::read_nested(&mut contract, owner1, spender)?;
            let after_delete2 = NestedMapping::read_nested(&mut contract, owner2, spender)?;

            prop_assert_eq!(after_delete1, U256::ZERO, "owner1 allowance not deleted");
            prop_assert_eq!(after_delete2, allowance2, "owner2 allowance affected");
        }
    }

    // -- RUNTIME SLOT OFFSET TESTS --------------------------------------------

    #[test]
    fn test_mapping_at_offset() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut contract = setup_test_contract(&mut storage);

        // Simulate: mapping(bytes32 => Orderbook) books
        // where Orderbook has a mapping field `bids` at field offset 1
        let pair_key: B256 = U256::from(0x1234).into();
        let orderbook_base_slot = mapping_slot(pair_key, TestSlot1::SLOT);

        // Use Mapping::*_at_offset() to access the bids mapping within the Orderbook struct
        let tick: i16 = 100;
        let bid_value = U256::from(500);

        // Write to orderbook.bids[tick]
        Mapping::<i16, U256, DummySlot>::write_at_offset(
            &mut contract,
            orderbook_base_slot,
            1, // bids field is at offset 1 in Orderbook
            tick,
            bid_value,
        )?;

        // Read from orderbook.bids[tick]
        let read_value = Mapping::<i16, U256, DummySlot>::read_at_offset(
            &mut contract,
            orderbook_base_slot,
            1,
            tick,
        )?;

        assert_eq!(read_value, bid_value);

        // Delete orderbook.bids[tick]
        Mapping::<i16, U256, DummySlot>::delete_at_offset(
            &mut contract,
            orderbook_base_slot,
            1,
            tick,
        )?;

        let deleted_value = Mapping::<i16, U256, DummySlot>::read_at_offset(
            &mut contract,
            orderbook_base_slot,
            1,
            tick,
        )?;

        assert_eq!(deleted_value, U256::ZERO);

        Ok(())
    }

    #[test]
    fn test_nested_mapping_at_offset() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut contract = setup_test_contract(&mut storage);

        // Simulate a struct with nested mapping at field offset 3
        let struct_key: B256 = U256::from(0xabcd).into();
        let struct_base_slot = mapping_slot(struct_key, TestSlot2::SLOT);

        let owner = Address::random();
        let spender = Address::random();
        let allowance = U256::from(1000);

        // Write to nested_mapping[owner][spender]
        Mapping::<Address, Mapping<Address, U256, DummySlot>, DummySlot>::write_nested_at_offset(
            &mut contract,
            struct_base_slot,
            3, // nested mapping at field offset 3
            owner,
            spender,
            allowance,
        )?;

        // Read back
        let read_allowance =
            Mapping::<Address, Mapping<Address, U256, DummySlot>, DummySlot>::read_nested_at_offset(
                &mut contract,
                struct_base_slot,
                3,
                owner,
                spender,
            )?;

        assert_eq!(read_allowance, allowance);

        // Delete
        Mapping::<Address, Mapping<Address, U256, DummySlot>, DummySlot>::delete_nested_at_offset(
            &mut contract,
            struct_base_slot,
            3,
            owner,
            spender,
        )?;

        let deleted =
            Mapping::<Address, Mapping<Address, U256, DummySlot>, DummySlot>::read_nested_at_offset(
                &mut contract,
                struct_base_slot,
                3,
                owner,
                spender,
            )?;

        assert_eq!(deleted, U256::ZERO);

        Ok(())
    }

    #[test]
    fn test_write_nested_at_offset_packed() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut contract = setup_test_contract(&mut storage);

        let key1 = Address::random();
        let key2 = Address::random();
        let value = U256::from(0xabcd);

        // Write packed field in nested mapping value
        Mapping::<Address, Mapping<Address, U256, DummySlot>, TestSlot1>::write_nested_at_offset_packed(
            &mut contract,
            0, // value_field_offset_slots
            0, // value_field_offset_bytes
            2, // value_field_size_bytes (uint16)
            key1,
            key2,
            value,
        )?;

        // Read back using read_nested_at_offset_packed
        let read_value =
            Mapping::<Address, Mapping<Address, U256, DummySlot>, TestSlot1>::read_nested_at_offset_packed(
                &mut contract,
                0,
                0,
                2,
                key1,
                key2,
            )?;

        assert_eq!(read_value, value);
        Ok(())
    }

    #[test]
    fn test_delete_nested_at_offset_packed() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut contract = setup_test_contract(&mut storage);

        let key1 = Address::random();
        let key2 = Address::random();
        let value = U256::from(0x1234);

        // Write then delete packed field
        Mapping::<Address, Mapping<Address, U256, DummySlot>, TestSlot2>::write_nested_at_offset_packed(
            &mut contract,
            0,
            0,
            2,
            key1,
            key2,
            value,
        )?;

        Mapping::<Address, Mapping<Address, U256, DummySlot>, TestSlot2>::delete_nested_at_offset_packed(
            &mut contract,
            0,
            0,
            2,
            key1,
            key2,
        )?;

        let deleted =
            Mapping::<Address, Mapping<Address, U256, DummySlot>, TestSlot2>::read_nested_at_offset_packed(
                &mut contract,
                0,
                0,
                2,
                key1,
                key2,
            )?;

        assert_eq!(deleted, U256::ZERO);
        Ok(())
    }

    #[test]
    fn test_multiple_fields_at_different_offsets() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut contract = setup_test_contract(&mut storage);

        // Simulate Orderbook with multiple mapping fields
        let pair_key: B256 = U256::from(0x5678).into();
        let orderbook_base = mapping_slot(pair_key, TestSlot0::SLOT);

        // bids at offset 1
        let tick1: i16 = 50;
        let bid1 = U256::from(100);
        Mapping::<i16, U256, DummySlot>::write_at_offset(
            &mut contract,
            orderbook_base,
            1,
            tick1,
            bid1,
        )?;

        // asks at offset 2
        let tick2: i16 = -25;
        let ask1 = U256::from(200);
        Mapping::<i16, U256, DummySlot>::write_at_offset(
            &mut contract,
            orderbook_base,
            2,
            tick2,
            ask1,
        )?;

        // bidBitmap at offset 3
        let bitmap_key: i16 = 10;
        let bitmap_value = U256::from(0xff);
        Mapping::<i16, U256, DummySlot>::write_at_offset(
            &mut contract,
            orderbook_base,
            3,
            bitmap_key,
            bitmap_value,
        )?;

        // Verify all fields are independent
        let read_bid = Mapping::<i16, U256, DummySlot>::read_at_offset(
            &mut contract,
            orderbook_base,
            1,
            tick1,
        )?;
        let read_ask = Mapping::<i16, U256, DummySlot>::read_at_offset(
            &mut contract,
            orderbook_base,
            2,
            tick2,
        )?;
        let read_bitmap = Mapping::<i16, U256, DummySlot>::read_at_offset(
            &mut contract,
            orderbook_base,
            3,
            bitmap_key,
        )?;

        assert_eq!(read_bid, bid1);
        assert_eq!(read_ask, ask1);
        assert_eq!(read_bitmap, bitmap_value);

        Ok(())
    }
}
