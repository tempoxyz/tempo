//! Single-word primitives (up-to 32 bytes) implementation for the `Storable trait`.

use alloy::primitives::{Address, U256};
use revm::interpreter::instructions::utility::{IntoAddress, IntoU256};
use tempo_precompiles_macros;

use crate::{
    error::Result,
    storage::{StorageOps, types::*},
};

// rust integers: (u)int8, (u)int16, (u)int32, (u)int64, (u)int128
tempo_precompiles_macros::storable_rust_ints!();
// alloy integers: U8, I8, U16, I16, U32, I32, U64, I64, U128, I128, U256, I256
tempo_precompiles_macros::storable_alloy_ints!();
// alloy fixed bytes: FixedBytes<1>, FixedBytes<2>, ..., FixedBytes<32>
tempo_precompiles_macros::storable_alloy_bytes!();
// fixed-size arrays: [T; N] for primitive types T and sizes 1-32
tempo_precompiles_macros::storable_arrays!();
// nested arrays: [[T; M]; N] for small primitive types
tempo_precompiles_macros::storable_nested_arrays!();

// -- MANUAL STORAGE TRAIT IMPLEMENTATIONS -------------------------------------

impl StorableType for bool {
    const LAYOUT: Layout = Layout::Bytes(1);
}

impl Storable<1> for bool {
    #[inline]
    fn load<S: StorageOps>(storage: &mut S, base_slot: U256, ctx: LayoutCtx) -> Result<Self> {
        match ctx.packed_offset() {
            None => storage.sload(base_slot).map(|val| !val.is_zero()),
            Some(offset) => {
                let slot = storage.sload(base_slot)?;
                crate::storage::packing::extract_packed_value(slot, offset, 1)
            }
        }
    }

    #[inline]
    fn store<S: StorageOps>(&self, storage: &mut S, base_slot: U256, ctx: LayoutCtx) -> Result<()> {
        let value = if *self { U256::ONE } else { U256::ZERO };
        match ctx.packed_offset() {
            None => storage.sstore(base_slot, value),
            Some(offset) => {
                let current = storage.sload(base_slot)?;
                let updated =
                    crate::storage::packing::insert_packed_value(current, &value, offset, 1)?;
                storage.sstore(base_slot, updated)
            }
        }
    }

    #[inline]
    fn to_evm_words(&self) -> Result<[U256; 1]> {
        Ok([if *self { U256::ONE } else { U256::ZERO }])
    }

    #[inline]
    fn from_evm_words(words: [U256; 1]) -> Result<Self> {
        Ok(!words[0].is_zero())
    }
}

impl StorableType for Address {
    const LAYOUT: Layout = Layout::Bytes(20);
}

impl Storable<1> for Address {
    #[inline]
    fn load<S: StorageOps>(storage: &mut S, base_slot: U256, ctx: LayoutCtx) -> Result<Self> {
        match ctx.packed_offset() {
            None => storage.sload(base_slot).map(|val| val.into_address()),
            Some(offset) => {
                let slot = storage.sload(base_slot)?;
                crate::storage::packing::extract_packed_value(slot, offset, 20)
            }
        }
    }

    #[inline]
    fn store<S: StorageOps>(&self, storage: &mut S, base_slot: U256, ctx: LayoutCtx) -> Result<()> {
        match ctx.packed_offset() {
            None => storage.sstore(base_slot, self.into_u256()),
            Some(offset) => {
                let current = storage.sload(base_slot)?;
                let value = self.into_u256();
                let updated =
                    crate::storage::packing::insert_packed_value(current, &value, offset, 20)?;
                storage.sstore(base_slot, updated)
            }
        }
    }

    #[inline]
    fn to_evm_words(&self) -> Result<[U256; 1]> {
        Ok([self.into_u256()])
    }

    #[inline]
    fn from_evm_words(words: [U256; 1]) -> Result<Self> {
        Ok(words[0].into_address())
    }
}

impl StorageKey for Address {
    #[inline]
    fn as_storage_bytes(&self) -> impl AsRef<[u8]> {
        self.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{
        PrecompileStorageProvider, StorageOps,
        hashmap::HashMapStorageProvider,
        packing::{gen_slot_from, insert_packed_value},
    };
    use proptest::prelude::*;

    // -- TEST HELPERS -------------------------------------------------------------

    // Test helper that owns storage and implements StorageOps
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

    // Strategy for generating arbitrary addresses
    fn arb_address() -> impl Strategy<Value = Address> {
        any::<[u8; 20]>().prop_map(Address::from)
    }

    // -- STORAGE TESTS --------------------------------------------------------

    // Generate property tests for all storage types:
    // - rust integers: (u)int8, (u)int16, (u)int32, (u)int64, (u)int128
    // - alloy integers: U8, I8, U16, I16, U32, I32, U64, I64, U128, I128, U256, I256
    // - alloy fixed bytes: FixedBytes<1>, FixedBytes<2>, ..., FixedBytes<32>
    tempo_precompiles_macros::gen_storable_tests!();

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        #[test]
        fn test_address(addr in arb_address(), base_slot in arb_safe_slot()) {
            let mut contract = setup_test_contract();

            // Verify store → load roundtrip
            addr.store(&mut contract, base_slot, LayoutCtx::FULL)?;
            let loaded = Address::load(&mut contract, base_slot, LayoutCtx::FULL)?;
            assert_eq!(addr, loaded, "Address roundtrip failed");

            // Verify delete works
            Address::delete(&mut contract, base_slot, LayoutCtx::FULL)?;
            let after_delete = Address::load(&mut contract, base_slot, LayoutCtx::FULL)?;
            assert_eq!(after_delete, Address::ZERO, "Address not zero after delete");

            // EVM words roundtrip
            let words = addr.to_evm_words()?;
            let recovered = Address::from_evm_words(words)?;
            assert_eq!(addr, recovered, "Address EVM words roundtrip failed");
        }

        #[test]
        fn test_bool_values(b in any::<bool>(), base_slot in arb_safe_slot()) {
            let mut contract = setup_test_contract();

            // Verify store → load roundtrip
            b.store(&mut contract, base_slot, LayoutCtx::FULL)?;
            let loaded = bool::load(&mut contract, base_slot, LayoutCtx::FULL)?;
            assert_eq!(b, loaded, "Bool roundtrip failed for value: {b}");

            // Verify delete works
            bool::delete(&mut contract, base_slot, LayoutCtx::FULL)?;
            let after_delete = bool::load(&mut contract, base_slot, LayoutCtx::FULL)?;
            assert!(!after_delete, "Bool not false after delete");

            // EVM words roundtrip
            let words = b.to_evm_words()?;
            let recovered = bool::from_evm_words(words)?;
            assert_eq!(b, recovered, "Bool EVM words roundtrip failed");
        }
    }

    // -- PRIMITIVE SLOT CONTENT VALIDATION TESTS ----------------------------------

    #[test]
    fn test_u8_at_various_offsets() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(100);

        // Test u8 at offset 0
        let val0: u8 = 0x42;
        let mut slot = U256::ZERO;
        slot = insert_packed_value(slot, &val0, 0, 1).unwrap();
        contract.sstore(base_slot, slot).unwrap();

        let loaded_slot = contract.sload(base_slot).unwrap();
        let expected = gen_slot_from(&[
            "0x42", // offset 0 (1 byte)
        ]);
        assert_eq!(loaded_slot, expected);

        // Test u8 at offset 15 (middle)
        let val15: u8 = 0xAB;
        slot = U256::ZERO;
        slot = insert_packed_value(slot, &val15, 15, 1).unwrap();
        contract.sstore(base_slot + U256::ONE, slot).unwrap();

        let loaded_slot = contract.sload(base_slot + U256::ONE).unwrap();
        let expected = gen_slot_from(&[
            "0xAB",                             // offset 15 (1 byte)
            "0x000000000000000000000000000000", // padding (15 bytes)
        ]);
        assert_eq!(loaded_slot, expected);

        // Test u8 at offset 31 (last byte)
        let val31: u8 = 0xFF;
        slot = U256::ZERO;
        slot = insert_packed_value(slot, &val31, 31, 1).unwrap();
        contract.sstore(base_slot + U256::from(2), slot).unwrap();

        let loaded_slot = contract.sload(base_slot + U256::from(2)).unwrap();
        let expected = gen_slot_from(&[
            "0xFF",                                                             // offset 31 (1 byte)
            "0x00000000000000000000000000000000000000000000000000000000000000", // padding (31 bytes)
        ]);
        assert_eq!(loaded_slot, expected);
    }

    #[test]
    fn test_u16_at_various_offsets() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(200);

        // Test u16 at offset 0
        let val0: u16 = 0x1234;
        let mut slot = U256::ZERO;
        slot = insert_packed_value(slot, &val0, 0, 2).unwrap();
        contract.sstore(base_slot, slot).unwrap();

        let loaded_slot = contract.sload(base_slot).unwrap();
        let expected = gen_slot_from(&[
            "0x1234", // offset 0 (2 bytes)
        ]);
        assert_eq!(loaded_slot, expected);

        // Test u16 at offset 15 (middle)
        let val15: u16 = 0xABCD;
        slot = U256::ZERO;
        slot = insert_packed_value(slot, &val15, 15, 2).unwrap();
        contract.sstore(base_slot + U256::ONE, slot).unwrap();

        let loaded_slot = contract.sload(base_slot + U256::ONE).unwrap();
        let expected = gen_slot_from(&[
            "0xABCD",                           // offset 15 (2 bytes)
            "0x000000000000000000000000000000", // padding (15 bytes)
        ]);
        assert_eq!(loaded_slot, expected);

        // Test u16 at offset 30 (last 2 bytes)
        let val30: u16 = 0xFFEE;
        slot = U256::ZERO;
        slot = insert_packed_value(slot, &val30, 30, 2).unwrap();
        contract.sstore(base_slot + U256::from(2), slot).unwrap();

        let loaded_slot = contract.sload(base_slot + U256::from(2)).unwrap();
        let expected = gen_slot_from(&[
            "0xFFEE",                                                         // offset 30 (2 bytes)
            "0x000000000000000000000000000000000000000000000000000000000000", // padding (30 bytes)
        ]);
        assert_eq!(loaded_slot, expected);
    }

    #[test]
    fn test_u32_at_various_offsets() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(300);

        // Test u32 at offset 0
        let val0: u32 = 0x12345678;
        let mut slot = U256::ZERO;
        slot = insert_packed_value(slot, &val0, 0, 4).unwrap();
        contract.sstore(base_slot, slot).unwrap();

        let loaded_slot = contract.sload(base_slot).unwrap();
        let expected = gen_slot_from(&[
            "0x12345678", // offset 0 (4 bytes)
        ]);
        assert_eq!(loaded_slot, expected);

        // Test u32 at offset 14
        let val14: u32 = 0xABCDEF01;
        slot = U256::ZERO;
        slot = insert_packed_value(slot, &val14, 14, 4).unwrap();
        contract.sstore(base_slot + U256::ONE, slot).unwrap();

        let loaded_slot = contract.sload(base_slot + U256::ONE).unwrap();
        let expected = gen_slot_from(&[
            "0xABCDEF01",                     // offset 14 (4 bytes)
            "0x0000000000000000000000000000", // padding (14 bytes)
        ]);
        assert_eq!(loaded_slot, expected);

        // Test u32 at offset 28 (last 4 bytes)
        let val28: u32 = 0xFFEEDDCC;
        slot = U256::ZERO;
        slot = insert_packed_value(slot, &val28, 28, 4).unwrap();
        contract.sstore(base_slot + U256::from(2), slot).unwrap();

        let loaded_slot = contract.sload(base_slot + U256::from(2)).unwrap();
        let expected = gen_slot_from(&[
            "0xFFEEDDCC",                                                 // offset 28 (4 bytes)
            "0x00000000000000000000000000000000000000000000000000000000", // padding (28 bytes)
        ]);
        assert_eq!(loaded_slot, expected);
    }

    #[test]
    fn test_u64_at_various_offsets() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(400);

        // Test u64 at offset 0
        let val0: u64 = 0x123456789ABCDEF0;
        let mut slot = U256::ZERO;
        slot = insert_packed_value(slot, &val0, 0, 8).unwrap();
        contract.sstore(base_slot, slot).unwrap();

        let loaded_slot = contract.sload(base_slot).unwrap();
        let expected = gen_slot_from(&[
            "0x123456789ABCDEF0", // offset 0 (8 bytes)
        ]);
        assert_eq!(loaded_slot, expected);

        // Test u64 at offset 12 (middle)
        let val12: u64 = 0xFEDCBA9876543210;
        slot = U256::ZERO;
        slot = insert_packed_value(slot, &val12, 12, 8).unwrap();
        contract.sstore(base_slot + U256::ONE, slot).unwrap();

        let loaded_slot = contract.sload(base_slot + U256::ONE).unwrap();
        let expected = gen_slot_from(&[
            "0xFEDCBA9876543210",         // offset 12 (8 bytes)
            "0x000000000000000000000000", // padding (12 bytes)
        ]);
        assert_eq!(loaded_slot, expected);

        // Test u64 at offset 24 (last 8 bytes)
        let val24: u64 = 0xAAAABBBBCCCCDDDD;
        slot = U256::ZERO;
        slot = insert_packed_value(slot, &val24, 24, 8).unwrap();
        contract.sstore(base_slot + U256::from(2), slot).unwrap();

        let loaded_slot = contract.sload(base_slot + U256::from(2)).unwrap();
        let expected = gen_slot_from(&[
            "0xAAAABBBBCCCCDDDD",                                 // offset 24 (8 bytes)
            "0x000000000000000000000000000000000000000000000000", // padding (24 bytes)
        ]);
        assert_eq!(loaded_slot, expected);
    }

    #[test]
    fn test_u128_at_various_offsets() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(500);

        // Test u128 at offset 0
        let val0: u128 = 0x123456789ABCDEF0_FEDCBA9876543210;
        let mut slot = U256::ZERO;
        slot = insert_packed_value(slot, &val0, 0, 16).unwrap();
        contract.sstore(base_slot, slot).unwrap();

        let loaded_slot = contract.sload(base_slot).unwrap();
        let expected = gen_slot_from(&[
            "0x123456789ABCDEF0FEDCBA9876543210", // offset 0 (16 bytes)
        ]);
        assert_eq!(loaded_slot, expected);

        // Test u128 at offset 16 (second half of slot)
        let val16: u128 = 0xAAAABBBBCCCCDDDD_1111222233334444;
        slot = U256::ZERO;
        slot = insert_packed_value(slot, &val16, 16, 16).unwrap();
        contract.sstore(base_slot + U256::ONE, slot).unwrap();

        let loaded_slot = contract.sload(base_slot + U256::ONE).unwrap();
        let expected = gen_slot_from(&[
            "0xAAAABBBBCCCCDDDD1111222233334444", // offset 16 (16 bytes)
            "0x00000000000000000000000000000000", // padding (16 bytes)
        ]);
        assert_eq!(loaded_slot, expected);
    }

    #[test]
    fn test_address_at_various_offsets() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(600);

        // Test Address at offset 0
        let addr0 = Address::from([0x12; 20]);
        let mut slot = U256::ZERO;
        slot = insert_packed_value(slot, &addr0, 0, 20).unwrap();
        contract.sstore(base_slot, slot).unwrap();

        let loaded_slot = contract.sload(base_slot).unwrap();
        let expected = gen_slot_from(&[
            "0x1212121212121212121212121212121212121212", // offset 0 (20 bytes)
        ]);
        assert_eq!(loaded_slot, expected);

        // Test Address at offset 12 (fits in one slot: 12 + 20 = 32)
        let addr12 = Address::from([0xAB; 20]);
        slot = U256::ZERO;
        slot = insert_packed_value(slot, &addr12, 12, 20).unwrap();
        contract.sstore(base_slot + U256::ONE, slot).unwrap();

        let loaded_slot = contract.sload(base_slot + U256::ONE).unwrap();
        let expected = gen_slot_from(&[
            "0xABABABABABABABABABABABABABABABABABABABAB", // offset 12 (20 bytes)
            "0x000000000000000000000000",                 // padding (12 bytes)
        ]);
        assert_eq!(loaded_slot, expected);
    }

    #[test]
    fn test_bool_at_various_offsets() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(700);

        // Test bool at offset 0
        let val0 = true;
        let mut slot = U256::ZERO;
        slot = insert_packed_value(slot, &val0, 0, 1).unwrap();
        contract.sstore(base_slot, slot).unwrap();

        let loaded_slot = contract.sload(base_slot).unwrap();
        let expected = gen_slot_from(&[
            "0x01", // offset 0 (1 byte)
        ]);
        assert_eq!(loaded_slot, expected);

        // Test bool at offset 31
        let val31 = false;
        slot = U256::ZERO;
        slot = insert_packed_value(slot, &val31, 31, 1).unwrap();
        contract.sstore(base_slot + U256::ONE, slot).unwrap();

        let loaded_slot = contract.sload(base_slot + U256::ONE).unwrap();
        let expected = gen_slot_from(&[
            "0x00",                                                             // offset 31 (1 byte)
            "0x00000000000000000000000000000000000000000000000000000000000000", // padding (31 bytes)
        ]);
        assert_eq!(loaded_slot, expected);
    }

    #[test]
    fn test_u256_fills_entire_slot() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(800);

        // U256 should always fill entire slot (offset must be 0)
        let val = U256::from(0x123456789ABCDEFu64);
        val.store(&mut contract, base_slot, LayoutCtx::FULL)
            .unwrap();

        let loaded_slot = contract.sload(base_slot).unwrap();
        assert_eq!(loaded_slot, val, "U256 should match slot contents exactly");

        // Verify it's stored as-is (no packing)
        let recovered = U256::load(&mut contract, base_slot, LayoutCtx::FULL).unwrap();
        assert_eq!(recovered, val, "U256 load failed");
    }

    #[test]
    fn test_primitive_delete_clears_slot() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(900);

        // Store a u64 value
        let val: u64 = 0x123456789ABCDEF0;
        val.store(&mut contract, base_slot, LayoutCtx::FULL)
            .unwrap();

        // Verify slot is non-zero
        let slot_before = contract.sload(base_slot).unwrap();
        assert_ne!(
            slot_before,
            U256::ZERO,
            "Slot should be non-zero before delete"
        );

        // Delete the value
        u64::delete(&mut contract, base_slot, LayoutCtx::FULL).unwrap();

        // Verify slot is now zero
        let slot_after = contract.sload(base_slot).unwrap();
        assert_eq!(slot_after, U256::ZERO, "Slot should be zero after delete");

        // Verify loading returns zero
        let loaded = u64::load(&mut contract, base_slot, LayoutCtx::FULL).unwrap();
        assert_eq!(loaded, 0u64, "Loaded value should be 0 after delete");
    }

    // -- FIXED-SIZE ARRAY TESTS ------------------------------------------------

    #[test]
    fn test_array_u8_32_single_slot() {
        let mut contract = setup_test_contract();
        let base_slot = U256::ZERO;

        // [u8; 32] should pack into exactly 1 slot
        let data: [u8; 32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];

        // Verify LAYOUT
        <[u8; 32] as Storable<1>>::validate_layout();
        assert_eq!(<[u8; 32] as StorableType>::LAYOUT, Layout::Slots(1));

        // Store and load
        data.store(&mut contract, base_slot, LayoutCtx::FULL)
            .unwrap();
        let loaded: [u8; 32] = Storable::load(&mut contract, base_slot, LayoutCtx::FULL).unwrap();
        assert_eq!(loaded, data, "[u8; 32] roundtrip failed");

        // Verify to_evm_words / from_evm_words
        let words = data.to_evm_words().unwrap();
        assert_eq!(words.len(), 1, "[u8; 32] should produce 1 word");
        let recovered: [u8; 32] = Storable::from_evm_words(words).unwrap();
        assert_eq!(recovered, data, "[u8; 32] EVM words roundtrip failed");

        // Verify delete
        <[u8; 32]>::delete(&mut contract, base_slot, LayoutCtx::FULL).unwrap();
        let slot_value = contract.sload(base_slot).unwrap();
        assert_eq!(slot_value, U256::ZERO, "Slot not cleared after delete");
    }

    #[test]
    fn test_array_u64_5_multi_slot() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(100);

        // [u64; 5] should require 2 slots (5 * 8 = 40 bytes > 32)
        let data: [u64; 5] = [1, 2, 3, 4, 5];

        // Verify slot count
        <[u64; 5] as Storable<2>>::validate_layout();
        assert_eq!(<[u64; 5] as StorableType>::LAYOUT, Layout::Slots(2));

        // Store and load
        data.store(&mut contract, base_slot, LayoutCtx::FULL)
            .unwrap();
        let loaded: [u64; 5] = Storable::load(&mut contract, base_slot, LayoutCtx::FULL).unwrap();
        assert_eq!(loaded, data, "[u64; 5] roundtrip failed");

        // Verify both slots are used
        let slot0 = contract.sload(base_slot).unwrap();
        let slot1 = contract.sload(base_slot + U256::ONE).unwrap();
        assert_ne!(slot0, U256::ZERO, "Slot 0 should be non-zero");
        assert_ne!(slot1, U256::ZERO, "Slot 1 should be non-zero");

        // Verify delete clears both slots
        <[u64; 5]>::delete(&mut contract, base_slot, LayoutCtx::FULL).unwrap();
        let slot0_after = contract.sload(base_slot).unwrap();
        let slot1_after = contract.sload(base_slot + U256::ONE).unwrap();
        assert_eq!(slot0_after, U256::ZERO, "Slot 0 not cleared");
        assert_eq!(slot1_after, U256::ZERO, "Slot 1 not cleared");
    }

    #[test]
    fn test_array_u16_packing() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(200);

        // [u16; 16] should pack into exactly 1 slot (16 * 2 = 32 bytes)
        let data: [u16; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        // Verify slot count
        <[u16; 16] as Storable<1>>::validate_layout();
        assert_eq!(<[u16; 16] as StorableType>::LAYOUT, Layout::Slots(1));

        // Store and load
        data.store(&mut contract, base_slot, LayoutCtx::FULL)
            .unwrap();
        let loaded: [u16; 16] = Storable::load(&mut contract, base_slot, LayoutCtx::FULL).unwrap();
        assert_eq!(loaded, data, "[u16; 16] roundtrip failed");
    }

    #[test]
    fn test_array_u256_no_packing() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(300);

        // [U256; 3] should use 3 slots (no packing for 32-byte types)
        let data: [U256; 3] = [U256::from(12345), U256::from(67890), U256::from(111111)];

        // Verify slot count
        <[U256; 3] as Storable<3>>::validate_layout();
        assert_eq!(<[U256; 3] as StorableType>::LAYOUT, Layout::Slots(3));

        // Store and load
        data.store(&mut contract, base_slot, LayoutCtx::FULL)
            .unwrap();
        let loaded: [U256; 3] = Storable::load(&mut contract, base_slot, LayoutCtx::FULL).unwrap();
        assert_eq!(loaded, data, "[U256; 3] roundtrip failed");

        // Verify each element is in its own slot
        for (i, expected_value) in data.iter().enumerate() {
            let slot_value = contract.sload(base_slot + U256::from(i)).unwrap();
            assert_eq!(slot_value, *expected_value, "Slot {i} mismatch");
        }
    }

    #[test]
    fn test_array_address_no_packing() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(400);

        // [Address; 3] should use 3 slots (20 bytes doesn't divide 32 evenly)
        let data: [Address; 3] = [
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x22),
            Address::repeat_byte(0x33),
        ];

        // Verify slot count
        <[Address; 3] as Storable<3>>::validate_layout();
        assert_eq!(<[Address; 3] as StorableType>::LAYOUT, Layout::Slots(3));

        // Store and load
        data.store(&mut contract, base_slot, LayoutCtx::FULL)
            .unwrap();
        let loaded: [Address; 3] =
            Storable::load(&mut contract, base_slot, LayoutCtx::FULL).unwrap();
        assert_eq!(loaded, data, "[Address; 3] roundtrip failed");
    }

    #[test]
    fn test_array_empty_single_element() {
        let mut contract = setup_test_contract();
        let base_slot = U256::from(500);

        // [u8; 1] should use 1 slot
        let data: [u8; 1] = [42];

        // Verify slot count
        <[u8; 1] as Storable<1>>::validate_layout();
        assert_eq!(<[u8; 1] as StorableType>::LAYOUT, Layout::Slots(1));

        // Store and load
        data.store(&mut contract, base_slot, LayoutCtx::FULL)
            .unwrap();
        let loaded: [u8; 1] = Storable::load(&mut contract, base_slot, LayoutCtx::FULL).unwrap();
        assert_eq!(loaded, data, "[u8; 1] roundtrip failed");
    }

    #[test]
    fn test_nested_array_u8_4x8() {
        let mut contract = setup_test_contract();
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
        <[[u8; 4]; 8] as Storable<8>>::validate_layout();
        assert_eq!(<[[u8; 4]; 8] as StorableType>::LAYOUT, Layout::Slots(8));

        // Store and load
        data.store(&mut contract, base_slot, LayoutCtx::FULL)
            .unwrap();
        let loaded: [[u8; 4]; 8] =
            Storable::load(&mut contract, base_slot, LayoutCtx::FULL).unwrap();
        assert_eq!(loaded, data, "[[u8; 4]; 8] roundtrip failed");

        // Verify to_evm_words / from_evm_words
        let words = data.to_evm_words().unwrap();
        assert_eq!(words.len(), 8, "[[u8; 4]; 8] should produce 8 words");
        let recovered: [[u8; 4]; 8] = Storable::from_evm_words(words).unwrap();
        assert_eq!(recovered, data, "[[u8; 4]; 8] EVM words roundtrip failed");

        // Verify delete clears all 8 slots
        <[[u8; 4]; 8]>::delete(&mut contract, base_slot, LayoutCtx::FULL).unwrap();
        for i in 0..8 {
            let slot_value = contract.sload(base_slot + U256::from(i)).unwrap();
            assert_eq!(slot_value, U256::ZERO, "Slot {i} not cleared after delete");
        }
    }

    #[test]
    fn test_nested_array_u16_2x8() {
        let mut contract = setup_test_contract();
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
        <[[u16; 2]; 8] as Storable<8>>::validate_layout();
        assert_eq!(<[[u16; 2]; 8] as StorableType>::LAYOUT, Layout::Slots(8));

        // Store and load
        data.store(&mut contract, base_slot, LayoutCtx::FULL)
            .unwrap();
        let loaded: [[u16; 2]; 8] =
            Storable::load(&mut contract, base_slot, LayoutCtx::FULL).unwrap();
        assert_eq!(loaded, data, "[[u16; 2]; 8] roundtrip failed");

        // Verify to_evm_words / from_evm_words
        let words = data.to_evm_words().unwrap();
        assert_eq!(words.len(), 8, "[[u16; 2]; 8] should produce 8 words");
        let recovered: [[u16; 2]; 8] = Storable::from_evm_words(words).unwrap();
        assert_eq!(recovered, data, "[[u16; 2]; 8] EVM words roundtrip failed");

        // Verify delete clears all 8 slots
        <[[u16; 2]; 8]>::delete(&mut contract, base_slot, LayoutCtx::FULL).unwrap();
        for i in 0..8 {
            let slot_value = contract.sload(base_slot + U256::from(i)).unwrap();
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
            let mut contract = setup_test_contract();

            // Store and load
            data.store(&mut contract, base_slot, LayoutCtx::FULL)?;
            let loaded: [u8; 32] = Storable::load(&mut contract, base_slot, LayoutCtx::FULL)?;
            prop_assert_eq!(&loaded, &data, "[u8; 32] roundtrip failed");

            // EVM words roundtrip
            let words = data.to_evm_words()?;
            let recovered: [u8; 32] = Storable::from_evm_words(words)?;
            prop_assert_eq!(&recovered, &data, "[u8; 32] EVM words roundtrip failed");

            // Delete
            <[u8; 32]>::delete(&mut contract, base_slot, LayoutCtx::FULL)?;
            let slot_value = contract.sload(base_slot)?;
            prop_assert_eq!(slot_value, U256::ZERO, "Slot not cleared after delete");
        }

        #[test]
        fn test_array_u16_16(
            data in prop::array::uniform16(any::<u16>()),
            base_slot in arb_safe_slot()
        ) {
            let mut contract = setup_test_contract();

            // Store and load
            data.store(&mut contract, base_slot, LayoutCtx::FULL)?;
            let loaded: [u16; 16] = Storable::load(&mut contract, base_slot, LayoutCtx::FULL)?;
            prop_assert_eq!(&loaded, &data, "[u16; 16] roundtrip failed");

            // EVM words roundtrip
            let words = data.to_evm_words()?;
            let recovered: [u16; 16] = Storable::from_evm_words(words)?;
            prop_assert_eq!(&recovered, &data, "[u16; 16] EVM words roundtrip failed");
        }

        #[test]
        fn test_array_u256_5(
            data in prop::array::uniform5(any::<u64>()).prop_map(|arr| arr.map(U256::from)),
            base_slot in arb_safe_slot()
        ) {
            let mut contract = setup_test_contract();

            // Store and load
            data.store(&mut contract, base_slot, LayoutCtx::FULL)?;
            let loaded: [U256; 5] = Storable::load(&mut contract, base_slot, LayoutCtx::FULL)?;
            prop_assert_eq!(&loaded, &data, "[U256; 5] roundtrip failed");

            // Verify each element is in its own slot
            for (i, expected_value) in data.iter().enumerate() {
                let slot_value = contract.sload(base_slot + U256::from(i))?;
                prop_assert_eq!(slot_value, *expected_value, "Slot {} mismatch", i);
            }

            // EVM words roundtrip
            let words = data.to_evm_words()?;
            let recovered: [U256; 5] = Storable::from_evm_words(words)?;
            prop_assert_eq!(&recovered, &data, "[U256; 5] EVM words roundtrip failed");

            // Delete
            <[U256; 5]>::delete(&mut contract, base_slot, LayoutCtx::FULL)?;
            for i in 0..5 {
                let slot_value = contract.sload(base_slot + U256::from(i))?;
                prop_assert_eq!(slot_value, U256::ZERO, "Slot {} not cleared", i);
            }
        }
    }
}
