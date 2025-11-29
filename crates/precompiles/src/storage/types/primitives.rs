//! Single-word primitives (up-to 32 bytes) implementation for the storage traits.

use alloy::primitives::{Address, U256};
use revm::interpreter::instructions::utility::{IntoAddress, IntoU256};
use std::rc::Rc;
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

// -- MANUAL STORAGE TRAIT IMPLEMENTATIONS -------------------------------------

impl StorableType for bool {
    const LAYOUT: Layout = Layout::Bytes(1);

    type Handler = Slot<Self>;

    fn handle(slot: U256, ctx: LayoutCtx, address: Rc<Address>) -> Self::Handler {
        Slot::new_with_ctx(slot, ctx, address)
    }
}

impl Packable for bool {
    #[inline]
    fn to_word(&self) -> U256 {
        if *self { U256::ONE } else { U256::ZERO }
    }

    #[inline]
    fn from_word(word: U256) -> Self {
        !word.is_zero()
    }
}

impl StorageKey for bool {
    #[inline]
    fn as_storage_bytes(&self) -> impl AsRef<[u8]> {
        if *self { [1u8] } else { [0u8] }
    }
}

impl StorableType for Address {
    const LAYOUT: Layout = Layout::Bytes(20);
    type Handler = Slot<Self>;

    fn handle(slot: U256, ctx: LayoutCtx, address: Rc<Address>) -> Self::Handler {
        Slot::new_with_ctx(slot, ctx, address)
    }
}

impl Packable for Address {
    #[inline]
    fn to_word(&self) -> U256 {
        self.into_u256()
    }

    #[inline]
    fn from_word(word: U256) -> Self {
        word.into_address()
    }
}

impl StorageKey for Address {
    #[inline]
    fn as_storage_bytes(&self) -> impl AsRef<[u8]> {
        self.as_slice()
    }
}

// -- STORABLE OPS IMPLEMENTATIONS FOR PRIMITIVES --------------------------------

impl Storable for bool {
    #[inline]
    fn load<S: StorageOps>(storage: &S, base_slot: U256, ctx: LayoutCtx) -> Result<Self> {
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

    // delete uses default implementation from trait
}

impl Storable for Address {
    #[inline]
    fn load<S: StorageOps>(storage: &S, base_slot: U256, ctx: LayoutCtx) -> Result<Self> {
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

    // delete uses default implementation from trait
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{
        Handler, PrecompileStorageContext, PrecompileStorageProvider,
        hashmap::HashMapStorageProvider, packing::gen_word_from,
    };
    use proptest::prelude::*;

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

    fn setup_storage() -> (HashMapStorageProvider, Rc<Address>) {
        (HashMapStorageProvider::new(1), Rc::new(Address::random()))
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
            let (mut storage, address) = setup_storage();
            let _guard = storage.enter().unwrap();
            let mut slot = Address::handle(base_slot, LayoutCtx::FULL, Rc::clone(&address));

            // Verify store → load roundtrip
            slot.write(addr).unwrap();
            let loaded = slot.read().unwrap();
            assert_eq!(addr, loaded, "Address roundtrip failed");

            // Verify delete works
            slot.delete().unwrap();
            let after_delete = slot.read().unwrap();
            assert_eq!(after_delete, Address::ZERO, "Address not zero after delete");

            // EVM word roundtrip
            let word = addr.to_word();
            let recovered = Address::from_word(word.into());
            assert_eq!(addr, recovered, "Address EVM word roundtrip failed");
        }

        #[test]
        fn test_bool_values(b in any::<bool>(), base_slot in arb_safe_slot()) {
            let (mut storage, address) = setup_storage();
            let _guard = storage.enter().unwrap();
            let mut slot = bool::handle(base_slot, LayoutCtx::FULL, Rc::clone(&address));

            // Verify store → load roundtrip
            slot.write(b).unwrap();
            let loaded = slot.read().unwrap();
            assert_eq!(b, loaded, "Bool roundtrip failed for value: {b}");

            // Verify delete works
            slot.delete().unwrap();
            let after_delete = slot.read().unwrap();
            assert!(!after_delete, "Bool not false after delete");

            // EVM word roundtrip
            let word = b.to_word();
            let recovered = bool::from_word(word);
            assert_eq!(b, recovered, "Bool EVM word roundtrip failed");
        }
    }

    // -- PRIMITIVE SLOT CONTENT VALIDATION TESTS ----------------------------------

    #[test]
    fn test_u8_at_various_offsets() {
        let (mut storage, address) = setup_storage();
        let base_slot = U256::from(100);

        // Test u8 at offset 0
        let val0: u8 = 0x42;
        let guard = storage.enter().unwrap();
        let mut slot0 = u8::handle(base_slot, LayoutCtx::packed(0), Rc::clone(&address));
        slot0.write(val0).unwrap();

        // Verify with Slot read
        let read_val = slot0.read().unwrap();
        assert_eq!(read_val, val0);

        // Verify with low-level read
        std::mem::drop(guard);
        let loaded_slot = storage.sload(*address, base_slot).unwrap();
        let expected = gen_word_from(&["0x42"]);
        assert_eq!(loaded_slot, expected);

        // Clear with low-level write
        storage.sstore(*address, base_slot, U256::ZERO).unwrap();

        // Verify with Slot read
        let guard = storage.enter().unwrap();
        let cleared_val = slot0.read().unwrap();
        assert_eq!(cleared_val, 0u8);
        std::mem::drop(guard);

        // Test u8 at offset 15 (middle)
        let val15: u8 = 0xAB;
        let guard = storage.enter().unwrap();
        let mut slot15 = u8::handle(
            base_slot + U256::ONE,
            LayoutCtx::packed(15),
            Rc::clone(&address),
        );
        slot15.write(val15).unwrap();

        // Verify with Slot read
        let read_val = slot15.read().unwrap();
        assert_eq!(read_val, val15);

        // Verify with low-level read
        std::mem::drop(guard);
        let loaded_slot = storage.sload(*address, base_slot + U256::ONE).unwrap();
        let expected = gen_word_from(&[
            "0xAB",                             // offset 15 (1 byte)
            "0x000000000000000000000000000000", // padding (15 bytes)
        ]);
        assert_eq!(loaded_slot, expected);

        // Clear with low-level write
        storage
            .sstore(*address, base_slot + U256::ONE, U256::ZERO)
            .unwrap();

        // Verify with Slot read
        let guard = storage.enter().unwrap();
        let cleared_val = slot15.read().unwrap();
        assert_eq!(cleared_val, 0u8);
        std::mem::drop(guard);

        // Test u8 at offset 31 (last byte)
        let val31: u8 = 0xFF;
        let guard = storage.enter().unwrap();
        let mut slot31 = u8::handle(
            base_slot + U256::from(2),
            LayoutCtx::packed(31),
            Rc::clone(&address),
        );
        slot31.write(val31).unwrap();

        // Verify with Slot read
        let read_val = slot31.read().unwrap();
        assert_eq!(read_val, val31);

        // Verify with low-level read
        std::mem::drop(guard);
        let loaded_slot = storage.sload(*address, base_slot + U256::from(2)).unwrap();
        let expected = gen_word_from(&[
            "0xFF",                                                             // offset 31 (1 byte)
            "0x00000000000000000000000000000000000000000000000000000000000000", // padding (31 bytes)
        ]);
        assert_eq!(loaded_slot, expected);

        // Clear with low-level write
        storage
            .sstore(*address, base_slot + U256::from(2), U256::ZERO)
            .unwrap();

        // Verify with Slot read
        let _guard = storage.enter().unwrap();
        let cleared_val = slot31.read().unwrap();
        assert_eq!(cleared_val, 0u8);
    }

    #[test]
    fn test_u16_at_various_offsets() {
        let (mut storage, address) = setup_storage();
        let base_slot = U256::from(200);

        // Test u16 at offset 0
        let val0: u16 = 0x1234;
        let guard = storage.enter().unwrap();
        let mut slot0 = u16::handle(base_slot, LayoutCtx::packed(0), Rc::clone(&address));
        slot0.write(val0).unwrap();

        // Verify with Slot read
        let read_val = slot0.read().unwrap();
        assert_eq!(read_val, val0);

        // Verify with low-level read
        std::mem::drop(guard);
        let loaded_slot = storage.sload(*address, base_slot).unwrap();
        let expected = gen_word_from(&["0x1234"]);
        assert_eq!(loaded_slot, expected);

        // Clear with low-level write
        storage.sstore(*address, base_slot, U256::ZERO).unwrap();

        // Verify with Slot read
        let guard = storage.enter().unwrap();
        let cleared_val = slot0.read().unwrap();
        assert_eq!(cleared_val, 0u16);
        std::mem::drop(guard);

        // Test u16 at offset 15 (middle)
        let val15: u16 = 0xABCD;
        let guard = storage.enter().unwrap();
        let mut slot15 = u16::handle(
            base_slot + U256::ONE,
            LayoutCtx::packed(15),
            Rc::clone(&address),
        );
        slot15.write(val15).unwrap();

        // Verify with Slot read
        let read_val = slot15.read().unwrap();
        assert_eq!(read_val, val15);

        // Verify with low-level read
        std::mem::drop(guard);
        let loaded_slot = storage.sload(*address, base_slot + U256::ONE).unwrap();
        let expected = gen_word_from(&[
            "0xABCD",                           // offset 15 (2 bytes)
            "0x000000000000000000000000000000", // padding (15 bytes)
        ]);
        assert_eq!(loaded_slot, expected);

        // Clear with low-level write
        storage
            .sstore(*address, base_slot + U256::ONE, U256::ZERO)
            .unwrap();

        // Verify with Slot read
        let guard = storage.enter().unwrap();
        let cleared_val = slot15.read().unwrap();
        assert_eq!(cleared_val, 0u16);
        std::mem::drop(guard);

        // Test u16 at offset 30 (last 2 bytes)
        let val30: u16 = 0xFFEE;
        let guard = storage.enter().unwrap();
        let mut slot30 = u16::handle(
            base_slot + U256::from(2),
            LayoutCtx::packed(30),
            Rc::clone(&address),
        );
        slot30.write(val30).unwrap();

        // Verify with Slot read
        let read_val = slot30.read().unwrap();
        assert_eq!(read_val, val30);

        // Verify with low-level read
        std::mem::drop(guard);
        let loaded_slot = storage.sload(*address, base_slot + U256::from(2)).unwrap();
        let expected = gen_word_from(&[
            "0xFFEE",                                                         // offset 30 (2 bytes)
            "0x000000000000000000000000000000000000000000000000000000000000", // padding (30 bytes)
        ]);
        assert_eq!(loaded_slot, expected);

        // Clear with low-level write
        storage
            .sstore(*address, base_slot + U256::from(2), U256::ZERO)
            .unwrap();

        // Verify with Slot read
        let _guard = storage.enter().unwrap();
        let cleared_val = slot30.read().unwrap();
        assert_eq!(cleared_val, 0u16);
    }

    #[test]
    fn test_u32_at_various_offsets() {
        let (mut storage, address) = setup_storage();
        let base_slot = U256::from(300);

        // Test u32 at offset 0
        let val0: u32 = 0x12345678;
        let guard = storage.enter().unwrap();
        let mut slot0 = u32::handle(base_slot, LayoutCtx::packed(0), Rc::clone(&address));
        slot0.write(val0).unwrap();

        // Verify with Slot read
        let read_val = slot0.read().unwrap();
        assert_eq!(read_val, val0);

        // Verify with low-level read
        std::mem::drop(guard);
        let loaded_slot = storage.sload(*address, base_slot).unwrap();
        let expected = gen_word_from(&["0x12345678"]);
        assert_eq!(loaded_slot, expected);

        // Clear with low-level write
        storage.sstore(*address, base_slot, U256::ZERO).unwrap();

        // Verify with Slot read
        let guard = storage.enter().unwrap();
        let cleared_val = slot0.read().unwrap();
        assert_eq!(cleared_val, 0u32);
        std::mem::drop(guard);

        // Test u32 at offset 14
        let val14: u32 = 0xABCDEF01;
        let guard = storage.enter().unwrap();
        let mut slot14 = u32::handle(
            base_slot + U256::ONE,
            LayoutCtx::packed(14),
            Rc::clone(&address),
        );
        slot14.write(val14).unwrap();

        // Verify with Slot read
        let read_val = slot14.read().unwrap();
        assert_eq!(read_val, val14);

        // Verify with low-level read
        std::mem::drop(guard);
        let loaded_slot = storage.sload(*address, base_slot + U256::ONE).unwrap();
        let expected = gen_word_from(&[
            "0xABCDEF01",                     // offset 14 (4 bytes)
            "0x0000000000000000000000000000", // padding (14 bytes)
        ]);
        assert_eq!(loaded_slot, expected);

        // Clear with low-level write
        storage
            .sstore(*address, base_slot + U256::ONE, U256::ZERO)
            .unwrap();

        // Verify with Slot read
        let guard = storage.enter().unwrap();
        let cleared_val = slot14.read().unwrap();
        assert_eq!(cleared_val, 0u32);
        std::mem::drop(guard);

        // Test u32 at offset 28 (last 4 bytes)
        let val28: u32 = 0xFFEEDDCC;
        let guard = storage.enter().unwrap();
        let mut slot28 = u32::handle(
            base_slot + U256::from(2),
            LayoutCtx::packed(28),
            Rc::clone(&address),
        );
        slot28.write(val28).unwrap();

        // Verify with Slot read
        let read_val = slot28.read().unwrap();
        assert_eq!(read_val, val28);

        // Verify with low-level read
        std::mem::drop(guard);
        let loaded_slot = storage.sload(*address, base_slot + U256::from(2)).unwrap();
        let expected = gen_word_from(&[
            "0xFFEEDDCC",                                                 // offset 28 (4 bytes)
            "0x00000000000000000000000000000000000000000000000000000000", // padding (28 bytes)
        ]);
        assert_eq!(loaded_slot, expected);

        // Clear with low-level write
        storage
            .sstore(*address, base_slot + U256::from(2), U256::ZERO)
            .unwrap();

        // Verify with Slot read
        let _guard = storage.enter().unwrap();
        let cleared_val = slot28.read().unwrap();
        assert_eq!(cleared_val, 0u32);
    }

    #[test]
    fn test_u64_at_various_offsets() {
        let (mut storage, address) = setup_storage();
        let base_slot = U256::from(400);

        // Test u64 at offset 0
        let val0: u64 = 0x123456789ABCDEF0;
        let guard = storage.enter().unwrap();
        let mut slot0 = u64::handle(base_slot, LayoutCtx::packed(0), Rc::clone(&address));
        slot0.write(val0).unwrap();

        // Verify with Slot read
        let read_val = slot0.read().unwrap();
        assert_eq!(read_val, val0);

        // Verify with low-level read
        std::mem::drop(guard);
        let loaded_slot = storage.sload(*address, base_slot).unwrap();
        let expected = gen_word_from(&["0x123456789ABCDEF0"]);
        assert_eq!(loaded_slot, expected);

        // Clear with low-level write
        storage.sstore(*address, base_slot, U256::ZERO).unwrap();

        // Verify with Slot read
        let guard = storage.enter().unwrap();
        let cleared_val = slot0.read().unwrap();
        assert_eq!(cleared_val, 0u64);
        std::mem::drop(guard);

        // Test u64 at offset 12 (middle)
        let val12: u64 = 0xFEDCBA9876543210;
        let guard = storage.enter().unwrap();
        let mut slot12 = u64::handle(
            base_slot + U256::ONE,
            LayoutCtx::packed(12),
            Rc::clone(&address),
        );
        slot12.write(val12).unwrap();

        // Verify with Slot read
        let read_val = slot12.read().unwrap();
        assert_eq!(read_val, val12);

        // Verify with low-level read
        std::mem::drop(guard);
        let loaded_slot = storage.sload(*address, base_slot + U256::ONE).unwrap();
        let expected = gen_word_from(&[
            "0xFEDCBA9876543210",         // offset 12 (8 bytes)
            "0x000000000000000000000000", // padding (12 bytes)
        ]);
        assert_eq!(loaded_slot, expected);

        // Clear with low-level write
        storage
            .sstore(*address, base_slot + U256::ONE, U256::ZERO)
            .unwrap();

        // Verify with Slot read
        let guard = storage.enter().unwrap();
        let cleared_val = slot12.read().unwrap();
        assert_eq!(cleared_val, 0u64);
        std::mem::drop(guard);

        // Test u64 at offset 24 (last 8 bytes)
        let val24: u64 = 0xAAAABBBBCCCCDDDD;
        let guard = storage.enter().unwrap();
        let mut slot24 = u64::handle(
            base_slot + U256::from(2),
            LayoutCtx::packed(24),
            Rc::clone(&address),
        );
        slot24.write(val24).unwrap();

        // Verify with Slot read
        let read_val = slot24.read().unwrap();
        assert_eq!(read_val, val24);

        // Verify with low-level read
        std::mem::drop(guard);
        let loaded_slot = storage.sload(*address, base_slot + U256::from(2)).unwrap();
        let expected = gen_word_from(&[
            "0xAAAABBBBCCCCDDDD",                                 // offset 24 (8 bytes)
            "0x000000000000000000000000000000000000000000000000", // padding (24 bytes)
        ]);
        assert_eq!(loaded_slot, expected);

        // Clear with low-level write
        storage
            .sstore(*address, base_slot + U256::from(2), U256::ZERO)
            .unwrap();

        // Verify with Slot read
        let _guard = storage.enter().unwrap();
        let cleared_val = slot24.read().unwrap();
        assert_eq!(cleared_val, 0u64);
    }

    #[test]
    fn test_u128_at_various_offsets() {
        let (mut storage, address) = setup_storage();
        let base_slot = U256::from(500);

        // Test u128 at offset 0
        let val0: u128 = 0x123456789ABCDEF0_FEDCBA9876543210;
        let guard = storage.enter().unwrap();
        let mut slot0 = u128::handle(base_slot, LayoutCtx::packed(0), Rc::clone(&address));
        slot0.write(val0).unwrap();

        // Verify with Slot read
        let read_val = slot0.read().unwrap();
        assert_eq!(read_val, val0);

        // Verify with low-level read
        std::mem::drop(guard);
        let loaded_slot = storage.sload(*address, base_slot).unwrap();
        let expected = gen_word_from(&["0x123456789ABCDEF0FEDCBA9876543210"]);
        assert_eq!(loaded_slot, expected);

        // Clear with low-level write
        storage.sstore(*address, base_slot, U256::ZERO).unwrap();

        // Verify with Slot read
        let guard = storage.enter().unwrap();
        let cleared_val = slot0.read().unwrap();
        assert_eq!(cleared_val, 0u128);
        std::mem::drop(guard);

        // Test u128 at offset 16 (second half of slot)
        let val16: u128 = 0xAAAABBBBCCCCDDDD_1111222233334444;
        let guard = storage.enter().unwrap();
        let mut slot16 = u128::handle(
            base_slot + U256::ONE,
            LayoutCtx::packed(16),
            Rc::clone(&address),
        );
        slot16.write(val16).unwrap();

        // Verify with Slot read
        let read_val = slot16.read().unwrap();
        assert_eq!(read_val, val16);

        // Verify with low-level read
        std::mem::drop(guard);
        let loaded_slot = storage.sload(*address, base_slot + U256::ONE).unwrap();
        let expected = gen_word_from(&[
            "0xAAAABBBBCCCCDDDD1111222233334444", // offset 16 (16 bytes)
            "0x00000000000000000000000000000000", // padding (16 bytes)
        ]);
        assert_eq!(loaded_slot, expected);

        // Clear with low-level write
        storage
            .sstore(*address, base_slot + U256::ONE, U256::ZERO)
            .unwrap();

        // Verify with Slot read
        let _guard = storage.enter().unwrap();
        let cleared_val = slot16.read().unwrap();
        assert_eq!(cleared_val, 0u128);
    }

    #[test]
    fn test_address_at_various_offsets() {
        let (mut storage, address) = setup_storage();
        let base_slot = U256::from(600);

        // Test Address at offset 0
        let addr0 = Address::from([0x12; 20]);
        let guard = storage.enter().unwrap();
        let mut slot0 = Address::handle(base_slot, LayoutCtx::packed(0), Rc::clone(&address));
        slot0.write(addr0).unwrap();

        // Verify with Slot read
        let read_val = slot0.read().unwrap();
        assert_eq!(read_val, addr0);

        // Verify with low-level read
        std::mem::drop(guard);
        let loaded_slot = storage.sload(*address, base_slot).unwrap();
        let expected = gen_word_from(&["0x1212121212121212121212121212121212121212"]);
        assert_eq!(loaded_slot, expected);

        // Clear with low-level write
        storage.sstore(*address, base_slot, U256::ZERO).unwrap();

        // Verify with Slot read
        let guard = storage.enter().unwrap();
        let cleared_val = slot0.read().unwrap();
        assert_eq!(cleared_val, Address::ZERO);
        std::mem::drop(guard);

        // Test Address at offset 12 (fits in one slot: 12 + 20 = 32)
        let addr12 = Address::from([0xAB; 20]);
        let guard = storage.enter().unwrap();
        let mut slot12 = Address::handle(
            base_slot + U256::ONE,
            LayoutCtx::packed(12),
            Rc::clone(&address),
        );
        slot12.write(addr12).unwrap();

        // Verify with Slot read
        let read_val = slot12.read().unwrap();
        assert_eq!(read_val, addr12);

        // Verify with low-level read
        std::mem::drop(guard);
        let loaded_slot = storage.sload(*address, base_slot + U256::ONE).unwrap();
        let expected = gen_word_from(&[
            "0xABABABABABABABABABABABABABABABABABABABAB", // offset 12 (20 bytes)
            "0x000000000000000000000000",                 // padding (12 bytes)
        ]);
        assert_eq!(loaded_slot, expected);

        // Clear with low-level write
        storage
            .sstore(*address, base_slot + U256::ONE, U256::ZERO)
            .unwrap();

        // Verify with Slot read
        let _guard = storage.enter().unwrap();
        let cleared_val = slot12.read().unwrap();
        assert_eq!(cleared_val, Address::ZERO);
    }

    #[test]
    fn test_bool_at_various_offsets() {
        let (mut storage, address) = setup_storage();
        let base_slot = U256::from(700);

        // Test bool at offset 0
        let val0 = true;
        let guard = storage.enter().unwrap();
        let mut slot0 = bool::handle(base_slot, LayoutCtx::packed(0), Rc::clone(&address));
        slot0.write(val0).unwrap();

        // Verify with Slot read
        let read_val = slot0.read().unwrap();
        assert_eq!(read_val, val0);

        // Verify with low-level read
        std::mem::drop(guard);
        let loaded_slot = storage.sload(*address, base_slot).unwrap();
        let expected = gen_word_from(&["0x01"]);
        assert_eq!(loaded_slot, expected);

        // Clear with low-level write
        storage.sstore(*address, base_slot, U256::ZERO).unwrap();

        // Verify with Slot read
        let guard = storage.enter().unwrap();
        let cleared_val = slot0.read().unwrap();
        assert!(!cleared_val);
        std::mem::drop(guard);

        // Test bool at offset 31
        let val31 = false;
        let guard = storage.enter().unwrap();
        let mut slot31 = bool::handle(
            base_slot + U256::ONE,
            LayoutCtx::packed(31),
            Rc::clone(&address),
        );
        slot31.write(val31).unwrap();

        // Verify with Slot read
        let read_val = slot31.read().unwrap();
        assert_eq!(read_val, val31);

        // Verify with low-level read
        std::mem::drop(guard);
        let loaded_slot = storage.sload(*address, base_slot + U256::ONE).unwrap();
        let expected = gen_word_from(&[
            "0x00",                                                             // offset 31 (1 byte)
            "0x00000000000000000000000000000000000000000000000000000000000000", // padding (31 bytes)
        ]);
        assert_eq!(loaded_slot, expected);

        // Clear with low-level write
        storage
            .sstore(*address, base_slot + U256::ONE, U256::ZERO)
            .unwrap();

        // Verify with Slot read
        let _guard = storage.enter().unwrap();
        let cleared_val = slot31.read().unwrap();
        assert!(!cleared_val);
    }

    #[test]
    fn test_u256_fills_entire_slot() {
        let (mut storage, address) = setup_storage();
        let guard = storage.enter().unwrap();
        let base_slot = U256::from(800);

        // U256 should always fill entire slot (offset must be 0)
        let val = U256::from(0x123456789ABCDEFu64);
        let mut slot = Slot::<U256>::new(base_slot, Rc::clone(&address));
        slot.write(val).unwrap();

        std::mem::drop(guard);
        let loaded_slot = storage.sload(*address, base_slot).unwrap();
        assert_eq!(loaded_slot, val, "U256 should match slot contents exactly");

        // Verify it's stored as-is (no packing)
        let _guard = storage.enter().unwrap();
        let recovered = slot.read().unwrap();
        assert_eq!(recovered, val, "U256 load failed");
    }

    #[test]
    fn test_primitive_delete_clears_slot() {
        let (mut storage, address) = setup_storage();
        let guard = storage.enter().unwrap();
        let base_slot = U256::from(900);

        // Store a u64 value
        let val: u64 = 0x123456789ABCDEF0;
        let mut slot = Slot::<u64>::new(base_slot, Rc::clone(&address));
        slot.write(val).unwrap();

        // Verify slot is non-zero
        std::mem::drop(guard);
        let slot_before = storage.sload(*address, base_slot).unwrap();
        assert_ne!(
            slot_before,
            U256::ZERO,
            "Slot should be non-zero before delete"
        );

        // Delete the value
        let guard = storage.enter().unwrap();
        slot.delete().unwrap();

        // Verify slot is now zero
        std::mem::drop(guard);
        let slot_after = storage.sload(*address, base_slot).unwrap();
        assert_eq!(slot_after, U256::ZERO, "Slot should be zero after delete");

        // Verify loading returns zero
        let _guard = storage.enter().unwrap();
        let loaded = slot.read().unwrap();
        assert_eq!(loaded, 0u64, "Loaded value should be 0 after delete");
    }
}
