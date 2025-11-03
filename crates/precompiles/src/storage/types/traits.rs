use alloy::primitives::{Address, U256, keccak256};
use revm::interpreter::instructions::utility::{IntoAddress, IntoU256};
use tempo_precompiles_macros::{storable_alloy_bytes, storable_alloy_ints, storable_rust_ints};

use crate::{
    error::{Result, TempoPrecompileError},
    storage::StorageOps,
};

/// Helper trait to access byte count without requiring const generic parameter.
///
/// This trait exists to allow the derive macro to query the byte size of field types
/// during layout computation, before the slot count is known.
pub trait StorableType {
    /// Number of bytes that the type requires.
    ///
    /// Only accurate for those types with a size known at compile-time (fixed-size).
    /// Otherwise, set to a full 32-byte slot.
    const BYTE_COUNT: usize;
}

/// Trait for types that can be stored/loaded from EVM storage.
///
/// This trait provides a flexible abstraction for reading and writing Rust types
/// to EVM storage. Types can occupy one or more consecutive storage slots, enabling
/// support for both simple values (Address, U256, bool) and complex multi-slot types
/// (structs, fixed arrays).
///
/// # Type Parameter
///
/// - `N`: The number of consecutive storage slots this type occupies.
///   For single-word types (Address, U256, bool), this is `1`.
///   For fixed-size arrays, this equals the number of elements.
///   For user-defined structs, this a number between `1` and the number of fields, which depends on slot packing.
///
/// # Storage Layout
///
/// For a type with `N = 3` starting at `base_slot`:
/// - Slot 0: `base_slot + 0`
/// - Slot 1: `base_slot + 1`
/// - Slot 2: `base_slot + 2`
///
/// # Safety
///
/// Implementations must ensure that:
/// - Round-trip conversions preserve data: `load(store(x)) == Ok(x)`
/// - `N` accurately reflects the number of slots used
/// - `store` and `load` access exactly `N` consecutive slots
/// - `to_evm_words` and `from_evm_words` produce/consume exactly `N` words
pub trait Storable<const N: usize>: Sized + StorableType {
    /// Load this type from storage starting at the given base slot.
    ///
    /// Reads `N` consecutive slots starting from `base_slot`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Storage read fails
    /// - Data cannot be decoded into this type
    fn load<S: StorageOps>(storage: &mut S, base_slot: U256) -> Result<Self>;

    /// Store this type to storage starting at the given base slot.
    ///
    /// Writes `N` consecutive slots starting from `base_slot`.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage write fails.
    fn store<S: StorageOps>(&self, storage: &mut S, base_slot: U256) -> Result<()>;

    /// Delete this type from storage (set all slots to zero).
    ///
    /// Sets `N` consecutive slots to zero, starting from `base_slot`.
    ///
    /// The default implementation sets each slot to zero individually.
    /// Types may override this for optimized bulk deletion.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage write fails.
    fn delete<S: StorageOps>(storage: &mut S, base_slot: U256) -> Result<()> {
        for offset in 0..N {
            storage.sstore(base_slot + U256::from(offset), U256::ZERO)?;
        }
        Ok(())
    }

    /// Encode this type to an array of U256 words.
    ///
    /// Returns exactly `N` words, where each word represents one storage slot.
    /// For single-slot types (`N = 1`), returns a single-element array.
    /// For multi-slot types, each array element corresponds to one slot's data.
    ///
    /// # Packed Storage
    ///
    /// When multiple small fields are packed into a single slot, they are
    /// positioned and combined into a single U256 word according to their
    /// byte offsets. The derive macro handles this automatically.
    fn to_evm_words(&self) -> Result<[U256; N]>;

    /// Decode this type from an array of U256 words.
    ///
    /// Accepts exactly `N` words, where each word represents one storage slot.
    /// Constructs the complete type from all provided words.
    ///
    /// # Packed Storage
    ///
    /// When multiple small fields are packed into a single slot, they are
    /// extracted from the appropriate word using bit shifts and masks.
    /// The derive macro handles this automatically.
    fn from_evm_words(words: [U256; N]) -> Result<Self>;
}

/// Trait for types that can be used as storage mapping keys.
///
/// Keys are hashed using keccak256 along with the mapping's base slot
/// to determine the final storage location. This trait provides the
/// byte representation used in that hash.
pub trait StorageKey {
    fn as_storage_bytes(&self) -> impl AsRef<[u8]>;
}

// -- STORAGE KEY IMPLEMENTATIONS ---------------------------------------------

impl StorageKey for Address {
    #[inline]
    fn as_storage_bytes(&self) -> impl AsRef<[u8]> {
        self.as_slice()
    }
}

// -- STORAGE TYPE IMPLEMENTATIONS ---------------------------------------------

storable_rust_ints!();
storable_alloy_ints!();
storable_alloy_bytes!();

impl StorableType for bool {
    const BYTE_COUNT: usize = 1;
}

impl Storable<1> for bool {
    #[inline]
    fn load<S: StorageOps>(storage: &mut S, base_slot: U256) -> Result<Self> {
        let value = storage.sload(base_slot)?;
        Ok(value != U256::ZERO)
    }

    #[inline]
    fn store<S: StorageOps>(&self, storage: &mut S, base_slot: U256) -> Result<()> {
        let value = if *self { U256::ONE } else { U256::ZERO };
        storage.sstore(base_slot, value)
    }

    #[inline]
    fn to_evm_words(&self) -> Result<[U256; 1]> {
        Ok([if *self { U256::ONE } else { U256::ZERO }])
    }

    #[inline]
    fn from_evm_words(words: [U256; 1]) -> Result<Self> {
        Ok(words[0] != U256::ZERO)
    }
}

impl StorableType for Address {
    const BYTE_COUNT: usize = 20;
}

impl Storable<1> for Address {
    #[inline]
    fn load<S: StorageOps>(storage: &mut S, base_slot: U256) -> Result<Self> {
        let value = storage.sload(base_slot)?;
        Ok(value.into_address())
    }

    #[inline]
    fn store<S: StorageOps>(&self, storage: &mut S, base_slot: U256) -> Result<()> {
        storage.sstore(base_slot, self.into_u256())
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

// -- STRING STORAGE HELPERS ---------------------------------------------------

/// Compute the storage slot where long string data begins.
///
/// For long strings (≥32 bytes), data is stored starting at `keccak256(base_slot)`.
#[inline]
fn compute_string_data_slot(base_slot: U256) -> U256 {
    U256::from_be_bytes(keccak256(base_slot.to_be_bytes::<32>()).0)
}

/// Check if a storage slot value represents a long string.
///
/// Solidity string encoding uses bit 0 of the LSB to distinguish:
/// - Bit 0 = 0: Short string (≤31 bytes)
/// - Bit 0 = 1: Long string (≥32 bytes)
#[inline]
fn is_long_string(slot_value: U256) -> bool {
    (slot_value.byte(0) & 1) != 0
}

/// Extract the string length from a storage slot value.
///
/// # Arguments
/// * `slot_value` - The value stored in the main slot
/// * `is_long` - Whether this is a long string (from `is_long_string()`)
///
/// # Returns
/// The length of the string in bytes
#[inline]
fn extract_string_length(slot_value: U256, is_long: bool) -> usize {
    if is_long {
        // Long string: slot stores (length * 2 + 1)
        // Extract length: (value - 1) / 2
        let length_times_two_plus_one: U256 = slot_value;
        let length_times_two: U256 = length_times_two_plus_one - U256::from(1);
        let length_u256: U256 = length_times_two >> 1;
        length_u256.to::<usize>()
    } else {
        // Short string: LSB stores (length * 2)
        // Extract length: LSB / 2
        let bytes = slot_value.to_be_bytes::<32>();
        (bytes[31] / 2) as usize
    }
}

/// String storage using Solidity's string encoding.
///
/// **Short strings (≤31 bytes)** are stored inline in a single slot:
/// - Bytes 0..len: UTF-8 string data (left-aligned)
/// - Byte 31 (LSB): length * 2 (bit 0 = 0 indicates short string)
///
/// **Long strings (≥32 bytes)** use keccak256-based storage:
/// - Base slot: stores `length * 2 + 1` (bit 0 = 1 indicates long string)
/// - Data slots: stored at `keccak256(main_slot) + i` for each 32-byte chunk
impl StorableType for String {
    const BYTE_COUNT: usize = 32;
}

impl Storable<1> for String {
    fn load<S: StorageOps>(storage: &mut S, base_slot: U256) -> Result<Self> {
        let main_slot_value = storage.sload(base_slot)?;
        let is_long = is_long_string(main_slot_value);
        let length = extract_string_length(main_slot_value, is_long);

        if is_long {
            // Long string: read data from keccak256(base_slot) + i
            let data_slot_start = compute_string_data_slot(base_slot);
            let chunk_count = (length + 31) / 32; // Ceiling division
            let mut data = Vec::with_capacity(length);

            for i in 0..chunk_count {
                let slot = data_slot_start + U256::from(i);
                let chunk_value = storage.sload(slot)?;
                let chunk_bytes = chunk_value.to_be_bytes::<32>();

                // For the last chunk, only take the remaining bytes
                let bytes_to_take = if i == chunk_count - 1 {
                    length - (i * 32)
                } else {
                    32
                };
                data.extend_from_slice(&chunk_bytes[..bytes_to_take]);
            }

            Self::from_utf8(data).map_err(|e| {
                TempoPrecompileError::Fatal(format!("Invalid UTF-8 in stored string: {e}"))
            })
        } else {
            // Short string: data is inline in the main slot
            let bytes = main_slot_value.to_be_bytes::<32>();
            let utf8_bytes = &bytes[..length];
            Self::from_utf8(utf8_bytes.to_vec()).map_err(|e| {
                TempoPrecompileError::Fatal(format!("Invalid UTF-8 in stored string: {e}"))
            })
        }
    }

    fn store<S: StorageOps>(&self, storage: &mut S, base_slot: U256) -> Result<()> {
        let bytes = self.as_bytes();
        let length = bytes.len();

        if length <= 31 {
            // Short string: store inline with length * 2 in LSB
            let mut storage_bytes = [0u8; 32];
            storage_bytes[..length].copy_from_slice(bytes);
            storage_bytes[31] = (length * 2) as u8;
            storage.sstore(base_slot, U256::from_be_bytes(storage_bytes))
        } else {
            // Long string: store length * 2 + 1 in main slot, data at keccak256(base_slot)
            let length_value = U256::from(length * 2 + 1);
            storage.sstore(base_slot, length_value)?;

            // Store data in chunks at keccak256(base_slot) + i
            let data_slot_start = compute_string_data_slot(base_slot);
            let chunk_count = (length + 31) / 32;

            for i in 0..chunk_count {
                let slot = data_slot_start + U256::from(i);
                let chunk_start = i * 32;
                let chunk_end = (chunk_start + 32).min(length);
                let chunk = &bytes[chunk_start..chunk_end];

                // Pad chunk to 32 bytes if it's the last chunk
                let mut chunk_bytes = [0u8; 32];
                chunk_bytes[..chunk.len()].copy_from_slice(chunk);

                storage.sstore(slot, U256::from_be_bytes(chunk_bytes))?;
            }

            Ok(())
        }
    }

    fn delete<S: StorageOps>(storage: &mut S, base_slot: U256) -> Result<()> {
        let main_slot_value = storage.sload(base_slot)?;
        let is_long = is_long_string(main_slot_value);

        if is_long {
            // Long string: need to clear data slots as well
            let length = extract_string_length(main_slot_value, true);
            let data_slot_start = compute_string_data_slot(base_slot);
            let chunk_count = (length + 31) / 32;

            // Clear all data slots
            for i in 0..chunk_count {
                let slot = data_slot_start + U256::from(i);
                storage.sstore(slot, U256::ZERO)?;
            }
        }

        // Clear the main slot (works for both short and long strings)
        storage.sstore(base_slot, U256::ZERO)
    }

    // TODO(rusowsky): impl and test
    fn to_evm_words(&self) -> Result<[U256; 1]> {
        Err(TempoPrecompileError::Fatal(
            "String type cannot be used in packed storage contexts.".into(),
        ))
    }

    // TODO(rusowsky): impl and test
    fn from_evm_words(_words: [U256; 1]) -> Result<Self> {
        Err(TempoPrecompileError::Fatal(
            "String type cannot be used in packed storage contexts.".into(),
        ))
    }
}

mod tests {
    use super::*;
    use crate::storage::{PrecompileStorageProvider, hashmap::HashMapStorageProvider};

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

    #[test]
    fn test_address_round_trip() {
        let mut storage = HashMapStorageProvider::new(1);
        let contract_addr = Address::random();
        let mut contract = TestContract {
            address: contract_addr,
            storage: &mut storage,
        };

        let addr = Address::random();
        let slot = U256::from(1);

        addr.store(&mut contract, slot).unwrap();
        let loaded = Address::load(&mut contract, slot).unwrap();
        assert_eq!(addr, loaded);
    }

    #[test]
    fn test_bool_conversions() {
        let mut storage = HashMapStorageProvider::new(1);
        let addr = Address::random();
        let mut contract = TestContract {
            address: addr,
            storage: &mut storage,
        };

        let slot = U256::from(3);

        // Test true
        true.store(&mut contract, slot).unwrap();
        assert!(bool::load(&mut contract, slot).unwrap());

        // Test false
        false.store(&mut contract, slot).unwrap();
        assert!(!bool::load(&mut contract, slot).unwrap());

        // Test that any non-zero value is true
        contract.storage.sstore(addr, slot, U256::from(42)).unwrap();
        assert!(bool::load(&mut contract, slot).unwrap());
    }

    #[test]
    fn test_u64_round_trip() {
        let mut storage = HashMapStorageProvider::new(1);
        let addr = Address::random();
        let mut contract = TestContract {
            address: addr,
            storage: &mut storage,
        };

        let value = u64::MAX;
        let slot = U256::from(4);

        value.store(&mut contract, slot).unwrap();
        let loaded = u64::load(&mut contract, slot).unwrap();
        assert_eq!(value, loaded);
    }

    #[test]
    fn test_string_empty() {
        let mut storage = HashMapStorageProvider::new(1);
        let addr = Address::random();
        let mut contract = TestContract {
            address: addr,
            storage: &mut storage,
        };

        let s = String::new();
        let slot = U256::from(7);

        s.store(&mut contract, slot).unwrap();
        let loaded = String::load(&mut contract, slot).unwrap();
        assert_eq!(s, loaded);
    }

    #[test]
    fn test_string_short() {
        let mut storage = HashMapStorageProvider::new(1);
        let addr = Address::random();
        let mut contract = TestContract {
            address: addr,
            storage: &mut storage,
        };

        let s = "Hello, Tempo!".to_string();
        assert!(s.len() <= 31, "Test string must be <= 31 bytes");

        let slot = U256::from(8);
        s.store(&mut contract, slot).unwrap();
        let loaded = String::load(&mut contract, slot).unwrap();
        assert_eq!(s, loaded);
    }

    #[test]
    fn test_string_max_length() {
        let mut storage = HashMapStorageProvider::new(1);
        let addr = Address::random();
        let mut contract = TestContract {
            address: addr,
            storage: &mut storage,
        };

        // 31 bytes is the maximum for short string encoding
        let s = "a".repeat(31);
        assert_eq!(s.len(), 31);

        let slot = U256::from(9);
        s.store(&mut contract, slot).unwrap();
        let loaded = String::load(&mut contract, slot).unwrap();
        assert_eq!(s, loaded);
    }

    #[test]
    fn test_string_unicode() {
        let mut storage = HashMapStorageProvider::new(1);
        let addr = Address::random();
        let mut contract = TestContract {
            address: addr,
            storage: &mut storage,
        };

        let s = "Hello 世界 🌍".to_string();
        assert!(s.len() <= 31, "Test string too long");

        let slot = U256::from(11);
        s.store(&mut contract, slot).unwrap();
        let loaded = String::load(&mut contract, slot).unwrap();
        assert_eq!(s, loaded);
    }

    #[test]
    fn test_string_storage_format() {
        let mut storage = HashMapStorageProvider::new(1);
        let addr = Address::random();
        let mut contract = TestContract {
            address: addr,
            storage: &mut storage,
        };

        let s = "test".to_string(); // 4 bytes
        let slot = U256::from(12);

        s.store(&mut contract, slot).unwrap();
        let raw_value = contract.storage.sload(addr, slot).unwrap();
        let bytes = raw_value.to_be_bytes::<32>();

        // Check first 4 bytes contain "test"
        assert_eq!(&bytes[0..4], b"test");

        // Check rest is zeros
        assert!(bytes[4..31].iter().all(|&b| b == 0));

        // Check length byte: 4 * 2 = 8
        assert_eq!(bytes[31], 8);
    }

    // -- LONG STRING TESTS ----------------------------------------------------

    #[test]
    fn test_string_32_bytes_boundary() {
        let mut storage = HashMapStorageProvider::new(1);
        let addr = Address::random();
        let mut contract = TestContract {
            address: addr,
            storage: &mut storage,
        };

        // 32 bytes is the minimum long string
        let s = "a".repeat(32);
        assert_eq!(s.len(), 32);

        let slot = U256::from(20);
        s.store(&mut contract, slot).unwrap();

        // Verify it's stored as a long string
        let main_slot_value = contract.storage.sload(addr, slot).unwrap();
        assert_eq!(main_slot_value.byte(0) & 1, 1); // Bit 0 should be 1

        // Verify length encoding: 32 * 2 + 1 = 65
        assert_eq!(main_slot_value, U256::from(65));

        // Verify round-trip
        let loaded = String::load(&mut contract, slot).unwrap();
        assert_eq!(s, loaded);
    }

    #[test]
    fn test_string_33_bytes() {
        let mut storage = HashMapStorageProvider::new(1);
        let addr = Address::random();
        let mut contract = TestContract {
            address: addr,
            storage: &mut storage,
        };

        let s = "b".repeat(33);
        let slot = U256::from(21);

        s.store(&mut contract, slot).unwrap();
        let loaded = String::load(&mut contract, slot).unwrap();
        assert_eq!(s, loaded);
    }

    #[test]
    fn test_string_64_bytes_exactly_two_slots() {
        let mut storage = HashMapStorageProvider::new(1);
        let addr = Address::random();
        let mut contract = TestContract {
            address: addr,
            storage: &mut storage,
        };

        // 64 bytes exactly fills 2 data slots
        let s = "c".repeat(64);
        let slot = U256::from(22);

        s.store(&mut contract, slot).unwrap();
        let loaded = String::load(&mut contract, slot).unwrap();
        assert_eq!(s, loaded);
    }

    #[test]
    fn test_string_65_bytes() {
        let mut storage = HashMapStorageProvider::new(1);
        let addr = Address::random();
        let mut contract = TestContract {
            address: addr,
            storage: &mut storage,
        };

        // 65 bytes requires 3 data slots (32 + 32 + 1)
        let s = "d".repeat(65);
        let slot = U256::from(23);

        s.store(&mut contract, slot).unwrap();
        let loaded = String::load(&mut contract, slot).unwrap();
        assert_eq!(s, loaded);
    }

    #[test]
    fn test_string_100_bytes() {
        let mut storage = HashMapStorageProvider::new(1);
        let addr = Address::random();
        let mut contract = TestContract {
            address: addr,
            storage: &mut storage,
        };

        let s = "e".repeat(100);
        let slot = U256::from(24);

        s.store(&mut contract, slot).unwrap();
        let loaded = String::load(&mut contract, slot).unwrap();
        assert_eq!(s, loaded);
    }

    #[test]
    fn test_string_long_unicode() {
        let mut storage = HashMapStorageProvider::new(1);
        let addr = Address::random();
        let mut contract = TestContract {
            address: addr,
            storage: &mut storage,
        };

        // Create a long unicode string (>32 bytes)
        let s = "Hello 世界 🌍 ".repeat(5); // Should be >32 bytes
        assert!(s.len() > 32, "Test string should be >32 bytes");

        let slot = U256::from(25);
        s.store(&mut contract, slot).unwrap();
        let loaded = String::load(&mut contract, slot).unwrap();
        assert_eq!(s, loaded);
    }

    #[test]
    fn test_string_long_storage_layout() {
        let mut storage = HashMapStorageProvider::new(1);
        let addr = Address::random();
        let mut contract = TestContract {
            address: addr,
            storage: &mut storage,
        };

        // Use a 35-byte string to verify storage layout
        let s = "x".repeat(35);
        let base_slot = U256::from(26);

        s.store(&mut contract, base_slot).unwrap();

        // Check main slot contains length * 2 + 1 = 35 * 2 + 1 = 71
        let main_value = contract.storage.sload(addr, base_slot).unwrap();
        assert_eq!(main_value, U256::from(71));

        // Compute expected data slot: keccak256(base_slot)
        let expected_data_slot =
            U256::from_be_bytes(alloy::primitives::keccak256(base_slot.to_be_bytes::<32>()).0);

        // Verify first data slot contains "xxxxx..." (32 x's)
        let data_slot_0 = contract.storage.sload(addr, expected_data_slot).unwrap();
        let data_bytes_0 = data_slot_0.to_be_bytes::<32>();
        assert_eq!(&data_bytes_0[..32], "x".repeat(32).as_bytes());

        // Verify second data slot contains remaining 3 x's (padded with zeros)
        let data_slot_1 = contract
            .storage
            .sload(addr, expected_data_slot + U256::from(1))
            .unwrap();
        let data_bytes_1 = data_slot_1.to_be_bytes::<32>();
        assert_eq!(&data_bytes_1[..3], "xxx".as_bytes());
        assert!(data_bytes_1[3..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_string_long_delete() {
        let mut storage = HashMapStorageProvider::new(1);
        let addr = Address::random();
        let mut contract = TestContract {
            address: addr,
            storage: &mut storage,
        };

        // Store a long string
        let s = "z".repeat(50);
        let slot = U256::from(27);

        s.store(&mut contract, slot).unwrap();

        // Verify it was stored
        let loaded = String::load(&mut contract, slot).unwrap();
        assert_eq!(s, loaded);

        // Delete it
        String::delete(&mut contract, slot).unwrap();

        // Verify main slot is cleared
        let main_value = contract.storage.sload(addr, slot).unwrap();
        assert_eq!(main_value, U256::ZERO);

        // Verify data slots are cleared
        let data_slot_start =
            U256::from_be_bytes(alloy::primitives::keccak256(slot.to_be_bytes::<32>()).0);
        let chunk_count = (50 + 31) / 32; // 2 chunks

        for i in 0..chunk_count {
            let data_slot = data_slot_start + U256::from(i);
            let value = contract.storage.sload(addr, data_slot).unwrap();
            assert_eq!(value, U256::ZERO, "Data slot {i} should be cleared");
        }

        // Loading after delete should return empty string
        let loaded_after_delete = String::load(&mut contract, slot).unwrap();
        assert_eq!(loaded_after_delete, String::new());
    }

    #[test]
    fn test_string_short_to_long_overwrite() {
        let mut storage = HashMapStorageProvider::new(1);
        let addr = Address::random();
        let mut contract = TestContract {
            address: addr,
            storage: &mut storage,
        };

        let slot = U256::from(28);

        // Store a short string first
        let short_s = "short".to_string();
        short_s.store(&mut contract, slot).unwrap();
        assert_eq!(String::load(&mut contract, slot).unwrap(), short_s);

        // Overwrite with a long string
        let long_s = "a".repeat(50);
        long_s.store(&mut contract, slot).unwrap();
        assert_eq!(String::load(&mut contract, slot).unwrap(), long_s);

        // Overwrite back to a short string
        let short_s2 = "tiny".to_string();
        short_s2.store(&mut contract, slot).unwrap();
        assert_eq!(String::load(&mut contract, slot).unwrap(), short_s2);
    }

    #[test]
    fn test_string_long_to_short_overwrite() {
        let mut storage = HashMapStorageProvider::new(1);
        let addr = Address::random();
        let mut contract = TestContract {
            address: addr,
            storage: &mut storage,
        };

        let slot = U256::from(29);

        // Store a long string first
        let long_s = "b".repeat(80);
        long_s.store(&mut contract, slot).unwrap();
        assert_eq!(String::load(&mut contract, slot).unwrap(), long_s);

        // Overwrite with a short string
        let short_s = "mini".to_string();
        short_s.store(&mut contract, slot).unwrap();
        assert_eq!(String::load(&mut contract, slot).unwrap(), short_s);

        // Note: The old long string data slots are not automatically cleared
        // when overwriting with a short string.
    }
}
