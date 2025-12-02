mod slot;
pub use slot::*;

pub mod mapping;
pub use mapping::*;

mod bytes_like;
mod primitives;
pub mod vec;

use crate::{error::Result, storage::StorageOps};
use alloy::primitives::U256;

// Helper trait to access byte count without requiring const generic parameter.
///
/// This trait exists to allow the derive macro to query the byte size of field types
/// during layout computation, before the slot count is known.
///
/// Primitives may have `BYTE_COUNT < 32`.
/// Non-primitives (arrays, Vec, structs) must satisfy `BYTE_COUNT = SLOT_COUNT * 32` as they are
/// not packable.
pub trait StorableType {
    /// Number of bytes that the type occupies (even if partially-empty).
    ///
    /// For dynamic types, set to a full 32-byte slot.
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
/// - `N`: The number of consecutive storage slots this type occupies. For single-word types
///   (Address, U256, bool), this is `1`. For fixed-size arrays, this equals the number of elements.
///   For user-defined structs, this a number between `1` and the number of fields, which depends on
///   slot packing.
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
    /// The number of consecutive storage slots this type occupies.
    ///
    /// Must be equal to `N`, and is provided as a convenient type-level access constant.
    const SLOT_COUNT: usize;

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
