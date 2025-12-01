mod slot;
pub use slot::*;

pub mod mapping;
pub use mapping::*;

mod bytes_like;
mod primitives;
pub mod vec;

use crate::{error::Result, storage::StorageOps};
use alloy::primitives::U256;

/// Describes how a type is laid out in EVM storage.
///
/// This determines whether a type can be packed with other fields
/// and how many storage slots it occupies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Single slot, N bytes (1-32). Can be packed with other fields if N < 32.
    ///
    /// Used for primitive types like integers, booleans, and addresses.
    Bytes(usize),

    /// Occupies N full slots (each 32 bytes). Cannot be packed.
    ///
    /// Used for structs, fixed-size arrays, and dynamic types.
    Slots(usize),
}

impl Layout {
    /// Returns true if this field can be packed with adjacent fields.
    pub const fn is_packable(&self) -> bool {
        match self {
            // TODO(rusowsky): use `Self::Bytes(n) => *n < 32` to reduce gas usage.
            // Note that this requires a hardfork and must be properly coordinated.
            Self::Bytes(_) => true,
            Self::Slots(_) => false,
        }
    }

    /// Returns the number of storage slots this type occupies.
    pub const fn slots(&self) -> usize {
        match self {
            Self::Bytes(_) => 1,
            Self::Slots(n) => *n,
        }
    }

    /// Returns the number of bytes this type occupies.
    ///
    /// For `Bytes(n)`, returns n.
    /// For `Slots(n)`, returns n * 32 (each slot is 32 bytes).
    pub const fn bytes(&self) -> usize {
        match self {
            Self::Bytes(n) => *n,
            Self::Slots(n) => {
                // Compute n * 32 using repeated addition for const compatibility
                let (mut i, mut result) = (0, 0);
                while i < *n {
                    result += 32;
                    i += 1;
                }
                result
            }
        }
    }
}

/// Describes the context in which a `Storable` value is being loaded or stored.
///
/// Determines whether the value occupies an entire storage slot or is packed
/// with other values at a specific byte offset within a slot.
///
/// **NOTE:** This type is not an enum to minimize its memory size, but its
/// implementation is equivalent to:
/// ```rs
/// enum LayoutCtx {
///    Full,
///    Packed(usize)
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct LayoutCtx(usize);

impl LayoutCtx {
    /// Load/store the entire value at `base_slot`.
    ///
    /// For writes, this directly overwrites the entire slot without needing SLOAD.
    /// All `Storable` types support this context.
    pub const FULL: Self = Self(usize::MAX);

    /// Load/store a packed primitive at the given byte offset within a slot.
    ///
    /// For writes, this requires a read-modify-write: SLOAD the current slot value,
    /// modify the bytes at the offset, then SSTORE back. This preserves other
    /// packed fields in the same slot.
    ///
    /// Only primitive types with `Layout::Bytes(n)` where `n < 32` support this context.
    pub const fn packed(offset: usize) -> Self {
        debug_assert!(offset < 32);
        Self(offset)
    }

    /// Get the packed offset, returns `None` for `Full`
    #[inline]
    pub const fn packed_offset(&self) -> Option<usize> {
        if self.0 == usize::MAX {
            None
        } else {
            Some(self.0)
        }
    }
}

/// Helper trait to access storage layout information without requiring const generic parameter.
///
/// This trait exists to allow the derive macro to query the layout and size of field types
/// during layout computation, before the slot count is known.
pub trait StorableType {
    /// Describes how this type is laid out in storage.
    ///
    /// - Primitives use `Layout::Bytes(N)` where N is their size
    /// - Dynamic types (String, Bytes, Vec) use `Layout::Slots(1)`
    /// - Structs and arrays use `Layout::Slots(N)` where N is the slot count
    const LAYOUT: Layout;

    /// Number of storage slots this type takes.
    const SLOTS: usize = Self::LAYOUT.slots();

    /// Number of bytes this type takes.
    const BYTES: usize = Self::LAYOUT.bytes();

    /// Whether this type can be packed with adjacent fields.
    const IS_PACKABLE: bool = Self::LAYOUT.is_packable();
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
/// - `SLOTS`: The number of consecutive storage slots this type occupies.
///   For single-word types (Address, U256, bool), this is `1`.
///   For fixed-size arrays, this equals the number of elements.
///   For user-defined structs, this a number between `1` and the number of fields, which depends on slot packing.
///
/// # Storage Layout
///
/// For a type with `SLOTS = 3` starting at `base_slot`:
/// - Slot 0: `base_slot + 0`
/// - Slot 1: `base_slot + 1`
/// - Slot 2: `base_slot + 2`
///
/// # Safety
///
/// Implementations must ensure that:
/// - Round-trip conversions preserve data: `load(store(x)) == Ok(x)`
/// - `SLOTS` accurately reflects the number of slots used
/// - `store` and `load` access exactly `SLOTS` consecutive slots
/// - `to_evm_words` and `from_evm_words` produce/consume exactly `SLOTS` words
pub trait Storable<const SLOTS: usize>: Sized + StorableType {
    /// Load this type from storage starting at the given base slot.
    ///
    /// Reads `SLOTS` consecutive slots starting from `base_slot`.
    ///
    /// # Context
    ///
    /// - `LayoutCtx::FULL`: Load the entire value from `base_slot` (and subsequent slots if multi-slot)
    /// - `LayoutCtx::packed(offset)`: Load a packed primitive from byte `offset` within `base_slot`
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Storage read fails
    /// - Data cannot be decoded into this type
    /// - Context is invalid for this type (e.g., `Packed` for a multi-slot type)
    fn load<S: StorageOps>(storage: &mut S, base_slot: U256, ctx: LayoutCtx) -> Result<Self>;

    /// Store this type to storage starting at the given base slot.
    ///
    /// Writes `SLOTS` consecutive slots starting from `base_slot`.
    ///
    /// # Context
    ///
    /// - `LayoutCtx::FULL`: Write the entire value to `base_slot` (overwrites full slot)
    /// - `LayoutCtx::packed(offset)`: Write a packed primitive at byte `offset` (read-modify-write)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Storage write fails
    /// - Context is invalid for this type (e.g., `Packed` for a multi-slot type)
    fn store<S: StorageOps>(&self, storage: &mut S, base_slot: U256, ctx: LayoutCtx) -> Result<()>;

    /// Delete this type from storage (set all slots to zero).
    ///
    /// Sets `SLOTS` consecutive slots to zero, starting from `base_slot`.
    ///
    /// # Context
    ///
    /// - `LayoutCtx::FULL`: Clear entire slot(s) by writing zero
    /// - `LayoutCtx::packed(offset)`: Clear only the bytes at the offset (read-modify-write)
    ///
    /// The default implementation handles both contexts appropriately.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Storage write fails
    /// - Context is invalid for this type
    fn delete<S: StorageOps>(storage: &mut S, base_slot: U256, ctx: LayoutCtx) -> Result<()> {
        match ctx.packed_offset() {
            None => {
                for offset in 0..SLOTS {
                    storage.sstore(base_slot + U256::from(offset), U256::ZERO)?;
                }
                Ok(())
            }
            Some(offset) => {
                // For packed context, we need to preserve other fields in the slot
                let bytes = Self::BYTES;
                let current = storage.sload(base_slot)?;
                let cleared = crate::storage::packing::zero_packed_value(current, offset, bytes)?;
                storage.sstore(base_slot, cleared)
            }
        }
    }

    /// Encode this type to an array of U256 words.
    ///
    /// Returns exactly `SLOTS` words, where each word represents one storage slot.
    /// For single-slot types (`SLOTS = 1`), returns a single-element array.
    /// For multi-slot types, each array element corresponds to one slot's data.
    ///
    /// # Packed Storage
    ///
    /// When multiple small fields are packed into a single slot, they are
    /// positioned and combined into a single U256 word according to their
    /// byte offsets. The derive macro handles this automatically.
    fn to_evm_words(&self) -> Result<[U256; SLOTS]>;

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
    fn from_evm_words(words: [U256; SLOTS]) -> Result<Self>;

    /// Test helper to ensure `LAYOUT` and `SLOTS` are in sync.
    fn validate_layout() {
        debug_assert_eq!(<Self as StorableType>::SLOTS, SLOTS)
    }
}

/// Trait for types that can be used as storage mapping keys.
///
/// Keys are hashed using keccak256 along with the mapping's base slot
/// to determine the final storage location. This trait provides the
/// byte representation used in that hash.
pub trait StorageKey {
    fn as_storage_bytes(&self) -> impl AsRef<[u8]>;
}
