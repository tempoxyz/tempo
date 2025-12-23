mod slot;
pub use slot::*;

pub mod mapping;
pub use mapping::*;

pub mod array;
pub mod vec;

mod bytes_like;
mod primitives;

use crate::{
    error::Result,
    storage::{StorageOps, packing},
};
use alloy::primitives::{Address, U256, keccak256};
use std::{cell::UnsafeCell, collections::HashMap, hash::Hash};

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

/// Describes the context in which a storable value is being loaded or stored.
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
    /// Load/store the entire value at a given slot.
    ///
    /// For writes, this directly overwrites the entire slot without needing SLOAD.
    /// All storable types support this context.
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
/// This trait provides compile-time layout information (slot count, byte size, packability)
/// and a factory method for creating handlers. It enables the derive macro to compute
/// struct layouts before the final slot count is known.
///
/// **NOTE:** Don't need to implement the trait manually. Use `#[derive(Storable)]` instead.
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

    /// Whether this type stores it's data in its base slot or not.
    ///
    /// Dynamic types (`Bytes`, `String`, `Vec`) store data at keccak256-addressed
    /// slots and need special cleanup. Non-dynamic types just zero their slots.
    const IS_DYNAMIC: bool = false;

    /// The handler type that provides storage access for this type.
    ///
    /// For primitives, this is `Slot<Self>`.
    /// For mappings, this is `Self` (mappings are their own handlers).
    /// For user-defined structs, this is a generated handler type (e.g., `MyStructHandler`).
    type Handler;

    /// Creates a handler for this type at the given storage location.
    fn handle(slot: U256, ctx: LayoutCtx, address: Address) -> Self::Handler;
}

/// Abstracts reading, writing, and deleting values for [`Storable`] types.
pub trait Handler<T: Storable> {
    /// Reads the value from storage.
    fn read(&self) -> Result<T>;

    /// Writes the value to storage.
    fn write(&mut self, value: T) -> Result<()>;

    /// Deletes the value from storage (sets to zero).
    fn delete(&mut self) -> Result<()>;

    /// Reads the value from storage.
    fn t_read(&self) -> Result<T>;

    /// Writes the value to storage.
    fn t_write(&mut self, value: T) -> Result<()>;

    /// Deletes the value from storage (sets to zero).
    fn t_delete(&mut self) -> Result<()>;
}

/// High-level storage operations for storable types.
///
/// This trait provides storage I/O operations: load, store, delete.
/// Types implement their own logic for handling packed vs full-slot contexts.
pub trait Storable: StorableType + Sized {
    /// Load this type from storage at the given slot.
    fn load<S: StorageOps>(storage: &S, slot: U256, ctx: LayoutCtx) -> Result<Self>;

    /// Store this type to storage at the given slot.
    fn store<S: StorageOps>(&self, storage: &mut S, slot: U256, ctx: LayoutCtx) -> Result<()>;

    /// Delete this type from storage (set to zero).
    ///
    /// Default implementation handles both full-slot and packed contexts:
    /// - `LayoutCtx::FULL`: Writes zero to all `Self::SLOTS` consecutive slots
    /// - `LayoutCtx::packed(offset)`: Clears only the bytes at the offset (read-modify-write)
    fn delete<S: StorageOps>(storage: &mut S, slot: U256, ctx: LayoutCtx) -> Result<()> {
        match ctx.packed_offset() {
            None => {
                for offset in 0..Self::SLOTS {
                    storage.store(slot + U256::from(offset), U256::ZERO)?;
                }
                Ok(())
            }
            Some(offset) => {
                // For packed context, we need to preserve other fields in the slot
                let bytes = Self::BYTES;
                let current = storage.load(slot)?;
                let cleared = crate::storage::packing::zero_packed_value(current, offset, bytes)?;
                storage.store(slot, cleared)
            }
        }
    }
}

/// Private module to seal the `Packable` trait.
#[allow(unnameable_types)]
pub(in crate::storage::types) mod sealed {
    /// Marker trait to prevent external implementations of `Packable`.
    pub trait OnlyPrimitives {}
}

/// Trait for types that can be packed into EVM storage slots.
///
/// This trait is **sealed** - it can only be implemented within this crate
/// for primitive types that fit in a single U256 word.
///
/// # Usage
///
/// `Packable` is used by the storage packing system to efficiently pack multiple
/// small values into a single 32-byte storage slot.
///
/// # Safety
///
/// Implementations must ensure:
/// - `IS_PACKABLE` is true for the implementing type (enforced at compile time)
/// - Round-trip conversions preserve data: `from_word(to_word(x)) == x`
pub trait Packable: sealed::OnlyPrimitives + StorableType {
    /// Encode this type to a single U256 word.
    fn to_word(&self) -> U256;

    /// Decode this type from a single U256 word.
    fn from_word(word: U256) -> Result<Self>
    where
        Self: Sized;
}

/// Blanket implementation of `Storable` for all `Packable` types.
///
/// This provides a unified load/store implementation for all primitive types,
/// handling both full-slot and packed contexts automatically.
impl<T: Packable> Storable for T {
    #[inline]
    fn load<S: StorageOps>(storage: &S, slot: U256, ctx: LayoutCtx) -> Result<Self> {
        const { assert!(T::IS_PACKABLE, "Packable requires IS_PACKABLE to be true") };

        match ctx.packed_offset() {
            None => storage.load(slot).and_then(Self::from_word),
            Some(offset) => {
                let slot_value = storage.load(slot)?;
                packing::extract_packed_value(slot_value, offset, Self::BYTES)
            }
        }
    }

    #[inline]
    fn store<S: StorageOps>(&self, storage: &mut S, slot: U256, ctx: LayoutCtx) -> Result<()> {
        const { assert!(T::IS_PACKABLE, "Packable requires IS_PACKABLE to be true") };

        match ctx.packed_offset() {
            None => storage.store(slot, self.to_word()),
            Some(offset) => {
                let current = storage.load(slot)?;
                let updated = packing::insert_packed_value(current, self, offset, Self::BYTES)?;
                storage.store(slot, updated)
            }
        }
    }
}

/// Trait for types that can be used as storage mapping keys.
///
/// Keys are hashed using keccak256 along with the mapping's base slot
/// to determine the final storage location. This trait provides the
/// byte representation used in that hash.
pub trait StorageKey {
    /// Returns a byte slice for this type.
    fn as_storage_bytes(&self) -> impl AsRef<[u8]>;

    /// Compute storage slot for a mapping with this key.
    ///
    /// Left-pads the key to the nearest 32-byte multiple, concatenates
    /// with the slot, and hashes.
    fn mapping_slot(&self, slot: U256) -> U256 {
        let key_bytes = self.as_storage_bytes();
        let key_bytes = key_bytes.as_ref();

        // Pad key to nearest multiple of 32 bytes
        let padded_len = key_bytes.len().div_ceil(32) * 32;
        let mut buf = vec![0u8; padded_len + 32];

        // Left-pad the key bytes
        buf[padded_len - key_bytes.len()..padded_len].copy_from_slice(key_bytes);
        // Append slot in big-endian
        buf[padded_len..].copy_from_slice(&slot.to_be_bytes::<32>());

        U256::from_be_bytes(keccak256(&buf).0)
    }
}

/// Cache for computed handlers with stable references.
///
/// Enables `Index` implementations on handlers by storing child handlers and
/// returning references that remain valid across insertions.
///
/// # SAFETY
///
/// This type uses `UnsafeCell` for interior mutability. Callers must ensure
/// that the closure passed to `get_or_insert` isn't reentrant.
#[derive(Debug, Default)]
pub(super) struct HandlerCache<K, H> {
    inner: UnsafeCell<HashMap<K, Box<H>>>,
}

impl<K, H> HandlerCache<K, H> {
    /// Creates a new empty handler cache.
    #[inline]
    pub(super) fn new() -> Self {
        Self {
            inner: UnsafeCell::new(HashMap::new()),
        }
    }
}

impl<K, H> Clone for HandlerCache<K, H> {
    /// Creates a new empty cache (cached handlers are not cloned).
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl<K: Hash + Eq, H> HandlerCache<K, H> {
    /// Returns a reference to a lazily initialized handler for the given key.
    ///
    /// # SAFETY
    ///
    /// This method is safe to call as long as the closure `f` doesn't re-enter.
    #[inline]
    pub(super) fn get_or_insert(&self, key: K, f: impl FnOnce() -> H) -> &H {
        // SAFETY: Same guarantees as get_or_insert_mut
        unsafe {
            let cache = &mut *self.inner.get();
            cache.entry(key).or_insert_with(|| Box::new(f()))
        }
    }

    /// Returns a mutable reference to a lazily initialized handler for the given key.
    ///
    /// # SAFETY
    ///
    /// This method is safe to call as long as the closure `f` doesn't re-enter.
    #[inline]
    pub(super) fn get_or_insert_mut(&mut self, key: K, f: impl FnOnce() -> H) -> &mut H {
        // SAFETY:
        // 1. Single-threaded access (EVM execution model)
        // 2. Box ensures stable heap address even when HashMap rehashes
        // 3. Append-only: we only insert, never remove entries
        // 4. Caller must ensure `f()` doesn't access (reenter) this cache
        unsafe {
            let cache = &mut *self.inner.get();
            cache.entry(key).or_insert_with(|| Box::new(f()))
        }
    }
}
