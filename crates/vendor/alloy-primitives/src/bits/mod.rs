#[macro_use]
mod macros;

mod address;
pub use address::{Address, AddressChecksumBuffer, AddressError};
#[cfg(feature = "rkyv")]
pub use address::{AddressResolver, ArchivedAddress};

mod bloom;
#[cfg(feature = "rkyv")]
pub use bloom::{ArchivedBloom, BloomResolver};
pub use bloom::{BLOOM_BITS_PER_ITEM, BLOOM_SIZE_BITS, BLOOM_SIZE_BYTES, Bloom, BloomInput};

mod fixed;
pub use fixed::FixedBytes;
#[cfg(feature = "rkyv")]
pub use fixed::{ArchivedFixedBytes, FixedBytesResolver};

mod flatten;
pub use flatten::{FixedBytesSliceExt, FixedBytesVecExt};

mod function;
pub use function::Function;

#[cfg(feature = "borsh")]
mod borsh;

#[cfg(feature = "rlp")]
mod rlp;

#[cfg(feature = "serde")]
mod serde;

#[cfg(feature = "schemars")]
mod schemars;

#[cfg(feature = "rkyv")]
mod rkyv;
