#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/alloy-rs/core/main/assets/alloy.jpg",
    html_favicon_url = "https://raw.githubusercontent.com/alloy-rs/core/main/assets/favicon.ico"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(feature = "nightly", feature(hasher_prefixfree_extras))]
#![cfg_attr(feature = "nightly", feature(core_intrinsics))]
#![cfg_attr(feature = "nightly", allow(internal_features))]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[macro_use]
extern crate alloc;

use paste as _;
use rustc_hash as _;
use sha3 as _;
#[cfg(feature = "tiny-keccak")]
use tiny_keccak as _;

#[cfg(feature = "postgres")]
pub mod postgres;

#[cfg(feature = "diesel")]
pub mod diesel;

#[cfg(feature = "sqlx")]
pub mod sqlx;

pub mod aliases;
#[doc(no_inline)]
pub use aliases::{
    B64, B128, B256, B512, BlockHash, BlockNumber, BlockTimestamp, ChainId, I8, I16, I32, I64,
    I128, I160, I256, Selector, StorageKey, StorageValue, TxHash, TxIndex, TxNonce, TxNumber, U8,
    U16, U32, U64, U128, U160, U256, U512,
};

#[macro_use]
mod bits;
pub use bits::{
    Address, AddressChecksumBuffer, AddressError, BLOOM_BITS_PER_ITEM, BLOOM_SIZE_BITS,
    BLOOM_SIZE_BYTES, Bloom, BloomInput, FixedBytes, FixedBytesSliceExt, FixedBytesVecExt,
    Function,
};
#[cfg(feature = "rkyv")]
pub use bits::{
    AddressResolver, ArchivedAddress, ArchivedBloom, ArchivedFixedBytes, BloomResolver,
    FixedBytesResolver,
};

#[path = "bytes/mod.rs"]
mod bytes_;
pub use self::bytes_::Bytes;

mod common;
pub use common::TxKind;

mod log;
pub use log::{IntoLogData, Log, LogData, logs_bloom};

#[cfg(feature = "map")]
pub mod map;

mod sealed;
pub use sealed::{Sealable, Sealed};

mod signed;
pub use signed::{BigIntConversionError, ParseSignedError, Sign, Signed};

mod signature;
pub use signature::{Signature, SignatureError, normalize_v, to_eip155_v};

pub mod utils;
pub use utils::{KECCAK256_EMPTY, Keccak256, eip191_hash_message, keccak256, keccak256_uncached};

#[doc(hidden)] // Use `hex` directly instead!
pub mod hex_literal;

#[doc(inline)]
pub use ruint::uint;
#[doc(no_inline)]
pub use {
    ::bytes,
    ::hex,
    ruint::{self, Uint},
};

#[cfg(feature = "serde")]
#[doc(no_inline)]
pub use ::hex::serde as serde_hex;

// Not public API.
#[doc(hidden)]
pub mod private {
    pub use alloc::{borrow::Cow, vec::Vec};
    pub use core::{
        self,
        borrow::{Borrow, BorrowMut},
        cmp::Ordering,
        prelude::rust_2021::*,
    };
    pub use derive_more;

    #[cfg(feature = "getrandom")]
    pub use getrandom;

    #[cfg(feature = "rand")]
    pub use rand;

    #[cfg(feature = "rlp")]
    pub use alloy_rlp;

    #[cfg(feature = "allocative")]
    pub use allocative;

    #[cfg(feature = "serde")]
    pub use serde;

    #[cfg(feature = "borsh")]
    pub use borsh;

    #[cfg(feature = "arbitrary")]
    pub use {arbitrary, proptest, proptest_derive};

    #[cfg(feature = "diesel")]
    pub use diesel;

    #[cfg(feature = "sqlx")]
    pub use sqlx_core;

    #[cfg(feature = "schemars")]
    pub use schemars;
}
