#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "std")]
mod network;
#[cfg(feature = "std")]
pub use network::*;

/// Provider traits.
#[cfg(feature = "std")]
pub mod provider;

#[cfg(feature = "std")]
pub mod rpc;

/// Transaction fillers.
#[cfg(feature = "std")]
pub mod fillers;

#[doc(inline)]
pub use tempo_primitives as primitives;

#[cfg(feature = "std")]
#[doc(inline)]
pub use tempo_contracts as contracts;
