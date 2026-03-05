#![doc = include_str!("../README.md")]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

/// Tempo bech32m address encoding.
pub mod address;

mod network;
pub use network::*;

/// Provider traits.
pub mod provider;

pub mod rpc;

/// Transaction fillers.
pub mod fillers;

#[doc(inline)]
pub use tempo_primitives as primitives;

#[doc(inline)]
pub use tempo_contracts as contracts;
