//! Tempo chainspec implementation.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(all(not(test), feature = "reth"), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "reth")]
extern crate alloc;

#[cfg(feature = "reth")]
mod bootnodes;
#[cfg(feature = "reth")]
pub mod spec;
#[cfg(feature = "reth")]
pub use spec::TempoChainSpec;

pub mod constants;
pub mod hardfork;
