//! Tempo chainspec implementation.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

mod bootnodes;
pub mod constants;
pub mod hardfork;
pub mod spec;
pub use spec::TempoChainSpec;
