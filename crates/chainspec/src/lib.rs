//! Tempo chainspec implementation.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod bootnodes;
pub mod hardfork;
pub mod spec;
pub use spec::TempoChainSpec;
