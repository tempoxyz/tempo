//! A Tempo node using commonware's threshold simplex as consensus.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub mod config;
pub mod consensus;
pub mod metrics;
pub mod network;
pub mod node;

// Re-export main types for convenience
pub use network::CommonwareNetworkHandle;
pub use node::CommonwareNode;
