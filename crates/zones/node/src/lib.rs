#![doc = include_str!("../README.md")]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(unnameable_types)]
#![allow(clippy::too_many_arguments)]

use eyre as _;

#[cfg(feature = "cli")]
pub mod cli;
pub mod dev;
pub mod engine;
pub mod genesis;
pub mod node;
pub mod rpc;
mod simplex;
mod tx_forwarding;
pub mod version;

pub use engine::ZoneEngine;
pub use node::{ZoneExecutorBuilder, ZoneNode, ZoneRedactedRpcConfig, ZoneSequencerAddOnsConfig};
pub use version::init_version_metadata;
