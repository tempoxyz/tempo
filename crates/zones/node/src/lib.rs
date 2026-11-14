#![doc = include_str!("../README.md")]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(unnameable_types)]
#![allow(clippy::too_many_arguments)]

use eyre as _;

#[cfg(feature = "cli")]
pub mod cli;
mod consensus;
#[cfg(feature = "corpus")]
pub mod corpus;
mod deposit_allowlist;
pub mod dev;
pub mod engine;
mod follower;
pub mod genesis;
pub mod node;
mod pool_maintenance;
mod replication;
pub mod role;
pub mod rpc;
mod settlement_attestation;
mod tx_forwarding;
pub mod version;

#[cfg(feature = "cli")]
pub mod state_bloat;

pub use consensus::ZoneConsensus;
pub use deposit_allowlist::{
    DepositAllowlist, DepositAllowlistAdmin, DepositAllowlistError, DepositAllowlistSnapshot,
    SequencerAllowlistStatus,
};
pub use engine::{EngineExit, ProductionPermit, ZoneEngine};
pub use node::{ZoneExecutorBuilder, ZoneNode, ZoneRedactedRpcConfig, ZoneSequencerAddOnsConfig};
pub use version::init_version_metadata;
