#![doc = include_str!("../README.md")]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod config;
mod identity;
mod manifest;
mod network;
mod runtime;

pub use config::P2pConfig;
pub use manifest::{ConsensusParams, ManifestAddress, ManifestError, ManifestNode, ZoneManifest};
pub use network::{MAX_TRANSACTION_MESSAGE_SIZE, P2pNetworkId};
pub use runtime::{
    BROADCASTER_CHANNEL, CERTIFICATES_CHANNEL, Channel, ForwardTransaction, ForwardedTransaction,
    MARSHAL_CHANNEL, RESOLVER_CHANNEL, SimplexHandle, SimplexNetwork, TRANSACTIONS_CHANNEL,
    VOTES_CHANNEL, spawn_simplex,
};
