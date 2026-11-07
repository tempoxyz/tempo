#![doc = include_str!("../README.md")]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod backfill;
mod capabilities;
mod identity;
mod manifest;
mod network;
mod protocol;
mod routing;
mod runtime;

pub use backfill::{BackfillCommand, BackfillPorts, BackfillRequest, BackfillResponse};
pub use manifest::{
    ForcedRecoveryConfig, ForcedRecoveryState, LeadershipSchedule, LeadershipState,
    ManifestAddress, ManifestError, ManifestNode, Role, ZoneManifest,
};
pub use network::{MAX_TRANSACTION_MESSAGE_SIZE, P2pNetworkId};
pub use protocol::{EncodedBlock, PeerTip};
pub use routing::P2pPeerId;
pub use runtime::{P2pCommand, P2pConfig, P2pEvent, P2pHandle, P2pHandleParts, spawn_p2p};
