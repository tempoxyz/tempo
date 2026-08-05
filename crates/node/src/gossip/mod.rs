//! The `tempo/1` RLPx subprotocol for gossiping consensus finalization
//! certificates between Tempo nodes.
//!
//! A follower uses this protocol if its upstream RPC server is unavailable. It
//! can receive a certified tip from an `eth` peer, verify the certificate with
//! the threshold key for that epoch, and update its execution layer.
//!
//! This module contains the code that must live next to reth: the frame format,
//! the streams polled by reth's session manager, and the coordinator that hides
//! transient duplicate connections behind one logical peer. The transport
//! enforces byte-level guards and a per-connection rate limit. Consensus handles
//! frame coalescing, peer fairness, verification limits, and certificate
//! verification. The transport does not inspect certificate payloads because
//! the consensus crate already depends on the node crate. The dependency cannot
//! point in both directions.

pub mod peer_control;
pub mod transport;
pub mod wire;

pub use peer_control::{NoPeerControl, PeerControl};
pub use transport::{
    Config, Frame, GossipProtocolHandler, PeerEvent, TransportHandle, TransportSender, init,
};
