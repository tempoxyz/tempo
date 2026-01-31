//! P2P networking abstractions for consensus.
//!
//! This module provides [`P2pNetwork`], a trait that abstracts the differences
//! between production (`lookup`) and test (`simulated`) network setups.

mod builder;
mod channels;
mod network;

pub use builder::TempoNetworkBuilder;
pub use channels::{Channels, CHANNEL_CONFIGS};
pub use network::TempoNetwork;

use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::{Address, Blocker, Receiver, Sender};
use commonware_utils::ordered::Map;

/// Abstraction over P2P network for consensus setup.
///
/// This trait allows consensus engine setup to be generic over the network
/// implementation - production uses `lookup::Network` while tests use
/// `simulated::Oracle`.
pub trait P2pNetwork {
    /// The blocker type for blocking misbehaving peers.
    type Blocker: Blocker<PublicKey = PublicKey> + Clone;

    /// The peer manager type.
    type PeerManager: commonware_p2p::Manager<PublicKey = PublicKey, Peers = Map<PublicKey, Address>>
        + Sync
        + Clone;

    /// Channel sender type.
    type Sender: Sender<PublicKey = PublicKey>;

    /// Channel receiver type.
    type Receiver: Receiver<PublicKey = PublicKey>;

    /// Returns a clone of the blocker.
    fn blocker(&self) -> Self::Blocker;

    /// Returns a clone of the peer manager.
    fn peer_manager(&self) -> Self::PeerManager;

    /// Registers all consensus channels.
    fn register_channels(
        &mut self,
    ) -> impl std::future::Future<Output = eyre::Result<Channels<Self::Sender, Self::Receiver>>>
           + Send;
}
