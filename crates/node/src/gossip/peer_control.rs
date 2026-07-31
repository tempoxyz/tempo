//! Peer control for `tempo/1`.
//!
//! The consensus layer decides when a peer has misbehaved because it has the
//! epoch scheme and certificate. Reth's network handle applies the penalty or
//! disconnect. This trait lets consensus tests run without a full node.

use reth_ethereum::network::api::{PeerId, Peers, ReputationChangeKind};

/// Applies reputation and connection changes to a peer.
pub trait PeerControl: Send + Sync + 'static {
    /// Penalizes a peer for a malformed frame or a certificate that fails
    /// verification with an available scheme.
    fn penalize(&self, peer: PeerId);

    /// Disconnects a peer after repeated bad messages.
    fn disconnect(&self, peer: PeerId);
}

impl<N: Peers + Send + Sync + 'static> PeerControl for N {
    fn penalize(&self, peer: PeerId) {
        self.reputation_change(peer, ReputationChangeKind::BadMessage);
    }

    fn disconnect(&self, peer: PeerId) {
        self.disconnect_peer(peer);
    }
}

/// A no-op implementation for tests and nodes that do not ingest gossip.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPeerControl;

impl PeerControl for NoPeerControl {
    fn penalize(&self, _peer: PeerId) {}

    fn disconnect(&self, _peer: PeerId) {}
}
