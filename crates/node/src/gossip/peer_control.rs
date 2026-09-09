//! Peer control for `tempo/1`.
//!
//! Consensus decides whether a certificate is invalid because it owns the
//! epoch scheme. Reth's network handle applies the report and decides when
//! reputation warrants a ban.

use reth_ethereum::network::api::{PeerId, Peers, ReputationChangeKind};

/// Applies reputation changes to a peer.
pub trait PeerControl: Send + Sync + 'static {
    /// Penalizes a peer for a malformed message or a certificate that fails
    /// verification with an available scheme.
    fn penalize(&self, peer: PeerId);
}

impl<N: Peers + Send + Sync + 'static> PeerControl for N {
    fn penalize(&self, peer: PeerId) {
        self.reputation_change(peer, ReputationChangeKind::BadMessage);
    }
}

/// A no-op implementation for tests that do not exercise reputation.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPeerControl;

impl PeerControl for NoPeerControl {
    fn penalize(&self, _peer: PeerId) {}
}
