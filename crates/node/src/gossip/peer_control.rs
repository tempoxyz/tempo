//! Peer control for `tempo/1`.
//!
//! Consensus decides whether a certificate is invalid because it owns the
//! epoch scheme. The transport can independently identify violations of the
//! `tempo/1` frame protocol. Reth's network handle applies both kinds of report
//! and decides when reputation warrants a ban.

use futures::future::BoxFuture;
use reth_ethereum::network::api::{PeerId, Peers, ReputationChangeKind};

/// Applies reputation changes to a peer.
pub trait PeerControl: Send + Sync + 'static {
    /// Penalizes a peer for a malformed message or a certificate that fails
    /// verification with an available scheme.
    fn penalize(&self, peer: PeerId);

    /// Reports an unambiguous protocol violation.
    ///
    /// The returned future resolves after Reth has processed the report. A
    /// transport must wait for it before closing the connection because Reth
    /// can otherwise remove an unknown inbound peer before recording the ban.
    fn protocol_breach(&self, peer: PeerId) -> BoxFuture<'_, ()>;
}

impl<N: Peers + Send + Sync + 'static> PeerControl for N {
    fn penalize(&self, peer: PeerId) {
        self.reputation_change(peer, ReputationChangeKind::BadMessage);
    }

    fn protocol_breach(&self, peer: PeerId) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            // Both requests use the same NetworkManager channel. The response
            // proves that the preceding reputation change was processed; the
            // reported reputation itself is not needed.
            self.reputation_change(peer, ReputationChangeKind::BadProtocol);
            let _ = self.reputation_by_id(peer).await;
        })
    }
}

/// A no-op implementation for tests that do not exercise reputation.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPeerControl;

impl PeerControl for NoPeerControl {
    fn penalize(&self, _peer: PeerId) {}

    fn protocol_breach(&self, _peer: PeerId) -> BoxFuture<'_, ()> {
        Box::pin(std::future::ready(()))
    }
}
