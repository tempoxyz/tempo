//! Consensus-side half of the `tempo/1` subprotocol.
//!
//! The transport in `tempo-node` treats frame payloads as opaque and presents a
//! logical peer lifecycle. Consensus decides what each frame means. This module
//! defines the types shared by the transport-facing actor and follower driver.
//! The driver owns the epoch schemes, so only the driver can verify a
//! certificate.

mod actor;
mod ingress;
mod metrics;
#[cfg(test)]
mod test;

pub(crate) use actor::{Actor, Config as ActorConfig, init};
pub(crate) use ingress::{Mailbox, channel};

use commonware_consensus::{
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization},
    types::Epoch,
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use tokio::sync::oneshot;

use crate::consensus::Digest;

/// Transport and policy settings for certificate gossip.
pub struct Config {
    /// The consensus layer's end of the `tempo/1` transport.
    pub transport: tempo_node::gossip::TransportHandle,
    /// Maximum driver judgements per second across all peers.
    pub verify_rate: u32,
    /// Frames remembered as already settled or published.
    pub recent_frames: usize,
    /// Whether to forward certificates verified from a peer.
    pub relay: bool,
}

/// A finalization certificate as it travels over `tempo/1`.
pub(crate) type Certificate = Finalization<Scheme<PublicKey, MinSig>, Digest>;

/// Result of asking the driver to verify and apply a certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Verified and sent to marshal.
    ///
    /// Marshal still must fetch and store the block. `Admitted` does not mean
    /// the finalization is stored.
    Admitted,
    /// At or below the highest round already applied.
    Stale,
    /// The signature failed with an available scheme, so the sender is
    /// responsible.
    Invalid,
    /// No authenticated epoch scheme can currently verify the certificate.
    ///
    /// Do not blame the sender. The network-identity fallback can reject an
    /// honest certificate after an identity rotation but before this node learns
    /// the new key from an authenticated boundary.
    NeedsScheme {
        /// Certificate epoch, used to retry after a boundary installs its scheme or a later one.
        epoch: Epoch,
    },
}

/// Verifies certificates and applies them to the consensus layer.
///
/// This trait lets transport-facing actor tests use a stub instead of a driver,
/// marshal, and scheme provider.
pub(crate) trait CertSink: Clone + Send + 'static {
    /// Submits a certificate for verification.
    ///
    /// The receiver returns the sink's result. It can close without a value if
    /// the sink cannot judge the certificate, such as during shutdown or on a
    /// publish-only node.
    fn verify_and_apply(&self, certificate: Certificate) -> oneshot::Receiver<Outcome>;
}

/// A sink for nodes that publish but never ingest.
///
/// Validators use this sink because they receive certificates over their
/// authenticated consensus network. Their `tempo/1` transport discards inbound
/// frames, so this sink is not called.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PublishOnlySink;

impl CertSink for PublishOnlySink {
    fn verify_and_apply(&self, _certificate: Certificate) -> oneshot::Receiver<Outcome> {
        let (_sender, receiver) = oneshot::channel();
        receiver
    }
}
