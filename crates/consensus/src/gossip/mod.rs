//! Consensus-side half of the `tempo/1` subprotocol.
//!
//! The transport in `tempo-node` only moves bytes. Consensus decides what each
//! frame means. This module defines the types shared by the transport-facing
//! actor and follower driver. The driver owns the epoch schemes, so only the
//! driver can verify a certificate.

use commonware_consensus::{
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization},
    types::Epoch,
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use tokio::sync::oneshot;

use crate::consensus::Digest;

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
    /// The signature failed with an available scheme, so the sender is responsible.
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
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "wired to the gossip actor in a following commit")
)]
pub(crate) trait CertSink: Clone + Send + 'static {
    /// Submits a certificate for verification.
    ///
    /// The receiver returns the driver's result. It closes without a value if
    /// the driver is shutting down.
    fn verify_and_apply(&self, certificate: Certificate) -> oneshot::Receiver<Outcome>;
}
