//! Consensus-side half of the `tempo/1` subprotocol.
//!
//! The transport in `tempo-node` treats frame payloads as opaque and presents a
//! logical peer lifecycle. Consensus decides what each frame means. This module
//! defines the types shared by the transport-facing actor and follower driver.
//! The driver owns the epoch schemes, so only the driver can verify a
//! certificate.

#![allow(
    dead_code,
    unused_imports,
    reason = "production wiring is added by the following stack layer"
)]

use std::future::Future;

mod actor;
mod ingress;
mod metrics;
#[cfg(test)]
mod test;

pub(crate) use actor::{Actor, Config, init};
#[cfg(test)]
pub(crate) use ingress::Message;
pub(crate) use ingress::{Mailbox, channel};

use commonware_consensus::{
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization},
    types::{Epoch, Height},
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use tokio::sync::oneshot;

use crate::consensus::Digest;

/// A finalization certificate as it travels over `tempo/1`.
pub(crate) type Certificate = Finalization<Scheme<PublicKey, MinSig>, Digest>;

/// Persisted certificate lookup used when marshal announces a finalized tip.
pub(crate) trait Marshal: Clone + Send + Sync + 'static {
    fn get_finalization(&self, height: Height) -> impl Future<Output = Option<Certificate>> + Send;
}

impl Marshal for crate::alias::marshal::Mailbox {
    fn get_finalization(&self, height: Height) -> impl Future<Output = Option<Certificate>> + Send {
        let mailbox = self.clone();
        async move { mailbox.get_finalization(height).await }
    }
}

/// A certificate the driver could not settle normally.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CertificateError {
    /// The signature failed with an available scheme, so the sender is
    /// responsible.
    #[error("certificate failed verification")]
    Invalid,
    /// No authenticated epoch scheme can currently verify the certificate.
    ///
    /// Do not blame the sender. The network-identity fallback can reject an
    /// honest certificate after an identity rotation but before this node learns
    /// the new key from an authenticated boundary.
    #[error("certificate requires a scheme for epoch {epoch}")]
    NeedsScheme {
        /// Certificate epoch, used to retry after a boundary installs its scheme or a later one.
        epoch: Epoch,
    },
}

/// Verifies certificates and applies them to the consensus layer.
///
/// This trait lets transport-facing actor tests use a stub instead of a driver,
/// marshal, and scheme provider.
pub(crate) trait CertificateMailbox: Clone + Send + 'static {
    /// Submits a certificate for verification.
    ///
    /// The receiver returns the mailbox's result. It can close without a value
    /// if the driver cannot judge the certificate, such as during shutdown or
    /// on a publish-only node.
    fn process_certificate(
        &self,
        certificate: Certificate,
    ) -> oneshot::Receiver<eyre::Result<(), CertificateError>>;
}

/// A certificate mailbox for nodes that publish but never ingest.
///
/// Validators use this mailbox because they receive certificates over their
/// authenticated consensus network. Their `tempo/1` transport discards inbound
/// frames, so this mailbox is not called.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PublishOnlySink;

impl CertificateMailbox for PublishOnlySink {
    fn process_certificate(
        &self,
        _certificate: Certificate,
    ) -> oneshot::Receiver<eyre::Result<(), CertificateError>> {
        let (_sender, receiver) = oneshot::channel();
        receiver
    }
}
