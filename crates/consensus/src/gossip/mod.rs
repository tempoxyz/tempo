//! Consensus-side half of the `tempo/1` subprotocol.
//!
//! The transport in `tempo-node` treats frame payloads as opaque and presents a
//! logical peer lifecycle. Consensus decides what each frame means. This module
//! defines the types shared by the transport-facing actor and follower driver.
//! In follow mode, the actor delegates inbound certificate verification to the
//! driver. Validator instances are publish-only.

use std::{future::Future, num::NonZeroU32};

pub(crate) mod actor;
mod ingress;
mod metrics;
#[cfg(test)]
mod test;

pub(crate) use actor::Actor;
pub(crate) use ingress::Mailbox;

use commonware_consensus::{
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization},
    types::{Epoch, Height},
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_runtime::{Clock, Metrics as RuntimeMetrics, Spawner};
use tokio::sync::oneshot;

use crate::consensus::Digest;

/// Transport and policy settings for certificate gossip.
pub struct Config {
    /// The consensus layer's end of the `tempo/1` transport.
    pub transport: tempo_node::gossip::TransportHandle,
    /// Maximum inbound certificate judgements per second across all peers.
    pub verify_rate: NonZeroU32,
}

pub(crate) fn init<TContext, K, P, M>(
    context: TContext,
    config: actor::Config<K, P, M>,
) -> (Actor<TContext, K, P, M>, Mailbox)
where
    TContext: Clock + RuntimeMetrics + Spawner,
{
    let (mailbox, receiver) = ingress::channel();
    let actor = actor::init(context, config, receiver);
    (actor, mailbox)
}

pub(crate) type NetworkPeerControl = reth_ethereum::network::NetworkHandle<
    reth_ethereum::network::primitives::BasicNetworkPrimitives<
        tempo_primitives::TempoPrimitives,
        tempo_primitives::TempoTxEnvelope,
    >,
>;

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
        /// Certificate epoch, used to retry after its boundary is processed.
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
