//! Tracks active peers and consists of an [`Actor`] and a [`Mailbox`].
//!
//! The actor is configured via [`Config`] passed to the [`init`] function.
//!
//! Other parts of the system interact with the actor through its [`Mailbox`],
//! which implements [`AddressableManager`], [`commonware_p2p::Provider`], and
//! [`commonware_consensus::Reporter`] to receive
//! [`commonware_consensus::marshal::Update`] from the marshal actor.
//!
//! At each boundary block, the actor reads the [`OnchainDkgOutcome`] from the
//! block header and the validator config from the execution node. It then
//! constructs and tracks the peer set for the next epoch from dealers, players,
//! and active validators.
//!
//! # Implementation details
//!
//! This actor contains a p2p oracle, for example
//! [`commonware_p2p::authenticated::lookup::Oracle`], to interact with the
//! consensus layer p2p stack, and to serve as the single source of truth for
//! peers.

use commonware_consensus::types::{FixedEpocher, Height};
use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::AddressableManager;
use commonware_runtime::{Clock, Metrics, Spawner};
use futures::channel::mpsc;
use tempo_node::TempoFullNode;

mod actor;
mod ingress;

pub(crate) use actor::Actor;
pub(crate) use ingress::Mailbox;

pub(crate) struct Config<TOracle> {
    pub(crate) oracle: TOracle,
    pub(crate) execution_node: TempoFullNode,
    pub(crate) epoch_strategy: FixedEpocher,
    /// The last finalized height according to the consensus layer (marshal).
    /// Used during start to determine the correct boundary block, since
    /// the execution layer may be behind.
    pub(crate) last_finalized_height: Height,
}

pub(crate) fn init<TContext, TPeerManager>(
    context: TContext,
    config: Config<TPeerManager>,
) -> (Actor<TContext, TPeerManager>, Mailbox)
where
    TContext: Clock + Metrics + Spawner,
    TPeerManager: AddressableManager<PublicKey = PublicKey>,
{
    let (tx, rx) = mpsc::unbounded();
    let actor = Actor::new(context, config, rx);
    let mailbox = Mailbox::new(tx);
    (actor, mailbox)
}
