//! Tracks active peers and consists of an [`Actor`] and a [`Mailbox`].
//!
//! The actor is configured via [`Config`] passed to the [`init`] function.
//!
//! Other parts of the system interact with the actor through its [`Mailbox`],
//! which implements [`AddressableManager`], [`commonware_p2p::Provider`], and
//! [`commonware_consensus::Reporter`] to receive
//! [`commonware_consensus::marshal::Update`] from the marshal actor.
//!
//! *NOTE*: Messages from the marshal actor are currently ignored (or, in the case
//! of blocks), silently acknowledged. In the future, this actor will read peers
//! directly from the execution layer after every finalized block.
//!
//! # Implementation details
//!
//! This actor contains a p2p oracle, for example
//! [`commonware_p2p::authenticated::lookup::Oracle`], to interact with the
//! consensus layer p2p stack, and to serve as the single source of truth for
//! peers.

use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::AddressableManager;
use futures::channel::mpsc;
use tempo_node::TempoFullNode;

mod actor;
mod ingress;

pub(crate) use actor::Actor;
pub(crate) use ingress::Mailbox;

pub(crate) struct Config<TOracle> {
    pub(crate) oracle: TOracle,
    pub(crate) execution_node: TempoFullNode,
}

pub(crate) fn init<TPeerManager>(
    Config {
        oracle,
        execution_node,
    }: Config<TPeerManager>,
) -> (Actor<TPeerManager>, Mailbox)
where
    TPeerManager: AddressableManager<PublicKey = PublicKey>,
{
    let (tx, rx) = mpsc::unbounded();
    let actor = Actor::new(oracle, execution_node, rx);
    let mailbox = Mailbox::new(tx);
    (actor, mailbox)
}
