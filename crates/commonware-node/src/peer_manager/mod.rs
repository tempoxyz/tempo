//! Tracks active peers and consists of an [`Actor`] and a [`Mailbox`].
//!
//! This actor acts as a layer on top of the commonware p2p network actor. It
//! reads chain state to determine who this node should peer with, and registers
//! these peers with the P2P actor.
//!
//! The actor is configured via [`Config`] passed to the [`init`] function.
//!
//! Other parts of the system interact with the actor through its [`Mailbox`],
//! which implements [`AddressableManager`], [`commonware_p2p::Provider`], and
//! [`commonware_consensus::Reporter`] to receive
//! [`commonware_consensus::marshal::Update`] from the marshal actor.
//!
//! # How peers are determined
//!
//! The set of peers is the union of two subsets:
//!
//! 1. Those entries in the Validator Config contract that have a field
//!    `active == true`.
//! 2. The dealers and players as per the last DKG outcome.
//!
//! Because DKG ceremonies can fail, it happens that the DKG outcome contains
//! validators that contain `active == false` in the contract. Therefore, the
//! actor reads all entries in the contract to look up the egress and ingress
//! addresses of the validators (active and inactive), before constructing an
//! overall peer set `{dealers, players, active validators}` together with
//! addresses.

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

use crate::executor;

/// Configuration of the peer manager actor.
pub(crate) struct Config<TOracle> {
    /// The mailbox to the P2P network to register the peer sets.
    pub(crate) oracle: TOracle,
    /// A handle to the full execution node to read block headers and look up
    /// the Validator Config contract
    pub(crate) execution_node: TempoFullNode,
    /// The mailbox to the executor actor. Used to check if the executor has
    /// already finalized a block at a given height.
    pub(crate) executor: executor::Mailbox,
    /// The  epoch strategy used by the node.
    pub(crate) epoch_strategy: FixedEpocher,
    /// The last finalized height according to the consensus layer (marshal).
    /// Used during start to determine the correct boundary block, since
    /// the execution layer may be behind.
    pub(crate) last_finalized_height: Height,
}

/// Initializes a peer manager actor from a `config` with runtime `context`.
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
