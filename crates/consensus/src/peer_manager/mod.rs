//! Tracks active peers and consists of an [`Actor`] and a [`Mailbox`].
//!
//! This actor acts as a layer on top of the commonware p2p network actor. It
//! reads chain state to determine who this node should peer with, and registers
//! these peers with the P2P actor.
//!
//! The actor is configured via [`Config`] passed to the [`init`] function.
//!
//! Other parts of the system interact with the actor through its [`Mailbox`],
//! which implements [`commonware_p2p::Provider`] (forwarded to the P2P actor)
//! and [`commonware_consensus::Reporter`] to receive
//! [`crate::executor::Finalized`] blocks from the executor actor.
//!
//! # How peers are determined
//!
//! Peers are read from two pieces of finalized state:
//!
//! - the DKG outcome in the header of the latest epoch boundary block at or
//!   below the highest finalized block;
//! - the Validator Config V2 contract at the highest finalized block.
//!
//! The highest finalized block is the latest one the executor reported. The
//! executor first reports the finalized block it starts from, after its
//! startup backfill, and then each block once the execution layer accepted
//! the forkchoice update finalizing it, so its state is readable by hash.
//!
//! The peer set is split into two tiers:
//!
//! 1. **Primary**: the players of the DKG outcome.
//! 2. **Secondary**: the next players of the DKG outcome and the contract's
//!    active validators, minus those already primary.
//!
//! Addresses for all peers are resolved against the contract. DKG peers that
//! are no longer active are looked up by public key; every DKG peer must have
//! a well-formed entry in the contract.
//!
//! # When peers are updated
//!
//! No peers are read before the executor's first report. Peers are read on
//! every finalized block reported by the executor, and the latest report is
//! read again every 30 seconds without a new one. A new peer set is tracked
//! under the finalized height it was read at when its membership changes;
//! when only addresses change, the existing set's addresses are overwritten.
//!
//! # Address overrides
//!
//! [`AddressOverrides`] rewrite the contract's ingress or egress address of
//! peers already in the set, on this node only. They let validators reach a
//! peer whose registered address is wrong while the chain cannot finalize the
//! transaction that fixes it. Each rewrite names the contract address it
//! replaces and applies only while the contract holds it, so it stops on its
//! own once the peer registers any other address.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    sync::Arc,
};

use commonware_consensus::types::FixedEpocher;
use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::AddressableManager;
use commonware_runtime::{Clock, Metrics, Spawner};
use futures::channel::mpsc;
use reth_provider::HeaderProvider as _;
use tempo_node::TempoFullNode;
use tempo_primitives::TempoHeader;

use crate::validators::ExecutionNode;

mod actor;
mod ingress;

pub(crate) use actor::Actor;
pub(crate) use ingress::Mailbox;

/// Configuration of the peer manager actor.
pub(crate) struct Config<TOracle, TExecutionNode> {
    /// The mailbox to the P2P network to register the peer sets.
    pub(crate) oracle: TOracle,
    /// A handle to the full execution node to read block headers and look up
    /// the Validator Config contract
    pub(crate) execution_node: Arc<TExecutionNode>,
    /// The  epoch strategy used by the node.
    pub(crate) epoch_strategy: FixedEpocher,
    /// The P2P network's maximum peer set size. The network panics on larger
    /// peer sets; a warning is logged past 2/3 of it.
    pub(crate) max_peers: NonZeroU32,
    /// Addresses that replace peers' contract entries on this node.
    pub(crate) address_overrides: AddressOverrides,
}

/// Rewrites of peers' validator config contract entries on this node only,
/// keyed by the peer's public key. A public key that is not in the peer set is
/// ignored; overrides never add peers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AddressOverrides {
    /// Rewrites the ingress address this node dials.
    pub ingress: HashMap<PublicKey, AddressRewrite<SocketAddr>>,
    /// Rewrites the egress IP this node accepts connections from.
    pub egress: HashMap<PublicKey, AddressRewrite<IpAddr>>,
}

/// Replaces a peer's contract address `from` with `to`, only while the
/// validator config contract holds exactly `from`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressRewrite<T> {
    /// The contract address this rewrite applies to.
    pub from: T,
    /// The address used instead of `from`.
    pub to: T,
}

impl<T: Copy + PartialEq> AddressRewrite<T> {
    /// Returns `to` if `contract` is `from`, and `None` for any other
    /// contract address.
    fn rewrite(&self, contract: T) -> Option<T> {
        (self.from == contract).then_some(self.to)
    }
}

/// Initializes the actor. It reads no peers until the executor reports a
/// finalized block.
pub(crate) fn init<TContext, TPeerManager, TExecutionNode>(
    context: TContext,
    config: Config<TPeerManager, TExecutionNode>,
) -> (Actor<TContext, TPeerManager, TExecutionNode>, Mailbox)
where
    TContext: Clock + Metrics + Spawner,
    TPeerManager: AddressableManager<PublicKey = PublicKey>,
    TExecutionNode: ExecutionLayer,
{
    let (tx, rx) = mpsc::unbounded();
    let actor = Actor::new(context, config, rx);
    let mailbox = Mailbox::new(tx);
    (actor, mailbox)
}

/// Execution-layer reads used to discover peers at reported finalized blocks.
pub(crate) trait ExecutionLayer: ExecutionNode + Send + Sync + 'static {
    fn header_by_number(&self, height: u64) -> eyre::Result<Option<TempoHeader>>;
}

impl ExecutionLayer for TempoFullNode {
    fn header_by_number(&self, height: u64) -> eyre::Result<Option<TempoHeader>> {
        self.provider
            .header_by_number(height)
            .map_err(eyre::Report::new)
    }
}
