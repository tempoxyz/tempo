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
//! [`commonware_consensus::marshal::Update`] from the marshal actor.
//!
//! # How peers are determined
//!
//! Peers are read from two pieces of finalized state:
//!
//! - the DKG outcome in the header of the latest epoch boundary block at or
//!   below the highest finalized height;
//! - the Validator Config V2 contract at the highest finalized height.
//!
//! The highest finalized height is the execution layer's finalized block,
//! capped by the latest finalized tip consensus has observed.
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
//! [`init`] registers the first peer set from execution state, before marshal
//! or the executor start, because DKG may need these peers to recover the tip.
//! After that, peers are re-read on every finalized block or tip reported by
//! marshal and every 30 seconds otherwise. A new peer set is tracked under the
//! finalized height it was read at when its membership changes; when only
//! addresses change, the existing set's addresses are overwritten.

use std::sync::Arc;

use commonware_consensus::types::{FixedEpocher, Height};
use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::AddressableManager;
use commonware_runtime::{Clock, Metrics, Spawner};
use futures::channel::mpsc;
use reth_provider::{BlockIdReader as _, HeaderProvider as _};
use tempo_node::TempoFullNode;
use tempo_primitives::TempoHeader;

use crate::{consensus::Digest, validators::ExecutionNode};

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
    /// Highest finalized tip observed from consensus at startup.
    /// Execution-layer-derived reads must not advance beyond this tip until
    /// marshal reports a newer finalized tip.
    pub(crate) finalized_tip: (Height, Digest),
}

/// Initializes the actor and registers its first peers from available execution
/// state, before marshal or executor startup can depend on those peers.
pub(crate) fn init<TContext, TPeerManager, TExecutionNode>(
    context: TContext,
    config: Config<TPeerManager, TExecutionNode>,
) -> eyre::Result<(Actor<TContext, TPeerManager, TExecutionNode>, Mailbox)>
where
    TContext: Clock + Metrics + Spawner,
    TPeerManager: AddressableManager<PublicKey = PublicKey>,
    TExecutionNode: ExecutionLayer,
{
    let (tx, rx) = mpsc::unbounded();
    let actor = Actor::new(context, config, rx)?;
    let mailbox = Mailbox::new(tx);
    Ok((actor, mailbox))
}

/// Execution-layer reads used to discover peers without waiting for consensus replay.
pub(crate) trait ExecutionLayer: ExecutionNode + Send + Sync + 'static {
    fn finalized_block_number(&self) -> eyre::Result<Option<u64>>;
    fn header_by_number(&self, height: u64) -> eyre::Result<Option<TempoHeader>>;
}

impl ExecutionLayer for TempoFullNode {
    fn finalized_block_number(&self) -> eyre::Result<Option<u64>> {
        self.provider
            .finalized_block_number()
            .map_err(eyre::Report::new)
    }

    fn header_by_number(&self, height: u64) -> eyre::Result<Option<TempoHeader>> {
        self.provider
            .header_by_number(height)
            .map_err(eyre::Report::new)
    }
}
