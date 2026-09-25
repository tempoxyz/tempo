use std::{future::Future, num::NonZeroUsize, sync::Arc};

use commonware_consensus::{
    marshal::core::DigestFallback,
    types::{Epoch, FixedEpocher, Height},
};
use commonware_cryptography::{
    bls12381::primitives::{group::Share, sharing::Sharing, variant::MinSig},
    ed25519::{PrivateKey, PublicKey},
};
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage};
use commonware_utils::ordered;
use eyre::{Report, WrapErr as _};
use futures::channel::mpsc;
use rand_core::CryptoRng;
use tempo_chainspec::{NetworkIdentity, TempoChainSpec};
use tempo_node::TempoFullNode;
use tempo_primitives::TempoHeader;
use tokio::sync::oneshot;

mod actor;
mod ingress;

pub(crate) use actor::Actor;
pub(crate) use ingress::Mailbox;

use crate::{
    consensus::{Block, Digest},
    epoch::SchemeProvider,
    gossip::Certificate,
};

use ingress::{Command, Message};

/// Authenticates the startup tip and registers its trusted identity before returning the actor.
pub(crate) async fn init<TContext, TExecutionLayer, TMarshal>(
    context: TContext,
    config: Config<TExecutionLayer, TMarshal>,
) -> eyre::Result<(Actor<TContext, TExecutionLayer, TMarshal>, Mailbox)>
where
    TContext: BufferPooler + Clock + CryptoRng + Metrics + Spawner + Storage,
    TExecutionLayer: ExecutionLayer,
    TMarshal: Marshal,
{
    let (tx, rx) = mpsc::unbounded();

    let actor = Actor::new(config, context, rx)
        .await
        .wrap_err("failed initializing actor")?;
    let mailbox = Mailbox::new(tx);
    Ok((actor, mailbox))
}

pub(crate) struct Config<TExecutionLayer, TMarshal> {
    pub(crate) epoch_strategy: FixedEpocher,

    /// The namespace the dkg manager will use when sending messages during
    /// a dkg ceremony.
    pub(crate) namespace: Vec<u8>,

    pub(crate) me: PrivateKey,

    pub(crate) mailbox_size: NonZeroUsize,

    /// The mailbox to the marshal actor. Used to determine if an epoch
    /// can be started at startup.
    pub(crate) marshal: TMarshal,

    /// The finalized floor reported by marshal at startup. Used to choose the
    /// boundary block that seeds the initial DKG state.
    pub(crate) last_finalized_height: Height,

    /// Archive height and certificate to authenticate during initialization.
    /// `None` only at genesis.
    pub(crate) finalized_tip: Option<(Height, Certificate)>,

    /// Trusted identity supplied by the binary or its explicit configuration.
    pub(crate) network_identity: NetworkIdentity,

    /// Registers the trusted identity during initialization, before any actor starts.
    pub(crate) scheme_provider: SchemeProvider,

    /// The partition prefix to use when persisting ceremony metadata during
    /// rounds.
    pub(crate) partition_prefix: String,

    /// Execution-layer state used to initialize DKG and determine future ceremonies.
    pub(crate) execution_node: TExecutionLayer,

    /// This node's initial share of the bls12381 private key.
    pub(crate) initial_share: Option<Share>,
}

/// Execution-layer reads used by the DKG manager.
///
/// During initialization, these reads provide the initial validator set and
/// public polynomial.
pub(crate) trait ExecutionLayer: Clone + Send + Sync + 'static {
    /// Chain specification used to select the ceremony transcript version.
    fn chain_spec(&self) -> Arc<TempoChainSpec>;

    /// Returns a finalized header at `height`, or `None` when execution has not finalized it.
    fn finalized_header(&self, height: Height) -> eyre::Result<Option<TempoHeader>>;
}

/// Marshal operations used by the DKG manager.
pub(crate) trait Marshal: Clone + Send + Sync + 'static {
    /// Makes a best-effort attempt to retrieve `height` from local storage.
    ///
    /// This lookup does not fetch the block from the network.
    fn get_block(&self, height: Height) -> impl Future<Output = Option<Block>> + Send;

    /// Subscribes to a block, optionally fetching it from peers.
    /// Dropping the receiver cancels the subscription.
    fn subscribe_by_digest(
        &self,
        digest: Digest,
        fallback: DigestFallback,
    ) -> oneshot::Receiver<Arc<Block>>;
}

/// Epoch transitions emitted by the DKG manager.
pub(crate) trait EpochManager: Send + Sync + 'static {
    /// Starts consensus for `epoch` with the DKG output and participant set.
    ///
    /// A present `share` makes the local validator a signer; without one, it
    /// enters the epoch as a verifier.
    fn enter(
        &mut self,
        epoch: Epoch,
        public: Sharing<MinSig>,
        share: Option<Share>,
        participants: ordered::Set<PublicKey>,
    ) -> eyre::Result<()>;

    /// Stops the consensus engine for `epoch`.
    fn exit(&mut self, epoch: Epoch) -> eyre::Result<()>;
}

/// The execution node that the DKG manager reads from in production.
#[derive(Clone)]
pub(crate) struct TempoExecutionLayer {
    pub(crate) node: Arc<TempoFullNode>,
}

impl ExecutionLayer for TempoExecutionLayer {
    fn chain_spec(&self) -> Arc<TempoChainSpec> {
        self.node.chain_spec()
    }

    fn finalized_header(&self, height: Height) -> eyre::Result<Option<TempoHeader>> {
        use reth_provider::HeaderProvider as _;

        let finalized = self
            .node
            .provider
            .canonical_in_memory_state()
            .get_finalized_num_hash()
            .map_or_else(Height::zero, |num_hash| Height::new(num_hash.number));

        if height > finalized {
            return Ok(None);
        }

        self.node
            .provider
            .header_by_number(height.get())
            .map_err(Report::new)
    }
}

impl Marshal for crate::alias::marshal::Mailbox {
    fn get_block(&self, height: Height) -> impl Future<Output = Option<Block>> + Send {
        let mailbox = self.clone();
        async move { mailbox.get_block(height).await }
    }

    fn subscribe_by_digest(
        &self,
        digest: Digest,
        fallback: DigestFallback,
    ) -> oneshot::Receiver<Arc<Block>> {
        Self::subscribe_by_digest(self, digest, fallback)
    }
}

impl EpochManager for crate::epoch::manager::Mailbox {
    fn enter(
        &mut self,
        epoch: Epoch,
        public: Sharing<MinSig>,
        share: Option<Share>,
        participants: ordered::Set<PublicKey>,
    ) -> eyre::Result<()> {
        Self::enter(self, epoch, public, share, participants)
    }

    fn exit(&mut self, epoch: Epoch) -> eyre::Result<()> {
        Self::exit(self, epoch)
    }
}
