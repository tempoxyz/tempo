use std::{future::Future, num::NonZeroUsize, pin::Pin, sync::Arc};

use commonware_consensus::{
    marshal::core::DigestFallback,
    types::{Epoch, FixedEpocher, Height},
};
use commonware_cryptography::{
    bls12381::primitives::{group::Share, sharing::Sharing, variant::MinSig},
    ed25519::{PrivateKey, PublicKey},
};
use commonware_runtime::{
    BufferPooler, Clock, Metrics, Spawner, Storage, telemetry::metrics::histogram::Timed,
};
use commonware_utils::ordered;
use eyre::{Report, WrapErr as _};
use futures::{Stream, channel::mpsc};
use rand_core::CryptoRng;
use tempo_node::TempoFullNode;
use tempo_precompiles::validator_config_v2::ValidatorConfigV2;
use tempo_primitives::TempoHeader;
use tracing::Level;

mod actor;
mod ingress;

pub(crate) use actor::Actor;
pub(crate) use ingress::Mailbox;

use crate::{
    consensus::{Block, Digest},
    validators::{read_active_and_known_peers_at_block_hash, read_validator_config_at_block_hash},
};

use ingress::{Command, Message};

pub(crate) async fn init<TContext, TExecutionLayer, TMarshal, TEpochManager>(
    context: TContext,
    config: Config<TExecutionLayer, TMarshal, TEpochManager>,
) -> eyre::Result<(
    Actor<TContext, TExecutionLayer, TMarshal, TEpochManager>,
    Mailbox,
)>
where
    TContext: BufferPooler + Clock + CryptoRng + Metrics + Spawner + Storage,
    TExecutionLayer: ExecutionLayer,
    TMarshal: Marshal,
    TEpochManager: EpochManager,
{
    let (tx, rx) = mpsc::unbounded();

    let actor = Actor::new(config, context, rx)
        .await
        .wrap_err("failed initializing actor")?;
    let mailbox = Mailbox::new(tx);
    Ok((actor, mailbox))
}

pub(crate) struct Config<TExecutionLayer, TMarshal, TEpochManager> {
    pub(crate) epoch_strategy: FixedEpocher,

    pub(crate) epoch_manager: TEpochManager,

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
/// public polynomial. During normal operation, they provide the validator
/// configuration used at the end of each epoch.
pub(crate) trait ExecutionLayer: Clone + Send + Sync + 'static {
    /// Returns a finalized header at `height`, or `None` when execution has not finalized it.
    fn finalized_header(&self, height: Height) -> eyre::Result<Option<TempoHeader>>;

    /// Determines the validator set selected for the epoch after the block
    /// identified by `digest`.
    ///
    /// This is used while constructing or verifying a proposal, so `digest`
    /// must identify that proposal's parent. If the corresponding execution
    /// state is unavailable, the proposal cannot be constructed or verified.
    fn next_players(&self, digest: Digest) -> eyre::Result<ordered::Set<PublicKey>>;

    /// Reads the epoch scheduled for the next full DKG ceremony from the
    /// validator configuration at `digest`.
    ///
    /// This determines whether the next ceremony creates a new polynomial
    /// instead of resharing the current one. It is used while constructing or
    /// verifying a proposal, so `digest` must identify that proposal's parent.
    /// If the corresponding execution state is unavailable, the proposal
    /// cannot be constructed or verified.
    fn next_full_dkg_epoch(&self, digest: Digest) -> eyre::Result<u64>;
}

/// Marshal operations used by the DKG manager.
pub(crate) trait Marshal: Clone + Send + Sync + 'static {
    /// Stream of blocks from a requested tip through its ancestry.
    type Ancestry: Stream<Item = Arc<Block>> + Send + Unpin + 'static;

    /// Makes a best-effort attempt to retrieve `height` from local storage.
    ///
    /// This lookup does not fetch the block from the network.
    fn get_block(&self, height: Height) -> impl Future<Output = Option<Block>> + Send;

    /// Returns a stream over the ancestry of the block identified by `start`.
    ///
    /// The fallback controls how the starting block is obtained, and the
    /// supplied timer records the latency of any missing-parent fetches.
    /// Returns `None` when the starting block cannot be found.
    fn ancestry<C>(
        &self,
        clock: Arc<C>,
        start: (DigestFallback, Digest),
        fetch_duration: Timed,
    ) -> impl Future<Output = Option<Self::Ancestry>> + Send
    where
        C: Clock;
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

impl ExecutionLayer for Arc<TempoFullNode> {
    fn finalized_header(&self, height: Height) -> eyre::Result<Option<TempoHeader>> {
        use reth_provider::HeaderProvider as _;

        let finalized = self
            .provider
            .canonical_in_memory_state()
            .get_finalized_num_hash()
            .map_or_else(Height::zero, |num_hash| Height::new(num_hash.number));

        if height > finalized {
            return Ok(None);
        }

        self.provider
            .header_by_number(height.get())
            .map_err(Report::new)
    }

    #[tracing::instrument(skip_all, fields(%digest), err(level = Level::WARN))]
    fn next_players(&self, digest: Digest) -> eyre::Result<ordered::Set<PublicKey>> {
        let next_players = read_active_and_known_peers_at_block_hash(
            self.as_ref(),
            &ordered::Set::default(),
            digest.0,
        )
        .wrap_err("failed reading peers from validator config v2")?
        .into_keys();

        tracing::debug!(?next_players, "determined next players");
        Ok(next_players)
    }

    #[tracing::instrument(
        skip_all,
        fields(%digest),
        err(level = Level::WARN),
        ret
    )]
    fn next_full_dkg_epoch(&self, digest: Digest) -> eyre::Result<u64> {
        read_validator_config_at_block_hash(
            self.as_ref(),
            digest.0,
            |config: &ValidatorConfigV2| {
                config
                    .get_next_network_identity_rotation_epoch()
                    .map_err(Report::new)
            },
        )
        .map(|(_, _, epoch)| epoch)
    }
}

impl Marshal for crate::alias::marshal::Mailbox {
    type Ancestry = Pin<Box<dyn Stream<Item = Arc<Block>> + Send>>;

    fn get_block(&self, height: Height) -> impl Future<Output = Option<Block>> + Send {
        let mailbox = self.clone();
        async move { mailbox.get_block(height).await }
    }

    fn ancestry<C>(
        &self,
        clock: Arc<C>,
        start: (DigestFallback, Digest),
        fetch_duration: Timed,
    ) -> impl Future<Output = Option<Self::Ancestry>> + Send
    where
        C: Clock,
    {
        let mailbox = self.clone();
        async move {
            mailbox
                .ancestry(clock, start, fetch_duration)
                .await
                .map(|stream| Box::pin(stream) as Self::Ancestry)
        }
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
