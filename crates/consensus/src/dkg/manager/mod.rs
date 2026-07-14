use std::sync::Arc;

use alloy_primitives::B256;
use commonware_consensus::{
    marshal,
    types::{FixedEpocher, Height},
};
use commonware_cryptography::{
    bls12381::primitives::group::Share,
    ed25519::{PrivateKey, PublicKey},
};
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage};
use commonware_utils::ordered;
use eyre::WrapErr as _;
use futures::{Stream, channel::mpsc};
use rand_core::CryptoRngCore;
use reth_provider::HeaderProvider as _;
use tempo_node::TempoFullNode;
use tempo_precompiles::validator_config_v2::ValidatorConfigV2;
use tempo_primitives::TempoHeader;
use tracing::{Level, debug, instrument, warn};

mod actor;
mod ingress;

pub(crate) use actor::Actor;
pub(crate) use ingress::Mailbox;

use crate::{
    consensus::{Digest, block::Block},
    epoch,
    validators::{read_active_and_known_peers_at_block_hash, read_validator_config_at_block_hash},
};

use ingress::{Command, Message};

pub(crate) async fn init<TContext, TChain>(
    context: TContext,
    config: Config<TChain>,
) -> eyre::Result<(Actor<TContext, TChain>, Mailbox)>
where
    TContext: BufferPooler + Clock + CryptoRngCore + Metrics + Spawner + Storage,
    TChain: ChainView,
{
    let (tx, rx) = mpsc::unbounded();

    let actor = Actor::new(config, context, rx)
        .await
        .wrap_err("failed initializing actor")?;
    let mailbox = Mailbox::new(tx);
    Ok((actor, mailbox))
}

/// Narrow view of the chain that the DKG manager needs: finalized headers,
/// notarized ancestry, and validator-config state at a block hash.
///
/// Exists to make unit testing easier. [`FullNodeChainView`] is used in
/// production.
pub(crate) trait ChainView: Clone + Send + Sync + 'static {
    /// The stream returned by [`Self::ancestry`].
    type Ancestry: Stream<Item = Block> + Send + Unpin;

    /// Returns the header of the finalized block at `height`.
    ///
    /// Errors if no source has a finalized block at that height.
    fn finalized_header(
        &self,
        height: Height,
    ) -> impl Future<Output = eyre::Result<TempoHeader>> + Send;

    /// Returns a stream over the notarized ancestry of the block identified
    /// by `digest`, starting at that block and walking towards genesis.
    ///
    /// Returns `None` if the block is not available.
    fn ancestry(&self, digest: Digest) -> impl Future<Output = Option<Self::Ancestry>> + Send;

    /// Reads the epoch at which the next full DKG ceremony (network identity
    /// rotation) is scheduled from the validator config at `digest`.
    ///
    /// This should only be used when constructing or verifying a proposal.
    /// `digest` should therefore always refer to the parent of the proposal.
    fn re_dkg_epoch(&self, digest: Digest) -> eyre::Result<u64>;

    /// Reads the next set of DKG players from the validator config at `hash`.
    fn next_players(&self, hash: B256) -> eyre::Result<ordered::Set<PublicKey>>;
}

/// Production [`ChainView`] backed by the full execution-layer node and the
/// marshal actor.
#[derive(Clone)]
pub(crate) struct FullNodeChainView {
    /// The full execution layer node. On init, used to read the initial set
    /// of peers and public polynomial.
    ///
    /// During normal operation, used to read the validator config at the end
    /// of each epoch.
    pub(crate) execution_node: Arc<TempoFullNode>,

    /// The mailbox to the marshal actor. Used to read finalized headers that
    /// the execution layer does not have and to stream notarized ancestry.
    pub(crate) marshal: crate::alias::marshal::Mailbox,
}

impl ChainView for FullNodeChainView {
    type Ancestry = marshal::ancestry::AncestorStream<crate::alias::marshal::Mailbox, Block>;

    #[instrument(skip_all, fields(%height))]
    async fn finalized_header(&self, height: Height) -> eyre::Result<TempoHeader> {
        let execution_finalized_watermark = self
            .execution_node
            .provider
            .canonical_in_memory_state()
            .get_finalized_num_hash()
            .map_or_else(Height::zero, |num_hash| Height::new(num_hash.number));

        if height <= execution_finalized_watermark {
            match self.execution_node.provider.header_by_number(height.get()) {
                Ok(Some(header)) => return Ok(header),
                Ok(None) => {
                    warn!(%height, "execution layer reported it had no header for DKG initial state");
                }
                Err(error) => {
                    warn!(
                        error = %eyre::Report::new(error),
                        %height,
                        "failed to read finalized header from execution layer for DKG initial state"
                    );
                }
            };
        }

        if let Some(block) = self.marshal.get_block(height).await {
            return Ok(block.header().clone());
        }

        eyre::bail!("could not find header for finalized block at `{height}`");
    }

    async fn ancestry(&self, digest: Digest) -> Option<Self::Ancestry> {
        self.marshal.ancestry((None, digest)).await
    }

    #[instrument(
        skip_all,
        fields(
            %digest,
        ),
        err(level = Level::WARN)
        ret,
    )]
    fn re_dkg_epoch(&self, digest: Digest) -> eyre::Result<u64> {
        read_validator_config_at_block_hash(
            &*self.execution_node,
            digest.0,
            |config: &ValidatorConfigV2| {
                config
                    .get_next_network_identity_rotation_epoch()
                    .map_err(eyre::Report::new)
            },
        )
        .map(|(_, _, epoch)| epoch)
    }

    #[instrument(skip_all, fields(%hash), err(level = Level::WARN))]
    fn next_players(&self, hash: B256) -> eyre::Result<ordered::Set<PublicKey>> {
        let next_players = read_active_and_known_peers_at_block_hash(
            &*self.execution_node,
            &ordered::Set::default(),
            hash,
        )
        .wrap_err("failed reading peers from  validator config v2")?
        .into_keys();

        debug!(?next_players, "determined next players");
        Ok(next_players)
    }
}

pub(crate) struct Config<TChain> {
    pub(crate) epoch_strategy: FixedEpocher,

    pub(crate) epoch_manager: epoch::manager::Mailbox,

    /// The namespace the dkg manager will use when sending messages during
    /// a dkg ceremony.
    pub(crate) namespace: Vec<u8>,

    pub(crate) me: PrivateKey,

    pub(crate) mailbox_size: usize,

    /// The finalized floor reported by marshal at startup. Used to choose the
    /// boundary block that seeds the initial DKG state.
    pub(crate) last_finalized_height: Height,

    /// The partition prefix to use when persisting ceremony metadata during
    /// rounds.
    pub(crate) partition_prefix: String,

    /// The DKG manager's view of the chain (execution layer and marshal).
    pub(crate) chain: TChain,

    /// This node's initial share of the bls12381 private key.
    pub(crate) initial_share: Option<Share>,
}
