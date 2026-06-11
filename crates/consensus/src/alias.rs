//! A collection of aliases and shared initialization for frequently used
//! (primarily commonware) types.

pub(crate) mod marshal {
    use std::{num::NonZeroUsize, path::Path, sync::Arc};

    use alloy_consensus::BlockHeader as _;
    use commonware_codec::ReadExt as _;
    use commonware_consensus::{
        Epochable as _,
        marshal::{
            self, Start, core,
            standard::Standard,
            store::{Blocks as _, Certificates},
        },
        simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization},
        types::{Epoch, Epocher as _, FixedEpocher, Height, ViewDelta},
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::MinSig, certificate::Provider as _, ed25519::PublicKey,
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        BufferPooler, Clock, Metrics, Spawner, Storage, buffer::paged::CacheRef,
    };
    use commonware_storage::archive::{Identifier, immutable};
    use commonware_utils::acknowledgement::Exact;
    use eyre::{OptionExt, WrapErr as _, ensure};
    use rand_08::{CryptoRng, Rng};
    use reth_ethereum::{chainspec::EthChainSpec, provider::db::DatabaseEnv};
    use reth_node_builder::NodeTypesWithDBAdapter;
    use reth_node_core::primitives::SealedBlock;
    use reth_provider::{
        BlockIdReader, BlockReader, HeaderProvider, providers::BlockchainProvider,
    };
    use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
    use tempo_node::{TempoFullNode, node::TempoNode};
    use tracing::instrument;

    use crate::{
        bootstrap,
        consensus::{Digest, block::Block},
        epoch::SchemeProvider,
        storage::{self, Hybrid},
    };

    type CertificateScheme = Scheme<PublicKey, MinSig>;

    type FinalizationsByHeight<TContext> =
        immutable::Archive<TContext, Digest, Finalization<CertificateScheme, Digest>>;
    type FinalizedBlocks<TContext> =
        Hybrid<TContext, BlockchainProvider<NodeTypesWithDBAdapter<TempoNode, DatabaseEnv>>>;

    pub(crate) type Actor<TContext> = core::Actor<
        TContext,
        Standard<Block>,
        SchemeProvider,
        FinalizationsByHeight<TContext>,
        FinalizedBlocks<TContext>,
        FixedEpocher,
        Sequential,
        Exact,
    >;

    pub(crate) type Mailbox = core::Mailbox<CertificateScheme, Standard<Block>>;

    /// Settings shared by both engines when initializing the marshal actor
    /// and its backing finalized-blocks store.
    pub(crate) struct Config {
        /// Partition prefix shared with the engine's other on-disk archives.
        pub partition_prefix: String,

        /// Marshal mailbox capacity.
        pub mailbox_size: NonZeroUsize,

        /// Minimum number of views to retain temporary marshal data after a
        /// block is processed. The two engines pick very different values for
        /// this — consensus keeps state around long enough to serve peers,
        /// follow mode does not — so the caller computes it.
        pub view_retention_timeout: ViewDelta,

        /// Maximum number of marshal-dispatched blocks the application may
        /// buffer before acknowledging.
        pub max_pending_acks: NonZeroUsize,

        /// Number of recently finalized blocks retained in the prunable
        /// archive. Older blocks are served from reth via [`Hybrid`].
        pub finalized_blocks_retention: u64,

        /// Epoch length / boundary configuration.
        pub epoch_strategy: FixedEpocher,

        /// Provider for epoch-specific signing schemes used by marshal to
        /// verify finalizations. The same instance is shared with the rest of
        /// the engine, so the caller passes it in.
        pub scheme_provider: SchemeProvider,
    }

    /// Marshal actor + mailbox + the height marshal will resume from,
    /// returned by [`init`].
    pub(crate) struct Initialized<TContext>
    where
        TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Rng + CryptoRng,
    {
        /// The marshal actor, ready to be started.
        pub actor: Actor<TContext>,

        /// Mailbox for sending messages to [`Self::actor`].
        pub mailbox: Mailbox,

        /// The highest finalized height persisted in marshal's certificate
        /// archive. The engine uses this to seed actors that need to know
        /// where chain replay starts.
        pub last_finalized_height: Height,
    }

    /// Initialize the marshal actor and its backing finalized-blocks store
    /// (the finalizations-by-height archive plus the [`Hybrid`] finalized
    /// blocks store), and determine the correct marshal start anchor.
    ///
    /// Both the consensus and follow engines must initialize marshal in
    /// exactly the same way so that nodes can switch modes without data
    /// migration. Use this function to maintain that invariant; differences
    /// between the two engines belong in [`Config`].
    #[instrument(
        skip_all,
        fields(partition_prefix = %config.partition_prefix),
        err(Display)
    )]
    pub(crate) async fn init<TContext>(
        context: &TContext,
        page_cache: CacheRef,
        execution_node: Arc<TempoFullNode>,
        config: Config,
        consensus_dir: &Path,
    ) -> eyre::Result<Initialized<TContext>>
    where
        TContext:
            Clock + Metrics + Spawner + Storage + BufferPooler + Rng + CryptoRng + Send + 'static,
    {
        let finalizations_by_height = storage::init_finalizations_archive(
            context,
            &config.partition_prefix,
            page_cache.clone(),
        )
        .await
        .wrap_err("failed to initialize finalizations by height archive")?;

        let finalized_blocks = storage::init_finalized_blocks(
            context,
            &config.partition_prefix,
            page_cache.clone(),
            execution_node.provider.clone(),
            config.finalized_blocks_retention,
        )
        .await
        .wrap_err("failed to initialize hybrid finalized blocks store")?;

        let (last_finalized_height, start) = start(
            &finalizations_by_height,
            &finalized_blocks,
            &execution_node,
            &config,
            consensus_dir,
        )
        .await?;

        let (actor, mailbox, _marshal_stored_height) = core::Actor::init(
            context.child("marshal"),
            finalizations_by_height,
            finalized_blocks,
            marshal::Config {
                start,
                page_cache,
                strategy: Sequential,
                provider: config.scheme_provider,
                epocher: config.epoch_strategy,
                partition_prefix: config.partition_prefix,
                mailbox_size: config.mailbox_size,
                view_retention_timeout: config.view_retention_timeout,
                prunable_items_per_section: storage::PRUNABLE_ITEMS_PER_SECTION,
                replay_buffer: storage::REPLAY_BUFFER,
                key_write_buffer: storage::WRITE_BUFFER,
                value_write_buffer: storage::WRITE_BUFFER,
                max_repair: storage::MAX_REPAIR,
                max_pending_acks: config.max_pending_acks,
                block_codec_config: (),
            },
        )
        .await;

        Ok(Initialized {
            actor,
            mailbox,
            last_finalized_height,
        })
    }

    async fn start<TContext>(
        finalizations_by_height: &FinalizationsByHeight<TContext>,
        finalized_blocks: &FinalizedBlocks<TContext>,
        execution_node: &TempoFullNode,
        config: &Config,
        consensus_dir: &Path,
    ) -> eyre::Result<(Height, Start<CertificateScheme, Digest, Block>)>
    where
        TContext:
            Clock + Metrics + Spawner + Storage + BufferPooler + Rng + CryptoRng + Send + 'static,
    {
        let last_finalized_height =
            Certificates::last_index(finalizations_by_height).unwrap_or_default();

        let finalization = if last_finalized_height > Height::zero() {
            let index = Identifier::Index(last_finalized_height.get());
            Some(
                Certificates::get(finalizations_by_height, index)
                    .await?
                    .expect("archive must have the last index"),
            )
        } else {
            bootstrap::read_finalization(consensus_dir)
                .wrap_err("failed reading bootstrap finalization")?
        };

        let Some(finalization) = finalization else {
            let genesis = genesis_start(execution_node)?;
            return Ok((last_finalized_height, Start::Genesis(genesis)));
        };

        let epoch = finalization.epoch();
        register_outcome(finalized_blocks, execution_node, config, epoch).await?;

        Ok((last_finalized_height, Start::Floor(finalization)))
    }

    async fn register_outcome<TContext>(
        finalized_blocks: &FinalizedBlocks<TContext>,
        execution_node: &TempoFullNode,
        config: &Config,
        epoch: Epoch,
    ) -> eyre::Result<()>
    where
        TContext:
            Clock + Metrics + Spawner + Storage + BufferPooler + Rng + CryptoRng + Send + 'static,
    {
        if config.scheme_provider.scoped(epoch).is_some() {
            return Ok(());
        }

        let height = epoch.previous().map_or_else(Height::zero, |previous| {
            config
                .epoch_strategy
                .last(previous)
                .expect("epoch strategy is for all epochs")
        });

        let extra_data = if let Some(block) = finalized_blocks
            .get(Identifier::Index(height.get()))
            .await?
        {
            block.extra_data().clone()
        } else {
            execution_node
                .provider
                .header_by_number(height.get())
                .wrap_err("failed to get boundary header")?
                .ok_or_eyre("missing boundary header for marshal verifier registration")?
                .extra_data()
                .clone()
        };

        let mut extra_data = extra_data.as_ref();
        let onchain_outcome = OnchainDkgOutcome::read(&mut extra_data)
            .wrap_err("boundary block did not contain on-chain DKG outcome")?;

        config.scheme_provider.register(
            onchain_outcome.epoch,
            Scheme::certificate_verifier(
                crate::config::NAMESPACE,
                *onchain_outcome.sharing().public(),
            ),
        );

        Ok(())
    }

    fn genesis_start(execution_node: &TempoFullNode) -> eyre::Result<Block> {
        let finalized_block_num = execution_node
            .provider
            .finalized_block_number()
            .wrap_err("failed to determine finalized block number")?
            .unwrap_or_default();

        ensure!(
            finalized_block_num == 0,
            "Genesis start with finalized execution state; finalized height: `{finalized_block_num}` \
            Finalization certificates or bootstrap finalization must be available.",
        );

        let genesis_hash = execution_node.chain_spec().genesis_hash();
        let genesis_block = execution_node
            .provider
            .block_by_hash(genesis_hash)?
            .expect("genesis block must exist");

        Ok(Block::from_execution_block_unchecked(
            SealedBlock::seal_slow(genesis_block),
            None,
        ))
    }
}
