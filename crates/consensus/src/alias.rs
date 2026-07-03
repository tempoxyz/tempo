//! A collection of aliases and shared initialization for frequently used
//! (primarily commonware) types.

pub(crate) mod marshal {
    use std::{num::NonZeroUsize, sync::Arc};

    use commonware_consensus::{
        marshal::{self, core, standard::Standard},
        simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization},
        types::{FixedEpocher, Height, ViewDelta},
    };
    use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        BufferPooler, Clock, Metrics, Spawner, Storage, buffer::paged::CacheRef,
    };
    use commonware_storage::archive::{Archive as _, Identifier, immutable};
    use commonware_utils::acknowledgement::Exact;
    use eyre::{OptionExt as _, WrapErr as _, bail, eyre};
    use rand_08::{CryptoRng, Rng};
    use reth_ethereum::{chainspec::EthChainSpec, provider::db::DatabaseEnv};
    use reth_node_builder::NodeTypesWithDBAdapter;
    use reth_provider::providers::BlockchainProvider;
    use tempo_node::{TempoFullNode, node::TempoNode};
    use tracing::{info, instrument};

    use crate::{
        consensus::{Digest, block::Block},
        epoch::SchemeProvider,
        storage::{self, Hybrid},
    };

    pub(crate) type Actor<TContext> = core::Actor<
        TContext,
        Standard<Block>,
        SchemeProvider,
        immutable::Archive<TContext, Digest, Finalization<Scheme<PublicKey, MinSig>, Digest>>,
        Hybrid<TContext, BlockchainProvider<NodeTypesWithDBAdapter<TempoNode, DatabaseEnv>>>,
        FixedEpocher,
        Sequential,
        Exact,
    >;

    pub(crate) type Mailbox = core::Mailbox<Scheme<PublicKey, MinSig>, Standard<Block>>;

    /// Settings shared by both engines when initializing the marshal actor
    /// and its backing finalized-blocks store.
    pub(crate) struct Config {
        /// Partition prefix shared with the engine's other on-disk archives.
        pub partition_prefix: String,

        /// Marshal mailbox capacity.
        pub mailbox_size: usize,

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

        /// Require startup to use the consensus finalization archive as its
        /// finalized floor instead of falling back to the execution layer.
        pub strict_startup: bool,

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

        /// Startup backfill target, selected from marshal's stored finalized
        /// height and the startup floor height.
        pub finalized_floor: Height,

        /// Finalized tip selected at startup. In strict mode this comes from
        /// the archive or genesis; otherwise it is the highest available value
        /// from the archive and execution layer.
        pub finalized_tip: (Height, Digest),
    }

    /// Initialize the marshal actor and its backing finalized-blocks store
    /// (the finalizations-by-height archive plus the [`Hybrid`] finalized
    /// blocks store), select the startup finalized floor, and advance
    /// marshal's sync floor when needed.
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
        context: TContext,
        page_cache: CacheRef,
        execution_node: Arc<TempoFullNode>,
        config: Config,
    ) -> eyre::Result<Initialized<TContext>>
    where
        TContext: Clock
            + Metrics
            + Spawner
            + Storage
            + BufferPooler
            + Rng
            + CryptoRng
            + Clone
            + Send
            + 'static,
    {
        let finalizations_by_height = storage::init_finalizations_archive(
            &context,
            &config.partition_prefix,
            page_cache.clone(),
        )
        .await
        .wrap_err("failed to initialize finalizations by height archive")?;

        let FinalizationRange {
            floor: finalized_floor,
            tip: finalized_tip,
        } = establish_finalization_range(
            &finalizations_by_height,
            &execution_node,
            config.strict_startup,
        )
        .await?;
        info!(
            floor_height = %finalized_floor.0,
            floor_digest = %finalized_floor.1,
            tip_height = %finalized_tip.0,
            tip_digest = %finalized_tip.1,
            strict_startup = config.strict_startup,
            "selected finalized startup range"
        );

        let finalized_blocks = storage::init_finalized_blocks(
            &context,
            &config.partition_prefix,
            page_cache.clone(),
            execution_node.provider.clone(),
            config.finalized_blocks_retention,
        )
        .await
        .wrap_err("failed to initialize hybrid finalized blocks store")?;

        let (actor, mailbox, marshal_stored_height) = core::Actor::init(
            context.with_label("marshal"),
            finalizations_by_height,
            finalized_blocks,
            marshal::Config {
                provider: config.scheme_provider,
                epocher: config.epoch_strategy,
                partition_prefix: config.partition_prefix,
                mailbox_size: config.mailbox_size,
                view_retention_timeout: config.view_retention_timeout,
                prunable_items_per_section: storage::PRUNABLE_ITEMS_PER_SECTION,
                page_cache,
                replay_buffer: storage::REPLAY_BUFFER,
                key_write_buffer: storage::WRITE_BUFFER,
                value_write_buffer: storage::WRITE_BUFFER,
                max_repair: storage::MAX_REPAIR,
                max_pending_acks: config.max_pending_acks,
                block_codec_config: (),
                strategy: Sequential,
            },
        )
        .await;

        let startup_floor_height = finalized_floor.0;
        let last_finalized_height = marshal_stored_height.max(startup_floor_height);
        info!(
            marshal_stored = %marshal_stored_height,
            selected_floor = %startup_floor_height,
            strict_startup = config.strict_startup,
            "setting marshal sync floor"
        );
        mailbox.set_floor(last_finalized_height).await;

        Ok(Initialized {
            actor,
            mailbox,
            finalized_floor: last_finalized_height,
            finalized_tip,
        })
    }

    struct FinalizationRange {
        floor: (Height, Digest),
        tip: (Height, Digest),
    }

    async fn establish_finalization_range<TContext>(
        finalizations_by_height: &immutable::Archive<
            TContext,
            Digest,
            Finalization<Scheme<PublicKey, MinSig>, Digest>,
        >,
        execution_node: &TempoFullNode,
        strict_startup: bool,
    ) -> eyre::Result<FinalizationRange>
    where
        TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Send + 'static,
    {
        let archive_range = finalized_archive_range(finalizations_by_height)
            .await
            .wrap_err("failed to establish finalized archive bounds")?;
        let execution_finalized = execution_finalized_point(execution_node);

        match (strict_startup, archive_range) {
            (true, Some((floor, tip))) => Ok(FinalizationRange { floor, tip }),
            (true, None) if execution_finalized.0.is_zero() => Ok(FinalizationRange {
                floor: execution_finalized,
                tip: execution_finalized,
            }),
            (true, None) => Err(eyre!(
                "strict consensus startup requires a finalized certificate archive unless the \
                    execution layer is empty, but no finalized certificate was found and execution \
                    finalized block is `{}` at height `{}`",
                execution_finalized.1,
                execution_finalized.0,
            )),
            (false, Some((archive_floor, archive_tip))) => Ok(FinalizationRange {
                floor: if archive_floor.0 >= execution_finalized.0 {
                    archive_floor
                } else {
                    execution_finalized
                },
                tip: if archive_tip.0 >= execution_finalized.0 {
                    archive_tip
                } else {
                    execution_finalized
                },
            }),
            (false, None) => Ok(FinalizationRange {
                floor: execution_finalized,
                tip: execution_finalized,
            }),
        }
    }

    async fn finalized_archive_range<TContext>(
        archive: &immutable::Archive<
            TContext,
            Digest,
            Finalization<Scheme<PublicKey, MinSig>, Digest>,
        >,
    ) -> eyre::Result<Option<((Height, Digest), (Height, Digest))>>
    where
        TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Send + 'static,
    {
        let (first, last) = match (archive.first_index(), archive.last_index()) {
            (None, None) => return Ok(None),
            (Some(first), Some(last)) => (first, last),
            (first, last) => {
                bail!(
                    "finalized certificate archive reported inconsistent index range: \
                    first={first:?}, last={last:?}"
                );
            }
        };

        let floor = finalized_archive_point(archive, first)
            .await
            .wrap_err_with(|| {
                format!("failed to read finalized floor from archive at height `{first}`")
            })?;
        let tip = if first == last {
            floor
        } else {
            finalized_archive_point(archive, last)
                .await
                .wrap_err_with(|| {
                    format!("failed to read finalized tip from archive at height `{last}`")
                })?
        };

        Ok(Some((floor, tip)))
    }

    async fn finalized_archive_point<TContext>(
        archive: &immutable::Archive<
            TContext,
            Digest,
            Finalization<Scheme<PublicKey, MinSig>, Digest>,
        >,
        height: u64,
    ) -> eyre::Result<(Height, Digest)>
    where
        TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Send + 'static,
    {
        let finalization = archive
            .get(Identifier::Index(height))
            .await
            .wrap_err("failed reading certificate from archive")?
            .ok_or_eyre("archive did not contain certificate")?;
        Ok((Height::new(height), finalization.proposal.payload))
    }

    fn execution_finalized_point(execution_node: &TempoFullNode) -> (Height, Digest) {
        execution_node
            .provider
            .canonical_in_memory_state()
            .get_finalized_num_hash()
            .map(|nh| (Height::new(nh.number), Digest(nh.hash)))
            .unwrap_or_else(|| {
                (
                    Height::zero(),
                    Digest(execution_node.chain_spec().genesis_hash()),
                )
            })
    }
}
