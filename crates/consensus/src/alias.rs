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
    use eyre::WrapErr as _;
    use rand_08::{CryptoRng, Rng};
    use reth_ethereum::chainspec::EthChainSpec;
    use reth_ethereum::provider::db::DatabaseEnv;
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

        /// The local consensus finalized tip used to seed actors that need to
        /// read startup state. When the finalization archive is absent, this
        /// preserves the legacy `max(marshal_stored_height,
        /// reth_finalized_height)` behavior.
        pub finalized_tip: Height,

        /// The local consensus height after which startup backfill should
        /// resume. This is the archive floor for snapshot/archive starts, or
        /// marshal's stored processed height otherwise.
        pub finalized_backfill_start: Height,

        /// The finalized tip known at startup, including the digest to
        /// canonicalize once startup backfill is complete.
        pub latest_observed_finalized_tip: (Height, Digest),
    }

    /// Initialize the marshal actor and its backing finalized-blocks store
    /// (the finalizations-by-height archive plus the [`Hybrid`] finalized
    /// blocks store), and advance marshal's sync floor.
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

        let finalized_blocks = storage::init_finalized_blocks(
            &context,
            &config.partition_prefix,
            page_cache.clone(),
            execution_node.provider.clone(),
            config.finalized_blocks_retention,
        )
        .await
        .wrap_err("failed to initialize hybrid finalized blocks store")?;

        let archive_bounds = archive_finalization_bounds(&finalizations_by_height).await?;

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

        // When a consensus archive exists, it is the startup source of truth:
        // floor marshal at the first local finalization and seed the other
        // actors from the local CL tip. For existing nodes, the floor may be
        // below the processed height restored from marshal metadata;
        // commonware ignores stale floors, so sending it unconditionally is
        // safe. If the archive is absent, preserve the legacy EL-driven
        // fallback.
        let reth_finalized_height = execution_node
            .provider
            .canonical_in_memory_state()
            .get_finalized_num_hash()
            .map(|nh| nh.number)
            .unwrap_or(0);
        let finalized_tip =
            initial_finalized_height(archive_bounds, marshal_stored_height, reth_finalized_height);
        let finalized_backfill_start =
            initial_backfill_start(archive_bounds, marshal_stored_height);
        let latest_observed_finalized_tip = archive_bounds
            .map(|bounds| (bounds.tip, bounds.tip_digest))
            .unwrap_or_else(|| {
                (
                    Height::zero(),
                    Digest(execution_node.chain_spec().genesis_hash()),
                )
            });

        if let Some(ArchiveFinalizationBounds {
            floor: archive_floor_height,
            tip: archive_tip_height,
            tip_digest: archive_tip_digest,
        }) = archive_bounds
        {
            info!(
                marshal_stored = %marshal_stored_height,
                archive_floor = %archive_floor_height,
                archive_tip = %archive_tip_height,
                archive_tip_digest = %archive_tip_digest,
                "setting marshal sync floor to first archived finalization certificate"
            );
            mailbox.set_floor(archive_floor_height).await;
        } else if finalized_tip > marshal_stored_height {
            info!(
                marshal_stored = %marshal_stored_height,
                reth_finalized = reth_finalized_height,
                "advancing marshal sync floor to reth's finalized block"
            );
            mailbox.set_floor(finalized_tip).await;
        }

        Ok(Initialized {
            actor,
            mailbox,
            finalized_tip,
            finalized_backfill_start,
            latest_observed_finalized_tip,
        })
    }

    #[derive(Clone, Copy)]
    struct ArchiveFinalizationBounds {
        floor: Height,
        tip: Height,
        tip_digest: Digest,
    }

    async fn archive_finalization_bounds<TContext>(
        finalizations_by_height: &immutable::Archive<
            TContext,
            Digest,
            Finalization<Scheme<PublicKey, MinSig>, Digest>,
        >,
    ) -> eyre::Result<Option<ArchiveFinalizationBounds>>
    where
        TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Clone + Send + 'static,
    {
        let Some(floor) = finalizations_by_height
            .ranges_from(0)
            .next()
            .map(|(start, _)| Height::new(start))
        else {
            return Ok(None);
        };
        let Some(tip) = finalizations_by_height.last_index().map(Height::new) else {
            return Ok(None);
        };
        let finalization = finalizations_by_height
            .get(Identifier::Index(tip.get()))
            .await
            .wrap_err_with(|| {
                format!("failed reading finalization certificate at archive tip `{tip}`")
            })?
            .ok_or_else(|| {
                eyre::eyre!(
                    "finalization archive reported tip `{tip}` but no certificate was present"
                )
            })?;
        let tip_digest = finalization.proposal.payload;
        Ok(Some(ArchiveFinalizationBounds {
            floor,
            tip,
            tip_digest,
        }))
    }

    fn initial_finalized_height(
        archive_bounds: Option<ArchiveFinalizationBounds>,
        marshal_stored_height: Height,
        reth_finalized_height: u64,
    ) -> Height {
        archive_bounds
            .map(|bounds| bounds.tip)
            .unwrap_or_else(|| marshal_stored_height.max(Height::new(reth_finalized_height)))
    }

    fn initial_backfill_start(
        archive_bounds: Option<ArchiveFinalizationBounds>,
        marshal_stored_height: Height,
    ) -> Height {
        archive_bounds
            .map(|bounds| bounds.floor)
            .unwrap_or(marshal_stored_height)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn initial_finalized_height_uses_archive_tip_when_present() {
            assert_eq!(
                initial_finalized_height(
                    Some(ArchiveFinalizationBounds {
                        floor: Height::new(7),
                        tip: Height::new(9),
                        tip_digest: Digest(alloy_primitives::B256::ZERO),
                    }),
                    Height::new(10),
                    12,
                ),
                Height::new(9),
            );
        }

        #[test]
        fn initial_finalized_height_preserves_existing_fallback_without_archive() {
            assert_eq!(
                initial_finalized_height(None, Height::new(10), 12),
                Height::new(12),
            );
            assert_eq!(
                initial_finalized_height(None, Height::new(14), 12),
                Height::new(14),
            );
        }

        #[test]
        fn initial_backfill_start_uses_archive_floor_when_present() {
            assert_eq!(
                initial_backfill_start(
                    Some(ArchiveFinalizationBounds {
                        floor: Height::new(7),
                        tip: Height::new(9),
                        tip_digest: Digest(alloy_primitives::B256::ZERO),
                    }),
                    Height::new(10),
                ),
                Height::new(7),
            );
        }

        #[test]
        fn initial_backfill_start_uses_marshal_stored_height_without_archive() {
            assert_eq!(
                initial_backfill_start(None, Height::new(10)),
                Height::new(10)
            );
        }
    }
}
