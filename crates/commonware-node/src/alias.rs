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
    use commonware_storage::archive::immutable;
    use commonware_utils::acknowledgement::Exact;
    use eyre::WrapErr as _;
    use rand_08::{CryptoRng, Rng};
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

        /// When `true`, skip dual-writing finalized blocks to the legacy
        /// immutable archive. See [`crate::storage::init_hybrid_finalized_blocks`]
        /// for the rollback-safety implications.
        pub no_legacy_archive: bool,

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

        /// `max(marshal_stored_height, reth_finalized_height)` after
        /// advancing marshal's sync floor to that height. The engine uses
        /// this to seed the executor and other actors that need to know
        /// where the chain starts replaying from.
        pub last_finalized_height: Height,
    }

    /// Initialize the marshal actor and its backing finalized-blocks store
    /// (the finalizations-by-height archive plus the [`Hybrid`] finalized
    /// blocks store), and advance marshal's sync floor to
    /// `max(marshal_stored_height, reth_finalized_height)`.
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

        let finalized_blocks = storage::init_hybrid_finalized_blocks(
            &context,
            &config.partition_prefix,
            page_cache.clone(),
            execution_node.provider.clone(),
            config.finalized_blocks_retention,
            !config.no_legacy_archive,
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

        // Floor marshal at reth's last finalized block so we don't try to
        // re-sync history that the execution layer already finalized. The
        // mailbox message is buffered until the actor starts; `set_floor` only
        // ever advances, so sending it unconditionally is safe.
        let reth_finalized_height = execution_node
            .provider
            .canonical_in_memory_state()
            .get_finalized_num_hash()
            .map(|nh| nh.number)
            .unwrap_or(0);
        let last_finalized_height = marshal_stored_height.max(Height::new(reth_finalized_height));
        if last_finalized_height > marshal_stored_height {
            info!(
                marshal_stored = %marshal_stored_height,
                reth_finalized = reth_finalized_height,
                "advancing marshal sync floor to reth's finalized block"
            );
            mailbox.set_floor(last_finalized_height).await;
        }

        Ok(Initialized {
            actor,
            mailbox,
            last_finalized_height,
        })
    }
}
