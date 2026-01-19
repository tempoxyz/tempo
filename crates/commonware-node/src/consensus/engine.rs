//! [`Engine`] drives the application and is modelled after commonware's [`alto`] toy blockchain.
//!
//! [`alto`]: https://github.com/commonwarexyx/alto

use std::{
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    time::{Duration, Instant},
};

use commonware_broadcast::buffered;
use commonware_consensus::{
    Reporters, marshal,
    simplex::scheme::bls12381_threshold::Scheme,
    types::{FixedEpocher, ViewDelta},
};
use commonware_cryptography::{
    Signer as _,
    bls12381::primitives::{group::Share, variant::MinSig},
    certificate::Scheme as _,
    ed25519::{PrivateKey, PublicKey},
};
use commonware_p2p::{Address, Blocker, Receiver, Sender};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics, Network, Pacer, Spawner, Storage, buffer::PoolRef,
    spawn_cell,
};
use commonware_storage::archive::immutable;
use commonware_utils::{NZU64, ordered::Map};
use eyre::{OptionExt as _, WrapErr as _};
use futures::future::try_join_all;
use rand::{CryptoRng, Rng};
use tempo_node::TempoFullNode;
use tracing::info;

use crate::{
    config::BLOCKS_FREEZER_TABLE_INITIAL_SIZE_BYTES,
    consensus::application,
    dkg,
    epoch::{self, SchemeProvider},
    subblocks,
};

use super::block::Block;

// A bunch of constants to configure commonwarexyz singletons and copied over form alto.

/// To better support peers near tip during network instability, we multiply
/// the consensus activity timeout by this factor.
const SYNCER_ACTIVITY_TIMEOUT_MULTIPLIER: u64 = 10;
const PRUNABLE_ITEMS_PER_SECTION: NonZeroU64 = NonZeroU64::new(4_096).expect("value is not zero");
const IMMUTABLE_ITEMS_PER_SECTION: NonZeroU64 =
    NonZeroU64::new(262_144).expect("value is not zero");
const FREEZER_TABLE_RESIZE_FREQUENCY: u8 = 4;
const FREEZER_TABLE_RESIZE_CHUNK_SIZE: u32 = 2u32.pow(16); // 3MB
const FREEZER_VALUE_TARGET_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
const FREEZER_VALUE_COMPRESSION: Option<u8> = Some(3);
const REPLAY_BUFFER: NonZeroUsize = NonZeroUsize::new(8 * 1024 * 1024).expect("value is not zero"); // 8MB
const WRITE_BUFFER: NonZeroUsize = NonZeroUsize::new(1024 * 1024).expect("value is not zero"); // 1MB
const BUFFER_POOL_PAGE_SIZE: NonZeroU16 = NonZeroU16::new(4_096).expect("value is not zero"); // 4KB
const BUFFER_POOL_CAPACITY: NonZeroUsize = NonZeroUsize::new(8_192).expect("value is not zero"); // 32MB
const MAX_REPAIR: NonZeroUsize = NonZeroUsize::new(20).expect("value is not zero");

/// Settings for [`Engine`].
///
// XXX: Mostly a one-to-one copy of alto for now. We also put the context in here
// because there doesn't really seem to be a point putting it into an extra initializer.
#[derive(Clone)]
pub struct Builder<TBlocker, TPeerManager> {
    pub fee_recipient: alloy_primitives::Address,

    pub execution_node: Option<TempoFullNode>,

    pub blocker: TBlocker,
    pub peer_manager: TPeerManager,

    pub partition_prefix: String,
    pub signer: PrivateKey,
    pub share: Option<Share>,

    pub mailbox_size: usize,
    pub deque_size: usize,

    pub time_to_propose: Duration,
    pub time_to_collect_notarizations: Duration,
    pub time_to_retry_nullify_broadcast: Duration,
    pub time_for_peer_response: Duration,
    pub views_to_track: u64,
    pub views_until_leader_skip: u64,
    pub new_payload_wait_time: Duration,
    pub time_to_build_subblock: Duration,
    pub subblock_broadcast_interval: Duration,
    pub fcu_heartbeat_interval: Duration,

    pub feed_state: crate::feed::FeedStateHandle,
}

impl<TBlocker, TPeerManager> Builder<TBlocker, TPeerManager>
where
    TBlocker: Blocker<PublicKey = PublicKey>,
    TPeerManager:
        commonware_p2p::Manager<PublicKey = PublicKey, Peers = Map<PublicKey, Address>> + Sync,
{
    pub fn with_execution_node(mut self, execution_node: TempoFullNode) -> Self {
        self.execution_node = Some(execution_node);
        self
    }

    pub async fn try_init<TContext>(
        self,
        context: TContext,
    ) -> eyre::Result<Engine<TBlocker, TContext, TPeerManager>>
    where
        TContext: Clock
            + governor::clock::Clock
            + Rng
            + CryptoRng
            + Pacer
            + Spawner
            + Storage
            + Metrics
            + Network,
    {
        let execution_node = self
            .execution_node
            .clone()
            .ok_or_eyre("execution_node must be set using with_execution_node()")?;

        let epoch_length = execution_node
            .chain_spec()
            .info
            .epoch_length()
            .ok_or_eyre("chainspec did not contain epochLength; cannot go on without it")?;

        info!(
            identity = %self.signer.public_key(),
            "using public ed25519 verifying key derived from provided private ed25519 signing key",
        );

        let (broadcast, broadcast_mailbox) = buffered::Engine::new(
            context.with_label("broadcast"),
            buffered::Config {
                public_key: self.signer.public_key(),
                mailbox_size: self.mailbox_size,
                deque_size: self.deque_size,
                priority: true,
                codec_config: (),
            },
        );

        // Create the buffer pool
        let buffer_pool = PoolRef::new(BUFFER_POOL_PAGE_SIZE, BUFFER_POOL_CAPACITY);

        // XXX: All hard-coded values here are the same as prior to commonware
        // making the resolver configurable in
        // https://github.com/commonwarexyz/monorepo/commit/92870f39b4a9e64a28434b3729ebff5aba67fb4e
        let resolver_config = commonware_consensus::marshal::resolver::p2p::Config {
            public_key: self.signer.public_key(),
            manager: self.peer_manager.clone(),
            mailbox_size: self.mailbox_size,
            blocker: self.blocker.clone(),
            initial: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        };
        let scheme_provider = SchemeProvider::new();

        const FINALIZATIONS_BY_HEIGHT: &str = "finalizations-by-height";
        let start = Instant::now();
        let finalizations_by_height = immutable::Archive::init(
            context.with_label("finalizations_by_height"),
            immutable::Config {
                metadata_partition: format!(
                    "{}-{FINALIZATIONS_BY_HEIGHT}-metadata",
                    self.partition_prefix,
                ),

                freezer_table_partition: format!(
                    "{}-{FINALIZATIONS_BY_HEIGHT}-freezer-table",
                    self.partition_prefix,
                ),

                freezer_table_initial_size: BLOCKS_FREEZER_TABLE_INITIAL_SIZE_BYTES,
                freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
                freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,

                freezer_key_partition: format!(
                    "{}-{FINALIZATIONS_BY_HEIGHT}-freezer-key",
                    self.partition_prefix,
                ),
                freezer_key_buffer_pool: buffer_pool.clone(),

                freezer_value_partition: format!(
                    "{}-{FINALIZATIONS_BY_HEIGHT}-freezer-value",
                    self.partition_prefix,
                ),
                freezer_value_target_size: FREEZER_VALUE_TARGET_SIZE,
                freezer_value_compression: FREEZER_VALUE_COMPRESSION,

                ordinal_partition: format!(
                    "{}-{FINALIZATIONS_BY_HEIGHT}-ordinal",
                    self.partition_prefix,
                ),

                items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
                codec_config: Scheme::<PublicKey, MinSig>::certificate_codec_config_unbounded(),

                replay_buffer: REPLAY_BUFFER,
                freezer_key_write_buffer: WRITE_BUFFER,
                freezer_value_write_buffer: WRITE_BUFFER,
                ordinal_write_buffer: WRITE_BUFFER,
            },
        )
        .await
        .wrap_err("failed to initialize finalizations by height archive")?;
        info!(elapsed = ?start.elapsed(), "restored finalizations by height archive");

        const FINALIZED_BLOCKS: &str = "finalized_blocks";
        let start = Instant::now();
        let finalized_blocks = immutable::Archive::init(
            context.with_label("finalized_blocks"),
            immutable::Config {
                metadata_partition: format!(
                    "{}-{FINALIZED_BLOCKS}-metadata",
                    self.partition_prefix,
                ),

                freezer_table_partition: format!(
                    "{}-{FINALIZED_BLOCKS}-freezer-table",
                    self.partition_prefix,
                ),

                freezer_table_initial_size: BLOCKS_FREEZER_TABLE_INITIAL_SIZE_BYTES,
                freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
                freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,

                freezer_key_partition: format!(
                    "{}-{FINALIZED_BLOCKS}-freezer-key",
                    self.partition_prefix,
                ),
                freezer_key_buffer_pool: buffer_pool.clone(),

                freezer_value_partition: format!(
                    "{}-{FINALIZED_BLOCKS}-freezer-value",
                    self.partition_prefix,
                ),
                freezer_value_target_size: FREEZER_VALUE_TARGET_SIZE,
                freezer_value_compression: FREEZER_VALUE_COMPRESSION,

                ordinal_partition: format!("{}-{FINALIZED_BLOCKS}-ordinal", self.partition_prefix,),
                items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
                codec_config: (),

                replay_buffer: REPLAY_BUFFER,
                freezer_key_write_buffer: WRITE_BUFFER,
                freezer_value_write_buffer: WRITE_BUFFER,
                ordinal_write_buffer: WRITE_BUFFER,
            },
        )
        .await
        .wrap_err("failed to initialize finalizations by height archive")?;
        info!(elapsed = ?start.elapsed(), "restored finalizations by height archive");

        let epoch_strategy = FixedEpocher::new(NZU64!(epoch_length));
        // TODO(janis): forward `last_finalized_height` to application so it can
        // forward missing blocks to EL.
        let (marshal, marshal_mailbox, last_finalized_height) = marshal::Actor::init(
            context.with_label("marshal"),
            finalizations_by_height,
            finalized_blocks,
            marshal::Config {
                provider: scheme_provider.clone(),
                epocher: epoch_strategy.clone(),
                partition_prefix: self.partition_prefix.clone(),
                mailbox_size: self.mailbox_size,
                view_retention_timeout: ViewDelta::new(
                    self.views_to_track
                        .saturating_mul(SYNCER_ACTIVITY_TIMEOUT_MULTIPLIER),
                ),
                prunable_items_per_section: PRUNABLE_ITEMS_PER_SECTION,

                buffer_pool: buffer_pool.clone(),

                replay_buffer: REPLAY_BUFFER,
                key_write_buffer: WRITE_BUFFER,
                value_write_buffer: WRITE_BUFFER,
                max_repair: MAX_REPAIR,
                block_codec_config: (),

                strategy: Sequential,
            },
        )
        .await;

        let subblocks = subblocks::Actor::new(subblocks::Config {
            context: context.clone(),
            signer: self.signer.clone(),
            scheme_provider: scheme_provider.clone(),
            node: execution_node.clone(),
            fee_recipient: self.fee_recipient,
            time_to_build_subblock: self.time_to_build_subblock,
            subblock_broadcast_interval: self.subblock_broadcast_interval,
            epoch_strategy: epoch_strategy.clone(),
        });

        let (feed, feed_mailbox) = crate::feed::init(
            context.with_label("feed"),
            marshal_mailbox.clone(),
            self.feed_state,
        );

        let (executor, executor_mailbox) = crate::executor::init(
            context.with_label("executor"),
            crate::executor::Config {
                execution_node: execution_node.clone(),
                last_finalized_height,
                marshal: marshal_mailbox.clone(),
                fcu_heartbeat_interval: self.fcu_heartbeat_interval,
            },
        )
        .wrap_err("failed initialization executor actor")?;

        let (application, application_mailbox) = application::init(super::application::Config {
            context: context.with_label("application"),
            fee_recipient: self.fee_recipient,
            mailbox_size: self.mailbox_size,
            marshal: marshal_mailbox.clone(),
            execution_node: execution_node.clone(),
            executor: executor_mailbox.clone(),
            new_payload_wait_time: self.new_payload_wait_time,
            subblocks: subblocks.mailbox(),
            scheme_provider: scheme_provider.clone(),
            epoch_strategy: epoch_strategy.clone(),
        })
        .await
        .wrap_err("failed initializing application actor")?;

        let (epoch_manager, epoch_manager_mailbox) = epoch::manager::init(
            context.with_label("epoch_manager"),
            epoch::manager::Config {
                application: application_mailbox.clone(),
                blocker: self.blocker.clone(),
                buffer_pool: buffer_pool.clone(),
                epoch_strategy: epoch_strategy.clone(),
                time_for_peer_response: self.time_for_peer_response,
                time_to_propose: self.time_to_propose,
                mailbox_size: self.mailbox_size,
                subblocks: subblocks.mailbox(),
                marshal: marshal_mailbox.clone(),
                feed: feed_mailbox.clone(),
                scheme_provider: scheme_provider.clone(),
                time_to_collect_notarizations: self.time_to_collect_notarizations,
                time_to_retry_nullify_broadcast: self.time_to_retry_nullify_broadcast,
                partition_prefix: format!("{}_epoch_manager", self.partition_prefix),
                views_to_track: ViewDelta::new(self.views_to_track),
                views_until_leader_skip: ViewDelta::new(self.views_until_leader_skip),
            },
        );

        let (dkg_manager, dkg_manager_mailbox) = dkg::manager::init(
            context.with_label("dkg_manager"),
            dkg::manager::Config {
                epoch_manager: epoch_manager_mailbox.clone(),
                epoch_strategy: epoch_strategy.clone(),
                execution_node,
                initial_share: self.share.clone(),
                mailbox_size: self.mailbox_size,
                marshal: marshal_mailbox,
                namespace: crate::config::NAMESPACE.to_vec(),
                me: self.signer.clone(),
                partition_prefix: format!("{}_dkg_manager", self.partition_prefix),
                peer_manager: self.peer_manager.clone(),
            },
        )
        .await
        .wrap_err("failed initializing dkg manager")?;

        Ok(Engine {
            context: ContextCell::new(context),

            broadcast,
            broadcast_mailbox,

            dkg_manager,
            dkg_manager_mailbox,

            application,

            executor,
            executor_mailbox,

            resolver_config,
            marshal,

            epoch_manager,
            epoch_manager_mailbox,

            feed,

            subblocks,
        })
    }
}

pub struct Engine<TBlocker, TContext, TPeerManager>
where
    TBlocker: Blocker<PublicKey = PublicKey>,
    TContext: Clock
        + governor::clock::Clock
        + Rng
        + CryptoRng
        + Metrics
        + Network
        + Pacer
        + Spawner
        + Storage,
    TPeerManager: commonware_p2p::Manager<PublicKey = PublicKey, Peers = Map<PublicKey, Address>>,
{
    context: ContextCell<TContext>,

    /// broadcasts messages to and caches messages from untrusted peers.
    // XXX: alto calls this `buffered`. That's confusing. We call it `broadcast`.
    broadcast: buffered::Engine<TContext, PublicKey, Block>,
    broadcast_mailbox: buffered::Mailbox<PublicKey, Block>,

    dkg_manager: dkg::manager::Actor<TContext, TPeerManager>,
    dkg_manager_mailbox: dkg::manager::Mailbox,

    /// Acts as the glue between the consensus and execution layers implementing
    /// the `[commonware_consensus::Automaton]` trait.
    application: application::Actor<TContext>,

    /// Responsible for keeping the consensus layer state and execution layer
    /// states in sync. Drives the chain state of the execution layer by sending
    /// forkchoice-updates.
    executor: crate::executor::Actor<TContext>,
    executor_mailbox: crate::executor::Mailbox,

    /// Resolver config that will be passed to the marshal actor upon start.
    resolver_config: marshal::resolver::p2p::Config<PublicKey, TPeerManager, TBlocker>,

    /// Listens to consensus events and syncs blocks from the network to the
    /// local node.
    marshal: crate::alias::marshal::Actor<TContext>,

    epoch_manager: epoch::manager::Actor<TBlocker, TContext>,
    epoch_manager_mailbox: epoch::manager::Mailbox,

    feed: crate::feed::Actor<TContext>,

    subblocks: subblocks::Actor<TContext>,
}

impl<TBlocker, TContext, TPeerManager> Engine<TBlocker, TContext, TPeerManager>
where
    TBlocker: Blocker<PublicKey = PublicKey>,
    TContext: Clock
        + governor::clock::Clock
        + Rng
        + CryptoRng
        + Metrics
        + Network
        + Pacer
        + Spawner
        + Storage,
    TPeerManager:
        commonware_p2p::Manager<PublicKey = PublicKey, Peers = Map<PublicKey, Address>> + Sync,
{
    #[expect(
        clippy::too_many_arguments,
        reason = "following commonware's style of writing"
    )]
    pub fn start(
        mut self,
        pending_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        recovered_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        resolver_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        broadcast_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        marshal_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        dkg_channel: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        subblocks_channel: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) -> Handle<eyre::Result<()>> {
        spawn_cell!(
            self.context,
            self.run(
                pending_network,
                recovered_network,
                resolver_network,
                broadcast_network,
                marshal_network,
                dkg_channel,
                subblocks_channel,
            )
            .await
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "following commonware's style of writing"
    )]
    async fn run(
        self,
        pending_channel: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        recovered_channel: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        resolver_channel: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        broadcast_channel: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        marshal_channel: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        dkg_channel: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        subblocks_channel: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) -> eyre::Result<()> {
        let broadcast = self.broadcast.start(broadcast_channel);
        let resolver =
            marshal::resolver::p2p::init(&self.context, self.resolver_config, marshal_channel);

        let application = self.application.start(self.dkg_manager_mailbox.clone());
        let executor = self.executor.start();

        let marshal = self.marshal.start(
            Reporters::from((
                self.epoch_manager_mailbox,
                Reporters::from((self.executor_mailbox, self.dkg_manager_mailbox.clone())),
            )),
            self.broadcast_mailbox,
            resolver,
        );

        let epoch_manager =
            self.epoch_manager
                .start(pending_channel, recovered_channel, resolver_channel);

        let feed = self.feed.start();

        let subblocks = self
            .context
            .spawn(|_| self.subblocks.run(subblocks_channel));

        let dkg_manager = self.dkg_manager.start(dkg_channel);

        try_join_all(vec![
            application,
            broadcast,
            epoch_manager,
            executor,
            feed,
            marshal,
            dkg_manager,
            subblocks,
        ])
        .await
        .map(|_| ())
        // TODO: look into adding error context so that we know which
        // component failed.
        .wrap_err("one of the consensus engine's actors failed")
    }
}
