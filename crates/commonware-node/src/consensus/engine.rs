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
    simplex::scheme::bls12381_threshold::vrf::Scheme,
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
use tempo_commonware_node_config::SigningKey;
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
pub struct EngineBuilder<TBlocker, TPeerManager> {
    fee_recipient: Option<alloy_primitives::Address>,
    execution_node: Option<TempoFullNode>,
    blocker: Option<TBlocker>,
    peer_manager: Option<TPeerManager>,
    partition_prefix: Option<String>,
    signer: Option<PrivateKey>,
    share: Option<Share>,
    mailbox_size: Option<usize>,
    deque_size: Option<usize>,
    time_to_propose: Option<Duration>,
    time_to_collect_notarizations: Option<Duration>,
    time_to_retry_nullify_broadcast: Option<Duration>,
    time_for_peer_response: Option<Duration>,
    views_to_track: Option<u64>,
    views_until_leader_skip: Option<u64>,
    new_payload_wait_time: Option<Duration>,
    time_to_build_subblock: Option<Duration>,
    subblock_broadcast_interval: Option<Duration>,
    fcu_heartbeat_interval: Option<Duration>,
    feed_state: Option<crate::feed::FeedStateHandle>,
}

impl<TBlocker, TPeerManager> Default for EngineBuilder<TBlocker, TPeerManager> {
    fn default() -> Self {
        Self {
            fee_recipient: None,
            execution_node: None,
            blocker: None,
            peer_manager: None,
            partition_prefix: None,
            signer: None,
            share: None,
            mailbox_size: None,
            deque_size: None,
            time_to_propose: None,
            time_to_collect_notarizations: None,
            time_to_retry_nullify_broadcast: None,
            time_for_peer_response: None,
            views_to_track: None,
            views_until_leader_skip: None,
            new_payload_wait_time: None,
            time_to_build_subblock: None,
            subblock_broadcast_interval: None,
            fcu_heartbeat_interval: None,
            feed_state: None,
        }
    }
}

impl<O> EngineBuilder<O, O>
where
    O: Blocker<PublicKey = PublicKey>
        + commonware_p2p::Manager<PublicKey = PublicKey, Peers = Map<PublicKey, Address>>
        + Sync
        + Clone,
{
    /// Sets both `blocker` and `peer_manager` to the same oracle.
    #[must_use]
    pub fn with_oracle(mut self, oracle: O) -> Self {
        self.blocker = Some(oracle.clone());
        self.peer_manager = Some(oracle);
        self
    }
}

impl<TBlocker, TPeerManager> EngineBuilder<TBlocker, TPeerManager>
where
    TBlocker: Blocker<PublicKey = PublicKey>,
    TPeerManager:
        commonware_p2p::Manager<PublicKey = PublicKey, Peers = Map<PublicKey, Address>> + Sync,
{
    #[must_use]
    pub fn with_fee_recipient(mut self, fee_recipient: alloy_primitives::Address) -> Self {
        self.fee_recipient = Some(fee_recipient);
        self
    }

    #[must_use]
    pub fn with_execution_node(mut self, execution_node: TempoFullNode) -> Self {
        self.execution_node = Some(execution_node);
        self
    }

    #[must_use]
    pub fn with_blocker(mut self, blocker: TBlocker) -> Self {
        self.blocker = Some(blocker);
        self
    }

    #[must_use]
    pub fn with_peer_manager(mut self, peer_manager: TPeerManager) -> Self {
        self.peer_manager = Some(peer_manager);
        self
    }

    #[must_use]
    pub fn with_partition_prefix(mut self, partition_prefix: impl Into<String>) -> Self {
        self.partition_prefix = Some(partition_prefix.into());
        self
    }

    #[must_use]
    pub fn with_signer(mut self, signing_key: impl Into<SigningKey>) -> Self {
        self.signer = Some(signing_key.into().into_inner());
        self
    }

    #[must_use]
    pub fn with_share(mut self, share: Option<Share>) -> Self {
        self.share = share;
        self
    }

    /// Returns a reference to the BLS share, if set.
    #[must_use]
    pub fn share(&self) -> Option<&Share> {
        self.share.as_ref()
    }

    /// Takes the BLS share, leaving `None` in its place.
    pub fn take_share(&mut self) -> Option<Share> {
        self.share.take()
    }

    /// Sets the fee recipient (for in-place mutation).
    pub fn set_fee_recipient(&mut self, fee_recipient: alloy_primitives::Address) {
        self.fee_recipient = Some(fee_recipient);
    }

    /// Sets the new-payload wait time (for in-place mutation).
    pub fn set_new_payload_wait_time_duration(&mut self, d: Duration) {
        self.new_payload_wait_time = Some(d);
    }

    #[must_use]
    pub fn with_mailbox_size(mut self, mailbox_size: usize) -> Self {
        self.mailbox_size = Some(mailbox_size);
        self
    }

    #[must_use]
    pub fn with_deque_size(mut self, deque_size: usize) -> Self {
        self.deque_size = Some(deque_size);
        self
    }

    pub fn with_time_to_propose(mut self, d: jiff::SignedDuration) -> eyre::Result<Self> {
        self.time_to_propose = Some(d.try_into()?);
        Ok(self)
    }

    #[must_use]
    pub fn with_time_to_propose_duration(mut self, d: Duration) -> Self {
        self.time_to_propose = Some(d);
        self
    }

    pub fn with_time_to_collect_notarizations(
        mut self,
        d: jiff::SignedDuration,
    ) -> eyre::Result<Self> {
        self.time_to_collect_notarizations = Some(d.try_into()?);
        Ok(self)
    }

    #[must_use]
    pub fn with_time_to_collect_notarizations_duration(mut self, d: Duration) -> Self {
        self.time_to_collect_notarizations = Some(d);
        self
    }

    pub fn with_time_to_retry_nullify_broadcast(
        mut self,
        d: jiff::SignedDuration,
    ) -> eyre::Result<Self> {
        self.time_to_retry_nullify_broadcast = Some(d.try_into()?);
        Ok(self)
    }

    #[must_use]
    pub fn with_time_to_retry_nullify_broadcast_duration(mut self, d: Duration) -> Self {
        self.time_to_retry_nullify_broadcast = Some(d);
        self
    }

    pub fn with_time_for_peer_response(mut self, d: jiff::SignedDuration) -> eyre::Result<Self> {
        self.time_for_peer_response = Some(d.try_into()?);
        Ok(self)
    }

    #[must_use]
    pub fn with_time_for_peer_response_duration(mut self, d: Duration) -> Self {
        self.time_for_peer_response = Some(d);
        self
    }

    #[must_use]
    pub fn with_views_to_track(mut self, views_to_track: u64) -> Self {
        self.views_to_track = Some(views_to_track);
        self
    }

    #[must_use]
    pub fn with_views_until_leader_skip(mut self, views_until_leader_skip: u64) -> Self {
        self.views_until_leader_skip = Some(views_until_leader_skip);
        self
    }

    pub fn with_new_payload_wait_time(mut self, d: jiff::SignedDuration) -> eyre::Result<Self> {
        self.new_payload_wait_time = Some(d.try_into()?);
        Ok(self)
    }

    #[must_use]
    pub fn with_new_payload_wait_time_duration(mut self, d: Duration) -> Self {
        self.new_payload_wait_time = Some(d);
        self
    }

    pub fn with_time_to_build_subblock(mut self, d: jiff::SignedDuration) -> eyre::Result<Self> {
        self.time_to_build_subblock = Some(d.try_into()?);
        Ok(self)
    }

    #[must_use]
    pub fn with_time_to_build_subblock_duration(mut self, d: Duration) -> Self {
        self.time_to_build_subblock = Some(d);
        self
    }

    pub fn with_subblock_broadcast_interval(
        mut self,
        d: jiff::SignedDuration,
    ) -> eyre::Result<Self> {
        self.subblock_broadcast_interval = Some(d.try_into()?);
        Ok(self)
    }

    #[must_use]
    pub fn with_subblock_broadcast_interval_duration(mut self, d: Duration) -> Self {
        self.subblock_broadcast_interval = Some(d);
        self
    }

    pub fn with_fcu_heartbeat_interval(mut self, d: jiff::SignedDuration) -> eyre::Result<Self> {
        self.fcu_heartbeat_interval = Some(d.try_into()?);
        Ok(self)
    }

    #[must_use]
    pub fn with_fcu_heartbeat_interval_duration(mut self, d: Duration) -> Self {
        self.fcu_heartbeat_interval = Some(d);
        self
    }

    #[must_use]
    pub fn with_feed_state(mut self, feed_state: crate::feed::FeedStateHandle) -> Self {
        self.feed_state = Some(feed_state);
        self
    }

    /// Validates required fields and initializes the [`Engine`].
    ///
    /// # Errors
    /// Returns an error if any required field is missing.
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
        let fee_recipient = self
            .fee_recipient
            .ok_or_eyre("fee_recipient is required - call with_fee_recipient()")?;
        let execution_node = self
            .execution_node
            .ok_or_eyre("execution_node is required - call with_execution_node()")?;
        let blocker = self
            .blocker
            .ok_or_eyre("blocker is required - call with_blocker() or with_oracle()")?;
        let peer_manager = self
            .peer_manager
            .ok_or_eyre("peer_manager is required - call with_peer_manager() or with_oracle()")?;
        let partition_prefix = self.partition_prefix.unwrap_or_else(|| "engine".into());
        let signer = self
            .signer
            .ok_or_eyre("signer is required - call with_signer()")?;
        let share = self.share;
        let mailbox_size = self
            .mailbox_size
            .ok_or_eyre("mailbox_size is required - call with_mailbox_size()")?;
        let deque_size = self
            .deque_size
            .ok_or_eyre("deque_size is required - call with_deque_size()")?;
        let time_to_propose = self
            .time_to_propose
            .ok_or_eyre("time_to_propose is required - call with_time_to_propose()")?;
        let time_to_collect_notarizations = self.time_to_collect_notarizations.ok_or_eyre(
            "time_to_collect_notarizations is required - call with_time_to_collect_notarizations()",
        )?;
        let time_to_retry_nullify_broadcast = self
            .time_to_retry_nullify_broadcast
            .ok_or_eyre("time_to_retry_nullify_broadcast is required - call with_time_to_retry_nullify_broadcast()")?;
        let time_for_peer_response = self.time_for_peer_response.ok_or_eyre(
            "time_for_peer_response is required - call with_time_for_peer_response()",
        )?;
        let views_to_track = self
            .views_to_track
            .ok_or_eyre("views_to_track is required - call with_views_to_track()")?;
        let views_until_leader_skip = self.views_until_leader_skip.ok_or_eyre(
            "views_until_leader_skip is required - call with_views_until_leader_skip()",
        )?;
        let new_payload_wait_time = self
            .new_payload_wait_time
            .ok_or_eyre("new_payload_wait_time is required - call with_new_payload_wait_time()")?;
        let time_to_build_subblock = self.time_to_build_subblock.ok_or_eyre(
            "time_to_build_subblock is required - call with_time_to_build_subblock()",
        )?;
        let subblock_broadcast_interval = self.subblock_broadcast_interval.ok_or_eyre(
            "subblock_broadcast_interval is required - call with_subblock_broadcast_interval()",
        )?;
        let fcu_heartbeat_interval = self.fcu_heartbeat_interval.ok_or_eyre(
            "fcu_heartbeat_interval is required - call with_fcu_heartbeat_interval()",
        )?;
        let feed_state = self
            .feed_state
            .ok_or_eyre("feed_state is required - call with_feed_state()")?;

        let epoch_length = execution_node
            .chain_spec()
            .info
            .epoch_length()
            .ok_or_eyre("chainspec did not contain epochLength; cannot go on without it")?;

        info!(
            identity = %signer.public_key(),
            "using public ed25519 verifying key derived from provided private ed25519 signing key",
        );

        let (broadcast, broadcast_mailbox) = buffered::Engine::new(
            context.with_label("broadcast"),
            buffered::Config {
                public_key: signer.public_key(),
                mailbox_size,
                deque_size,
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
            public_key: signer.public_key(),
            manager: peer_manager.clone(),
            mailbox_size,
            blocker: blocker.clone(),
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
                    partition_prefix,
                ),

                freezer_table_partition: format!(
                    "{}-{FINALIZATIONS_BY_HEIGHT}-freezer-table",
                    partition_prefix,
                ),

                freezer_table_initial_size: BLOCKS_FREEZER_TABLE_INITIAL_SIZE_BYTES,
                freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
                freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,

                freezer_key_partition: format!(
                    "{}-{FINALIZATIONS_BY_HEIGHT}-freezer-key",
                    partition_prefix,
                ),
                freezer_key_buffer_pool: buffer_pool.clone(),

                freezer_value_partition: format!(
                    "{}-{FINALIZATIONS_BY_HEIGHT}-freezer-value",
                    partition_prefix,
                ),
                freezer_value_target_size: FREEZER_VALUE_TARGET_SIZE,
                freezer_value_compression: FREEZER_VALUE_COMPRESSION,

                ordinal_partition: format!(
                    "{}-{FINALIZATIONS_BY_HEIGHT}-ordinal",
                    partition_prefix,
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
                metadata_partition: format!("{}-{FINALIZED_BLOCKS}-metadata", partition_prefix,),

                freezer_table_partition: format!(
                    "{}-{FINALIZED_BLOCKS}-freezer-table",
                    partition_prefix,
                ),

                freezer_table_initial_size: BLOCKS_FREEZER_TABLE_INITIAL_SIZE_BYTES,
                freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
                freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,

                freezer_key_partition: format!(
                    "{}-{FINALIZED_BLOCKS}-freezer-key",
                    partition_prefix,
                ),
                freezer_key_buffer_pool: buffer_pool.clone(),

                freezer_value_partition: format!(
                    "{}-{FINALIZED_BLOCKS}-freezer-value",
                    partition_prefix,
                ),
                freezer_value_target_size: FREEZER_VALUE_TARGET_SIZE,
                freezer_value_compression: FREEZER_VALUE_COMPRESSION,

                ordinal_partition: format!("{}-{FINALIZED_BLOCKS}-ordinal", partition_prefix,),
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
                partition_prefix: partition_prefix.clone(),
                mailbox_size,
                view_retention_timeout: ViewDelta::new(
                    views_to_track.saturating_mul(SYNCER_ACTIVITY_TIMEOUT_MULTIPLIER),
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
            signer: signer.clone(),
            scheme_provider: scheme_provider.clone(),
            node: execution_node.clone(),
            fee_recipient,
            time_to_build_subblock,
            subblock_broadcast_interval,
            epoch_strategy: epoch_strategy.clone(),
        });

        let (feed, feed_mailbox) = crate::feed::init(
            context.with_label("feed"),
            marshal_mailbox.clone(),
            epoch_strategy.clone(),
            feed_state,
        );

        let (executor, executor_mailbox) = crate::executor::init(
            context.with_label("executor"),
            crate::executor::Config {
                execution_node: execution_node.clone(),
                last_finalized_height,
                marshal: marshal_mailbox.clone(),
                fcu_heartbeat_interval,
            },
        )
        .wrap_err("failed initialization executor actor")?;

        let (application, application_mailbox) = application::init(super::application::Config {
            context: context.with_label("application"),
            fee_recipient,
            mailbox_size,
            marshal: marshal_mailbox.clone(),
            execution_node: execution_node.clone(),
            executor: executor_mailbox.clone(),
            new_payload_wait_time,
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
                blocker: blocker.clone(),
                buffer_pool: buffer_pool.clone(),
                epoch_strategy: epoch_strategy.clone(),
                time_for_peer_response,
                time_to_propose,
                mailbox_size,
                subblocks: subblocks.mailbox(),
                marshal: marshal_mailbox.clone(),
                feed: feed_mailbox.clone(),
                scheme_provider: scheme_provider.clone(),
                time_to_collect_notarizations,
                time_to_retry_nullify_broadcast,
                partition_prefix: format!("{}_epoch_manager", partition_prefix),
                views_to_track: ViewDelta::new(views_to_track),
                views_until_leader_skip: ViewDelta::new(views_until_leader_skip),
            },
        );

        let (dkg_manager, dkg_manager_mailbox) = dkg::manager::init(
            context.with_label("dkg_manager"),
            dkg::manager::Config {
                epoch_manager: epoch_manager_mailbox.clone(),
                epoch_strategy: epoch_strategy.clone(),
                execution_node,
                initial_share: share.clone(),
                mailbox_size,
                marshal: marshal_mailbox,
                namespace: crate::config::NAMESPACE.to_vec(),
                me: signer.clone(),
                partition_prefix: format!("{}_dkg_manager", partition_prefix),
                peer_manager: peer_manager.clone(),
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
        votes_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        certificates_network: (
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
                votes_network,
                certificates_network,
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
        votes_channel: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        certificates_channel: (
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
                .start(votes_channel, certificates_channel, resolver_channel);

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
