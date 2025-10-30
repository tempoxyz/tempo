//! [`Engine`] drives the application and is modelled after commonware's [`alto`] toy blockchain.
//!
//! [`alto`]: https://github.com/commonwarexyx/alto

use std::{
    num::{NonZeroU64, NonZeroUsize},
    time::Duration,
};

use commonware_broadcast::buffered;
use commonware_consensus::{Reporters, marshal};
use commonware_cryptography::{
    Signer as _,
    bls12381::primitives::{
        group::Share,
        poly::Poly,
        variant::{MinSig, Variant},
    },
    ed25519::{PrivateKey, PublicKey},
};
use commonware_p2p::{Blocker, Receiver, Sender};
use commonware_runtime::{
    Clock, Handle, Metrics, Network, Pacer, Spawner, Storage, buffer::PoolRef,
};
use commonware_utils::set::Ordered;
use eyre::WrapErr as _;
use futures::future::try_join_all;
use rand::{CryptoRng, Rng};
use tempo_node::TempoFullNode;

use crate::{
    config::{BACKFILL_QUOTA, BLOCKS_FREEZER_TABLE_INITIAL_SIZE_BYTES},
    consensus::application,
    dkg,
    epoch::{self, Coordinator, SchemeProvider},
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
const FREEZER_JOURNAL_TARGET_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
const FREEZER_JOURNAL_COMPRESSION: Option<u8> = Some(3);
const REPLAY_BUFFER: NonZeroUsize = NonZeroUsize::new(8 * 1024 * 1024).expect("value is not zero"); // 8MB
const WRITE_BUFFER: NonZeroUsize = NonZeroUsize::new(1024 * 1024).expect("value is not zero"); // 1MB
const BUFFER_POOL_PAGE_SIZE: NonZeroUsize = NonZeroUsize::new(4_096).expect("value is not zero"); // 4KB
const BUFFER_POOL_CAPACITY: NonZeroUsize = NonZeroUsize::new(8_192).expect("value is not zero"); // 32MB
const MAX_REPAIR: u64 = 20;

/// Settings for [`Engine`].
///
// XXX: Mostly a one-to-one copy of alto for now. We also put the context in here
// because there doesn't really seem to be a point putting it into an extra initializer.
pub struct Builder<
    TBlocker,
    TContext,
    // TODO: add the indexer. It's part of alto and we have skipped it, for now.
    // TIndexer,
> {
    /// The contextg
    pub context: TContext,

    pub fee_recipient: alloy_primitives::Address,

    pub execution_node: TempoFullNode,

    pub blocker: TBlocker,
    pub partition_prefix: String,
    pub signer: PrivateKey,
    pub polynomial: Poly<<MinSig as Variant>::Public>,
    pub share: Share,
    pub participants: Ordered<PublicKey>,
    pub mailbox_size: usize,
    pub deque_size: usize,

    pub epoch_length: u64,

    pub time_to_propose: Duration,
    pub time_to_collect_notarizations: Duration,
    pub time_to_retry_nullify_broadcast: Duration,
    pub time_for_peer_response: Duration,
    pub views_to_track: u64,
    pub views_until_leader_skip: u64,
    pub new_payload_wait_time: Duration,
}

impl<TBlocker, TContext> Builder<TBlocker, TContext>
where
    TBlocker: Blocker<PublicKey = PublicKey>,
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
    pub async fn try_init(self) -> eyre::Result<Engine<TBlocker, TContext>> {
        let (broadcast, broadcast_mailbox) = buffered::Engine::new(
            self.context.with_label("broadcast"),
            buffered::Config {
                public_key: self.signer.public_key(),
                mailbox_size: self.mailbox_size,
                deque_size: self.deque_size,
                priority: true,
                codec_config: (),
            },
        );

        let coordinator = Coordinator::new(self.participants.clone());

        // Create the buffer pool
        let buffer_pool = PoolRef::new(BUFFER_POOL_PAGE_SIZE, BUFFER_POOL_CAPACITY);

        // XXX: All hard-coded values here are the same as prior to commonware
        // making the resolver configurable in
        // https://github.com/commonwarexyz/monorepo/commit/92870f39b4a9e64a28434b3729ebff5aba67fb4e
        let resolver_config = commonware_consensus::marshal::resolver::p2p::Config {
            public_key: self.signer.public_key(),
            // FIXME(janis): this information should probably be flow from the DKG manager, since
            // the players in epoch E are the peers in epoch E+1. But `Coordinator::peers -> &[PubKey]`,
            // and so we can't pass it a mailbox.
            coordinator,
            mailbox_size: self.mailbox_size,
            requester_config: commonware_p2p::utils::requester::Config {
                public_key: self.signer.public_key(),
                rate_limit: BACKFILL_QUOTA,
                initial: Duration::from_secs(1),
                timeout: Duration::from_secs(2),
            },
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        };
        let scheme_provider = SchemeProvider::new();
        let (marshal, marshal_mailbox) = marshal::Actor::init(
            self.context.with_label("marshal"),
            marshal::Config {
                scheme_provider: scheme_provider.clone(),
                epoch_length: self.epoch_length,
                // identity: *self.polynomial.constant(),
                partition_prefix: self.partition_prefix.clone(),
                mailbox_size: self.mailbox_size,
                view_retention_timeout: self
                    .views_to_track
                    .saturating_mul(SYNCER_ACTIVITY_TIMEOUT_MULTIPLIER),
                namespace: crate::config::NAMESPACE.to_vec(),
                prunable_items_per_section: PRUNABLE_ITEMS_PER_SECTION,
                immutable_items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
                freezer_table_initial_size: BLOCKS_FREEZER_TABLE_INITIAL_SIZE_BYTES,
                freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
                freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,
                freezer_journal_target_size: FREEZER_JOURNAL_TARGET_SIZE,
                freezer_journal_compression: FREEZER_JOURNAL_COMPRESSION,

                freezer_journal_buffer_pool: buffer_pool.clone(),

                replay_buffer: REPLAY_BUFFER,
                write_buffer: WRITE_BUFFER,
                block_codec_config: (),
                max_repair: MAX_REPAIR,
                _marker: std::marker::PhantomData,
            },
        )
        .await;

        let (application, application_mailbox) = application::init(super::application::Config {
            context: self.context.with_label("application"),
            // TODO: pass in from the outside,
            fee_recipient: self.fee_recipient,
            mailbox_size: self.mailbox_size,
            marshal: marshal_mailbox.clone(),
            execution_node: self.execution_node,
            new_payload_wait_time: self.new_payload_wait_time,
            epoch_length: self.epoch_length,
        })
        .await
        .wrap_err("failed initializing application actor")?;

        let (epoch_manager, epoch_manager_mailbox) = epoch::manager::init(
            epoch::manager::Config {
                application: application_mailbox.clone(),
                blocker: self.blocker.clone(),
                buffer_pool: buffer_pool.clone(),
                epoch_length: self.epoch_length,
                time_for_peer_response: self.time_for_peer_response,
                time_to_propose: self.time_to_propose,
                mailbox_size: self.mailbox_size,
                marshal: marshal_mailbox,
                me: self.signer.clone(),
                scheme_provider,
                time_to_collect_notarizations: self.time_to_collect_notarizations,
                time_to_retry_nullify_broadcast: self.time_to_retry_nullify_broadcast,
                partition_prefix: format!("{}_epoch_manager", self.partition_prefix),
                views_to_track: self.views_to_track,
                views_until_leader_skip: self.views_until_leader_skip,
            },
            self.context.with_label("epoch_manager"),
        );

        let (dkg_manager, dkg_manager_mailbox) = dkg::manager::init(
            self.context.with_label("dkg_manager"),
            dkg::manager::Config {
                epoch_manager: epoch_manager_mailbox,
                epoch_length: self.epoch_length,
                initial_participants: self.participants.clone(),
                initial_public: self.polynomial.clone(),
                initial_share: Some(self.share.clone()),
                mailbox_size: self.mailbox_size,
                namespace: crate::config::NAMESPACE.to_vec(),
                me: self.signer.clone(),
                partition_prefix: format!("{}_dkg_manager", self.partition_prefix),
            },
        )
        .await;

        Ok(Engine {
            context: self.context,

            broadcast,
            broadcast_mailbox,

            dkg_manager,
            dkg_manager_mailbox,

            application,
            application_mailbox,

            resolver_config,
            marshal,

            epoch_manager,
        })
    }
}

pub struct Engine<TBlocker, TContext>
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
    // XXX: alto also defines an Indexer trait (not part of commonwarexyz itself); we will
    // not define it for now.
    // TIndexer,
{
    context: TContext,

    /// broadcasts messages to and caches messages from untrusted peers.
    // XXX: alto calls this `buffered`. That's confusing. We call it `broadcast`.
    broadcast: buffered::Engine<TContext, PublicKey, Block>,
    broadcast_mailbox: buffered::Mailbox<PublicKey, Block>,

    dkg_manager: dkg::manager::Actor<TContext>,
    dkg_manager_mailbox: dkg::manager::Mailbox,

    /// The core of the application, the glue between commonware-xyz consensus and reth-execution.
    application: application::Actor<TContext>,
    application_mailbox: application::Mailbox,

    /// Resolver config that will be passed to the marshal actor upon start.
    resolver_config: marshal::resolver::p2p::Config<PublicKey, Coordinator>,

    /// Listens to consensus events and syncs blocks from the network to the
    /// local node.
    marshal: crate::alias::marshal::Actor<TContext>,

    epoch_manager: epoch::manager::Actor<TBlocker, TContext>,
}

impl<TBlocker, TContext> Engine<TBlocker, TContext>
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
{
    pub fn start(
        self,
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
        backfill_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        dkg_channel: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) -> Handle<eyre::Result<()>> {
        self.context.clone().spawn(|_| {
            self.run(
                pending_network,
                recovered_network,
                resolver_network,
                broadcast_network,
                backfill_network,
                dkg_channel,
            )
        })
    }

    /// Start the `simplex` consensus engine.
    ///
    /// This will also rebuild the state of the engine from provided `Journal`.
    async fn run(
        self,
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
        backfill_network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        dkg_channel: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) -> eyre::Result<()> {
        let broadcast = self.broadcast.start(broadcast_network);
        let application = self.application.start(self.dkg_manager_mailbox.clone());

        let resolver =
            marshal::resolver::p2p::init(&self.context, self.resolver_config, backfill_network);

        let syncer = self.marshal.start(
            Reporters::from((self.application_mailbox, self.dkg_manager_mailbox)),
            self.broadcast_mailbox,
            resolver,
        );

        let epoch_manager =
            self.epoch_manager
                .start(pending_network, recovered_network, resolver_network);

        let dkg_manager = self.dkg_manager.start(dkg_channel);

        try_join_all(vec![
            application,
            broadcast,
            epoch_manager,
            syncer,
            dkg_manager,
        ])
        .await
        .map(|_| ())
        // TODO: look into adding error context so that we know which
        // component failed.
        .wrap_err("one of the consensus engine's actors failed")
    }
}
