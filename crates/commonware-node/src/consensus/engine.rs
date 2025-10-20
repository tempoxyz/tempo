//! [`Engine`] drives the application and is modelled after commonware's [`alto`] toy blockchain.
//!
//! [`alto`]: https://github.com/commonwarexyx/alto

use std::{
    num::{NonZeroU64, NonZeroUsize},
    time::Duration,
};

use commonware_broadcast::buffered;
use commonware_consensus::{marshal, threshold_simplex};
use commonware_cryptography::Signer as _;
use commonware_p2p::{Blocker, Receiver, Sender};
use commonware_runtime::{Handle, Metrics, Pacer, Spawner, Storage, buffer::PoolRef};
use eyre::WrapErr as _;
use futures::future::try_join_all;
use rand::{CryptoRng, Rng};
use tempo_commonware_node_cryptography::{
    BlsScheme, GroupShare, PrivateKey, PublicKey, PublicPolynomial,
};
use tempo_node::TempoFullNode;

use crate::config::{
    BACKFILL_QUOTA, BLOCKS_FREEZER_TABLE_INITIAL_SIZE_BYTES, NUMBER_CONCURRENT_FETCHES,
    NUMBER_MAX_FETCHES, RESOLVER_LIMIT,
};

use super::{block::Block, supervisor::Supervisor};

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
    pub polynomial: PublicPolynomial,
    pub share: GroupShare,
    pub participants: Vec<PublicKey>,
    pub mailbox_size: usize,
    pub deque_size: usize,

    pub leader_timeout: Duration,
    pub notarization_timeout: Duration,
    pub nullify_retry: Duration,
    pub fetch_timeout: Duration,
    pub activity_timeout: u64,
    pub skip_timeout: u64,
    pub new_payload_wait_time: Duration,
    // pub indexer: Option<TIndexer>,
}

impl<TBlocker, TContext> Builder<TBlocker, TContext>
where
    TBlocker: Blocker<PublicKey = PublicKey>,
    TContext: Pacer + governor::clock::Clock + Rng + CryptoRng + Spawner + Storage + Metrics,
{
    pub async fn try_init(self) -> eyre::Result<Engine<TBlocker, TContext>> {
        let supervisor = Supervisor::new(
            self.polynomial.clone(),
            self.participants.clone(),
            self.share,
        );

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

        // Create the buffer pool
        let buffer_pool = PoolRef::new(BUFFER_POOL_PAGE_SIZE, BUFFER_POOL_CAPACITY);

        // XXX: All hard-coded values here are the same as prior to commonware
        // making the resolver configurable in
        // https://github.com/commonwarexyz/monorepo/commit/92870f39b4a9e64a28434b3729ebff5aba67fb4e
        let resolver_config = commonware_consensus::marshal::resolver::p2p::Config {
            public_key: self.signer.public_key(),
            coordinator: supervisor.clone(),
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
        let (syncer, syncer_mailbox): (_, marshal::Mailbox<BlsScheme, Block>) =
            marshal::Actor::init(
                self.context.with_label("sync"),
                marshal::Config {
                    identity: *self.polynomial.constant(),
                    partition_prefix: self.partition_prefix.clone(),
                    mailbox_size: self.mailbox_size,
                    view_retention_timeout: self
                        .activity_timeout
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
                    codec_config: (),
                    max_repair: MAX_REPAIR,
                },
            )
            .await;

        let execution_driver = super::execution_driver::ExecutionDriverBuilder {
            context: self.context.with_label("execution_driver"),
            // TODO: pass in from the outside,
            fee_recipient: self.fee_recipient,
            mailbox_size: self.mailbox_size,
            syncer: syncer_mailbox.clone(),
            execution_node: self.execution_node,
            new_payload_wait_time: self.new_payload_wait_time,
            // chainspec: self.chainspec,
            // engine_handle: self.execution_engine,
            // payload_builder: self.execution_payload_builder,
        }
        .build()
        .wrap_err("failed initializing execution driver")?;

        let execution_driver_mailbox = execution_driver.mailbox().clone();

        // Create the consensus engine
        let consensus = threshold_simplex::Engine::new(
            self.context.with_label("consensus"),
            threshold_simplex::Config {
                // TODO(janis): make configuration epoch aware.
                epoch: 0,
                namespace: crate::config::NAMESPACE.to_vec(),
                crypto: self.signer,
                automaton: execution_driver.mailbox().clone(),
                relay: execution_driver.mailbox().clone(),
                // XXX: this is where the `indexer` would usually go (in alto)
                reporter: syncer_mailbox,
                supervisor,
                partition: format!("{}-consensus", self.partition_prefix),
                mailbox_size: self.mailbox_size,
                leader_timeout: self.leader_timeout,
                notarization_timeout: self.notarization_timeout,
                nullify_retry: self.nullify_retry,
                fetch_timeout: self.fetch_timeout,
                activity_timeout: self.activity_timeout,
                skip_timeout: self.skip_timeout,
                max_fetch_count: NUMBER_MAX_FETCHES,
                fetch_concurrent: NUMBER_CONCURRENT_FETCHES,
                fetch_rate_per_peer: RESOLVER_LIMIT,
                replay_buffer: REPLAY_BUFFER,
                write_buffer: WRITE_BUFFER,
                blocker: self.blocker,
                buffer_pool,
            },
        );

        Ok(Engine {
            context: self.context,

            broadcast,
            broadcast_mailbox,

            execution_driver,
            execution_driver_mailbox,

            resolver_config,
            syncer,

            consensus,
        })
    }
}

pub struct Engine<TBlocker, TContext>
where
    TBlocker: Blocker<PublicKey = PublicKey>,
    TContext: Pacer + governor::clock::Clock + Rng + CryptoRng + Spawner + Storage + Metrics,
    // XXX: alto also defines an Indexer trait (not part of commonwarexyz itself); we will
    // not define it for now.
    // TIndexer,
{
    context: TContext,

    /// broadcasts messages to and caches messages from untrusted peers.
    // XXX: alto calls this `buffered`. That's confusing. We call it `broadcast`.
    broadcast: buffered::Engine<TContext, PublicKey, Block>,
    broadcast_mailbox: buffered::Mailbox<PublicKey, Block>,

    /// The core of the application, the glue between commonware-xyz consensus and reth-execution.
    execution_driver: crate::consensus::execution_driver::ExecutionDriver<TContext>,
    execution_driver_mailbox: crate::consensus::execution_driver::ExecutionDriverMailbox,

    /// Resolver config that will be passed to the marshal actor upon start.
    resolver_config: marshal::resolver::p2p::Config<PublicKey, Supervisor>,

    /// Listens to consensus events and syncs blocks from the network to the
    /// local node.
    syncer: marshal::Actor<Block, TContext, BlsScheme>,

    consensus: crate::consensus::Consensus<TContext, TBlocker>,
}

impl<TBlocker, TContext> Engine<TBlocker, TContext>
where
    TBlocker: Blocker<PublicKey = PublicKey>,
    TContext: Pacer + governor::clock::Clock + Rng + CryptoRng + Spawner + Storage + Metrics,
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
    ) -> Handle<eyre::Result<()>> {
        self.context.clone().spawn(|_| {
            self.run(
                pending_network,
                recovered_network,
                resolver_network,
                broadcast_network,
                backfill_network,
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
    ) -> eyre::Result<()> {
        let broadcast = self.broadcast.start(broadcast_network);
        let execution_driver = self.execution_driver.start();

        let resolver =
            marshal::resolver::p2p::init(&self.context, self.resolver_config, backfill_network);
        let syncer = self.syncer.start(
            self.execution_driver_mailbox,
            self.broadcast_mailbox,
            resolver,
        );

        let simplex = self
            .consensus
            .start(pending_network, recovered_network, resolver_network);

        try_join_all(vec![broadcast, execution_driver, simplex, syncer])
            .await
            .map(|_| ())
            // TODO: look into adding error context so that we know which
            // component failed.
            .wrap_err("one of the consensus engine's actors failed")
    }
}
