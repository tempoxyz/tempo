//! Tests for follow mode.
//!
//! These tests verify that a follower node can sync blocks from an upstream
//! node (validator or another follower) using in-process direct access.

use std::{
    num::NonZeroU64,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use crate::{
    Setup, TestingNode, connect_execution_peers,
    execution_runtime::{ExecutionNode, ExecutionRuntimeHandle, test_db_args},
    metrics::{MetricScope, MetricsExt, wait_for_height},
    setup_validators,
};
use commonware_consensus::types::FixedEpocher;
use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
use commonware_macros::test_traced;
use commonware_math::algebra::Random as _;
use commonware_runtime::{
    BufferPooler, Clock, Handle, Metrics as RuntimeMetrics, Pacer, Runner as _, Spawner, Storage,
    deterministic::{self, Context, Runner},
};
use commonware_utils::NZU64;
use futures::future::join_all;
use rand_core::CryptoRngCore;
use tempo_consensus::{feed::FeedStateHandle, follow};
use tempo_node::rpc::consensus::{ConsensusFeed as _, Query, types::Response};
use tracing::{Event, Subscriber, field::Visit};
use tracing_subscriber::{
    EnvFilter, Layer,
    layer::{Context as LayerContext, SubscriberExt},
    registry::LookupSpan,
};

static EPOCH_LENGTH: u64 = 10;
const DEFAULT_FINALIZED_BLOCKS_ITEMS_PER_SECTION: NonZeroU64 = NZU64!(4_096);

trait FeedStateProvider {
    fn feed_state(&self) -> FeedStateHandle;
}

impl<TContext: Clock> FeedStateProvider for TestingNode<TContext> {
    fn feed_state(&self) -> FeedStateHandle {
        self.consensus_config.feed_state.clone()
    }
}

impl FeedStateProvider for Follower {
    fn feed_state(&self) -> FeedStateHandle {
        self.feed.clone()
    }
}

impl<T: FeedStateProvider> FeedStateProvider for &T {
    fn feed_state(&self) -> FeedStateHandle {
        (*self).feed_state()
    }
}

#[derive(Default)]
struct FollowerBuilder {
    name: Option<String>,
    partition_prefix: Option<String>,
    runtime: Option<ExecutionRuntimeHandle>,
    donor: Option<TestingNode<Context>>,
    epoch_length: Option<u64>,
    finalized_blocks_retention: Option<u64>,
    finalized_blocks_items_per_section: Option<NonZeroU64>,
}

impl FollowerBuilder {
    fn new() -> Self {
        Self::default()
    }

    fn runtime(self, runtime: ExecutionRuntimeHandle) -> Self {
        Self {
            runtime: Some(runtime),
            ..self
        }
    }

    /// Fully consume a stopped validator and donate its consensus partition
    /// (`uid`) and execution-layer state to the follower being built.
    ///
    /// The donor must already be stopped; both `consensus_handle` and
    /// `execution_node` must be `None`.
    fn donor(self, donor: TestingNode<Context>) -> Self {
        assert!(
            donor.consensus_handle.is_none(),
            "donor consensus must be stopped before donation"
        );
        assert!(
            donor.execution_node.is_none(),
            "donor execution must be stopped before donation"
        );

        Self {
            partition_prefix: Some(donor.uid.clone()),
            donor: Some(donor),
            ..self
        }
    }

    fn epoch_length(self, epoch_length: u64) -> Self {
        Self {
            epoch_length: Some(epoch_length),
            ..self
        }
    }

    fn finalized_blocks_retention(self, finalized_blocks_retention: u64) -> Self {
        Self {
            finalized_blocks_retention: Some(finalized_blocks_retention),
            ..self
        }
    }

    fn finalized_blocks_items_per_section(
        self,
        finalized_blocks_items_per_section: NonZeroU64,
    ) -> Self {
        Self {
            finalized_blocks_items_per_section: Some(finalized_blocks_items_per_section),
            ..self
        }
    }

    async fn follow<TContext>(
        self,
        context: &mut TContext,
        upstream: impl FeedStateProvider,
    ) -> Follower
    where
        TContext: BufferPooler + Clock + CryptoRngCore + RuntimeMetrics + Pacer + Spawner + Storage,
    {
        use tempo_consensus::follow::upstream::in_process;
        let Self {
            name,
            partition_prefix,
            runtime,
            donor,
            epoch_length,
            finalized_blocks_retention,
            finalized_blocks_items_per_section,
        } = self;
        let runtime = runtime.expect("must pass a runtime handle to start a follower");

        let name = name.unwrap_or_else(|| {
            format!(
                "follower_{}",
                PrivateKey::random(&mut *context).public_key()
            )
        });

        let partition_prefix = partition_prefix.unwrap_or_else(|| name.clone());
        let feed_state = FeedStateHandle::new();

        let config = crate::ExecutionNodeConfig {
            secret_key: alloy_primitives::B256::random(),
            validator_key: None,
            feed_state: Some(feed_state.clone()),
            share_sparse_trie_with_payload_builder: false,
        };

        let (spawn_name, db, rocksdb) = if let Some(donor) = donor {
            (
                donor.execution_node_name,
                donor
                    .execution_database
                    .expect("donor must have an execution database"),
                donor.execution_rocksdb,
            )
        } else {
            let db_path = runtime.nodes_dir().join(&name).join("db");
            std::fs::create_dir_all(&db_path)
                .expect("failed to create follower database directory");
            let db = reth_db::init_db(db_path, test_db_args()).expect("reth db init");
            (name.clone(), db, None)
        };

        let node = runtime
            .spawn_node(&spawn_name, config, db, rocksdb)
            .await
            .expect("must be able to spawn follower execution node");

        let (upstream, upstream_mailbox) = in_process::init(
            context.with_label("upstream"),
            in_process::Config {
                execution_node: node.node.clone().into(),
                feed: upstream.feed_state(),
            },
        );

        let network_identity = node
            .node
            .chain_spec()
            .network_identity
            .clone()
            .expect("no genesis network identity");

        let config = follow::Config {
            network_identity,
            upstream,
            upstream_mailbox,
            execution_node: node.node.clone().into(),
            feed_state: feed_state.clone(),
            partition_prefix,
            epoch_strategy: FixedEpocher::new(NZU64!(epoch_length.unwrap_or(EPOCH_LENGTH))),
            mailbox_size: 16_384,
            fcu_heartbeat_interval: Duration::from_secs(300),
            // Plenty of headroom for any test; the marshal will fall back to
            // reth past this depth via the hybrid finalized blocks store.
            finalized_blocks_retention: finalized_blocks_retention.unwrap_or(1024),
            finalized_blocks_items_per_section: finalized_blocks_items_per_section
                .unwrap_or(DEFAULT_FINALIZED_BLOCKS_ITEMS_PER_SECTION),
            strict_startup: true,
        };

        let handle = config
            .try_init(context.with_label(&name))
            .await
            .expect("failed to initialize follow engine")
            .start();

        Follower {
            name,
            feed: feed_state,
            execution_node: node,
            _handle: handle,
        }
    }
}

struct Follower {
    name: String,
    feed: FeedStateHandle,
    execution_node: ExecutionNode,
    _handle: Handle<eyre::Result<()>>,
}

impl Follower {
    fn builder() -> FollowerBuilder {
        FollowerBuilder::new()
    }

    async fn connect_peers<T: Clock>(&self, peers: &[TestingNode<T>]) {
        for peer in peers {
            if let Some(execution_node) = &peer.execution_node {
                self.execution_node.connect_peer(execution_node).await;
            }
        }
    }
}

impl MetricScope for Follower {
    fn metric_prefix(&self) -> String {
        self.name.clone()
    }
}

/// Polls the feed until `query` resolves successfully.
///
/// The follower's archives fill in asynchronously via marshal's gap repair,
/// so finalizations below the follower's join point become available only
/// once backfill catches up.
async fn wait_for_finalization<TContext: Clock>(
    context: &TContext,
    feed: &FeedStateHandle,
    query: Query,
) {
    while !matches!(
        feed.get_finalization(query.clone()).await,
        Response::Success(..)
    ) {
        context.sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_execution_finalized_bounded<TContext: Clock>(
    context: &TContext,
    follower: &Follower,
    target_height: u64,
    attempts: usize,
) -> bool {
    for _ in 0..attempts {
        let finalized_height = follower
            .execution_node
            .node
            .provider
            .canonical_in_memory_state()
            .get_finalized_num_hash()
            .map_or(0, |num_hash| num_hash.number);
        if finalized_height >= target_height {
            return true;
        }
        context.sleep(Duration::from_millis(100)).await;
    }
    false
}

async fn wait_for_consensus_height_bounded<TContext: Clock + RuntimeMetrics>(
    context: &TContext,
    scope: &impl MetricScope,
    target_height: u64,
    attempts: usize,
) -> bool {
    for _ in 0..attempts {
        if context
            .to_metrics()
            .for_scope(scope)
            .consensus_at_height(target_height)
            > 0
        {
            return true;
        }
        context.sleep(Duration::from_millis(100)).await;
    }
    false
}

struct HybridNoopPutDetector {
    threshold: usize,
    count: Arc<AtomicUsize>,
}

impl<S> Layer<S> for HybridNoopPutDetector
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: LayerContext<'_, S>) {
        if event.metadata().target() != "tempo_consensus::storage::hybrid" {
            return;
        }

        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let Some(message) = visitor.message else {
            return;
        };

        if !message.contains("finalized block below prunable cache window") {
            return;
        }

        let count = self.count.fetch_add(1, Ordering::Relaxed) + 1;
        assert!(
            count <= self.threshold,
            "marshal/hybrid gap repair livelock: observed {count} finalized-block puts below the \
            hybrid prunable cache window"
        );
    }
}

#[derive(Default)]
struct MessageVisitor {
    message: Option<String>,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}"));
        }
    }
}

fn with_hybrid_noop_put_detector(threshold: usize, f: impl FnOnce()) {
    let subscriber = tracing_subscriber::Registry::default()
        .with(EnvFilter::new(
            "warn,tempo_consensus::storage::hybrid=debug",
        ))
        .with(HybridNoopPutDetector {
            threshold,
            count: Arc::new(AtomicUsize::new(0)),
        });
    let dispatcher = tracing::Dispatch::new(subscriber);

    tracing::dispatcher::with_default(&dispatcher, f);
}

#[test_traced]
fn follower_bootstraps_from_validator() {
    let _ = tempo_eyre::install();

    let target_height = 15;

    let setup = Setup::new().how_many_signers(1).epoch_length(EPOCH_LENGTH);
    let cfg = deterministic::Config::default().with_seed(setup.seed);

    let executor = Runner::from(cfg);
    executor.start(|mut context| async move {
        let (mut validators, execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        wait_for_height(&context, &validators[0], target_height).await;

        let follower = Follower::builder()
            .runtime(execution_runtime.handle())
            .follow(&mut context, &validators[0])
            .await;

        follower.connect_peers(&validators).await;

        wait_for_height(&context, &follower, target_height).await;

        follower.feed.get_finalization(Query::Latest).await.unwrap();

        // The marshal floor only advances with actually processed blocks, so
        // the follower backfills the gap between its startup floor (genesis
        // for a fresh node) and the join point via gap repair.
        wait_for_finalization(&context, &follower.feed, Query::Height(1)).await;
    });
}

#[test]
fn follower_backfills_after_reth_finalizes_beyond_hybrid_window() {
    let _ = tempo_eyre::install();

    with_hybrid_noop_put_detector(256, || {
        let target_height = 128;
        let epoch_length = 256;
        let setup = Setup::new().how_many_signers(1).epoch_length(epoch_length);
        let cfg = deterministic::Config::default().with_seed(setup.seed);

        let executor = Runner::from(cfg);
        executor.start(|mut context| async move {
            let (mut validators, execution_runtime) = setup_validators(&mut context, setup).await;
            join_all(validators.iter_mut().map(|v| v.start(&context))).await;

            wait_for_height(&context, &validators[0], target_height).await;

            let follower = Follower::builder()
                .runtime(execution_runtime.handle())
                .epoch_length(epoch_length)
                .finalized_blocks_retention(1)
                .finalized_blocks_items_per_section(NZU64!(8))
                .follow(&mut context, &validators[0])
                .await;

            follower.connect_peers(&validators).await;

            assert!(
                wait_for_execution_finalized_bounded(&context, &follower, target_height, 200).await,
                "follower execution layer did not finalize to the join point"
            );

            // Ensure at least one post-catch-up finalization event arrives. On
            // the old prunable-only gap-tracking path, that event drove a
            // Hybrid::put that evicted the tiny archive below reth's finalized
            // watermark and exposed the repair livelock. The detector above
            // turns any recurrence into a quick failing test.
            wait_for_height(&context, &validators[0], target_height + 2).await;

            assert!(
                wait_for_consensus_height_bounded(&context, &follower, target_height, 200).await,
                "follower marshal did not dispatch backfilled blocks after reth finalized beyond \
                the hybrid cache window"
            );
        });
    });
}

#[test_traced]
fn follower_backfills_historical_boundaries() {
    let _ = tempo_eyre::install();

    let start_height = 2 * EPOCH_LENGTH + 1;
    let follower_target_height = start_height + 1;

    let setup = Setup::new().how_many_signers(1).epoch_length(EPOCH_LENGTH);
    let cfg = deterministic::Config::default().with_seed(setup.seed);

    let executor = Runner::from(cfg);
    executor.start(|mut context| async move {
        let (mut validators, execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        wait_for_height(&context, &validators[0], start_height).await;

        let follower = Follower::builder()
            .runtime(execution_runtime.handle())
            .follow(&mut context, &validators[0])
            .await;

        follower.connect_peers(&validators).await;

        wait_for_height(&context, &follower, follower_target_height).await;
        wait_for_finalization(&context, &follower.feed, Query::Latest).await;

        // The follower joined past two epoch boundaries; gap repair backfills
        // them (blocks and certificates) down to the startup floor.
        let epoch_0_boundary = EPOCH_LENGTH - 1;
        let epoch_1_boundary = 2 * EPOCH_LENGTH - 1;
        for boundary in [epoch_0_boundary, epoch_1_boundary] {
            wait_for_finalization(&context, &follower.feed, Query::Height(boundary)).await;
        }
    });
}

#[test_traced]
fn follower_reads_boundaries_after_full_dkg() {
    let _ = tempo_eyre::install();

    let full_dkg_epoch = 1;
    let start_height = 2 * EPOCH_LENGTH + 1;
    let follower_target_height = start_height + 1;

    let setup = Setup::new().how_many_signers(1).epoch_length(EPOCH_LENGTH);
    let cfg = deterministic::Config::default().with_seed(setup.seed);

    let executor = Runner::from(cfg);
    executor.start(|mut context| async move {
        let (mut validators, execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        let http_url = validators[0]
            .execution()
            .rpc_server_handle()
            .http_url()
            .unwrap()
            .parse()
            .unwrap();

        execution_runtime
            .set_next_full_dkg_ceremony_v2(http_url, full_dkg_epoch)
            .await
            .unwrap();

        wait_for_height(&context, &validators[0], start_height).await;
        context.to_metrics().assert_no_dkg_failures();

        let follower = Follower::builder()
            .runtime(execution_runtime.handle())
            .follow(&mut context, &validators[0])
            .await;
        follower.connect_peers(&validators).await;

        wait_for_height(&context, &follower, follower_target_height).await;

        // After the full DKG rotated the network identity, the follower can
        // only verify (and thus feed) tip finalizations once dispatch has
        // caught up to the boundary block carrying the rotated identity, so
        // poll rather than assert immediately.
        wait_for_finalization(&context, &follower.feed, Query::Latest).await;

        let epoch_0_boundary = EPOCH_LENGTH - 1;
        let epoch_1_boundary = 2 * EPOCH_LENGTH - 1;
        for boundary in [epoch_0_boundary, epoch_1_boundary] {
            wait_for_finalization(&context, &follower.feed, Query::Height(boundary)).await;
        }
    });
}

#[test_traced]
fn follower_bootstraps_from_follower() {
    let _ = tempo_eyre::install();

    let target_height = 15;

    let setup = Setup::new().how_many_signers(1).epoch_length(EPOCH_LENGTH);
    let cfg = deterministic::Config::default().with_seed(setup.seed);

    let executor = Runner::from(cfg);
    executor.start(|mut context| async move {
        let (mut validators, execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        // Some finalization state needs to be present.
        wait_for_height(&context, &validators[0], target_height).await;

        let validator_follower = Follower::builder()
            .runtime(execution_runtime.handle())
            .follow(&mut context, &validators[0])
            .await;
        validator_follower.connect_peers(&validators).await;

        // Some finalization state needs to be present.
        wait_for_height(&context, &validator_follower, target_height).await;

        let follower_follower = Follower::builder()
            .runtime(execution_runtime.handle())
            .follow(&mut context, &validator_follower) // <-- needs feed of follower
            .await;
        follower_follower.connect_peers(&validators).await;

        // Wait on the *primary*, but query the *secondary* follower. This
        // should address all race conditions between a) the secondary follower
        // starting, b) receving the finalized block, and c) propagating it to its
        // consensus feed so that it can d) be queried successfully.
        wait_for_height(&context, &validator_follower, target_height * 2).await;

        follower_follower
            .feed
            .get_finalization(Query::Latest)
            .await
            .unwrap();
    });
}

#[test_traced]
fn follower_starts_from_validator_archives() {
    let _ = tempo_eyre::install();
    let target_height = 15;
    let follower_target_height = target_height + 5;

    let setup = Setup::new().how_many_signers(4).epoch_length(EPOCH_LENGTH);
    let cfg = deterministic::Config::default().with_seed(setup.seed);

    let executor = Runner::from(cfg);
    executor.start(|mut context| async move {
        let (mut validators, execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(validators.iter_mut().map(|v| v.start(&context))).await;
        connect_execution_peers(&validators).await;

        // Wait for validator[0] specifically since we'll donate its archive.
        wait_for_height(&context, &validators[0], target_height).await;

        // Stop validator[0] and donate both its consensus archive and EL chaindata
        // to the follower. Block production continues with 3/4 validators.
        let mut donor = validators.remove(0);
        donor.stop().await;

        let follower = Follower::builder()
            .runtime(execution_runtime.handle())
            .donor(donor)
            .follow(&mut context, &validators[0])
            .await;
        follower.connect_peers(&validators).await;

        wait_for_height(&context, &follower, follower_target_height).await;

        follower.feed.get_finalization(Query::Latest).await.unwrap();

        // With an archive, the follower syncs from that state. All historical state remains
        let historical_cert = follower.feed.get_finalization(Query::Height(1)).await;
        historical_cert.unwrap();
    });
}
