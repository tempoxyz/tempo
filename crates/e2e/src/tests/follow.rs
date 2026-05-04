//! Tests for follow mode.
//!
//! These tests verify that a follower node can sync blocks from an upstream
//! node (validator or another follower) using in-process direct access.

use std::{sync::Arc, time::Duration};

use crate::{
    CONSENSUS_NODE_PREFIX, Setup, TestingNode, connect_execution_peers,
    execution_runtime::{ExecutionNode, ExecutionRuntimeHandle, test_db_args},
    setup_validators,
};
use commonware_consensus::types::FixedEpocher;
use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
use commonware_macros::test_traced;
use commonware_math::algebra::Random as _;
use commonware_runtime::{
    BufferPooler, Clock, Handle, Metrics, Pacer, Runner as _, Spawner, Storage,
    deterministic::{self, Context, Runner},
};
use commonware_utils::NZU64;
use futures::future::join_all;
use rand_core::CryptoRngCore;
use tempo_commonware_node::{feed::FeedStateHandle, follow};
use tempo_node::rpc::consensus::{ConsensusFeed as _, Query, types::Response};
use tracing::info;

static EPOCH_LENGTH: u64 = 10;

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

impl<'a, T: FeedStateProvider> FeedStateProvider for &'a T {
    fn feed_state(&self) -> FeedStateHandle {
        (*self).feed_state()
    }
}

async fn wait_for_height(context: &Context, prefix: &str, target_height: u64) {
    loop {
        let metrics = context.encode();
        for line in metrics.lines() {
            if !line.starts_with(prefix) {
                continue;
            }
            let mut parts = line.split_whitespace();
            let metric = parts.next().unwrap();
            let value = parts.next().unwrap();
            if metric.ends_with("_marshal_processed_height") {
                let height = value.parse::<u64>().unwrap();
                if height >= target_height {
                    return;
                }
            }
        }

        context.sleep(Duration::from_millis(100)).await;
    }
}

#[derive(Default)]
struct FollowerBuilder {
    name: Option<String>,
    partition_prefix: Option<String>,
    runtime: Option<ExecutionRuntimeHandle>,
    donor: Option<TestingNode<Context>>,
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

    async fn follow<TContext>(
        self,
        context: &mut TContext,
        upstream: impl FeedStateProvider,
    ) -> Follower
    where
        TContext: BufferPooler + Clock + CryptoRngCore + Metrics + Pacer + Spawner + Storage,
    {
        use tempo_commonware_node::follow::upstream::in_process;
        let Self {
            name,
            partition_prefix,
            runtime,
            donor,
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
                execution_node: Arc::new(node.node.clone()),
                feed: upstream.feed_state(),
            },
        );

        let config = follow::Config {
            execution_node: node.node.clone(),
            feed_state: feed_state.clone(),
            partition_prefix: partition_prefix.into(),
            epoch_strategy: FixedEpocher::new(NZU64!(EPOCH_LENGTH)),
            mailbox_size: 16_384,
            fcu_heartbeat_interval: Duration::from_secs(300),
            upstream,
            upstream_mailbox,
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

    fn name(&self) -> &str {
        &self.name
    }
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

        wait_for_height(&context, CONSENSUS_NODE_PREFIX, target_height).await;

        let follower = Follower::builder()
            .runtime(execution_runtime.handle())
            .follow(&mut context, &validators[0])
            .await;
        follower.connect_peers(&validators).await;

        wait_for_height(&context, &follower.name, target_height).await;

        follower.feed.get_finalization(Query::Latest).await.unwrap();

        // Follower starts only from the bootstrap point.
        let historical_cert = follower.feed.get_finalization(Query::Height(1)).await;
        let Response::Missing(..) = historical_cert else {
            panic!("shouldn't have historical certs");
        };
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
        wait_for_height(&context, CONSENSUS_NODE_PREFIX, target_height).await;

        let validator_follower = Follower::builder()
            .runtime(execution_runtime.handle())
            .follow(&mut context, &validators[0])
            .await;
        validator_follower.connect_peers(&validators).await;

        info!(
            new_follower_name = validator_follower.name(),
            "started following validator",
        );

        // Some finalization state needs to be present.
        wait_for_height(&context, &validator_follower.name(), target_height).await;

        let follower_follower = Follower::builder()
            .runtime(execution_runtime.handle())
            .follow(&mut context, &validator_follower) // <-- needs feed of follower
            .await;
        follower_follower.connect_peers(&validators).await;

        info!(
            new_follower_name = follower_follower.name(),
            "started following follower",
        );

        // Wait on the *primary*, but query the *secondary* follower. This
        // should address all race conditions between a) the secondary follower
        // starting, b) receving the finalized block, and c) propagating it to its
        // consensus feed so that it can d) be queried successfully.
        wait_for_height(&context, &validator_follower.name(), target_height * 2).await;

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
        wait_for_height(&context, &validators[0].metric_prefix(), target_height).await;

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

        wait_for_height(&context, &follower.name, follower_target_height).await;

        follower.feed.get_finalization(Query::Latest).await.unwrap();

        // With an archive, the follower syncs from that state. All historical state remains
        let historical_cert = follower.feed.get_finalization(Query::Height(1)).await;
        historical_cert.unwrap();
    });
}
