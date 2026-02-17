//! Tests for follow mode.
//!
//! These tests verify that a follower node can sync blocks from an upstream
//! node (validator or another follower) using in-process direct access.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use crate::{
    CONSENSUS_NODE_PREFIX, Setup,
    execution_runtime::{self, ExecutionNode, ExecutionRuntimeHandle},
    setup_validators, wait_for_height,
};
use commonware_consensus::types::FixedEpocher;
use commonware_macros::test_traced;
use commonware_runtime::{
    Metrics as _, Runner as _, Spawner as _,
    deterministic::{self, Runner},
};
use commonware_utils::NZU64;
use futures::future::join_all;
use reth_ethereum::network::PeersInfo as _;
use tempo_commonware_node::{
    feed::FeedStateHandle,
    follow::{self, LocalUpstream},
};
use tempo_node::rpc::consensus::{ConsensusFeed as _, Query};

static FOLLOWER_COUNTER: AtomicU32 = AtomicU32::new(0);
static EPOCH_LENGTH: u64 = 10;

fn next_follower_name() -> String {
    let id = FOLLOWER_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("follower_{id}")
}

struct Follower {
    name: String,
    feed: FeedStateHandle,
    execution_node: ExecutionNode,
}

impl Follower {
    async fn start(
        context: &deterministic::Context,
        runtime: &ExecutionRuntimeHandle,
        upstream_feed: FeedStateHandle,
        upstream_node: tempo_node::TempoFullNode,
        trusted_peers: Vec<String>,
        partition_prefix: Option<&str>,
    ) -> Self {
        let name = next_follower_name();
        let partition_prefix = partition_prefix.unwrap_or(&name);
        let feed_state = FeedStateHandle::new();

        let db_path = runtime.nodes_dir().join(&name).join("db");
        std::fs::create_dir_all(&db_path).expect("failed to create follower database directory");

        let reth_db = reth_db::init_db(db_path, execution_runtime::test_db_args());
        let database = Arc::new(reth_db.expect("reth db init"));

        let config = crate::ExecutionNodeConfig {
            secret_key: alloy_primitives::B256::random(),
            trusted_peers,
            port: 0,
            validator_key: None,
            feed_state: Some(feed_state.clone()),
        };

        let node = runtime
            .spawn_node(&name, config, database)
            .await
            .expect("must be able to spawn follower execution node");

        let engine = follow::Builder {
            execution_node: node.node.clone(),
            feed_state: feed_state.clone(),
            partition_prefix: partition_prefix.into(),
            upstream: Arc::new(LocalUpstream::new(upstream_feed, upstream_node)),
            epoch_strategy: FixedEpocher::new(NZU64!(EPOCH_LENGTH)),
            mailbox_size: 16_384,
            fcu_heartbeat_interval: Duration::from_secs(300),
        };

        let engine = engine
            .try_init(context.with_label(&name))
            .await
            .expect("failed to initialize follow engine");

        context.with_label(&name).spawn(move |_| async move {
            let _ = engine.start().await;
        });

        Self {
            name,
            feed: feed_state,
            execution_node: node,
        }
    }
}

#[test_traced]
fn follower_bootstraps_from_validator() {
    let target_height = 15;

    let setup = Setup::new().how_many_signers(4).epoch_length(EPOCH_LENGTH);
    let cfg = deterministic::Config::default().with_seed(setup.seed);

    let executor = Runner::from(cfg);
    executor.start(|mut context| async move {
        let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        let runtime = _execution_runtime.handle();
        let trusted_peers = validators
            .iter()
            .map(|v| v.execution().network.local_node_record().to_string())
            .collect::<Vec<_>>();

        // -- Follower syncs from validator 2.
        let validator_feed_state = validators[0].consensus_config.feed_state.clone();
        let validator_full_node = validators[0].execution().clone();

        wait_for_height(&context, CONSENSUS_NODE_PREFIX, target_height).await;

        let follower = Follower::start(
            &context,
            &runtime,
            validator_feed_state,
            validator_full_node,
            trusted_peers,
            None,
        )
        .await;

        wait_for_height(&context, &follower.name, target_height).await;

        let cert = follower.feed.get_finalization(Query::Latest).await;
        assert!(cert.is_some());

        // Follower starts only from the bootstrap point.
        let historical_cert = follower.feed.get_finalization(Query::Height(1)).await;
        assert!(historical_cert.is_none());
    });
}

#[test_traced]
fn follower_bootstraps_from_follower() {
    let target_height = 15;

    let setup = Setup::new().how_many_signers(4).epoch_length(EPOCH_LENGTH);
    let cfg = deterministic::Config::default().with_seed(setup.seed);

    let executor = Runner::from(cfg);
    executor.start(|mut context| async move {
        let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        let runtime = _execution_runtime.handle();
        let trusted_peers = validators
            .iter()
            .map(|v| v.execution().network.local_node_record().to_string())
            .collect::<Vec<_>>();

        // -- Follower1 syncs from validator 1.
        let validator_feed_state = validators[0].consensus_config.feed_state.clone();
        let validator_full_node = validators[0].execution().clone();

        let follower1 = Follower::start(
            &context,
            &runtime,
            validator_feed_state,
            validator_full_node,
            trusted_peers.clone(),
            None,
        )
        .await;

        // -- Follower2 syncs from follower 1.
        let follower2 = Follower::start(
            &context,
            &runtime,
            follower1.feed.clone(),
            follower1.execution_node.node.clone(),
            trusted_peers,
            None,
        )
        .await;

        wait_for_height(&context, &follower2.name, target_height).await;

        let cert = follower2.feed.get_finalization(Query::Latest).await;
        assert!(cert.is_some());
    });
}

#[test_traced]
fn follower_starts_from_validator_archives() {
    let target_height = 15;
    let follower_target_height = target_height + 5;

    let setup = Setup::new().how_many_signers(4).epoch_length(EPOCH_LENGTH);
    let cfg = deterministic::Config::default().with_seed(setup.seed);

    let executor = Runner::from(cfg);
    executor.start(|mut context| async move {
        let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        let runtime = _execution_runtime.handle();
        let trusted_peers = validators
            .iter()
            .map(|v| v.execution().network.local_node_record().to_string())
            .collect::<Vec<_>>();

        wait_for_height(&context, CONSENSUS_NODE_PREFIX, target_height).await;

        // Let's stop the validator and start the follower from its archive. Block production
        // continues with 3/4 validators. Much easier than copying archives around.
        let validator_partition = validators[0].uid.clone();
        validators[0].stop_consensus().await;

        // -- Follower syncs from validator 1.
        let upstream_feed = validators[1].consensus_config.feed_state.clone();
        let upstream_node = validators[1].execution().clone();

        let follower = Follower::start(
            &context,
            &runtime,
            upstream_feed,
            upstream_node,
            trusted_peers,
            Some(&validator_partition),
        )
        .await;

        wait_for_height(&context, &follower.name, follower_target_height).await;

        let cert = follower.feed.get_finalization(Query::Latest).await;
        assert!(cert.is_some());

        // With an archive, the follower syncs from that state.
        let historical_cert = follower.feed.get_finalization(Query::Height(1)).await;
        assert!(historical_cert.is_some());
    });
}
