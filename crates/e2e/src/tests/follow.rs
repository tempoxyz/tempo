//! Tests for follow mode.
//!
//! These tests verify that a follower node can sync blocks from an upstream
//! node (validator or another follower) using in-process direct access.

use std::{
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use crate::{
    CONSENSUS_NODE_PREFIX, ExecutionRuntime, Setup, TestingNode,
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
use tempo_node::rpc::consensus::{ConsensusFeed as _, Query};

static FOLLOWER_COUNTER: AtomicU32 = AtomicU32::new(0);
static EPOCH_LENGTH: u64 = 10;

fn next_follower_name() -> String {
    let id = FOLLOWER_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("follower_{id}")
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

    fn partition_prefix(self, partition_prefix: &str) -> Self {
        Self {
            partition_prefix: Some(partition_prefix.into()),
            ..self
        }
    }

    fn name(self, name: &str) -> Self {
        Self {
            name: Some(name.into()),
            ..self
        }
    }

    async fn follow<TContext>(
        self,
        context: &mut TContext,
        validator: &TestingNode<TContext>,
    ) -> Follower
    where
        TContext: BufferPooler + Clock + CryptoRngCore + Metrics + Pacer + Spawner + Storage,
    {
        let Self {
            name,
            partition_prefix,
            runtime,
        } = self;
        let runtime = runtime.expect("must pass a runtime handle to start a follower");
        let websocket_addr = validator
            .execution()
            .rpc_server_handles
            .rpc
            .ws_local_addr()
            .unwrap();

        let name = name.unwrap_or_else(|| {
            format!(
                "follower_{}",
                PrivateKey::random(&mut *context).public_key()
            )
        });
        let partition_prefix = partition_prefix.unwrap_or_else(|| name.clone());

        let feed_state = FeedStateHandle::new();
        let db_path = runtime.nodes_dir().join(&name).join("db");
        std::fs::create_dir_all(&db_path).expect("failed to create follower database directory");
        let db = reth_db::init_db(db_path, test_db_args()).expect("reth db init");

        let config = crate::ExecutionNodeConfig {
            secret_key: alloy_primitives::B256::random(),
            validator_key: None,
            feed_state: Some(feed_state.clone()),
        };

        let node = runtime
            .spawn_node(&name, config, db, None)
            .await
            .expect("must be able to spawn follower execution node");

        let config = follow::Config {
            execution_node: node.node.clone(),
            feed_state: feed_state.clone(),
            partition_prefix: partition_prefix.into(),
            upstream_url: format!("ws://{websocket_addr}"),
            epoch_strategy: FixedEpocher::new(NZU64!(EPOCH_LENGTH)),
            mailbox_size: 16_384,
            fcu_heartbeat_interval: Duration::from_secs(300),
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
            handle,
        }
    }
}

struct Follower {
    name: String,
    feed: FeedStateHandle,
    execution_node: ExecutionNode,
    handle: Handle<eyre::Result<()>>,
}

impl Follower {
    fn builder() -> FollowerBuilder {
        FollowerBuilder::default()
    }

    async fn connect_peers<T: Clock>(&self, peers: &[TestingNode<T>]) {
        for peer in peers {
            if let Some(execution_node) = &peer.execution_node {
                self.execution_node.connect_peer(execution_node).await;
            }
        }
    }

    async fn start(
        context: &deterministic::Context,
        runtime: &ExecutionRuntimeHandle,
        upstream_url: String,
        partition_prefix: Option<&str>,
        trusted_peers: Vec<&ExecutionNode>,
    ) -> Self {
        let name = next_follower_name();
        let partition_prefix = partition_prefix.unwrap_or(&name);
        let feed_state = FeedStateHandle::new();

        let db_path = runtime.nodes_dir().join(&name).join("db");
        std::fs::create_dir_all(&db_path).expect("failed to create follower database directory");

        let db = reth_db::init_db(db_path, test_db_args()).expect("reth db init");

        let config = crate::ExecutionNodeConfig {
            secret_key: alloy_primitives::B256::random(),
            validator_key: None,
            feed_state: Some(feed_state.clone()),
        };

        let node = runtime
            .spawn_node(&name, config, db, None)
            .await
            .expect("must be able to spawn follower execution node");

        for peer in trusted_peers {
            node.connect_peer(peer).await;
        }

        let config = follow::Config {
            execution_node: node.node.clone(),
            feed_state: feed_state.clone(),
            partition_prefix: partition_prefix.into(),
            upstream_url,
            epoch_strategy: FixedEpocher::new(NZU64!(EPOCH_LENGTH)),
            mailbox_size: 16_384,
            fcu_heartbeat_interval: Duration::from_secs(300),
        };

        let handle = config
            .try_init(context.with_label(&name))
            .await
            .expect("failed to initialize follow engine")
            .start();

        Self {
            name,
            feed: feed_state,
            execution_node: node,
            handle,
        }
    }
}

#[test_traced]
fn follower_bootstraps_from_validator() {
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

        let cert = follower.feed.get_finalization(Query::Latest).await;
        assert!(cert.is_some());

        // Follower starts only from the bootstrap point.
        let historical_cert = follower.feed.get_finalization(Query::Height(1)).await;
        assert!(historical_cert.is_none());
    });
}

// #[test_traced]
// fn follower_bootstraps_from_follower() {
//     let target_height = 15;

//     let setup = Setup::new().how_many_signers(4).epoch_length(EPOCH_LENGTH);
//     let cfg = deterministic::Config::default().with_seed(setup.seed);

//     let executor = Runner::from(cfg);
//     executor.start(|mut context| async move {
//         let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
//         join_all(validators.iter_mut().map(|v| v.start(&context))).await;

//         let runtime = _execution_runtime.handle();
//         let trusted_peers = validators
//             .iter()
//             .map(|v| v.execution_node.as_ref().unwrap())
//             .collect::<Vec<_>>();

//         let local_ws_addr = validators[0]
//             .execution()
//             .rpc_server_handles
//             .rpc
//             .ws_local_addr()
//             .unwrap();

//         // Some finalization state needs to be present.
//         wait_for_height(&context, CONSENSUS_NODE_PREFIX, target_height).await;

//         let follower1 = Follower::start(
//             &context,
//             &runtime,
//             format!("ws://{local_ws_addr}"),
//             None,
//             trusted_peers.clone(),
//         )
//         .await;

//         // Some finalization state needs to be present.
//         wait_for_height(&context, &follower1.name, target_height).await;

//         todo!("follower 2 should follow follower 1")
//         // // -- Follower2 syncs from follower 1.
//         // let follower2 = Follower::start(
//         //     &context,
//         //     &runtime,
//         //     follower1.feed.clone(),
//         //     follower1.execution_node.node.clone(),
//         //     None,
//         //     trusted_peers,
//         // )
//         // .await;

//         // wait_for_height(&context, &follower2.name, target_height).await;

//         // let cert = follower2.feed.get_finalization(Query::Latest).await;
//         // assert!(cert.is_some());
//     });
// }

// #[test_traced]
// fn follower_starts_from_validator_archives() {
//     let target_height = 15;
//     let follower_target_height = target_height + 5;

//     let setup = Setup::new().how_many_signers(4).epoch_length(EPOCH_LENGTH);
//     let cfg = deterministic::Config::default().with_seed(setup.seed);

//     let executor = Runner::from(cfg);
//     executor.start(|mut context| async move {
//         let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
//         join_all(validators.iter_mut().map(|v| v.start(&context))).await;

//         let runtime = _execution_runtime.handle();

//         // Wait for validator[0] specifically since we'll reuse its archive.
//         wait_for_height(&context, &validators[0].metric_prefix(), target_height).await;

//         // Let's stop the validator and start the follower from its archive. Block production
//         // continues with 3/4 validators. Much easier than copying archives around.
//         let validator_partition = validators[0].uid.clone();
//         validators[0].stop().await;

//         let local_ws_addr = validators[1]
//             .execution()
//             .rpc_server_handles
//             .rpc
//             .ws_local_addr()
//             .unwrap();

//         let trusted_peers = validators[1..]
//             .iter()
//             .map(|v| v.execution_node.as_ref().unwrap())
//             .collect::<Vec<_>>();

//         let follower = Follower::start(
//             &context,
//             &runtime,
//             format!("ws://{local_ws_addr}"),
//             Some(&validator_partition),
//             trusted_peers,
//         )
//         .await;

//         wait_for_height(&context, &follower.name, follower_target_height).await;

//         let cert = follower.feed.get_finalization(Query::Latest).await;
//         assert!(cert.is_some());

//         // With an archive, the follower syncs from that state. All historical state remains
//         let historical_cert = follower.feed.get_finalization(Query::Height(1)).await;
//         assert!(historical_cert.is_some());
//     });
// }
