//! e2e tests using the [`commonware_runtime::deterministic`].
//!
//! This crate mimics how a full tempo node is run in production but runs the
//! consensus engine in a deterministic runtime while maintaining a tokio
//! async environment to launch execution nodes.
//!
//! All definitions herein are only intended to support the the tests defined
//! in tests/.

use std::{net::SocketAddr, time::Duration};

use commonware_cryptography::{
    PrivateKeyExt as _, Signer as _,
    bls12381::{dkg::ops, primitives::variant::MinSig},
    ed25519::{PrivateKey, PublicKey},
};
use commonware_p2p::{
    Manager as _,
    simulated::{self, Control, Link, Network, Oracle, SocketManager},
};

use commonware_runtime::{
    Clock, Handle, Metrics as _, Runner as _,
    deterministic::{self, Context, Runner},
};
use commonware_utils::{quorum, set::OrderedAssociated};
use futures::future::join_all;
use itertools::Itertools as _;
use reth_node_metrics::recorder::PrometheusRecorder;
use tempo_commonware_node::consensus;
use tracing::debug;

pub mod execution_runtime;
// pub mod genesis;
pub use execution_runtime::ExecutionRuntime;

use crate::execution_runtime::ExecutionNode;

#[cfg(test)]
mod tests;

pub const CONSENSUS_NODE_PREFIX: &str = "consensus";
pub const EXECUTION_NODE_PREFIX: &str = "execution";

/// A Tempo node with lazily started consensus engine.
pub struct PreparedNode {
    pub uid: String,

    /// Execution-layer node. Spawned in the background but won't progress unless consensus engine is started.
    pub execution_node: ExecutionNode,

    /// Public key of the validator.
    pub public_key: PublicKey,

    pub consensus_config: consensus::Builder<Control<PublicKey>, Context, SocketManager<PublicKey>>,

    pub oracle: simulated::Oracle<PublicKey>,
}

impl PreparedNode {
    pub async fn start(self) -> RunningNode {
        let Self {
            uid,
            execution_node,
            public_key,
            consensus_config,
            oracle,
        } = self;
        let engine = consensus_config
            .clone()
            .try_init()
            .await
            .expect("must be able to start the engine");
        let pending = oracle
            .control(public_key.clone())
            .register(0)
            .await
            .unwrap();
        let recovered = oracle
            .control(public_key.clone())
            .register(1)
            .await
            .unwrap();
        let resolver = oracle
            .control(public_key.clone())
            .register(2)
            .await
            .unwrap();
        let broadcast = oracle
            .control(public_key.clone())
            .register(3)
            .await
            .unwrap();
        let marshal = oracle
            .control(public_key.clone())
            .register(4)
            .await
            .unwrap();
        let dkg = oracle
            .control(public_key.clone())
            .register(5)
            .await
            .unwrap();
        let boundary_certs = oracle
            .control(public_key.clone())
            .register(6)
            .await
            .unwrap();
        let subblocks = oracle
            .control(public_key.clone())
            .register(7)
            .await
            .unwrap();

        let consensus_handle = engine.start(
            pending,
            recovered,
            resolver,
            broadcast,
            marshal,
            dkg,
            boundary_certs,
            subblocks,
        );

        debug!(%uid, "started validator");

        RunningNode {
            uid,
            consensus_config,
            consensus_handle,
            execution_node,
            public_key,
            oracle,
        }
    }
}

/// A Tempo node with lazily started consensus engine.
pub struct RunningNode {
    pub uid: String,

    pub consensus_config: consensus::Builder<Control<PublicKey>, Context, SocketManager<PublicKey>>,
    pub consensus_handle: Handle<eyre::Result<()>>,

    /// Execution-layer node. Spawned in the background but won't progress unless consensus engine is started.
    pub execution_node: ExecutionNode,

    /// Public key of the validator.
    pub public_key: PublicKey,

    pub oracle: simulated::Oracle<PublicKey>,
}

impl RunningNode {
    pub fn stop(self) -> PreparedNode {
        let Self {
            uid,
            execution_node,
            public_key,
            oracle,
            consensus_config,
            consensus_handle,
        } = self;
        consensus_handle.abort();
        PreparedNode {
            uid,
            execution_node,
            public_key,
            consensus_config,
            oracle,
        }
    }
}

/// The test setup run by [`run`].
#[derive(Clone)]
pub struct Setup {
    /// How many signing validators to launch.
    pub how_many_signers: u32,

    /// The seed used for setting up the deterministic runtime.
    pub seed: u64,
    /// The linkage between individual validators.
    pub linkage: Link,
    /// The number of heights in an epoch.
    pub epoch_length: u64,

    pub connect_execution_layer_nodes: bool,
}

pub async fn setup_validators(
    mut context: Context,
    execution_runtime: &ExecutionRuntime,
    Setup {
        how_many_signers,
        seed,
        epoch_length,
        connect_execution_layer_nodes,
        ..
    }: Setup,
) -> (Vec<PreparedNode>, simulated::Oracle<PublicKey>) {
    let (network, oracle) = Network::new(
        context.with_label("network"),
        simulated::Config {
            max_size: 1024 * 1024,
            disconnect_on_block: true,
            tracked_peer_sets: Some(3),
        },
    );
    network.start();

    let mut private_keys = Vec::new();

    for i in 0..how_many_signers {
        let signer = PrivateKey::from_seed(seed + u64::from(i));
        private_keys.push(signer);
    }
    private_keys.sort_by_key(|s| s.public_key());

    let threshold = quorum(how_many_signers);
    let (polynomial, shares) =
        ops::generate_shares::<_, MinSig>(&mut context, None, how_many_signers, threshold);

    let mut nodes = Vec::new();
    let mut execution_nodes: Vec<ExecutionNode> = Vec::with_capacity(how_many_signers as usize);

    // The actual port here does not matter because in the simulated p2p
    // oracle it will be ignored. But it's nice because the nodes can be
    // more easily identified in some logs..
    let peers: OrderedAssociated<_, _> = private_keys
        .iter()
        .take(how_many_signers as usize)
        .cloned()
        .enumerate()
        .map(|(i, signer)| {
            (
                signer.public_key(),
                SocketAddr::from(([127, 0, 0, 1], i as u16 + 1)),
            )
        })
        .collect::<Vec<_>>()
        .into();

    for signer in &private_keys {
        let node = execution_runtime
            .spawn_node(&format!("{EXECUTION_NODE_PREFIX}-{}", signer.public_key()))
            .await
            .expect("must be able to spawn nodes on the runtime");

        if connect_execution_layer_nodes {
            // ensure EL p2p connectivity for backfill syncs
            for existing_node in &execution_nodes {
                existing_node.connect_peer(&node).await;
            }
        }

        execution_nodes.push(node);
    }

    let mut private_keys = private_keys.into_iter();

    // First, process the signers
    for (private_key, share) in private_keys
        .by_ref()
        .take(how_many_signers as usize)
        .zip_eq(shares)
    {
        let oracle = oracle.clone();

        let uid = format!("{CONSENSUS_NODE_PREFIX}-{}", private_key.public_key());
        let execution_node = execution_nodes.remove(0);

        oracle.socket_manager().update(0, peers.clone()).await;
        let engine_config = tempo_commonware_node::consensus::Builder {
            context: context.with_label(&uid),
            fee_recipient: alloy_primitives::Address::ZERO,
            execution_node: execution_node.node.clone(),
            blocker: oracle.control(private_key.public_key()),
            peer_manager: oracle.socket_manager(),
            partition_prefix: uid.clone(),
            signer: private_key.clone(),
            share,
            polynomial: polynomial.clone(),
            participants: peers.keys().clone(),
            epoch_length,
            mailbox_size: 1024,
            deque_size: 10,
            time_to_propose: Duration::from_secs(2),
            time_to_collect_notarizations: Duration::from_secs(3),
            time_to_retry_nullify_broadcast: Duration::from_secs(10),
            time_for_peer_response: Duration::from_secs(2),
            views_to_track: 10,
            views_until_leader_skip: 5,
            new_payload_wait_time: Duration::from_millis(200),
            time_to_build_subblock: Duration::from_millis(100),
        };

        nodes.push(PreparedNode {
            execution_node,
            public_key: private_key.public_key(),
            consensus_config: engine_config,
            oracle: oracle.clone(),
            uid: uid.clone(),
        });
    }

    (nodes, oracle)
}

/// Runs a test configured by [`Setup`].
pub fn run(setup: Setup, mut stop_condition: impl FnMut(&str, &str) -> bool) -> String {
    let cfg = deterministic::Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|context| async move {
        let execution_runtime = ExecutionRuntime::new();

        let linkage = setup.linkage.clone();
        // Setup and run all validators.
        let (nodes, mut oracle) =
            setup_validators(context.clone(), &execution_runtime, setup).await;

        let running = join_all(nodes.into_iter().map(|node| node.start())).await;

        link_validators(&mut oracle, &running, linkage, None).await;

        let pat = format!("{CONSENSUS_NODE_PREFIX}-");
        loop {
            let metrics = context.encode();

            let mut success = false;
            for line in metrics.lines() {
                if !line.starts_with(&pat) {
                    continue;
                }

                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();

                if metrics.ends_with("_peers_blocked") {
                    let value = value.parse::<u64>().unwrap();
                    assert_eq!(value, 0);
                }

                if stop_condition(metric, value) {
                    success = true;
                    break;
                }
            }

            if success {
                break;
            }

            context.sleep(Duration::from_secs(1)).await;
        }

        context.auditor().state()
    })
}

/// Links (or unlinks) validators using the oracle.
///
/// The `action` parameter determines the action (e.g. link, unlink) to take.
/// The `restrict_to` function can be used to restrict the linking to certain connections,
/// otherwise all validators will be linked to all other validators.
pub async fn link_validators(
    oracle: &mut Oracle<PublicKey>,
    validators: &[RunningNode],
    link: Link,
    restrict_to: Option<fn(usize, usize, usize) -> bool>,
) {
    for (i1, v1) in validators.iter().enumerate() {
        for (i2, v2) in validators.iter().enumerate() {
            // Ignore self
            if v1.public_key == v2.public_key {
                continue;
            }

            // Restrict to certain connections
            if let Some(f) = restrict_to
                && !f(validators.len(), i1, i2)
            {
                continue;
            }

            // Add link
            match oracle
                .add_link(v1.public_key.clone(), v2.public_key.clone(), link.clone())
                .await
            {
                Ok(()) => (),
                // TODO: it should be possible to remove the below if Commonware simulated network exposes list of registered peers.
                //
                // This is fine because some of the peers might be registered later
                Err(commonware_p2p::simulated::Error::PeerMissing) => (),
                // This is fine because we might call this multiple times as peers are joining the network.
                Err(commonware_p2p::simulated::Error::LinkExists) => (),
                res @ Err(_) => res.unwrap(),
            }
        }
    }
}

/// Get the number of pipeline runs from the Prometheus metrics recorder
pub fn get_pipeline_runs(recorder: &PrometheusRecorder) -> u64 {
    recorder
        .handle()
        .render()
        .lines()
        .find(|line| line.starts_with("reth_consensus_engine_beacon_pipeline_runs"))
        .and_then(|line| line.split_whitespace().nth(1)?.parse().ok())
        .unwrap_or(0)
}
