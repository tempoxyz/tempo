//! e2e tests using the [`commonware_runtime::deterministic`].
//!
//! This crate mimics how a full tempo node is run in production but runs the
//! consensus engine in a deterministic runtime while maintaining a tokio
//! async environment to launch execution nodes.
//!
//! All definitions herein are only intended to support the the tests defined
//! in tests/.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

use std::{net::SocketAddr, time::Duration};

use commonware_cryptography::{
    PrivateKeyExt as _, Signer as _,
    bls12381::{dkg::ops, primitives::variant::MinSig},
    ed25519::{PrivateKey, PublicKey},
};
use commonware_p2p::simulated::{self, Control, Link, Network, Oracle, SocketManager};

use commonware_runtime::{
    Clock, Handle, Metrics as _, Runner as _,
    deterministic::{self, Context, Runner},
};
use commonware_utils::{SystemTimeExt as _, quorum, set::OrderedAssociated};
use futures::future::join_all;
use itertools::Itertools as _;
use reth_node_metrics::recorder::PrometheusRecorder;
use tempo_chainspec::TempoChainSpec;
use tempo_commonware_node::consensus;
use tracing::debug;

pub mod execution_runtime;
pub use execution_runtime::ExecutionRuntime;

use crate::execution_runtime::{
    ExecutionNode, insert_allegretto, insert_epoch_length, insert_public_polynomial,
    insert_validators,
};

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

    /// How many nodes to launch that will be verifiers but not signers,
    /// because they lack a key share.
    ///
    /// These will also not be added to the genesis.
    pub how_many_verifiers: u32,

    /// The seed used for setting up the deterministic runtime.
    pub seed: u64,
    /// The linkage between individual validators.
    pub linkage: Link,
    /// The number of heights in an epoch.
    pub epoch_length: u64,

    pub connect_execution_layer_nodes: bool,

    pub allegretto_in_seconds: Option<u64>,
}

impl Setup {
    pub fn new() -> Self {
        Self {
            how_many_signers: 4,
            how_many_verifiers: 0,
            seed: 0,
            linkage: Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            },
            epoch_length: 20,
            connect_execution_layer_nodes: false,
            allegretto_in_seconds: None,
        }
    }

    pub fn how_many_signers(self, how_many_signers: u32) -> Self {
        Self {
            how_many_signers,
            ..self
        }
    }

    pub fn how_many_verifiers(self, how_many_verifiers: u32) -> Self {
        Self {
            how_many_verifiers,
            ..self
        }
    }

    pub fn seed(self, seed: u64) -> Self {
        Self { seed, ..self }
    }

    pub fn linkage(self, linkage: Link) -> Self {
        Self { linkage, ..self }
    }

    pub fn epoch_length(self, epoch_length: u64) -> Self {
        Self {
            epoch_length,
            ..self
        }
    }

    pub fn connect_execution_layer_nodes(self, connect_execution_layer_nodes: bool) -> Self {
        Self {
            connect_execution_layer_nodes,
            ..self
        }
    }

    pub fn allegretto_in_seconds(self, seconds: u64) -> Self {
        Self {
            allegretto_in_seconds: Some(seconds),
            ..self
        }
    }
}

impl Default for Setup {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn setup_validators(
    mut context: Context,
    Setup {
        how_many_signers,
        how_many_verifiers,
        seed,
        connect_execution_layer_nodes,
        linkage,
        epoch_length,
        allegretto_in_seconds,
    }: Setup,
) -> (Vec<PreparedNode>, ExecutionRuntime) {
    let (network, mut oracle) = Network::new(
        context.with_label("network"),
        simulated::Config {
            max_size: 1024 * 1024,
            disconnect_on_block: true,
            tracked_peer_sets: Some(3),
        },
    );
    network.start();

    let mut private_keys = Vec::new();

    for i in 0..(how_many_signers + how_many_verifiers) {
        let signer = PrivateKey::from_seed(seed + u64::from(i));
        private_keys.push(signer);
    }
    private_keys.sort_by_key(|s| s.public_key());

    link_validators(
        &mut oracle,
        &private_keys
            .iter()
            .map(|key| key.public_key())
            .collect::<Vec<_>>(),
        linkage,
        None,
    )
    .await;

    let threshold = quorum(how_many_signers);
    let (polynomial, shares) =
        ops::generate_shares::<_, MinSig>(&mut context, None, how_many_signers, threshold);

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

    let mut genesis = crate::execution_runtime::genesis();
    if let Some(allegretto_in_seconds) = allegretto_in_seconds {
        genesis = insert_allegretto(
            genesis,
            context.current().epoch().as_secs() + allegretto_in_seconds,
        );
    }
    genesis = insert_epoch_length(genesis, epoch_length);
    genesis = insert_public_polynomial(genesis, polynomial.into());
    genesis = insert_validators(genesis, peers.into());

    let chain_spec = TempoChainSpec::from_genesis(genesis);

    let execution_runtime = ExecutionRuntime::with_chain_spec(chain_spec);

    let mut execution_nodes: Vec<ExecutionNode> =
        Vec::with_capacity((how_many_signers + how_many_verifiers) as usize);
    for key in &private_keys {
        let execution_node = execution_runtime
            .spawn_node(&format!("{EXECUTION_NODE_PREFIX}-{}", key.public_key()))
            .await
            .expect("must be able to spawn nodes on the runtime");

        if connect_execution_layer_nodes {
            // ensure EL p2p connectivity for backfill syncs
            for existing_node in &execution_nodes {
                existing_node.connect_peer(&execution_node).await;
            }
        }

        execution_nodes.push(execution_node);
    }

    let mut private_keys = private_keys.into_iter();

    let mut nodes = vec![];

    // First, process the signers
    for (private_key, share) in private_keys
        .by_ref()
        .take(how_many_signers as usize)
        .zip_eq(shares)
    {
        let oracle = oracle.clone();

        let public_key = private_key.public_key();
        let uid = format!("{CONSENSUS_NODE_PREFIX}-{public_key}");
        let execution_node = execution_nodes.remove(0);

        let consensus_config = tempo_commonware_node::consensus::Builder {
            context: context.with_label(&uid),
            fee_recipient: alloy_primitives::Address::ZERO,
            execution_node: execution_node.node.clone(),
            blocker: oracle.control(public_key.clone()),
            peer_manager: oracle.socket_manager(),
            partition_prefix: uid.clone(),
            share: Some(share),
            signer: private_key,
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
            subblock_broadcast_interval: Duration::from_millis(50),
        };

        nodes.push(PreparedNode {
            execution_node,
            public_key,
            consensus_config,
            oracle,
            uid,
        });
    }

    // Then, process the verifiers
    for private_key in private_keys {
        let oracle = oracle.clone();

        let public_key = private_key.public_key();
        let uid = format!("{CONSENSUS_NODE_PREFIX}-{public_key}");
        let execution_node = execution_nodes.remove(0);

        let consensus_config = tempo_commonware_node::consensus::Builder {
            context: context.with_label(&uid),
            fee_recipient: alloy_primitives::Address::ZERO,
            execution_node: execution_node.node.clone(),
            blocker: oracle.control(public_key.clone()),
            peer_manager: oracle.socket_manager(),
            partition_prefix: uid.clone(),
            signer: private_key,
            share: None,
            mailbox_size: 1024,
            deque_size: 10,
            time_to_propose: Duration::from_secs(2),
            time_to_collect_notarizations: Duration::from_secs(3),
            time_to_retry_nullify_broadcast: Duration::from_secs(10),
            time_for_peer_response: Duration::from_secs(2),
            views_to_track: 10,
            views_until_leader_skip: 5,
            new_payload_wait_time: Duration::from_millis(100),
            time_to_build_subblock: Duration::from_millis(100),
            subblock_broadcast_interval: Duration::from_millis(50),
        };

        nodes.push(PreparedNode {
            execution_node,
            public_key,
            consensus_config,
            oracle,
            uid,
        });
    }

    (nodes, execution_runtime)
}

/// Runs a test configured by [`Setup`].
pub fn run(setup: Setup, mut stop_condition: impl FnMut(&str, &str) -> bool) -> String {
    let cfg = deterministic::Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|context| async move {
        // Setup and run all validators.
        let (nodes, _execution_runtime) = setup_validators(context.clone(), setup).await;
        let _running = join_all(nodes.into_iter().map(|node| node.start())).await;

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
    validators: &[PublicKey],
    link: Link,
    restrict_to: Option<fn(usize, usize, usize) -> bool>,
) {
    for (i1, v1) in validators.iter().enumerate() {
        for (i2, v2) in validators.iter().enumerate() {
            // Ignore self
            if v1 == v2 {
                continue;
            }

            // Restrict to certain connections
            if let Some(f) = restrict_to
                && !f(validators.len(), i1, i2)
            {
                continue;
            }

            // Add link
            match oracle.add_link(v1.clone(), v2.clone(), link.clone()).await {
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
