//! e2e tests using the [`commonware_runtime::deterministic`].
//!
//! This crate mimics how a full tempo node is run in production but runs the
//! consensus engine in a deterministic runtime while maintaining a tokio
//! async environment to launch execution nodes.
//!
//! All definitions herein are only intended to support the the tests defined
//! in tests/.

use std::{collections::HashSet, net::SocketAddr, pin::Pin, time::Duration};

use commonware_cryptography::{
    PrivateKeyExt as _, Signer as _,
    bls12381::{dkg::ops, primitives::variant::MinSig},
    ed25519::{PrivateKey, PublicKey},
};
use commonware_p2p::{
    Manager,
    simulated::{self, Link, Network, Oracle},
};

use commonware_runtime::{
    Clock, Metrics as _, Runner as _,
    deterministic::{self, Context, Runner},
};
use commonware_utils::quorum;
use futures::future::join_all;
use reth_node_metrics::recorder::PrometheusRecorder;
use tracing::debug;

pub mod execution_runtime;
pub use execution_runtime::ExecutionRuntime;

use crate::execution_runtime::ExecutionNode;

#[cfg(test)]
mod tests;

/// A Tempo node with lazily started consensus engine.
pub struct ValidatorNode {
    /// Execution-layer node. Spawned in the background but won't progress unless consensus engine is started.
    pub node: ExecutionNode,

    /// Public key of the validator.
    pub public_key: PublicKey,

    /// Future that should be awaited to start the consensus engine.
    start_engine: Option<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>,
}

impl ValidatorNode {
    pub fn start(&mut self) -> impl Future<Output = ()> + use<> {
        self.start_engine.take().expect("engine already started")
    }
}

/// The test setup run by [`run`].
#[derive(Clone)]
pub struct Setup {
    /// How many validators to launch.
    pub how_many: u32,
    /// The seed used for setting up the deterministic runtime.
    pub seed: u64,
    /// The linkage between individual validators.
    pub linkage: Link,
    /// The number of heights in an epoch.
    pub epoch_length: u64,
}

pub async fn setup_validators(
    mut context: Context,
    execution_runtime: &ExecutionRuntime,
    Setup {
        how_many,
        seed: _,
        linkage,
        epoch_length,
    }: Setup,
) -> (Vec<ValidatorNode>, Oracle<PublicKey>) {
    let threshold = quorum(how_many);

    let (network, oracle) = Network::new(
        context.with_label("network"),
        simulated::Config {
            max_size: 1024 * 1024,
            disconnect_on_block: true,
            tracked_peer_sets: Some(3),
        },
    );
    network.start();

    let mut signers = Vec::new();
    let mut validators = Vec::new();
    for i in 0..how_many {
        let signer = PrivateKey::from_seed(u64::from(i));
        let public_key = signer.public_key();
        signers.push(signer);
        validators.push(public_key);
    }
    validators.sort();
    signers.sort_by_key(|s| s.public_key());
    oracle
        .socket_manager()
        .update(
            0,
            validators
                .clone()
                .into_iter()
                // NOTE: the simulated oracle socket manager ignores the port.
                // We set this here for completeness.
                .enumerate()
                .map(|(i, val)| (val, SocketAddr::from(([127u8, 0, 0, 1], i as u16))))
                .collect::<Vec<(_, _)>>()
                .into(),
        )
        .await;

    let (polynomial, shares) =
        ops::generate_shares::<_, MinSig>(&mut context, None, how_many, threshold);

    let mut public_keys = HashSet::new();
    let mut nodes = Vec::new();
    let mut execution_nodes: Vec<ExecutionNode> = Vec::with_capacity(how_many as usize);

    for i in 0..how_many {
        let node = execution_runtime
            .spawn_node_blocking(&format!("node-{i}"))
            .expect("must be able to spawn nodes on the runtime");

        // ensure EL p2p connectivity for backfill syncs
        for existing_node in &execution_nodes {
            existing_node.connect_peer(&node).await;
        }

        execution_nodes.push(node);
    }

    for (signer, share) in signers.into_iter().zip(shares) {
        let public_key = signer.public_key();
        public_keys.insert(public_key.clone());
        let uid = format!("validator-{public_key}");
        let node = execution_nodes.remove(0);

        let engine = tempo_commonware_node::consensus::Builder {
            context: context.with_label(&uid),
            fee_recipient: alloy_primitives::Address::ZERO,
            execution_node: node.node.clone(),
            blocker: oracle.control(public_key.clone()),
            peer_manager: oracle.socket_manager().clone(),
            partition_prefix: uid.clone(),
            signer: signer.clone(),
            polynomial: polynomial.clone(),
            share,
            participants: validators.clone().into(),
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
            epoch_length,
        }
        .try_init()
        .await
        .expect("must be able to initialize consensus engines to run tests");

        let mut oracle = oracle.clone();
        let validators = validators.clone();
        let link = linkage.clone();
        nodes.push(ValidatorNode {
            node,
            public_key: signer.public_key(),
            start_engine: Some(Box::pin(async move {
                let pending = oracle
                    .control(signer.public_key())
                    .register(0)
                    .await
                    .unwrap();
                let recovered = oracle
                    .control(signer.public_key())
                    .register(1)
                    .await
                    .unwrap();
                let resolver = oracle
                    .control(signer.public_key())
                    .register(2)
                    .await
                    .unwrap();
                let broadcast = oracle
                    .control(signer.public_key())
                    .register(3)
                    .await
                    .unwrap();
                let marshal = oracle
                    .control(signer.public_key())
                    .register(4)
                    .await
                    .unwrap();
                let dkg = oracle
                    .control(signer.public_key())
                    .register(5)
                    .await
                    .unwrap();
                let boundary_certs = oracle
                    .control(signer.public_key())
                    .register(6)
                    .await
                    .unwrap();
                let subblocks = oracle
                    .control(signer.public_key())
                    .register(7)
                    .await
                    .unwrap();

                link_validators(&mut oracle, &validators, link, None).await;

                engine.start(
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
            })),
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

        // Setup and run all validators.
        let (nodes, _oracle) = setup_validators(context.clone(), &execution_runtime, setup).await;
        join_all(nodes.into_iter().map(|mut node| node.start())).await;

        loop {
            let metrics = context.encode();

            let mut success = false;
            for line in metrics.lines() {
                if !line.starts_with("validator-") {
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
            if v2 == v1 {
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
