//! e2e tests using the [`commonware_runtime::deterministic`].
//!
//! This crate mimics how a full tempo node is run in production but runs the
//! consensus engine in a deterministic runtime while maintaining a tokio
//! async environment to launch execution nodes.
//!
//! All definitions herein are only intended to support the the tests defined
//! in tests/.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use commonware_cryptography::{
    PrivateKeyExt as _, Signer as _,
    bls12381::{dkg::ops, primitives::variant::MinSig},
    ed25519::{PrivateKey, PublicKey},
};
use commonware_p2p::{
    Manager as _,
    simulated::{self, Link, Network, Oracle},
};

use commonware_runtime::{
    Clock, Metrics as _, Runner as _,
    deterministic::{self, Context, Runner},
};
use commonware_utils::{quorum, set::OrderedAssociated};
use futures::future::join_all;
use itertools::Itertools as _;
use reth_node_metrics::recorder::PrometheusRecorder;

pub mod execution_runtime;
pub use execution_runtime::ExecutionNodeConfig;
pub mod testing_node;
// pub mod genesis;
pub use execution_runtime::ExecutionRuntime;
pub use testing_node::TestingNode;

#[cfg(test)]
mod tests;

pub const CONSENSUS_NODE_PREFIX: &str = "consensus";
pub const EXECUTION_NODE_PREFIX: &str = "execution";

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
) -> (Vec<TestingNode>, simulated::Oracle<PublicKey>) {
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

    let mut private_keys = private_keys.into_iter();
    let execution_configs = ExecutionNodeConfig::generator()
        .with_count(how_many_signers)
        .with_peers(connect_execution_layer_nodes)
        .generate();

    // Process the signers
    for ((private_key, share), execution_config) in private_keys
        .by_ref()
        .take(how_many_signers as usize)
        .zip_eq(shares)
        .zip_eq(execution_configs)
    {
        let oracle = oracle.clone();

        let uid = format!("{CONSENSUS_NODE_PREFIX}-{}", private_key.public_key());

        oracle.socket_manager().update(0, peers.clone()).await;
        let engine_config = tempo_commonware_node::consensus::Builder {
            context: context.with_label(&uid),
            fee_recipient: alloy_primitives::Address::ZERO,
            execution_node: None,
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
            new_payload_wait_time: Duration::from_millis(100),
            time_to_build_subblock: Duration::from_millis(100),
        };

        nodes.push(TestingNode::new(
            uid,
            private_key.public_key(),
            oracle.clone(),
            engine_config,
            execution_runtime.handle(),
            execution_config,
        ));
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
        let (mut nodes, mut oracle) =
            setup_validators(context.clone(), &execution_runtime, setup).await;

        join_all(nodes.iter_mut().map(|node| node.start())).await;

        link_validators(&mut oracle, &nodes, linkage, None).await;

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
    validators: &[TestingNode],
    link: Link,
    restrict_to: Option<fn(usize, usize, usize) -> bool>,
) {
    for (i1, v1) in validators.iter().enumerate() {
        for (i2, v2) in validators.iter().enumerate() {
            // Ignore self
            if v1.public_key() == v2.public_key() {
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
                .add_link(
                    v1.public_key().clone(),
                    v2.public_key().clone(),
                    link.clone(),
                )
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
