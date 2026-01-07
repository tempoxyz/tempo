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

use std::{iter::repeat_with, net::SocketAddr, time::Duration};

use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    Signer as _,
    bls12381::{dkg, primitives::sharing::Mode},
    ed25519::{PrivateKey, PublicKey},
};
use commonware_math::algebra::Random as _;
use commonware_p2p::simulated::{self, Link, Network, Oracle};

use commonware_codec::Encode;
use commonware_runtime::{
    Clock, Metrics as _, Runner as _,
    deterministic::{self, Context, Runner},
};
use commonware_utils::{TryFromIterator as _, ordered};
use futures::future::join_all;
use itertools::Itertools as _;
use reth_node_metrics::recorder::PrometheusRecorder;
use tempo_commonware_node::{consensus, feed::FeedStateHandle};

pub mod execution_runtime;
pub use execution_runtime::ExecutionNodeConfig;
pub mod testing_node;
pub use execution_runtime::ExecutionRuntime;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
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

    /// How many non-signing validators (verifiers) to launch.
    /// These nodes participate in consensus but don't have shares.
    pub how_many_verifiers: u32,

    /// The seed used for setting up the deterministic runtime.
    pub seed: u64,

    /// The linkage between individual validators.
    pub linkage: Link,

    /// The number of heights in an epoch.
    pub epoch_length: u64,

    /// Whether to connect execution layer nodes directly.
    pub connect_execution_layer_nodes: bool,
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
}

impl Default for Setup {
    fn default() -> Self {
        Self::new()
    }
}

/// Sets up validators and returns the nodes and execution runtime.
///
/// The execution runtime is created internally with a chainspec configured
/// according to the Setup parameters (epoch_length, validators, polynomial).
///
/// The oracle is accessible via `TestingNode::oracle()` if needed for dynamic linking.
pub async fn setup_validators(
    mut context: Context,
    Setup {
        how_many_signers,
        how_many_verifiers,
        connect_execution_layer_nodes,
        linkage,
        epoch_length,
        ..
    }: Setup,
) -> (Vec<TestingNode<Context>>, ExecutionRuntime) {
    let (network, mut oracle) = Network::new(
        context.with_label("network"),
        simulated::Config {
            max_size: 1024 * 1024,
            disconnect_on_block: true,
            tracked_peer_sets: Some(3),
        },
    );
    network.start();

    let mut signer_keys = repeat_with(|| PrivateKey::random(&mut context))
        .take(how_many_signers as usize)
        .collect::<Vec<_>>();
    signer_keys.sort_by_key(|key| key.public_key());
    let (initial_dkg_outcome, shares) = dkg::deal(
        &mut context,
        Mode::NonZeroCounter,
        ordered::Set::try_from_iter(signer_keys.iter().map(|key| key.public_key())).unwrap(),
    )
    .unwrap();

    let onchain_dkg_outcome = OnchainDkgOutcome {
        epoch: Epoch::zero(),
        output: initial_dkg_outcome,
        next_players: shares.keys().clone(),
        is_next_full_dkg: false,
    };
    let mut verifier_keys = repeat_with(|| PrivateKey::random(&mut context))
        .take(how_many_verifiers as usize)
        .collect::<Vec<_>>();
    verifier_keys.sort_by_key(|key| key.public_key());

    // The port here does not matter because it will be ignored in simulated p2p.
    // Still nice, because sometimes nodes can be better identified in logs.
    let validators =
        ordered::Map::try_from_iter(shares.keys().iter().enumerate().map(|(i, key)| {
            (
                key.clone(),
                SocketAddr::from(([127, 0, 0, 1], i as u16 + 1)),
            )
        }))
        .unwrap();

    let execution_runtime = ExecutionRuntime::builder()
        .with_epoch_length(epoch_length)
        .with_initial_dkg_outcome(onchain_dkg_outcome)
        .with_validators(validators)
        .launch()
        .unwrap();

    let execution_configs = ExecutionNodeConfig::generator()
        .with_count(how_many_signers + how_many_verifiers)
        .with_peers(connect_execution_layer_nodes)
        .generate();

    let mut nodes = vec![];
    for ((private_key, share), mut execution_config) in signer_keys
        .into_iter()
        .zip_eq(shares)
        .map(|(signing_key, (verifying_key, share))| {
            assert_eq!(signing_key.public_key(), verifying_key);
            (signing_key, Some(share))
        })
        .chain(verifier_keys.into_iter().map(|key| (key, None)))
        .zip_eq(execution_configs)
    {
        let oracle = oracle.clone();
        let uid = format!("{CONSENSUS_NODE_PREFIX}_{}", private_key.public_key());
        let feed_state = FeedStateHandle::new();

        execution_config.validator_key = Some(
            private_key
                .public_key()
                .encode()
                .as_ref()
                .try_into()
                .unwrap(),
        );
        execution_config.feed_state = Some(feed_state.clone());

        let engine_config = consensus::Builder {
            context: context.with_label(&uid),
            fee_recipient: alloy_primitives::Address::ZERO,
            execution_node: None,
            blocker: oracle.control(private_key.public_key()),
            peer_manager: oracle.socket_manager(),
            partition_prefix: uid.clone(),
            share,
            signer: private_key.clone(),
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
            feed_state,
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

    link_validators(&mut oracle, &nodes, linkage, None).await;

    (nodes, execution_runtime)
}

/// Runs a test configured by [`Setup`].
pub fn run(setup: Setup, mut stop_condition: impl FnMut(&str, &str) -> bool) -> String {
    let cfg = deterministic::Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|context| async move {
        // Setup and run all validators.
        let (mut nodes, _execution_runtime) = setup_validators(context.clone(), setup).await;

        join_all(nodes.iter_mut().map(|node| node.start())).await;

        loop {
            let metrics = context.encode();

            let mut success = false;
            for line in metrics.lines() {
                if !line.starts_with(CONSENSUS_NODE_PREFIX) {
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
/// The `restrict_to` function can be used to restrict the linking to certain connections,
/// otherwise all validators will be linked to all other validators.
pub async fn link_validators<TClock: commonware_runtime::Clock>(
    oracle: &mut Oracle<PublicKey, TClock>,
    validators: &[TestingNode<TClock>],
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
