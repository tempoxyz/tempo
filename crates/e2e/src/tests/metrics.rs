use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use commonware_cryptography::ed25519::PrivateKey;
use commonware_macros::test_traced;
use commonware_math::algebra::Random as _;
use commonware_p2p::authenticated::lookup;
use commonware_runtime::{
    Clock as _, Runner as _, Supervisor as _,
    deterministic::{Config, Runner},
};
use futures::future::join_all;

use crate::{
    Setup,
    metrics::{MetricsExt as _, assert_no_duplicate_definitions, wait_for_metrics},
    setup_validators,
};

/// Consensus engine metrics referenced by production alerts, relative to the engine's scope.
///
/// Production nodes run the engine under the `consensus` and `engine` contexts, so these are
/// exported as `consensus_engine_<name>`. Test nodes replace that scope with their
/// [`crate::TestingNode::metric_prefix`].
///
/// `epoch_manager_simplex_voter_state_timeouts_total` is also alerted on, but it is a labeled
/// family that is only emitted once a view times out.
const ALERTED_ENGINE_METRICS: &[&str] = &[
    "dkg_manager_ceremony_failures_total",
    "dkg_manager_ceremony_successes_total",
    "epoch_manager_latest_epoch",
    "epoch_manager_simplex_batcher_inbound_messages_total",
    "epoch_manager_simplex_voter_outbound_messages_total",
    "executor_finalized_blocks_proposed_by_self_total",
    "marshal_finalized_height",
    "marshal_processed_height",
    "peer_manager_peers",
];

/// P2P network metrics referenced by production alerts.
///
/// Production nodes run the network under the `consensus` and `network` contexts.
const ALERTED_NETWORK_METRICS: &[&str] = &["consensus_network_listener_handshakes_blocked_total"];

#[test_traced]
fn no_duplicate_metrics() {
    let _ = tempo_eyre::install();

    let setup = Setup::new().how_many_signers(1).epoch_length(10);

    let cfg = Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        // Setup and run all validators.
        let (mut nodes, _execution_runtime) = setup_validators(&mut context, setup).await;

        join_all(nodes.iter_mut().map(|node| node.start(&context))).await;

        wait_for_metrics(&context, |metrics| metrics.consensus_at_epoch(2) > 0).await;

        // NOTE: useful for debugging
        // std::fs::write("metrics-dump", &all_metrics).unwrap();
        assert_no_duplicate_definitions(&context);
    })
}

/// Renaming a metric silently breaks the alerts that query it, so pin the alerted names.
#[test_traced]
fn alerted_engine_metric_names() {
    let _ = tempo_eyre::install();

    let setup = Setup::new().how_many_signers(4).epoch_length(10);

    let cfg = Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let (mut nodes, _execution_runtime) = setup_validators(&mut context, setup).await;

        join_all(nodes.iter_mut().map(|node| node.start(&context))).await;

        // Simplex message counters are per-epoch families, so run a few blocks into a new epoch
        // to make sure every node has sent and received votes in it.
        wait_for_metrics(&context, |metrics| {
            metrics.consensus_at_height(25) == nodes.len()
        })
        .await;

        let metrics = context.to_metrics();
        for node in &nodes {
            let prefix = node.metric_prefix();
            for name in ALERTED_ENGINE_METRICS {
                let name = format!("{prefix}_{name}");
                assert!(metrics.contains(&name), "missing `{name}`");
            }
        }
    })
}

/// Renaming a metric silently breaks the alerts that query it, so pin the alerted names.
#[test_traced]
fn alerted_network_metric_names() {
    let executor = Runner::default();

    executor.start(|mut context| async move {
        let config = lookup::Config::local(
            PrivateKey::random(&mut context),
            b"tempo",
            SocketAddr::from((Ipv4Addr::LOCALHOST, 3000)),
            1024,
        );
        let (network, _oracle) =
            lookup::Network::new(context.child("consensus").child("network"), config);
        let _network = network.start();

        // The network registers its actors' metrics once it starts running.
        context.sleep(Duration::from_millis(100)).await;

        let metrics = context.to_metrics();
        for name in ALERTED_NETWORK_METRICS {
            assert!(metrics.contains(name), "missing `{name}`");
        }
    })
}
