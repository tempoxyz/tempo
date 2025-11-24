//! Tests for validator restart/kill scenarios
//!
//! These tests verify that validators can be killed and restarted, and that they
//! properly catch up to the rest of the network after restart.

use std::time::Duration;

use commonware_macros::test_traced;
use commonware_runtime::{
    Clock, Metrics as _, Runner as _,
    deterministic::{self, Context, Runner},
};
use futures::future::join_all;
use rand::Rng;
use tracing::debug;

use crate::{CONSENSUS_NODE_PREFIX, ExecutionRuntime, Setup, setup_validators};

/// Test configuration for restart scenarios
#[derive(Clone)]
struct RestartSetup {
    // Setup for the nodes to launch.
    node_setup: Setup,
    /// Height at which to shutdown a validator
    pub shutdown_height: u64,
    /// Height at which to restart the validator
    pub restart_height: u64,
    /// Final height that all validators (including restarted) must reach
    pub final_height: u64,
}

/// Runs a validator restart test with the given configuration
fn run_restart_test(
    RestartSetup {
        node_setup,
        shutdown_height,
        restart_height,
        final_height,
    }: RestartSetup,
) -> String {
    let cfg = deterministic::Config::default().with_seed(node_setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let execution_runtime = ExecutionRuntime::new();

        let nodes = setup_validators(context.clone(), &execution_runtime, node_setup.clone()).await;

        let mut running = join_all(nodes.into_iter().map(|node| node.start())).await;

        debug!(
            height = shutdown_height,
            "waiting for network to reach target height before stopping a validator",
        );
        wait_for_height(&context, node_setup.how_many_signers, shutdown_height).await;

        // Randomly select a validator to kill
        let idx = context.gen_range(0..running.len());
        let to_restart = running.remove(idx).stop();

        debug!(public_key = %to_restart.public_key, "stopped a random validator");

        debug!(
            height = restart_height,
            "waiting for remaining validators to reach target height before restarting validator",
        );
        wait_for_height(&context, running.len() as u32, restart_height).await;

        running.push(to_restart.start().await);
        debug!(
            public_key = %running.last().unwrap().public_key,
            "restarted validator",
        );

        debug!(
            height = final_height,
            "waiting for reconstituted validators to reach target height to reach test success",
        );
        wait_for_height(&context, running.len() as u32, final_height).await;

        context.auditor().state()
    })
}

/// Wait for a specific number of validators to reach a target height
async fn wait_for_height(context: &Context, expected_validators: u32, target_height: u64) {
    let prefix = format!("{CONSENSUS_NODE_PREFIX}-");
    loop {
        let metrics = context.encode();
        let mut validators_at_height = 0;

        for line in metrics.lines() {
            if !line.starts_with(&prefix) {
                continue;
            }

            let mut parts = line.split_whitespace();
            let metric = parts.next().unwrap();
            let value = parts.next().unwrap();

            // Check if this is a height metric
            if metric.ends_with("_marshal_processed_height") {
                let height = value.parse::<u64>().unwrap();
                if height >= target_height {
                    validators_at_height += 1;
                }
            }
        }
        if validators_at_height >= expected_validators {
            break;
        }
        context.sleep(Duration::from_secs(1)).await;
    }
}

/// Ensures that no more finalizations happen.
async fn ensure_no_progress(context: &Context, tries: u32) {
    let prefix = format!("{CONSENSUS_NODE_PREFIX}-");
    let baseline = {
        let metrics = context.encode();
        let mut height = None;
        for line in metrics.lines() {
            if !line.starts_with(&prefix) {
                continue;
            }
            let mut parts = line.split_whitespace();
            let metrics = parts.next().unwrap();
            let value = parts.next().unwrap();
            if metrics.ends_with("_marshal_processed_height") {
                let value = value.parse::<u64>().unwrap();
                if Some(value) > height {
                    height.replace(value);
                }
            }
        }
        height.expect("processed height is a metric")
    };
    for _ in 0..=tries {
        context.sleep(Duration::from_secs(1)).await;

        let metrics = context.encode();
        let mut height = None;
        for line in metrics.lines() {
            if !line.starts_with(&prefix) {
                continue;
            }
            let mut parts = line.split_whitespace();
            let metrics = parts.next().unwrap();
            let value = parts.next().unwrap();
            if metrics.ends_with("_marshal_processed_height") {
                let value = value.parse::<u64>().unwrap();
                if Some(value) > height {
                    height.replace(value);
                }
            }
        }
        let height = height.expect("processed height is a metric");
        if height != baseline {
            panic!(
                "height has changed, progress was made while the network was \
                stopped: baseline = `{baseline}`, progressed_to = `{height}`"
            );
        }
    }
}

/// This is the simplest possible restart case: the network stops because we
/// dropped below quorum. The node should be able to pick up after.
#[test_traced]
fn network_resumes_after_restart() {
    let _ = tempo_eyre::install();

    for seed in 0..3 {
        let setup = Setup::new()
            .how_many_signers(3) // quorum for 3 validators is 3.
            .seed(seed)
            .epoch_length(100);

        let shutdown_height = 5;
        let final_height = 10;

        let cfg = deterministic::Config::default().with_seed(setup.seed);
        let executor = Runner::from(cfg);

        executor.start(|mut context| async move {
            let execution_runtime = ExecutionRuntime::new();

            let nodes = setup_validators(context.clone(), &execution_runtime, setup.clone()).await;

            let mut running = join_all(nodes.into_iter().map(|node| node.start())).await;

            debug!(
                height = shutdown_height,
                "waiting for network to reach target height before stopping a validator",
            );
            wait_for_height(&context, setup.how_many_signers, shutdown_height).await;

            let idx = context.gen_range(0..running.len());
            let to_restart = running.remove(idx).stop();
            debug!(public_key = %to_restart.public_key, "stopped a random validator");

            // wait a bit to let the network settle; some finalizations come in later
            context.sleep(Duration::from_secs(1)).await;
            ensure_no_progress(&context, 5).await;

            running.push(to_restart.start().await);
            debug!(
                public_key = %running.last().unwrap().public_key,
                "restarted validator",
            );

            debug!(
                height = final_height,
                "waiting for reconstituted validators to reach target height to reach test success",
            );
            wait_for_height(&context, running.len() as u32, final_height).await;
        })
    }
}

// NOTE: ceremonies are finalized on the pre-to-last block.
#[test_traced]
fn node_recovers_after_finalizing_ceremony() {
    let prefix = format!("{CONSENSUS_NODE_PREFIX}-");

    let setup = Setup::new();

    let cfg = deterministic::Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|context| async move {
        let execution_runtime = ExecutionRuntime::new();

        let nodes = setup_validators(context.clone(), &execution_runtime, setup.clone()).await;

        let mut running = join_all(nodes.into_iter().map(|node| node.start())).await;

        // Catch a node right after it processed the pre-to-boundary height.
        // Best-effort: we hot-loop in 100ms steps, but if processing is too
        // fast we might miss the window and the test will succeed no matter
        // what.
        let (metric, height) = 'wait_to_boundary: loop {
            let metrics = context.encode();
            'lines: for line in metrics.lines() {
                if !line.starts_with(&prefix) {
                    continue 'lines;
                }
                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();

                if metric.ends_with("_marshal_processed_height") {
                    let height = value.parse::<u64>().unwrap();
                    if height
                        >= commonware_consensus::utils::last_block_in_epoch(setup.epoch_length, 0)
                            - 1
                    {
                        break 'wait_to_boundary (metric.to_string(), height);
                    }
                }
            }
            context.sleep(Duration::from_millis(100)).await;
        };

        tracing::debug!(
            metric,
            height,
            "found a node that reached the pre-to-last height; restarting it"
        );
        // Now restart the node for which we found the metric.
        let idx = running
            .iter()
            .position(|node| metric.contains(&node.uid))
            .unwrap();
        let _node = running.remove(idx).stop().start().await;

        let mut iteration = 0;
        'look_for_progress: loop {
            context.sleep(Duration::from_secs(1)).await;
            let metrics = context.encode();
            'lines: for line in metrics.lines() {
                if !line.starts_with(&prefix) {
                    continue 'lines;
                }
                if line.starts_with(&metric) {
                    let mut parts = line.split_whitespace();
                    let _ = parts.next().unwrap();
                    let value = parts.next().unwrap();
                    if value.parse::<u64>().unwrap() > height {
                        break 'look_for_progress;
                    }
                }
            }
            iteration += 1;
            assert!(
                iteration < 10,
                "node did not progress for 10 iterations; restart on boundary likely failed"
            );
        }
    });
}

#[test_traced]
fn validator_catches_up_to_network_during_epoch() {
    let _ = tempo_eyre::install();

    let setup = RestartSetup {
        node_setup: Setup::new().epoch_length(100),
        shutdown_height: 5,
        restart_height: 10,
        final_height: 15,
    };

    let _state = run_restart_test(setup);
}

#[test_traced]
fn validator_catches_up_across_epochs() {
    let _ = tempo_eyre::install();

    let epoch_length = 30;
    let setup = RestartSetup {
        node_setup: Setup::new().epoch_length(epoch_length),
        shutdown_height: epoch_length + 1,
        restart_height: 2 * epoch_length + 1,
        final_height: 3 * epoch_length + 1,
    };

    let _state = run_restart_test(setup);
}
