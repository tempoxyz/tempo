//! Tests for validator restart/kill scenarios
//!
//! These tests verify that validators can be killed and restarted, and that they
//! properly catch up to the rest of the network after restart.

use std::time::Duration;

use commonware_macros::test_traced;
use commonware_p2p::simulated::Link;
use commonware_runtime::{
    Clock, Metrics as _, Runner as _,
    deterministic::{self, Context, Runner},
};
use futures::future::join_all;
use rand::Rng;
use tracing::{debug, info};

use crate::{ExecutionRuntime, Setup, link_validators, setup_validators};

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

        let (nodes, mut oracle) =
            setup_validators(context.clone(), &execution_runtime, node_setup.clone()).await;

        let mut running = join_all(nodes.into_iter().map(|node| node.start())).await;
        link_validators(&mut oracle, &running, node_setup.linkage.clone(), None).await;

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

        info!("Test completed successfully");
        context.auditor().state()
    })
}

/// Wait for a specific number of validators to reach a target height
async fn wait_for_height(context: &Context, expected_validators: u32, target_height: u64) {
    loop {
        let metrics = context.encode();
        let mut validators_at_height = 0;

        for line in metrics.lines() {
            if !line.starts_with("validator-") {
                continue;
            }

            let mut parts = line.split_whitespace();
            let metric = parts.next().unwrap();
            let value = parts.next().unwrap();

            // Check if this is a height metric
            if metric.ends_with("_marshal_processed_height")
                && let Ok(height) = value.parse::<u64>()
                && height >= target_height
            {
                validators_at_height += 1;
            }
        }

        if validators_at_height >= expected_validators {
            debug!(
                "Found {} validators at height {} (target: {})",
                validators_at_height, target_height, expected_validators
            );
            break;
        }

        context.sleep(Duration::from_secs(1)).await;
    }
}

#[test_traced]
fn test_validator_restart_simple() {
    let _ = tempo_eyre::install();

    let linkage = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };

    // Very simple test - just check that validator can be killed and restarted
    let setup = RestartSetup {
        node_setup: Setup {
            how_many_signers: 3,
            seed: 0,
            linkage,
            epoch_length: 10,
            connect_execution_layer_nodes: false,
        },
        shutdown_height: 3, // Kill very early
        restart_height: 6,  // Restart soon after
        final_height: 10,   // Reach one epoch
    };

    let _state = run_restart_test(setup);
    // If we get here without panicking, the test passed
}

#[test_traced]
fn test_validator_restart_perfect_links() {
    let _ = tempo_eyre::install();

    let linkage = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };

    let setup = RestartSetup {
        node_setup: Setup {
            how_many_signers: 4,
            seed: 0,
            linkage,
            epoch_length: 10,
            connect_execution_layer_nodes: false,
        },
        shutdown_height: 5, // Kill at height 5
        restart_height: 10, // Restart at height 10
        final_height: 15,   // All reach height 15
    };

    let _state = run_restart_test(setup);
}

#[test_traced]
fn test_validator_restart_with_failures() {
    let _ = tempo_eyre::install();

    let linkage = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(5),
        success_rate: 0.95, // 5% packet loss
    };

    let epoch_length = 30;
    let setup = RestartSetup {
        node_setup: Setup {
            how_many_signers: 4,
            seed: 0,
            linkage,
            epoch_length: 10,
            connect_execution_layer_nodes: false,
        },
        shutdown_height: epoch_length + 1,
        restart_height: 2 * epoch_length + 1,
        final_height: 3 * epoch_length + 1,
    };

    let _state = run_restart_test(setup);
}
