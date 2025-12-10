//! Tests for validator restart/kill scenarios
//!
//! These tests verify that validators can be killed and restarted, and that they
//! properly catch up to the rest of the network after restart.

use std::{net::SocketAddr, time::Duration};

use alloy::transports::http::reqwest::Url;
use commonware_consensus::utils::is_last_block_in_epoch;
use commonware_macros::test_traced;
use commonware_runtime::{
    Clock, Metrics as _, Runner as _,
    deterministic::{self, Context, Runner},
};
use futures::future::join_all;
use rand::Rng;
use tracing::debug;

use crate::{CONSENSUS_NODE_PREFIX, Setup, execution_runtime::validator, setup_validators};

/// Test configuration for restart scenarios
#[derive(Clone)]
struct RestartSetup {
    // Setup for the nodes to launch.
    node_setup: Setup,
    /// Height at which to shutdown a validator
    shutdown_height: u64,
    /// Height at which to restart the validator
    restart_height: u64,
    /// Final height that all validators (including restarted) must reach
    final_height: u64,
}

/// Runs a validator restart test with the given configuration
#[track_caller]
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
        let (mut validators, _execution_runtime) =
            setup_validators(context.clone(), node_setup.clone()).await;

        join_all(validators.iter_mut().map(|v| v.start())).await;

        debug!(
            height = shutdown_height,
            "waiting for network to reach target height before stopping a validator",
        );
        wait_for_height(&context, node_setup.how_many_signers, shutdown_height).await;

        // Randomly select a validator to kill
        let idx = context.gen_range(0..validators.len());
        validators[idx].stop().await;

        debug!(public_key = %validators[idx].public_key(), "stopped a random validator");

        debug!(
            height = restart_height,
            "waiting for remaining validators to reach target height before restarting validator",
        );
        wait_for_height(&context, node_setup.how_many_signers - 1, restart_height).await;

        debug!("target height reached, restarting stopped validator");
        validators[idx].start().await;
        debug!(
            public_key = %validators[idx].public_key(),
            "restarted validator",
        );

        debug!(
            height = final_height,
            "waiting for reconstituted validators to reach target height to reach test success",
        );
        wait_for_height(&context, node_setup.how_many_signers, final_height).await;

        context.auditor().state()
    })
}

/// Wait for a specific number of validators to reach a target height
async fn wait_for_height(context: &Context, expected_validators: u32, target_height: u64) {
    loop {
        let metrics = context.encode();
        let mut validators_at_height = 0;

        for line in metrics.lines() {
            if !line.starts_with(CONSENSUS_NODE_PREFIX) {
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
        if validators_at_height == expected_validators {
            break;
        }
        context.sleep(Duration::from_secs(1)).await;
    }
}

/// Ensures that no more finalizations happen.
async fn ensure_no_progress(context: &Context, tries: u32) {
    let baseline = {
        let metrics = context.encode();
        let mut height = None;
        for line in metrics.lines() {
            if !line.starts_with(CONSENSUS_NODE_PREFIX) {
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
            if !line.starts_with(CONSENSUS_NODE_PREFIX) {
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
            .epoch_length(100)
            // FIXME(https://github.com/tempoxyz/tempo/issues/1309): this should
            // be also tested without connecting the execution layer nodes to
            // force a CL -> EL backfill.
            .connect_execution_layer_nodes(true);

        let shutdown_height = 5;
        let final_height = 10;

        let cfg = deterministic::Config::default().with_seed(setup.seed);
        let executor = Runner::from(cfg);

        executor.start(|mut context| async move {
            let (mut validators, _execution_runtime) =
                setup_validators(context.clone(), setup.clone()).await;

            join_all(validators.iter_mut().map(|v| v.start())).await;

            debug!(
                height = shutdown_height,
                "waiting for network to reach target height before stopping a validator",
            );
            wait_for_height(&context, setup.how_many_signers, shutdown_height).await;

            let idx = context.gen_range(0..validators.len());
            validators[idx].stop().await;
            debug!(public_key = %validators[idx].public_key(), "stopped a random validator");

            // wait a bit to let the network settle; some finalizations come in later
            context.sleep(Duration::from_secs(1)).await;
            ensure_no_progress(&context, 5).await;

            validators[idx].start().await;
            debug!(
                public_key = %validators[idx].public_key(),
                "restarted validator",
            );

            debug!(
                height = final_height,
                "waiting for reconstituted validators to reach target height to reach test success",
            );
            wait_for_height(&context, validators.len() as u32, final_height).await;
        })
    }
}

#[test_traced]
fn pre_allegretto_validator_catches_up_to_network_during_epoch() {
    let _ = tempo_eyre::install();

    let setup = RestartSetup {
        node_setup: Setup::new().epoch_length(100).no_validators_in_genesis(),
        shutdown_height: 5,
        restart_height: 10,
        final_height: 15,
    };

    let _state = run_restart_test(setup);
}

#[test_traced]
fn allegretto_at_genesis_validator_catches_up_to_network_during_epoch() {
    let _ = tempo_eyre::install();

    let setup = RestartSetup {
        node_setup: Setup::new().epoch_length(100).allegretto_time(0),
        shutdown_height: 5,
        restart_height: 10,
        final_height: 15,
    };

    let _state = run_restart_test(setup);
}

#[test_traced]
fn pre_allegretto_validator_catches_up_across_epochs() {
    let _ = tempo_eyre::install();

    let epoch_length = 30;
    let setup = RestartSetup {
        node_setup: Setup::new()
            .epoch_length(epoch_length)
            .no_validators_in_genesis(),
        shutdown_height: epoch_length + 1,
        restart_height: 2 * epoch_length + 1,
        final_height: 3 * epoch_length + 1,
    };

    let _state = run_restart_test(setup);
}

#[test_traced]
fn allegretto_at_genesis_validator_catches_up_across_epochs() {
    let _ = tempo_eyre::install();

    let epoch_length = 30;
    let setup = RestartSetup {
        node_setup: Setup::new().epoch_length(epoch_length).allegretto_time(0),
        shutdown_height: epoch_length + 1,
        restart_height: 2 * epoch_length + 1,
        final_height: 3 * epoch_length + 1,
    };

    let _state = run_restart_test(setup);
}

// FIXME: needs https://github.com/tempoxyz/tempo/issues/1309
#[ignore]
#[test_traced]
fn single_node_with_allegretto_at_genesis_recovers_after_finalizing_ceremony() {
    AssertNodeRecoversAfterFinalizingBlock {
        n_validators: 1,
        epoch_length: 10,
        shutdown_after_finalizing: ShutdownAfterFinalizing::Ceremony,
        allegretto_at_genesis: true,
        await_transition: false,
    }
    .run()
}

#[test_traced]
fn node_recovers_after_finalizing_ceremony_allegretto_at_genesis_four_validators() {
    AssertNodeRecoversAfterFinalizingBlock {
        n_validators: 4,
        epoch_length: 30,
        shutdown_after_finalizing: ShutdownAfterFinalizing::Ceremony,
        allegretto_at_genesis: true,
        await_transition: false,
    }
    .run()
}

// FIXME: needs https://github.com/tempoxyz/tempo/issues/1309
#[ignore]
#[test_traced]
fn single_node_with_allegretto_at_genesis_recovers_after_finalizing_boundary() {
    AssertNodeRecoversAfterFinalizingBlock {
        n_validators: 1,
        epoch_length: 10,
        shutdown_after_finalizing: ShutdownAfterFinalizing::Boundary,
        allegretto_at_genesis: true,
        await_transition: false,
    }
    .run()
}

#[test_traced]
fn node_recovers_after_finalizing_boundary_allegretto_at_genesis_four_validators() {
    AssertNodeRecoversAfterFinalizingBlock {
        n_validators: 4,
        epoch_length: 30,
        shutdown_after_finalizing: ShutdownAfterFinalizing::Boundary,
        allegretto_at_genesis: true,
        await_transition: false,
    }
    .run()
}

// FIXME: needs https://github.com/tempoxyz/tempo/issues/1309
#[ignore]
#[test_traced]
fn single_node_with_pre_allegretto_logic_recovers_after_finalizing_ceremony() {
    AssertNodeRecoversAfterFinalizingBlock {
        n_validators: 1,
        epoch_length: 10,
        shutdown_after_finalizing: ShutdownAfterFinalizing::Ceremony,
        allegretto_at_genesis: false,
        await_transition: false,
    }
    .run()
}

#[test_traced]
fn node_recovers_after_finalizing_ceremony_pre_allegretto_four_validators() {
    AssertNodeRecoversAfterFinalizingBlock {
        n_validators: 4,
        epoch_length: 30,
        shutdown_after_finalizing: ShutdownAfterFinalizing::Ceremony,
        allegretto_at_genesis: false,
        await_transition: false,
    }
    .run()
}

// FIXME: needs https://github.com/tempoxyz/tempo/issues/1309
#[ignore]
#[test_traced]
fn single_node_with_pre_allegretto_logic_recovers_after_finalizing_boundary() {
    AssertNodeRecoversAfterFinalizingBlock {
        n_validators: 1,
        epoch_length: 10,
        shutdown_after_finalizing: ShutdownAfterFinalizing::Boundary,
        allegretto_at_genesis: false,
        await_transition: false,
    }
    .run()
}

#[test_traced]
fn node_recovers_after_finalizing_boundary_pre_allegretto_four_validators() {
    AssertNodeRecoversAfterFinalizingBlock {
        n_validators: 4,
        epoch_length: 30,
        shutdown_after_finalizing: ShutdownAfterFinalizing::Boundary,
        allegretto_at_genesis: false,
        await_transition: false,
    }
    .run()
}

// FIXME: needs https://github.com/tempoxyz/tempo/issues/1309
#[ignore]
#[test_traced]
fn single_node_transitions_to_allegretto_and_recovers_after_finalizing_ceremony() {
    AssertNodeRecoversAfterFinalizingBlock {
        n_validators: 1,
        epoch_length: 10,
        shutdown_after_finalizing: ShutdownAfterFinalizing::Ceremony,
        allegretto_at_genesis: false,
        await_transition: true,
    }
    .run()
}

#[test_traced]
fn node_recovers_after_finalizing_ceremony_post_allegretto_four_validators() {
    AssertNodeRecoversAfterFinalizingBlock {
        n_validators: 4,
        epoch_length: 30,
        shutdown_after_finalizing: ShutdownAfterFinalizing::Ceremony,
        allegretto_at_genesis: false,
        await_transition: true,
    }
    .run()
}

// FIXME: needs https://github.com/tempoxyz/tempo/issues/1309
#[ignore]
#[test_traced]
fn single_node_transitions_to_allegretto_and_recovers_after_finalizing_boundary() {
    AssertNodeRecoversAfterFinalizingBlock {
        n_validators: 1,
        epoch_length: 10,
        shutdown_after_finalizing: ShutdownAfterFinalizing::Boundary,
        allegretto_at_genesis: false,
        await_transition: true,
    }
    .run()
}

#[test_traced]
fn node_recovers_after_finalizing_boundary_post_allegretto_four_validators() {
    AssertNodeRecoversAfterFinalizingBlock {
        n_validators: 4,
        epoch_length: 30,
        shutdown_after_finalizing: ShutdownAfterFinalizing::Boundary,
        allegretto_at_genesis: false,
        await_transition: true,
    }
    .run()
}

enum ShutdownAfterFinalizing {
    Ceremony,
    Boundary,
}

impl ShutdownAfterFinalizing {
    fn is_target_height(&self, epoch_length: u64, block_height: u64) -> bool {
        let target_height = match self {
            // NOTE: ceremonies are finalized on the pre-to-last block, so
            // block + 1 needs to be the boundary / last block.
            Self::Ceremony => block_height + 1,
            Self::Boundary => block_height,
        };
        is_last_block_in_epoch(epoch_length, target_height).is_some()
    }
}

struct AssertNodeRecoversAfterFinalizingBlock {
    n_validators: u32,
    epoch_length: u64,
    shutdown_after_finalizing: ShutdownAfterFinalizing,
    allegretto_at_genesis: bool,
    await_transition: bool,
}

impl AssertNodeRecoversAfterFinalizingBlock {
    fn run(self) {
        let Self {
            n_validators,
            epoch_length,
            shutdown_after_finalizing,
            allegretto_at_genesis,
            await_transition,
        } = self;
        assert!(
            !(allegretto_at_genesis && await_transition),
            "awaiting a hardfork transition and setting allegretto at genesis is mutually exclusive"
        );

        let setup = Setup::new()
            .how_many_signers(n_validators)
            .epoch_length(epoch_length);

        let setup = if allegretto_at_genesis {
            setup.allegretto_time(0)
        } else {
            setup.no_validators_in_genesis()
        };

        let setup = if await_transition {
            setup.allegretto_in_seconds(10)
        } else {
            setup
        };

        let cfg = deterministic::Config::default().with_seed(setup.seed);
        let executor = Runner::from(cfg);

        executor.start(|context| async move {
            let (mut validators, execution_runtime) =
                setup_validators(context.clone(), setup.clone()).await;

            join_all(validators.iter_mut().map(|node| node.start())).await;

            if await_transition {
                // Send an arbitrary node of the initial validator set the smart contract call.
                let http_url = validators[0]
                    .execution()
                    .rpc_server_handle()
                    .http_url()
                    .unwrap()
                    .parse::<Url>()
                    .unwrap();

                for (i, node) in validators.iter().enumerate() {
                    let receipt = execution_runtime
                        .add_validator(
                            http_url.clone(),
                            validator(i as u32),
                            node.public_key().clone(),
                            SocketAddr::from(([127, 0, 0, 1], (i + 1) as u16)),
                        )
                        .await
                        .unwrap();

                    tracing::debug!(
                        block.number = receipt.block_number,
                        "addValidator call returned receipt"
                    );
                }

                // Next, wait until a transition is observed.
                loop {
                    context.sleep(Duration::from_secs(1)).await;
                    let metrics = context.encode();

                    let mut transitioned = 0;

                    for line in metrics.lines() {
                        if !line.starts_with(CONSENSUS_NODE_PREFIX) {
                            continue;
                        }
                        let mut parts = line.split_whitespace();
                        let metric = parts.next().unwrap();
                        let value = parts.next().unwrap();

                        if metric.ends_with("_dkg_manager_post_allegretto_ceremonies_total") {
                            let value = value.parse::<u64>().unwrap();
                            transitioned += (value > 0) as u32;
                        }
                    }

                    if transitioned == n_validators {
                        break;
                    }
                }

                tracing::debug!("all nodes transitioned, looking for boundary height");
            }

            // Catch a node right after it processed the pre-to-boundary height.
            // Best-effort: we hot-loop in 100ms steps, but if processing is too
            // fast we might miss the window and the test will succeed no matter
            // what.
            let (metric, height) = 'wait_to_boundary: loop {
                let metrics = context.encode();
                'lines: for line in metrics.lines() {
                    if !line.starts_with(CONSENSUS_NODE_PREFIX) {
                        continue 'lines;
                    }
                    let mut parts = line.split_whitespace();
                    let metric = parts.next().unwrap();
                    let value = parts.next().unwrap();

                    if metric.ends_with("_marshal_processed_height") {
                        let height = value.parse::<u64>().unwrap();
                        if shutdown_after_finalizing.is_target_height(setup.epoch_length, height) {
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
            let idx = validators
                .iter()
                .position(|node| metric.contains(node.uid()))
                .unwrap();
            validators[idx].stop().await;
            validators[idx].start().await;

            let mut iteration = 0;
            'look_for_progress: loop {
                context.sleep(Duration::from_secs(1)).await;
                let metrics = context.encode();
                'lines: for line in metrics.lines() {
                    if !line.starts_with(CONSENSUS_NODE_PREFIX) {
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
}
