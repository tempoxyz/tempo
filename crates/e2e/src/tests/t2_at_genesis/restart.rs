//! Tests for validator restart/kill scenarios
//!
//! These tests verify that validators can be killed and restarted, and that they
//! properly catch up to the rest of the network after restart.

use std::time::Duration;

use commonware_consensus::types::{Epocher, FixedEpocher, Height};
use commonware_macros::test_traced;
use commonware_runtime::{
    Clock, Metrics as _, Runner as _,
    deterministic::{self, Context, Runner},
};
use commonware_utils::NZU64;
use futures::future::join_all;
use rand_08::Rng;
use tracing::debug;

use crate::{CONSENSUS_NODE_PREFIX, Setup, setup_validators};

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

    /// Whether to assert that DKG rounds were skipped
    assert_skips: bool,
}

/// Runs a validator restart test with the given configuration
#[track_caller]
fn run_restart_test(
    RestartSetup {
        node_setup,
        shutdown_height,
        restart_height,
        final_height,
        assert_skips,
    }: RestartSetup,
) -> String {
    let _ = tempo_eyre::install();
    let cfg = deterministic::Config::default().with_seed(node_setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let (mut validators, _execution_runtime) =
            setup_validators(&mut context, node_setup.clone()).await;

        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        debug!(
            height = shutdown_height,
            "waiting for network to reach target height before stopping a validator",
        );
        wait_for_height(
            &context,
            node_setup.how_many_signers,
            shutdown_height,
            false,
        )
        .await;

        // Randomly select a validator to kill
        let idx = context.gen_range(0..validators.len());
        validators[idx].stop().await;

        debug!(public_key = %validators[idx].public_key(), "stopped a random validator");

        debug!(
            height = restart_height,
            "waiting for remaining validators to reach target height before restarting validator",
        );
        wait_for_height(
            &context,
            node_setup.how_many_signers - 1,
            restart_height,
            false,
        )
        .await;

        debug!("target height reached, restarting stopped validator");
        validators[idx].start(&context).await;
        debug!(
            public_key = %validators[idx].public_key(),
            "restarted validator",
        );

        debug!(
            height = final_height,
            "waiting for reconstituted validators to reach target height to reach test success",
        );
        wait_for_height(
            &context,
            node_setup.how_many_signers,
            final_height,
            assert_skips,
        )
        .await;

        context.auditor().state()
    })
}

/// Wait for a specific number of validators to reach a target height
async fn wait_for_height(
    context: &Context,
    expected_validators: u32,
    target_height: u64,
    assert_skips: bool,
) {
    let mut skips_observed = false;
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
            if metric.ends_with("_rounds_skipped_total") {
                let count = value.parse::<u64>().unwrap();
                skips_observed |= count > 0;
            }
        }
        if validators_at_height == expected_validators {
            assert!(!assert_skips || skips_observed);
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
fn network_resumes_after_restart_with_el_p2p() {
    let _ = tempo_eyre::install();

    for seed in 0..3 {
        let setup = Setup::new()
            .how_many_signers(3) // quorum for 3 validators is 3.
            .seed(seed)
            .epoch_length(100)
            .connect_execution_layer_nodes(true);

        let shutdown_height = 5;
        let final_height = 10;

        let cfg = deterministic::Config::default().with_seed(setup.seed);
        let executor = Runner::from(cfg);

        executor.start(|mut context| async move {
            let (mut validators, _execution_runtime) =
                setup_validators(&mut context, setup.clone()).await;

            join_all(validators.iter_mut().map(|v| v.start(&context))).await;

            debug!(
                height = shutdown_height,
                "waiting for network to reach target height before stopping a validator",
            );
            wait_for_height(&context, setup.how_many_signers, shutdown_height, false).await;

            let idx = context.gen_range(0..validators.len());
            validators[idx].stop().await;
            debug!(public_key = %validators[idx].public_key(), "stopped a random validator");

            // wait a bit to let the network settle; some finalizations come in later
            context.sleep(Duration::from_secs(1)).await;
            ensure_no_progress(&context, 5).await;

            validators[idx].start(&context).await;
            debug!(
                public_key = %validators[idx].public_key(),
                "restarted validator",
            );

            debug!(
                height = final_height,
                "waiting for reconstituted validators to reach target height to reach test success",
            );
            wait_for_height(&context, validators.len() as u32, final_height, false).await;
        })
    }
}

/// This is the simplest possible restart case: the network stops because we
/// dropped below quorum. The node should be able to pick up after.
#[test_traced]
fn network_resumes_after_restart_without_el_p2p() {
    let _ = tempo_eyre::install();

    for seed in 0..3 {
        let setup = Setup::new()
            .how_many_signers(3) // quorum for 3 validators is 3.
            .seed(seed)
            .epoch_length(100)
            .connect_execution_layer_nodes(false);

        let shutdown_height = 5;
        let final_height = 10;

        let cfg = deterministic::Config::default().with_seed(setup.seed);
        let executor = Runner::from(cfg);

        executor.start(|mut context| async move {
            let (mut validators, _execution_runtime) =
                setup_validators(&mut context, setup.clone()).await;

            join_all(validators.iter_mut().map(|v| v.start(&context))).await;

            debug!(
                height = shutdown_height,
                "waiting for network to reach target height before stopping a validator",
            );
            wait_for_height(&context, setup.how_many_signers, shutdown_height, false).await;

            let idx = context.gen_range(0..validators.len());
            validators[idx].stop().await;
            debug!(public_key = %validators[idx].public_key(), "stopped a random validator");

            // wait a bit to let the network settle; some finalizations come in later
            context.sleep(Duration::from_secs(1)).await;
            ensure_no_progress(&context, 5).await;

            validators[idx].start(&context).await;
            debug!(
                public_key = %validators[idx].public_key(),
                "restarted validator",
            );

            debug!(
                height = final_height,
                "waiting for reconstituted validators to reach target height to reach test success",
            );
            wait_for_height(&context, validators.len() as u32, final_height, false).await;
        })
    }
}

#[test_traced]
fn validator_catches_up_to_network_during_epoch() {
    let _ = tempo_eyre::install();

    let setup = RestartSetup {
        node_setup: Setup::new().epoch_length(100),
        shutdown_height: 5,
        restart_height: 10,
        final_height: 15,
        assert_skips: false,
    };

    let _state = run_restart_test(setup);
}

#[test_traced]
fn validator_catches_up_with_gap_of_one_epoch() {
    let _ = tempo_eyre::install();

    let epoch_length = 30;
    let setup = RestartSetup {
        node_setup: Setup::new().epoch_length(epoch_length),
        shutdown_height: epoch_length + 1,
        restart_height: 2 * epoch_length + 1,
        final_height: 3 * epoch_length + 1,
        assert_skips: false,
    };

    let _state = run_restart_test(setup);
}

#[test_traced]
fn validator_catches_up_with_gap_of_three_epochs() {
    let _ = tempo_eyre::install();

    let epoch_length = 30;
    let setup = RestartSetup {
        node_setup: Setup::new()
            .epoch_length(epoch_length)
            .connect_execution_layer_nodes(true),
        shutdown_height: epoch_length + 1,
        restart_height: 4 * epoch_length + 1,
        final_height: 5 * epoch_length + 1,
        assert_skips: true,
    };

    let _state = run_restart_test(setup);
}

#[test_traced]
fn single_node_recovers_after_finalizing_ceremony() {
    AssertNodeRecoversAfterFinalizingBlock {
        n_validators: 1,
        epoch_length: 6,
        shutdown_after_finalizing: ShutdownAfterFinalizing::Ceremony,
    }
    .run()
}

#[test_traced]
fn node_recovers_after_finalizing_ceremony_four_validators() {
    AssertNodeRecoversAfterFinalizingBlock {
        n_validators: 4,
        epoch_length: 30,
        shutdown_after_finalizing: ShutdownAfterFinalizing::Ceremony,
    }
    .run()
}

#[test_traced]
fn node_recovers_after_finalizing_middle_of_epoch_four_validators() {
    AssertNodeRecoversAfterFinalizingBlock {
        n_validators: 4,
        epoch_length: 30,
        shutdown_after_finalizing: ShutdownAfterFinalizing::MiddleOfEpoch,
    }
    .run()
}

#[test_traced]
fn node_recovers_before_finalizing_middle_of_epoch_four_validators() {
    AssertNodeRecoversAfterFinalizingBlock {
        n_validators: 4,
        epoch_length: 30,
        shutdown_after_finalizing: ShutdownAfterFinalizing::BeforeMiddleOfEpoch,
    }
    .run()
}

#[test_traced]
fn single_node_recovers_after_finalizing_boundary() {
    AssertNodeRecoversAfterFinalizingBlock {
        n_validators: 1,
        epoch_length: 10,
        shutdown_after_finalizing: ShutdownAfterFinalizing::Boundary,
    }
    .run()
}

#[test_traced]
fn node_recovers_after_finalizing_boundary_four_validators() {
    AssertNodeRecoversAfterFinalizingBlock {
        n_validators: 4,
        epoch_length: 30,
        shutdown_after_finalizing: ShutdownAfterFinalizing::Boundary,
    }
    .run()
}

enum ShutdownAfterFinalizing {
    Boundary,
    Ceremony,
    BeforeMiddleOfEpoch,
    MiddleOfEpoch,
}

impl ShutdownAfterFinalizing {
    fn is_target_height(&self, epoch_length: u64, block_height: Height) -> bool {
        let epoch_strategy = FixedEpocher::new(NZU64!(epoch_length));
        match self {
            // NOTE: ceremonies are finalized on the pre-to-last block, so
            // block + 1 needs to be the boundary / last block.
            Self::Ceremony => {
                block_height.next()
                    == epoch_strategy
                        .containing(block_height.next())
                        .unwrap()
                        .last()
            }
            Self::Boundary => {
                block_height == epoch_strategy.containing(block_height).unwrap().last()
            }
            Self::BeforeMiddleOfEpoch => {
                block_height.next().get().rem_euclid(epoch_length) == epoch_length / 2
            }
            Self::MiddleOfEpoch => block_height.get().rem_euclid(epoch_length) == epoch_length / 2,
        }
    }
}

impl std::fmt::Display for ShutdownAfterFinalizing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::Boundary => "boundary",
            Self::Ceremony => "ceremony",
            Self::BeforeMiddleOfEpoch => "before-middle-of-epoch",
            Self::MiddleOfEpoch => "middle-of-epoch",
        };
        f.write_str(msg)
    }
}

struct AssertNodeRecoversAfterFinalizingBlock {
    n_validators: u32,
    epoch_length: u64,
    shutdown_after_finalizing: ShutdownAfterFinalizing,
}

impl AssertNodeRecoversAfterFinalizingBlock {
    fn run(self) {
        let _ = tempo_eyre::install();

        let Self {
            n_validators,
            epoch_length,
            shutdown_after_finalizing,
        } = self;

        let setup = Setup::new()
            .how_many_signers(n_validators)
            .epoch_length(epoch_length);

        let cfg = deterministic::Config::default().with_seed(setup.seed);
        let executor = Runner::from(cfg);

        executor.start(|mut context| async move {
            let (mut validators, _execution_runtime) =
                setup_validators(&mut context, setup.clone()).await;

            join_all(validators.iter_mut().map(|node| node.start(&context))).await;

            // Catch a node right after it processed the pre-to-boundary height.
            // Best-effort: we hot-loop in 100ms steps, but if processing is too
            // fast we might miss the window and the test will succeed no matter
            // what.
            let (stopped_val_metric, height) = 'wait_to_boundary: loop {
                let metrics = context.encode();
                'lines: for line in metrics.lines() {
                    if !line.starts_with(CONSENSUS_NODE_PREFIX) {
                        continue 'lines;
                    }
                    let mut parts = line.split_whitespace();
                    let metric = parts.next().unwrap();
                    let value = parts.next().unwrap();

                    if metric.ends_with("_marshal_processed_height") {
                        let value = value.parse::<u64>().unwrap();
                        if shutdown_after_finalizing
                            .is_target_height(setup.epoch_length, Height::new(value))
                        {
                            break 'wait_to_boundary (metric.to_string(), value);
                        }
                    }
                }
                context.sleep(Duration::from_millis(100)).await;
            };

            tracing::debug!(
                stopped_val_metric,
                height,
                target = %shutdown_after_finalizing,
                "found a node that finalized the target height",
            );
            // Now restart the node for which we found the metric.
            let idx = validators
                .iter()
                .position(|node| stopped_val_metric.contains(node.uid()))
                .unwrap();
            let uid = validators[idx].uid.clone();
            validators[idx].stop().await;
            validators[idx].start(&context).await;

            let mut iteration = 0;
            'look_for_progress: loop {
                context.sleep(Duration::from_secs(1)).await;
                let metrics = context.encode();
                'lines: for line in metrics.lines() {
                    if !line.starts_with(CONSENSUS_NODE_PREFIX) {
                        continue 'lines;
                    }
                    let mut parts = line.split_whitespace();
                    let metric = parts.next().unwrap();
                    let value = parts.next().unwrap();
                    if metric.contains(&uid)
                        && metric.ends_with("_marshal_processed_height")
                        && value.parse::<u64>().unwrap() > height + 10
                    {
                        break 'look_for_progress;
                    }
                    if metric.ends_with("ceremony_bad_dealings") {
                        assert_eq!(value.parse::<u64>().unwrap(), 0);
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
