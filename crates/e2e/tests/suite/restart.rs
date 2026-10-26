//! Tests for validator restart/kill scenarios
//!
//! These tests verify that validators can be killed and restarted, and that they
//! properly catch up to the rest of the network after restart.

use std::time::Duration;

use commonware_macros::test_traced;
use commonware_runtime::{
    Clock, Runner as _,
    deterministic::{self, Context, Runner},
};
use futures::future::join_all;
use rand::RngExt as _;
use reth_ethereum::storage::BlockNumReader;
use reth_node_metrics::recorder::install_prometheus_recorder;
use tracing::debug;

use crate::{
    Setup, connect_execution_peers, connect_execution_to_peers, get_pipeline_runs,
    metrics::{Metrics, MetricsExt, wait_for_metrics_with_interval},
    setup_validators,
};

#[test_traced("WARN")]
fn committee_of_one_restart() {
    SimpleRestart {
        committee_size: 1,
        epoch_length: 10,
        restart_after: 5,
        stop_at: 10,
        connect_execution_layer: false,
    }
    .run()
}

#[test_traced]
fn committee_of_three_restart() {
    SimpleRestart {
        committee_size: 3,
        epoch_length: 10,
        restart_after: 5,
        stop_at: 10,
        connect_execution_layer: false,
    }
    .run()
}

struct SimpleRestart {
    committee_size: u32,
    epoch_length: u64,
    restart_after: u64,
    stop_at: u64,
    connect_execution_layer: bool,
}

impl SimpleRestart {
    #[track_caller]
    fn run(self) {
        let Self {
            committee_size,
            epoch_length,
            restart_after,
            stop_at,
            connect_execution_layer,
        } = self;
        let _ = tempo_eyre::install();

        let setup = Setup::new(crate::VERIFICATION_MODE)
            .how_many_signers(committee_size)
            .seed(0)
            .epoch_length(epoch_length);

        let cfg = deterministic::Config::default().with_seed(setup.seed);
        let executor = Runner::from(cfg);

        executor.start(|mut context| async move {
            let (mut validators, _execution_runtime) =
                setup_validators(&mut context, setup.clone()).await;

            join_all(validators.iter_mut().map(|v| v.start(&context))).await;
            if connect_execution_layer {
                connect_execution_peers(&validators).await;
            }

            debug!(
                height = restart_after,
                "waiting for network to reach target height before stopping a validator",
            );
            wait_for_height(&context, setup.how_many_signers, restart_after).await;

            validators[0].stop().await;
            debug!(public_key = %validators[0].public_key(), "stopped validator");

            // wait a bit to let the network settle; some finalizations come in later
            context.sleep(Duration::from_secs(2)).await;
            ensure_no_progress(&context, 3).await;

            validators[0].start(&context).await;
            if connect_execution_layer {
                connect_execution_to_peers(&validators[0], &validators).await;
            }

            debug!(
                public_key = %validators[0].public_key(),
                "restarted validator",
            );

            debug!(
                height = stop_at,
                "waiting for reconstituted validators to reach target height to reach test success",
            );
            wait_for_height(&context, validators.len() as u32, stop_at).await;
        })
    }
}

#[test_traced]
fn validator_catches_up_to_network_during_epoch() {
    let _ = tempo_eyre::install();

    RestartSetup {
        epoch_length: 100,
        shutdown_height: 5,
        restart_height: 10,
        final_height: 15,
        connect_execution_layer: false,
    }
    .run();
}

#[test_traced]
fn validator_catches_up_with_gap_of_one_epoch() {
    let _ = tempo_eyre::install();

    // Keep the epoch longer than the default 20-block marshal repair batch.
    let epoch_length = 21;
    RestartSetup {
        epoch_length,
        shutdown_height: epoch_length + 1,
        restart_height: 2 * epoch_length + 1,
        final_height: 3 * epoch_length + 1,
        connect_execution_layer: false,
    }
    .run();
}

#[test_traced]
fn validator_catches_up_with_gap_of_three_epochs() {
    let _ = tempo_eyre::install();

    // Keep the epoch longer than the default 20-block marshal repair batch.
    let epoch_length = 21;
    RestartSetup {
        epoch_length,
        connect_execution_layer: true,
        shutdown_height: epoch_length + 1,
        restart_height: 4 * epoch_length + 1,
        final_height: 5 * epoch_length + 1,
    }
    .run();
}

/// Restarts a validator while its execution layer has finalized an epoch
/// boundary that marshal has not yet processed, because the boundary is not
/// yet durable. After the restart, marshal re-delivers the boundary to the
/// DKG manager, which must neither stall nor produce bad dealings.
///
/// The restart point depends on timing across the deterministic and the
/// execution layer's runtimes, so the test asserts that it reached the
/// intended state instead of assuming it.
#[test_traced]
fn node_recovers_after_restart_with_unprocessed_boundary() {
    let _ = tempo_eyre::install();

    let epoch_length = 30;
    // The second boundary, once the execution layer persists in steady state.
    let boundary = 2 * epoch_length - 1;
    let setup = Setup::new(crate::VERIFICATION_MODE)
        .how_many_signers(4)
        .epoch_length(epoch_length);

    let cfg = deterministic::Config::default().with_seed(setup.seed);
    Runner::from(cfg).start(|mut context| async move {
        let (mut validators, _execution_runtime) =
            setup_validators(&mut context, setup.clone()).await;
        join_all(validators.iter_mut().map(|node| node.start(&context))).await;

        let restarted = 0;
        let mut attempts = 0;
        while validators[restarted]
            .execution()
            .provider
            .canonical_in_memory_state()
            .get_finalized_num_hash()
            .is_none_or(|finalized| finalized.number < boundary)
        {
            attempts += 1;
            assert!(
                attempts < 3_000,
                "execution layer did not finalize the boundary `{boundary}` in time"
            );
            context.sleep(Duration::from_millis(20)).await;
        }
        let processed = context
            .to_metrics()
            .for_scope(&validators[restarted])
            .latest_consensus_height()
            .unwrap_or_default();
        assert!(
            processed < boundary,
            "marshal already processed height `{processed}`, so the restart \
            would not replay the boundary `{boundary}`",
        );

        validators[restarted].stop().await;
        validators[restarted].start(&context).await;

        for attempt in 0.. {
            context.sleep(Duration::from_secs(1)).await;
            let metrics = context.to_metrics();
            assert!(
                metrics
                    .values::<u64>("ceremony_bad_dealings")
                    .all(|bad_dealings| bad_dealings == 0)
            );
            if metrics
                .for_scope(&validators[restarted])
                .latest_consensus_height()
                .is_some_and(|height| height > boundary + 10)
            {
                break;
            }
            assert!(
                attempt < 30,
                "restarted validator did not progress past the replayed boundary"
            );
        }
    });
}

/// Test configuration for restart scenarios
#[derive(Clone)]
struct RestartSetup {
    // The epoch length to use.
    epoch_length: u64,
    /// Whether to connect the execution layer.
    connect_execution_layer: bool,
    /// Height at which to shutdown a validator
    shutdown_height: u64,
    /// Height at which to restart the validator
    restart_height: u64,
    /// Final height that all validators (including restarted) must reach
    final_height: u64,
}

impl RestartSetup {
    #[track_caller]
    fn run(self) {
        let Self {
            epoch_length,
            shutdown_height,
            restart_height,
            final_height,
            connect_execution_layer,
        } = self;
        let _ = tempo_eyre::install();

        let setup = Setup::new(crate::VERIFICATION_MODE).epoch_length(epoch_length);

        let cfg = deterministic::Config::default().with_seed(setup.seed);
        let executor = Runner::from(cfg);

        executor.start(|mut context| async move {
            let (mut validators, _execution_runtime) =
                setup_validators(&mut context, setup.clone()).await;

            join_all(validators.iter_mut().map(|v| v.start(&context))).await;
            if connect_execution_layer {
                connect_execution_peers(&validators).await;
            }

            debug!(
                height = shutdown_height,
                "waiting for network to reach target height before stopping a validator",
            );
            wait_for_height(&context, setup.how_many_signers, shutdown_height).await;

            // Randomly select a validator to kill
            let idx = context.random_range(0..validators.len());
            validators[idx].stop().await;

            debug!(public_key = %validators[idx].public_key(), "stopped a random validator");

            debug!(
                height = restart_height,
                "waiting for remaining validators to reach target height before restarting validator",
            );
            wait_for_height(&context, setup.how_many_signers - 1, restart_height).await;

            debug!("target height reached, restarting stopped validator");
            validators[idx].start(&context).await;
            if connect_execution_layer {
                connect_execution_to_peers(&validators[idx], &validators).await;
            }

            debug!(
                public_key = %validators[idx].public_key(),
                "restarted validator",
            );

            debug!(
                height = final_height,
                "waiting for reconstituted validators to reach target height to reach test success",
            );
            wait_for_height(&context, setup.how_many_signers, final_height).await;
        })
    }
}

/// Wait for a specific number of validators to reach a target height
async fn wait_for_height(context: &Context, expected_validators: u32, target_height: u64) {
    wait_for_metrics_with_interval(context, Duration::from_secs(1), |metrics| {
        metrics.consensus_at_height(target_height) == expected_validators as usize
    })
    .await;
}

/// Ensures that no more finalizations happen.
async fn ensure_no_progress(context: &Context, tries: u32) {
    let baseline = max_consensus_height(&context.to_metrics());
    for _ in 0..=tries {
        context.sleep(Duration::from_secs(1)).await;

        let height = max_consensus_height(&context.to_metrics());
        if height != baseline {
            panic!(
                "height has changed, progress was made while the network was \
                stopped: baseline = `{baseline:?}`, progressed_to = `{height:?}`"
            );
        }
    }
}

fn max_consensus_height(metrics: &Metrics) -> Option<u64> {
    metrics.values::<u64>("_marshal_processed_height").max()
}
/// After a clean stop, unwind reth's DB by 2 blocks, then restart. The CL's
/// marshal storage still has the higher finalized height, so the executor's
/// `backfill_on_start` path fires to replay the missing blocks.
///
/// This also simulates regular expected EL behavior, where the last few
/// blocks are not guaranteed to be persisted even if finalized.
#[test_traced]
fn backfill_on_start_after_crash() {
    let _ = tempo_eyre::install();

    let setup = Setup::new(crate::VERIFICATION_MODE)
        .how_many_signers(1)
        .epoch_length(100);

    let cfg = deterministic::Config::default().with_seed(setup.seed);
    Runner::from(cfg).start(|mut context| async move {
        let (mut validators, _execution_runtime) =
            setup_validators(&mut context, setup.clone()).await;

        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        // Wait for chain to advance past 10
        wait_for_height(&context, 1, 10).await;

        validators[0].stop().await;

        // Unwind EL by 2 blocks to simulate crash
        let (el_before, el_after) = validators[0].unwind(2);
        assert!(el_before > el_after);

        // Restart — should trigger backfill_on_start
        validators[0].start(&context).await;

        // Wait for the node to recover and produce past the pre-unwind height
        wait_for_height(&context, 1, el_before + 5).await;

        // Verify the EL's canonical head includes the recovered blocks. Recent
        // canonical blocks may remain in memory until reth's persistence threshold is reached.
        let el_recovered = validators[0]
            .execution_provider()
            .best_block_number()
            .unwrap();
        assert!(
            el_recovered >= el_before,
            "EL should have recovered to at least {el_before} after backfill, \
            got {el_recovered}"
        );
    });
}

/// Reproduces the race where a large EL gap triggers a pipeline run on
/// restart.
///
/// On restart with a 50-block gap, `select_biased!` in the consensus loop
/// falls through to the mailbox while `marshal.get_block()` is still
/// pending. A `Finalize` for `CL_tip + 1` arrives from live consensus;
/// its FCU triggers a download from EL peers. The downloaded block is
/// disconnected from the local chain and the gap exceeds 32, so reth
/// triggers a pipeline run.
///
/// The test asserts that **no** pipeline runs occur — the node should
/// recover purely via backfill + live sync.
#[test_traced]
fn backfill_on_start_large_gap_does_not_trigger_pipeline_sync() {
    let _ = tempo_eyre::install();
    let metrics_recorder = install_prometheus_recorder();

    let setup = Setup::new(crate::VERIFICATION_MODE)
        .how_many_signers(4)
        .epoch_length(100);

    let cfg = deterministic::Config::default().with_seed(setup.seed);
    Runner::from(cfg).start(|mut context| async move {
        let (mut validators, _execution_runtime) =
            setup_validators(&mut context, setup.clone()).await;

        join_all(validators.iter_mut().map(|v| v.start(&context))).await;
        connect_execution_peers(&validators).await;

        // Let the network reach height 40.
        wait_for_height(&context, 4, 40).await;

        // Stop validator[0] and unwind its EL by 35 blocks (exceeds 32-block pipeline sync threshold).
        validators[0].stop().await;
        let (el_before, el_after) = validators[0].unwind(35);
        debug!(el_before, el_after, "unwound validator[0] by 35 blocks");

        // Let the remaining 3 validators advance 10 more blocks.
        wait_for_height(&context, 3, 50).await;

        let pipeline_runs_before = get_pipeline_runs(metrics_recorder);

        // Restart validator[0] with EL peers connected.
        validators[0].start(&context).await;
        connect_execution_to_peers(&validators[0], &validators).await;

        // Wait up to 60s for the node to recover.
        let mut recovered = false;
        for _ in 0..60 {
            context.sleep(Duration::from_secs(1)).await;
            let current = validators[0]
                .execution_provider()
                .last_block_number()
                .unwrap();

            if current >= el_before + 5 {
                recovered = true;
                break;
            }
        }

        assert!(recovered, "unwound validator did not recover");

        let new_pipeline_runs = get_pipeline_runs(metrics_recorder) - pipeline_runs_before;
        assert_eq!(new_pipeline_runs, 0);
    });
}
