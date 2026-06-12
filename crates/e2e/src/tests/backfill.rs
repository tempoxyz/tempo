use std::time::Duration;

use commonware_macros::test_traced;
use commonware_runtime::{
    Clock, Metrics, Runner as _,
    deterministic::{Config, Runner},
};
use futures::future::join_all;
use reth_ethereum::storage::BlockNumReader;
use reth_node_metrics::recorder::install_prometheus_recorder;

use crate::{
    Setup, connect_execution_peers, connect_execution_to_peers, get_pipeline_runs, setup_validators,
};

#[test_traced]
fn validator_can_join_later_with_live_sync() {
    AssertJoinsLate {
        blocks_before_join: 5,
        blocks_after_join: 10,
        should_pipeline_sync: false,
    }
    .run();
}

#[test_traced]
fn validator_can_join_later_with_pipeline_sync() {
    AssertJoinsLate {
        blocks_before_join: 65,
        blocks_after_join: 70,
        should_pipeline_sync: false,
    }
    .run();
    let _ = tempo_eyre::install();
}

#[track_caller]
fn assert_no_new_epoch(context: &impl Metrics, max_epoch: u64) {
    let metrics = context.encode();
    for line in metrics.lines() {
        let mut parts = line.split_whitespace();
        let metric = parts.next().unwrap();
        let value = parts.next().unwrap();

        if metric.ends_with("_peers_blocked") {
            let value = value.parse::<u64>().unwrap();
            assert_eq!(value, 0);
        }

        if metric.ends_with("_epoch_manager_latest_epoch") {
            let value = value.parse::<u64>().unwrap();
            assert!(value <= max_epoch, "epoch progressed; sync likely failed");
        }
    }
}

struct AssertJoinsLate {
    blocks_before_join: u64,
    blocks_after_join: u64,
    should_pipeline_sync: bool,
}
impl AssertJoinsLate {
    fn run(self) {
        let Self {
            blocks_before_join,
            blocks_after_join,
            should_pipeline_sync,
        } = self;

        let _ = tempo_eyre::install();
        let metrics_recorder = install_prometheus_recorder();

        let setup = Setup::new().epoch_length(100);

        Runner::from(Config::default().with_seed(setup.seed)).start(|mut context| async move {
            let (mut nodes, _execution_runtime) =
                setup_validators(&mut context, setup.clone()).await;

            // Start all nodes except the last one
            let mut last = nodes.pop().unwrap();
            join_all(nodes.iter_mut().map(|node| node.start(&context))).await;
            if should_pipeline_sync {
                connect_execution_peers(&nodes).await;
            }

            // Wait for chain to advance before starting the last node
            while nodes[0].execution_provider().last_block_number().unwrap() < blocks_before_join {
                context.sleep(Duration::from_secs(1)).await;
            }

            last.start(&context).await;
            if should_pipeline_sync {
                connect_execution_to_peers(&last, &nodes).await;
            }

            assert_eq!(last.execution_provider().last_block_number().unwrap(), 0);

            tracing::debug!("last node started");

            // Assert that last node is able to catch up and progress
            while last.execution_provider().last_block_number().unwrap() < blocks_after_join {
                context.sleep(Duration::from_millis(100)).await;
                assert_no_new_epoch(&context, 0);
            }
            // Verify backfill behavior
            let actual_runs = get_pipeline_runs(metrics_recorder);
            if should_pipeline_sync {
                assert!(
                    actual_runs > 0,
                    "at least one backfill must have been triggered"
                );
            } else {
                assert_eq!(
                    0, actual_runs,
                    "expected no backfill, got {actual_runs} runs"
                );
            }

            // Verify that the node is still progressing after sync
            let last_block = last.execution_provider().last_block_number().unwrap();
            context.sleep(Duration::from_secs(10)).await;
            assert!(
                last.execution_provider().last_block_number().unwrap() > last_block,
                "node should still be progressing after sync"
            );
        });
    }
}

#[test_traced]
fn node_restarts_after_pipeline_sync_with_consensus_behind_execution() {
    AssertRestartsAfterPipelineSync.run();
}

struct AssertRestartsAfterPipelineSync;

impl AssertRestartsAfterPipelineSync {
    fn run(self) {
        let _ = tempo_eyre::install();
        let metrics_recorder = install_prometheus_recorder();

        let setup = Setup::new().epoch_length(100);

        Runner::from(Config::default().with_seed(setup.seed)).start(|mut context| async move {
            let (mut validators, _execution_runtime) =
                setup_validators(&mut context, setup.clone()).await;
            join_all(validators.iter_mut().map(|v| v.start(&context))).await;

            // Wire execution-layer p2p so pipeline sync can transfer data.
            connect_execution_peers(&validators).await;

            while validators[0].execution_provider().last_block_number().unwrap() < 5 {
                context.sleep(Duration::from_millis(100)).await;
            }

            validators[3].stop().await;
            let stopped_at = validators[3].last_db_block_on_stop.unwrap();

            // Advance 65 blocks past where node 3 stopped. Pipeline sync threshold
            // is MIN_BLOCKS_FOR_PIPELINE_RUN = 32; 65 gives comfortable margin.
            let target = stopped_at + 65;
            while validators[0].execution_provider().last_block_number().unwrap() < target {
                context.sleep(Duration::from_millis(100)).await;
            }

            // Snapshot the counter so we can detect a fresh pipeline run.
            let runs_before = get_pipeline_runs(metrics_recorder);

            validators[3].start(&context).await;
            connect_execution_to_peers(&validators[3], &validators).await;

            while get_pipeline_runs(metrics_recorder) <= runs_before {
                context.sleep(Duration::from_millis(200)).await;
            }

            // Read consensus height via metric_prefix(), which returns
            // "{uid}_{n_starts-1}" — after the first restart this is "_1".
            let prefix = validators[3].metric_prefix();
            let consensus_height_after_sync: u64 = loop {
                let metrics = context.encode();
                let mut found = None;
                for line in metrics.lines() {
                    if line.starts_with(&prefix) && line.contains("_marshal_processed_height") {
                        let value = line.split_whitespace().nth(1).unwrap();
                        found = Some(value.parse::<u64>().unwrap());
                        break;
                    }
                }
                if let Some(h) = found {
                    break h;
                }
                context.sleep(Duration::from_millis(200)).await;
            };

            // Stop immediately after pipeline sync — execution is now ahead of consensus.
            validators[3].stop().await;
            let execution_height_after_sync = validators[3].last_db_block_on_stop.unwrap();
            assert!(
                execution_height_after_sync > consensus_height_after_sync,
                "expected execution ({execution_height_after_sync}) > consensus \
                ({consensus_height_after_sync}) after pipeline sync; \
                test precondition not met — the crash-loop scenario was not reproduced"
            );

            // Second restart: this is the crash-loop trigger point fixed by PR #768.
            validators[3].start(&context).await;
            connect_execution_to_peers(&validators[3], &validators).await;

            // Assert node 3 progresses normally rather than crash-looping.
            let prefix2 = validators[3].metric_prefix();
            let mut iterations = 0u32;
            loop {
                let metrics = context.encode();
                let mut height = None;
                for line in metrics.lines() {
                    if line.starts_with(&prefix2) && line.contains("_marshal_processed_height") {
                        let value = line.split_whitespace().nth(1).unwrap();
                        height = Some(value.parse::<u64>().unwrap());
                        break;
                    }
                }
                if height.unwrap_or(0) > execution_height_after_sync {
                    break;
                }
                iterations += 1;
                assert!(
                    iterations < 300,
                    "node 3 did not progress past execution height after 30s; \
                    likely crash-looping or failing to start"
                );
                context.sleep(Duration::from_millis(100)).await;
            }
        });
    }
}
