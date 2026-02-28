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
    CONSENSUS_NODE_PREFIX, Setup, get_pipeline_runs, setup_validators,
    tests::v2_at_genesis::assert_no_v1,
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

        if metrics.ends_with("_peers_blocked") {
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

        let setup = Setup::new()
            .epoch_length(100)
            .t2_time(0)
            .connect_execution_layer_nodes(should_pipeline_sync);

        Runner::from(Config::default().with_seed(setup.seed)).start(|mut context| async move {
            let (mut nodes, _execution_runtime) =
                setup_validators(&mut context, setup.clone()).await;

            // Start all nodes except the last one
            let mut last = nodes.pop().unwrap();
            join_all(nodes.iter_mut().map(|node| node.start(&context))).await;

            // Wait for chain to advance before starting the last node
            while nodes[0].execution_provider().last_block_number().unwrap() < blocks_before_join {
                context.sleep(Duration::from_secs(1)).await;
            }

            last.start(&context).await;
            assert_eq!(last.execution_provider().last_block_number().unwrap(), 0);

            tracing::debug!("last node started");

            // Assert that last node is able to catch up and progress
            while last.execution_provider().last_block_number().unwrap() < blocks_after_join {
                context.sleep(Duration::from_millis(100)).await;
                assert_no_new_epoch(&context, 0);
            }
            for line in context.encode().lines() {
                if line.starts_with(CONSENSUS_NODE_PREFIX) {
                    continue;
                }
                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();
                assert_no_v1(metric, value);
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
