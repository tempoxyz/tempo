use std::time::Duration;

use commonware_macros::test_traced;
use commonware_runtime::{
    Clock, Metrics, Runner as _,
    deterministic::{self, Context, Runner},
};
use futures::future::join_all;
use reth_ethereum::storage::BlockNumReader;
use reth_node_metrics::recorder::install_prometheus_recorder;

use crate::{Setup, get_pipeline_runs, setup_validators};

async fn run_validator_late_join_test(
    context: &mut Context,
    blocks_before_join: u64,
    blocks_after_join: u64,
    should_pipeline_sync: bool,
) {
    let metrics_recorder = install_prometheus_recorder();

    let setup = Setup::new()
        .epoch_length(100)
        .connect_execution_layer_nodes(should_pipeline_sync);

    let (mut nodes, _execution_runtime) = setup_validators(context, setup.clone()).await;

    // Start all nodes except the last one
    let mut last = nodes.pop().unwrap();
    join_all(nodes.iter_mut().map(|node| node.start(context))).await;

    // Wait for chain to advance before starting the last node
    while nodes[0].execution_provider().last_block_number().unwrap() < blocks_before_join {
        context.sleep(Duration::from_secs(1)).await;
    }

    last.start(context).await;
    assert_eq!(last.execution_provider().last_block_number().unwrap(), 0);

    tracing::debug!("last node started");

    // Assert that last node is able to catch up and progress
    while last.execution_provider().last_block_number().unwrap() < blocks_after_join {
        context.sleep(Duration::from_millis(100)).await;
        assert_no_new_epoch(context, 0);
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
}

#[test_traced]
fn validator_can_join_later_with_live_sync() {
    let _ = tempo_eyre::install();

    Runner::from(deterministic::Config::default().with_seed(0)).start(|mut context| async move {
        run_validator_late_join_test(&mut context, 5, 10, false).await;
    });
}

#[test_traced]
fn validator_can_join_later_with_pipeline_sync() {
    let _ = tempo_eyre::install();

    Runner::from(deterministic::Config::default().with_seed(0)).start(|mut context| async move {
        run_validator_late_join_test(&mut context, 65, 70, true).await;
    });
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
