use std::time::Duration;

use commonware_macros::test_traced;
use commonware_runtime::{
    Clock, Runner as _,
    deterministic::{self, Context, Runner},
};
use futures::future::join_all;
use reth_ethereum::storage::BlockNumReader;
use reth_node_metrics::recorder::install_prometheus_recorder;

use crate::{Setup, get_pipeline_runs, setup_validators};

async fn run_validator_late_join_test(
    context: &Context,
    blocks_before_join: u64,
    blocks_after_join: u64,
    should_pipeline_sync: bool,
) {
    let metrics_recorder = install_prometheus_recorder();

    let setup = Setup::new()
        .epoch_length(100)
        .connect_execution_layer_nodes(should_pipeline_sync);

    let (mut nodes, _execution_runtime) = setup_validators(context.clone(), setup.clone()).await;

    // Start all nodes except the last one
    let mut last = nodes.pop().unwrap();
    join_all(nodes.iter_mut().map(|node| node.start())).await;

    // Wait for chain to advance before starting the last node
    while nodes[0].execution_provider().last_block_number().unwrap() < blocks_before_join {
        context.sleep(Duration::from_secs(1)).await;
    }

    // Start the last node
    last.start().await;
    assert_eq!(last.execution_provider().last_block_number().unwrap(), 0);

    // Assert that last node is able to catch up and progress
    while last.execution_provider().last_block_number().unwrap() < blocks_after_join {
        context.sleep(Duration::from_millis(100)).await;
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
            "Expected no backfill, got {actual_runs} runs"
        );
    }

    // Verify that the node is still progressing after sync
    let last_block = last.execution_provider().last_block_number().unwrap();
    context.sleep(Duration::from_secs(5)).await;
    assert!(
        last.execution_provider().last_block_number().unwrap() > last_block,
        "Node should still be progressing after sync"
    );
}

#[test_traced]
fn validator_can_join_later_with_live_sync() {
    let _ = tempo_eyre::install();

    Runner::from(deterministic::Config::default().with_seed(0)).start(|context| async move {
        run_validator_late_join_test(&context, 5, 10, false).await;
    });
}

#[test_traced]
fn validator_can_join_later_with_pipeline_sync() {
    let _ = tempo_eyre::install();

    Runner::from(deterministic::Config::default().with_seed(0)).start(|context| async move {
        run_validator_late_join_test(&context, 65, 70, true).await;
    });
}
