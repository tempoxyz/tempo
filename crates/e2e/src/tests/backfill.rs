use std::time::Duration;

use commonware_macros::test_traced;
use commonware_p2p::simulated::Link;
use commonware_runtime::{
    Clock, Runner as _,
    deterministic::{self, Context, Runner},
};
use reth_ethereum::storage::BlockNumReader;
use reth_node_metrics::recorder::install_prometheus_recorder;

use crate::{ExecutionRuntime, Setup, get_pipeline_runs, setup_validators};

async fn run_validator_late_join_test(
    context: &Context,
    blocks_before_join: u64,
    blocks_after_join: u64,
    expected_backfill_runs: u64,
) {
    let num_nodes = 5;

    let setup = Setup {
        how_many: num_nodes,
        seed: 0,
        linkage: Link {
            latency: Duration::from_millis(10),
            jitter: Duration::from_millis(1),
            success_rate: 1.0,
        },
        epoch_length: 100,
    };

    let execution_runtime = ExecutionRuntime::new();
    let (mut nodes, _network_handle) =
        setup_validators(context.clone(), &execution_runtime, setup).await;

    // Start all nodes except the last one
    let mut last = nodes.pop().unwrap();
    for node in &mut nodes {
        node.start().await;
    }

    // Wait for chain to advance before starting the last node
    while nodes[0].node.node.provider.last_block_number().unwrap() < blocks_before_join {
        context.sleep(Duration::from_secs(1)).await;
    }

    assert_eq!(last.node.node.provider.last_block_number().unwrap(), 0);

    let metrics_recorder = install_prometheus_recorder();

    // Start the last node
    last.start().await;

    // Assert that last node is able to catch up and progress
    while last.node.node.provider.last_block_number().unwrap() < blocks_after_join {
        context.sleep(Duration::from_millis(100)).await;
    }

    // Verify backfill behavior
    let actual_runs = get_pipeline_runs(metrics_recorder);
    assert!(
        actual_runs == expected_backfill_runs,
        "Expected {expected_backfill_runs} backfill runs, got {actual_runs}"
    );

    // Verify that the node is still progressing after sync
    let last_block = last.node.node.provider.last_block_number().unwrap();
    context.sleep(Duration::from_secs(2)).await;
    assert!(
        last.node.node.provider.last_block_number().unwrap() > last_block,
        "Node should still be progressing after sync"
    );
}

#[test_traced]
fn validator_can_join_later_with_live_sync() {
    let _ = tempo_eyre::install();

    Runner::from(deterministic::Config::default().with_seed(0)).start(|context| async move {
        run_validator_late_join_test(&context, 5, 10, 0).await;
    });
}

#[test_traced]
fn validator_can_join_later_with_pipeline_sync() {
    let _ = tempo_eyre::install();

    Runner::from(deterministic::Config::default().with_seed(0)).start(|context| async move {
        run_validator_late_join_test(&context, 65, 70, 1).await;
    });
}
