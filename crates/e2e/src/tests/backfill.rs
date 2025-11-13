use std::time::Duration;

use commonware_macros::test_traced;
use commonware_p2p::simulated::Link;
use commonware_runtime::{
    Clock, Runner as _,
    deterministic::{self, Context, Runner},
};
use reth_ethereum::storage::BlockNumReader;
use reth_node_metrics::recorder::install_prometheus_recorder;

use crate::{ExecutionRuntime, Setup, get_pipeline_runs, link_validators, setup_validators};

async fn run_validator_late_join_test(
    context: &Context,
    blocks_before_join: u64,
    blocks_after_join: u64,
    should_pipeline_sync: bool,
) {
    let how_many_signers = 5;

    let linkage = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };
    let setup = Setup {
        how_many_signers,
        seed: 0,
        linkage: linkage.clone(),
        epoch_length: 100,
        connect_execution_layer_nodes: should_pipeline_sync,
    };

    let execution_runtime = ExecutionRuntime::new();
    let (mut nodes, mut oracle) =
        setup_validators(context.clone(), &execution_runtime, setup).await;

    let validators = nodes
        .iter()
        .map(|node| node.public_key.clone())
        .collect::<Vec<_>>();

    // Start all nodes except the last one
    let last = nodes.pop().unwrap();
    let mut running = vec![];
    for node in nodes {
        running.push(node.start().await);
    }

    link_validators(&mut oracle, &validators[0..4], linkage.clone(), None).await;

    // Wait for chain to advance before starting the last node
    while running[0].node.node.provider.last_block_number().unwrap() < blocks_before_join {
        context.sleep(Duration::from_secs(1)).await;
    }

    assert_eq!(last.node.node.provider.last_block_number().unwrap(), 0);

    let metrics_recorder = install_prometheus_recorder();

    // Start the last node
    let last = last.start().await;
    link_validators(&mut oracle, &validators[0..5], linkage.clone(), None).await;

    // Assert that last node is able to catch up and progress
    while last.node.node.provider.last_block_number().unwrap() < blocks_after_join {
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
