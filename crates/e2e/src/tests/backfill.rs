use std::time::Duration;

use commonware_macros::test_traced;
use commonware_runtime::{
    Clock, Runner as _,
    deterministic::{Config, Runner},
};
use futures::future::join_all;
use reth_ethereum::storage::BlockNumReader;
use reth_node_metrics::recorder::install_prometheus_recorder;

use crate::{
    Setup, connect_execution_peers, connect_execution_to_peers, get_pipeline_runs,
    metrics::MetricsExt, setup_validators,
};

#[test_traced]
fn validator_joins_on_small_gap() {
    AssertJoinsLate {
        blocks_before_join: 5,
        blocks_after_join: 10,
    }
    .run();
}

#[test_traced]
fn validator_joins_on_large_gap_without_triggering_pipeline_sync() {
    AssertJoinsLate {
        // reth triggers a pipeline sync if a gap exceeds 32 blocks.
        // 32 * 2 + 1 ensures that this should definitely have triggered a
        // pipelinesync if the executor sent the wrong FCU.
        blocks_before_join: 65,
        blocks_after_join: 70,
    }
    .run();
    let _ = tempo_eyre::install();
}

struct AssertJoinsLate {
    blocks_before_join: u64,
    blocks_after_join: u64,
}
impl AssertJoinsLate {
    fn run(self) {
        let Self {
            blocks_before_join,
            blocks_after_join,
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
            connect_execution_peers(&nodes).await;

            // Wait for chain to advance before starting the last node
            while nodes[0].execution_provider().last_block_number().unwrap() < blocks_before_join {
                context.sleep(Duration::from_secs(1)).await;
            }

            last.start(&context).await;
            connect_execution_to_peers(&last, &nodes).await;

            assert_eq!(last.execution_provider().last_block_number().unwrap(), 0);

            tracing::debug!("last node started");

            // Assert that last node is able to catch up and progress
            while last.execution_provider().last_block_number().unwrap() < blocks_after_join {
                context.sleep(Duration::from_millis(100)).await;
                let metrics = context.to_metrics();
                metrics.assert_no_blocked_peers();
                assert!(
                    metrics.consensus_before_epoch(2),
                    "epoch progressed; sync likely failed"
                );
            }
            // Verify backfill behavior
            let actual_runs = get_pipeline_runs(metrics_recorder);
            assert_eq!(
                0, actual_runs,
                "expected no pipline sync, got {actual_runs}",
            );
        });
    }
}
