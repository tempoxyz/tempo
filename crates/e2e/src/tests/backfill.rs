use std::time::Duration;

use commonware_macros::test_traced;
use commonware_p2p::simulated::Link;
use commonware_runtime::{
    Clock, Runner as _,
    deterministic::{self, Runner},
};
use reth_ethereum::storage::BlockNumReader;

use crate::{ExecutionRuntime, Setup, setup_validators};

#[test_traced]
fn validator_can_join_later() {
    let _ = tempo_eyre::install();

    Runner::from(deterministic::Config::default().with_seed(0)).start(|context| async move {
        let num_nodes = 5;

        let setup = Setup {
            how_many: num_nodes,
            seed: 0,
            // linkage: Link {
            //     latency: Duration::from_millis(10),
            //     jitter: Duration::from_millis(1),
            //     success_rate: 1.0,
            // },
            start_port: 1044,
            epoch_length: 100,
        };

        let execution_runtime = ExecutionRuntime::new();
        let mut nodes = setup_validators(context.clone(), &execution_runtime, setup).await;

        // Start all nodes except the last one
        let mut last = nodes.pop().unwrap();
        for node in &mut nodes {
            node.start().await;
        }

        // Wait for chain to advance a bit.
        while nodes[0].node.node.provider.last_block_number().unwrap() < 5 {
            context.sleep(Duration::from_secs(1)).await;
        }

        assert_eq!(last.node.node.provider.last_block_number().unwrap(), 0);

        // Start the last node.
        last.start().await;

        // Assert that last node is able to catch up and progress.
        while last.node.node.provider.last_block_number().unwrap() < 10 {
            context.sleep(Duration::from_secs(1)).await;
        }
    });
}
