//! Tests that consensus context appears only after the T4 fork activates.

use std::time::Duration;

use alloy::consensus::BlockHeader;
use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _,
    deterministic::{self, Runner},
};
use futures::future::join_all;
use reth_ethereum::provider::BlockReader as _;

use crate::{CONSENSUS_NODE_PREFIX, Setup, setup_validators};

#[test_traced]
fn consensus_context_appears_after_t4_activation() {
    let _ = tempo_eyre::install();

    // T3 active at genesis, T4 activates at timestamp 5.
    let t4_time = 5;

    let setup = Setup::new()
        .how_many_signers(4)
        .epoch_length(100)
        .t4_time(t4_time)
        .seed(0);

    let cfg = deterministic::Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let (mut nodes, _execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(nodes.iter_mut().map(|node| node.start(&context))).await;

        let uid = nodes[0].uid();
        let provider = nodes[0].execution_provider();

        'setup: loop {
            for line in context.encode().lines() {
                if !line.starts_with(CONSENSUS_NODE_PREFIX) {
                    continue;
                }

                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();
                if metric.contains(uid) && metric.ends_with("_marshal_processed_height") {
                    let height = value.parse::<u64>().unwrap();
                    if height >= 10 {
                        break 'setup;
                    }
                }
            }

            context.sleep(Duration::from_secs(1)).await;
        }

        // Ensure we've transitioned at the latest height
        let latest = provider.block_by_number(10).ok().flatten().unwrap();
        assert!(latest.timestamp() > t4_time);

        for height in 1..=10 {
            let block = provider.block_by_number(height).ok().flatten().unwrap();
            if block.header.timestamp() < t4_time {
                assert!(block.header.consensus_context.is_none());
            } else {
                assert!(block.header.consensus_context.is_some());
            }
        }
    });
}
