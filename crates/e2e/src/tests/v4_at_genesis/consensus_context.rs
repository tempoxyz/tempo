//! Tests for consensus context in block headers when T4 is active at genesis.

use std::time::Duration;

use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _,
    deterministic::{self, Runner},
};
use futures::future::join_all;
use reth_ethereum::provider::BlockReader as _;

use crate::{CONSENSUS_NODE_PREFIX, Setup, setup_validators};

#[test_traced]
fn blocks_have_consensus_context() {
    let _ = tempo_eyre::install();

    let setup = Setup::new()
        .how_many_signers(4)
        .epoch_length(100)
        .t4_time(0)
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
                    if height >= 5 {
                        break 'setup;
                    }
                }
            }

            context.sleep(Duration::from_secs(1)).await;
        }

        // Genesis block should not have a consensus context.
        let genesis = provider.block_by_number(0).ok().flatten().unwrap();
        assert_eq!(genesis.header.consensus_context, None);

        for height in 1..=5 {
            let block = provider.block_by_number(height).ok().flatten().unwrap();
            let ctx = block.header.consensus_context.unwrap();
            assert!(ctx.epoch > 0 || ctx.view > 0);

            if height > 1 {
                let parent = provider.block_by_number(height - 1).ok().flatten().unwrap();
                let parent_ctx = parent.header.consensus_context.unwrap();

                assert_eq!(ctx.parent_view, parent_ctx.view);
            }
        }
    });
}
