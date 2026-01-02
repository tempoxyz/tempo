//! Tests for syncing nodes from scratch.
//!
//! These tests are similar to the tests in [`crate::tests::restart`], but
//! assume that the node has never been run but been given a synced execution
//! layer database./// Runs a validator restart test with the given configuration

use std::time::Duration;

use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _,
    deterministic::{self, Context, Runner},
};
use futures::future::join_all;
use tracing::info;

use crate::{CONSENSUS_NODE_PREFIX, Setup, setup_validators};

#[test_traced]
fn joins_from_snapshot() {
    let _ = tempo_eyre::install();

    let setup = Setup::new().how_many_signers(4).epoch_length(20);
    let cfg = deterministic::Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|context| async move {
        let (mut validators, _execution_runtime) =
            setup_validators(context.clone(), setup.clone()).await;

        join_all(validators.iter_mut().map(|v| v.start())).await;

        wait_for_epoch(&context, 4, 2).await;

        let mut stopped = validators.pop().unwrap();
        stopped.stop().await;

        info!("stopping validator and invalidating its consensus storage to force a start from the execution layer");

        // Change the validator's storage prefix from under it. This simulates
        // starting a new validator from a snapshot:
        // TOOD: spin up a new validator and actually copy over the execution
        // layer state.
        stopped.consensus_config.partition_prefix.push_str("_moved");

        stopped.start().await;

        wait_for_epoch(&context, 4, 4).await;
    });
}

/// Wait for a specific number of validators to reach a target height
async fn wait_for_epoch(context: &Context, expected_validators: u32, target_epoch: u64) {
    loop {
        let metrics = context.encode();
        let mut validators_at_epoch = 0;

        for line in metrics.lines() {
            if !line.starts_with(CONSENSUS_NODE_PREFIX) {
                continue;
            }

            let mut parts = line.split_whitespace();
            let metric = parts.next().unwrap();
            let value = parts.next().unwrap();

            // Check if this is a height metric
            if metric.ends_with("_epoch_manager_latest_epoch") {
                let height = value.parse::<u64>().unwrap();
                if height >= target_epoch {
                    validators_at_epoch += 1;
                }
            }
        }
        if validators_at_epoch == expected_validators {
            break;
        }
        context.sleep(Duration::from_secs(1)).await;
    }
}
