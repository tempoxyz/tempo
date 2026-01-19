use std::{collections::HashSet, time::Duration};

use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _,
    deterministic::{Config, Runner},
};
use futures::future::join_all;

use crate::{CONSENSUS_NODE_PREFIX, Setup, setup_validators};

#[test_traced]
fn no_duplicate_metrics() {
    let _ = tempo_eyre::install();

    let setup = Setup::new().how_many_signers(1).epoch_length(10);

    let cfg = Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        // Setup and run all validators.
        let (mut nodes, _execution_runtime) = setup_validators(&mut context, setup).await;

        join_all(nodes.iter_mut().map(|node| node.start(&context))).await;

        'wait_for_epoch: loop {
            let metrics = context.encode();

            for line in metrics.lines() {
                if !line.starts_with(CONSENSUS_NODE_PREFIX) {
                    continue;
                }

                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();
                if metric.ends_with("_epoch_manager_latest_epoch")
                    && value.parse::<u64>().unwrap() >= 2
                {
                    break 'wait_for_epoch;
                }
            }
            context.sleep(Duration::from_secs(1)).await;
        }

        let mut dupes = HashSet::new();
        let all_metrics = context.encode();
        // NOTE: useful for debugging
        // std::fs::write("metrics-dump", &all_metrics).unwrap();
        for metric in all_metrics.lines().filter(|line| line.starts_with("#")) {
            assert!(dupes.insert(metric), "metric `{metric}` is duplicate");
        }
    })
}
