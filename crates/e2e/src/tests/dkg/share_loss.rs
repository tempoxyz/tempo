use std::time::Duration;

use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _,
    deterministic::{Config, Runner},
};
use futures::future::join_all;

use crate::{CONSENSUS_NODE_PREFIX, Setup, setup_validators};

#[test_traced("WARN")]
fn validator_lost_share_but_gets_share_in_next_epoch() {
    let _ = tempo_eyre::install();

    let seed = 0;

    let cfg = Config::default().with_seed(seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let epoch_length = 30;
        let setup = Setup::new().seed(seed).epoch_length(epoch_length);

        let (mut validators, _execution_runtime) =
            setup_validators(&mut context, setup.clone()).await;
        let uid = {
            let last_node = validators
                .last_mut()
                .expect("we just asked for a couple of validators");
            last_node
                .consensus_config_mut()
                .share
                .take()
                .expect("the node must have had a share");
            last_node.uid().to_string()
        };

        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        let mut node_forgot_share = false;

        'acquire_share: loop {
            context.sleep(Duration::from_secs(1)).await;

            let metrics = context.encode();

            'metrics: for line in metrics.lines() {
                if !line.starts_with(CONSENSUS_NODE_PREFIX) {
                    continue 'metrics;
                }

                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();

                if metrics.ends_with("_peers_blocked") {
                    let value = value.parse::<u64>().unwrap();
                    assert_eq!(value, 0);
                }

                if metric.ends_with("_epoch_manager_latest_epoch") {
                    let value = value.parse::<u64>().unwrap();
                    assert!(value < 2, "reached 2nd epoch without recovering new share");
                }

                // Ensures that node has no share.
                if !node_forgot_share
                    && metric.contains(&uid)
                    && metric.ends_with("_epoch_manager_how_often_verifier_total")
                {
                    let value = value.parse::<u64>().unwrap();
                    tracing::warn!(metric, value,);
                    node_forgot_share = value > 0;
                }

                // Ensure that the node gets a share by becoming a signer.
                if node_forgot_share
                    && metric.contains(&uid)
                    && metric.ends_with("_epoch_manager_how_often_signer_total")
                {
                    let value = value.parse::<u64>().unwrap();
                    tracing::warn!(metric, value,);
                    if value > 0 {
                        break 'acquire_share;
                    }
                }
            }
        }
    });
}
