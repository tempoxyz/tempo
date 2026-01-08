use std::time::Duration;

use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _,
    deterministic::{Config, Runner},
};
use futures::future::join_all;

use crate::{CONSENSUS_NODE_PREFIX, Setup, setup_validators};

#[test_traced("WARN")]
fn validator_lost_key_but_gets_key_in_next_epoch() {
    let _ = tempo_eyre::install();

    let seed = 0;

    let cfg = Config::default().with_seed(seed);
    let executor = Runner::from(cfg);

    executor.start(|context| async move {
        let epoch_length = 30;
        let setup = Setup::new().seed(seed).epoch_length(epoch_length);

        let (mut validators, _execution_runtime) =
            setup_validators(context.clone(), setup.clone()).await;
        let last_node = {
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

        join_all(validators.iter_mut().map(|v| v.start())).await;

        let mut epoch_reached = false;
        let mut height_reached = false;
        let mut dkg_successful = false;

        let mut node_forgot_share = false;
        let mut node_is_not_signer = true;
        let mut node_got_new_share = false;

        let mut success = false;
        while !success {
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
                    if value > 1 {
                        assert!(
                            node_forgot_share && node_got_new_share,
                            "reached 2nd epoch without recovering new share",
                        );
                    }
                }

                // Ensures that node has no share.
                if !node_forgot_share
                    && metric.ends_with(&format!(
                        "{last_node}_epoch_manager_how_often_verifier_total"
                    ))
                {
                    let value = value.parse::<u64>().unwrap();
                    tracing::warn!(metric, value,);
                    node_forgot_share = value > 0;
                }

                // Double check that the node is indeed not a signer.
                if !node_is_not_signer
                    && metric
                        .ends_with(&format!("{last_node}_epoch_manager_how_often_signer_total"))
                {
                    let value = value.parse::<u64>().unwrap();
                    tracing::warn!(metric, value,);
                    node_is_not_signer = value == 0;
                }

                // Ensure that the node gets a share by becoming a signer.
                if node_forgot_share
                    && node_is_not_signer
                    && !node_got_new_share
                    && metric
                        .ends_with(&format!("{last_node}_epoch_manager_how_often_signer_total"))
                {
                    let value = value.parse::<u64>().unwrap();
                    tracing::warn!(metric, value,);
                    node_got_new_share = value > 0;
                }

                if metric.ends_with("_dkg_manager_ceremony_failures_total") {
                    let value = value.parse::<u64>().unwrap();
                    assert!(value < 1);
                }

                if metric.ends_with("_epoch_manager_latest_epoch") {
                    let value = value.parse::<u64>().unwrap();
                    epoch_reached |= value >= 1;
                }
                if metric.ends_with("_marshal_processed_height") {
                    let value = value.parse::<u64>().unwrap();
                    height_reached |= value >= epoch_length;
                }
                if metric.ends_with("_dkg_manager_ceremony_successes_total") {
                    let value = value.parse::<u64>().unwrap();
                    dkg_successful |= value >= 1;
                }
            }

            success = epoch_reached
                && height_reached
                && dkg_successful
                && node_forgot_share
                && node_got_new_share;
        }
    });
}
