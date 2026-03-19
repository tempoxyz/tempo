use std::time::Duration;

use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _,
    deterministic::{Config, Runner},
};
use futures::future::join_all;

use crate::{CONSENSUS_NODE_PREFIX, Setup, setup_validators};

fn metric_value(metrics: &str, uid: &str, metric_suffix: &str) -> Option<u64> {
    metrics.lines().find_map(|line| {
        if !line.starts_with(CONSENSUS_NODE_PREFIX) {
            return None;
        }
        let mut parts = line.split_whitespace();
        let metric = parts.next()?;
        let value = parts.next()?;
        if metric.contains(uid) && metric.ends_with(metric_suffix) {
            value.parse::<u64>().ok()
        } else {
            None
        }
    })
}

#[test_traced]
fn validator_lost_share_but_gets_share_in_next_epoch() {
    let _ = tempo_eyre::install();

    let seed = 0;

    let cfg = Config::default().with_seed(seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let epoch_length = 20;
        let setup = Setup::new()
            .seed(seed)
            .epoch_length(epoch_length)
            .t2_time(0)
            .connect_execution_layer_nodes(true);

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

            if let Some(v) = metric_value(&metrics, &uid, "peers_blocked") {
                assert_eq!(v, 0);
            }

            if let Some(epoch) = metric_value(&metrics, &uid, "_epoch_manager_latest_epoch") {
                assert!(epoch < 2, "reached 2nd epoch without recovering new share");
            }

            // Ensures that node has no share.
            if !node_forgot_share
                && let Some(v) =
                    metric_value(&metrics, &uid, "_epoch_manager_how_often_verifier_total")
            {
                node_forgot_share = v > 0;
            }

            // Ensure that the node gets a share by becoming a signer.
            if node_forgot_share
                && let Some(v) =
                    metric_value(&metrics, &uid, "_epoch_manager_how_often_signer_total")
                && v > 0
            {
                break 'acquire_share;
            }
        }
    });
}

#[test_traced]
fn validator_loses_consensus_state_becomes_observer() {
    let _ = tempo_eyre::install();

    let seed = 0;

    let cfg = Config::default().with_seed(seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let epoch_length = 20;
        let setup = Setup::new()
            .seed(seed)
            .t2_time(0)
            .epoch_length(epoch_length);

        let (mut validators, _execution_runtime) =
            setup_validators(&mut context, setup.clone()).await;

        let target_idx = validators.len() - 1;
        let uid = validators[target_idx].uid().to_string();

        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        'setup: loop {
            context.sleep(Duration::from_secs(1)).await;
            let metrics = context.encode();

            // Dealings in the first epoch.
            if let Some(epoch) = metric_value(&metrics, &uid, "_epoch_manager_latest_epoch") {
                assert_eq!(epoch, 0);

                if let Some(v) = metric_value(&metrics, &uid, "_dkg_manager_ceremony_acks_sent")
                    && v > 0
                {
                    break 'setup;
                }
            }
        }

        validators[target_idx].stop().await;

        let old_prefix = &validators[target_idx].consensus_config().partition_prefix;
        let new_prefix = format!("{old_prefix}_wiped");
        let cfg = validators[target_idx].consensus_config_mut();

        // Also remove the share from config since post-setup we may still be in Epoch 0
        cfg.partition_prefix = new_prefix;
        cfg.share.take();

        validators[target_idx].start(&context).await;

        let uid = validators[target_idx].metric_prefix();

        'recover: loop {
            context.sleep(Duration::from_secs(1)).await;
            let metrics = context.encode();

            if let Some(epoch) = metric_value(&metrics, &uid, "_epoch_manager_latest_epoch") {
                assert!(epoch < 3);

                // Only receive shares in Epoch 1
                if epoch == 1
                    && let Some(v) =
                        metric_value(&metrics, &uid, "_dkg_manager_how_often_dealer_total")
                {
                    assert_eq!(v, 0);
                }

                // Participate as a Dealer in Epoch 2
                if let Some(v) = metric_value(&metrics, &uid, "_dkg_manager_how_often_dealer_total")
                    && v > 0
                {
                    assert_eq!(v, 1);
                    assert_eq!(epoch, 2);
                    break 'recover;
                }
            }
        }
    });
}
