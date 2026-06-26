use std::time::Duration;

use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Runner as _,
    deterministic::{Config, Runner},
};
use futures::future::join_all;

use crate::{Setup, connect_execution_peers, metrics::MetricsExt, setup_validators};

#[test_traced]
fn validator_lost_share_but_gets_share_in_next_epoch() {
    let _ = tempo_eyre::install();

    let seed = 0;

    let cfg = Config::default().with_seed(seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let epoch_length = 20;
        let setup = Setup::new().seed(seed).epoch_length(epoch_length);

        let (mut validators, _execution_runtime) =
            setup_validators(&mut context, setup.clone()).await;

        let lost_share_index = validators.len() - 1;
        {
            let last_node = &mut validators[lost_share_index];
            last_node
                .consensus_config_mut()
                .share
                .take()
                .expect("the node must have had a share");
        }

        join_all(validators.iter_mut().map(|v| v.start(&context))).await;
        connect_execution_peers(&validators).await;

        let mut node_forgot_share = false;

        'acquire_share: loop {
            context.sleep(Duration::from_secs(1)).await;
            let metrics = context
                .to_metrics()
                .for_scope(&validators[lost_share_index]);

            if let Some(v) = metrics.value::<u64>("peers_blocked") {
                assert_eq!(v, 0);
            }

            if let Some(epoch) = metrics.latest_consensus_epoch() {
                assert!(epoch < 2, "reached 2nd epoch without recovering new share");
            }

            // Ensures that node has no share.
            if !node_forgot_share
                && let Some(v) = metrics.value::<u64>("_epoch_manager_how_often_verifier_total")
            {
                node_forgot_share = v > 0;
            }

            // Ensure that the node gets a share by becoming a signer.
            if node_forgot_share
                && let Some(v) = metrics.value::<u64>("_epoch_manager_how_often_signer_total")
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
        let setup = Setup::new().seed(seed).epoch_length(epoch_length);

        let (mut validators, _execution_runtime) =
            setup_validators(&mut context, setup.clone()).await;

        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        let mut specimen = validators.pop().unwrap();

        'setup: loop {
            context.sleep(Duration::from_secs(1)).await;
            let metrics = context.to_metrics().for_scope(&specimen);

            // Dealings in the first epoch.
            if let Some(epoch) = metrics.latest_consensus_epoch() {
                assert_eq!(epoch, 0);

                if let Some(v) = metrics.value::<u64>("_dkg_manager_ceremony_acks_sent")
                    && v > 0
                {
                    break 'setup;
                }
            }
        }

        specimen.stop().await;

        // Rename the storage prefix to simulate loss of consensus storage.
        specimen.consensus_config.partition_prefix =
            format!("{}_wiped", specimen.consensus_config.partition_prefix);
        // Rename the UID to ensure that old metrics are ignored.
        specimen.uid = format!("{}_new", specimen.uid);
        // Remove the share from config since post-setup we may still be in Epoch 0
        specimen.consensus_config.share.take();

        specimen.start(&context).await;

        'recover: for iteration in 1.. {
            let metrics = context.to_metrics().for_scope(&specimen);

            if let Some(epoch) = metrics.latest_consensus_epoch() {
                assert!(epoch < 3, "node should have recovered its share by epoch 3");

                if epoch < 2
                    && let Some(v) = metrics.value::<u64>("_dkg_manager_how_often_dealer_total")
                {
                    assert_eq!(
                        v, 0,
                        "validator must not be a dealer before epoch 3; iteration {iteration}"
                    );
                }

                if epoch == 2
                    && let Some(v) = metrics.value::<u64>("_dkg_manager_how_often_dealer_total")
                {
                    assert_eq!(
                        v, 1,
                        "validator must be a dealer in epoch 2; iteration {iteration}"
                    );
                    assert_eq!(epoch, 2);
                    break 'recover;
                }
            }
            context.sleep(Duration::from_secs(1)).await;
        }
    });
}
