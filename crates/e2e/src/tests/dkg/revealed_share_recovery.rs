//! Tests recovery of a publicly revealed DKG share.

use commonware_macros::test_traced;
use commonware_runtime::{
    Runner as _,
    deterministic::{Config, Runner},
};
use futures::future::join_all;

use crate::{
    Setup, connect_execution_peers, connect_execution_to_peers,
    consensus_snapshot::write_consensus_snapshot, metrics::wait_for_metrics, setup_validators,
};

/// A validator with no private dealings can reconstruct its next share while replaying the
/// ceremony's revealed dealer logs.
#[test_traced]
fn validator_recovers_revealed_share_while_replaying_ceremony() {
    let _ = tempo_eyre::install();

    let epoch_length = 30;
    let setup = Setup::new().how_many_signers(4).epoch_length(epoch_length);
    let cfg = Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
        let mut recovering = validators.pop().expect("at least one validator");

        // Keep this validator offline for epoch 0 so every selected dealer reveals its dealing.
        // Remove its genesis share so the only way it can sign in epoch 1 is recovery from chain.
        recovering
            .consensus_config_mut()
            .share
            .take()
            .expect("validator starts with a genesis share");

        join_all(validators.iter_mut().map(|node| node.start(&context))).await;
        connect_execution_peers(&validators).await;

        wait_for_metrics(&context, |m| m.consensus_at_epoch(1) == validators.len()).await;

        recovering.start(&context).await;
        connect_execution_to_peers(&recovering, &validators).await;

        wait_for_metrics(&context, |metrics| {
            assert!(
                metrics.consensus_before_epoch(2),
                "validator did not reconstruct its share while replaying epoch 0"
            );

            let recovering_metrics = metrics.for_scope(&recovering);
            recovering_metrics.latest_consensus_epoch() == Some(1)
                && recovering_metrics
                    .value::<u64>("_epoch_manager_how_often_signer_total")
                    .is_some_and(|started_as_signer| started_as_signer > 0)
        })
        .await;
    });
}

/// A validator with synced execution state and no consensus state can reconstruct its current
/// share by scanning the previous epoch's revealed dealer logs.
#[test_traced]
fn validator_recovers_revealed_share_without_consensus_state() {
    let _ = tempo_eyre::install();

    let epoch_length = 30;
    let setup = Setup::new().how_many_signers(4).epoch_length(epoch_length);
    let cfg = Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
        let mut recovering = validators.pop().expect("at least one validator");

        recovering
            .consensus_config_mut()
            .share
            .take()
            .expect("validator starts with a genesis share");

        join_all(validators.iter_mut().map(|node| node.start(&context))).await;
        connect_execution_peers(&validators).await;

        wait_for_metrics(&context, |m| m.consensus_at_epoch(1) == validators.len()).await;

        // Give the offline validator an already-synced execution database and consensus snapshot,
        // but no DKG state. Its first DKG-manager loop therefore starts at the current boundary and
        // must scan the previous epoch rather than replaying it.
        let mut donor = validators.pop().expect("at least one running validator");
        let execution_provider = donor.execution_provider();
        donor.stop().await;
        write_consensus_snapshot(
            &context,
            &donor,
            execution_provider,
            &recovering.consensus_config.partition_prefix,
        )
        .await;

        recovering.consensus_config.strict_startup = true;
        donor.adopt_identity_from(recovering);
        donor.start(&context).await;
        connect_execution_to_peers(&donor, &validators).await;

        let recovering = donor;
        wait_for_metrics(&context, |metrics| {
            assert!(
                metrics.consensus_before_epoch(3),
                "network advanced without the validator recovering its current share"
            );

            metrics
                .for_scope(&recovering)
                .value::<u64>("_epoch_manager_how_often_signer_total")
                .is_some_and(|started_as_signer| started_as_signer > 0)
        })
        .await;
    });
}
