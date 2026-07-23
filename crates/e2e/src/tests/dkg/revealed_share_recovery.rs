//! Tests recovery of a publicly revealed DKG share.

use alloy::transports::http::reqwest::Url;
use commonware_macros::test_traced;
use commonware_runtime::{
    Runner as _,
    deterministic::{Config, Runner},
};
use futures::future::join_all;

use super::common::{target_epoch, wait_for_outcome};
use crate::{
    Setup, connect_execution_peers, connect_execution_to_peers,
    consensus_snapshot::write_consensus_snapshot, metrics::wait_for_metrics, setup_validators,
};

/// A validator with no private dealings can reconstruct its next share while replaying the
/// ceremony's revealed dealer logs.
#[test_traced]
fn validator_recovers_revealed_share_while_replaying_ceremony() {
    let _ = tempo_eyre::install();

    let epoch_length = 20;
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

    let epoch_length = 20;
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

/// A carried-forward output belongs to an older successful ceremony and is not recovered from the
/// immediately preceding failed ceremony.
#[test_traced]
fn validator_skips_recovery_after_failed_ceremony() {
    let _ = tempo_eyre::install();

    let epoch_length = 20;
    let setup = Setup::new()
        .how_many_signers(4)
        .how_many_verifiers(1)
        .epoch_length(epoch_length);

    let cfg = Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let (mut nodes, execution_runtime) = setup_validators(&mut context, setup).await;
        let verifier_index = nodes
            .iter()
            .position(|node| node.is_verifier())
            .expect("setup includes a verifier");

        let mut offline_player = nodes.remove(verifier_index);
        let signer_index = nodes
            .iter()
            .position(|node| node.is_signer())
            .expect("setup includes signers");

        let mut recovering = nodes.remove(signer_index);
        recovering
            .consensus_config_mut()
            .share
            .take()
            .expect("validator starts with a genesis share");

        join_all(nodes.iter_mut().map(|node| node.start(&context))).await;
        connect_execution_peers(&nodes).await;

        // Add another offline player during epoch 0. Together with the recovering validator this
        // exceeds the reveal limit in epoch 1, causing that ceremony to fail while the three
        // online members of the current four-validator committee keep consensus live.
        let http_url = nodes[0]
            .execution()
            .rpc_server_handle()
            .http_url()
            .expect("execution RPC is enabled")
            .parse::<Url>()
            .expect("execution RPC URL is valid");

        let receipt = execution_runtime
            .add_validator_v2(http_url, &offline_player)
            .await
            .expect("validator is added");
        assert_eq!(
            target_epoch(
                epoch_length,
                receipt.block_number.expect("receipt has a block number")
            )
            .get(),
            1,
            "offline player must join the epoch 1 ceremony"
        );

        let epoch_one = wait_for_outcome(&context, &nodes, 0, epoch_length).await;
        assert!(
            epoch_one
                .output
                .revealed()
                .position(&recovering.public_key())
                .is_some(),
            "offline validator's share must be revealed by the successful epoch 0 ceremony"
        );

        let epoch_two = wait_for_outcome(&context, &nodes, 1, epoch_length).await;
        assert_eq!(
            epoch_two.output, epoch_one.output,
            "failed epoch 1 ceremony must carry its input output forward"
        );

        // Sync the added verifier after it has served its purpose as an offline player. Using it as
        // the snapshot donor keeps all three original signers online to maintain quorum in epoch 2.
        offline_player.start(&context).await;
        connect_execution_to_peers(&offline_player, &nodes).await;
        wait_for_metrics(&context, |metrics| {
            metrics
                .for_scope(&offline_player)
                .latest_consensus_epoch()
                .is_some_and(|epoch| epoch >= 2)
        })
        .await;

        let execution_provider = offline_player.execution_provider();
        offline_player.stop().await;
        write_consensus_snapshot(
            &context,
            &offline_player,
            execution_provider,
            &recovering.consensus_config.partition_prefix,
        )
        .await;

        // Start the revealed validator at epoch 2 with synced execution and consensus state but no
        // DKG state. Recovery must recognize that epoch 1 did not produce the current output,
        // continue as an observer, and obtain a new share from the epoch 2 ceremony.
        recovering.consensus_config.strict_startup = true;
        offline_player.adopt_identity_from(recovering);
        offline_player.start(&context).await;
        connect_execution_to_peers(&offline_player, &nodes).await;

        wait_for_metrics(&context, |metrics| {
            let recovering_metrics = metrics.for_scope(&offline_player);
            let Some(epoch) = recovering_metrics.latest_consensus_epoch() else {
                return false;
            };
            assert!(
                epoch <= 3,
                "recovering validator advanced past epoch 3 before becoming a signer"
            );

            epoch == 3
                && recovering_metrics.value::<u64>("_epoch_manager_how_often_verifier_total")
                    == Some(1)
                && recovering_metrics.value::<u64>("_epoch_manager_how_often_signer_total")
                    == Some(1)
        })
        .await;
    });
}
