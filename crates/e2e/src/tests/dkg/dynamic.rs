use std::time::Duration;

use alloy::transports::http::reqwest::Url;
use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Runner as _,
    deterministic::{Config, Runner},
};
use futures::future::join_all;

use crate::{Setup, metrics::MetricsExt, setup_validators, tests::dkg::common::target_epoch};

#[test_traced]
fn validator_is_added_to_a_set_of_two() {
    AssertValidatorIsAdded {
        how_many_initial: 2,
        epoch_length: 20,
    }
    .run();
}

#[test_traced]
fn validator_is_added_to_a_set_of_four() {
    AssertValidatorIsAdded {
        how_many_initial: 4,
        epoch_length: 40,
    }
    .run();
}

#[test_traced]
fn validator_is_removed_from_set_of_two() {
    AssertValidatorIsRemoved {
        how_many_initial: 2,
        epoch_length: 20,
    }
    .run();
}

#[test_traced]
fn validator_is_removed_from_set_of_four() {
    AssertValidatorIsRemoved {
        how_many_initial: 4,
        epoch_length: 40,
    }
    .run();
}

struct AssertValidatorIsAdded {
    how_many_initial: u32,
    epoch_length: u64,
}

impl AssertValidatorIsAdded {
    #[track_caller]
    fn run(self) {
        let Self {
            how_many_initial,
            epoch_length,
        } = self;
        let _ = tempo_eyre::install();
        let setup = Setup::new()
            .how_many_signers(how_many_initial)
            .how_many_verifiers(1)
            .epoch_length(epoch_length);

        let cfg = Config::default().with_seed(setup.seed);
        let executor = Runner::from(cfg);

        executor.start(|mut context| async move {
            let (mut validators, execution_runtime) = setup_validators(&mut context, setup).await;

            let added_index = validators.iter().position(|v| v.is_verifier()).unwrap();
            let signer_index = validators.iter().position(|v| v.is_signer()).unwrap();
            join_all(validators.iter_mut().map(|v| v.start(&context))).await;

            // We will send an arbitrary node of the initial validator set the smart
            // contract call.
            let http_url = validators[signer_index]
                .execution()
                .rpc_server_handle()
                .http_url()
                .unwrap()
                .parse::<Url>()
                .unwrap();

            let receipt = execution_runtime
                .add_validator_v2(http_url.clone(), &validators[added_index])
                .await
                .unwrap();

            tracing::debug!(
                block.number = receipt.block_number,
                "addValidator call returned receipt"
            );

            let player_epoch = target_epoch(epoch_length, receipt.block_number.unwrap());
            let dealer_epoch = player_epoch.next();

            'becomes_signer: loop {
                context.sleep(Duration::from_secs(1)).await;

                let metrics = context.to_metrics();
                metrics.assert_no_dkg_failures();

                let added_metrics = metrics.for_scope(&validators[added_index]);
                let network_metrics = metrics.for_scope(&validators[signer_index]);

                let added_epoch = added_metrics.latest_consensus_epoch().unwrap();
                let added_signer = added_metrics
                    .value::<u64>("_epoch_manager_how_often_signer_total")
                    .unwrap();
                let dealers = added_metrics
                    .value::<u64>("_dkg_manager_ceremony_dealers")
                    .unwrap() as u32;
                let network_epoch = network_metrics.latest_consensus_epoch().unwrap();
                let players = added_metrics
                    .value::<u64>("_dkg_manager_ceremony_players")
                    .unwrap() as u32;

                if added_epoch >= player_epoch.get() && added_epoch < dealer_epoch.get() {
                    assert_eq!(how_many_initial + 1, players);
                    assert_eq!(how_many_initial, dealers);
                }

                if added_epoch >= dealer_epoch.get() {
                    assert_eq!(how_many_initial + 1, dealers);
                    assert!(added_signer > 0);
                    break 'becomes_signer;
                }

                assert!(
                    network_epoch <= dealer_epoch.get(),
                    "network reached epoch `{network_epoch}` without added validator getting a share",
                );
            }
        })
    }
}

struct AssertValidatorIsRemoved {
    how_many_initial: u32,
    epoch_length: u64,
}

impl AssertValidatorIsRemoved {
    #[track_caller]
    fn run(self) {
        let Self {
            how_many_initial,
            epoch_length,
        } = self;
        let _ = tempo_eyre::install();
        let setup = Setup::new()
            .how_many_signers(how_many_initial)
            .epoch_length(epoch_length);

        let cfg = Config::default().with_seed(setup.seed);
        let executor = Runner::from(cfg);

        executor.start(|mut context| async move {
            let (mut validators, execution_runtime) = setup_validators(&mut context, setup).await;

            join_all(validators.iter_mut().map(|v| v.start(&context))).await;

            // We will send an arbitrary node of the initial validator set the smart
            // contract call.
            let http_url = validators
                .iter()
                .find(|v| v.is_signer())
                .unwrap()
                .execution()
                .rpc_server_handle()
                .http_url()
                .unwrap()
                .parse::<Url>()
                .unwrap();

            let removed_validator = validators.pop().unwrap();

            let receipt = execution_runtime
                .deactivate_validator_v2(http_url, &removed_validator)
                .await
                .unwrap();

            let removal_epoch = target_epoch(epoch_length, receipt.block_number.unwrap());
            let removed_epoch = removal_epoch.next();

            tracing::debug!(
                block.number = receipt.block_number,
                %removal_epoch,
                %removed_epoch,
                "deactivateValidator call returned receipt; now monitoring \
                removal of validator"
            );

            'is_removed: loop {
                context.sleep(Duration::from_secs(1)).await;

                let metrics = context.to_metrics();
                metrics.assert_no_dkg_failures();

                let network_metrics = metrics.for_scope(&validators[0]);
                let dealers = network_metrics
                    .value::<u64>("_dkg_manager_ceremony_dealers")
                    .unwrap() as u32;
                let network_epoch = network_metrics.latest_consensus_epoch().unwrap();
                let players = network_metrics
                    .value::<u64>("_dkg_manager_ceremony_players")
                    .unwrap() as u32;
                if network_epoch < removed_epoch.get() && network_epoch >= removal_epoch.get() {
                    assert_eq!(how_many_initial - 1, players);
                    assert_eq!(how_many_initial, dealers);
                }

                if network_epoch >= removed_epoch.get() {
                    assert_eq!(
                        how_many_initial - 1,
                        dealers,
                        "there should be one less initial dealers than the \
                        initial number of dealers"
                    );
                    break 'is_removed;
                }

                assert!(
                    network_epoch <= removed_epoch.get(),
                    "network epoch `{network_epoch}` exceeded `{removed_epoch}` \
                    without validator being removed"
                );
            }
        })
    }
}
