use std::time::Duration;

use alloy::transports::http::reqwest::Url;
use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _,
    deterministic::{Config, Runner},
};
use futures::future::join_all;

use crate::{
    CONSENSUS_NODE_PREFIX, Setup, setup_validators,
    tests::{
        dkg::common::target_epoch,
        v2_at_genesis::{assert_no_dkg_failure, assert_no_v1},
    },
};

#[test_traced]
fn validator_is_added_to_a_set_of_one() {
    AssertValidatorIsAdded {
        how_many_initial: 1,
        epoch_length: 10,
    }
    .run();
}

#[test_traced]
fn validator_is_added_to_a_set_of_three() {
    AssertValidatorIsAdded {
        how_many_initial: 3,
        epoch_length: 30,
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
    fn run(self) {
        let Self {
            how_many_initial,
            epoch_length,
        } = self;
        let _ = tempo_eyre::install();
        let setup = Setup::new()
            .how_many_signers(how_many_initial)
            .how_many_verifiers(1)
            .t2_time(0)
            .epoch_length(epoch_length);

        let cfg = Config::default().with_seed(setup.seed);
        let executor = Runner::from(cfg);

        executor.start(|mut context| async move {
            let (mut validators, execution_runtime) = setup_validators(&mut context, setup).await;

            let added_uid = validators
                .iter()
                .find(|v| v.is_verifier())
                .unwrap()
                .uid
                .clone();
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

            let receipt = execution_runtime
                .add_validator_v2(
                    http_url.clone(),
                    validators.iter().find(|v| v.is_verifier()).unwrap(),
                )
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

                let mut entered_player_epoch = false;
                let mut entered_dealer_epoch = false;
                for line in context.encode().lines() {
                    if !line.starts_with(CONSENSUS_NODE_PREFIX) {
                        continue;
                    }

                    let mut parts = line.split_whitespace();
                    let key = parts.next().unwrap();
                    let value = parts.next().unwrap();

                    assert_no_v1(key, value);
                    assert_no_dkg_failure(key, value);

                    if key.ends_with("peer_manager_peers") {
                        assert_eq!(
                            how_many_initial + 1,
                            value.parse::<u32>().unwrap(),
                            "peers are registered on the next finalized block; this should have happened almost immediately",
                        );
                    }

                    if key.ends_with("_epoch_manager_latest_epoch") {
                        let epoch = value.parse::<u64>().unwrap();

                        if key.contains(&added_uid) {
                            entered_player_epoch |= epoch >= player_epoch.get();
                            entered_dealer_epoch |= epoch >= dealer_epoch.get();
                        }

                        assert!(
                            epoch < dealer_epoch.next().get(),
                            "network reached epoch `{}` without added validator getting a share",
                            dealer_epoch.next(),
                        );
                    }

                    if entered_player_epoch && !entered_dealer_epoch {
                        if key.ends_with("_dkg_manager_ceremony_players") {
                            assert_eq!(how_many_initial + 1, value.parse::<u32>().unwrap(),)
                        }
                        if key.ends_with("_dkg_manager_ceremony_dealers") {
                            assert_eq!(how_many_initial, value.parse::<u32>().unwrap(),)
                        }
                    }

                    if entered_dealer_epoch {
                        if key.ends_with("_dkg_manager_ceremony_dealers") {
                            assert_eq!(how_many_initial + 1, value.parse::<u32>().unwrap(),)
                        }

                        if key.ends_with("_epoch_manager_how_often_signer_total") {
                            assert!(value.parse::<u64>().unwrap() > 0,);
                            break 'becomes_signer;
                        }
                    }
                }
            }
        })
    }
}

struct AssertValidatorIsRemoved {
    how_many_initial: u32,
    epoch_length: u64,
}

impl AssertValidatorIsRemoved {
    fn run(self) {
        let Self {
            how_many_initial,
            epoch_length,
        } = self;
        let _ = tempo_eyre::install();
        let setup = Setup::new()
            .how_many_signers(how_many_initial)
            .t2_time(0)
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

            tracing::debug!(
                block.number = receipt.block_number,
                "deactivateValidator call returned receipt"
            );

            let removal_epoch = target_epoch(epoch_length, receipt.block_number.unwrap());
            let removed_epoch = removal_epoch.next();

            'is_removed: loop {
                context.sleep(Duration::from_secs(1)).await;

                let mut entered_removal_epoch = false;
                let mut entered_removed_epoch = false;
                for line in context.encode().lines() {
                    if !line.starts_with(CONSENSUS_NODE_PREFIX) {
                        continue;
                    }

                    let mut parts = line.split_whitespace();
                    let key = parts.next().unwrap();
                    let value = parts.next().unwrap();

                    assert_no_v1(key, value);
                    assert_no_dkg_failure(key, value);

                    if key.ends_with("ceremony_failures_total") {
                        assert_eq!(0, value.parse::<u64>().unwrap(),);
                    }

                    if key.ends_with("_epoch_manager_latest_epoch") {
                        let epoch = value.parse::<u64>().unwrap();

                        assert!(
                            epoch < removed_epoch.next().get(),
                            "validator removal should have happened by epoch \
                            `{removed_epoch}`, but network is already in epoch \
                            {}",
                            removed_epoch.next(),
                        );

                        if key.contains(&removed_validator.uid) {
                            entered_removal_epoch |= epoch >= removal_epoch.get();
                        }

                        entered_removed_epoch |= epoch >= removed_epoch.get();
                    }

                    if entered_removal_epoch && !entered_removed_epoch {
                        if key.ends_with("_dkg_manager_ceremony_players") {
                            assert_eq!(how_many_initial - 1, value.parse::<u32>().unwrap(),)
                        }
                        if key.ends_with("_dkg_manager_ceremony_dealers") {
                            assert_eq!(how_many_initial, value.parse::<u32>().unwrap(),)
                        }
                    }

                    if entered_removed_epoch && !key.contains(&removed_validator.uid) {
                        if key.ends_with("peer_manager_peers") {
                            assert_eq!(
                                how_many_initial - 1,
                                value.parse::<u32>().unwrap(),
                                "once the peer is deactivated and no longer a \
                                dealer, it should be removed from the list of \
                                peers immediately"
                            );
                        }

                        if key.ends_with("_dkg_manager_ceremony_dealers") {
                            assert_eq!(how_many_initial - 1, value.parse::<u32>().unwrap(),);
                            break 'is_removed;
                        }
                    }
                }
            }
        })
    }
}
