use std::time::Duration;

use alloy::transports::http::reqwest::Url;
use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _,
    deterministic::{Config, Runner},
};
use futures::future::join_all;

use crate::{CONSENSUS_NODE_PREFIX, Setup, setup_validators};

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
            .epoch_length(epoch_length);

        let cfg = Config::default().with_seed(setup.seed);
        let executor = Runner::from(cfg);

        executor.start(|mut context| async move {
            let (mut validators, execution_runtime) = setup_validators(&mut context, setup).await;

            let mut new_validator = {
                let idx = validators
                    .iter()
                    .position(|node| node.consensus_config().share.is_none())
                    .expect("at least one node must be a verifier, i.e. not have a share");
                validators.remove(idx)
            };

            assert!(
                validators
                    .iter()
                    .all(|node| node.consensus_config().share.is_some()),
                "must have removed the one non-signer node; must be left with only signers",
            );

            join_all(validators.iter_mut().map(|v| v.start(&context))).await;

            // We will send an arbitrary node of the initial validator set the smart
            // contract call.
            let http_url = validators[0]
                .execution()
                .rpc_server_handle()
                .http_url()
                .unwrap()
                .parse::<Url>()
                .unwrap();

            // Now add and start the new validator.
            let receipt = execution_runtime
                .add_validator(
                    http_url.clone(),
                    new_validator.chain_address,
                    new_validator.public_key().clone(),
                    new_validator.network_address,
                )
                .await
                .unwrap();

            tracing::debug!(
                block.number = receipt.block_number,
                "addValidator call returned receipt"
            );

            let _new_validator = new_validator.start(&context).await;
            tracing::info!("new validator was started");

            // First, all initial validator nodes must observe a ceremony with
            // dealers = how_many_initial, players = how_many_initial + 1.
            loop {
                context.sleep(Duration::from_secs(1)).await;

                let mut dealers_is_initial = 0;
                let mut players_is_initial_plus_one = 0;

                let metrics = context.encode();
                for line in metrics.lines() {
                    if !line.starts_with(CONSENSUS_NODE_PREFIX) {
                        continue;
                    }

                    // Only consider metrics from the initial set of validators.
                    if !validators.iter().any(|val| line.contains(val.uid())) {
                        continue;
                    }

                    let mut parts = line.split_whitespace();
                    let metric = parts.next().unwrap();
                    let value = parts.next().unwrap();

                    if metric.ends_with("_dkg_manager_ceremony_dealers") {
                        let value = value.parse::<u64>().unwrap();
                        if value as u32 > how_many_initial {
                            panic!(
                                "observed dealers = {value} before observing \
                            dealers = {how_many_initial}, \
                            players = {how_many_initial} +1",
                            );
                        }
                        dealers_is_initial += (value as u32 == how_many_initial) as u32;
                    }

                    if metric.ends_with("_dkg_manager_ceremony_players") {
                        let value = value.parse::<u64>().unwrap();
                        players_is_initial_plus_one +=
                            (value as u32 == how_many_initial + 1) as u32;
                    }
                }
                if dealers_is_initial == how_many_initial
                    && players_is_initial_plus_one == how_many_initial
                {
                    break;
                }
            }

            // Then, all how_many_initial + 1 nodes must observe an epoch with the
            // same number of participants (= how_many_initial + 1).
            loop {
                context.sleep(Duration::from_secs(1)).await;

                let metrics = context.encode();
                let mut participants_is_initial_plus_one = 0;

                for line in metrics.lines() {
                    if !line.starts_with(CONSENSUS_NODE_PREFIX) {
                        continue;
                    }
                    let mut parts = line.split_whitespace();
                    let metric = parts.next().unwrap();
                    let value = parts.next().unwrap();

                    if metric.ends_with("_epoch_manager_latest_participants") {
                        let value = value.parse::<u64>().unwrap();
                        participants_is_initial_plus_one +=
                            (value as u32 == how_many_initial + 1) as u32;
                    }
                }
                if participants_is_initial_plus_one == how_many_initial + 1 {
                    break;
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
            .epoch_length(epoch_length);

        let cfg = Config::default().with_seed(setup.seed);
        let executor = Runner::from(cfg);

        executor.start(|mut context| async move {
            let (mut validators, execution_runtime) = setup_validators(&mut context, setup).await;

            join_all(validators.iter_mut().map(|v| v.start(&context))).await;

            // We will send an arbitrary node of the initial validator set the smart
            // contract call.
            let http_url = validators[0]
                .execution()
                .rpc_server_handle()
                .http_url()
                .unwrap()
                .parse::<Url>()
                .unwrap();

            // The addValidator calls during genesis add validators 0..validators.len().
            // So the last validator has index `validators.len() - 1`.
            let last_validator_index = (validators.len() - 1) as u64;
            let receipt = execution_runtime
                .change_validator_status(http_url, last_validator_index, false)
                .await
                .unwrap();

            tracing::debug!(
                block.number = receipt.block_number,
                "changeValidatorStatus call returned receipt"
            );

            tracing::info!("validator was removed");

            // First, all initial validator nodes must observe a ceremony with
            // dealers = how_many_initial, players = how_many_initial - 1,
            // including the validator to be removed because it is part of the
            // original dealer set.
            loop {
                context.sleep(Duration::from_secs(1)).await;

                let mut dealers_is_initial = 0;
                let mut players_is_initial_minus_one = 0;

                let metrics = context.encode();
                for line in metrics.lines() {
                    if !line.starts_with(CONSENSUS_NODE_PREFIX) {
                        continue;
                    }

                    // Only consider metrics from the initial set of validators.
                    if !validators.iter().any(|val| line.contains(val.uid())) {
                        continue;
                    }

                    let mut parts = line.split_whitespace();
                    let metric = parts.next().unwrap();
                    let value = parts.next().unwrap();

                    if metric.ends_with("_dkg_manager_ceremony_dealers") {
                        let value = value.parse::<u64>().unwrap();
                        if (value as u32) < how_many_initial {
                            panic!(
                                "observed dealers = {value} before observing \
                            dealers = {how_many_initial}, \
                            players = {how_many_initial} - 1",
                            );
                        }
                        dealers_is_initial += (value as u32 == how_many_initial) as u32;
                    }

                    if metric.ends_with("_dkg_manager_ceremony_players") {
                        let value = value.parse::<u64>().unwrap();
                        players_is_initial_minus_one +=
                            (value as u32 == how_many_initial - 1) as u32;
                    }
                }
                if dealers_is_initial == how_many_initial
                    && players_is_initial_minus_one == how_many_initial
                {
                    break;
                }
            }

            // Then, all how_many_initial nodes must observe an epoch with the
            // same number of participants (= how_many_intial - 1). This even
            // includes the validator to be removed, since it will still transition.
            loop {
                context.sleep(Duration::from_secs(1)).await;

                let metrics = context.encode();
                let mut participants_is_initial_minus_one = 0;

                for line in metrics.lines() {
                    if !line.starts_with(CONSENSUS_NODE_PREFIX) {
                        continue;
                    }
                    let mut parts = line.split_whitespace();
                    let metric = parts.next().unwrap();
                    let value = parts.next().unwrap();

                    if metric.ends_with("_epoch_manager_latest_participants") {
                        let value = value.parse::<u64>().unwrap();
                        participants_is_initial_minus_one +=
                            (value as u32 == how_many_initial - 1) as u32;
                    }
                }
                if participants_is_initial_minus_one == how_many_initial {
                    break;
                }
            }
        })
    }
}
