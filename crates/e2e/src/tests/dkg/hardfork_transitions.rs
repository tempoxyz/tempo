//! Tests checking that the pre- to post-allegretto handover works.

use std::{net::SocketAddr, time::Duration};

use alloy::transports::http::reqwest::Url;
use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _,
    deterministic::{Config, Runner},
};
use futures::future::join_all;

use crate::{CONSENSUS_NODE_PREFIX, Setup, execution_runtime::validator, setup_validators};

#[test_traced]
fn single_validator_does_allegretto_transition_with_validator_in_contract() {
    assert_allegretto_transition(1, 20);
}

#[test_traced]
fn four_validators_do_allegretto_transition_with_validators_in_contract() {
    assert_allegretto_transition(4, 30);
}

#[test_traced]
fn single_validator_refuses_allegretto_transition_without_contract_validators() {
    assert_allegretto_transition_refused_without_contract_validators(1, 20);
}

#[test_traced]
fn four_validators_refuse_allegretto_transition_without_contract_validators() {
    assert_allegretto_transition_refused_without_contract_validators(4, 40);
}

#[test_traced]
fn single_validator_refuses_allegretto_transition_with_bad_socket_address_in_contract() {
    assert_allegretto_transition_refused_with_wrong_socket_addr(1, 20);
}

#[test_traced]
fn four_validators_refuse_allegretto_transition_with_bad_socket_address_in_contract() {
    assert_allegretto_transition_refused_with_wrong_socket_addr(4, 40);
}

fn assert_allegretto_transition(how_many: u32, epoch_length: u64) {
    let _ = tempo_eyre::install();

    let setup = Setup::new()
        .how_many_signers(how_many)
        .epoch_length(epoch_length)
        .allegretto_in_seconds(10)
        .no_validators_in_genesis();

    let cfg = Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|context| async move {
        let (mut validators, execution_runtime) = setup_validators(context.clone(), setup).await;
        join_all(validators.iter_mut().map(|v| v.start())).await;

        // We will send an arbitrary node of the initial validator set the smart
        // contract call.
        let http_url = validators[0]
            .execution()
            .rpc_server_handle()
            .http_url()
            .unwrap()
            .parse::<Url>()
            .unwrap();

        for (i, node) in validators.iter().enumerate() {
            let receipt = execution_runtime
                .add_validator(
                    http_url.clone(),
                    validator(i as u32),
                    node.public_key().clone(),
                    SocketAddr::from(([127, 0, 0, 1], (i + 1) as u16)),
                )
                .await
                .unwrap();

            tracing::debug!(
                block.number = receipt.block_number,
                "addValidator call returned receipt"
            );
        }

        loop {
            context.sleep(Duration::from_secs(1)).await;
            let metrics = context.encode();

            let mut transitioned = 0;

            for line in metrics.lines() {
                if !line.starts_with(CONSENSUS_NODE_PREFIX) {
                    continue;
                }
                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();

                if metric.ends_with("_dkg_manager_post_allegretto_ceremonies_total") {
                    let value = value.parse::<u64>().unwrap();
                    transitioned += (value > 0) as u32;
                }
            }

            if transitioned == how_many {
                break;
            }
        }
    })
}
fn assert_allegretto_transition_refused_with_wrong_socket_addr(how_many: u32, epoch_length: u64) {
    let _ = tempo_eyre::install();

    let setup = Setup::new()
        .how_many_signers(how_many)
        .epoch_length(epoch_length)
        .allegretto_in_seconds(10)
        .no_validators_in_genesis();

    let cfg = Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|context| async move {
        let (mut validators, execution_runtime) = setup_validators(context.clone(), setup).await;
        join_all(validators.iter_mut().map(|v| v.start())).await;

        // We will send an arbitrary node of the initial validator set the smart
        // contract call.
        let http_url = validators[0]
            .execution()
            .rpc_server_handle()
            .http_url()
            .unwrap()
            .parse::<Url>()
            .unwrap();

        for (i, node) in validators.iter().enumerate() {
            let receipt = execution_runtime
                .add_validator(
                    http_url.clone(),
                    validator(i as u32),
                    node.public_key().clone(),
                    // Shift ports by 1 to misalign the ports.
                    // TODO: put the addresses into the test validators to not
                    // rely on known implementation behavior.
                    SocketAddr::from(([127, 0, 0, 1], (i + 2) as u16)),
                )
                .await
                .unwrap();

            tracing::debug!(
                block.number = receipt.block_number,
                "addValidator call returned receipt"
            );
        }

        loop {
            context.sleep(Duration::from_secs(1)).await;
            let metrics = context.encode();

            let mut transition_refused = 0;
            let mut epoch_transitioned = 0;
            let mut dkg_successful = 0;

            // Two, because the ceremony started on setup also counts.
            let mut at_least_two_post_allegretto_ceremonies_started = 0;

            for line in metrics.lines() {
                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();

                if metric.ends_with("_dkg_manager_post_allegretto_ceremonies_total") {
                    let value = value.parse::<u64>().unwrap();
                    assert_eq!(
                        value, 0,
                        "must never start a post allegretto ceremony without validators on chain"
                    );
                }
                if metric.ends_with("_dkg_manager_failed_allegretto_transitions_total") {
                    let value = value.parse::<u64>().unwrap();
                    transition_refused += (value > 0) as u32;
                }

                if metric.ends_with("_epoch_manager_latest_epoch") {
                    let value = value.parse::<u64>().unwrap();
                    epoch_transitioned += (value > 0) as u32;
                }
                if metric.ends_with("_dkg_manager_ceremony_successes_total") {
                    let value = value.parse::<u64>().unwrap();
                    dkg_successful += (value >= 2) as u32;
                }
                if metric.ends_with("_dkg_manager_pre_allegretto_ceremonies_total") {
                    let value = value.parse::<u64>().unwrap();
                    at_least_two_post_allegretto_ceremonies_started += (value >= 2) as u32;
                }
            }

            if transition_refused == how_many
                && epoch_transitioned == how_many
                && dkg_successful == how_many
                && at_least_two_post_allegretto_ceremonies_started == how_many
            {
                break;
            }
        }
    })
}

fn assert_allegretto_transition_refused_without_contract_validators(
    how_many: u32,
    epoch_length: u64,
) {
    let _ = tempo_eyre::install();

    let setup = Setup::new()
        .how_many_signers(how_many)
        .epoch_length(epoch_length)
        .allegretto_in_seconds(10)
        .no_validators_in_genesis();

    let cfg = Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|context| async move {
        let (mut validators, _execution_runtime) = setup_validators(context.clone(), setup).await;
        join_all(validators.iter_mut().map(|v| v.start())).await;

        loop {
            context.sleep(Duration::from_secs(1)).await;
            let metrics = context.encode();

            let mut transition_refused = 0;
            let mut epoch_transitioned = 0;
            let mut dkg_successful = 0;

            // Two, because the ceremony started on setup also counts.
            let mut at_least_two_post_allegretto_ceremonies_started = 0;

            for line in metrics.lines() {
                let mut parts = line.split_whitespace();
                let metric = parts.next().unwrap();
                let value = parts.next().unwrap();

                if metric.ends_with("_dkg_manager_post_allegretto_ceremonies_total") {
                    let value = value.parse::<u64>().unwrap();
                    assert_eq!(
                        value, 0,
                        "must never start a post allegretto ceremony without validators on chain"
                    );
                }
                if metric.ends_with("_dkg_manager_failed_allegretto_transitions_total") {
                    let value = value.parse::<u64>().unwrap();
                    transition_refused += (value > 0) as u32;
                }

                if metric.ends_with("_epoch_manager_latest_epoch") {
                    let value = value.parse::<u64>().unwrap();
                    epoch_transitioned += (value > 0) as u32;
                }
                if metric.ends_with("_dkg_manager_ceremony_successes_total") {
                    let value = value.parse::<u64>().unwrap();
                    dkg_successful += (value >= 2) as u32;
                }
                if metric.ends_with("_dkg_manager_pre_allegretto_ceremonies_total") {
                    let value = value.parse::<u64>().unwrap();
                    at_least_two_post_allegretto_ceremonies_started += (value >= 2) as u32;
                }
            }

            if transition_refused == how_many
                && epoch_transitioned == how_many
                && dkg_successful == how_many
                && at_least_two_post_allegretto_ceremonies_started == how_many
            {
                break;
            }
        }
    })
}
