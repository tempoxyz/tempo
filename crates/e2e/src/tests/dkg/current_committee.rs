//! Tests for the current committee precompile populated from DKG outcomes.

use alloy::transports::http::reqwest::Url;
use alloy_primitives::{B256, U256, keccak256};
use commonware_macros::test_traced;
use commonware_runtime::{
    Runner as _,
    deterministic::{Config, Context, Runner},
};
use futures::future::join_all;
use reth_ethereum::provider::{StateProvider as _, StateProviderFactory as _};
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_precompiles::current_committee::CURRENT_COMMITTEE_ADDRESS;

use super::common::{target_epoch, wait_for_outcome, wait_for_validators_to_reach_epoch};
use crate::{Setup, TestingNode, metrics::MetricsExt as _, setup_validators};

#[test_traced]
fn current_committee_tracks_consecutive_boundary_outcomes() {
    let _ = tempo_eyre::install();

    let how_many_signers = 1;
    let epoch_length = 5;
    let setup = Setup::new()
        .how_many_signers(how_many_signers)
        .epoch_length(epoch_length);

    let cfg = Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;

        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        for boundary_epoch in 0..3 {
            let outcome =
                wait_for_outcome(&context, &validators, boundary_epoch, epoch_length).await;
            wait_for_validators_to_reach_epoch(&context, outcome.epoch.get(), how_many_signers)
                .await;
            context.to_metrics().assert_no_dkg_failures();

            assert_current_committee_matches(
                &validators[0],
                boundary_height(boundary_epoch, epoch_length),
                &outcome,
            );
        }
    });
}

#[test_traced]
fn current_committee_replaces_members_after_validator_removal() {
    let _ = tempo_eyre::install();

    let how_many_signers = 2;
    let epoch_length = 20;
    let setup = Setup::new()
        .how_many_signers(how_many_signers)
        .epoch_length(epoch_length);

    let cfg = Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let (mut validators, execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        let initial_outcome = wait_for_outcome(&context, &validators, 0, epoch_length).await;
        assert_current_committee_matches(
            &validators[0],
            boundary_height(0, epoch_length),
            &initial_outcome,
        );
        assert_eq!(initial_outcome.players().len(), how_many_signers as usize);

        let http_url = validators[0]
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
        let effective_epoch = removal_epoch.next();
        let boundary_epoch = effective_epoch.get() - 1;
        let replacement =
            wait_for_outcome(&context, &validators, boundary_epoch, epoch_length).await;
        wait_for_validators_to_reach_epoch(&context, effective_epoch.get(), how_many_signers - 1)
            .await;
        context.to_metrics().assert_no_dkg_failures();

        assert_eq!(replacement.epoch, effective_epoch);
        assert_eq!(replacement.players().len(), (how_many_signers - 1) as usize);
        assert_current_committee_matches(
            &validators[0],
            boundary_height(boundary_epoch, epoch_length),
            &replacement,
        );

        // The removed tail must not remain readable after the shorter vector replaces it.
        let (_, public_keys) = read_current_committee(
            &validators[0],
            boundary_height(boundary_epoch, epoch_length),
        );
        assert_eq!(public_keys.len(), (how_many_signers - 1) as usize);
    });
}

fn boundary_height(epoch: u64, epoch_length: u64) -> u64 {
    (epoch + 1) * epoch_length - 1
}

fn assert_current_committee_matches(
    validator: &TestingNode<Context>,
    block_number: u64,
    outcome: &OnchainDkgOutcome,
) {
    let (epoch, public_keys) = read_current_committee(validator, block_number);
    let expected_public_keys = outcome
        .players()
        .iter()
        .map(|key| B256::from_slice(key.as_ref()))
        .collect::<Vec<_>>();

    assert_eq!(epoch, outcome.epoch.get());
    assert_eq!(public_keys, expected_public_keys);
}

fn read_current_committee(validator: &TestingNode<Context>, block_number: u64) -> (u64, Vec<B256>) {
    let provider = validator.execution_provider();
    let state = provider.history_by_block_number(block_number).unwrap();

    let epoch = state
        .storage(CURRENT_COMMITTEE_ADDRESS, U256::ZERO.into())
        .unwrap()
        .unwrap_or_default()
        .to::<u64>();
    let public_keys_len = state
        .storage(CURRENT_COMMITTEE_ADDRESS, U256::from(1).into())
        .unwrap()
        .unwrap_or_default()
        .to::<usize>();
    let public_keys_data_slot = U256::from_be_bytes(keccak256(U256::from(1).to_be_bytes::<32>()).0);
    let public_keys = (0..public_keys_len)
        .map(|index| {
            state
                .storage(
                    CURRENT_COMMITTEE_ADDRESS,
                    (public_keys_data_slot + U256::from(index)).into(),
                )
                .unwrap()
                .unwrap_or_default()
        })
        .map(|value| B256::from(value.to_be_bytes::<32>()))
        .collect();

    (epoch, public_keys)
}
