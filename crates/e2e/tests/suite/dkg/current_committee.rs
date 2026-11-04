//! Tests for the current committee precompile populated from DKG outcomes.

use alloy_primitives::{B256, U256, keccak256};
use commonware_consensus::types::{Epoch, Epocher as _, FixedEpocher, Height};
use commonware_macros::test_traced;
use commonware_runtime::{
    Runner as _,
    deterministic::{Config, Runner},
};
use commonware_utils::{NZU64, TryFromIterator as _, ordered};
use futures::future::join_all;
use reth_ethereum::provider::{BlockReader as _, StateProvider as _, StateProviderFactory as _};
use tempo_dkg_onchain_artifacts::OutcomeEncoding;
use tempo_precompiles::{
    current_committee::{CURRENT_COMMITTEE_ADDRESS, ICurrentCommittee},
    error::TempoPrecompileError,
};

use super::common::{
    public_keys, read_outcome_from_validator, read_stored_dkg_ceremony, wait_for_outcome,
    wait_for_validators_to_reach_epoch,
};
use crate::{
    Setup, TestingNode, connect_execution_peers,
    metrics::{MetricsExt as _, wait_for_metrics},
    setup_validators,
};

#[test_traced]
fn current_committee_matches_boundary_dkg_outcome() {
    let _ = tempo_eyre::install();

    let how_many_signers = 1;
    let epoch_length = 10;
    let setup = Setup::new(crate::VERIFICATION_MODE)
        .how_many_signers(how_many_signers)
        .epoch_length(epoch_length);

    let cfg = Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;

        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        let outcome = wait_for_outcome(&context, &validators, 0, epoch_length).await;
        wait_for_validators_to_reach_epoch(&context, outcome.epoch, how_many_signers).await;
        context.to_metrics().assert_no_dkg_failures();

        let provider = validators[0].execution_provider();
        let state = provider.history_by_block_number(epoch_length - 1).unwrap();

        let epoch = state
            .storage(CURRENT_COMMITTEE_ADDRESS, B256::ZERO)
            .unwrap()
            .unwrap_or_default()
            .to::<u64>();
        let public_keys_len = state
            .storage(CURRENT_COMMITTEE_ADDRESS, B256::with_last_byte(1))
            .unwrap()
            .unwrap_or_default()
            .to::<usize>();
        let public_keys_data_slot = U256::from_be_bytes(keccak256(B256::with_last_byte(1)).0);
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
            .map(B256::from)
            .collect::<Vec<_>>();
        let expected_public_keys = outcome
            .players()
            .iter()
            .map(|key| B256::from_slice(key.as_ref()))
            .collect::<Vec<_>>();

        assert_eq!(epoch, outcome.epoch);
        assert_eq!(public_keys, expected_public_keys);
    });
}

/// Returns the keys of `validators` in the order the precompile stores ceremony players.
fn sorted_keys(
    validators: &[TestingNode<commonware_runtime::deterministic::Context>],
) -> Vec<B256> {
    public_keys(
        &ordered::Set::try_from_iter(validators.iter().map(TestingNode::public_key))
            .expect("validator keys are distinct"),
    )
}

#[test_traced]
fn boundaries_store_the_next_dkg_ceremony_from_genesis() {
    let _ = tempo_eyre::install();

    let how_many_signers = 4;
    let epoch_length = 20;
    let setup = Setup::new(crate::VERIFICATION_MODE)
        .how_many_signers(how_many_signers)
        .epoch_length(epoch_length);

    let cfg = Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;

        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        let outcome = wait_for_outcome(&context, &validators, 0, epoch_length).await;
        wait_for_validators_to_reach_epoch(&context, outcome.epoch, how_many_signers).await;
        context.to_metrics().assert_no_dkg_failures();

        // The boundary carries only the outcome; its ceremony lives in state.
        assert_eq!(outcome.encoding(), OutcomeEncoding::CeremonyInState);

        let validator = &validators[0];
        let players = sorted_keys(&validators);
        let genesis_outcome = read_outcome_from_validator(validator, Height::zero()).unwrap();
        assert_eq!(genesis_outcome.encoding(), OutcomeEncoding::CeremonyInState);
        let genesis_ceremony = ICurrentCommittee::getDkgCeremonyReturn {
            epoch: 0,
            dealers: public_keys(genesis_outcome.players()),
            players: players.clone(),
            isRotatingNetworkIdentity: false,
        };
        assert_eq!(
            read_stored_dkg_ceremony(validator, Height::zero()).unwrap(),
            genesis_ceremony
        );
        // The record changes only at boundaries.
        assert_eq!(
            read_stored_dkg_ceremony(validator, Height::new(epoch_length - 2)).unwrap(),
            genesis_ceremony
        );
        assert_eq!(
            read_stored_dkg_ceremony(validator, Height::new(epoch_length - 1)).unwrap(),
            ICurrentCommittee::getDkgCeremonyReturn {
                epoch: 1,
                dealers: public_keys(outcome.players()),
                players,
                isRotatingNetworkIdentity: false,
            }
        );
    });
}

#[test_traced]
fn first_activated_boundary_stores_the_next_dkg_ceremony() {
    let _ = tempo_eyre::install();
    const EPOCH_LENGTH: u64 = 20;
    // Activates T15 after genesis, so that at least one legacy boundary precedes the first
    // TIP-1123 boundary. Which boundary is first depends on how fast blocks are produced, so the
    // test walks boundaries until it finds it, up to MAX_EPOCH.
    const ACTIVATION: u64 = 6;
    const MAX_EPOCH: u64 = 8;

    let how_many_signers = 4;
    let setup = Setup::new(crate::VERIFICATION_MODE)
        .how_many_signers(how_many_signers)
        .epoch_length(EPOCH_LENGTH)
        .t15_time(ACTIVATION);

    let cfg = Config::default().with_seed(setup.seed);

    Runner::from(cfg).start(|mut context| async move {
        let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(validators.iter_mut().map(|node| node.start(&context))).await;
        connect_execution_peers(&validators).await;

        let epocher = FixedEpocher::new(NZU64!(EPOCH_LENGTH));
        let validator = &validators[0];
        let provider = validator.execution_provider();
        let timestamp = |height: Height| {
            provider
                .block_by_number(height.get())
                .unwrap()
                .unwrap()
                .header
                .inner
                .timestamp
        };
        assert!(timestamp(Height::zero()) < ACTIVATION);
        assert!(matches!(
            read_stored_dkg_ceremony(validator, Height::zero()),
            Err(TempoPrecompileError::CurrentCommitteeError(
                ICurrentCommittee::ICurrentCommitteeErrors::Uninitialized(_)
            ))
        ));

        let players = sorted_keys(&validators);
        let mut transition = None;
        for epoch in 0..=MAX_EPOCH {
            let boundary = epocher.last(Epoch::new(epoch)).unwrap();
            // Waits until the epoch after the boundary started, so its ceremony is running.
            let target_height = epocher.first(Epoch::new(epoch + 1)).unwrap();
            wait_for_metrics(&context, |metrics| {
                metrics.assert_no_dkg_failures();
                metrics.consensus_at_height(target_height.get()) == validators.len()
            })
            .await;

            // The ceremony read from state at the first activated boundary ran through its epoch.
            if transition.is_some_and(|transition| transition < boundary) {
                break;
            }

            let outcome = read_outcome_from_validator(validator, boundary).unwrap();
            assert_eq!(outcome.epoch, epoch + 1);
            let stored = read_stored_dkg_ceremony(validator, boundary);
            tracing::info!(
                epoch,
                %boundary,
                timestamp = timestamp(boundary),
                parent_timestamp = timestamp(boundary.previous().unwrap()),
                ?stored,
                "boundary"
            );

            // A boundary's own timestamp selects its rules, whatever its parent's.
            if timestamp(boundary) < ACTIVATION {
                assert_eq!(outcome.encoding(), OutcomeEncoding::Legacy);
                assert!(matches!(
                    stored,
                    Err(TempoPrecompileError::CurrentCommitteeError(
                        ICurrentCommittee::ICurrentCommitteeErrors::Uninitialized(_)
                    ))
                ));
                continue;
            }
            transition.get_or_insert(boundary);
            assert_eq!(outcome.encoding(), OutcomeEncoding::CeremonyInState);
            assert_eq!(
                stored.unwrap(),
                ICurrentCommittee::getDkgCeremonyReturn {
                    epoch: epoch + 1,
                    dealers: public_keys(outcome.players()),
                    players: players.clone(),
                    isRotatingNetworkIdentity: false,
                }
            );
        }

        // The first activated boundary follows a legacy one.
        let transition = transition.expect("T15 activates by the boundary of MAX_EPOCH");
        assert!(transition > epocher.last(Epoch::zero()).unwrap());
    });
}
