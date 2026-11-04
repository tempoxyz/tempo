//! DKG manager tests for boundary blocks with TIP-1123 outcomes, whose next
//! ceremony is stored in the `CurrentCommittee` precompile.

use std::time::Duration;

use alloy_consensus::Sealable as _;
use commonware_consensus::types::{Epoch, Height, Round as ConsensusRound, View};
use commonware_cryptography::{
    Signer as _,
    ed25519::{PrivateKey, PublicKey},
};
use commonware_runtime::{
    Clock as _, Runner as _, Supervisor as _,
    deterministic::{Context, Runner},
};
use commonware_utils::{TryFromIterator as _, ordered};
use rand::{SeedableRng as _, rngs::StdRng};
use tempo_dkg_onchain_artifacts::{DkgCeremony, OnchainDkgOutcome, OutcomeEncoding};

use super::{
    super::{State, recovered_ceremony, state},
    harness::{
        EpochEvent, Harness, ceremony_in_state_header, dkg_state, header, parent_block,
        revealed_recovery_fixture,
    },
};
use crate::{test_utils::dkg_fixture, validators::StoredDkgCeremony};

/// T15 activates at this timestamp: after the boundary block of epoch 0
/// (timestamp 0), at the boundary block of epoch 1.
const T15_ACTIVATION: u64 = 100;

/// Players of a ceremony that differ from the players of the outputs that
/// [`dkg_state`] deals.
fn other_players() -> ordered::Set<PublicKey> {
    ordered::Set::try_from_iter((10..13).map(|seed| PrivateKey::from_seed(seed).public_key()))
        .unwrap()
}

/// Starts an actor in epoch 1, whose ceremony comes from the legacy outcome of
/// the pre-T15 boundary block of epoch 0. Returns it with the state of epoch 2
/// that the post-T15 boundary block of epoch 1 starts: the ceremony of epoch 1
/// has no dealings and fails, so epoch 2 keeps the output of epoch 1.
async fn start_in_epoch_one(context: &mut Context, partition: &str) -> (Harness, State) {
    let (state, keys, _) = dkg_state(context, Epoch::new(1), 4, false);
    let mut harness = Harness::builder(context.child("test"), partition)
        .epoch_length(10)
        .initial_state(state.clone())
        .identity(keys[0].clone())
        .build()
        .await;
    harness.execution.set_t15_activation(Some(T15_ACTIVATION));
    harness.start().await;

    // Finalizing past the parent lets the actor conclude the ceremony without
    // fetching the parent.
    for height in [10, 11] {
        harness
            .report_finalized_header(header(Height::new(height)))
            .await;
    }
    let output = harness
        .mailbox()
        .subscribe_dkg_ceremony(parent_block(
            ConsensusRound::new(state.epoch, View::new(10)),
            Height::new(10),
            1,
        ))
        .await
        .unwrap();
    assert_eq!(output, state.output, "the ceremony without dealings fails");

    let next_state = State {
        epoch: state.epoch.next(),
        players: other_players(),
        is_full_dkg: true,
        ..state
    };
    (harness, next_state)
}

#[test]
fn boundary_takes_the_next_ceremony_from_its_post_state() {
    Runner::default().start(|mut context| async move {
        let (mut harness, next_state) =
            start_in_epoch_one(&mut context, "ceremony_in_state_boundary").await;
        let (boundary, stored) =
            ceremony_in_state_header(Height::new(19), T15_ACTIVATION, &next_state);
        assert!(
            OnchainDkgOutcome::decode_extra_data(
                &boundary.inner.extra_data,
                OutcomeEncoding::Legacy
            )
            .is_err(),
            "the boundary block must not carry a legacy outcome",
        );

        // The execution layer executes the boundary block only after the
        // actor received it.
        let execution = harness.execution.clone();
        let boundary_hash = boundary.hash_slow();
        let (acknowledged, ()) =
            futures::join!(harness.try_report_finalized_header(boundary), async {
                context.sleep(Duration::from_secs(2)).await;
                execution.set_dkg_ceremony(boundary_hash, Some(stored));
            },);
        assert!(acknowledged);
        assert!(!harness.has_dealer_log(next_state.epoch).await);

        assert_eq!(
            harness.epoch_manager.events().last(),
            Some(&EpochEvent::Enter {
                epoch: next_state.epoch,
                public: next_state.output.public().clone(),
                share: None,
                participants: next_state.dealers().clone(),
            }),
        );
        harness.stop().await;
        let current = harness.storage().current();
        assert_eq!(current.epoch, next_state.epoch);
        assert_eq!(current.players(), &other_players());
        assert!(current.is_full_dkg);
    });
}

/// Turns the ceremony a boundary block stores into a corrupted post-state.
type CorruptCeremony = fn(StoredDkgCeremony) -> Option<StoredDkgCeremony>;

/// The ways the post-state of a TIP-1123 boundary block can fail to hold the
/// ceremony of the outcome's epoch.
fn corrupted_ceremonies() -> [(&'static str, CorruptCeremony); 2] {
    [
        ("uninitialized", |_| None),
        ("epoch_mismatch", |stored| {
            Some(StoredDkgCeremony {
                epoch: stored.epoch + 1,
                ..stored
            })
        }),
    ]
}

#[test]
fn boundary_rejects_a_missing_or_mismatched_stored_ceremony() {
    for (case, corrupt) in corrupted_ceremonies() {
        Runner::default().start(|mut context| async move {
            let (mut harness, next_state) =
                start_in_epoch_one(&mut context, &format!("ceremony_in_state_{case}")).await;
            let (boundary, stored) =
                ceremony_in_state_header(Height::new(19), T15_ACTIVATION, &next_state);
            harness
                .execution
                .set_dkg_ceremony(boundary.hash_slow(), corrupt(stored));

            assert!(!harness.try_report_finalized_header(boundary).await);
            harness.wait_for_exit().await;

            assert!(
                !harness.epoch_manager.events().iter().any(|event| matches!(
                    event,
                    EpochEvent::Enter { epoch, .. } if *epoch == next_state.epoch
                )),
                "{case}: the actor must not enter the next epoch",
            );
            assert_eq!(
                harness.storage().current().epoch,
                Epoch::new(1),
                "{case}: the next epoch must not be persisted",
            );
        });
    }
}

#[test]
fn startup_takes_the_ceremony_from_the_boundary_post_state() {
    Runner::default().start(|mut context| async move {
        let (mut current_state, _, _) = dkg_state(&mut context, Epoch::new(2), 4, false);
        current_state.players = other_players();
        current_state.is_full_dkg = true;
        let mut harness = Harness::builder(context.child("test"), "ceremony_in_state_startup")
            .epoch_length(10)
            // An observer, so startup does not try to recover a share.
            .identity(PrivateKey::from_seed(u64::MAX))
            .finalized_floor(Height::new(19))
            .build()
            .await;
        harness.execution.set_t15_activation(Some(0));
        let (boundary, stored) = ceremony_in_state_header(Height::new(19), 0, &current_state);
        harness
            .execution
            .set_dkg_ceremony(boundary.hash_slow(), Some(stored));
        harness.execution.add_header(boundary);

        harness.start().await;
        assert!(!harness.has_dealer_log(current_state.epoch).await);

        assert_eq!(
            harness.epoch_manager.events(),
            vec![EpochEvent::Enter {
                epoch: current_state.epoch,
                public: current_state.output.public().clone(),
                share: None,
                participants: current_state.dealers().clone(),
            }]
        );
        harness.stop().await;
        let current = harness.storage().current();
        assert_eq!(current.players(), &other_players());
        assert!(current.is_full_dkg);
    });
}

#[test]
fn startup_takes_the_ceremony_from_the_finalized_floor_state() {
    Runner::default().start(|mut context| async move {
        let (mut current_state, _, _) = dkg_state(&mut context, Epoch::new(2), 4, false);
        current_state.players = other_players();
        current_state.is_full_dkg = true;
        let mut harness = Harness::builder(context.child("test"), "ceremony_in_state_floor")
            .epoch_length(10)
            .identity(PrivateKey::from_seed(u64::MAX))
            .finalized_floor(Height::new(25))
            .build()
            .await;
        harness.execution.set_t15_activation(Some(0));
        // Only the floor's state is available, as on a node that pruned the
        // state of the boundary block.
        let (boundary, stored) = ceremony_in_state_header(Height::new(19), 0, &current_state);
        harness.execution.add_header(boundary);
        for height in 20..=25 {
            harness.execution.add_header(header(Height::new(height)));
        }
        harness
            .execution
            .set_dkg_ceremony(header(Height::new(25)).hash_slow(), Some(stored));

        harness.start().await;
        assert!(!harness.has_dealer_log(current_state.epoch).await);

        assert_eq!(
            harness.epoch_manager.events(),
            vec![EpochEvent::Enter {
                epoch: current_state.epoch,
                public: current_state.output.public().clone(),
                share: None,
                participants: current_state.dealers().clone(),
            }]
        );
        harness.stop().await;
        let current = harness.storage().current();
        assert_eq!(current.players(), &other_players());
        assert!(current.is_full_dkg);
    });
}

#[test]
fn startup_rejects_a_missing_or_mismatched_stored_ceremony() {
    for (case, corrupt) in corrupted_ceremonies() {
        Runner::default().start(|mut context| async move {
            let partition = format!("ceremony_in_state_startup_{case}");
            let (current_state, _, _) = dkg_state(&mut context, Epoch::new(2), 4, false);
            let mut harness = Harness::builder(context.child("test"), partition.clone())
                .epoch_length(10)
                .finalized_floor(Height::new(19))
                .build()
                .await;
            harness.execution.set_t15_activation(Some(0));
            let (boundary, stored) = ceremony_in_state_header(Height::new(19), 0, &current_state);
            harness
                .execution
                .set_dkg_ceremony(boundary.hash_slow(), corrupt(stored));
            harness.execution.add_header(boundary);

            harness.start().await;
            harness.wait_for_exit().await;

            assert!(harness.epoch_manager.events().is_empty(), "{case}");
            let storage = state::builder()
                .partition_prefix(&partition)
                .init_unverified(context.child("reopened"))
                .await
                .unwrap();
            assert!(
                storage.state().is_none(),
                "{case}: no state must be persisted"
            );
        });
    }
}

#[test]
fn startup_recovers_share_from_ceremony_in_state_outcomes() {
    Runner::default().start(|mut context| async move {
        let ceremony_epoch = Epoch::new(1);
        let fixture = revealed_recovery_fixture(&mut context, ceremony_epoch, true);
        let mut harness = Harness::builder(context.child("test"), "ceremony_in_state_recovery")
            .epoch_length(10)
            .identity(fixture.identity.clone())
            .finalized_floor(Height::new(19))
            .build()
            .await;
        harness.execution.set_t15_activation(Some(0));
        fixture.populate_execution(
            &harness.execution,
            &harness.epoch_strategy,
            OutcomeEncoding::CeremonyInState,
        );

        harness.start().await;
        assert!(!harness.has_dealer_log(ceremony_epoch.next()).await);

        assert_eq!(
            harness.epoch_manager.events(),
            vec![EpochEvent::Enter {
                epoch: ceremony_epoch.next(),
                public: fixture.expected_output.public().clone(),
                share: Some(fixture.recovered_share),
                participants: fixture.expected_output.players().clone(),
            }]
        );
    });
}

/// Returns the legacy outcome of a DKG dealt for `epoch`, seeded with `epoch`.
fn dealt(epoch: u64) -> OnchainDkgOutcome {
    dkg_fixture(&mut StdRng::seed_from_u64(epoch), Epoch::new(epoch)).outcome
}

/// Returns a state whose output is `outcome`'s.
fn state_with_output(outcome: &OnchainDkgOutcome) -> State {
    let (state, _, _) = dkg_state(&mut StdRng::seed_from_u64(0), outcome.epoch(), 1, false);
    State {
        output: outcome.output.clone(),
        ..state
    }
}

#[test]
fn recovery_uses_the_ceremony_of_a_legacy_outcome() {
    let ceremony_outcome = dealt(1);
    let current = state_with_output(&dealt(2));

    assert_eq!(
        Some(recovered_ceremony(&ceremony_outcome, &current)),
        ceremony_outcome.next_ceremony,
    );
}

#[test]
fn recovery_derives_the_ceremony_of_a_ceremony_in_state_outcome() {
    let ceremony_outcome = OnchainDkgOutcome {
        next_ceremony: None,
        ..dealt(1)
    };

    // A full DKG changes the network identity.
    let full_dkg = state_with_output(&dealt(2));
    assert_eq!(
        recovered_ceremony(&ceremony_outcome, &full_dkg),
        DkgCeremony {
            players: full_dkg.output.players().clone(),
            is_full_dkg: true,
        },
    );

    // A reshare keeps it.
    let reshare = state_with_output(&ceremony_outcome);
    assert_eq!(
        recovered_ceremony(&ceremony_outcome, &reshare),
        DkgCeremony {
            players: ceremony_outcome.players().clone(),
            is_full_dkg: false,
        },
    );
}
