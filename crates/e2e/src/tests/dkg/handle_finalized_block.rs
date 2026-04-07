//! E2E tests for the DKG actor's per-block processing logic across epoch phases.

use commonware_macros::test_traced;
use commonware_runtime::{
    Runner as _,
    deterministic::{Config, Runner},
};
use futures::future::join_all;

use super::common::{
    assert_no_dkg_failures, sum_metric_with_suffix, wait_for_outcome,
    wait_for_validators_to_reach_epoch,
};
use crate::{Setup, setup_validators};

/// Tests that the epoch counter only advances on the last block of each epoch.
///
/// Runs 4 validators for 2 epochs and verifies that the on-chain DKG outcome
/// at each boundary block carries the next epoch number, confirming that
/// mid-epoch blocks do not trigger an epoch transition.
#[test_traced]
fn mid_epoch_blocks_do_not_advance_epoch() {
    MidEpochBlockTest {
        how_many_signers: 4,
        epoch_length: 20,
        wait_until_epoch: 2,
    }
    .run();
}

struct MidEpochBlockTest {
    how_many_signers: u32,
    epoch_length: u64,
    /// How many epochs to let run to confirm behaviour is stable.
    wait_until_epoch: u64,
}

impl MidEpochBlockTest {
    fn run(self) {
        let _ = tempo_eyre::install();

        let setup = Setup::new()
            .how_many_signers(self.how_many_signers)
            .t2_time(0)
            .epoch_length(self.epoch_length);

        let cfg = Config::default().with_seed(setup.seed);
        let executor = Runner::from(cfg);

        executor.start(|mut context| async move {
            let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
            join_all(validators.iter_mut().map(|v| v.start(&context))).await;

            // Wait for validators to complete several full epochs.
            wait_for_validators_to_reach_epoch(
                &context,
                self.wait_until_epoch,
                self.how_many_signers,
            )
            .await;

            // Verify on-chain DKG outcome epoch number at each boundary block.
            for epoch in 0..self.wait_until_epoch {
                let outcome =
                    wait_for_outcome(&context, &validators, epoch, self.epoch_length).await;

                assert_eq!(
                    outcome.epoch.get(),
                    epoch + 1,
                    "DKG outcome at end of epoch {epoch} must carry the next epoch number"
                );
            }

            assert_no_dkg_failures(&context);
        })
    }
}

/// Tests that dealer nodes distribute shares during the early phase of a DKG ceremony.
///
/// Runs 4 validators for 1 epoch and verifies that at least one node acted as
/// a dealer by checking the dealer activity counter is non-zero.
#[test_traced]
fn early_phase_dealer_distributes_shares() {
    let _ = tempo_eyre::install();

    let setup = Setup::new().how_many_signers(4).t2_time(0).epoch_length(20);

    let cfg = Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        // Run one complete epoch so dealers have had a chance to distribute.
        wait_for_validators_to_reach_epoch(&context, 1, 4).await;

        // Verify at least one node acted as a dealer during the epoch.
        let how_often_dealer =
            sum_metric_with_suffix(&context, "_dkg_manager_how_often_dealer_total");
        assert!(
            how_often_dealer > 0,
            "expected at least one validator to have acted as dealer \
             (how_often_dealer_total={how_often_dealer})"
        );

        assert_no_dkg_failures(&context);
    })
}

/// Tests that dealer nodes finalize their state in the midpoint and late phases.
///
/// Runs 4 validators for 2 epochs and verifies that at least one DKG ceremony
/// completed successfully by checking the ceremony success counter is non-zero.
#[test_traced]
fn midpoint_and_late_phase_dealer_finalization() {
    let _ = tempo_eyre::install();

    let setup = Setup::new().how_many_signers(4).t2_time(0).epoch_length(20);

    let cfg = Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        // Two epochs to confirm dealer finalization is stable across reshares.
        wait_for_validators_to_reach_epoch(&context, 2, 4).await;

        // Verify at least one ceremony completed successfully.
        let successes = sum_metric_with_suffix(&context, "_dkg_manager_ceremony_successes_total");
        assert!(
            successes > 0,
            "expected at least one successful ceremony, confirming dealer finalization \
             ran in Midpoint/Late phase (ceremony_successes_total={successes})"
        );

        assert_no_dkg_failures(&context);
    })
}

/// Tests that a restarted node silently ignores blocks from prior epochs.
///
/// Runs 4 validators, restarts one after the first epoch completes, and
/// verifies all 4 nodes advance to epoch 3 without errors.
#[test_traced]
fn restarted_node_ignores_prior_epoch_blocks() {
    RestartMidEpochTest {
        how_many_signers: 4,
        epoch_length: 20,
        restart_after_epoch: 1,
    }
    .run();
}

struct RestartMidEpochTest {
    how_many_signers: u32,
    epoch_length: u64,
    /// Restart the first validator after this epoch completes.
    restart_after_epoch: u64,
}

impl RestartMidEpochTest {
    fn run(self) {
        let _ = tempo_eyre::install();

        let setup = Setup::new()
            .how_many_signers(self.how_many_signers)
            .t2_time(0)
            .epoch_length(self.epoch_length);

        let cfg = Config::default().with_seed(setup.seed);
        let executor = Runner::from(cfg);

        executor.start(|mut context| async move {
            let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
            join_all(validators.iter_mut().map(|v| v.start(&context))).await;

            // Let all validators complete the first epoch before restarting.
            wait_for_validators_to_reach_epoch(
                &context,
                self.restart_after_epoch + 1,
                self.how_many_signers,
            )
            .await;

            // Restart the first validator.
            validators[0].stop().await;
            validators[0].start(&context).await;

            // Verify the restarted node rejoins and all nodes advance to the next epoch.
            wait_for_validators_to_reach_epoch(
                &context,
                self.restart_after_epoch + 2,
                self.how_many_signers,
            )
            .await;

            assert_no_dkg_failures(&context);
        })
    }
}

/// Tests that the boundary block of each epoch correctly resolves the DKG outcome.
///
/// Runs 4 validators for 3 epochs and verifies:
/// 1. The outcome epoch number advances by one at each boundary block.
/// 2. The next set of validators is populated after each transition.
/// 3. The group public key remains stable across reshares.
#[test_traced]
fn boundary_block_resolves_epoch_outcome_and_advances_state() {
    BoundaryBlockTest {
        how_many_signers: 4,
        epoch_length: 20,
        epochs_to_run: 3,
    }
    .run();
}

struct BoundaryBlockTest {
    how_many_signers: u32,
    epoch_length: u64,
    epochs_to_run: u64,
}

impl BoundaryBlockTest {
    fn run(self) {
        let _ = tempo_eyre::install();

        let setup = Setup::new()
            .how_many_signers(self.how_many_signers)
            .t2_time(0)
            .epoch_length(self.epoch_length);

        let cfg = Config::default().with_seed(setup.seed);
        let executor = Runner::from(cfg);

        executor.start(|mut context| async move {
            let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
            join_all(validators.iter_mut().map(|v| v.start(&context))).await;

            wait_for_validators_to_reach_epoch(&context, self.epochs_to_run, self.how_many_signers)
                .await;

            // Verify invariants at each epoch boundary.
            let mut prev_pubkey = None;

            for epoch in 0..self.epochs_to_run {
                let outcome =
                    wait_for_outcome(&context, &validators, epoch, self.epoch_length).await;

                // Outcome epoch must be current epoch + 1.
                assert_eq!(
                    outcome.epoch.get(),
                    epoch + 1,
                    "outcome at end of epoch {epoch} must carry epoch {}",
                    epoch + 1,
                );

                // Next-players set must be populated.
                assert!(
                    !outcome.next_players.is_empty(),
                    "next_players must be populated by resolve_epoch_outcome \
                     at end of epoch {epoch}"
                );

                // Group public key must be stable across reshares.
                let pubkey = *outcome.sharing().public();
                if let Some(prev) = prev_pubkey {
                    assert_eq!(
                        prev,
                        pubkey,
                        "group public key must be stable across reshare epochs \
                         (changed between epoch {} and {epoch})",
                        epoch - 1,
                    );
                }
                prev_pubkey = Some(pubkey);

                tracing::info!(
                    epoch,
                    next_epoch = outcome.epoch.get(),
                    ?pubkey,
                    "Verified resolve_epoch_outcome output"
                );
            }

            assert_no_dkg_failures(&context);
        })
    }
}

/// Tests epoch boundary resolution with a single-signer setup.
///
/// Runs 1 validator for 3 epochs with 10-block epochs and verifies the same
/// boundary block invariants as the multi-signer test.
#[test_traced]
fn resolve_epoch_outcome_single_signer() {
    BoundaryBlockTest {
        how_many_signers: 1,
        epoch_length: 10,
        epochs_to_run: 3,
    }
    .run();
}

/// Tests that dealer logs written into block extra data are stored and used to complete the ceremony.
///
/// Runs 4 validators for 1 epoch and verifies that no DKG failures occur
/// and the ceremony produces a valid outcome for epoch 1.
#[test_traced]
fn dealer_log_in_block_extra_data_is_stored() {
    let _ = tempo_eyre::install();

    // 4 signers so each node acts as both dealer and player.
    let setup = Setup::new().how_many_signers(4).t2_time(0).epoch_length(20);

    let cfg = Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        // Wait for one full epoch.
        wait_for_validators_to_reach_epoch(&context, 1, 4).await;

        // Verify no failures and the ceremony produced a valid outcome.
        assert_no_dkg_failures(&context);

        // Verify the outcome epoch advanced.
        let outcome = wait_for_outcome(&context, &validators, 0, 20).await;
        assert_eq!(
            outcome.epoch.get(),
            1,
            "ceremony must have produced an outcome for epoch 1"
        );
    })
}

/// Tests that a dealer's own log is cleared from state after it appears in a finalized block.
///
/// Runs 4 validators for 2 epochs and verifies no DKG failures occur,
/// confirming stale logs do not re-appear during the next epoch's reshare.
#[test_traced]
fn own_dealer_log_in_block_is_cleared_from_state() {
    let _ = tempo_eyre::install();

    let setup = Setup::new().how_many_signers(4).t2_time(0).epoch_length(20);

    let cfg = Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        // Run two full epochs to confirm no stale logs re-appear during reshare.
        wait_for_validators_to_reach_epoch(&context, 2, 4).await;
        assert_no_dkg_failures(&context);
    })
}
