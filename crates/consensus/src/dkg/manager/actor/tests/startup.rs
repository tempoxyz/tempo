//! Startup authentication uses only the binary and the latest persisted DKG state.

use alloy_consensus::{BlockHeader as _, Sealable as _};
use commonware_consensus::types::{Epoch, FixedEpocher, Height};
use commonware_cryptography::{Signer as _, transcript::Summary};
use commonware_math::algebra::Random as _;
use commonware_runtime::{Runner as _, Supervisor as _, deterministic::Runner};
use rand_core::CryptoRng;
use tempo_chainspec::NetworkIdentity;
use tempo_primitives::TempoHeader;

use super::{
    super::{
        startup::verify_finalized_tip,
        state::{self, ShareState, State},
    },
    harness::{Harness, header, outcome_header},
};
use crate::{
    alias::marshal::FinalizedTip,
    consensus::Digest,
    test_utils::{DkgFixture, dkg_fixture, make_certificate},
};

fn identity(fixture: &DkgFixture) -> NetworkIdentity {
    NetworkIdentity {
        from_epoch: fixture.outcome.epoch,
        identity: *fixture.outcome.network_identity(),
    }
}

fn persisted(fixture: &DkgFixture, rng: &mut impl CryptoRng) -> State {
    State {
        epoch: fixture.outcome.epoch(),
        seed: Summary::random(rng),
        output: fixture.outcome.output.clone(),
        share: ShareState::unset_plaintext(),
        players: fixture.outcome.next_players.clone(),
        is_full_dkg: false,
    }
}

fn tip(fixture: &DkgFixture, epoch: u64) -> FinalizedTip {
    tip_for_header(fixture, &header(Height::new(epoch * 10 + 2)))
}

fn tip_for_header(fixture: &DkgFixture, header: &TempoHeader) -> FinalizedTip {
    FinalizedTip::new(
        Height::new(header.number()),
        header,
        make_certificate(
            Digest(header.hash_slow()),
            Epoch::new(header.number() / 10),
            1,
            &fixture.schemes,
        ),
    )
    .unwrap()
}

#[test]
fn startup_uses_the_newest_trusted_identity_without_falling_back() {
    Runner::default().start(|mut context| async move {
        let old = dkg_fixture(&mut context, Epoch::new(1));
        let new = dkg_fixture(&mut context, Epoch::new(3));
        let old_state = persisted(&old, &mut context);
        let new_state = persisted(&new, &mut context);
        let old_tip = tip(&old, 3);
        let new_tip = tip(&new, 3);
        let reshared_tip = tip(&new, 4);
        let strategy = FixedEpocher::new(commonware_utils::NZU64!(10));
        for (name, binary, state, tip, accepted) in [
            ("binary identity", identity(&new), None, &new_tip, true),
            (
                "same key in a later epoch",
                identity(&old),
                None,
                &old_tip,
                true,
            ),
            (
                "unknown rotation without local state",
                identity(&old),
                None,
                &new_tip,
                false,
            ),
            (
                "newer local state",
                identity(&old),
                Some(&new_state),
                &new_tip,
                true,
            ),
            (
                "newer binary",
                identity(&new),
                Some(&old_state),
                &new_tip,
                true,
            ),
            (
                "matching binary and local state",
                identity(&new),
                Some(&new_state),
                &new_tip,
                true,
            ),
            (
                "stale local state cannot authenticate rotation",
                identity(&old),
                Some(&old_state),
                &new_tip,
                false,
            ),
            (
                "no fallback to old binary",
                identity(&old),
                Some(&new_state),
                &old_tip,
                false,
            ),
            (
                "no fallback to old local state",
                identity(&new),
                Some(&old_state),
                &old_tip,
                false,
            ),
            (
                "reshare after persisted epoch",
                identity(&old),
                Some(&new_state),
                &reshared_tip,
                true,
            ),
        ] {
            let result = verify_finalized_tip(
                &mut context,
                &strategy,
                &binary,
                state,
                Some(tip),
                Height::zero(),
            );
            assert_eq!(result.is_ok(), accepted, "{name}: {result:?}");
        }
    });
}

#[test]
fn historical_tips_and_genesis_remain_allowed() {
    Runner::default().start(|mut context| async move {
        let old = dkg_fixture(&mut context, Epoch::new(1));
        let new = dkg_fixture(&mut context, Epoch::new(3));
        let state = persisted(&new, &mut context);
        // Last block of epoch 2, signed by the outgoing key. Persisted DKG
        // state already holds the identity for epoch 3.
        let boundary_tip = tip_for_header(&old, &header(Height::new(29)));
        let strategy = FixedEpocher::new(commonware_utils::NZU64!(10));
        for (binary, local) in [
            (identity(&new), None),
            (identity(&old), Some(&state)),
            (identity(&new), Some(&state)),
        ] {
            verify_finalized_tip(
                &mut context,
                &strategy,
                &binary,
                local,
                Some(&boundary_tip),
                Height::new(29),
            )
            .unwrap();
            verify_finalized_tip(
                &mut context,
                &strategy,
                &binary,
                local,
                None,
                Height::zero(),
            )
            .unwrap();
        }
    });
}

#[test]
fn startup_rejects_malformed_or_invalid_tip_certificates() {
    Runner::default().start(|mut context| async move {
        let fixture = dkg_fixture(&mut context, Epoch::new(0));
        let binary = identity(&fixture);
        let strategy = FixedEpocher::new(commonware_utils::NZU64!(10));
        let valid = tip(&fixture, 1);
        let mut altered_header = header(valid.height());
        altered_header.inner.extra_data = vec![1].into();
        let mut invalid_certificate = valid.certificate().clone();
        invalid_certificate.proposal.payload = Digest(altered_header.hash_slow());
        // Header and payload agree, but the signature still covers the original payload.
        let invalid =
            FinalizedTip::new(valid.height(), &altered_header, invalid_certificate).unwrap();
        let wrong_epoch_header = header(Height::new(22));
        let wrong_epoch = FinalizedTip::new(
            Height::new(22),
            &wrong_epoch_header,
            make_certificate(
                Digest(wrong_epoch_header.hash_slow()),
                Epoch::new(1),
                1,
                &fixture.schemes,
            ),
        )
        .unwrap();
        let genesis_certificate = tip_for_header(&fixture, &header(Height::zero()));
        for tip in [invalid, wrong_epoch, genesis_certificate] {
            assert!(
                verify_finalized_tip(
                    &mut context,
                    &strategy,
                    &binary,
                    None,
                    Some(&tip),
                    Height::zero()
                )
                .is_err()
            );
        }
        assert!(
            verify_finalized_tip(&mut context, &strategy, &binary, None, None, Height::new(1))
                .is_err()
        );
        assert!(
            verify_finalized_tip(
                &mut context,
                &strategy,
                &binary,
                None,
                Some(&tip(&fixture, 1)),
                Height::new(13)
            )
            .is_err()
        );
    });
}

#[test]
#[should_panic(expected = "persisted DKG network identity differs from the binary")]
fn startup_rejects_conflicting_persisted_identity_even_for_a_historical_tip() {
    Runner::default().start(|mut context| async move {
        let binary = dkg_fixture(&mut context, Epoch::new(3));
        let local = dkg_fixture(&mut context, Epoch::new(3));
        let state = persisted(&local, &mut context);
        let strategy = FixedEpocher::new(commonware_utils::NZU64!(10));
        let _ = verify_finalized_tip(
            &mut context,
            &strategy,
            &identity(&binary),
            Some(&state),
            None,
            Height::zero(),
        );
    });
}

#[test]
fn rejected_tip_does_not_heal_or_persist_snapshot_identity() {
    for has_local_state in [false, true] {
        Runner::default().start(|mut context| async move {
            let trusted = dkg_fixture(&mut context, Epoch::new(1));
            let snapshot = dkg_fixture(&mut context, Epoch::new(2));
            let local_state = persisted(&trusted, &mut context);
            let snapshot_state = persisted(&snapshot, &mut context);
            let prefix = "reject_snapshot_rotation";
            let mut builder = Harness::builder(context.child("test"), prefix)
                .finalized_floor(Height::new(19))
                .startup(identity(&trusted), Some(tip(&snapshot, 2)));
            if has_local_state {
                builder = builder.initial_state(local_state.clone());
            }
            let mut harness = builder.build().await;
            harness
                .execution
                .add_header(outcome_header(Height::new(19), &snapshot_state));
            harness.start().await;
            harness.wait_for_actor_exit().await;
            assert!(harness.epoch_manager.events().is_empty());
            assert!(
                harness.execution.reads().is_empty(),
                "verification must precede healing from the snapshot"
            );
            let storage = state::builder()
                .partition_prefix(prefix)
                .init_unverified(context.child("inspect_storage"))
                .await
                .unwrap();
            match storage.state() {
                Some(state) => {
                    assert!(has_local_state);
                    assert_eq!(state.epoch, local_state.epoch);
                    assert_eq!(state.output, local_state.output);
                }
                None => assert!(!has_local_state),
            }
        });
    }
}

#[test]
fn authenticated_tip_allows_healing_from_an_older_floor() {
    Runner::default().start(|mut context| async move {
        let old = dkg_fixture(&mut context, Epoch::new(1));
        let current = dkg_fixture(&mut context, Epoch::new(2));
        let old_state = persisted(&old, &mut context);
        let current_state = persisted(&current, &mut context);
        let mut harness = Harness::builder(context.child("test"), "authenticate_before_healing")
            .initial_state(old_state)
            .identity(commonware_cryptography::ed25519::PrivateKey::from_seed(
                u64::MAX,
            ))
            .finalized_floor(Height::new(19))
            // The floor is still in epoch 1, but the actual tip is in epoch 2
            // and must be verified with the updated binary identity.
            .startup(identity(&current), Some(tip(&current, 2)))
            .build()
            .await;
        harness
            .execution
            .add_header(outcome_header(Height::new(19), &current_state));
        harness.start().await;
        assert!(!harness.has_dealer_log(current_state.epoch).await);
        harness.stop().await;
        assert_eq!(harness.storage().current().epoch, current_state.epoch);
        assert_eq!(harness.storage().current().output, current_state.output);
        assert_eq!(harness.execution.reads(), vec![Height::new(19)]);
    });
}
