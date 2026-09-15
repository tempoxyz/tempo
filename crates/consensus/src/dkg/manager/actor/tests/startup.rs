//! Startup authentication uses only the configured identity and the latest persisted DKG state.

use alloy_consensus::{BlockHeader as _, Sealable as _};
use commonware_consensus::types::{Epoch, FixedEpocher, Height, Round};
use commonware_cryptography::{Signer as _, transcript::Summary};
use commonware_math::algebra::Random as _;
use commonware_runtime::{Runner as _, Supervisor as _, deterministic::Runner};
use rand_core::CryptoRng;
use tempo_chainspec::NetworkIdentity;
use tempo_primitives::{TempoConsensusContext, TempoHeader};

use super::{
    super::{
        startup::verify_finalized_tip,
        state::{self, ShareState, State},
    },
    harness::{Harness, block, header, outcome_header},
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
        for (name, configured_identity, state, tip, accepted) in [
            ("configured identity", identity(&new), None, &new_tip, true),
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
                "newer configured identity",
                identity(&new),
                Some(&old_state),
                &new_tip,
                true,
            ),
            (
                "matching configured identity and local state",
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
                "no fallback to old configured identity",
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
                &configured_identity,
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
        for (configured_identity, local) in [
            (identity(&new), None),
            (identity(&old), Some(&state)),
            (identity(&new), Some(&state)),
        ] {
            verify_finalized_tip(
                &mut context,
                &strategy,
                &configured_identity,
                local,
                Some(&boundary_tip),
                Height::new(29),
            )
            .unwrap();
            verify_finalized_tip(
                &mut context,
                &strategy,
                &configured_identity,
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
        let configured_identity = identity(&fixture);
        let strategy = FixedEpocher::new(commonware_utils::NZU64!(10));
        let valid = tip(&fixture, 1);
        let mut altered_header = header(valid.height());
        altered_header.inner.extra_data = vec![1].into();
        let mut invalid_certificate = valid.certificate().clone();
        invalid_certificate.proposal.payload = Digest(altered_header.hash_slow());
        // Header and payload agree, but the signature still covers the original payload.
        let invalid =
            FinalizedTip::new(valid.height(), &altered_header, invalid_certificate).unwrap();
        let genesis_certificate = tip_for_header(&fixture, &header(Height::zero()));
        for (name, tip) in [
            ("invalid signature", invalid),
            ("genesis certificate", genesis_certificate),
        ] {
            assert!(
                verify_finalized_tip(
                    &mut context,
                    &strategy,
                    &configured_identity,
                    None,
                    Some(&tip),
                    Height::zero()
                )
                .is_err(),
                "{name} unexpectedly accepted",
            );
        }
        assert!(
            verify_finalized_tip(
                &mut context,
                &strategy,
                &configured_identity,
                None,
                None,
                Height::new(1)
            )
            .is_err()
        );
        assert!(
            verify_finalized_tip(
                &mut context,
                &strategy,
                &configured_identity,
                None,
                Some(&tip(&fixture, 1)),
                Height::new(13)
            )
            .is_err()
        );
    });
}

#[test]
fn startup_rejects_epoch_tampering() {
    Runner::default().start(|mut context| async move {
        let fixture = dkg_fixture(&mut context, Epoch::new(2));
        let configured_identity = identity(&fixture);
        let strategy = FixedEpocher::new(commonware_utils::NZU64!(10));
        let mut header = header(Height::new(22));
        header.consensus_context = Some(TempoConsensusContext {
            epoch: 2,
            view: 1,
            parent_view: 0,
            proposer: crate::utils::public_key_to_tempo_primitive(
                fixture.outcome.players().iter().next().unwrap(),
            ),
        });
        let valid = tip_for_header(&fixture, &header);
        verify_finalized_tip(
            &mut context,
            &strategy,
            &configured_identity,
            None,
            Some(&valid),
            Height::zero(),
        )
        .unwrap();

        // Changing the header's context invalidates its binding to the original
        // certificate. Keep the archive height and certificate unchanged.
        let mut altered_header = header.clone();
        altered_header.consensus_context.as_mut().unwrap().epoch = 1;
        let error = FinalizedTip::new(valid.height(), &altered_header, valid.certificate().clone())
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("header hash does not match certificate payload")
        );

        // Updating the payload to match the altered header cannot preserve the
        // signature. Nor can changing only the certificate's own epoch.
        let mut altered_payload = valid.certificate().clone();
        altered_payload.proposal.payload = Digest(altered_header.hash_slow());
        let mut altered_round = valid.certificate().clone();
        altered_round.proposal.round =
            Round::new(Epoch::new(1), altered_round.proposal.round.view());
        for (name, header, certificate) in [
            (
                "header context and payload",
                &altered_header,
                altered_payload,
            ),
            ("certificate epoch", &header, altered_round),
        ] {
            let tip = FinalizedTip::new(valid.height(), header, certificate).unwrap();
            let result = verify_finalized_tip(
                &mut context,
                &strategy,
                &configured_identity,
                None,
                Some(&tip),
                Height::zero(),
            );
            let error = result.expect_err(name);
            assert!(
                error.to_string().contains("failed verification"),
                "{name}: {error}"
            );
        }
    });
}

#[test]
#[should_panic(expected = "persisted DKG network identity differs from the configured identity")]
fn startup_rejects_conflicting_persisted_identity_even_for_a_historical_tip() {
    Runner::default().start(|mut context| async move {
        let configured_fixture = dkg_fixture(&mut context, Epoch::new(3));
        let local = dkg_fixture(&mut context, Epoch::new(3));
        let state = persisted(&local, &mut context);
        let strategy = FixedEpocher::new(commonware_utils::NZU64!(10));
        let _ = verify_finalized_tip(
            &mut context,
            &strategy,
            &identity(&configured_fixture),
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
            // and must be verified with the updated configured identity.
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

#[test]
fn tip_recovery_precedes_healing_and_epoch_entry() {
    for case in [
        "valid",
        "wrong_height",
        "wrong_hash",
        "invalid_signature",
        "closed",
    ] {
        Runner::default().start(|mut context| async move {
            let old = dkg_fixture(&mut context, Epoch::new(1));
            let current = dkg_fixture(&mut context, Epoch::new(2));
            let old_state = persisted(&old, &mut context);
            let current_state = persisted(&current, &mut context);
            let prefix = "recover_tip_before_healing";
            let tip_header = header(Height::new(22));
            let tip = tip_for_header(&current, &tip_header);
            let mut certificate = tip.certificate().clone();
            let mut recovered_header = tip_header;
            let archive_height = if case == "wrong_height" {
                tip.height().next()
            } else {
                tip.height()
            };
            if case == "wrong_hash" {
                recovered_header.inner.extra_data = vec![1].into();
            }
            if case == "invalid_signature" {
                // Header binding succeeds, but this signature uses the old key.
                certificate = tip_for_header(&old, &recovered_header)
                    .certificate()
                    .clone();
            }

            let mut harness = Harness::builder(context.child("test"), prefix)
                .initial_state(old_state.clone())
                .identity(commonware_cryptography::ed25519::PrivateKey::from_seed(
                    u64::MAX,
                ))
                .finalized_floor(Height::new(19))
                .startup(identity(&current), Some(tip))
                .build()
                .await;
            harness
                .execution
                .add_header(outcome_header(Height::new(19), &current_state));

            let (recovery_started, waiting) = tokio::sync::oneshot::channel();
            let (recovered, block_rx) = tokio::sync::oneshot::channel();
            let validation = Box::pin(FinalizedTip::recover(
                archive_height,
                certificate,
                None,
                async move {
                    recovery_started.send(()).unwrap();
                    block_rx.await.ok()
                },
            ));
            harness.start_with_tip(Some(validation)).await;
            waiting.await.unwrap();
            assert!(
                harness.execution.reads().is_empty(),
                "must not heal while the tip is missing"
            );
            assert!(
                harness.epoch_manager.events().is_empty(),
                "must not enter an epoch while the tip is missing"
            );

            // Deliver directly, without sending or acknowledging replayed blocks.
            if case == "closed" {
                drop(recovered);
            } else {
                recovered
                    .send(std::sync::Arc::new(block(recovered_header)))
                    .unwrap();
            }
            if case == "valid" {
                assert!(!harness.has_dealer_log(current_state.epoch).await);
                assert!(!harness.epoch_manager.events().is_empty());
                harness.stop().await;
                assert_eq!(harness.storage().current().output, current_state.output);
            } else {
                harness.wait_for_actor_exit().await;
                assert!(harness.epoch_manager.events().is_empty(), "{case}");
                assert!(harness.execution.reads().is_empty(), "{case}");
                let storage = state::builder()
                    .partition_prefix(prefix)
                    .init_unverified(context.child("inspect_storage"))
                    .await
                    .unwrap();
                let persisted = storage.state().unwrap();
                assert_eq!(persisted.epoch, old_state.epoch, "{case}");
                assert_eq!(persisted.output, old_state.output, "{case}");
            }
        });
    }
}
