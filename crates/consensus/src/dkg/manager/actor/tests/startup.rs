//! Startup authentication uses only the configured identity and the latest persisted DKG state.

use alloy_consensus::{BlockHeader as _, Sealable as _};
use commonware_consensus::types::{Epoch, Height, Round};
use commonware_cryptography::{Signer as _, certificate::Provider as _, transcript::Summary};
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
    consensus::Digest,
    epoch::SchemeProvider,
    gossip::Certificate,
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

fn tip(fixture: &DkgFixture, epoch: u64) -> (Height, Certificate) {
    tip_for_header(fixture, &header(Height::new(epoch * 10 + 2)))
}

fn tip_for_header(fixture: &DkgFixture, header: &TempoHeader) -> (Height, Certificate) {
    (
        Height::new(header.number()),
        make_certificate(
            Digest(header.hash_slow()),
            Epoch::new(header.number() / 10),
            1,
            &fixture.schemes,
        ),
    )
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
        for (name, configured_identity, state, tip, expected) in [
            (
                "configured identity",
                identity(&new),
                None,
                &new_tip,
                Some(identity(&new)),
            ),
            (
                "same key in a later epoch",
                identity(&old),
                None,
                &old_tip,
                Some(identity(&old)),
            ),
            (
                "unknown rotation without local state",
                identity(&old),
                None,
                &new_tip,
                None,
            ),
            (
                "newer local state",
                identity(&old),
                Some(&new_state),
                &new_tip,
                Some(identity(&new)),
            ),
            (
                "newer configured identity",
                identity(&new),
                Some(&old_state),
                &new_tip,
                Some(identity(&new)),
            ),
            (
                "matching configured identity and local state",
                identity(&new),
                Some(&new_state),
                &new_tip,
                Some(identity(&new)),
            ),
            (
                "stale local state cannot authenticate rotation",
                identity(&old),
                Some(&old_state),
                &new_tip,
                None,
            ),
            (
                "no fallback to old configured identity",
                identity(&old),
                Some(&new_state),
                &old_tip,
                None,
            ),
            (
                "no fallback to old local state",
                identity(&new),
                Some(&old_state),
                &old_tip,
                None,
            ),
            (
                "reshare after persisted epoch",
                identity(&old),
                Some(&new_state),
                &reshared_tip,
                Some(identity(&new)),
            ),
        ] {
            let provider = SchemeProvider::new();
            let result = verify_finalized_tip(
                &mut context,
                &configured_identity,
                state,
                Some((tip.0, &tip.1)),
                Height::zero(),
                &provider,
            );
            assert_eq!(result.is_ok(), expected.is_some(), "{name}: {result:?}");
            if let Some(expected) = expected {
                for epoch in [
                    Epoch::new(expected.from_epoch),
                    tip.1.proposal.round.epoch(),
                ] {
                    assert_eq!(
                        provider.scheme(epoch).unwrap().identity(),
                        &expected.identity,
                        "{name}"
                    );
                }
            } else {
                assert!(
                    provider.scheme(tip.1.proposal.round.epoch()).is_none(),
                    "{name}"
                );
            }
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
        for (configured_identity, local) in [
            (identity(&new), None),
            (identity(&old), Some(&state)),
            (identity(&new), Some(&state)),
        ] {
            for tip in [None, Some((boundary_tip.0, &boundary_tip.1))] {
                for existing_historical_scheme in [false, true] {
                    let provider = SchemeProvider::new();
                    if existing_historical_scheme {
                        provider.register(Epoch::new(2), old.schemes[0].clone());
                    }
                    verify_finalized_tip(
                        &mut context,
                        &configured_identity,
                        local,
                        tip,
                        tip.map_or(Height::zero(), |(height, _)| height),
                        &provider,
                    )
                    .unwrap();
                    assert_eq!(
                        provider.scheme(Epoch::new(3)).unwrap().identity(),
                        new.outcome.network_identity(),
                    );
                    assert_eq!(
                        provider
                            .scheme(Epoch::new(2))
                            .map(|scheme| *scheme.identity()),
                        existing_historical_scheme.then_some(*old.outcome.network_identity()),
                    );
                }
            }
        }
    });
}

#[test]
fn startup_rejects_malformed_or_invalid_tip_certificates() {
    Runner::default().start(|mut context| async move {
        let fixture = dkg_fixture(&mut context, Epoch::new(0));
        let configured_identity = identity(&fixture);
        let valid = tip(&fixture, 1);
        let mut altered_header = header(valid.0);
        altered_header.inner.extra_data = vec![1].into();
        let mut invalid_certificate = valid.1.clone();
        invalid_certificate.proposal.payload = Digest(altered_header.hash_slow());
        // The signature still covers the original payload.
        let invalid = (valid.0, invalid_certificate);
        let genesis_certificate = tip_for_header(&fixture, &header(Height::zero()));
        for (name, tip) in [
            ("invalid signature", invalid),
            ("genesis certificate", genesis_certificate),
        ] {
            assert!(
                verify_finalized_tip(
                    &mut context,
                    &configured_identity,
                    None,
                    Some((tip.0, &tip.1)),
                    Height::zero(),
                    &SchemeProvider::new(),
                )
                .is_err(),
                "{name} unexpectedly accepted",
            );
        }
        assert!(
            verify_finalized_tip(
                &mut context,
                &configured_identity,
                None,
                None,
                Height::new(1),
                &SchemeProvider::new(),
            )
            .is_err()
        );
        assert!(
            verify_finalized_tip(
                &mut context,
                &configured_identity,
                None,
                Some((valid.0, &valid.1)),
                Height::new(13),
                &SchemeProvider::new(),
            )
            .is_err()
        );
    });
}

#[test]
fn startup_uses_certificate_epoch_for_verification() {
    Runner::default().start(|mut context| async move {
        let old = dkg_fixture(&mut context, Epoch::new(1));
        let current = dkg_fixture(&mut context, Epoch::new(2));
        let configured_identity = identity(&current);
        let historical = tip(&old, 1).1;
        let valid = tip(&current, 2).1;
        let invalid = tip(&old, 2).1;

        // The archive height must not decide whether a certificate needs verification.
        for height in [Height::new(12), Height::new(32)] {
            for (certificate, accepted) in [(&historical, true), (&valid, true), (&invalid, false)]
            {
                let provider = SchemeProvider::new();
                let result = verify_finalized_tip(
                    &mut context,
                    &configured_identity,
                    None,
                    Some((height, certificate)),
                    Height::zero(),
                    &provider,
                );
                assert_eq!(result.is_ok(), accepted, "height {height}: {result:?}");
                if accepted {
                    assert_eq!(
                        provider.scheme(Epoch::new(2)).unwrap().identity(),
                        &configured_identity.identity,
                    );
                } else {
                    assert!(provider.scheme(Epoch::new(2)).is_none());
                }
                assert!(provider.scheme(Epoch::new(1)).is_none());
                assert!(provider.scheme(Epoch::new(3)).is_none());
            }
        }
    });
}

#[test]
fn startup_rejects_epoch_tampering_at_or_after_identity_epoch() {
    Runner::default().start(|mut context| async move {
        let fixture = dkg_fixture(&mut context, Epoch::new(2));
        let configured_identity = identity(&fixture);
        let (height, mut certificate) = tip(&fixture, 2);
        certificate.proposal.round = Round::new(Epoch::new(3), certificate.proposal.round.view());
        let error = verify_finalized_tip(
            &mut context,
            &configured_identity,
            None,
            Some((height, &certificate)),
            Height::zero(),
            &SchemeProvider::new(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("failed verification"), "{error}");
    });
}

#[test]
#[should_panic(expected = "persisted DKG network identity differs from the configured identity")]
fn startup_rejects_conflicting_persisted_identity_even_for_a_historical_tip() {
    Runner::default().start(|mut context| async move {
        let configured_fixture = dkg_fixture(&mut context, Epoch::new(3));
        let local = dkg_fixture(&mut context, Epoch::new(3));
        let state = persisted(&local, &mut context);
        let _ = verify_finalized_tip(
            &mut context,
            &identity(&configured_fixture),
            Some(&state),
            None,
            Height::zero(),
            &SchemeProvider::new(),
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
            // A scheme loaded from the snapshot cannot authenticate that snapshot.
            harness
                .scheme_provider
                .register(Epoch::new(2), snapshot.schemes[0].clone());
            let error = harness
                .init()
                .await
                .err()
                .expect("invalid tip must fail initialization");
            assert!(format!("{error:#}").contains("failed verification"));
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
        assert_eq!(harness.execution.reads(), vec![Height::new(19); 3]);
    });
}

#[test]
fn missing_tip_is_authenticated_and_registered_before_actors_start() {
    Runner::timed(std::time::Duration::from_secs(10)).start(|mut context| async move {
        let old = dkg_fixture(&mut context, Epoch::new(1));
        let current = dkg_fixture(&mut context, Epoch::new(3));
        let current_state = persisted(&current, &mut context);
        let mut harness = Harness::builder(context.child("test"), "init_without_tip_header")
            .initial_state(persisted(&old, &mut context))
            .identity(commonware_cryptography::ed25519::PrivateKey::from_seed(
                u64::MAX,
            ))
            .finalized_floor(Height::new(29))
            .startup(identity(&current), Some(tip(&current, 4)))
            .build()
            .await;

        // Neither the execution layer nor marshal has the tip block. Initialization
        // authenticates its certificate and pins both the identity and tip epochs.
        let (actor, mailbox) = harness.init().await.unwrap();
        for epoch in [Epoch::new(3), Epoch::new(4)] {
            assert_eq!(
                harness.scheme_provider.scheme(epoch).unwrap().identity(),
                current.outcome.network_identity(),
            );
        }
        assert!(harness.execution.reads().is_empty());
        assert!(harness.marshal.reads().is_empty());
        assert!(harness.epoch_manager.events().is_empty());
        drop((actor, mailbox));

        // Healing and epoch entry need only the boundary at the floor, not the tip.
        harness
            .execution
            .add_header(outcome_header(Height::new(29), &current_state));
        harness.start().await;
        assert!(!harness.has_dealer_log(current_state.epoch).await);
        assert!(!harness.epoch_manager.events().is_empty());
        assert_eq!(harness.execution.reads(), vec![Height::new(29); 3]);
        assert!(harness.marshal.reads().is_empty());
        harness.stop().await;
        assert_eq!(harness.storage().current().output, current_state.output);
    });
}
