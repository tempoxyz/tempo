//! Startup authentication uses only the configured identity and the latest persisted DKG state.

use alloy_consensus::{BlockHeader as _, Sealable as _};
use commonware_consensus::types::{Epoch, Height, Round};
use commonware_cryptography::{Signer as _, certificate::Provider as _, transcript::Summary};
use commonware_math::algebra::Random as _;
use commonware_runtime::{
    Runner as _, Supervisor as _,
    deterministic::{self, Runner},
};
use rand::{SeedableRng as _, rngs::StdRng};
use rand_core::CryptoRng;
use reth_ethereum::chainspec::EthChainSpec as _;
use tempo_chainspec::{NetworkIdentity, spec::DEV};
use tempo_primitives::TempoHeader;

use super::{
    super::state::{self, ShareState, State},
    harness::{Harness, header, outcome_header},
};
use crate::{
    consensus::Digest,
    epoch::SchemeProvider,
    gossip::Certificate,
    startup::{
        VerifiedFloor, ensure_boundary_matches_floor, verify_finalized_tip,
        verify_floor_certificate,
    },
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
        let old_state = identity(&old);
        let new_state = identity(&new);
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
        let state = identity(&new);
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
    });
}

#[test]
fn startup_accepts_a_tip_below_the_processed_floor() {
    Runner::default().start(|mut context| async move {
        let fixture = dkg_fixture(&mut context, Epoch::new(0));
        let configured_identity = identity(&fixture);
        let (height, certificate) = tip(&fixture, 1);
        let trusted = verify_finalized_tip(
            &mut context,
            &configured_identity,
            None,
            Some((height, &certificate)),
            height.next(),
            &SchemeProvider::new(),
        )
        .expect("a tip below the floor must be accepted");
        assert_eq!(trusted, configured_identity);
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
fn startup_rejects_conflicting_persisted_identity_even_for_a_historical_tip() {
    Runner::default().start(|mut context| async move {
        let configured_fixture = dkg_fixture(&mut context, Epoch::new(3));
        let local = dkg_fixture(&mut context, Epoch::new(3));
        let state = identity(&local);
        let error = verify_finalized_tip(
            &mut context,
            &identity(&configured_fixture),
            Some(&state),
            None,
            Height::zero(),
            &SchemeProvider::new(),
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "persisted DKG network identity differs from the configured identity in epoch `3`"
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

#[test]
fn historical_tip_bounds_the_startup_epoch() {
    Runner::timed(std::time::Duration::from_secs(10)).start(|mut context| async move {
        let trusted = dkg_fixture(&mut context, Epoch::new(3));
        let snapshot = dkg_fixture(&mut context, Epoch::new(5));
        let snapshot_state = persisted(&snapshot, &mut context);
        // The snapshot's floor is the boundary into epoch 5, past the trusted
        // identity's epoch 3, while its tip claims epoch 1 to skip verification.
        let tip_header = header(Height::new(52));
        let historical_tip = (
            Height::new(52),
            make_certificate(
                Digest(tip_header.hash_slow()),
                Epoch::new(1),
                1,
                &snapshot.schemes,
            ),
        );
        let mut harness = Harness::builder(context.child("test"), "historical_tip_bound")
            .finalized_floor(Height::new(49))
            .startup(identity(&trusted), Some(historical_tip))
            .build()
            .await;
        harness
            .execution
            .add_header(outcome_header(Height::new(49), &snapshot_state));
        harness.start().await;
        harness.wait_for_exit().await;
        assert!(harness.epoch_manager.events().is_empty());
        assert!(harness.scheme_provider.scheme(Epoch::new(5)).is_none());
    });
}

#[test]
fn floor_certificate_verifies_against_a_trusted_identity() {
    Runner::default().start(|mut context| async move {
        let old = dkg_fixture(&mut context, Epoch::new(1));
        let current = dkg_fixture(&mut context, Epoch::new(3));
        let (height, certificate) = tip(&current, 3);
        let verified = verify_floor_certificate(
            &mut context,
            &identity(&current),
            None,
            height,
            &certificate,
        )
        .unwrap();
        assert_eq!(verified.height, height);
        assert_eq!(verified.epoch, Epoch::new(3));
        assert_eq!(verified.digest, certificate.proposal.payload);
        assert_eq!(verified.identity, identity(&current));

        // The persisted identity's `from_epoch` is the node's latest epoch, so it may verify a
        // floor from long before it.
        let persisted = NetworkIdentity {
            from_epoch: 50,
            ..identity(&current)
        };
        let verified = verify_floor_certificate(
            &mut context,
            &identity(&old),
            Some(&persisted),
            height,
            &certificate,
        )
        .unwrap();
        assert_eq!(verified.identity, persisted);
    });
}

#[test]
fn floor_certificate_before_the_trusted_identity_is_refused() {
    Runner::default().start(|mut context| async move {
        let old = dkg_fixture(&mut context, Epoch::new(1));
        let current = dkg_fixture(&mut context, Epoch::new(3));
        let (height, certificate) = tip(&old, 1);
        let error = verify_floor_certificate(
            &mut context,
            &identity(&current),
            None,
            height,
            &certificate,
        )
        .err()
        .unwrap();
        assert_eq!(
            error.to_string(),
            "finalized floor certificate at height `12` in epoch `1` predates the trusted network \
             identity from epoch `3`; restore a snapshot taken at or after that epoch"
        );
    });
}

#[test]
fn floor_certificate_signed_by_another_identity_is_refused() {
    Runner::default().start(|mut context| async move {
        let trusted = dkg_fixture(&mut context, Epoch::new(1));
        let other = dkg_fixture(&mut context, Epoch::new(1));
        let (height, certificate) = tip(&other, 1);
        let error = verify_floor_certificate(
            &mut context,
            &identity(&trusted),
            None,
            height,
            &certificate,
        )
        .err()
        .unwrap();
        assert_eq!(
            error.to_string(),
            "finalized floor certificate at height `12` in epoch `1` failed verification against \
             every trusted network identity"
        );
    });
}

fn verified_floor(fixture: &DkgFixture, header: &TempoHeader) -> VerifiedFloor {
    VerifiedFloor {
        height: Height::new(header.number()),
        digest: Digest(header.hash_slow()),
        epoch: Epoch::new(header.number() / 10),
        identity: identity(fixture),
    }
}

#[test]
fn boundary_at_genesis_must_be_the_chain_spec_genesis() {
    let genesis = DEV.genesis_header().clone();
    let outcome = dkg_fixture(&mut StdRng::seed_from_u64(0), Epoch::zero()).outcome;
    ensure_boundary_matches_floor(Height::zero(), &genesis, &outcome, None, DEV.genesis_hash())
        .unwrap();

    let error = ensure_boundary_matches_floor(
        Height::zero(),
        &header(Height::zero()),
        &outcome,
        None,
        DEV.genesis_hash(),
    )
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "genesis header does not match the chain spec's genesis hash `{}`",
            DEV.genesis_hash()
        )
    );
}

#[test]
fn boundary_at_the_floor_must_be_the_certified_block() {
    Runner::default().start(|mut context| async move {
        let fixture = dkg_fixture(&mut context, Epoch::new(1));
        let boundary = outcome_header(Height::new(19), &persisted(&fixture, &mut context));
        let floor = verified_floor(&fixture, &boundary);
        ensure_boundary_matches_floor(
            Height::new(19),
            &boundary,
            &fixture.outcome,
            Some(&floor),
            DEV.genesis_hash(),
        )
        .unwrap();

        let error = ensure_boundary_matches_floor(
            Height::new(19),
            &header(Height::new(19)),
            &fixture.outcome,
            Some(&floor),
            DEV.genesis_hash(),
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "boundary header at height `19` does not match the finalized floor certificate"
        );
    });
}

#[test]
fn boundary_below_the_floor_must_carry_the_floor_identity() {
    Runner::default().start(|mut context| async move {
        let trusted = dkg_fixture(&mut context, Epoch::new(1));
        let forged = dkg_fixture(&mut context, Epoch::new(1));
        let later = dkg_fixture(&mut context, Epoch::new(2));
        let floor = verified_floor(&trusted, &header(Height::new(12)));
        let check = |outcome| {
            ensure_boundary_matches_floor(
                Height::new(9),
                &header(Height::new(9)),
                outcome,
                Some(&floor),
                DEV.genesis_hash(),
            )
        };

        check(&trusted.outcome).unwrap();
        assert_eq!(
            check(&forged.outcome).unwrap_err().to_string(),
            "boundary outcome at height `9` carries a network identity other than the one the \
             finalized floor certificate in epoch `1` verified against"
        );
        assert_eq!(
            check(&later.outcome).unwrap_err().to_string(),
            "boundary outcome at height `9` is for epoch `2`, but the finalized floor certificate \
             is in epoch `1`"
        );
    });
}

#[test]
fn boundary_above_the_floor_is_refused() {
    Runner::default().start(|mut context| async move {
        let trusted = dkg_fixture(&mut context, Epoch::new(1));
        let floor = verified_floor(&trusted, &header(Height::new(12)));
        let error = ensure_boundary_matches_floor(
            Height::new(19),
            &header(Height::new(19)),
            &trusted.outcome,
            Some(&floor),
            DEV.genesis_hash(),
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "boundary at height `19` is above the finalized floor certificate at height `12`"
        );
    });
}

#[test]
fn healing_refuses_a_floor_before_the_trusted_identity() {
    Runner::default().start(|mut context| async move {
        let old = dkg_fixture(&mut context, Epoch::new(1));
        let current = dkg_fixture(&mut context, Epoch::new(3));
        let mut harness = Harness::builder(context.child("test"), "floor_before_identity")
            .identity(commonware_cryptography::ed25519::PrivateKey::from_seed(
                u64::MAX,
            ))
            .finalized_floor(Height::new(12))
            .startup(identity(&current), Some(tip(&old, 1)))
            .floor_certificate(tip(&old, 1))
            .build()
            .await;
        harness.execution.add_header(outcome_header(
            Height::new(9),
            &persisted(&old, &mut context),
        ));
        harness.start().await;
        harness.wait_for_actor_exit().await;
        assert!(harness.epoch_manager.events().is_empty());
    });
}

#[test]
fn healing_trusts_a_boundary_above_an_old_floor() {
    Runner::default().start(|mut context| async move {
        // A node synced from genesis keeps its first certificate, far below its processed height.
        let old = dkg_fixture(&mut context, Epoch::new(0));
        let current = dkg_fixture(&mut context, Epoch::new(2));
        let current_state = persisted(&current, &mut context);
        let mut harness = Harness::builder(context.child("test"), "boundary_above_old_floor")
            .identity(commonware_cryptography::ed25519::PrivateKey::from_seed(
                u64::MAX,
            ))
            .finalized_floor(Height::new(22))
            .startup(identity(&current), Some(tip(&current, 2)))
            .floor_certificate(tip(&old, 0))
            .build()
            .await;
        harness
            .execution
            .add_header(outcome_header(Height::new(19), &current_state));
        for height in 20..=22 {
            harness.execution.add_header(header(Height::new(height)));
        }
        harness.start().await;
        assert!(!harness.has_dealer_log(current_state.epoch).await);
        harness.stop().await;
        assert_eq!(harness.storage().current().output, current_state.output);
    });
}

/// Builds a harness healing from the boundary at 19 with `boundary_state`'s outcome, below a
/// floor certificate at 22 signed by `current`.
async fn healing_below_floor(
    context: &mut deterministic::Context,
    current: &DkgFixture,
    boundary_state: &State,
) -> Harness {
    let mut harness = Harness::builder(context.child("test"), "floor_identity_healing")
        .identity(commonware_cryptography::ed25519::PrivateKey::from_seed(
            u64::MAX,
        ))
        .finalized_floor(Height::new(22))
        .startup(identity(current), Some(tip(current, 2)))
        .floor_certificate(tip(current, 2))
        .build()
        .await;
    harness
        .execution
        .add_header(outcome_header(Height::new(19), boundary_state));
    for height in 20..=22 {
        harness.execution.add_header(header(Height::new(height)));
    }
    harness.start().await;
    harness
}

#[test]
fn healing_accepts_the_floor_identity_below_the_floor() {
    Runner::default().start(|mut context| async move {
        let current = dkg_fixture(&mut context, Epoch::new(2));
        let boundary_state = persisted(&current, &mut context);
        let mut harness = healing_below_floor(&mut context, &current, &boundary_state).await;
        assert!(!harness.has_dealer_log(boundary_state.epoch).await);
        harness.stop().await;
        assert_eq!(harness.storage().current().output, boundary_state.output);
    });
}

#[test]
fn healing_refuses_another_identity_below_the_floor() {
    Runner::default().start(|mut context| async move {
        let current = dkg_fixture(&mut context, Epoch::new(2));
        let forged = dkg_fixture(&mut context, Epoch::new(2));
        let boundary_state = persisted(&forged, &mut context);
        let mut harness = healing_below_floor(&mut context, &current, &boundary_state).await;
        harness.wait_for_actor_exit().await;
        assert!(harness.epoch_manager.events().is_empty());
    });
}
