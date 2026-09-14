use super::super::*;
use crate::follow::test_utils::{EPOCH_LENGTH, dkg_fixture, make_block, make_finalization};
use commonware_consensus::{simplex::types::Finalization, types::Epoch};
use commonware_runtime::{Runner as _, Supervisor as _, deterministic};

#[test]
fn snapshot_tip_rejects_stale_identity_even_if_old_boundary_matched() {
    deterministic::Runner::default().start(|mut context| async move {
        let old = dkg_fixture(&mut context, Epoch::zero());
        let rotated = dkg_fixture(&mut context, Epoch::new(2));
        let strategy = FixedEpocher::new(EPOCH_LENGTH);
        let block = make_block(21, None);
        let certificate = make_finalization(&block, Epoch::new(2), &rotated.schemes);
        let stale = tempo_chainspec::NetworkIdentity {
            identity: *old.outcome.network_identity(),
            from_epoch: 0,
        };
        assert!(
            verify_tip(
                &mut context,
                &strategy,
                &stale,
                None,
                block.header(),
                Some(&certificate),
            )
            .await
            .is_err()
        );
        let updated = tempo_chainspec::NetworkIdentity {
            identity: *rotated.outcome.network_identity(),
            from_epoch: 2,
        };
        verify_tip(
            &mut context,
            &strategy,
            &updated,
            None,
            block.header(),
            Some(&certificate),
        )
        .await
        .unwrap();
    });
}

#[test]
fn boundary_tip_is_verified_with_outgoing_epoch_identity() {
    deterministic::Runner::default().start(|mut context| async move {
        let old = dkg_fixture(&mut context, Epoch::new(1));
        let rotated = dkg_fixture(&mut context, Epoch::new(2));
        let strategy = FixedEpocher::new(EPOCH_LENGTH);
        let block = make_block(19, Some(&rotated.outcome));
        let certificate = make_finalization(&block, Epoch::new(1), &old.schemes);
        let stale = tempo_chainspec::NetworkIdentity {
            identity: *old.outcome.network_identity(),
            from_epoch: 0,
        };
        verify_tip(
            &mut context,
            &strategy,
            &stale,
            None,
            block.header(),
            Some(&certificate),
        )
        .await
        .unwrap();
        let updated = tempo_chainspec::NetworkIdentity {
            identity: *rotated.outcome.network_identity(),
            from_epoch: 2,
        };
        for observed in [None, Some(&rotated.outcome), Some(&old.outcome)] {
            let result = verify_tip(
                &mut context,
                &strategy,
                &updated,
                observed,
                block.header(),
                Some(&certificate),
            )
            .await;
            assert_eq!(
                result.is_ok(),
                observed.is_some_and(|outcome| outcome.epoch == Epoch::new(1))
            );
        }
    });
}

#[test]
fn snapshot_identity_matrix() {
    deterministic::Runner::default().start(|mut context| async move {
        let old = dkg_fixture(&mut context, Epoch::zero());
        let rotated = dkg_fixture(&mut context, Epoch::new(2));
        for fixture in [&old, &rotated] {
            let outcome = &fixture.outcome;
            for (identity, from_epoch) in [
                (old.outcome.network_identity(), 0),
                (rotated.outcome.network_identity(), 2),
            ] {
                let configured = tempo_chainspec::NetworkIdentity {
                    identity: *identity,
                    from_epoch,
                };
                let strategy = FixedEpocher::new(EPOCH_LENGTH);
                let block = if outcome.epoch == Epoch::zero() {
                    make_block(0, Some(outcome))
                } else {
                    make_block(outcome.epoch.get() * EPOCH_LENGTH.get() + 1, None)
                };
                let certificate = (outcome.epoch != Epoch::zero())
                    .then(|| make_finalization(&block, outcome.epoch, &fixture.schemes));
                let result = verify_tip(
                    &mut context,
                    &strategy,
                    &configured,
                    None,
                    block.header(),
                    certificate.as_ref(),
                )
                .await;
                let should_pass =
                    outcome.epoch.get() >= from_epoch && outcome.network_identity() == identity;
                assert_eq!(
                    result.is_ok(),
                    should_pass,
                    "epoch {}, configured from {from_epoch}",
                    outcome.epoch
                );
            }
        }
    });
}

#[test]
fn observed_identity_does_not_fall_back_to_configured_identity() {
    deterministic::Runner::default().start(|mut context| async move {
        let configured = dkg_fixture(&mut context, Epoch::zero());
        let observed = dkg_fixture(&mut context, Epoch::new(2));
        let block = make_block(21, None);
        let certificate = make_finalization(&block, Epoch::new(2), &configured.schemes);
        let result = verify_tip(
            &mut context,
            &FixedEpocher::new(EPOCH_LENGTH),
            &tempo_chainspec::NetworkIdentity {
                from_epoch: 0,
                identity: *configured.outcome.network_identity(),
            },
            Some(&observed.outcome),
            block.header(),
            Some(&certificate),
        )
        .await;
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("failed verification")
        );
    });
}

#[test]
fn observed_identity_still_requires_matching_tip_digest() {
    deterministic::Runner::default().start(|mut context| async move {
        let fixture = dkg_fixture(&mut context, Epoch::new(1));
        let block = make_block(11, None);
        let other_block = make_block(12, None);
        let certificate = make_finalization(&other_block, Epoch::new(1), &fixture.schemes);
        let result = verify_tip(
            &mut context,
            &FixedEpocher::new(EPOCH_LENGTH),
            &tempo_chainspec::NetworkIdentity {
                from_epoch: 2,
                identity: *fixture.outcome.network_identity(),
            },
            Some(&fixture.outcome),
            block.header(),
            Some(&certificate),
        )
        .await;
        assert!(result.unwrap_err().to_string().contains("digest mismatch"));
    });
}

async fn verify_tip(
    context: &mut deterministic::Context,
    epoch_strategy: &FixedEpocher,
    network_identity: &tempo_chainspec::NetworkIdentity,
    observed_outcome: Option<&OnchainDkgOutcome>,
    header: &TempoHeader,
    certificate: Option<&Finalization<Scheme<PublicKey, MinSig>, Digest>>,
) -> eyre::Result<()> {
    use super::harness::{StubEpochManager, StubExecutionProvider, StubMarshal};

    let label = rand_core::Rng::next_u64(context);
    let (mut actor, _mailbox) = super::super::super::init(
        context.child("verification").with_attribute("case", label),
        super::super::super::Config {
            epoch_strategy: epoch_strategy.clone(),
            epoch_manager: StubEpochManager::default(),
            namespace: crate::config::NAMESPACE.to_vec(),
            me: PrivateKey::from_seed(0),
            mailbox_size: std::num::NonZeroUsize::new(1).unwrap(),
            marshal: StubMarshal::default(),
            finalized_floor: Height::new(header.number()),
            finalized_tip: crate::alias::marshal::FinalizedTip {
                header: header.clone(),
                certificate: certificate.cloned(),
            },
            network_identity: network_identity.clone(),
            partition_prefix: "startup_verification".into(),
            execution_node: StubExecutionProvider::default(),
            initial_share: None,
        },
    )
    .await?;
    let initial = super::harness::dkg_state(context, Epoch::zero(), 4, false).0;
    let mut storage = state::builder()
        .partition_prefix(&format!("verification_{label}"))
        .init_unverified(context.child("storage").with_attribute("case", label))
        .await?
        .init_verified(initial)
        .await;
    if let Some(outcome) = observed_outcome {
        storage
            .set_state(State {
                epoch: outcome.epoch,
                seed: Summary::random(&mut *context),
                output: outcome.output.clone(),
                share: ShareState::unset_plaintext(),
                players: outcome.next_players.clone(),
                is_full_dkg: outcome.is_next_full_dkg,
            })
            .await;
    }
    actor.verify_finalized_tip(&storage)
}
