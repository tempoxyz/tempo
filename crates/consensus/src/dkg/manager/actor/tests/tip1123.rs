//! TIP-1123 boundary configuration, activation, and recovery invariants.

use commonware_consensus::Reporter as _;
use tempo_chainspec::NetworkIdentity;

use super::*;
use crate::test_utils::{dkg_fixture, make_certificate};

fn compact_header(height: u64, timestamp: u64, state: &State) -> TempoHeader {
    let mut header = outcome_header(Height::new(height), state);
    let mut outcome =
        OnchainDkgOutcome::decode_boundary(header.extra_data().as_ref(), &TempoHardfork::T13)
            .unwrap();
    outcome.legacy_config = None;
    header.inner.extra_data = outcome.encode().into();
    header.inner.timestamp = timestamp;
    header
}

#[test]
fn configuration_uses_boundary_post_state_and_survives_restart() {
    for is_full in [false, true] {
        Runner::default().start(|mut context| async move {
            let (state, _, _) = dkg_state(&mut context, Epoch::new(1), 4, false);
            let (changed, _, _) = dkg_state(&mut context, Epoch::new(2), 5, false);
            let boundary = compact_header(9, 10, &state);
            let after = header(Height::new(10));
            let prior = dkg_fixture(&mut context, Epoch::zero());
            let mut harness = Harness::builder(context.child("test"), "tip1123_restart")
                .identity(PrivateKey::from_seed(u64::MAX))
                .startup(
                    NetworkIdentity {
                        from_epoch: state.epoch.get(),
                        identity: *state.output.public().public(),
                    },
                    Some((
                        Height::new(9),
                        make_certificate(
                            Digest(boundary.hash_slow()),
                            Epoch::zero(),
                            1,
                            &prior.schemes,
                        ),
                    )),
                )
                .build()
                .await;
            harness.execution.set_tip1123_activation(10);
            harness.execution.set_configuration(
                &boundary,
                changed.players.clone(),
                if is_full { 1 } else { 2 },
            );
            harness
                .execution
                .set_configuration(&after, state.players.clone(), 1);
            harness.execution.add_header(boundary.clone());
            harness.start().await;
            assert!(!harness.has_dealer_log(state.epoch).await);
            harness.stop().await;
            let persisted = harness.storage().current();
            assert_eq!(persisted.players, changed.players);
            assert_eq!(persisted.is_full_dkg, is_full);
            assert_eq!(
                harness.execution.configuration_reads(),
                vec![Digest(boundary.hash_slow()); 2]
            );

            // Later configuration changes and unavailable execution state cannot reconfigure
            // an already initialized ceremony on restart.
            harness.execution.fail_next_players();
            harness.execution.fail_next_full_dkg_epoch();
            harness.start().await;
            assert!(!harness.has_dealer_log(state.epoch).await);
            harness.stop().await;
            assert_eq!(harness.storage().current().players, changed.players);
            assert_eq!(harness.storage().current().is_full_dkg, is_full);
            assert_eq!(
                harness.execution.configuration_reads(),
                vec![Digest(boundary.hash_slow()); 2]
            );
        });
    }
}

#[test]
fn compact_outcome_does_not_read_execution_configuration() {
    Runner::default().start(|context| async move {
        let mut harness = Harness::builder(context.child("test"), "tip1123_outcome")
            .initial_epoch(1)
            .build()
            .await;
        let state = harness.initial_state().clone();
        harness.execution.fail_next_players();
        harness.execution.fail_next_full_dkg_epoch();
        harness.start().await;
        for height in 10..=11 {
            harness
                .report_finalized_header(header(Height::new(height)))
                .await;
        }
        for _ in 0..2 {
            let outcome = harness
                .mailbox()
                .get_dkg_outcome(
                    Digest(B256::repeat_byte(1)),
                    Height::new(10),
                    TempoHardfork::Tip1123,
                )
                .await
                .unwrap();
            assert_eq!(outcome.output, state.output);
            assert_eq!(outcome.epoch, state.epoch.next().get());
            assert_eq!(outcome.legacy_config, None);
        }
        assert!(harness.execution.configuration_reads().is_empty());
    });
}

#[test]
fn configuration_read_failures_prevent_epoch_initialization() {
    for fail_players in [false, true] {
        Runner::default().start(|mut context| async move {
            let (state, _, _) = dkg_state(&mut context, Epoch::new(1), 4, false);
            let boundary = compact_header(9, 10, &state);
            let mut harness = Harness::builder(context.child("test"), "tip1123_missing_state")
                .identity(PrivateKey::from_seed(u64::MAX))
                .build()
                .await;
            harness.execution.set_tip1123_activation(10);
            harness
                .execution
                .set_configuration(&boundary, state.players.clone(), 1);
            harness.execution.add_header(boundary);
            if fail_players {
                harness.execution.fail_next_players();
            } else {
                harness.execution.fail_next_full_dkg_epoch();
            }
            harness.start().await;
            harness.wait_for_exit().await;
            assert!(harness.epoch_manager.events().is_empty());
        });
    }
}

#[test]
fn activation_uses_each_boundary_including_genesis() {
    Runner::default().start(|mut context| async move {
        for activation in [0, 10, 15] {
            let mut execution = StubExecutionProvider::default();
            execution.set_tip1123_activation(activation);
            let marshal = harness::StubMarshal::default();
            for (height, timestamp, epoch) in [(0, 0, 0), (9, 10, 1), (19, 20, 2)] {
                let (state, _, _) = dkg_state(&mut context, Epoch::new(epoch), 4, false);
                let mut boundary = if timestamp >= activation {
                    compact_header(height, timestamp, &state)
                } else {
                    outcome_header(Height::new(height), &state)
                };
                boundary.inner.timestamp = timestamp;
                execution.set_configuration(&boundary, state.players.clone(), epoch);
                execution.add_header(boundary);
                let (outcome, config) =
                    read_outcome_from_boundary(&context, &execution, &marshal, Height::new(height))
                        .await
                        .unwrap();
                assert_eq!(outcome.legacy_config.is_none(), timestamp >= activation);
                assert_eq!(config.is_next_full_dkg, timestamp >= activation);
                assert_eq!(config.next_players, state.players);
            }
        }
    });
}

#[test]
fn revealed_share_recovery_uses_historical_boundary_configuration() {
    Runner::default().start(|mut context| async move {
        let fixture = revealed_recovery_fixture(&mut context, Epoch::new(1), true);
        let mut harness = Harness::builder(context.child("test"), "tip1123_recovery")
            .identity(fixture.identity.clone())
            .finalized_floor(Height::new(19))
            .build()
            .await;
        fixture.populate_execution(&harness.execution, &harness.epoch_strategy);
        harness.execution.set_tip1123_activation(0);
        for (height, state) in [(9, &fixture.ceremony_state), (19, &fixture.recovered_state)] {
            let boundary = compact_header(height, height, state);
            harness.execution.set_configuration(
                &boundary,
                state.players.clone(),
                if state.is_full_dkg {
                    state.epoch.get()
                } else {
                    u64::MAX
                },
            );
            harness.execution.add_header(boundary);
        }
        harness.start().await;
        assert!(!harness.has_dealer_log(fixture.recovered_state.epoch).await);
        harness.stop().await;
        assert_eq!(
            harness.storage().current().share.into_inner(),
            Some(fixture.recovered_share)
        );
        assert_eq!(harness.execution.configuration_reads().len(), 4);
        assert_ne!(
            harness.execution.configuration_reads()[0],
            harness.execution.configuration_reads()[2]
        );
    });
}

#[test]
fn mid_epoch_activation_waits_for_finalized_boundary_to_reconfigure() {
    Runner::default().start(|mut context| async move {
        let mut harness = Harness::builder(context.child("test"), "tip1123_transition")
            .initial_epoch(0)
            .finalized_floor(Height::zero())
            .identity(PrivateKey::from_seed(u64::MAX))
            .build()
            .await;
        let state = harness.initial_state().clone();
        let (changed, _, _) = dkg_state(&mut context, Epoch::new(1), 5, true);
        let mut next = state.clone();
        next.epoch = state.epoch.next();
        let boundary = compact_header(9, 10, &next);
        harness.execution.set_tip1123_activation(5);
        harness
            .execution
            .set_configuration(&boundary, changed.players.clone(), 1);
        harness.execution.add_header(boundary.clone());
        harness.start().await;
        for height in 1..9 {
            let mut header = header(Height::new(height));
            header.inner.timestamp = height;
            harness.report_finalized_header(header).await;
        }
        assert!(!harness.has_dealer_log(Epoch::zero()).await);
        assert!(harness.execution.configuration_reads().is_empty());
        harness.report_finalized_header(boundary.clone()).await;
        assert!(!harness.has_dealer_log(Epoch::new(1)).await);
        harness.stop().await;
        let entered = harness.storage().current();
        assert_eq!(entered.epoch, Epoch::new(1));
        assert_eq!(entered.players, changed.players);
        assert!(entered.is_full_dkg);
        assert_eq!(
            harness.execution.configuration_reads(),
            vec![Digest(boundary.hash_slow()); 2]
        );
    });
}

#[test]
fn epoch_entry_waits_for_boundary_execution_without_blocking_mailbox() {
    Runner::default().start(|context| async move {
        let mut harness = Harness::builder(context.child("test"), "tip1123_execution_lag")
            .initial_epoch(0)
            .finalized_floor(Height::zero())
            .identity(PrivateKey::from_seed(u64::MAX))
            .build()
            .await;
        let mut next = harness.initial_state().clone();
        next.epoch = Epoch::new(1);
        let boundary = compact_header(9, 10, &next);
        harness.execution.set_tip1123_activation(5);
        harness
            .execution
            .set_configuration(&boundary, next.players.clone(), 1);
        harness.start().await;
        assert!(!harness.has_dealer_log(Epoch::zero()).await);

        // Marshal has finalized the boundary, but execution has not imported it yet.
        let (ack, waiter) = Exact::handle();
        assert!(
            harness
                .mailbox()
                .clone()
                .report(Update::Block(Arc::new(block(boundary.clone())), ack))
                .accepted()
        );
        context.sleep(Duration::from_millis(200)).await;
        assert!(harness.execution.configuration_reads().is_empty());
        assert!(!harness.has_dealer_log(Epoch::zero()).await);
        assert_eq!(harness.epoch_manager.events().len(), 1);

        harness.execution.add_header(boundary.clone());
        waiter.await.unwrap();
        assert!(!harness.has_dealer_log(Epoch::new(1)).await);
        harness.stop().await;
        assert_eq!(harness.storage().current().epoch, Epoch::new(1));
        assert!(harness.storage().current().is_full_dkg);
        assert_eq!(
            harness.execution.configuration_reads(),
            vec![Digest(boundary.hash_slow()); 2],
        );
    });
}
