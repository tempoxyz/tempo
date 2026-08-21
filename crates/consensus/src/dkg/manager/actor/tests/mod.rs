//! Standalone DKG manager actor tests.

mod utils;

use std::time::Duration;

use alloy_primitives::B256;
use commonware_consensus::types::{Epoch, Height};
use commonware_cryptography::ed25519::PrivateKey;
use commonware_runtime::{Runner as _, Supervisor as _, deterministic::Runner};
use futures::channel::oneshot;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;

use super::*;
use utils::{
    EpochEvent, Harness, StubExecutionProvider, TestNetwork, acked_recovery_fixture, block,
    dkg_state, header, outcome_header,
};

#[test]
fn exhausted_ancestry_releases_pending_outcome_request() {
    Runner::default().start(|_| async move {
        let (response, receiver) = oneshot::channel();
        let request = GetDkgOutcome {
            digest: Digest(B256::repeat_byte(1)),
            height: Height::new(1),
            response,
        };
        let mut ancestry = AncestorStream::new();
        ancestry.set((tracing::Span::none(), request), futures::stream::empty());

        assert!(ancestry.next().await.is_none());
        assert!(
            matches!(receiver.now_or_never(), Some(Err(_))),
            "an exhausted ancestry stream must fail its pending outcome request"
        );
    });
}

#[test]
fn actor_fails_outcome_request_when_ancestry_is_exhausted() {
    Runner::default().start(|mut context| async move {
        let (state, _) = dkg_state(&mut context, Epoch::new(1), 4, true);
        let mut harness = Harness::new(context.child("test"), "exhausted_ancestry").await;
        harness.execution.set_next_players(state.players().clone());
        harness
            .execution
            .add_header(outcome_header(Height::new(9), &state));

        harness.marshal.return_empty_ancestry();

        harness.start().await;

        harness
            .report_finalized_header(header(Height::new(10)))
            .await;
        harness
            .report_finalized_header(header(Height::new(11)))
            .await;

        let request_mailbox = harness.mailbox().clone();
        let response = context
            .timeout(Duration::from_secs(1), async move {
                request_mailbox
                    .get_dkg_outcome(Digest(B256::repeat_byte(1)), Height::new(11))
                    .await
            })
            .await
            .expect("an exhausted ancestry stream must not leave the outcome request pending");

        assert!(response.is_err());
    });
}

#[test]
fn healing_discards_stale_state_on_startup() {
    Runner::default().start(|mut context| async move {
        let (current_state, _) = dkg_state(&mut context, Epoch::new(1).next(), 4, false);
        let mut harness =
            Harness::with_initial_state(context.child("test"), "healing_discards_stale_state", 1)
                .await
                // Exercise stale-state replacement as an observer, without
                // recovering a share from the previous epoch.
                .with_me(PrivateKey::from_seed(u64::MAX))
                .with_last_finalized_height(Height::new(19));
        let stale_state = harness.initial_state().clone();

        harness
            .execution
            .add_header(outcome_header(Height::new(19), &current_state));

        harness.start().await;

        // A mailbox round-trip ensures startup healing and epoch entry have completed.
        assert!(!harness.has_dealer_log(current_state.epoch).await);

        assert_ne!(current_state.output, stale_state.output);
        assert_eq!(
            harness.epoch_manager.events(),
            vec![EpochEvent::Enter {
                epoch: current_state.epoch,
                public: current_state.output.public().clone(),
                share: None,
                participants: current_state.dealers().clone(),
            }]
        );
        assert_eq!(
            harness.execution.reads(),
            vec![Height::new(19)],
            "healing should replace stale state from the latest boundary"
        );
    });
}

#[test]
fn healing_recovers_an_acked_share_from_persisted_dealings() {
    Runner::default().start(|mut context| async move {
        let epoch_strategy = Harness::epoch_strategy();
        let ceremony_epoch = Epoch::new(1);
        let execution = StubExecutionProvider::default();

        let fixture =
            acked_recovery_fixture(&mut context, &execution, &epoch_strategy, ceremony_epoch);

        let mut harness = Harness::from_state(
            context.child("test"),
            "healing_recovers_persisted_dealings",
            fixture.ceremony_state.clone(),
        )
        .await
        .with_execution(execution)
        .with_me(fixture.local_key.clone())
        .with_last_finalized_height(epoch_strategy.last(ceremony_epoch).unwrap());

        let round = Round::from_state(&fixture.ceremony_state, crate::config::NAMESPACE);
        let persisted = harness.storage_mut();
        let mut player = persisted
            .create_player_for_round(fixture.local_key.clone(), &round)
            .unwrap()
            .unwrap();

        let (dealer, public_message, private_message) = &fixture.local_dealing;
        player
            .receive_dealing(
                persisted,
                round.epoch(),
                dealer.clone(),
                public_message.clone(),
                private_message.clone(),
            )
            .await
            .unwrap();

        drop(player);

        harness.start().await;

        // A mailbox round-trip ensures startup recovery and epoch entry have completed.
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

#[test]
fn healing_skips_reading_previous_epoch_after_a_failed_ceremony() {
    Runner::default().start(|mut context| async move {
        let epoch_strategy = Harness::epoch_strategy();
        let ceremony_epoch = Epoch::new(1);
        let (ceremony_state, keys) = dkg_state(&mut context, ceremony_epoch, 1, true);
        let mut carried_state = ceremony_state.clone();
        carried_state.epoch = ceremony_epoch.next();
        carried_state.is_full_dkg = false;

        let last_finalized_height = epoch_strategy.last(ceremony_epoch).unwrap();
        let mut harness = Harness::from_state(
            context.child("test"),
            "healing_skips_failed_ceremony",
            ceremony_state.clone(),
        )
        .await
        .with_me(keys[0].clone())
        .with_last_finalized_height(last_finalized_height);

        let ceremony_boundary = epoch_strategy
            .last(ceremony_epoch.previous().unwrap())
            .unwrap();

        harness
            .execution
            .add_header(outcome_header(ceremony_boundary, &ceremony_state));

        harness
            .execution
            .add_header(outcome_header(last_finalized_height, &carried_state));

        harness.start().await;

        assert!(!harness.has_dealer_log(carried_state.epoch).await);
        assert_eq!(
            harness.epoch_manager.events(),
            vec![EpochEvent::Enter {
                epoch: carried_state.epoch,
                public: carried_state.output.public().clone(),
                share: None,
                participants: carried_state.dealers().clone(),
            }]
        );
        assert_eq!(
            harness.execution.reads(),
            vec![last_finalized_height, ceremony_boundary],
            "a carried-forward output must skip dealer-log recovery"
        );
    });
}

#[test]
fn healing_prepopulates_to_a_non_boundary_finalized_floor() {
    Runner::default().start(|mut context| async move {
        let epoch_strategy = Harness::epoch_strategy();
        let (current_state, _) = dkg_state(&mut context, Epoch::new(1).next(), 4, false);
        let boundary = epoch_strategy.last(Epoch::new(1)).unwrap();
        let first = epoch_strategy.first(Epoch::new(1).next()).unwrap();
        let prepopulation_heights = (0..3)
            .map(|offset| Height::new(first.get() + offset))
            .collect::<Vec<_>>();
        let last_finalized_height = *prepopulation_heights.last().unwrap();

        let mut harness = Harness::with_initial_state(
            context.child("test"),
            "healing_prepopulates_non_boundary_floor",
            1,
        )
        .await
        .with_me(PrivateKey::from_seed(u64::MAX))
        .with_last_finalized_height(last_finalized_height);

        harness
            .execution
            .add_header(outcome_header(boundary, &current_state));

        for height in &prepopulation_heights {
            harness.execution.add_header(header(*height));
        }

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

        let mut expected_reads = vec![boundary];
        expected_reads.extend(prepopulation_heights);
        assert_eq!(harness.execution.reads(), expected_reads);
    });
}

#[test]
fn prepopulation_replays_only_missing_headers() {
    Runner::default().start(|context| async move {
        let mut harness =
            Harness::with_initial_state(context.child("test"), "prepopulation_missing_range", 1)
                .await
                .with_last_finalized_height(Height::new(12));

        let initial_epoch = harness.initial_state().epoch;
        harness.execution.add_header(header(Height::new(10)));
        harness.execution.add_header(header(Height::new(11)));
        harness.marshal.add_block(block(header(Height::new(12))));

        harness.start().await;

        assert!(!harness.has_dealer_log(initial_epoch).await);
        harness.stop().await;

        assert_eq!(
            harness
                .storage()
                .get_latest_finalized_block_for_epoch(&Epoch::new(1))
                .map(|(height, _)| *height),
            Some(Height::new(12))
        );
        assert_eq!(
            harness.execution.reads(),
            vec![Height::new(10), Height::new(11), Height::new(12)]
        );
        assert_eq!(harness.marshal.reads(), vec![Height::new(12)]);

        harness.start().await;
        assert!(!harness.has_dealer_log(initial_epoch).await);

        assert_eq!(
            harness.execution.reads(),
            vec![Height::new(10), Height::new(11), Height::new(12)],
            "already-populated headers must not be read again"
        );
    });
}

#[test]
fn prepopulation_skips_replay_when_dkg_state_is_ahead() {
    Runner::default().start(|context| async move {
        let mut harness =
            Harness::with_initial_state(context.child("test"), "prepopulation_ahead", 1)
                .await
                .with_last_finalized_height(Height::new(8));

        let state = harness.initial_state().clone();

        harness.start().await;

        assert!(!harness.has_dealer_log(state.epoch).await);

        // Harness populates initial state for Epoch 1. Thus nothing to read for Epoch 0.
        assert!(harness.execution.reads().is_empty());
        assert!(harness.marshal.reads().is_empty());
        assert_eq!(
            harness.epoch_manager.events(),
            vec![EpochEvent::Enter {
                epoch: state.epoch,
                public: state.output.public().clone(),
                share: None,
                participants: state.dealers().clone(),
            }]
        );
    });
}

#[test]
fn prepopulation_fails_when_required_header_is_unavailable() {
    Runner::default().start(|context| async move {
        let mut harness =
            Harness::with_initial_state(context.child("test"), "prepopulation_missing_header", 1)
                .await
                .with_last_finalized_height(Height::new(10));

        harness.start().await;

        // Since storage has no finalized headers for epoch 1, it tries to read [10] which fails
        harness.wait_for_exit().await;

        assert_eq!(harness.execution.reads(), vec![Height::new(10)]);
    });
}

#[test]
fn epoch_shares_only_distributed_in_the_first_half() {
    Runner::default().start(|mut context| async move {
        let (state, _) = dkg_state(&mut context, Epoch::new(1), 4, true);

        let mut harness = Harness::new(context.child("test"), "epoch_shares_distributed").await;
        harness
            .execution
            .add_header(outcome_header(Height::new(9), &state));

        harness.start().await;

        // A mailbox round-trip ensures the actor has entered the epoch before
        // finalized blocks are delivered.
        assert!(!harness.has_dealer_log(state.epoch).await);
        assert_eq!(
            harness.epoch_manager.events(),
            vec![EpochEvent::Enter {
                epoch: state.epoch,
                public: state.output.public().clone(),
                share: None,
                participants: state.dealers().clone(),
            }]
        );

        harness
            .report_finalized_header(header(Height::new(10)))
            .await;

        assert!(!harness.has_dealer_log(state.epoch).await);
        assert_eq!(harness.sender().send_count(), state.players().len() - 1);

        harness
            .report_finalized_header(header(Height::new(15)))
            .await;

        assert!(harness.has_dealer_log(state.epoch).await);

        harness
            .report_finalized_header(header(Height::new(16)))
            .await;

        assert_eq!(
            harness.sender().send_count(),
            state.players().len() - 1,
            "midpoint and late blocks must not redistribute shares"
        );

        let next_state = OnchainDkgOutcome {
            epoch: state.epoch.next(),
            output: state.output.clone(),
            next_players: state.players().clone(),
            is_next_full_dkg: false,
        };

        let mut boundary = header(Height::new(19));
        boundary.inner.extra_data = next_state.encode().into();

        harness.report_finalized_header(boundary).await;

        assert!(!harness.has_dealer_log(state.epoch.next()).await);
        assert_eq!(
            harness.epoch_manager.events(),
            vec![
                EpochEvent::Enter {
                    epoch: state.epoch,
                    public: state.output.public().clone(),
                    share: None,
                    participants: state.dealers().clone(),
                },
                EpochEvent::Exit(state.epoch),
                EpochEvent::Enter {
                    epoch: state.epoch.next(),
                    public: state.output.public().clone(),
                    share: None,
                    participants: state.dealers().clone(),
                },
            ]
        );
    });
}

#[test]
fn acked_dealer_messages_not_re_exchanged_after_restart() {
    Runner::default().start(|mut context| async move {
        let (state, keys) = dkg_state(&mut context, Epoch::new(1), 4, true);
        let first = keys[0].clone();
        let second = keys[1].clone();
        let first_public = first.public_key();
        let second_public = second.public_key();

        let execution = StubExecutionProvider::default();
        execution.add_header(outcome_header(Height::new(9), &state));

        let network = TestNetwork::default();
        let mut first_harness = Harness::new(context.child("first"), "actor_exchange_first")
            .await
            .with_me(first.clone())
            .with_execution(execution.clone())
            .with_network(network.clone());
        let mut second_harness = Harness::new(context.child("second"), "actor_exchange_second")
            .await
            .with_me(second.clone())
            .with_execution(execution.clone())
            .with_network(network.clone());

        first_harness.start().await;
        second_harness.start().await;

        assert!(!first_harness.has_dealer_log(state.epoch).await);
        assert!(!second_harness.has_dealer_log(state.epoch).await);

        // Synchronize first with the player receiving the dealing, then with
        // the dealer receiving its ACK.
        first_harness
            .report_finalized_header(header(Height::new(10)))
            .await;
        assert!(!second_harness.has_dealer_log(state.epoch).await);
        assert!(!first_harness.has_dealer_log(state.epoch).await);

        // Apply the same ordering in the opposite direction. Once these calls
        // return, both ACKs have been processed and persisted.
        second_harness
            .report_finalized_header(header(Height::new(10)))
            .await;

        assert!(!first_harness.has_dealer_log(state.epoch).await);
        assert!(!second_harness.has_dealer_log(state.epoch).await);
        assert_eq!(
            (
                network.deliveries_between(&first_public, &second_public),
                network.deliveries_between(&second_public, &first_public),
            ),
            (2, 2),
            "each actor should send a dealing and return an ACK"
        );

        first_harness.stop().await;
        second_harness.stop().await;

        let deliveries_before_restart = (
            network.deliveries_between(&first_public, &second_public),
            network.deliveries_between(&second_public, &first_public),
        );

        drop(first_harness);
        drop(second_harness);

        let mut first_harness =
            Harness::new(context.child("first_restart"), "actor_exchange_first")
                .await
                .with_me(first)
                .with_execution(execution.clone())
                .with_last_finalized_height(Height::new(10))
                .with_network(network.clone());
        let mut second_harness =
            Harness::new(context.child("second_restart"), "actor_exchange_second")
                .await
                .with_me(second)
                .with_execution(execution)
                .with_last_finalized_height(Height::new(10))
                .with_network(network.clone());

        first_harness.start().await;
        second_harness.start().await;

        assert!(!first_harness.has_dealer_log(state.epoch).await);
        assert!(!second_harness.has_dealer_log(state.epoch).await);

        first_harness
            .report_finalized_header(header(Height::new(11)))
            .await;
        second_harness
            .report_finalized_header(header(Height::new(11)))
            .await;

        // Round trips after both updates ensure any resulting network messages
        // have been handled before inspecting the transport.
        assert!(!first_harness.has_dealer_log(state.epoch).await);
        assert!(!second_harness.has_dealer_log(state.epoch).await);
        assert_eq!(
            (
                network.deliveries_between(&first_public, &second_public),
                network.deliveries_between(&second_public, &first_public),
            ),
            deliveries_before_restart,
            "restarted actors must not redistribute shares already acknowledged"
        );

        first_harness
            .report_finalized_header(header(Height::new(15)))
            .await;
        second_harness
            .report_finalized_header(header(Height::new(15)))
            .await;

        assert!(first_harness.has_dealer_log(state.epoch).await);
        assert!(second_harness.has_dealer_log(state.epoch).await);
    });
}

#[test]
fn outcome_requests_use_reshare_fallback_and_require_next_players() {
    Runner::default().start(|mut context| async move {
        let (state, _) = dkg_state(&mut context, Epoch::new(1), 4, true);
        let mut harness =
            Harness::new(context.child("test"), "outcome_execution_dependencies").await;

        harness.execution.fail_next_full_dkg_epoch();
        harness.execution.set_next_players(state.players().clone());
        harness
            .execution
            .add_header(outcome_header(Height::new(9), &state));

        harness.start().await;

        assert!(!harness.has_dealer_log(state.epoch).await);

        harness
            .report_finalized_header(header(Height::new(10)))
            .await;
        harness
            .report_finalized_header(header(Height::new(11)))
            .await;

        let outcome = harness
            .mailbox()
            .get_dkg_outcome(Digest(B256::repeat_byte(1)), Height::new(10))
            .await
            .unwrap();

        assert_eq!(outcome.epoch, state.epoch.next());

        // The incomplete ceremony fails forward by carrying the prior output
        // into the next epoch.
        assert_eq!(outcome.output, state.output);
        assert_eq!(outcome.next_players, state.players);
        assert!(!outcome.is_next_full_dkg);

        harness.execution.fail_next_players();

        assert!(
            harness
                .mailbox()
                .get_dkg_outcome(Digest(B256::repeat_byte(2)), Height::new(10))
                .await
                .is_err()
        );

        assert!(
            !harness.has_dealer_log(state.epoch).await,
            "next-player lookup failure must not terminate the actor"
        );
    });
}
