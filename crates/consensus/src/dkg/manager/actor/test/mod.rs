//! Standalone DKG manager actor tests.

mod utils;

use std::{num::NonZeroU64, time::Duration};

use alloy_primitives::B256;
use commonware_consensus::types::{Epoch, FixedEpocher, Height};
use commonware_cryptography::ed25519::PrivateKey;
use commonware_runtime::{Runner as _, Supervisor as _, deterministic::Runner};
use futures::channel::oneshot;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;

use super::*;
use utils::{
    EpochEvent, StubExecutionProvider, TestDkg, TestNetwork, acked_recovery_fixture, block,
    dkg_state, full_dkg_state, header, outcome_header,
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
        let (state, _) = full_dkg_state(&mut context, Epoch::new(1), 4);
        let mut actor = TestDkg::new(context.child("test"), "exhausted_ancestry", None).await;
        actor
            .execution_node
            .set_next_players(state.players().clone());
        actor
            .execution_node
            .add_header(outcome_header(Height::new(9), &state));

        actor.marshal.return_empty_ancestry();

        actor.start().await;

        actor.report_finalized_header(header(Height::new(10))).await;
        actor.report_finalized_header(header(Height::new(11))).await;

        let request_mailbox = actor.mailbox().clone();
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
        let stale_state = dkg_state(&mut context, Epoch::new(1));
        let current_state = dkg_state(&mut context, Epoch::new(2));

        let mut actor = TestDkg::new(
            context.child("test"),
            "healing_discards_stale_state",
            Some(stale_state.clone()),
        )
        .await
        .with_last_finalized_height(Height::new(19));

        actor
            .execution_node
            .add_header(outcome_header(Height::new(19), &current_state));

        actor.start().await;

        // A mailbox round-trip ensures startup healing and epoch entry have completed.
        assert!(!actor.has_dealer_log(current_state.epoch).await);

        assert_ne!(current_state.output, stale_state.output);
        assert_eq!(
            actor.epoch_manager.events(),
            vec![EpochEvent::Enter {
                epoch: current_state.epoch,
                public: current_state.output.public().clone(),
                share: None,
                participants: current_state.dealers().clone(),
            }]
        );
        assert_eq!(
            actor.execution_node.reads(),
            vec![Height::new(19)],
            "healing should replace stale state from the latest boundary"
        );
    });
}

#[test]
fn healing_recovers_an_acked_share_from_persisted_dealings() {
    Runner::default().start(|mut context| async move {
        let epoch_strategy = FixedEpocher::new(NonZeroU64::new(10).unwrap());
        let ceremony_epoch = Epoch::new(1);
        let execution_node = StubExecutionProvider::default();

        let fixture = acked_recovery_fixture(
            &mut context,
            &execution_node,
            &epoch_strategy,
            ceremony_epoch,
        );

        let mut actor = TestDkg::new(
            context.child("test"),
            "healing_recovers_persisted_dealings",
            Some(fixture.ceremony_state.clone()),
        )
        .await
        .with_execution_node(execution_node)
        .with_epoch_strategy(epoch_strategy.clone())
        .with_me(fixture.local_key.clone())
        .with_last_finalized_height(epoch_strategy.last(ceremony_epoch).unwrap());

        let round = Round::from_state(&fixture.ceremony_state, crate::config::NAMESPACE);
        let persisted = actor.storage_mut();
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

        actor.start().await;

        // A mailbox round-trip ensures startup recovery and epoch entry have completed.
        assert!(!actor.has_dealer_log(ceremony_epoch.next()).await);

        assert_eq!(
            actor.epoch_manager.events(),
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
        let epoch_strategy = FixedEpocher::new(NonZeroU64::new(10).unwrap());
        let ceremony_epoch = Epoch::new(1);
        let (ceremony_state, keys) = full_dkg_state(&mut context, ceremony_epoch, 1);
        let mut carried_state = ceremony_state.clone();
        carried_state.epoch = ceremony_epoch.next();
        carried_state.is_full_dkg = false;

        let last_finalized_height = epoch_strategy.last(ceremony_epoch).unwrap();
        let mut actor = TestDkg::new(
            context.child("test"),
            "healing_skips_failed_ceremony",
            Some(ceremony_state.clone()),
        )
        .await
        .with_me(keys[0].clone())
        .with_epoch_strategy(epoch_strategy.clone())
        .with_last_finalized_height(last_finalized_height);

        let ceremony_boundary = epoch_strategy
            .last(ceremony_epoch.previous().unwrap())
            .unwrap();

        actor
            .execution_node
            .add_header(outcome_header(ceremony_boundary, &ceremony_state));

        actor
            .execution_node
            .add_header(outcome_header(last_finalized_height, &carried_state));

        actor.start().await;

        assert!(!actor.has_dealer_log(carried_state.epoch).await);
        assert_eq!(
            actor.epoch_manager.events(),
            vec![EpochEvent::Enter {
                epoch: carried_state.epoch,
                public: carried_state.output.public().clone(),
                share: None,
                participants: carried_state.dealers().clone(),
            }]
        );
        assert_eq!(
            actor.execution_node.reads(),
            vec![last_finalized_height, ceremony_boundary],
            "a carried-forward output must skip dealer-log recovery"
        );
    });
}

#[test]
fn healing_prepopulates_to_a_non_boundary_finalized_floor() {
    Runner::default().start(|mut context| async move {
        let epoch_strategy = FixedEpocher::new(NonZeroU64::new(10).unwrap());
        let stale_state = dkg_state(&mut context, Epoch::new(1));
        let current_state = dkg_state(&mut context, Epoch::new(2));

        let boundary = epoch_strategy.last(Epoch::new(1)).unwrap();
        let first = epoch_strategy.first(current_state.epoch).unwrap();
        let prepopulation_heights = (0..3)
            .map(|offset| Height::new(first.get() + offset))
            .collect::<Vec<_>>();

        let last_finalized_height = *prepopulation_heights.last().unwrap();
        let mut actor = TestDkg::new(
            context.child("test"),
            "healing_prepopulates_non_boundary_floor",
            Some(stale_state.clone()),
        )
        .await
        .with_me(PrivateKey::from_seed(u64::MAX))
        .with_epoch_strategy(epoch_strategy)
        .with_last_finalized_height(last_finalized_height);

        actor
            .execution_node
            .add_header(outcome_header(boundary, &current_state));

        for height in &prepopulation_heights {
            actor.execution_node.add_header(header(*height));
        }

        actor.start().await;

        assert!(!actor.has_dealer_log(current_state.epoch).await);
        assert_eq!(
            actor.epoch_manager.events(),
            vec![EpochEvent::Enter {
                epoch: current_state.epoch,
                public: current_state.output.public().clone(),
                share: None,
                participants: current_state.dealers().clone(),
            }]
        );

        let mut expected_reads = vec![boundary];
        expected_reads.extend(prepopulation_heights);
        assert_eq!(actor.execution_node.reads(), expected_reads);
    });
}

#[test]
fn prepopulation_replays_only_missing_headers() {
    Runner::default().start(|mut context| async move {
        let initial_state = dkg_state(&mut context, Epoch::new(1));
        let mut actor = TestDkg::new(
            context.child("test"),
            "prepopulation_missing_range",
            Some(initial_state.clone()),
        )
        .await
        .with_last_finalized_height(Height::new(12));
        actor.execution_node.add_header(header(Height::new(10)));
        actor.execution_node.add_header(header(Height::new(11)));
        actor.marshal.add_block(block(header(Height::new(12))));

        actor.start().await;

        assert!(!actor.has_dealer_log(initial_state.epoch).await);
        actor.stop().await;

        assert_eq!(
            actor
                .storage()
                .get_latest_finalized_block_for_epoch(&Epoch::new(1))
                .map(|(height, _)| *height),
            Some(Height::new(12))
        );
        assert_eq!(
            actor.execution_node.reads(),
            vec![Height::new(10), Height::new(11), Height::new(12)]
        );
        assert_eq!(actor.marshal.reads(), vec![Height::new(12)]);

        actor.start().await;
        assert!(!actor.has_dealer_log(initial_state.epoch).await);

        assert_eq!(
            actor.execution_node.reads(),
            vec![Height::new(10), Height::new(11), Height::new(12)],
            "already-populated headers must not be read again"
        );
    });
}

#[test]
fn prepopulation_enforces_dkg_epoch_relative_to_finalized_tip() {
    Runner::default().start(|mut context| async move {
        let behind_state = dkg_state(&mut context, Epoch::zero());
        let mut behind = TestDkg::new(context.child("behind"), "prepopulation_behind", None)
            .await
            .with_last_finalized_height(Height::new(10));
        behind
            .execution_node
            .add_header(outcome_header(Height::new(9), &behind_state));

        behind.start().await;

        behind.wait_for_exit().await;

        let ahead_state = dkg_state(&mut context, Epoch::new(1));
        let mut ahead = TestDkg::new(
            context.child("ahead"),
            "prepopulation_ahead",
            Some(ahead_state.clone()),
        )
        .await
        .with_last_finalized_height(Height::new(8));

        ahead.start().await;

        assert!(!ahead.has_dealer_log(ahead_state.epoch).await);

        assert!(ahead.execution_node.reads().is_empty());
        assert!(ahead.marshal.reads().is_empty());
        assert_eq!(
            ahead.epoch_manager.events(),
            vec![EpochEvent::Enter {
                epoch: ahead_state.epoch,
                public: ahead_state.output.public().clone(),
                share: None,
                participants: ahead_state.dealers().clone(),
            }]
        );
    });
}

#[test]
fn prepopulation_fails_when_required_header_is_unavailable() {
    Runner::default().start(|mut context| async move {
        let initial_state = dkg_state(&mut context, Epoch::new(1));
        let mut actor = TestDkg::new(
            context.child("test"),
            "prepopulation_missing_header",
            Some(initial_state),
        )
        .await
        .with_last_finalized_height(Height::new(10));

        actor.start().await;

        actor.wait_for_exit().await;

        assert_eq!(actor.execution_node.reads(), vec![Height::new(10)]);
    });
}

#[test]
fn epoch_phases_distribute_then_finalize_without_redistributing() {
    Runner::default().start(|mut context| async move {
        let (state, _) = full_dkg_state(&mut context, Epoch::new(1), 4);

        let mut actor = TestDkg::new(context.child("test"), "epoch_phase_transitions", None).await;
        actor
            .execution_node
            .add_header(outcome_header(Height::new(9), &state));

        actor.start().await;

        // A mailbox round-trip ensures the actor has entered the epoch before
        // finalized blocks are delivered.
        assert!(!actor.has_dealer_log(state.epoch).await);
        assert_eq!(
            actor.epoch_manager.events(),
            vec![EpochEvent::Enter {
                epoch: state.epoch,
                public: state.output.public().clone(),
                share: None,
                participants: state.dealers().clone(),
            }]
        );

        actor.report_finalized_header(header(Height::new(10))).await;

        assert!(!actor.has_dealer_log(state.epoch).await);
        assert_eq!(actor.sender().send_count(), state.players().len() - 1);

        actor.report_finalized_header(header(Height::new(15))).await;

        assert!(actor.has_dealer_log(state.epoch).await);

        actor.report_finalized_header(header(Height::new(16))).await;

        assert_eq!(
            actor.sender().send_count(),
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

        actor.report_finalized_header(boundary).await;

        assert!(!actor.has_dealer_log(state.epoch.next()).await);
        assert_eq!(
            actor.epoch_manager.events(),
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
fn exchange_dealer_messages_and_replay_acks_after_restart() {
    Runner::default().start(|mut context| async move {
        let (state, keys) = full_dkg_state(&mut context, Epoch::new(1), 4);
        let first = keys[0].clone();
        let second = keys[1].clone();
        let first_public = first.public_key();
        let second_public = second.public_key();

        let execution = StubExecutionProvider::default();
        execution.add_header(outcome_header(Height::new(9), &state));

        let network = TestNetwork::default();
        let mut first_actor = TestDkg::new(context.child("first"), "actor_exchange_first", None)
            .await
            .with_me(first.clone())
            .with_execution_node(execution.clone())
            .with_network(network.clone());
        let mut second_actor = TestDkg::new(context.child("second"), "actor_exchange_second", None)
            .await
            .with_me(second.clone())
            .with_execution_node(execution.clone())
            .with_network(network.clone());

        first_actor.start().await;
        second_actor.start().await;

        assert!(!first_actor.has_dealer_log(state.epoch).await);
        assert!(!second_actor.has_dealer_log(state.epoch).await);

        // Synchronize first with the player receiving the dealing, then with
        // the dealer receiving its ACK.
        first_actor
            .report_finalized_header(header(Height::new(10)))
            .await;
        assert!(!second_actor.has_dealer_log(state.epoch).await);
        assert!(!first_actor.has_dealer_log(state.epoch).await);

        // Apply the same ordering in the opposite direction. Once these calls
        // return, both ACKs have been processed and persisted.
        second_actor
            .report_finalized_header(header(Height::new(10)))
            .await;

        assert!(!first_actor.has_dealer_log(state.epoch).await);
        assert!(!second_actor.has_dealer_log(state.epoch).await);
        assert_eq!(
            (
                network.deliveries_between(&first_public, &second_public),
                network.deliveries_between(&second_public, &first_public),
            ),
            (2, 2),
            "each actor should send a dealing and return an ACK"
        );

        first_actor.stop().await;
        second_actor.stop().await;

        let deliveries_before_restart = (
            network.deliveries_between(&first_public, &second_public),
            network.deliveries_between(&second_public, &first_public),
        );

        drop(first_actor);
        drop(second_actor);

        let mut first_restart =
            TestDkg::new(context.child("first_restart"), "actor_exchange_first", None)
                .await
                .with_me(first)
                .with_execution_node(execution.clone())
                .with_last_finalized_height(Height::new(10))
                .with_network(network.clone());
        let mut second_restart = TestDkg::new(
            context.child("second_restart"),
            "actor_exchange_second",
            None,
        )
        .await
        .with_me(second)
        .with_execution_node(execution)
        .with_last_finalized_height(Height::new(10))
        .with_network(network.clone());

        first_restart.start().await;
        second_restart.start().await;

        assert!(!first_restart.has_dealer_log(state.epoch).await);
        assert!(!second_restart.has_dealer_log(state.epoch).await);

        first_restart
            .report_finalized_header(header(Height::new(11)))
            .await;
        second_restart
            .report_finalized_header(header(Height::new(11)))
            .await;

        // Round trips after both updates ensure any resulting network messages
        // have been handled before inspecting the transport.
        assert!(!first_restart.has_dealer_log(state.epoch).await);
        assert!(!second_restart.has_dealer_log(state.epoch).await);
        assert_eq!(
            (
                network.deliveries_between(&first_public, &second_public),
                network.deliveries_between(&second_public, &first_public),
            ),
            deliveries_before_restart,
            "restarted actors must not redistribute shares already acknowledged"
        );

        first_restart
            .report_finalized_header(header(Height::new(15)))
            .await;
        second_restart
            .report_finalized_header(header(Height::new(15)))
            .await;

        assert!(first_restart.has_dealer_log(state.epoch).await);
        assert!(second_restart.has_dealer_log(state.epoch).await);
    });
}

#[test]
fn outcome_requests_use_reshare_fallback_and_require_next_players() {
    Runner::default().start(|mut context| async move {
        let (state, _) = full_dkg_state(&mut context, Epoch::new(1), 4);
        let mut actor = TestDkg::new(
            context.child("test"),
            "outcome_execution_dependencies",
            None,
        )
        .await;

        actor.execution_node.fail_next_full_dkg_epoch();
        actor
            .execution_node
            .set_next_players(state.players().clone());
        actor
            .execution_node
            .add_header(outcome_header(Height::new(9), &state));

        actor.start().await;

        assert!(!actor.has_dealer_log(state.epoch).await);

        actor.report_finalized_header(header(Height::new(10))).await;
        actor.report_finalized_header(header(Height::new(11))).await;

        let outcome = actor
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

        actor.execution_node.fail_next_players();

        assert!(
            actor
                .mailbox()
                .get_dkg_outcome(Digest(B256::repeat_byte(2)), Height::new(10))
                .await
                .is_err()
        );

        assert!(
            !actor.has_dealer_log(state.epoch).await,
            "next-player lookup failure must not terminate the actor"
        );
    });
}
