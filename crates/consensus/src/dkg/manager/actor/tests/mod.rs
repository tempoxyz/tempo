//! Standalone DKG manager actor tests.

mod harness;

use std::time::Duration;

use alloy_primitives::B256;
use commonware_consensus::types::{Epoch, Height};
use commonware_cryptography::{
    bls12381::primitives::group::{Private, Share},
    ed25519::PrivateKey,
};
use commonware_runtime::{Runner as _, Supervisor as _, deterministic::Runner};
use commonware_utils::ordered::Quorum as _;
use futures::channel::oneshot;

use super::*;
use harness::{
    EpochEvent, Harness, StubExecutionProvider, TestNetwork, block, dkg_state, header,
    outcome_header, revealed_recovery_fixture,
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
        let (state, _, _) = dkg_state(&mut context, Epoch::new(1), 4, true);
        let mut harness = Harness::builder(context.child("test"), "exhausted_ancestry")
            .epoch_length(10)
            .build()
            .await;
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
fn startup_discards_stale_state_on_startup() {
    Runner::default().start(|mut context| async move {
        let (current_state, _, _) = dkg_state(&mut context, Epoch::new(1).next(), 4, false);
        let mut harness = Harness::builder(context.child("test"), "startup_discards_stale_state")
            .epoch_length(10)
            .initial_epoch(1)
            // Exercise stale-state replacement as an observer, without
            // recovering a share from the previous epoch.
            .identity(PrivateKey::from_seed(u64::MAX))
            .finalized_floor(Height::new(19))
            .build()
            .await;

        let stale_state = harness.initial_state().clone();

        harness
            .execution
            .add_header(outcome_header(Height::new(19), &current_state));

        harness.start().await;

        // A mailbox round-trip ensures startup healing and epoch entry have completed as
        // heal() completes priot to starting the event loop
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
fn startup_recovers_a_share_from_revealed_dealings() {
    Runner::default().start(|mut context| async move {
        let ceremony_epoch = Epoch::new(1);
        let fixture = revealed_recovery_fixture(&mut context, ceremony_epoch);

        // Since the finalized floor is the boundary of epoch 1, it will try look through this epoch
        // to see if the share was revealed onchain.
        let mut harness =
            Harness::builder(context.child("test"), "startup_recovers_revealed_share")
                .epoch_length(10)
                .identity(fixture.identity.clone())
                .finalized_floor(Height::new(19))
                .build()
                .await;

        fixture.populate_execution(&harness.execution, &harness.epoch_strategy);

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
fn startup_skips_reading_previous_epoch_after_a_failed_ceremony() {
    Runner::default().start(|mut context| async move {
        let ceremony_epoch = Epoch::new(1);
        let (ceremony_state, keys, _) = dkg_state(&mut context, ceremony_epoch, 1, true);
        let mut carried_state = ceremony_state.clone();
        carried_state.epoch = ceremony_epoch.next();
        carried_state.is_full_dkg = false;

        let mut harness = Harness::builder(context.child("test"), "startup_skips_failed_ceremony")
            .epoch_length(10)
            .initial_state(ceremony_state.clone())
            .identity(keys[0].clone())
            .finalized_floor(Height::new(19))
            .build()
            .await;

        let last_finalized_height = Height::new(19);
        let ceremony_boundary = harness
            .epoch_strategy
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
fn failed_dkg_outcomes_carry_share_forward() {
    Runner::default().start(|mut context| async move {
        let (mut state, keys, _) = dkg_state(&mut context, Epoch::new(1), 4, false);
        let identity = keys[0].clone();
        let index = state
            .output
            .players()
            .index(&identity.public_key())
            .unwrap();
        let share = Share::new(index, Private::random(&mut context));
        state.share = ShareState::Plaintext(Some(share.clone()));

        let mut harness = Harness::builder(context.child("test"), "failed_dkg_carries_share")
            .epoch_length(10)
            .initial_state(state.clone())
            .identity(identity)
            .build()
            .await;
        harness.execution.set_next_players(state.players.clone());

        harness.start().await;
        assert!(!harness.has_dealer_log(state.epoch).await);

        harness
            .report_finalized_header(header(Height::new(10)))
            .await;
        harness
            .report_finalized_header(header(Height::new(11)))
            .await;

        let first_digest = Digest(B256::repeat_byte(1));
        let first_outcome = harness
            .mailbox()
            .get_dkg_outcome(first_digest, Height::new(10))
            .await
            .unwrap();
        assert_eq!(first_outcome.epoch, state.epoch.next());
        assert_eq!(first_outcome.output, state.output);

        let mut first_boundary = header(Height::new(19));
        first_boundary.inner.parent_hash = first_digest.0;
        first_boundary.inner.extra_data = first_outcome.encode().into();
        harness.report_finalized_header(first_boundary).await;
        assert!(!harness.has_dealer_log(first_outcome.epoch).await);

        harness
            .report_finalized_header(header(Height::new(20)))
            .await;
        harness
            .report_finalized_header(header(Height::new(21)))
            .await;

        let second_digest = Digest(B256::repeat_byte(2));
        let second_outcome = harness
            .mailbox()
            .get_dkg_outcome(second_digest, Height::new(20))
            .await
            .unwrap();
        assert_eq!(second_outcome.epoch, first_outcome.epoch.next());
        assert_eq!(second_outcome.output, state.output);

        let mut second_boundary = header(Height::new(29));
        second_boundary.inner.parent_hash = second_digest.0;
        second_boundary.inner.extra_data = second_outcome.encode().into();
        harness.report_finalized_header(second_boundary).await;
        assert!(!harness.has_dealer_log(second_outcome.epoch).await);

        assert_eq!(
            harness.epoch_manager.events(),
            vec![
                EpochEvent::Enter {
                    epoch: state.epoch,
                    public: state.output.public().clone(),
                    share: Some(share.clone()),
                    participants: state.dealers().clone(),
                },
                EpochEvent::Exit(state.epoch),
                EpochEvent::Enter {
                    epoch: first_outcome.epoch,
                    public: state.output.public().clone(),
                    share: Some(share.clone()),
                    participants: state.dealers().clone(),
                },
                EpochEvent::Exit(first_outcome.epoch),
                EpochEvent::Enter {
                    epoch: second_outcome.epoch,
                    public: state.output.public().clone(),
                    share: Some(share),
                    participants: state.dealers().clone(),
                },
            ]
        );
    });
}

#[test]
fn startup_prepopulates_to_a_non_boundary_finalized_floor() {
    Runner::default().start(|mut context| async move {
        let (current_state, _, _) = dkg_state(&mut context, Epoch::new(1).next(), 4, false);
        let mut harness =
            Harness::builder(context.child("test"), "prepopulates_non_boundary_floor")
                .epoch_length(10)
                .initial_epoch(1)
                .identity(PrivateKey::from_seed(u64::MAX))
                .finalized_floor(Height::new(22))
                .build()
                .await;

        let boundary = harness.epoch_strategy.last(Epoch::new(1)).unwrap();
        harness
            .execution
            .add_header(outcome_header(boundary, &current_state));

        // Add a few headers into the epoch.
        harness.execution.add_header(header(Height::new(20)));
        harness.execution.add_header(header(Height::new(21)));
        harness.execution.add_header(header(Height::new(22)));

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

        assert_eq!(
            harness.execution.reads(),
            [boundary, Height::new(20), Height::new(21), Height::new(22)]
        );
    });
}

#[test]
fn prepopulation_replays_only_missing_headers() {
    Runner::default().start(|context| async move {
        let mut harness = Harness::builder(context.child("test"), "prepopulation_missing_range")
            .epoch_length(10)
            .initial_epoch(1)
            .finalized_floor(Height::new(12))
            .build()
            .await;

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
        let mut harness = Harness::builder(context.child("test"), "prepopulation_ahead")
            .epoch_length(10)
            .initial_epoch(1)
            .finalized_floor(Height::new(8))
            .build()
            .await;

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
        let mut harness = Harness::builder(context.child("test"), "prepopulation_missing_header")
            .epoch_length(10)
            .initial_epoch(1)
            .finalized_floor(Height::new(10))
            .build()
            .await;

        harness.start().await;

        // Since storage has no finalized headers for epoch 1, it tries to read [10] which fails
        harness.wait_for_exit().await;

        assert_eq!(harness.execution.reads(), vec![Height::new(10)]);
    });
}

#[test]
fn epoch_shares_only_distributed_in_the_first_half() {
    Runner::default().start(|mut context| async move {
        let (state, _, _) = dkg_state(&mut context, Epoch::new(1), 4, true);
        let mut harness = Harness::builder(context.child("test"), "epoch_shares_distributed")
            .epoch_length(10)
            .build()
            .await;
        harness.execution.set_next_players(state.players().clone());

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

        let digest = Digest(B256::repeat_byte(1));
        let outcome = harness
            .mailbox()
            .get_dkg_outcome(digest, Height::new(15))
            .await
            .unwrap();

        let mut boundary = header(Height::new(19));
        boundary.inner.parent_hash = digest.0;
        boundary.inner.extra_data = outcome.encode().into();

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
fn two_actors_produce_the_same_new_dkg_output() {
    Runner::default().start(|mut context| async move {
        let (state, keys, _) = dkg_state(&mut context, Epoch::new(1), 2, true);
        let execution = StubExecutionProvider::default();
        execution.add_header(outcome_header(Height::new(9), &state));
        execution.set_next_players(state.players().clone());

        let network = TestNetwork::default();
        let mut first_harness = Harness::builder(context.child("first"), "new_output_first")
            .epoch_length(10)
            .identity(keys[0].clone())
            .execution(execution.clone())
            .network(network.clone())
            .build()
            .await;
        let mut second_harness = Harness::builder(context.child("second"), "new_output_second")
            .epoch_length(10)
            .identity(keys[1].clone())
            .execution(execution)
            .network(network)
            .build()
            .await;

        first_harness.start().await;
        second_harness.start().await;

        first_harness
            .report_finalized_header(header(Height::new(10)))
            .await;
        assert!(!second_harness.has_dealer_log(state.epoch).await);
        assert!(!first_harness.has_dealer_log(state.epoch).await);

        second_harness
            .report_finalized_header(header(Height::new(10)))
            .await;
        assert!(!first_harness.has_dealer_log(state.epoch).await);
        assert!(!second_harness.has_dealer_log(state.epoch).await);

        first_harness
            .report_finalized_header(header(Height::new(15)))
            .await;
        second_harness
            .report_finalized_header(header(Height::new(15)))
            .await;

        let first_log = first_harness
            .mailbox()
            .get_dealer_log(state.epoch)
            .await
            .unwrap()
            .unwrap();
        let second_log = second_harness
            .mailbox()
            .get_dealer_log(state.epoch)
            .await
            .unwrap()
            .unwrap();

        let mut first_log_header = header(Height::new(16));
        first_log_header.inner.extra_data = first_log.encode().into();
        first_harness
            .report_finalized_header(first_log_header.clone())
            .await;
        second_harness
            .report_finalized_header(first_log_header)
            .await;

        let mut second_log_header = header(Height::new(17));
        second_log_header.inner.extra_data = second_log.encode().into();
        first_harness
            .report_finalized_header(second_log_header.clone())
            .await;
        second_harness
            .report_finalized_header(second_log_header)
            .await;

        let digest = Digest(B256::repeat_byte(1));
        let first_outcome = first_harness
            .mailbox()
            .get_dkg_outcome(digest, Height::new(17))
            .await
            .unwrap();
        let second_outcome = second_harness
            .mailbox()
            .get_dkg_outcome(digest, Height::new(17))
            .await
            .unwrap();

        assert_eq!(first_outcome, second_outcome);
        assert_ne!(first_outcome.output, state.output);
    });
}

#[test]
fn reshare_produces_new_shares() {
    Runner::default().start(|mut context| async move {
        let (state, keys, shares) = dkg_state(&mut context, Epoch::new(1), 2, false);
        let first_share = shares[0].clone();
        let mut first_state = state.clone();
        first_state.share = ShareState::Plaintext(Some(first_share.clone()));

        let second_share = shares[1].clone();
        let mut second_state = state.clone();
        second_state.share = ShareState::Plaintext(Some(second_share.clone()));

        let execution = StubExecutionProvider::default();
        execution.set_next_players(state.players().clone());

        let network = TestNetwork::default();
        let mut first_harness = Harness::builder(context.child("first"), "reshare_first")
            .epoch_length(10)
            .initial_state(first_state)
            .identity(keys[0].clone())
            .execution(execution.clone())
            .network(network.clone())
            .build()
            .await;
        let mut second_harness = Harness::builder(context.child("second"), "reshare_second")
            .epoch_length(10)
            .initial_state(second_state)
            .identity(keys[1].clone())
            .execution(execution)
            .network(network)
            .build()
            .await;

        first_harness.start().await;
        second_harness.start().await;

        first_harness
            .report_finalized_header(header(Height::new(10)))
            .await;
        assert!(!second_harness.has_dealer_log(state.epoch).await);
        assert!(!first_harness.has_dealer_log(state.epoch).await);

        second_harness
            .report_finalized_header(header(Height::new(10)))
            .await;
        assert!(!first_harness.has_dealer_log(state.epoch).await);
        assert!(!second_harness.has_dealer_log(state.epoch).await);

        first_harness
            .report_finalized_header(header(Height::new(15)))
            .await;
        second_harness
            .report_finalized_header(header(Height::new(15)))
            .await;

        let first_log = first_harness
            .mailbox()
            .get_dealer_log(state.epoch)
            .await
            .unwrap()
            .unwrap();

        let mut first_log_header = header(Height::new(16));
        first_log_header.inner.extra_data = first_log.encode().into();

        first_harness
            .report_finalized_header(first_log_header.clone())
            .await;
        second_harness
            .report_finalized_header(first_log_header)
            .await;

        let second_log = second_harness
            .mailbox()
            .get_dealer_log(state.epoch)
            .await
            .unwrap()
            .unwrap();

        let mut second_log_header = header(Height::new(17));
        second_log_header.inner.extra_data = second_log.encode().into();

        first_harness
            .report_finalized_header(second_log_header.clone())
            .await;
        second_harness
            .report_finalized_header(second_log_header)
            .await;

        let digest = Digest(B256::repeat_byte(1));
        let first_outcome = first_harness
            .mailbox()
            .get_dkg_outcome(digest, Height::new(17))
            .await
            .unwrap();
        let second_outcome = second_harness
            .mailbox()
            .get_dkg_outcome(digest, Height::new(17))
            .await
            .unwrap();

        assert_eq!(first_outcome, second_outcome);
        assert_eq!(
            first_outcome.output.public().public(),
            state.output.public().public()
        );

        let mut boundary = header(Height::new(19));
        boundary.inner.parent_hash = digest.0;
        boundary.inner.extra_data = first_outcome.encode().into();
        first_harness
            .report_finalized_header(boundary.clone())
            .await;

        second_harness.report_finalized_header(boundary).await;
        assert!(!first_harness.has_dealer_log(first_outcome.epoch).await);
        assert!(!second_harness.has_dealer_log(first_outcome.epoch).await);

        let first_events = first_harness.epoch_manager.events();
        let EpochEvent::Enter {
            share: Some(new_first_share),
            ..
        } = first_events.last().unwrap()
        else {
            panic!("first actor should enter with a reshared share");
        };
        let second_events = second_harness.epoch_manager.events();
        let EpochEvent::Enter {
            share: Some(new_second_share),
            ..
        } = second_events.last().unwrap()
        else {
            panic!("second actor should enter with a reshared share");
        };

        assert_ne!(new_first_share, &first_share);
        assert_ne!(new_second_share, &second_share);
        assert_eq!(
            new_first_share.public::<MinSig>(),
            first_outcome
                .output
                .public()
                .partial_public(new_first_share.index)
                .unwrap()
        );
        assert_eq!(
            new_second_share.public::<MinSig>(),
            first_outcome
                .output
                .public()
                .partial_public(new_second_share.index)
                .unwrap()
        );
    });
}

#[test]
fn acked_dealer_messages_not_re_exchanged_after_restart() {
    Runner::default().start(|mut context| async move {
        let (state, keys, _) = dkg_state(&mut context, Epoch::new(1), 4, true);
        let first = keys[0].clone();
        let second = keys[1].clone();
        let first_public = first.public_key();
        let second_public = second.public_key();

        let execution = StubExecutionProvider::default();
        execution.add_header(outcome_header(Height::new(9), &state));

        let network = TestNetwork::default();
        let mut first_harness = Harness::builder(context.child("first"), "actor_exchange_first")
            .epoch_length(10)
            .identity(first.clone())
            .execution(execution.clone())
            .network(network.clone())
            .build()
            .await;
        let mut second_harness = Harness::builder(context.child("second"), "actor_exchange_second")
            .epoch_length(10)
            .identity(second.clone())
            .execution(execution.clone())
            .network(network.clone())
            .build()
            .await;

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
            Harness::builder(context.child("first_restart"), "actor_exchange_first")
                .epoch_length(10)
                .identity(first)
                .execution(execution.clone())
                .finalized_floor(Height::new(10))
                .network(network.clone())
                .build()
                .await;
        let mut second_harness =
            Harness::builder(context.child("second_restart"), "actor_exchange_second")
                .epoch_length(10)
                .identity(second)
                .execution(execution)
                .finalized_floor(Height::new(10))
                .network(network.clone())
                .build()
                .await;

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
        let (state, _, _) = dkg_state(&mut context, Epoch::new(1), 4, true);
        let mut harness = Harness::builder(context.child("test"), "outcome_execution_dependencies")
            .epoch_length(10)
            .build()
            .await;

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

#[test]
fn outcome_request_fills_gap_from_notarized_ancestry() {
    Runner::default().start(|context| async move {
        let mut harness = Harness::builder(context.child("test"), "outcome_notarized_gap")
            .epoch_length(10)
            .initial_epoch(0)
            .finalized_floor(Height::new(5))
            .build()
            .await;
        let state = harness.initial_state().clone();
        harness.execution.set_next_players(state.players().clone());

        // Finalized Blocks
        let mut anchor = None;
        for height in 0..=5 {
            let header = header(Height::new(height));
            harness.execution.add_header(header.clone());
            if height == 5 {
                anchor = Some(block(header));
            }
        }

        // Notarized Blocks yielded by the AncestryStream
        let anchor = anchor.unwrap();
        let mut parent = anchor.digest();
        harness.marshal.add_block(anchor);
        for height in 6..=8 {
            let mut header = header(Height::new(height));
            header.inner.parent_hash = parent.0;
            let block = block(header);
            parent = block.digest();
            harness.marshal.add_block(block);
        }

        harness.start().await;

        let outcome = harness
            .mailbox()
            .get_dkg_outcome(parent, Height::new(8))
            .await
            .unwrap();

        assert_eq!(outcome.output, state.output);
        assert_eq!(
            harness.marshal.reads(),
            vec![
                Height::new(8),
                Height::new(7),
                Height::new(6),
                Height::new(5),
            ]
        );
    });
}

#[test]
fn outcome_request_switches_notarized_ancestry_branches() {
    Runner::default().start(|context| async move {
        let mut harness = Harness::builder(context.child("test"), "outcome_notarized_fork")
            .epoch_length(10)
            .initial_epoch(0)
            .finalized_floor(Height::new(5))
            .build()
            .await;
        let state = harness.initial_state().clone();
        harness.execution.set_next_players(state.players().clone());

        let mut anchor = None;
        for height in 0..=5 {
            let header = header(Height::new(height));
            harness.execution.add_header(header.clone());
            if height == 5 {
                anchor = Some(block(header));
            }
        }

        let anchor = anchor.unwrap();
        let anchor_digest = anchor.digest();

        harness.start().await;
        harness.marshal.add_block(anchor);

        // First Notarized Chain
        let mut first_parent = anchor_digest;
        let mut first_chain = Vec::new();
        for height in 6..=8 {
            let mut header = header(Height::new(height));
            header.inner.parent_hash = first_parent.0;
            header.inner.timestamp = 1;
            let block = block(header);
            first_parent = block.digest();
            first_chain.push(first_parent);
            harness.marshal.add_block(block);
        }

        let first_outcome = harness
            .mailbox()
            .get_dkg_outcome(first_parent, Height::new(8))
            .await
            .unwrap();

        // Second Notarized Chain
        let mut second_parent = anchor_digest;
        let mut second_chain = Vec::new();
        for height in 6..=8 {
            let mut header = header(Height::new(height));
            header.inner.parent_hash = second_parent.0;
            header.inner.timestamp = 2;
            let block = block(header);
            second_parent = block.digest();
            second_chain.push(second_parent);
            harness.marshal.add_block(block);
        }

        let second_outcome = harness
            .mailbox()
            .get_dkg_outcome(second_parent, Height::new(8))
            .await
            .unwrap();

        assert_eq!(first_outcome.output, state.output);
        assert_eq!(second_outcome.output, state.output);
        let ancestry_reads = vec![
            first_chain[2],
            first_chain[1],
            first_chain[0],
            anchor_digest,
            second_chain[2],
            second_chain[1],
            second_chain[0],
        ];

        assert_eq!(harness.marshal.ancestry_reads(), ancestry_reads);

        // DKG Outcomes are cached, thus we can request the outcome without re-reading state
        let cached_first_outcome = harness
            .mailbox()
            .get_dkg_outcome(first_parent, Height::new(8))
            .await
            .unwrap();

        assert_eq!(cached_first_outcome, first_outcome);
        assert_eq!(harness.marshal.ancestry_reads(), ancestry_reads);
    });
}
