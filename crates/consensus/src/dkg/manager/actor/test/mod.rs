//! Standalone DKG manager actor tests.

mod utils;

use std::{
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::Duration,
};

use alloy_primitives::B256;
use commonware_codec::Encode as _;
use commonware_consensus::{
    Reporter as _,
    marshal::Update,
    types::{Epoch, Epocher as _, FixedEpocher, Height},
};
use commonware_cryptography::ed25519::PrivateKey;
use commonware_runtime::{
    Clock as _, Runner as _, Supervisor as _,
    deterministic::{Context, Runner},
};
use commonware_utils::{Acknowledgement as _, acknowledgement::Exact};
use futures::{
    FutureExt as _, StreamExt as _,
    channel::{mpsc, oneshot},
};
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;

use super::{
    super::{Config, Mailbox, init},
    *,
};
use utils::{
    EpochEvent, InertReceiver, RecordingSender, StubEpochManager, StubExecutionProvider,
    StubMarshal, TestNetwork, acked_recovery_fixture, block, dkg_state, full_dkg_state, header,
    outcome_header,
};

fn config(
    me: PrivateKey,
    epoch_strategy: FixedEpocher,
    last_finalized_height: Height,
    partition_prefix: &str,
    execution_node: StubExecutionProvider,
    marshal: StubMarshal,
    epoch_manager: StubEpochManager,
) -> Config<StubExecutionProvider, StubMarshal, StubEpochManager> {
    Config {
        epoch_strategy,
        epoch_manager,
        namespace: crate::config::NAMESPACE.to_vec(),
        me,
        mailbox_size: NonZeroUsize::new(1).unwrap(),
        marshal,
        last_finalized_height,
        partition_prefix: partition_prefix.to_string(),
        execution_node,
        initial_share: None,
    }
}

async fn actor(
    context: Context,
    epoch_strategy: FixedEpocher,
    last_finalized_height: Height,
    execution_node: StubExecutionProvider,
    marshal: StubMarshal,
    epoch_manager: StubEpochManager,
) -> Actor<Context, StubExecutionProvider, StubMarshal, StubEpochManager> {
    let (_mailbox, receiver) = mpsc::unbounded();
    Actor::new(
        config(
            PrivateKey::from_seed(0),
            epoch_strategy,
            last_finalized_height,
            "dkg_actor_test",
            execution_node,
            marshal,
            epoch_manager,
        ),
        context,
        receiver,
    )
    .await
    .unwrap()
}

async fn report_finalized_header(mailbox: &mut Mailbox, header: TempoHeader) {
    let (acknowledgement, waiter) = Exact::handle();
    assert!(
        mailbox
            .report(Update::Block(Arc::new(block(header)), acknowledgement))
            .accepted()
    );
    waiter
        .await
        .expect("finalized block should be acknowledged");
}

async fn has_dealer_log(mailbox: &Mailbox, epoch: Epoch) -> bool {
    mailbox.get_dealer_log(epoch).await.unwrap().is_some()
}

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
        let execution = StubExecutionProvider::default();
        let (state, _) = full_dkg_state(&mut context, Epoch::new(1), 4);
        execution.set_next_players(state.players().clone());
        execution.add_header(outcome_header(Height::new(9), &state));

        let marshal = StubMarshal::default();
        marshal.return_empty_ancestry();

        let (actor, mut mailbox) = init(
            context.child("actor"),
            config(
                PrivateKey::from_seed(0),
                FixedEpocher::new(NonZeroU64::new(10).unwrap()),
                Height::new(9),
                "exhausted_ancestry",
                execution,
                marshal,
                StubEpochManager::default(),
            ),
        )
        .await
        .unwrap();

        let handle = actor.start((RecordingSender::default(), InertReceiver));

        report_finalized_header(&mut mailbox, header(Height::new(10))).await;
        report_finalized_header(&mut mailbox, header(Height::new(11))).await;

        let request_mailbox = mailbox.clone();
        let response = context
            .timeout(Duration::from_secs(1), async move {
                request_mailbox
                    .get_dkg_outcome(Digest(B256::repeat_byte(1)), Height::new(11))
                    .await
            })
            .await
            .expect("an exhausted ancestry stream must not leave the outcome request pending");

        assert!(response.is_err());

        drop(mailbox);
        handle
            .await
            .expect("actor should stop when its mailbox closes");
    });
}

#[test]
fn healing_discards_stale_state_on_startup() {
    Runner::default().start(|mut context| async move {
        let stale_state = dkg_state(&mut context, Epoch::new(1));
        let current_state = dkg_state(&mut context, Epoch::new(2));

        let persisted = state::builder()
            .partition_prefix("healing_discards_stale_state")
            .init_unverified(context.child("persisted"))
            .await
            .unwrap()
            .init_verified(stale_state.clone())
            .await
            .unwrap();
        drop(persisted);

        let execution = StubExecutionProvider::default();
        execution.add_header(outcome_header(Height::new(19), &current_state));

        let epoch_manager = StubEpochManager::default();
        let (actor, mailbox) = init(
            context.child("actor"),
            config(
                PrivateKey::from_seed(0),
                FixedEpocher::new(NonZeroU64::new(10).unwrap()),
                Height::new(19),
                "healing_discards_stale_state",
                execution.clone(),
                StubMarshal::default(),
                epoch_manager.clone(),
            ),
        )
        .await
        .unwrap();

        let handle = actor.start((RecordingSender::default(), InertReceiver));

        // A mailbox round-trip ensures startup healing and epoch entry have completed.
        assert!(!has_dealer_log(&mailbox, current_state.epoch).await);

        assert_ne!(current_state.output, stale_state.output);
        assert_eq!(
            epoch_manager.events(),
            vec![EpochEvent::Enter {
                epoch: current_state.epoch,
                public: current_state.output.public().clone(),
                share: None,
                participants: current_state.dealers().clone(),
            }]
        );
        assert_eq!(
            execution.reads(),
            vec![Height::new(19)],
            "healing should replace stale state from the latest boundary"
        );

        drop(mailbox);
        handle
            .await
            .expect("actor should stop when its mailbox closes");
    });
}

#[test]
fn healing_recovers_an_acked_share_from_persisted_dealings() {
    Runner::default().start(|mut context| async move {
        let execution = StubExecutionProvider::default();
        let epoch_strategy = FixedEpocher::new(NonZeroU64::new(10).unwrap());
        let ceremony_epoch = Epoch::new(1);

        let fixture =
            acked_recovery_fixture(&mut context, &execution, &epoch_strategy, ceremony_epoch);

        let mut persisted = state::builder()
            .partition_prefix("healing_recovers_persisted_dealings")
            .init_unverified(context.child("persisted"))
            .await
            .unwrap()
            .init_verified(fixture.ceremony_state.clone())
            .await
            .unwrap();

        let round = Round::from_state(&fixture.ceremony_state, crate::config::NAMESPACE);
        let mut player = persisted
            .create_player_for_round(fixture.local_key.clone(), &round)
            .unwrap()
            .unwrap();

        let (dealer, public_message, private_message) = &fixture.local_dealing;
        player
            .receive_dealing(
                &mut persisted,
                round.epoch(),
                dealer.clone(),
                public_message.clone(),
                private_message.clone(),
            )
            .await
            .unwrap();

        drop(player);
        drop(persisted);

        let last_finalized_height = epoch_strategy.last(ceremony_epoch).unwrap();
        let epoch_manager = StubEpochManager::default();
        let (actor, mailbox) = init(
            context.child("actor"),
            config(
                fixture.local_key.clone(),
                epoch_strategy,
                last_finalized_height,
                "healing_recovers_persisted_dealings",
                execution,
                StubMarshal::default(),
                epoch_manager.clone(),
            ),
        )
        .await
        .unwrap();

        let handle = actor.start((RecordingSender::default(), InertReceiver));

        // A mailbox round-trip ensures startup recovery and epoch entry have completed.
        assert!(!has_dealer_log(&mailbox, ceremony_epoch.next()).await);

        assert_eq!(
            epoch_manager.events(),
            vec![EpochEvent::Enter {
                epoch: ceremony_epoch.next(),
                public: fixture.expected_output.public().clone(),
                share: Some(fixture.recovered_share),
                participants: fixture.expected_output.players().clone(),
            }]
        );

        drop(mailbox);
        handle
            .await
            .expect("actor should stop when its mailbox closes");
    });
}

#[test]
fn healing_skips_recovery_after_a_failed_ceremony() {
    Runner::default().start(|mut context| async move {
        let epoch_strategy = FixedEpocher::new(NonZeroU64::new(10).unwrap());
        let ceremony_epoch = Epoch::new(1);
        let (ceremony_state, keys) = full_dkg_state(&mut context, ceremony_epoch, 1);
        let mut carried_state = ceremony_state.clone();
        carried_state.epoch = ceremony_epoch.next();
        carried_state.is_full_dkg = false;

        let persisted = state::builder()
            .partition_prefix("healing_skips_failed_ceremony")
            .init_unverified(context.child("persisted"))
            .await
            .unwrap()
            .init_verified(ceremony_state.clone())
            .await
            .unwrap();
        drop(persisted);

        let execution = StubExecutionProvider::default();
        let ceremony_boundary = epoch_strategy
            .last(ceremony_epoch.previous().unwrap())
            .unwrap();
        execution.add_header(outcome_header(ceremony_boundary, &ceremony_state));

        let last_finalized_height = epoch_strategy.last(ceremony_epoch).unwrap();
        execution.add_header(outcome_header(last_finalized_height, &carried_state));

        let epoch_manager = StubEpochManager::default();
        let (actor, mailbox) = init(
            context.child("actor"),
            config(
                keys[0].clone(),
                epoch_strategy,
                last_finalized_height,
                "healing_skips_failed_ceremony",
                execution.clone(),
                StubMarshal::default(),
                epoch_manager.clone(),
            ),
        )
        .await
        .unwrap();

        let handle = actor.start((RecordingSender::default(), InertReceiver));

        assert!(!has_dealer_log(&mailbox, carried_state.epoch).await);
        assert_eq!(
            epoch_manager.events(),
            vec![EpochEvent::Enter {
                epoch: carried_state.epoch,
                public: carried_state.output.public().clone(),
                share: None,
                participants: carried_state.dealers().clone(),
            }]
        );
        assert_eq!(
            execution.reads(),
            vec![last_finalized_height, ceremony_boundary],
            "a carried-forward output must skip dealer-log recovery"
        );

        drop(mailbox);
        handle
            .await
            .expect("actor should stop when its mailbox closes");
    });
}

#[test]
fn healing_prepopulates_to_a_non_boundary_finalized_floor() {
    Runner::default().start(|mut context| async move {
        let epoch_strategy = FixedEpocher::new(NonZeroU64::new(10).unwrap());
        let stale_state = dkg_state(&mut context, Epoch::new(1));
        let current_state = dkg_state(&mut context, Epoch::new(2));

        let persisted = state::builder()
            .partition_prefix("healing_prepopulates_non_boundary_floor")
            .init_unverified(context.child("persisted"))
            .await
            .unwrap()
            .init_verified(stale_state.clone())
            .await
            .unwrap();
        drop(persisted);

        let execution = StubExecutionProvider::default();
        let boundary = epoch_strategy.last(Epoch::new(1)).unwrap();
        execution.add_header(outcome_header(boundary, &current_state));

        let first = epoch_strategy.first(current_state.epoch).unwrap();
        let prepopulation_heights = (0..3)
            .map(|offset| Height::new(first.get() + offset))
            .collect::<Vec<_>>();

        for height in &prepopulation_heights {
            execution.add_header(header(*height));
        }

        let last_finalized_height = *prepopulation_heights.last().unwrap();
        let epoch_manager = StubEpochManager::default();
        let (actor, mailbox) = init(
            context.child("actor"),
            config(
                PrivateKey::from_seed(u64::MAX),
                epoch_strategy,
                last_finalized_height,
                "healing_prepopulates_non_boundary_floor",
                execution.clone(),
                StubMarshal::default(),
                epoch_manager.clone(),
            ),
        )
        .await
        .unwrap();

        let handle = actor.start((RecordingSender::default(), InertReceiver));

        assert!(!has_dealer_log(&mailbox, current_state.epoch).await);
        assert_eq!(
            epoch_manager.events(),
            vec![EpochEvent::Enter {
                epoch: current_state.epoch,
                public: current_state.output.public().clone(),
                share: None,
                participants: current_state.dealers().clone(),
            }]
        );

        let mut expected_reads = vec![boundary];
        expected_reads.extend(prepopulation_heights);
        assert_eq!(execution.reads(), expected_reads);

        drop(mailbox);
        handle
            .await
            .expect("actor should stop when its mailbox closes");
    });
}

#[test]
fn prepopulation_replays_only_missing_headers() {
    Runner::default().start(|mut context| async move {
        let execution = StubExecutionProvider::default();
        execution.add_header(header(Height::new(10)));
        execution.add_header(header(Height::new(11)));

        let marshal = StubMarshal::default();
        marshal.add_block(block(header(Height::new(12))));

        let actor = actor(
            context.child("actor"),
            FixedEpocher::new(NonZeroU64::new(10).unwrap()),
            Height::new(12),
            execution.clone(),
            marshal.clone(),
            StubEpochManager::default(),
        )
        .await;

        let mut storage = state::builder()
            .partition_prefix("prepopulation_missing_range")
            .init_unverified(context.child("storage"))
            .await
            .unwrap()
            .init_verified(dkg_state(&mut context, Epoch::new(1)))
            .await
            .unwrap();

        actor
            .prepopulate_to_last_finalized_height(&mut storage)
            .await
            .unwrap();

        assert_eq!(
            storage
                .get_latest_finalized_block_for_epoch(&Epoch::new(1))
                .map(|(height, _)| *height),
            Some(Height::new(12))
        );
        assert_eq!(
            execution.reads(),
            vec![Height::new(10), Height::new(11), Height::new(12)]
        );
        assert_eq!(marshal.reads(), vec![Height::new(12)]);

        actor
            .prepopulate_to_last_finalized_height(&mut storage)
            .await
            .unwrap();

        assert_eq!(
            execution.reads(),
            vec![Height::new(10), Height::new(11), Height::new(12)],
            "already-populated headers must not be read again"
        );
    });
}

#[test]
fn prepopulation_enforces_dkg_epoch_relative_to_finalized_tip() {
    Runner::default().start(|mut context| async move {
        let behind_execution = StubExecutionProvider::default();
        let behind_state = dkg_state(&mut context, Epoch::zero());
        behind_execution.add_header(outcome_header(Height::new(9), &behind_state));

        let (behind_actor, _mailbox) = init(
            context.child("behind_actor_run"),
            config(
                PrivateKey::from_seed(0),
                FixedEpocher::new(NonZeroU64::new(10).unwrap()),
                Height::new(10),
                "prepopulation_behind",
                behind_execution,
                StubMarshal::default(),
                StubEpochManager::default(),
            ),
        )
        .await
        .unwrap();

        behind_actor
            .start((RecordingSender::default(), InertReceiver))
            .await
            .expect("actor must terminate when its initial DKG state is stale");

        let execution = StubExecutionProvider::default();
        let marshal = StubMarshal::default();
        let ahead_state = dkg_state(&mut context, Epoch::new(1));
        let ahead_storage = state::builder()
            .partition_prefix("prepopulation_ahead")
            .init_unverified(context.child("ahead_storage"))
            .await
            .unwrap()
            .init_verified(ahead_state.clone())
            .await
            .unwrap();
        drop(ahead_storage);

        let epoch_manager = StubEpochManager::default();
        let (ahead_actor, mailbox) = init(
            context.child("ahead_actor"),
            config(
                PrivateKey::from_seed(0),
                FixedEpocher::new(NonZeroU64::new(10).unwrap()),
                Height::new(8),
                "prepopulation_ahead",
                execution.clone(),
                marshal.clone(),
                epoch_manager.clone(),
            ),
        )
        .await
        .unwrap();

        let handle = ahead_actor.start((RecordingSender::default(), InertReceiver));

        assert!(!has_dealer_log(&mailbox, ahead_state.epoch).await);

        assert!(execution.reads().is_empty());
        assert!(marshal.reads().is_empty());
        assert_eq!(
            epoch_manager.events(),
            vec![EpochEvent::Enter {
                epoch: ahead_state.epoch,
                public: ahead_state.output.public().clone(),
                share: None,
                participants: ahead_state.dealers().clone(),
            }]
        );

        drop(mailbox);
        handle
            .await
            .expect("actor should stop when its mailbox closes");
    });
}

#[test]
fn prepopulation_fails_when_required_header_is_unavailable() {
    Runner::default().start(|mut context| async move {
        let actor = actor(
            context.child("actor"),
            FixedEpocher::new(NonZeroU64::new(10).unwrap()),
            Height::new(10),
            StubExecutionProvider::default(),
            StubMarshal::default(),
            StubEpochManager::default(),
        )
        .await;

        let mut storage = state::builder()
            .partition_prefix("prepopulation_missing_header")
            .init_unverified(context.child("storage"))
            .await
            .unwrap()
            .init_verified(dkg_state(&mut context, Epoch::new(1)))
            .await
            .unwrap();

        let error = actor
            .prepopulate_to_last_finalized_height(&mut storage)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("height `10`"));
    });
}

#[test]
fn epoch_phases_distribute_then_finalize_without_redistributing() {
    Runner::default().start(|mut context| async move {
        let (state, _) = full_dkg_state(&mut context, Epoch::new(1), 4);

        let execution = StubExecutionProvider::default();
        execution.add_header(outcome_header(Height::new(9), &state));

        let epoch_manager = StubEpochManager::default();
        let (actor, mut mailbox) = init(
            context.child("actor"),
            config(
                PrivateKey::from_seed(0),
                FixedEpocher::new(NonZeroU64::new(10).unwrap()),
                Height::new(9),
                "epoch_phase_transitions",
                execution,
                StubMarshal::default(),
                epoch_manager.clone(),
            ),
        )
        .await
        .unwrap();

        let sender = RecordingSender::default();
        let handle = actor.start((sender.clone(), InertReceiver));

        // A mailbox round-trip ensures the actor has entered the epoch before
        // finalized blocks are delivered.
        assert!(!has_dealer_log(&mailbox, state.epoch).await);
        assert_eq!(
            epoch_manager.events(),
            vec![EpochEvent::Enter {
                epoch: state.epoch,
                public: state.output.public().clone(),
                share: None,
                participants: state.dealers().clone(),
            }]
        );

        report_finalized_header(&mut mailbox, header(Height::new(10))).await;

        assert!(!has_dealer_log(&mailbox, state.epoch).await);
        assert_eq!(sender.send_count(), state.players().len() - 1);

        report_finalized_header(&mut mailbox, header(Height::new(15))).await;

        assert!(has_dealer_log(&mailbox, state.epoch).await);

        report_finalized_header(&mut mailbox, header(Height::new(16))).await;

        assert_eq!(
            sender.send_count(),
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

        report_finalized_header(&mut mailbox, boundary).await;

        assert!(!has_dealer_log(&mailbox, state.epoch.next()).await);
        assert_eq!(
            epoch_manager.events(),
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

        drop(mailbox);
        handle
            .await
            .expect("actor should stop when its mailbox closes");
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

        let (first_actor, mut first_mailbox) = init(
            context.child("first_actor"),
            config(
                first.clone(),
                FixedEpocher::new(NonZeroU64::new(10).unwrap()),
                Height::new(9),
                "actor_exchange_first",
                execution.clone(),
                StubMarshal::default(),
                StubEpochManager::default(),
            ),
        )
        .await
        .unwrap();

        let (second_actor, mut second_mailbox) = init(
            context.child("second_actor"),
            config(
                second.clone(),
                FixedEpocher::new(NonZeroU64::new(10).unwrap()),
                Height::new(9),
                "actor_exchange_second",
                execution.clone(),
                StubMarshal::default(),
                StubEpochManager::default(),
            ),
        )
        .await
        .unwrap();

        let network = TestNetwork::default();
        let first_channel = network.register(first_public.clone());
        let first_handle = first_actor.start(first_channel);
        let second_channel = network.register(second_public.clone());
        let second_handle = second_actor.start(second_channel);

        assert!(!has_dealer_log(&first_mailbox, state.epoch).await);
        assert!(!has_dealer_log(&second_mailbox, state.epoch).await);

        // Synchronize first with the player receiving the dealing, then with
        // the dealer receiving its ACK.
        report_finalized_header(&mut first_mailbox, header(Height::new(10))).await;
        assert!(!has_dealer_log(&second_mailbox, state.epoch).await);
        assert!(!has_dealer_log(&first_mailbox, state.epoch).await);

        // Apply the same ordering in the opposite direction. Once these calls
        // return, both ACKs have been processed and persisted.
        report_finalized_header(&mut second_mailbox, header(Height::new(10))).await;
        assert!(!has_dealer_log(&first_mailbox, state.epoch).await);
        assert!(!has_dealer_log(&second_mailbox, state.epoch).await);
        assert_eq!(
            (
                network.deliveries_between(&first_public, &second_public),
                network.deliveries_between(&second_public, &first_public),
            ),
            (2, 2),
            "each actor should send a dealing and return an ACK"
        );

        drop(first_mailbox);
        drop(second_mailbox);
        first_handle.await.expect("first actor should stop");
        second_handle.await.expect("second actor should stop");

        let deliveries_before_restart = (
            network.deliveries_between(&first_public, &second_public),
            network.deliveries_between(&second_public, &first_public),
        );

        let (first_actor, mut first_mailbox) = init(
            context.child("first_actor_restart"),
            config(
                first,
                FixedEpocher::new(NonZeroU64::new(10).unwrap()),
                Height::new(10),
                "actor_exchange_first",
                execution.clone(),
                StubMarshal::default(),
                StubEpochManager::default(),
            ),
        )
        .await
        .unwrap();

        let (second_actor, mut second_mailbox) = init(
            context.child("second_actor_restart"),
            config(
                second,
                FixedEpocher::new(NonZeroU64::new(10).unwrap()),
                Height::new(10),
                "actor_exchange_second",
                execution,
                StubMarshal::default(),
                StubEpochManager::default(),
            ),
        )
        .await
        .unwrap();

        let first_handle = first_actor.start(network.register(first_public.clone()));
        let second_handle = second_actor.start(network.register(second_public.clone()));

        assert!(!has_dealer_log(&first_mailbox, state.epoch).await);
        assert!(!has_dealer_log(&second_mailbox, state.epoch).await);
        report_finalized_header(&mut first_mailbox, header(Height::new(11))).await;
        report_finalized_header(&mut second_mailbox, header(Height::new(11))).await;

        // Round trips after both updates ensure any resulting network messages
        // have been handled before inspecting the transport.
        assert!(!has_dealer_log(&first_mailbox, state.epoch).await);
        assert!(!has_dealer_log(&second_mailbox, state.epoch).await);
        assert_eq!(
            (
                network.deliveries_between(&first_public, &second_public),
                network.deliveries_between(&second_public, &first_public),
            ),
            deliveries_before_restart,
            "restarted actors must not redistribute shares already acknowledged"
        );

        report_finalized_header(&mut first_mailbox, header(Height::new(15))).await;
        report_finalized_header(&mut second_mailbox, header(Height::new(15))).await;
        assert!(has_dealer_log(&first_mailbox, state.epoch).await);
        assert!(has_dealer_log(&second_mailbox, state.epoch).await);

        drop(first_mailbox);
        drop(second_mailbox);
        first_handle.await.expect("first actor should stop");
        second_handle.await.expect("second actor should stop");
    });
}

#[test]
fn outcome_requests_use_reshare_fallback_and_require_next_players() {
    Runner::default().start(|mut context| async move {
        let execution = StubExecutionProvider::default();
        execution.fail_next_full_dkg_epoch();

        let (state, _) = full_dkg_state(&mut context, Epoch::new(1), 4);
        execution.set_next_players(state.players().clone());
        execution.add_header(outcome_header(Height::new(9), &state));

        let (actor, mut mailbox) = init(
            context.child("actor"),
            config(
                PrivateKey::from_seed(0),
                FixedEpocher::new(NonZeroU64::new(10).unwrap()),
                Height::new(9),
                "outcome_execution_dependencies",
                execution.clone(),
                StubMarshal::default(),
                StubEpochManager::default(),
            ),
        )
        .await
        .unwrap();

        let handle = actor.start((RecordingSender::default(), InertReceiver));

        assert!(!has_dealer_log(&mailbox, state.epoch).await);

        report_finalized_header(&mut mailbox, header(Height::new(10))).await;
        report_finalized_header(&mut mailbox, header(Height::new(11))).await;

        let outcome = mailbox
            .get_dkg_outcome(Digest(B256::repeat_byte(1)), Height::new(10))
            .await
            .unwrap();

        assert_eq!(outcome.epoch, state.epoch.next());

        // The incomplete ceremony fails forward by carrying the prior output
        // into the next epoch.
        assert_eq!(outcome.output, state.output);
        assert_eq!(outcome.next_players, state.players);
        assert!(!outcome.is_next_full_dkg);

        execution.fail_next_players();

        assert!(
            mailbox
                .get_dkg_outcome(Digest(B256::repeat_byte(2)), Height::new(10))
                .await
                .is_err()
        );

        assert!(
            !has_dealer_log(&mailbox, state.epoch).await,
            "next-player lookup failure must not terminate the actor"
        );

        drop(mailbox);
        handle
            .await
            .expect("actor should stop when its mailbox closes");
    });
}
