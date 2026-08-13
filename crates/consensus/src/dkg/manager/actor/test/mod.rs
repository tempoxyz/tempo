//! Standalone DKG manager actor tests.

mod utils;

use std::{
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
};

use alloy_primitives::B256;
use commonware_codec::Encode as _;
use commonware_consensus::{
    Reporter as _,
    marshal::Update,
    types::{Epoch, FixedEpocher, Height},
};
use commonware_cryptography::ed25519::PrivateKey;
use commonware_runtime::{
    Runner as _, Supervisor as _,
    deterministic::{Context, Runner as DeterministicRunner},
};
use commonware_utils::{Acknowledgement as _, acknowledgement::Exact};
use futures::channel::mpsc;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;

use super::{
    super::{Config, Mailbox, init},
    state::Storage as DkgStorage,
    *,
};
use utils::{
    EpochEvent, InertReceiver, RecordingSender, StubEpochManager, StubExecutionProvider,
    StubMarshal, TestNetwork, block, dkg_state, full_dkg_state, header,
};

fn config(
    me: PrivateKey,
    last_finalized_height: Height,
    partition_prefix: &str,
    execution_provider: StubExecutionProvider,
    marshal: StubMarshal,
    epoch_manager: StubEpochManager,
) -> Config<StubExecutionProvider, StubMarshal, StubEpochManager> {
    Config {
        epoch_strategy: FixedEpocher::new(NonZeroU64::new(10).unwrap()),
        epoch_manager,
        namespace: crate::config::NAMESPACE.to_vec(),
        me,
        mailbox_size: NonZeroUsize::new(1).unwrap(),
        marshal,
        last_finalized_height,
        partition_prefix: partition_prefix.to_string(),
        execution_provider,
        initial_share: None,
    }
}

async fn actor(
    context: Context,
    last_finalized_height: Height,
    execution_provider: StubExecutionProvider,
    marshal: StubMarshal,
    epoch_manager: StubEpochManager,
) -> Actor<Context, StubExecutionProvider, StubMarshal, StubEpochManager> {
    let (_mailbox, receiver) = mpsc::unbounded();
    Actor::new(
        config(
            PrivateKey::from_seed(0),
            last_finalized_height,
            "dkg_actor_test",
            execution_provider,
            marshal,
            epoch_manager,
        ),
        context,
        receiver,
    )
    .await
    .unwrap()
}

async fn storage(
    context: Context,
    partition_prefix: &'static str,
    initial_state: State,
) -> DkgStorage<Context> {
    let storage = state::builder()
        .partition_prefix(partition_prefix)
        .init_unverified(context)
        .await
        .unwrap();
    storage.init_verified(initial_state).await.unwrap()
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

fn outcome_header(height: Height, state: &State) -> TempoHeader {
    let outcome = OnchainDkgOutcome {
        epoch: state.epoch,
        output: state.output.clone(),
        next_players: state.players().clone(),
        is_next_full_dkg: state.is_full_dkg,
    };

    let mut header = header(height);
    header.inner.extra_data = outcome.encode().into();
    header
}

#[test]
fn prepopulation_replays_only_missing_headers() {
    DeterministicRunner::default().start(|mut context| async move {
        let execution = StubExecutionProvider::default();
        execution.add_header(header(Height::new(10)));
        execution.add_header(header(Height::new(11)));

        let marshal = StubMarshal::default();
        marshal.add_block(block(header(Height::new(12))));

        let actor = actor(
            context.child("actor"),
            Height::new(12),
            execution.clone(),
            marshal.clone(),
            StubEpochManager::default(),
        )
        .await;

        let mut storage = storage(
            context.child("storage"),
            "prepopulation_missing_range",
            dkg_state(&mut context, Epoch::new(1)),
        )
        .await;

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
    DeterministicRunner::default().start(|mut context| async move {
        let behind_execution = StubExecutionProvider::default();
        let behind_state = dkg_state(&mut context, Epoch::zero());
        behind_execution.add_header(outcome_header(Height::new(9), &behind_state));

        let (behind_actor, _mailbox) = init(
            context.child("behind_actor_run"),
            config(
                PrivateKey::from_seed(0),
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
        let ahead_actor = actor(
            context.child("ahead_actor"),
            Height::new(8),
            execution.clone(),
            marshal.clone(),
            StubEpochManager::default(),
        )
        .await;

        let mut ahead_storage = storage(
            context.child("ahead_storage"),
            "prepopulation_ahead",
            dkg_state(&mut context, Epoch::new(1)),
        )
        .await;

        ahead_actor
            .prepopulate_to_last_finalized_height(&mut ahead_storage)
            .await
            .unwrap();

        assert!(execution.reads().is_empty());
        assert!(marshal.reads().is_empty());
    });
}

#[test]
fn prepopulation_fails_when_required_header_is_unavailable() {
    DeterministicRunner::default().start(|mut context| async move {
        let actor = actor(
            context.child("actor"),
            Height::new(10),
            StubExecutionProvider::default(),
            StubMarshal::default(),
            StubEpochManager::default(),
        )
        .await;

        let mut storage = storage(
            context.child("storage"),
            "prepopulation_missing_header",
            dkg_state(&mut context, Epoch::new(1)),
        )
        .await;

        let error = actor
            .prepopulate_to_last_finalized_height(&mut storage)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("height `10`"));
    });
}

#[test]
fn epoch_phases_distribute_then_finalize_without_redistributing() {
    DeterministicRunner::default().start(|mut context| async move {
        let (state, _) = full_dkg_state(&mut context, Epoch::new(1), 4);

        let execution = StubExecutionProvider::default();
        execution.add_header(outcome_header(Height::new(9), &state));

        let epoch_manager = StubEpochManager::default();
        let (actor, mut mailbox) = init(
            context.child("actor"),
            config(
                PrivateKey::from_seed(0),
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
        assert!(mailbox.get_dealer_log(state.epoch).await.unwrap().is_none());
        assert_eq!(
            epoch_manager.events(),
            vec![EpochEvent::Enter {
                epoch: state.epoch,
                public: state.output.public().clone(),
                has_share: false,
                participants: state.dealers().clone(),
            }]
        );

        report_finalized_header(&mut mailbox, header(Height::new(10))).await;

        assert!(mailbox.get_dealer_log(state.epoch).await.unwrap().is_none());
        assert_eq!(sender.send_count(), state.players().len() - 1);

        report_finalized_header(&mut mailbox, header(Height::new(15))).await;

        assert!(mailbox.get_dealer_log(state.epoch).await.unwrap().is_some());

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

        assert!(
            mailbox
                .get_dealer_log(state.epoch.next())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            epoch_manager.events(),
            vec![
                EpochEvent::Enter {
                    epoch: state.epoch,
                    public: state.output.public().clone(),
                    has_share: false,
                    participants: state.dealers().clone(),
                },
                EpochEvent::Exit(state.epoch),
                EpochEvent::Enter {
                    epoch: state.epoch.next(),
                    public: state.output.public().clone(),
                    has_share: false,
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
    DeterministicRunner::default().start(|mut context| async move {
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

        assert!(
            first_mailbox
                .get_dealer_log(state.epoch)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            second_mailbox
                .get_dealer_log(state.epoch)
                .await
                .unwrap()
                .is_none()
        );

        // Synchronize first with the player receiving the dealing, then with
        // the dealer receiving its ACK.
        report_finalized_header(&mut first_mailbox, header(Height::new(10))).await;
        assert!(
            second_mailbox
                .get_dealer_log(state.epoch)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            first_mailbox
                .get_dealer_log(state.epoch)
                .await
                .unwrap()
                .is_none()
        );

        // Apply the same ordering in the opposite direction. Once these calls
        // return, both ACKs have been processed and persisted.
        report_finalized_header(&mut second_mailbox, header(Height::new(10))).await;
        assert!(
            first_mailbox
                .get_dealer_log(state.epoch)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            second_mailbox
                .get_dealer_log(state.epoch)
                .await
                .unwrap()
                .is_none()
        );
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

        assert!(
            first_mailbox
                .get_dealer_log(state.epoch)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            second_mailbox
                .get_dealer_log(state.epoch)
                .await
                .unwrap()
                .is_none()
        );
        report_finalized_header(&mut first_mailbox, header(Height::new(11))).await;
        report_finalized_header(&mut second_mailbox, header(Height::new(11))).await;

        // Round trips after both updates ensure any resulting network messages
        // have been handled before inspecting the transport.
        assert!(
            first_mailbox
                .get_dealer_log(state.epoch)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            second_mailbox
                .get_dealer_log(state.epoch)
                .await
                .unwrap()
                .is_none()
        );
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
        assert!(
            first_mailbox
                .get_dealer_log(state.epoch)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            second_mailbox
                .get_dealer_log(state.epoch)
                .await
                .unwrap()
                .is_some()
        );

        drop(first_mailbox);
        drop(second_mailbox);
        first_handle.await.expect("first actor should stop");
        second_handle.await.expect("second actor should stop");
    });
}

#[test]
fn outcome_requests_use_reshare_fallback_and_require_next_players() {
    DeterministicRunner::default().start(|mut context| async move {
        let execution = StubExecutionProvider::default();
        execution.fail_next_full_dkg_epoch();

        let (state, _) = full_dkg_state(&mut context, Epoch::new(1), 4);
        execution.set_next_players(state.players().clone());

        execution.add_header(outcome_header(Height::new(9), &state));

        let (actor, mut mailbox) = init(
            context.child("actor"),
            config(
                PrivateKey::from_seed(0),
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

        assert!(mailbox.get_dealer_log(state.epoch).await.unwrap().is_none());

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
            mailbox.get_dealer_log(state.epoch).await.unwrap().is_none(),
            "next-player lookup failure must not terminate the actor"
        );

        drop(mailbox);
        handle
            .await
            .expect("actor should stop when its mailbox closes");
    });
}
