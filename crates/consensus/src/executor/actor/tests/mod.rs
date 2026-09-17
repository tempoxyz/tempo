use alloy_primitives::B256;
use commonware_consensus::{
    simplex::types::Context,
    types::{Height, View},
};
use commonware_runtime::{Runner as _, deterministic};
use futures::{StreamExt as _, executor::block_on};

use commonware_consensus::Heightable as _;

use super::{ExecutionTask, ExecutionTaskOutcome, ExecutionTaskType, Verification, WalkOwner};
use crate::consensus::Digest;

mod harness;

mod arbitration;
mod backfill;
mod build;
mod convergence;
mod finalization;
mod forkchoice;
mod metrics;
mod scheduling;
mod verify;
mod walk;

use super::super::Actor;
use crate::executor::ingress::Build;
use harness::{FakeExecution, FakeMarshal, GENESIS, attributes, make_block, round};

#[test]
fn execution_task_finishes_with_an_outcome() {
    let mut task = ExecutionTask::new(
        ExecutionTaskType::Verify,
        futures::future::ready(ExecutionTaskOutcome::Delivered {
            owner: WalkOwner::Verification(round(1)),
            digest: make_block(1, 1, GENESIS).digest(),
            finalized_round: round(0),
            status: Err(eyre::eyre!("delivery failed")),
        }),
    );

    assert!(matches!(task.task_type, ExecutionTaskType::Verify));
    let finished = block_on(&mut task);
    assert!(matches!(finished.task_type, ExecutionTaskType::Verify));
    assert!(matches!(
        finished.outcome,
        ExecutionTaskOutcome::Delivered { .. }
    ));
}

#[test]
fn delivery_count_resets_only_after_a_successful_forkchoice_response() {
    deterministic::Runner::default().start(|context| async move {
        let parent = make_block(1, 1, GENESIS);
        let digest = parent.digest();
        let execution = FakeExecution::new();
        execution.seed_canonical_block(&parent);
        let (mut actor, mailbox) = crate::executor::init(
            context,
            crate::executor::Config {
                execution_node: execution.clone(),
                marshal: FakeMarshal::new(),
                finalized_floor: Height::zero(),
                finalized_tip: (round(1), Height::new(1), digest),
                fcu_heartbeat_interval: std::time::Duration::from_secs(3600),
                public_key: None,
            },
        )
        .unwrap();

        // Scheduling an FCU does not settle the preceding deliveries.
        actor.delivered_finalized = (Height::new(1), digest);
        actor.deliveries_since_forkchoice = 7;
        assert!(actor.start_forkchoice_update());
        assert_eq!(actor.deliveries_since_forkchoice, 7);
        let finished = (&mut actor.execution_task).await;
        actor.handle_execution_task_finished(finished).unwrap();
        assert_eq!(actor.deliveries_since_forkchoice, 0);

        // A heartbeat settles deliveries even when forkchoice is unchanged.
        actor.deliveries_since_forkchoice = 3;
        actor.send_forkchoice_update_heartbeat();
        assert_eq!(actor.deliveries_since_forkchoice, 3);
        let finished = (&mut actor.execution_task).await;
        assert!(matches!(finished.task_type, ExecutionTaskType::Heartbeat));
        actor.handle_execution_task_finished(finished).unwrap();
        assert_eq!(actor.deliveries_since_forkchoice, 0);
        assert_eq!(execution.fcus(), vec![(digest, digest, false); 2]);

        // Execution finality advances beyond the actor's tracked state.
        // A build still delivers its parent, but its FCU is skipped.
        let tip = make_block(2, 2, digest);
        execution.seed_canonical_block(&tip);
        execution.set_finalized(2, tip.digest());
        actor.deliveries_since_forkchoice = 3;
        let build = mailbox
            .build_proposal(
                Context {
                    round: round(2),
                    leader: tempo_primitives::ed25519::PublicKey::from_seed(42).to_inner(),
                    parent: (View::new(1), digest),
                },
                attributes(),
            )
            .unwrap();
        let message = actor.mailbox.next().await.unwrap();
        actor.handle_message(message);
        actor.start_next_execution_task();
        let finished = (&mut actor.execution_task).await;
        assert!(matches!(finished.task_type, ExecutionTaskType::Build));
        actor.handle_execution_task_finished(finished).unwrap();
        assert!(build.await.is_err());
        assert_eq!(execution.new_payloads(), vec![digest]);
        assert_eq!(execution.fcus(), vec![(digest, digest, false); 2]);
        assert_eq!(actor.deliveries_since_forkchoice, 4);
    });
}

#[test]
fn verifications_queue_per_round_and_builds_keep_their_own_slot() {
    fn verification(view: u64, height: u64) -> Verification {
        let (response, _rx) = futures::channel::oneshot::channel();
        Verification::new(
            round(view),
            tracing::Span::none(),
            make_block(view, height, Digest(B256::ZERO)).into(),
            response,
        )
    }

    fn build(view: u64) -> Box<Build> {
        let (response, _rx) = futures::channel::oneshot::channel();
        Box::new(Build {
            context: Context {
                round: round(view),
                leader: tempo_primitives::ed25519::PublicKey::from_seed(42).to_inner(),
                parent: (View::new(view.saturating_sub(1)), GENESIS),
            },
            attributes: Box::new(attributes()),
            response,
        })
    }

    fn queued_build_round<C, E, M>(actor: &Actor<C, E, M>) -> Option<u64> {
        actor
            .pending_build
            .as_ref()
            .map(|(round, ..)| round.view().get())
    }

    fn queued_rounds<C, E, M>(actor: &Actor<C, E, M>) -> Vec<u64> {
        actor
            .queued_verifications
            .keys()
            .map(|round| round.view().get())
            .collect()
    }

    deterministic::Runner::default().start(|context| async move {
        let (mut actor, _mailbox) = crate::executor::init(
            context,
            crate::executor::Config {
                execution_node: FakeExecution::new(),
                marshal: FakeMarshal::new(),
                finalized_floor: Height::new(0),
                finalized_tip: (round(0), Height::new(0), GENESIS),
                fcu_heartbeat_interval: std::time::Duration::from_secs(3600),
                public_key: None,
            },
        )
        .expect("actor should initialize");

        // Verifications from different rounds queue side by side, in any order.
        actor.queue_verification(verification(2, 2));
        actor.queue_verification(verification(1, 1));
        assert_eq!(queued_rounds(&actor), vec![1, 2]);

        // One for the same round replaces the pending one.
        actor.queue_verification(verification(2, 20));
        assert_eq!(queued_rounds(&actor), vec![1, 2]);
        assert_eq!(
            actor.queued_verifications[&round(2)]
                .walk
                .target
                .height()
                .get(),
            20
        );

        // Builds keep their own slot: the latest request replaces the queued
        // one whatever its round, and verifications never touch it.
        actor.queue_build(round(1), tracing::Span::none(), build(1));
        assert_eq!(queued_build_round(&actor), Some(1));
        actor.queue_build(round(3), tracing::Span::none(), build(3));
        assert_eq!(queued_build_round(&actor), Some(3));
        actor.queue_build(round(2), tracing::Span::none(), build(2));
        assert_eq!(queued_build_round(&actor), Some(2));
        actor.queue_verification(verification(4, 4));
        assert_eq!(queued_build_round(&actor), Some(2));
        assert_eq!(queued_rounds(&actor), vec![1, 2, 4]);
    });
}
