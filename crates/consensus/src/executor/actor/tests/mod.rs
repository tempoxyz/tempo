use alloy_primitives::B256;
use commonware_consensus::{
    simplex::types::Context,
    types::{Height, View},
};
use commonware_runtime::{Runner as _, deterministic};
use futures::executor::block_on;

use commonware_consensus::Heightable as _;

use super::{ExecutionTask, ExecutionTaskOutcome, ExecutionTaskType, Verification, WalkOwner};
use crate::consensus::Digest;

mod harness;

mod arbitration;
mod backfill;
mod build;
mod convergence;
mod finalization;
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
