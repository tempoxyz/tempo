use alloy_primitives::B256;
use commonware_consensus::{
    simplex::types::Context,
    types::{Height, Round, View},
};
use commonware_runtime::{Runner as _, deterministic};
use futures::{StreamExt as _, executor::block_on};

use commonware_consensus::Heightable as _;

use super::{
    ConsensusRequest, ExecutionTask, ExecutionTaskOutcome, ExecutionTaskType, PendingVerification,
    WalkOwner,
};
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
fn consensus_requests_from_stale_rounds_are_dropped() {
    fn validate_request(view: u64, height: u64) -> ConsensusRequest {
        let (response, _rx) = futures::channel::oneshot::channel();
        ConsensusRequest::Verify(PendingVerification::new(
            tracing::Span::none(),
            make_block(view, height, Digest(B256::ZERO)).into(),
            response,
        ))
    }

    fn queued_height(slot: &Option<(Round, ConsensusRequest)>) -> Option<u64> {
        slot.as_ref().map(|(_, request)| match request {
            ConsensusRequest::Verify(pending) => pending.candidate().height().get(),
            ConsensusRequest::Build { .. } => unreachable!("test only queues validations"),
        })
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

        actor.queue_consensus_request(round(2), validate_request(2, 2));
        assert_eq!(queued_height(&actor.pending_consensus_request), Some(2));

        // Older and same rounds are dropped.
        actor.queue_consensus_request(round(1), validate_request(1, 1));
        assert_eq!(queued_height(&actor.pending_consensus_request), Some(2));
        actor.queue_consensus_request(round(2), validate_request(2, 20));
        assert_eq!(queued_height(&actor.pending_consensus_request), Some(2));

        // Newer rounds supersede.
        actor.queue_consensus_request(round(3), validate_request(3, 3));
        assert_eq!(queued_height(&actor.pending_consensus_request), Some(3));
    });
}
