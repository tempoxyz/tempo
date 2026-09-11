use alloy_primitives::B256;
use commonware_consensus::types::{Height, Round};
use commonware_runtime::{Runner as _, deterministic};
use futures::executor::block_on;

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
mod metrics;
mod scheduling;
mod verify;
mod walk;

use harness::{FakeExecution, FakeMarshal, GENESIS, make_block, round};

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
