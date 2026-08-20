use alloy_primitives::B256;
use commonware_consensus::types::{Height, Round};
use futures::executor::block_on;

use commonware_consensus::Heightable as _;

use super::{
    ConsensusRequest, ExecutionTask, ExecutionTaskOutcome, ExecutionTaskType, VerifyBlockRequest,
    notarized_tree::LocalState, queue_consensus_request,
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

use harness::{make_block, round};

#[test]
fn execution_task_finishes_with_an_outcome() {
    let state = LocalState {
        head: (Height::new(1), Digest(B256::repeat_byte(1))),
        finalized: (Height::new(0), Digest(B256::ZERO)),
    };
    let mut task = ExecutionTask::new(
        ExecutionTaskType::Verify,
        state,
        futures::future::ready(ExecutionTaskOutcome::Completed {
            canonicalized: None,
            payload_job: None,
        }),
    );

    assert!(matches!(task.task_type, ExecutionTaskType::Verify));
    assert_eq!(task.on_top_of, state);
    let finished = block_on(&mut task);
    assert!(matches!(finished.task_type, ExecutionTaskType::Verify));
    assert_eq!(finished.on_top_of, state);
    assert!(matches!(
        finished.outcome,
        ExecutionTaskOutcome::Completed { .. }
    ));
}

#[test]
fn consensus_requests_from_stale_rounds_are_dropped() {
    // The queue logic is agnostic to the request kind; validation requests
    // stand in for both.
    fn validate_request(view: u64, height: u64) -> ConsensusRequest {
        let (response, _rx) = futures::channel::oneshot::channel();
        ConsensusRequest::Verify(VerifyBlockRequest {
            cause: tracing::Span::none(),
            block: make_block(view, height, Digest(B256::ZERO)).into(),
            validator_set: None,
            response,
        })
    }

    fn queued_height(slot: &Option<(Round, ConsensusRequest)>) -> Option<u64> {
        slot.as_ref().map(|(_, request)| match request {
            ConsensusRequest::Verify(validate) => validate.block.height().get(),
            ConsensusRequest::Build { .. } => unreachable!("test only queues validations"),
        })
    }

    let mut slot = None;
    queue_consensus_request(&mut slot, round(2), validate_request(2, 2));
    assert_eq!(queued_height(&slot), Some(2));

    // Older and same rounds are dropped.
    queue_consensus_request(&mut slot, round(1), validate_request(1, 1));
    assert_eq!(queued_height(&slot), Some(2));
    queue_consensus_request(&mut slot, round(2), validate_request(2, 20));
    assert_eq!(queued_height(&slot), Some(2));

    // Newer rounds supersede.
    queue_consensus_request(&mut slot, round(3), validate_request(3, 3));
    assert_eq!(queued_height(&slot), Some(3));
}
