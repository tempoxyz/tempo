//! Scenario tests for the finalization pipeline: finalized blocks arriving
//! from the marshal actor are forwarded to the execution layer as
//! `newPayload` + `forkchoiceUpdated` pairs, in order, and acknowledged
//! only once the execution layer accepted them.

use alloy_rpc_types_engine::{ForkchoiceState, PayloadStatusEnum};
use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, deterministic};
use tempo_primitives::ed25519::PublicKey;

use super::harness::{
    ElCall, ForkchoiceStateExt as _, GENESIS, Harness, HarnessOptions, make_block,
    make_block_with_proposer, round,
};

fn finalized_blocks_proposed_by_self(h: &Harness) -> u64 {
    h.metrics()
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(' ')?;
            (name == "executor_finalized_blocks_proposed_by_self_total")
                .then(|| value.parse().expect("counter should contain an integer"))
        })
        .expect("self-proposed finalization counter should be published")
}

#[test_traced]
fn finalized_block_without_local_public_key_is_forwarded_and_acknowledged() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        let block = make_block(1, 1, GENESIS);
        let digest = block.digest();
        h.deliver_tip(round(1), 1, digest);
        h.deliver_finalized(block)
            .await
            .expect("valid finalized block should be acknowledged");

        assert_eq!(h.execution.new_payloads(), vec![digest]);
        assert_eq!(h.execution.fcus(), vec![(digest, digest, false)]);
        assert_eq!(h.execution.head(), digest);
        assert_eq!(h.execution.finalized(), Some((1, digest)));
        assert_eq!(finalized_blocks_proposed_by_self(&h), 0);
    });
}

#[test_traced]
fn finalized_blocks_are_forwarded_in_order() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let b3 = make_block(3, 3, b2.digest());
        let digests = [b1.digest(), b2.digest(), b3.digest()];

        h.deliver_tip(round(3), 3, b3.digest());
        let w1 = h.deliver_finalized(b1);
        let w2 = h.deliver_finalized(b2);
        let w3 = h.deliver_finalized(b3);
        w1.await.expect("first block should be acknowledged");
        w2.await.expect("second block should be acknowledged");
        w3.await.expect("third block should be acknowledged");

        assert_eq!(h.execution.new_payloads(), digests);
        assert_eq!(
            h.execution.fcus(),
            digests.map(|d| (d, d, false)).to_vec(),
            "every finalized block must advance head and finalized together",
        );
        assert_eq!(h.execution.finalized(), Some((3, digests[2])));
    });
}

#[test_traced]
fn syncing_finalized_block_is_postponed_and_retried_in_order() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let (d1, d2) = (b1.digest(), b2.digest());

        // The execution layer reports SYNCING once (e.g. while rebuilding
        // indices); the block must be retried, and the block queued behind
        // it must stay behind it.
        h.execution
            .script_new_payload(d1, Ok(PayloadStatusEnum::Syncing));
        h.execution
            .script_new_payload(d1, Ok(PayloadStatusEnum::Valid));

        h.deliver_tip(round(2), 2, d2);
        let w1 = h.deliver_finalized(b1);
        let w2 = h.deliver_finalized(b2);
        w1.await
            .expect("postponed block should still be acknowledged");
        w2.await.expect("queued block should be acknowledged");

        assert_eq!(
            h.execution.new_payloads(),
            vec![d1, d1, d2],
            "the postponed block is retried before the queued one is forwarded",
        );
        assert_eq!(h.execution.finalized(), Some((2, d2)));
    });
}

#[test_traced]
fn invalid_finalized_block_is_fatal() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        h.execution.script_new_payload(
            b1.digest(),
            Ok(PayloadStatusEnum::Invalid {
                validation_error: "bad block".into(),
            }),
        );

        h.deliver_tip(round(1), 1, b1.digest());
        h.deliver_finalized(b1)
            .await
            .expect_err("an invalid finalized block must not be acknowledged");

        h.actor
            .await
            .expect("actor should shut down cleanly on a fatal error");
        assert_eq!(
            h.execution.fcus(),
            vec![],
            "no forkchoice update may follow"
        );
    });
}

#[test_traced]
fn accepted_finalized_block_is_fatal() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        h.execution
            .script_new_payload(d1, Ok(PayloadStatusEnum::Accepted));

        h.deliver_tip(round(1), 1, d1);
        h.deliver_finalized(b1)
            .await
            .expect_err("an unexecuted finalized payload must not be acknowledged");

        h.actor
            .await
            .expect("actor should shut down cleanly on a fatal error");
        assert_eq!(h.execution.new_payloads(), vec![d1]);
        assert!(
            h.execution.fcus().is_empty(),
            "ACCEPTED does not prove execution, so no forkchoice update may follow",
        );
    });
}

#[test_traced]
fn new_payload_transport_error_is_fatal() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        h.execution
            .script_new_payload(b1.digest(), Err("connection closed"));

        h.deliver_tip(round(1), 1, b1.digest());
        h.deliver_finalized(b1)
            .await
            .expect_err("a transport failure must not acknowledge the finalized block");

        h.actor
            .await
            .expect("actor should shut down cleanly on a finalization transport error");
        assert!(h.execution.fcus().is_empty());
    });
}

#[test_traced]
fn canonical_block_lookup_error_is_fatal() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        h.execution
            .script_canonical_block_hash(1, Err("database unavailable"));

        h.deliver_tip(round(1), 1, b1.digest());
        h.deliver_finalized(b1)
            .await
            .expect_err("a canonical lookup failure must not acknowledge the finalized block");

        h.actor
            .await
            .expect("actor should shut down cleanly on a canonical lookup error");
        assert!(h.execution.new_payloads().is_empty());
        assert!(h.execution.fcus().is_empty());
    });
}

#[test_traced]
fn rejected_finalization_forkchoice_update_is_fatal() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        h.execution.script_fcu(
            ForkchoiceState::from_finalized_head(d1, d1),
            [Ok(PayloadStatusEnum::Invalid {
                validation_error: "rejected".into(),
            })],
        );

        // newPayload succeeds by default. Rejecting the following FCU must
        // still cancel, rather than resolve, the acknowledgement waiter.
        h.deliver_tip(round(1), 1, d1);
        h.deliver_finalized(b1)
            .await
            .expect_err("the block must not be acknowledged when its FCU fails");

        h.actor
            .await
            .expect("actor should shut down cleanly on a fatal error");
        assert_eq!(h.execution.new_payloads(), vec![d1]);
        assert_eq!(
            h.execution.fcus(),
            vec![(d1, d1, false)],
            "the rejected FCU must have followed a successful new-payload request",
        );
    });
}

#[test_traced]
fn forkchoice_update_transport_error_is_fatal() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        h.execution.script_fcu(
            ForkchoiceState::from_finalized_head(d1, d1),
            [Err("connection closed")],
        );

        h.deliver_tip(round(1), 1, d1);
        h.deliver_finalized(b1)
            .await
            .expect_err("an FCU transport failure must not acknowledge the finalized block");

        h.actor
            .await
            .expect("actor should shut down cleanly on a finalization FCU transport error");
        assert_eq!(h.execution.new_payloads(), vec![d1]);
        assert_eq!(h.execution.fcus(), vec![(d1, d1, false)]);
        assert_eq!(h.execution.finalized(), None);
    });
}

#[test_traced]
fn finalized_block_below_the_tracked_state_is_fatal() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        h.deliver_tip(round(2), 2, b2.digest());
        h.deliver_finalized(b1.clone())
            .await
            .expect("first block should be acknowledged");
        h.deliver_finalized(b2)
            .await
            .expect("second block should be acknowledged");

        // Delivering a block below the tracked finalized height violates
        // the in-order delivery protocol.
        h.deliver_finalized(b1)
            .await
            .expect_err("a block below the tracked finalized state must not be acknowledged");

        h.actor
            .await
            .expect("actor should shut down cleanly on a fatal error");
    });
}

#[test_traced]
fn conflicting_finalized_block_at_the_tracked_height_is_fatal() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        h.deliver_tip(round(1), 1, b1.digest());
        h.deliver_finalized(b1)
            .await
            .expect("first block should be acknowledged");

        // A different block finalized at the same height means consensus
        // failed fundamentally.
        let conflicting = make_block(9, 1, GENESIS);
        h.deliver_finalized(conflicting)
            .await
            .expect_err("a conflicting finalized block must not be acknowledged");

        h.actor
            .await
            .expect("actor should shut down cleanly on a fatal error");
    });
}

#[test_traced]
fn redelivered_finalized_block_at_the_tracked_state_is_acknowledged() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        h.deliver_tip(round(1), 1, b1.digest());
        h.deliver_finalized(b1.clone())
            .await
            .expect("first delivery should be acknowledged");

        // Marshal may re-deliver the block at the tracked state (e.g. a
        // replay across a restart); the executor acknowledges it without
        // treating it as progress.
        h.deliver_finalized(b1)
            .await
            .expect("the re-delivered block should be acknowledged");
        let d1 = make_block(1, 1, GENESIS).digest();
        assert_eq!(
            h.execution.calls(),
            vec![
                ElCall::NewPayload(d1),
                ElCall::Fcu {
                    head: d1,
                    finalized: d1,
                    with_attrs: false,
                },
                ElCall::NewPayload(d1),
                ElCall::Fcu {
                    head: d1,
                    finalized: d1,
                    with_attrs: false,
                },
            ],
            "a redelivery is re-checked and re-affirmed before acknowledgment",
        );
        assert_eq!(h.execution.finalized(), Some((1, d1)),);
    });
}

#[test_traced]
fn only_blocks_proposed_by_this_node_increment_the_metric() {
    deterministic::Runner::default().start(|context| async move {
        let local_proposer = PublicKey::from_seed(42);
        let other_proposer = PublicKey::from_seed(43);
        let mut h = Harness::builder()
            .harness_options(HarnessOptions {
                public_key: Some(local_proposer.to_inner()),
                ..Default::default()
            })
            .start(&context);

        let b1 = make_block_with_proposer(1, 1, GENESIS, local_proposer);
        let d1 = b1.digest();
        h.deliver_tip(round(1), 1, d1);
        h.deliver_finalized(b1)
            .await
            .expect("the locally proposed block should be acknowledged");
        assert_eq!(finalized_blocks_proposed_by_self(&h), 1);

        let b2 = make_block_with_proposer(2, 2, d1, other_proposer);
        let d2 = b2.digest();
        h.deliver_tip(round(2), 2, d2);
        h.deliver_finalized(b2)
            .await
            .expect("the block proposed by another node should be acknowledged");
        assert_eq!(
            finalized_blocks_proposed_by_self(&h),
            1,
            "another proposer's finalized block must not increment the counter",
        );
    });
}

#[test_traced]
fn finalizing_a_canonical_ancestor_leaves_the_head_untouched() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        // Converge the head onto b2 through the notarization pipeline, then
        // finalize b1. The head (b2) descends from the finalized block, so
        // only the finalized side of the forkchoice state may move.
        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let (d1, d2) = (b1.digest(), b2.digest());

        h.verify(round(1), b1.clone())
            .await
            .expect("b1 should validate")
            .expect("b1 should be valid");
        h.report_pending_head(2, 1, d1);
        h.wait_until(|| h.execution.head() == d1).await;

        h.verify(round(2), b2.clone())
            .await
            .expect("b2 should validate")
            .expect("b2 should be valid");
        h.report_pending_head(3, 2, d2);
        h.wait_until(|| h.execution.head() == d2).await;

        h.deliver_tip(round(1), 1, d1);
        h.deliver_finalized(b1)
            .await
            .expect("finalized ancestor should be acknowledged");

        assert_eq!(
            h.execution.fcus().last(),
            Some(&(d2, d1, false)),
            "the finalization must keep the descending head in place",
        );
        assert_eq!(h.execution.head(), d2);
        assert_eq!(h.execution.finalized(), Some((1, d1)));
    });
}

#[test_traced]
fn finalizing_a_conflicting_branch_moves_the_head() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        // The head sits on notarized block a1; the network finalizes b1 on
        // a different branch. The head must be moved onto the finalized
        // block.
        let a1 = make_block(1, 1, GENESIS);
        let b1 = make_block(2, 1, GENESIS);
        let (da1, db1) = (a1.digest(), b1.digest());

        h.verify(round(1), a1)
            .await
            .expect("a1 should validate")
            .expect("a1 should be valid");
        h.report_pending_head(2, 1, da1);
        h.wait_until(|| h.execution.head() == da1).await;

        h.deliver_tip(round(2), 1, db1);
        h.deliver_finalized(b1)
            .await
            .expect("the finalized branch should be acknowledged");

        assert_eq!(
            h.execution.fcus().last(),
            Some(&(db1, db1, false)),
            "the head must be moved onto the finalized branch",
        );
        assert_eq!(h.execution.head(), db1);
        assert_eq!(h.execution.finalized(), Some((1, db1)));
    });
}
