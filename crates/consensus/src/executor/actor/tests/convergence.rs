//! Scenario tests for notarized-chain convergence: the executor drives the
//! execution layer's head onto the pending head reported by consensus,
//! fetching missing bodies from the marshal actor, and never runs ahead of
//! the finalization pipeline.

use std::time::Duration;

use alloy_rpc_types_engine::{ForkchoiceState, PayloadStatusEnum};
use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, deterministic};

use super::harness::{
    ForkchoiceStateExt as _, GENESIS, Harness, HarnessOptions, make_block, round,
};

#[test_traced]
fn pending_head_with_known_body_is_forwarded() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();

        // The validation request records the body; the pending-head report
        // marks it as the convergence target.
        h.verify(round(1), b1)
            .await
            .expect("verification should complete")
            .expect("block should be valid");
        h.report_pending_head(2, 1, d1);

        h.wait_until(|| h.execution.head() == d1).await;
        assert_eq!(
            h.execution.fcus().last(),
            Some(&(d1, GENESIS, false)),
            "convergence must move the head without touching the finalized tip",
        );
        assert!(
            h.marshal.subscribe_log().is_empty(),
            "the body was in hand; nothing may be fetched",
        );
    });
}

#[test_traced]
fn missing_ancestor_bodies_are_fetched_and_forwarded_bottom_up() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let b3 = make_block(3, 3, b2.digest());
        let (d1, d2, d3) = (b1.digest(), b2.digest(), b3.digest());

        // Only the pending head is known; every body on its ancestry is
        // missing and must be fetched, walking the path tip-down.
        h.report_pending_head(4, 3, d3);

        h.wait_until(|| h.marshal.fulfill_subscription(d3, b3.clone()))
            .await;
        h.wait_until(|| h.marshal.fulfill_subscription(d2, b2.clone()))
            .await;
        h.wait_until(|| h.marshal.fulfill_subscription(d1, b1.clone()))
            .await;

        h.wait_until(|| h.execution.head() == d3).await;
        assert_eq!(
            h.marshal.subscribe_log(),
            vec![(d3, round(3)), (d2, round(2)), (d1, round(1))],
            "gaps are discovered tip-down, one fetch at a time",
        );
        assert_eq!(
            h.execution.new_payloads(),
            vec![d1, d2, d3],
            "blocks are forwarded bottom-up",
        );
        assert_eq!(
            h.execution.fcus(),
            vec![
                (d1, GENESIS, false),
                (d2, GENESIS, false),
                (d3, GENESIS, false)
            ],
        );
    });
}

#[test_traced]
fn dropped_body_fetch_is_retried() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        h.report_pending_head(2, 1, d1);

        // Marshal gives up on the first subscription; the block is still on
        // the canonical notarized path, so the fetch must be re-issued.
        h.wait_until(|| h.marshal.drop_subscription(d1)).await;
        h.wait_until(|| h.marshal.subscribe_log().len() == 2).await;

        h.wait_until(|| h.marshal.fulfill_subscription(d1, b1.clone()))
            .await;
        h.wait_until(|| h.execution.head() == d1).await;
    });
}

#[test_traced]
fn stale_body_fetch_is_dropped_when_the_pending_head_moves() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let a1 = make_block(5, 1, GENESIS);
        let (d1, da1) = (b1.digest(), a1.digest());

        h.report_pending_head(2, 1, d1);
        h.wait_until(|| !h.marshal.open_subscriptions().is_empty())
            .await;

        // A newer context re-anchors the pending head onto a different
        // block; the in-flight fetch is now pointless and must be dropped
        // (nobody is required to serve a forked-out block).
        h.report_pending_head(6, 5, da1);
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(da1, round(5))])
            .await;

        assert!(
            !h.marshal.fulfill_subscription(d1, b1),
            "the stale subscription must have been dropped",
        );

        h.wait_until(|| h.marshal.fulfill_subscription(da1, a1.clone()))
            .await;
        h.wait_until(|| h.execution.head() == da1).await;
    });
}

#[test_traced]
fn rejected_notarized_block_is_withheld_then_retried() {
    deterministic::Runner::default().start(|context| async move {
        // Retries of rejected notarized blocks are driven by later events;
        // with nothing else going on, the FCU heartbeat is what re-runs the
        // scheduler, so the test gives it a short interval.
        let h = Harness::builder()
            .harness_options(HarnessOptions {
                fcu_heartbeat_interval: Duration::from_millis(200),
                ..Default::default()
            })
            .start(&context);

        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        h.execution.script_new_payload(
            d1,
            Ok(PayloadStatusEnum::Invalid {
                validation_error: "transient".into(),
            }),
        );
        h.execution
            .script_new_payload(d1, Ok(PayloadStatusEnum::Valid));

        h.report_pending_head(2, 1, d1);
        h.wait_until(|| h.marshal.fulfill_subscription(d1, b1.clone()))
            .await;

        // The forward is rejected; the block is withheld from retries.
        h.wait_until(|| h.execution.new_payloads() == vec![d1])
            .await;
        h.run_for(Duration::from_secs(5)).await;
        assert_eq!(
            h.execution.new_payloads(),
            vec![d1],
            "a rejected block must not be retried in a tight loop",
        );
        assert_eq!(h.execution.head(), GENESIS);

        // After the retry delay (10s) the block becomes forwardable again.
        h.run_for(Duration::from_secs(6)).await;
        h.wait_until(|| h.execution.head() == d1).await;
        assert_eq!(h.execution.new_payloads(), vec![d1, d1]);
    });
}

#[test_traced]
fn new_payload_transport_error_is_withheld_then_retried() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::builder()
            .harness_options(HarnessOptions {
                fcu_heartbeat_interval: Duration::from_millis(200),
                ..Default::default()
            })
            .start(&context);

        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        h.execution.script_new_payload(d1, Err("connection closed"));
        h.execution
            .script_new_payload(d1, Ok(PayloadStatusEnum::Valid));

        h.report_pending_head(2, 1, d1);
        h.wait_until(|| h.marshal.fulfill_subscription(d1, b1.clone()))
            .await;

        h.wait_until(|| h.execution.new_payloads() == vec![d1])
            .await;
        h.run_for(Duration::from_secs(5)).await;
        assert_eq!(
            h.execution.new_payloads(),
            vec![d1],
            "a transport failure must not trigger a tight retry loop",
        );

        h.run_for(Duration::from_secs(6)).await;
        h.wait_until(|| h.execution.head() == d1).await;
        assert_eq!(h.execution.new_payloads(), vec![d1, d1]);
    });
}

#[test_traced]
fn rejected_notarized_fcu_does_not_advance_the_tracked_state() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        h.execution.script_fcu(
            ForkchoiceState::from_finalized_head(GENESIS, d1),
            [Ok(PayloadStatusEnum::Invalid {
                validation_error: "rejected".into(),
            })],
        );

        h.report_pending_head(2, 1, d1);
        h.wait_until(|| h.marshal.fulfill_subscription(d1, b1.clone()))
            .await;
        h.wait_until(|| h.execution.fcus().len() == 1).await;
        h.run_for(Duration::from_millis(10)).await;

        assert!(
            h.execution.knows_block(d1),
            "the successful new-payload call must leave the block known to the EL",
        );
        assert_eq!(
            h.execution.head(),
            GENESIS,
            "the rejected FCU must not move the EL head",
        );

        // Re-anchor consensus on genesis. If the actor had advanced its own
        // tracked head despite the rejected FCU, it would now issue a repoint.
        h.report_pending_head(3, 0, GENESIS);
        let candidate = make_block(3, 1, GENESIS);
        assert!(
            h.verify(round(3), candidate)
                .await
                .expect("the actor should continue serving validation")
                .is_some(),
        );
        h.run_for(Duration::from_millis(10)).await;
        assert_eq!(
            h.execution.fcus().len(),
            1,
            "the actor and EL must agree that the head remained at genesis",
        );
    });
}

#[test_traced]
fn rejected_notarized_fcu_is_withheld_then_retried() {
    deterministic::Runner::default().start(|context| async move {
        // An FCU rejection uses the shared notarized-block retry mechanism:
        // the block is withheld for the rejection delay, and heartbeats drive
        // the scheduler until it becomes eligible to be forwarded again.
        let h = Harness::builder()
            .harness_options(HarnessOptions {
                fcu_heartbeat_interval: Duration::from_millis(200),
                ..Default::default()
            })
            .start(&context);

        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        h.execution.script_fcu(
            ForkchoiceState::from_finalized_head(GENESIS, d1),
            [
                Ok(PayloadStatusEnum::Invalid {
                    validation_error: "transient".into(),
                }),
                Ok(PayloadStatusEnum::Valid),
            ],
        );

        h.report_pending_head(2, 1, d1);
        h.wait_until(|| h.marshal.fulfill_subscription(d1, b1.clone()))
            .await;
        h.wait_until(|| h.execution.new_payloads() == vec![d1])
            .await;

        h.run_for(Duration::from_secs(5)).await;
        assert_eq!(
            h.execution.new_payloads(),
            vec![d1],
            "a rejected FCU must not trigger a tight convergence retry",
        );
        assert_eq!(h.execution.head(), GENESIS);

        h.run_for(Duration::from_secs(4)).await;
        h.wait_until(|| h.execution.head() == d1).await;
        assert_eq!(h.execution.new_payloads(), vec![d1, d1]);
    });
}

#[test_traced]
fn syncing_notarized_payload_is_rejected_without_updating_forkchoice() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        h.execution
            .script_new_payload(d1, Ok(PayloadStatusEnum::Syncing));

        h.report_pending_head(2, 1, d1);
        h.wait_until(|| h.marshal.fulfill_subscription(d1, b1.clone()))
            .await;
        h.wait_until(|| h.execution.new_payloads() == vec![d1])
            .await;
        h.run_for(Duration::from_millis(10)).await;

        assert!(h.execution.fcus().is_empty());
        assert_eq!(h.execution.head(), GENESIS);

        let candidate = make_block(3, 1, GENESIS);
        assert!(
            h.verify(round(3), candidate)
                .await
                .expect("the actor should survive a SYNCING notarized payload")
                .is_some(),
        );
    });
}

#[test_traced]
fn accepted_notarized_payload_is_rejected_without_updating_forkchoice() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        h.execution
            .script_new_payload(d1, Ok(PayloadStatusEnum::Accepted));

        h.report_pending_head(2, 1, d1);
        h.wait_until(|| h.marshal.fulfill_subscription(d1, b1.clone()))
            .await;
        h.wait_until(|| h.execution.new_payloads() == vec![d1])
            .await;
        h.run_for(Duration::from_millis(10)).await;

        assert!(h.execution.fcus().is_empty());
        assert_eq!(h.execution.head(), GENESIS);

        let candidate = make_block(3, 1, GENESIS);
        assert!(
            h.verify(round(3), candidate)
                .await
                .expect("the actor should survive an ACCEPTED notarized payload")
                .is_some(),
        );
    });
}

#[test_traced]
fn stranded_head_is_repointed_onto_the_finalized_tip() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        // The head converges onto notarized a1. After nullifications,
        // consensus re-anchors onto the finalized tip (genesis): there is
        // no block to forward, only a bare forkchoice update repointing the
        // head.
        let a1 = make_block(1, 1, GENESIS);
        let da1 = a1.digest();
        h.verify(round(1), a1)
            .await
            .expect("verification should complete")
            .expect("block should be valid");
        h.report_pending_head(2, 1, da1);
        h.wait_until(|| h.execution.head() == da1).await;

        let payloads_before = h.execution.new_payloads();
        h.report_pending_head(5, 0, GENESIS);
        h.wait_until(|| h.execution.head() == GENESIS).await;

        assert_eq!(
            h.execution.new_payloads(),
            payloads_before,
            "a repoint is a bare forkchoice update; no payload is forwarded",
        );
        assert_eq!(h.execution.fcus().last(), Some(&(GENESIS, GENESIS, false)));
    });
}

#[test_traced]
fn failed_repoint_is_fatal() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let a1 = make_block(1, 1, GENESIS);
        let da1 = a1.digest();
        h.verify(round(1), a1)
            .await
            .expect("verification should complete")
            .expect("block should be valid");
        h.report_pending_head(2, 1, da1);
        h.wait_until(|| h.execution.head() == da1).await;

        // A repoint targets an ancestor the execution layer provably has;
        // failure means consensus and execution disagree fundamentally.
        h.execution.script_fcu(
            ForkchoiceState::from_finalized_head(GENESIS, GENESIS),
            [Ok(PayloadStatusEnum::Invalid {
                validation_error: "corrupt".into(),
            })],
        );
        h.report_pending_head(5, 0, GENESIS);

        h.actor
            .await
            .expect("actor should shut down cleanly on a failed repoint");
    });
}

// A repoint transport error is fatal because repointing is currently limited
// to the local finalized tip, which the execution layer must already know.
// TODO: Adjust this policy once repointing can target any block between the
// finalized and pending heads.
#[test_traced]
fn repoint_transport_error_is_fatal() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let a1 = make_block(1, 1, GENESIS);
        let da1 = a1.digest();
        h.verify(round(1), a1)
            .await
            .expect("verification should complete")
            .expect("block should be valid");
        h.report_pending_head(2, 1, da1);
        h.wait_until(|| h.execution.head() == da1).await;

        h.execution.script_fcu(
            ForkchoiceState::from_finalized_head(GENESIS, GENESIS),
            [Err("connection closed")],
        );
        h.report_pending_head(5, 0, GENESIS);

        h.actor
            .await
            .expect("actor should shut down cleanly on a repoint transport error");
    });
}

#[test_traced]
fn repoint_canonical_lookup_error_is_fatal() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let a1 = make_block(1, 1, GENESIS);
        let da1 = a1.digest();
        h.verify(round(1), a1)
            .await
            .expect("verification should complete")
            .expect("block should be valid");
        h.report_pending_head(2, 1, da1);
        h.wait_until(|| h.execution.head() == da1).await;
        let accepted_fcus = h.execution.fcus();

        // Repointing checks the locally tracked finalized hash through the
        // Reth provider before sending the forkchoice update.
        h.execution.set_finalized(0, GENESIS);
        h.execution
            .script_canonical_block_hash(0, Err("database unavailable"));
        h.report_pending_head(5, 0, GENESIS);

        let execution = h.execution.clone();
        h.actor
            .await
            .expect("actor should shut down cleanly when the canonical lookup fails");
        assert_eq!(
            execution.fcus(),
            accepted_fcus,
            "the provider error must be detected before the repoint FCU reaches the EL",
        );
    });
}

#[test_traced]
fn branch_flip_flop_reconverges_from_resident_bodies() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        // Chain B: g -> b1 -> b2, converged through validations.
        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let d2 = b2.digest();
        for (view, block) in [(1, b1), (2, b2)] {
            let digest = block.digest();
            h.verify(round(view), block)
                .await
                .expect("verification should complete")
                .expect("block should be valid");
            h.report_pending_head(view + 1, view, digest);
            h.wait_until(|| h.execution.head() == digest).await;
        }

        // Branch A: a1 at the same height as b1, body fetched from marshal.
        let a1 = make_block(3, 1, GENESIS);
        let da1 = a1.digest();
        h.report_pending_head(4, 3, da1);
        h.wait_until(|| h.marshal.fulfill_subscription(da1, a1.clone()))
            .await;
        h.wait_until(|| h.execution.head() == da1).await;
        let fetches = h.marshal.subscribe_log().len();

        // Flip back to branch B: both bodies are still resident, so the
        // re-convergence must not fetch anything.
        h.report_pending_head(5, 2, d2);
        h.wait_until(|| h.execution.head() == d2).await;
        assert_eq!(
            h.marshal.subscribe_log().len(),
            fetches,
            "flip-flopping between branches must reuse resident bodies",
        );
        assert_eq!(h.execution.new_payloads().last(), Some(&d2));
    });
}

#[test_traced]
fn advancing_finalized_tip_prunes_covered_state() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        // a1's body is resident (from a validation request) but never
        // becomes the pending head.
        let a1 = make_block(1, 1, GENESIS);
        let da1 = a1.digest();
        h.verify(round(1), a1)
            .await
            .expect("verification should complete")
            .expect("block should be valid");

        // The network finalizes b1 at the same height in a later round;
        // the tip covers a1, which must be expunged.
        let b1 = make_block(5, 1, GENESIS);
        let db1 = b1.digest();
        h.deliver_tip(round(5), 1, db1);
        h.deliver_finalized(b1)
            .await
            .expect("finalized block should be acknowledged");
        h.wait_until(|| h.execution.head() == db1).await;

        // A stale context naming the pruned block must not resurrect it:
        // its round is covered by the finalized tip, so the tree re-anchors
        // on the tip instead of fetching or forwarding a1.
        h.report_pending_head(2, 1, da1);
        h.run_for(Duration::from_millis(500)).await;

        assert!(
            h.marshal.subscribe_log().is_empty(),
            "nothing may be fetched for a pruned block",
        );
        assert_eq!(h.execution.head(), db1);
        // The validation request itself submitted a1 once; the pruning must
        // prevent any later forward of it.
        assert_eq!(
            h.execution
                .new_payloads()
                .into_iter()
                .filter(|d| *d == da1)
                .count(),
            1,
        );
    });
}
