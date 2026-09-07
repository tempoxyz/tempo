//! Scenario tests for notarized-chain convergence: the executor drives the
//! execution layer's head onto the parent selected by consensus requests,
//! fetching missing bodies from the marshal actor, and never runs ahead of
//! the finalization pipeline.

use std::time::Duration;

use alloy_rpc_types_engine::{ForkchoiceState, PayloadStatusEnum};
use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, deterministic};

use super::harness::{
    ForkchoiceStateExt as _, GENESIS, Harness, HarnessOptions, STARTUP_FCU, built_payload,
    make_block, round,
};

#[test_traced]
fn build_converges_onto_its_verified_parent() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();

        // The validation request records the body; the later build request
        // selects it as the convergence target and builds on it.
        h.verify(round(1), b1)
            .await
            .expect("verification should complete")
            .expect("block should be valid");
        let proposal = make_block(2, 2, d1);
        h.execution.script_built_payload(built_payload(&proposal));
        h.build(round(2), d1).await.expect("build should complete");

        assert_eq!(h.execution.head(), d1);
        assert_eq!(
            h.execution.fcus().last(),
            Some(&(d1, GENESIS, true)),
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
        let proposal = make_block(4, 4, d3);
        h.execution.script_built_payload(built_payload(&proposal));
        let build = h.build(round(4), d3);

        h.wait_until(|| h.marshal.fulfill_subscription(d3, b3.clone()))
            .await;
        h.wait_until(|| h.marshal.fulfill_subscription(d2, b2.clone()))
            .await;
        h.wait_until(|| h.marshal.fulfill_subscription(d1, b1.clone()))
            .await;

        build
            .await
            .expect("build should complete after fetching its ancestry");
        assert_eq!(h.execution.head(), d3);
        assert_eq!(
            h.marshal.subscribe_log(),
            vec![(d3, round(3)), (d2, round(2)), (d1, round(1))],
            "gaps are discovered tip-down, one fetch at a time",
        );
        assert_eq!(
            h.execution.new_payloads(),
            vec![d1, d2, d3],
            "blocks are delivered bottom-up",
        );
        assert_eq!(
            h.execution.fcus(),
            vec![STARTUP_FCU, (d3, GENESIS, false), (d3, GENESIS, true)],
            "one update converges across the delivered run before the build submits attributes",
        );
    });
}

#[test_traced]
fn long_delivery_runs_are_locked_in_every_few_blocks() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        // Ten notarized blocks above genesis, all bodies fetched tip-down.
        let mut blocks = Vec::new();
        let mut parent = GENESIS;
        for height in 1..=10 {
            let block = make_block(height, height, parent);
            parent = block.digest();
            blocks.push(block);
        }
        let digests = blocks.iter().map(|b| b.digest()).collect::<Vec<_>>();
        let proposal = make_block(11, 11, digests[9]);
        h.execution.script_built_payload(built_payload(&proposal));
        let build = h.build(round(11), digests[9]);
        for block in blocks.iter().rev() {
            h.wait_until(|| {
                h.marshal
                    .fulfill_subscription(block.digest(), block.clone())
            })
            .await;
        }

        // The run is delivered bottom-up, with a forkchoice update forced
        // after every eight deliveries so that the execution layer never
        // holds more than that many uncanonicalized blocks.
        build
            .await
            .expect("build should complete after the long delivery run");
        assert_eq!(h.execution.head(), digests[9]);
        assert_eq!(h.execution.new_payloads(), digests);
        assert_eq!(
            h.execution.fcus(),
            vec![
                STARTUP_FCU,
                (digests[7], GENESIS, false),
                (digests[9], GENESIS, false),
                (digests[9], GENESIS, true),
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
        let proposal = make_block(2, 2, d1);
        h.execution.script_built_payload(built_payload(&proposal));
        let build = h.build(round(2), d1);

        // Marshal gives up on the first subscription; the block is still on
        // the canonical notarized path, so the fetch must be re-issued.
        h.wait_until(|| h.marshal.drop_subscription(d1)).await;
        h.wait_until(|| h.marshal.subscribe_log().len() == 2).await;

        h.wait_until(|| h.marshal.fulfill_subscription(d1, b1.clone()))
            .await;
        build
            .await
            .expect("build should complete after retrying its parent");
        assert_eq!(h.execution.head(), d1);
    });
}

#[test_traced]
fn stale_body_fetch_is_dropped_when_the_pending_head_moves() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let a1 = make_block(5, 1, GENESIS);
        let (d1, da1) = (b1.digest(), a1.digest());

        let first = h.build(round(2), d1);
        h.wait_until(|| !h.marshal.open_subscriptions().is_empty())
            .await;

        // A newer context re-anchors the pending head onto a different
        // block; the in-flight fetch is now pointless and must be dropped
        // (nobody is required to serve a forked-out block).
        let proposal = make_block(6, 2, da1);
        h.execution.script_built_payload(built_payload(&proposal));
        let second = h.build(round(6), da1);
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(da1, round(5))])
            .await;

        first
            .await
            .expect_err("the newer build must supersede the first");
        assert!(
            !h.marshal.fulfill_subscription(d1, b1),
            "the stale subscription must have been dropped",
        );

        h.wait_until(|| h.marshal.fulfill_subscription(da1, a1.clone()))
            .await;
        second
            .await
            .expect("build on the new branch should complete");
        assert_eq!(h.execution.head(), da1);
    });
}

#[test_traced]
fn waiting_build_allows_its_rejected_parent_to_be_retried() {
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

        let proposal = make_block(2, 2, d1);
        h.execution.script_built_payload(built_payload(&proposal));
        let mut build = h.build(round(2), d1);
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
        assert!(
            build
                .try_recv()
                .expect("build must remain queued")
                .is_none()
        );

        // After the retry delay (10s) the block becomes forwardable again.
        h.run_for(Duration::from_secs(6)).await;
        h.wait_until(|| h.execution.head() == d1).await;
        assert_eq!(h.execution.new_payloads(), vec![d1, d1]);
        build
            .await
            .expect("build must complete after its parent is accepted");
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

        let proposal = make_block(2, 2, d1);
        h.execution.script_built_payload(built_payload(&proposal));
        let build = h.build(round(2), d1);
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
        build
            .await
            .expect("build should complete after retrying its parent");
        assert_eq!(h.execution.head(), d1);
        assert_eq!(h.execution.new_payloads(), vec![d1, d1]);
    });
}

#[test_traced]
fn rejected_notarized_fcu_is_fatal() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        // The forkchoice update names a block the execution layer accepted
        // through its delivery. A rejection means the executor's view of the
        // execution layer has diverged from it: the node shuts down.
        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        h.execution.script_fcu(
            ForkchoiceState::from_finalized_head(GENESIS, d1),
            Ok(PayloadStatusEnum::Invalid {
                validation_error: "rejected".into(),
            }),
        );

        let build = h.build(round(2), d1);
        h.wait_until(|| h.marshal.fulfill_subscription(d1, b1.clone()))
            .await;

        build
            .await
            .expect_err("failed parent convergence must fail the build");
        h.actor
            .await
            .expect("actor should shut down cleanly on a rejected forkchoice update");
        assert!(
            h.execution.knows_block(d1),
            "the successful new-payload call must leave the block known to the EL",
        );
        assert_eq!(h.execution.fcus().len(), 2);
        assert_eq!(
            h.execution.head(),
            GENESIS,
            "the rejected FCU must not move the EL head",
        );
    });
}

#[test_traced]
fn notarized_fcu_transport_error_is_fatal() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        h.execution.script_fcu(
            ForkchoiceState::from_finalized_head(GENESIS, d1),
            Err("connection closed"),
        );

        let build = h.build(round(2), d1);
        h.wait_until(|| h.marshal.fulfill_subscription(d1, b1.clone()))
            .await;

        build
            .await
            .expect_err("failed parent convergence must fail the build");
        h.actor
            .await
            .expect("actor should shut down cleanly on a forkchoice transport error");
        assert_eq!(h.execution.new_payloads(), vec![d1]);
        assert_eq!(h.execution.head(), GENESIS);
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

        let mut build = h.build(round(2), d1);
        h.wait_until(|| h.marshal.fulfill_subscription(d1, b1.clone()))
            .await;
        h.wait_until(|| h.execution.new_payloads() == vec![d1])
            .await;
        h.run_for(Duration::from_millis(10)).await;

        assert_eq!(h.execution.fcus(), vec![STARTUP_FCU]);
        assert_eq!(h.execution.head(), GENESIS);
        assert!(
            build
                .try_recv()
                .expect("build should still be waiting on its parent")
                .is_none()
        );

        let candidate = make_block(3, 1, GENESIS);
        assert!(
            h.verify(round(3), candidate)
                .await
                .expect("the actor should survive a SYNCING notarized payload")
                .is_some(),
        );
        build
            .await
            .expect_err("the newer verification must supersede the waiting build");
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

        let mut build = h.build(round(2), d1);
        h.wait_until(|| h.marshal.fulfill_subscription(d1, b1.clone()))
            .await;
        h.wait_until(|| h.execution.new_payloads() == vec![d1])
            .await;
        h.run_for(Duration::from_millis(10)).await;

        assert_eq!(h.execution.fcus(), vec![STARTUP_FCU]);
        assert_eq!(h.execution.head(), GENESIS);
        assert!(
            build
                .try_recv()
                .expect("build should still be waiting on its parent")
                .is_none()
        );

        let candidate = make_block(3, 1, GENESIS);
        assert!(
            h.verify(round(3), candidate)
                .await
                .expect("the actor should survive an ACCEPTED notarized payload")
                .is_some(),
        );
        build
            .await
            .expect_err("the newer verification must supersede the waiting build");
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
        let proposal = make_block(2, 2, da1);
        h.execution.script_built_payload(built_payload(&proposal));
        h.build(round(2), da1).await.expect("build should complete");
        assert_eq!(h.execution.head(), da1);

        let payloads_before = h.execution.new_payloads();
        let proposal = make_block(5, 1, GENESIS);
        h.execution.script_built_payload(built_payload(&proposal));
        h.build(round(5), GENESIS)
            .await
            .expect("build should complete");
        assert_eq!(h.execution.head(), GENESIS);

        assert_eq!(
            h.execution.new_payloads(),
            payloads_before,
            "a repoint is a bare forkchoice update; no payload is forwarded",
        );
        assert!(
            h.execution
                .fcus()
                .ends_with(&[(GENESIS, GENESIS, false), (GENESIS, GENESIS, true),])
        );
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
        let proposal = make_block(2, 2, da1);
        h.execution.script_built_payload(built_payload(&proposal));
        h.build(round(2), da1).await.expect("build should complete");
        assert_eq!(h.execution.head(), da1);

        // A repoint targets an ancestor the execution layer provably has;
        // failure means consensus and execution disagree fundamentally.
        h.execution.script_fcu(
            ForkchoiceState::from_finalized_head(GENESIS, GENESIS),
            Ok(PayloadStatusEnum::Invalid {
                validation_error: "corrupt".into(),
            }),
        );
        h.build(round(5), GENESIS)
            .await
            .expect_err("failed repoint must fail the build");

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
        let proposal = make_block(2, 2, da1);
        h.execution.script_built_payload(built_payload(&proposal));
        h.build(round(2), da1).await.expect("build should complete");
        assert_eq!(h.execution.head(), da1);

        h.execution.script_fcu(
            ForkchoiceState::from_finalized_head(GENESIS, GENESIS),
            Err("connection closed"),
        );
        h.build(round(5), GENESIS)
            .await
            .expect_err("failed repoint must fail the build");

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
        let proposal = make_block(2, 2, da1);
        h.execution.script_built_payload(built_payload(&proposal));
        h.build(round(2), da1).await.expect("build should complete");
        assert_eq!(h.execution.head(), da1);
        let accepted_fcus = h.execution.fcus();

        // Repointing checks the locally tracked finalized hash through the
        // Reth provider before sending the forkchoice update.
        h.execution.set_finalized(0, GENESIS);
        h.execution
            .script_canonical_block_hash(0, Err("database unavailable"));
        h.build(round(5), GENESIS)
            .await
            .expect_err("failed repoint must fail the build");

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
            h.verify(round(view), block)
                .await
                .expect("verification should complete")
                .expect("block should be valid");
        }
        let proposal = make_block(3, 3, d2);
        h.execution.script_built_payload(built_payload(&proposal));
        h.build(round(3), d2).await.expect("build should complete");
        h.wait_until(|| h.execution.head() == d2).await;

        // Branch A: a1 at the same height as b1, body fetched from marshal.
        let a1 = make_block(3, 1, GENESIS);
        let da1 = a1.digest();
        let proposal = make_block(4, 2, da1);
        h.execution.script_built_payload(built_payload(&proposal));
        let build = h.build(round(4), da1);
        h.wait_until(|| h.marshal.fulfill_subscription(da1, a1.clone()))
            .await;
        build.await.expect("build on branch A should complete");
        assert_eq!(h.execution.head(), da1);
        let fetches = h.marshal.subscribe_log().len();

        // Flip back to branch B: both bodies are still resident, so the
        // re-convergence must not fetch anything. The execution layer
        // already knows the branch, so the head is repointed onto it with a
        // bare forkchoice update.
        let payloads_before = h.execution.new_payloads();
        let proposal = make_block(5, 3, d2);
        h.execution.script_built_payload(built_payload(&proposal));
        h.build_on(round(5), 2, d2)
            .await
            .expect("build should complete");
        h.wait_until(|| h.execution.head() == d2).await;
        assert_eq!(
            h.marshal.subscribe_log().len(),
            fetches,
            "flip-flopping between branches must reuse resident bodies",
        );
        assert_eq!(
            h.execution.new_payloads(),
            payloads_before,
            "a branch the execution layer knows is not delivered again",
        );
        assert!(
            h.execution
                .fcus()
                .ends_with(&[(d2, GENESIS, false), (d2, GENESIS, true),])
        );
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
        h.build_on(round(2), 1, da1)
            .await
            .expect_err("a build on a pruned parent must fail");

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
