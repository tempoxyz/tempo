//! Scenario tests for proposal builds: forkchoice updates that carry
//! payload attributes, and the payload jobs that deliver the built block.

use std::time::Duration;

use alloy_rpc_types_engine::PayloadStatusEnum;
use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, deterministic};

use super::harness::{ElCall, GENESIS, Harness, built_payload, make_block, round};
use crate::consensus::Digest;

#[test_traced]
fn build_on_the_local_head_delivers_the_payload() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let proposal = make_block(1, 1, GENESIS);
        let digest = proposal.digest();
        h.execution.script_built_payload(built_payload(&proposal));

        let rx = h.build(round(1), 0, GENESIS);
        let payload = rx.await.expect("payload should be delivered");
        let (block, _) = payload.into_execution_payload();
        assert_eq!(Digest(block.hash()), digest);

        assert!(
            h.execution
                .fcus()
                .contains(&(GENESIS, GENESIS, true)),
            "the build must be registered via an attribute-carrying FCU on the parent",
        );

        // The delivered block is recorded in the notarized tree: once it is
        // notarized, convergence forwards it without a marshal fetch.
        h.report_pending_head(2, 1, digest);
        h.wait_until(|| h.execution.head() == digest).await;
        assert!(h.marshal.subscribe_log().is_empty());
    });
}

#[test_traced]
fn build_is_deferred_while_its_parent_converges_just_in_time() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        let proposal = make_block(2, 2, d1);

        // The network tip names b1 and marshal will deliver it imminently;
        // the build on top of it waits for the delivery.
        h.deliver_tip(round(1), 1, d1);
        let rx = h.build(round(2), 1, d1);
        h.run_for(Duration::from_millis(500)).await;
        assert!(
            !h.execution.fcus().iter().any(|(_, _, attrs)| *attrs),
            "no build may be registered before the parent is the head",
        );

        h.execution.script_built_payload(built_payload(&proposal));
        h.deliver_finalized(b1)
            .await
            .expect("finalized block should be acknowledged");

        let payload = rx.await.expect("payload should be delivered");
        let (block, _) = payload.into_execution_payload();
        assert_eq!(Digest(block.hash()), proposal.digest());
        assert!(
            h.execution.fcus().contains(&(d1, d1, true)),
            "the build is registered once the parent became the head",
        );
    });
}

#[test_traced]
fn build_on_an_unknown_parent_is_dropped() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let stranger = make_block(7, 7, GENESIS);
        let rx = h.build(round(8), 7, stranger.digest());
        rx.await
            .expect_err("a build that cannot start must signal failure");

        assert!(
            !h.execution.fcus().iter().any(|(_, _, attrs)| *attrs),
            "no build may be registered for an unknown parent",
        );
    });
}

#[test_traced]
fn build_canceled_while_queued_still_reaffirms_the_head() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();

        // The build defers on its just-in-time parent, then the subscriber
        // goes away before it can start.
        h.deliver_tip(round(1), 1, d1);
        let rx = h.build(round(2), 1, d1);
        h.run_for(Duration::from_millis(100)).await;
        drop(rx);

        h.deliver_finalized(b1)
            .await
            .expect("finalized block should be acknowledged");
        h.wait_until(|| h.execution.fcus().iter().filter(|(head, ..)| *head == d1).count() >= 2)
            .await;

        assert!(
            !h.execution.fcus().iter().any(|(.., attrs)| *attrs),
            "the canceled build must not submit attributes; the FCU degrades \
            to a bare head re-affirmation",
        );
        assert!(h.execution.pending_payload_jobs().is_empty());
    });
}

#[test_traced]
fn missing_payload_id_fails_the_build() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        h.execution.suppress_payload_ids(true);
        let rx = h.build(round(1), 0, GENESIS);
        rx.await
            .expect_err("a build the execution layer did not register must fail");

        // Not fatal: a later build succeeds.
        h.execution.suppress_payload_ids(false);
        let proposal = make_block(1, 1, GENESIS);
        h.execution.script_built_payload(built_payload(&proposal));
        let rx = h.build(round(2), 0, GENESIS);
        rx.await.expect("the later build should deliver");
    });
}

#[test_traced]
fn missing_payload_job_fails_the_build_without_shutdown() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        h.execution.omit_payload_job(true);
        let rx = h.build(round(1), 0, GENESIS);
        rx.await
            .expect_err("a missing payload job must fail the build");
        assert!(
            h.execution
                .calls()
                .iter()
                .any(|call| matches!(call, ElCall::Resolve(_))),
            "the actor must attempt to resolve the payload ID returned by the FCU",
        );

        // A missing payload job is local to the build request. The actor
        // remains available for later consensus work.
        let b1 = make_block(1, 1, GENESIS);
        let verdict = h
            .verify(round(2), b1)
            .await
            .expect("verification should complete after the missing payload job");
        assert!(verdict.is_some());
    });
}

#[test_traced]
fn canceling_the_subscription_kills_the_payload_job() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        // No scripted payload: the job hangs in the builder until the
        // subscriber goes away.
        let rx = h.build(round(1), 0, GENESIS);
        h.wait_until(|| !h.execution.pending_payload_jobs().is_empty())
            .await;
        drop(rx);
        h.run_for(Duration::from_millis(100)).await;

        // The actor survives and keeps serving; the killed job never
        // delivers anything.
        let b1 = make_block(1, 1, GENESIS);
        let verdict = h
            .verify(round(2), b1)
            .await
            .expect("verification should complete");
        assert!(verdict.is_some());
    });
}

#[test_traced]
fn aborted_payload_job_fails_the_build_without_shutdown() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let rx = h.build(round(1), 0, GENESIS);
        h.wait_until(|| !h.execution.pending_payload_jobs().is_empty())
            .await;
        let payload_id = h.execution.pending_payload_jobs()[0];
        h.execution.abort_payload(payload_id);

        rx.await
            .expect_err("an aborted payload job must fail the build");

        // Payload-builder failures are local to the build request. The actor
        // remains available for later consensus work.
        let b1 = make_block(1, 1, GENESIS);
        let verdict = h
            .verify(round(2), b1)
            .await
            .expect("verification should complete after the aborted build");
        assert!(verdict.is_some());
    });
}

#[test_traced]
fn rejected_build_forkchoice_update_fails_the_build_without_shutdown() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        h.execution.script_fcu(Ok(PayloadStatusEnum::Invalid {
            validation_error: "rejected".into(),
        }));
        let rx = h.build(round(1), 0, GENESIS);
        rx.await
            .expect_err("the failed FCU must fail the build");

        // Build failures are not fatal for the executor.
        let b1 = make_block(1, 1, GENESIS);
        let verdict = h
            .verify(round(2), b1)
            .await
            .expect("verification should complete");
        assert!(verdict.is_some());
    });
}

#[test_traced]
fn forkchoice_update_transport_error_fails_the_build_without_shutdown() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        h.execution.script_fcu(Err("connection closed"));
        let rx = h.build(round(1), 0, GENESIS);
        rx.await
            .expect_err("an FCU transport error must fail the build");

        // Build transport failures are request-local. The actor remains
        // available for later consensus work.
        let b1 = make_block(1, 1, GENESIS);
        let verdict = h
            .verify(round(2), b1)
            .await
            .expect("verification should complete after the FCU transport error");
        assert!(verdict.is_some());
    });
}
