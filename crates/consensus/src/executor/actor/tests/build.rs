//! Scenario tests for proposal builds: forkchoice updates that carry
//! payload attributes, and the payload jobs that deliver the built block.

use std::time::Duration;

use alloy_primitives::{B256, Bytes};
use alloy_rpc_types_engine::{ForkchoiceState, PayloadStatusEnum};
use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, deterministic};
use tempo_payload_types::TempoPayloadAttributes;
use tempo_primitives::TempoConsensusContext;

use super::harness::{
    ElCall, ForkchoiceStateExt as _, GENESIS, Harness, built_payload, make_block, round,
};
use crate::consensus::Digest;

#[test_traced]
fn building_on_an_unfinalized_head_leaves_forkchoice_unchanged() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        // Converge onto an unfinalized b1 so the two sides of forkchoice are
        // observably different before the build starts.
        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        h.verify(round(1), b1)
            .await
            .expect("b1 should validate")
            .expect("b1 should be valid");
        h.report_pending_head(2, 1, d1);
        h.wait_until(|| h.execution.head() == d1).await;
        assert_eq!(h.execution.finalized(), Some((0, GENESIS)));

        let proposal = make_block(2, 2, d1);
        h.execution.script_built_payload(built_payload(&proposal));
        h.build(round(2), d1)
            .await
            .expect("payload should be delivered");

        assert_eq!(
            h.execution.fcus().last(),
            Some(&(d1, GENESIS, true)),
            "the build FCU must re-affirm both sides of the existing forkchoice state",
        );
        assert_eq!(h.execution.head(), d1);
        assert_eq!(h.execution.finalized(), Some((0, GENESIS)));
    });
}

#[test_traced]
fn pending_payload_job_is_delivered() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let proposal = make_block(1, 1, GENESIS);
        let digest = proposal.digest();
        let build = h.build(round(1), GENESIS);
        h.wait_until(|| {
            h.execution
                .calls()
                .iter()
                .any(|call| matches!(call, ElCall::Resolve(_)))
        })
        .await;
        let payload_id = h.execution.pending_payload_jobs()[0];

        h.execution
            .deliver_payload(payload_id, built_payload(&proposal));
        let payload = build.await.expect("payload should be delivered");
        let (block, _) = payload.into_execution_payload();
        assert_eq!(Digest(block.hash()), digest);
        assert!(h.execution.pending_payload_jobs().is_empty());
        assert!(h.execution.canceled_payload_jobs().is_empty());

        // The delivered block is recorded in the notarized tree: once it is
        // notarized, convergence forwards it without a marshal fetch.
        h.report_pending_head(2, 1, digest);
        h.wait_until(|| h.execution.head() == digest).await;
        assert!(h.marshal.subscribe_log().is_empty());
    });
}

#[test_traced]
fn subscriber_cancellation_immediately_before_delivery_discards_the_payload() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let proposal = make_block(1, 1, GENESIS);
        let digest = proposal.digest();
        let build = h.build(round(1), GENESIS);
        h.wait_until(|| {
            h.execution
                .calls()
                .iter()
                .any(|call| matches!(call, ElCall::Resolve(_)))
        })
        .await;
        let payload_id = h.execution.pending_payload_jobs()[0];

        // Make cancellation and payload resolution ready without yielding in
        // between. Either side may win that race, but the block must not be
        // retained after its subscriber has canceled.
        drop(build);
        h.execution
            .deliver_payload(payload_id, built_payload(&proposal));
        h.run_for(Duration::from_millis(10)).await;
        assert!(h.execution.pending_payload_jobs().is_empty());

        // A completed payload whose subscriber is still active is always
        // returned to the actor and recorded in its notarized-block cache.
        // Conversely, the actor only asks marshal for a pending-head body when
        // that body is absent from the cache. Observing the subscription below
        // therefore proves that this raced payload was not retained.
        h.report_pending_head(2, 1, digest);
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(digest, round(1))])
            .await;
        assert!(
            h.marshal.fulfill_subscription(digest, proposal),
            "the discarded payload must be fetched before convergence",
        );
        h.wait_until(|| h.execution.head() == digest).await;
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
        let rx = h.build(round(2), d1);
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
        let rx = h.build(round(8), stranger.digest());
        rx.await
            .expect_err("a build that cannot start must signal failure");

        assert!(
            !h.execution.fcus().iter().any(|(_, _, attrs)| *attrs),
            "no build may be registered for an unknown parent",
        );
    });
}

#[test_traced]
fn queued_build_is_dropped_when_finality_advances_past_its_parent() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();

        // Queue finalization and then a build on the current genesis head
        // without yielding. Finalization owns the next execution slot, so the
        // build waits behind the state transition that makes it stale.
        h.deliver_tip(round(1), 1, d1);
        let finalized = h.deliver_finalized(b1);
        let build = h.build(round(2), GENESIS);

        finalized
            .await
            .expect("finalization should eventually complete");
        build
            .await
            .expect_err("the finalized parent has made the queued build stale");
        assert!(
            !h.execution.fcus().iter().any(|(.., attrs)| *attrs),
            "a stale build must not submit payload attributes",
        );
        assert!(h.execution.pending_payload_jobs().is_empty());
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
        let rx = h.build(round(2), d1);
        h.run_for(Duration::from_millis(100)).await;
        drop(rx);

        h.deliver_finalized(b1)
            .await
            .expect("finalized block should be acknowledged");
        h.wait_until(|| {
            h.execution
                .fcus()
                .iter()
                .filter(|(head, ..)| *head == d1)
                .count()
                >= 2
        })
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
        let rx = h.build(round(1), GENESIS);
        rx.await
            .expect_err("a build the execution layer did not register must fail");

        // Not fatal: a later build succeeds.
        h.execution.suppress_payload_ids(false);
        let proposal = make_block(1, 1, GENESIS);
        h.execution.script_built_payload(built_payload(&proposal));
        let rx = h.build(round(2), GENESIS);
        rx.await.expect("the later build should deliver");
    });
}

#[test_traced]
fn missing_payload_job_fails_the_build_without_shutdown() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        h.execution.omit_payload_job(true);
        let rx = h.build(round(1), GENESIS);
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
        let rx = h.build(round(1), GENESIS);
        h.wait_until(|| !h.execution.pending_payload_jobs().is_empty())
            .await;
        let payload_id = h.execution.pending_payload_jobs()[0];
        drop(rx);
        h.wait_until(|| h.execution.canceled_payload_jobs() == vec![payload_id])
            .await;

        assert!(
            h.execution.pending_payload_jobs().is_empty(),
            "dropping the subscriber must remove the underlying payload job",
        );

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

        let rx = h.build(round(1), GENESIS);
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

        h.execution.script_fcu(
            ForkchoiceState::from_finalized_head(GENESIS, GENESIS),
            Ok(PayloadStatusEnum::Invalid {
                validation_error: "rejected".into(),
            }),
        );
        let rx = h.build(round(1), GENESIS);
        rx.await.expect_err("the failed FCU must fail the build");

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

        h.execution.script_fcu(
            ForkchoiceState::from_finalized_head(GENESIS, GENESIS),
            Err("connection closed"),
        );
        let rx = h.build(round(1), GENESIS);
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

#[test_traced]
fn payload_attributes_reach_the_execution_layer_unchanged() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let proposer = B256::repeat_byte(0x42);
        let consensus_context = TempoConsensusContext {
            epoch: 7,
            view: 11,
            parent_view: 9,
            proposer: tempo_primitives::ed25519::PublicKey::from_seed(7),
        };
        let extra_data = Bytes::from_static(b"distinct payload attributes");
        let build_budget = Duration::from_millis(750);
        let attributes = TempoPayloadAttributes::new(
            Some(proposer),
            123,
            456,
            extra_data.clone(),
            Some(consensus_context),
            Vec::new,
        )
        .with_payload_build_budget(build_budget);

        let proposal = make_block(1, 1, GENESIS);
        h.execution.script_built_payload(built_payload(&proposal));
        h.build_with_attributes(round(1), GENESIS, attributes)
            .await
            .expect("build should complete");

        let received = h.execution.payload_attributes();
        let [received] = received.as_slice() else {
            panic!("expected exactly one attribute-carrying FCU");
        };
        assert_eq!(received.proposer_public_key(), Some(&proposer));
        assert_eq!(received.timestamp_millis(), 123_456);
        assert_eq!(received.extra_data(), &extra_data);
        assert_eq!(received.consensus_context(), Some(consensus_context));
        assert_eq!(received.payload_build_budget(), Some(build_budget));
        assert!(received.validation_latency_estimate().is_none());
        assert!(received.subblocks().is_empty());
    });
}
