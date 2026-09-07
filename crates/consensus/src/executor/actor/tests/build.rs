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
    ElCall, ForkchoiceStateExt as _, GENESIS, Harness, STARTUP_FCU, built_payload, make_block,
    round,
};
use crate::consensus::Digest;

#[test_traced]
fn building_on_an_unfinalized_head_leaves_forkchoice_unchanged() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        // Verifying b2 converges onto its unfinalized parent b1, making the
        // two sides of forkchoice observably different before the build.
        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        h.verify(round(1), b1)
            .await
            .expect("b1 should validate")
            .expect("b1 should be valid");
        h.verify(round(2), make_block(2, 2, d1))
            .await
            .unwrap()
            .unwrap();
        h.wait_until(|| h.execution.head() == d1).await;
        assert_eq!(h.execution.finalized(), Some((0, GENESIS)));

        let proposal = make_block(3, 2, d1);
        h.execution.script_built_payload(built_payload(&proposal));
        h.build_on(round(3), 1, d1)
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
        let next_proposal = make_block(2, 2, digest);
        h.execution
            .script_built_payload(built_payload(&next_proposal));
        let next_build = h.build(round(2), digest);
        next_build
            .await
            .expect("next build should complete on the retained or fetched parent");
        assert_eq!(h.execution.head(), digest);
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
        let next_proposal = make_block(2, 2, digest);
        h.execution
            .script_built_payload(built_payload(&next_proposal));
        let next_build = h.build(round(2), digest);
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(digest, round(1))])
            .await;
        assert!(
            h.marshal.fulfill_subscription(digest, proposal),
            "the discarded payload must be fetched before convergence",
        );
        next_build
            .await
            .expect("next build should complete on the retained or fetched parent");
        assert_eq!(h.execution.head(), digest);
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
fn build_waits_for_its_unknown_parent_to_be_fetched_and_canonicalized() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let parent = make_block(7, 1, GENESIS);
        let digest = parent.digest();
        let proposal = make_block(8, 2, digest);
        let mut rx = h.build(round(8), digest);
        h.wait_until(|| h.marshal.open_subscriptions().contains(&(digest, round(7))))
            .await;
        assert!(rx.try_recv().expect("build must remain queued").is_none());
        assert!(
            !h.execution.fcus().iter().any(|(_, _, attrs)| *attrs),
            "no build may be registered for an unknown parent",
        );

        h.execution.script_built_payload(built_payload(&proposal));
        assert!(h.marshal.fulfill_subscription(digest, parent));
        rx.await
            .expect("build should complete once its parent converges");
        assert_eq!(h.execution.head(), digest);
        assert!(h.execution.fcus().contains(&(digest, GENESIS, true)));
    });
}

#[test_traced]
fn build_selects_its_known_parent_as_the_head() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        // Validation alone does not make a1 the head. The subsequent build
        // selects it as its parent and drives the execution layer onto it.
        let a1 = make_block(1, 1, GENESIS);
        let da1 = a1.digest();
        h.verify(round(1), a1)
            .await
            .expect("verification should complete")
            .expect("block should be valid");

        assert_eq!(h.execution.head(), GENESIS);
        let proposal = make_block(2, 2, da1);
        h.execution.script_built_payload(built_payload(&proposal));
        h.build(round(2), da1).await.expect("build should complete");
        assert_eq!(h.execution.head(), da1);
        assert!(h.execution.fcus().contains(&(da1, GENESIS, true)));
    });
}

#[test_traced]
fn build_on_a_head_the_network_finalized_past_is_dropped() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        // The head sits on notarized a1.
        let a1 = make_block(1, 1, GENESIS);
        let da1 = a1.digest();
        h.verify(round(1), a1)
            .await
            .expect("a1 should validate")
            .expect("a1 should be valid");
        h.verify(round(2), make_block(2, 2, da1))
            .await
            .expect("child should validate")
            .expect("child should be valid");
        h.wait_until(|| h.execution.head() == da1).await;

        // The network finalizes b1 on another branch. The tip report alone
        // re-anchors the pending head onto the tip, so a1 is no longer what
        // consensus builds on: the build is dropped before the finalized
        // block is even delivered, and no payload is registered on the
        // abandoned head.
        let b1 = make_block(3, 1, GENESIS);
        let db1 = b1.digest();
        h.deliver_tip(round(3), 1, db1);
        h.build_on(round(4), 1, da1)
            .await
            .expect_err("the build on the abandoned head must fail");
        assert!(
            !h.execution.fcus().iter().any(|(.., attrs)| *attrs),
            "no payload may be registered on the abandoned head",
        );

        h.deliver_finalized(b1)
            .await
            .expect("b1 should be acknowledged");
        assert_eq!(h.execution.head(), db1);
    });
}

#[test_traced]
fn canceled_build_keeps_its_parent_target_despite_an_older_request() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        // Two validated siblings; consensus moves on to build on b1.
        let a1 = make_block(1, 1, GENESIS);
        let b1 = make_block(2, 1, GENESIS);
        let (da1, db1) = (a1.digest(), b1.digest());
        for (view, block) in [(1, a1), (2, b1)] {
            h.verify(round(view), block)
                .await
                .expect("verification should complete")
                .expect("block should be valid");
        }
        let build = h.build_on(round(4), 2, db1);
        drop(build);
        h.wait_until(|| h.execution.head() == db1).await;

        // An older build arrives after the newest build has been canceled.
        // Its context must not restore the previous target.
        h.build_on(round(3), 1, da1)
            .await
            .expect_err("an older build cannot select a different parent");
        assert_eq!(h.execution.head(), db1);
        let proposal = make_block(5, 2, db1);
        h.execution.script_built_payload(built_payload(&proposal));
        h.build(round(5), db1)
            .await
            .expect("the build on the current pending head must complete");
        assert_eq!(h.execution.head(), db1);
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

        h.wait_until(|| h.execution.fcus().len() == 3).await;
        assert_eq!(
            h.execution.fcus(),
            vec![STARTUP_FCU, (d1, d1, false), (d1, d1, false)],
            "the canceled build must not submit attributes; its FCU degrades \
            to a bare re-affirmation of the head",
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
fn rejected_build_forkchoice_update_is_fatal() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        // The build re-affirms the tracked state; a rejection means the
        // execution layer disagrees with the executor about that state.
        h.execution.script_fcu(
            ForkchoiceState::from_finalized_head(GENESIS, GENESIS),
            Ok(PayloadStatusEnum::Invalid {
                validation_error: "rejected".into(),
            }),
        );
        let rx = h.build(round(1), GENESIS);
        rx.await.expect_err("the failed FCU must fail the build");

        h.actor
            .await
            .expect("actor should shut down cleanly on a rejected build forkchoice update");
        assert!(h.execution.pending_payload_jobs().is_empty());
    });
}

#[test_traced]
fn build_forkchoice_update_transport_error_is_fatal() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        h.execution.script_fcu(
            ForkchoiceState::from_finalized_head(GENESIS, GENESIS),
            Err("connection closed"),
        );
        let rx = h.build(round(1), GENESIS);
        rx.await
            .expect_err("an FCU transport error must fail the build");

        h.actor
            .await
            .expect("actor should shut down cleanly on a build forkchoice transport error");
        assert!(h.execution.pending_payload_jobs().is_empty());
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
