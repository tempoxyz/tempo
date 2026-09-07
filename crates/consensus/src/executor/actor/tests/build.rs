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

        // The delivered block is retained: the next build delivers its
        // notarized parent without a marshal fetch.
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

        // The next build checks retained proposal bodies and the EL before
        // asking marshal. The subscription therefore proves this raced
        // payload was not retained.
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
fn build_delivers_its_parent_before_queued_finalization() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        let proposal = make_block(2, 2, d1);

        // Even when its parent is the finalized network tip, the build owns
        // its fetch and delivery. Finalization waits until the build FCU lands.
        h.deliver_tip(round(1), 1, d1);
        let rx = h.build(round(2), d1);
        h.run_for(Duration::from_millis(500)).await;
        assert!(
            !h.execution.fcus().iter().any(|(_, _, attrs)| *attrs),
            "no build may be registered before the parent is the head",
        );

        h.execution.script_built_payload(built_payload(&proposal));
        let finalized = h.deliver_finalized(b1.clone());
        h.run_for(Duration::from_millis(10)).await;
        assert!(h.execution.new_payloads().is_empty());
        assert!(h.marshal.fulfill_subscription(d1, b1));
        let payload = rx.await.expect("payload should be delivered");
        finalized
            .await
            .expect("finalized block should be acknowledged");

        let (block, _) = payload.into_execution_payload();
        assert_eq!(Digest(block.hash()), proposal.digest());
        assert!(
            h.execution.fcus().contains(&(d1, GENESIS, true)),
            "the build FCU uses delivered finality, not the network tip",
        );
        assert_eq!(h.execution.new_payloads(), vec![d1, d1]);
    });
}

#[test_traced]
fn build_fetches_and_delivers_its_parent_then_starts_with_one_fcu() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let parent = make_block(7, 1, GENESIS);
        let digest = parent.digest();
        let proposal = make_block(8, 2, digest);
        let mut rx = h.build(round(8), digest);
        h.wait_until(|| h.marshal.open_subscriptions().contains(&(digest, round(7))))
            .await;
        assert!(rx.try_recv().expect("build must remain live").is_none());
        assert!(
            !h.execution.fcus().iter().any(|(_, _, attrs)| *attrs),
            "no build may be registered for an unknown parent",
        );

        h.execution.script_built_payload(built_payload(&proposal));
        assert!(h.marshal.fulfill_subscription(digest, parent));
        rx.await
            .expect("build should complete once its parent converges");
        assert_eq!(h.execution.head(), digest);
        assert_eq!(h.execution.new_payloads(), vec![digest]);
        assert_eq!(
            h.execution.fcus(),
            vec![STARTUP_FCU, (digest, GENESIS, true)]
        );
        assert_eq!(h.marshal.subscribe_log(), vec![(digest, round(7))]);
    });
}

#[test_traced]
fn build_delivers_the_parent_found_in_the_execution_layer_before_forkchoice() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        let parent = make_block(1, 1, GENESIS);
        let digest = parent.digest();
        h.execution.add_body(parent);
        let release = h
            .execution
            .script_delayed_new_payload(digest, Ok(PayloadStatusEnum::Valid));
        h.execution
            .script_built_payload(built_payload(&make_block(2, 2, digest)));

        let build = h.build(round(2), digest);
        h.wait_until(|| h.execution.new_payloads() == vec![digest])
            .await;
        assert!(h.marshal.subscribe_log().is_empty());
        assert_eq!(h.execution.fcus(), vec![STARTUP_FCU]);

        release.send(()).unwrap();
        build
            .await
            .expect("the locally available parent should support a build");
        assert_eq!(
            h.execution.fcus(),
            vec![STARTUP_FCU, (digest, GENESIS, true)]
        );
        assert!(h.marshal.subscribe_log().is_empty());
    });
}

#[test_traced]
fn build_falls_back_to_marshal_when_the_execution_layer_lookup_fails() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        let parent = make_block(1, 1, GENESIS);
        let digest = parent.digest();
        h.execution
            .script_block_by_digest(digest, Err("database unavailable"));
        h.execution
            .script_built_payload(built_payload(&make_block(2, 2, digest)));

        let build = h.build(round(2), digest);
        h.wait_until(|| h.marshal.fulfill_subscription(digest, parent.clone()))
            .await;
        build
            .await
            .expect("the marshal fallback should let the build complete");
        assert_eq!(h.marshal.subscribe_log(), vec![(digest, round(1))]);
        assert_eq!(h.execution.new_payloads(), vec![digest]);
        assert_eq!(h.execution.head(), digest);
    });
}

#[test_traced]
fn build_redelivers_its_known_parent_before_selecting_it_as_head() {
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
        assert_eq!(h.execution.fcus(), vec![STARTUP_FCU, (da1, GENESIS, true)]);
        assert!(h.marshal.subscribe_log().is_empty());
        assert_eq!(h.execution.new_payloads(), vec![da1, da1]);
    });
}

#[test_traced]
fn non_valid_parent_delivery_fails_the_build_without_walking_ancestors() {
    for status in [
        Ok(PayloadStatusEnum::Syncing),
        Ok(PayloadStatusEnum::Accepted),
        Ok(PayloadStatusEnum::Invalid {
            validation_error: "rejected parent".into(),
        }),
        Err("connection closed"),
    ] {
        deterministic::Runner::default().start(|context| async move {
            let h = Harness::start_at_genesis(&context);
            let ancestor = make_block(1, 1, GENESIS);
            let parent = make_block(2, 2, ancestor.digest());
            let digest = parent.digest();
            h.execution.script_new_payload(digest, status);

            let build = h.build(round(3), digest);
            h.wait_until(|| h.marshal.fulfill_subscription(digest, parent.clone()))
                .await;
            build
                .await
                .expect_err("only a VALID parent can start a build");
            assert_eq!(h.execution.new_payloads(), vec![digest]);
            assert_eq!(h.execution.fcus(), vec![STARTUP_FCU]);
            assert!(h.marshal.subscribe_log().iter().all(|(d, _)| *d == digest));

            // Failure releases the slot. The independent convergence target
            // can be superseded and subsequent consensus work still runs.
            h.verify(round(4), make_block(4, 1, GENESIS))
                .await
                .unwrap()
                .unwrap();
            assert!(h.execution.pending_payload_jobs().is_empty());
        });
    }
}

#[test_traced]
fn failed_parent_fetch_ends_the_build_without_engine_calls() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        let parent = make_block(1, 1, GENESIS);
        let digest = parent.digest();
        let build = h.build(round(2), digest);
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(digest, round(1))])
            .await;
        assert!(h.marshal.drop_subscription(digest));
        build
            .await
            .expect_err("a failed fetch must fail this build attempt");
        assert!(h.execution.new_payloads().is_empty());
        assert_eq!(h.execution.fcus(), vec![STARTUP_FCU]);
        h.verify(round(3), make_block(3, 1, GENESIS))
            .await
            .unwrap()
            .unwrap();
    });
}

#[test_traced]
fn latest_queued_build_survives_while_the_active_build_finishes() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        let parent = make_block(1, 1, GENESIS);
        let digest = parent.digest();
        let release = h
            .execution
            .script_delayed_new_payload(digest, Ok(PayloadStatusEnum::Valid));
        let first_proposal = make_block(2, 2, digest);
        h.execution
            .script_built_payload(built_payload(&first_proposal));
        let mut first = h.build(round(2), digest);
        h.wait_until(|| h.marshal.fulfill_subscription(digest, parent.clone()))
            .await;
        h.wait_until(|| h.execution.new_payloads() == vec![digest])
            .await;

        let replaced = h.build(round(3), GENESIS);
        let proposal = make_block(4, 1, GENESIS);
        h.execution.script_built_payload(built_payload(&proposal));
        let latest = h.build(round(4), GENESIS);
        replaced
            .await
            .expect_err("only the latest queued build survives");
        assert!(
            first
                .try_recv()
                .expect("the active build must remain live")
                .is_none()
        );
        assert_eq!(h.execution.fcus(), vec![STARTUP_FCU]);

        release
            .send(())
            .expect("new requests must not cancel active delivery");
        let payload = first.await.expect("the active build should complete");
        let (block, _) = payload.into_execution_payload();
        assert_eq!(Digest(block.hash()), first_proposal.digest());
        let payload = latest
            .await
            .expect("the latest queued build should complete next");
        let (block, _) = payload.into_execution_payload();
        assert_eq!(Digest(block.hash()), proposal.digest());
        assert_eq!(
            h.execution.fcus(),
            vec![
                STARTUP_FCU,
                (digest, GENESIS, true),
                // Converge HEAD before starting the queued build.
                (GENESIS, GENESIS, false),
                (GENESIS, GENESIS, true)
            ]
        );
        assert_eq!(h.execution.head(), GENESIS);
    });
}

#[test_traced]
fn canceling_a_build_waits_for_parent_delivery_before_finalization() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);
        let finalized = make_block(1, 1, GENESIS);
        let parent = make_block(2, 2, finalized.digest());
        let digest = parent.digest();
        let release = h
            .execution
            .script_delayed_new_payload(digest, Ok(PayloadStatusEnum::Valid));
        h.execution
            .script_new_payload(digest, Ok(PayloadStatusEnum::Valid));
        let build = h.build(round(3), digest);
        h.wait_until(|| h.marshal.fulfill_subscription(digest, parent.clone()))
            .await;
        h.wait_until(|| h.execution.new_payloads() == vec![digest])
            .await;

        h.deliver_tip(round(1), 1, finalized.digest());
        let finalized_digest = finalized.digest();
        let acknowledged = h.deliver_finalized(finalized);
        h.run_for(Duration::from_millis(20)).await;
        assert_eq!(h.execution.new_payloads(), vec![digest]);
        drop(build);
        h.run_for(Duration::from_millis(20)).await;
        assert_eq!(h.execution.new_payloads(), vec![digest]);
        release
            .send(())
            .expect("parent delivery must still be waiting for the EL");
        acknowledged
            .await
            .expect("finalization should proceed after the EL response");
        h.wait_until(|| h.execution.head() == digest).await;
        assert_eq!(
            h.execution.new_payloads(),
            vec![digest, finalized_digest, digest]
        );
        assert!(!h.execution.fcus().iter().any(|(_, _, attrs)| *attrs));
    });
}

#[test_traced]
fn superseding_a_submitted_build_fcu_still_tracks_its_response() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        let parent = make_block(1, 1, GENESIS);
        let digest = parent.digest();
        let release = h.execution.script_delayed_fcu(
            ForkchoiceState::from_finalized_head(GENESIS, digest),
            Ok(PayloadStatusEnum::Valid),
        );
        let first = h.build(round(2), digest);
        h.wait_until(|| h.marshal.fulfill_subscription(digest, parent.clone()))
            .await;
        h.wait_until(|| h.execution.fcus().contains(&(digest, GENESIS, true)))
            .await;

        // This context replaces the target while the first FCU is in flight.
        // Its response must still update local state so we repoint to genesis.
        drop(first);
        drop(h.build(round(3), GENESIS));
        h.run_for(Duration::from_millis(20)).await;
        assert_eq!(
            h.execution.fcus(),
            vec![STARTUP_FCU, (digest, GENESIS, true)]
        );
        release
            .send(())
            .expect("a submitted FCU must not be canceled");
        h.wait_until(|| h.execution.fcus().last() == Some(&(GENESIS, GENESIS, false)))
            .await;
        assert_eq!(h.execution.head(), GENESIS);
    });
}

#[test_traced]
fn build_on_an_old_head_is_rejected_before_network_finality_is_delivered() {
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

        // Network finality makes the old parent ineligible even before
        // the finalized block is delivered to the execution layer.
        let b1 = make_block(3, 1, GENESIS);
        let db1 = b1.digest();
        h.deliver_tip(round(3), 1, db1);
        h.build_on(round(4), 1, da1)
            .await
            .expect_err("the old parent must be rejected before scheduling");
        assert!(h.marshal.subscribe_log().is_empty());
        assert_eq!(h.execution.fcus().last(), Some(&(GENESIS, GENESIS, false)));

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
        // It runs on its own parent without replacing the convergence target.
        let old_proposal = make_block(3, 2, da1);
        h.execution
            .script_built_payload(built_payload(&old_proposal));
        h.build_on(round(3), 1, da1)
            .await
            .expect("an older request should still build on its parent");
        h.wait_until(|| h.execution.head() == db1).await;
        assert!(
            h.execution
                .fcus()
                .ends_with(&[(da1, GENESIS, true), (db1, GENESIS, false)])
        );
        let proposal = make_block(5, 2, db1);
        h.execution.script_built_payload(built_payload(&proposal));
        h.build(round(5), db1)
            .await
            .expect("the build on the current pending head must complete");
        assert_eq!(h.execution.head(), db1);
    });
}

#[test_traced]
fn builds_at_or_below_finality_are_rejected_before_fetching() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let (d1, d2) = (b1.digest(), b2.digest());
        h.deliver_tip(round(2), 2, d2);
        h.deliver_finalized(b1.clone()).await.unwrap();
        h.deliver_finalized(b2).await.unwrap();

        let other = make_block(2, 1, GENESIS);
        for (request_view, parent_view, parent) in [(3, 1, d1), (4, 2, other.digest())] {
            h.build_on(round(request_view), parent_view, parent)
                .await
                .expect_err("the stale parent must be rejected before fetching");
        }
        assert!(h.marshal.subscribe_log().is_empty());
        assert_eq!(h.execution.new_payloads(), vec![d1, d2]);
        assert!(
            !h.execution.fcus().iter().any(|(.., attrs)| *attrs),
            "a stale build must not submit payload attributes",
        );
        assert!(h.execution.pending_payload_jobs().is_empty());
        h.verify(round(5), make_block(5, 3, d2))
            .await
            .unwrap()
            .unwrap();
    });
}

#[test_traced]
fn queued_build_is_checked_against_finality_when_scheduled() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);
        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        let release = h
            .execution
            .script_delayed_new_payload(d1, Ok(PayloadStatusEnum::Valid));
        h.execution
            .script_new_payload(d1, Ok(PayloadStatusEnum::Valid));
        let mut verify = Box::pin(h.verify(round(1), b1.clone()));
        assert!(futures::poll!(&mut verify).is_pending());
        h.wait_until(|| h.execution.new_payloads() == vec![d1])
            .await;

        let mut build = h.build(round(2), GENESIS);
        h.run_for(Duration::from_millis(10)).await;
        h.deliver_tip(round(1), 1, d1);
        let finalized = h.deliver_finalized(b1);
        h.run_for(Duration::from_millis(10)).await;
        assert!(
            build
                .try_recv()
                .expect("the build remains queued")
                .is_none()
        );

        release.send(()).unwrap();
        let _ = verify
            .await
            .expect_err("the build replaced the verification slot");
        build
            .await
            .expect_err("finality made the queued parent stale");
        finalized
            .await
            .expect("rejecting the build should let finalization proceed");
        assert!(h.marshal.subscribe_log().is_empty());
        assert!(h.execution.fcus().iter().all(|(_, _, attrs)| !attrs));
        assert_eq!(h.execution.new_payloads(), vec![d1, d1]);
    });
}

#[test_traced]
fn active_build_keeps_its_finalized_target_when_network_finality_advances() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);
        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        let b2 = make_block(3, 2, d1);
        let d2 = b2.digest();
        h.execution
            .script_built_payload(built_payload(&make_block(2, 2, d1)));
        let build = h.build(round(2), d1);
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(d1, round(1))])
            .await;

        h.deliver_tip(round(3), 2, d2);
        let first_finalized = h.deliver_finalized(b1.clone());
        let second_finalized = h.deliver_finalized(b2);
        h.run_for(Duration::from_millis(10)).await;
        assert!(h.execution.new_payloads().is_empty());
        assert!(h.marshal.fulfill_subscription(d1, b1));

        build
            .await
            .expect("the admitted build must finish against its captured finality");
        assert!(h.execution.fcus().contains(&(d1, GENESIS, true)));
        first_finalized.await.unwrap();
        second_finalized.await.unwrap();
        assert_eq!(h.execution.new_payloads(), vec![d1, d1, d2]);
        assert_eq!(h.execution.finalized(), Some((2, d2)));
    });
}

#[test_traced]
fn canceling_a_build_waiting_on_marshal_releases_finalization() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();

        // Cancellation releases the execution slot without waiting for marshal.
        h.deliver_tip(round(1), 1, d1);
        let rx = h.build(round(2), d1);
        h.run_for(Duration::from_millis(100)).await;
        drop(rx);

        h.deliver_finalized(b1)
            .await
            .expect("finalized block should be acknowledged");

        h.wait_until(|| h.marshal.open_subscriptions().is_empty())
            .await;
        assert_eq!(
            h.execution.fcus(),
            vec![STARTUP_FCU, (d1, d1, false)],
            "only finalization submits an FCU after the build is canceled",
        );
        assert!(h.execution.pending_payload_jobs().is_empty());
    });
}

#[test_traced]
fn missing_payload_id_fails_the_build_after_tracking_forkchoice() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        let parent = make_block(1, 1, GENESIS);
        let digest = parent.digest();
        h.verify(round(1), parent).await.unwrap().unwrap();

        // Invalid payload attributes after applying forkchoice are normalized
        // by the EL adapter to VALID without an ID. This is its actor-visible
        // result: the build fails, but its forkchoice must still be tracked.
        h.execution.suppress_payload_ids(true);
        let rx = h.build(round(2), digest);
        rx.await
            .expect_err("a build the execution layer did not register must fail");
        assert_eq!(h.execution.head(), digest);
        drop(h.build(round(3), GENESIS));
        h.wait_until(|| h.execution.head() == GENESIS).await;
        assert_eq!(h.execution.fcus().last(), Some(&(GENESIS, GENESIS, false)));

        // Not fatal: a later build succeeds.
        h.execution.suppress_payload_ids(false);
        let proposal = make_block(1, 1, GENESIS);
        h.execution.script_built_payload(built_payload(&proposal));
        let rx = h.build(round(4), GENESIS);
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
