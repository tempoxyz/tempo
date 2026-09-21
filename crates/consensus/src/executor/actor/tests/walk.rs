//! Verification retains the candidate and discovers ancestors from SYNCING.

use std::{sync::Arc, time::Duration};

use alloy_rpc_types_engine::PayloadStatusEnum;
use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, deterministic};

use super::harness::{FakeExecution, GENESIS, Harness, built_payload, make_block, round};

#[test_traced]
fn valid_candidate_leaves_its_parent_for_independent_delivery() {
    deterministic::Runner::default().start(|context| async move {
        let parent = make_block(1, 1, GENESIS);
        let candidate = make_block(2, 2, parent.digest());
        let h = Harness::start_at_genesis(&context);
        h.verify(round(1), parent.clone()).await.unwrap().unwrap();
        let release = h
            .execution
            .script_delayed_new_payload(parent.digest(), Ok(PayloadStatusEnum::Valid));

        h.verify(round(2), candidate.clone())
            .await
            .unwrap()
            .unwrap();
        h.wait_until(|| h.execution.new_payloads().len() == 3).await;
        assert_eq!(h.execution.head(), GENESIS);
        release.send(()).unwrap();
        h.wait_until(|| h.execution.head() == parent.digest()).await;
        h.run_for(Duration::from_millis(50)).await;
        assert_eq!(
            h.execution.new_payloads(),
            vec![parent.digest(), candidate.digest(), parent.digest()]
        );
        assert!(h.marshal.subscribe_log().is_empty());
        assert!(
            h.execution
                .fcus()
                .iter()
                .all(|(head, _, _)| *head != candidate.digest())
        );
    });
}

#[test_traced]
fn verification_walk_uses_local_bodies_before_fetching_missing_ancestors() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let b3 = make_block(3, 3, b2.digest());
        let (d1, d2, d3) = (b1.digest(), b2.digest(), b3.digest());
        h.execution.add_body(b2);

        let mut verify = Box::pin(h.verify(round(3), b3));
        assert!(futures::poll!(&mut verify).is_pending());
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(d1, round(1))])
            .await;
        // The verification descends through the local body to b1's fetch.
        // Convergence found the pending head b2 locally as well and probes
        // it on its own; both walks share the one fetch for b1.
        assert_eq!(h.execution.new_payloads(), vec![d3, d2, d2]);
        assert!(h.marshal.fulfill_subscription(d1, b1));

        verify
            .await
            .unwrap()
            .expect("verification should finish through the local parent");
        h.wait_until(|| h.execution.head() == d2).await;
        assert_eq!(h.marshal.subscribe_log(), vec![(d1, round(1))]);
        assert_eq!(h.execution.new_payloads(), vec![d3, d2, d2, d1, d3, d1, d2]);
    });
}

#[test_traced]
fn canceling_verification_leaves_its_parent_eligible_for_delivery() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        let parent = make_block(1, 1, GENESIS);
        let candidate = make_block(2, 2, parent.digest());
        let mut verify = Box::pin(h.verify(round(2), candidate.clone()));
        assert!(futures::poll!(&mut verify).is_pending());
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(parent.digest(), round(1))])
            .await;
        drop(verify);
        // Convergence subscribed for the same parent, the pending head, and
        // keeps the shared fetch open after the verification is gone.
        h.run_for(Duration::from_millis(10)).await;
        assert_eq!(
            h.marshal.open_subscriptions(),
            vec![(parent.digest(), round(1))]
        );
        assert_eq!(h.marshal.subscribe_log().len(), 1);
        assert!(
            h.marshal
                .fulfill_subscription(parent.digest(), parent.clone())
        );
        h.wait_until(|| h.execution.head() == parent.digest()).await;
        assert_eq!(
            h.execution.new_payloads(),
            vec![candidate.digest(), parent.digest()]
        );
        assert!(
            h.execution
                .fcus()
                .iter()
                .all(|(head, _, _)| *head != candidate.digest())
        );

        h.execution
            .script_built_payload(built_payload(&make_block(1, 1, GENESIS)));
        h.build(round(1), GENESIS)
            .await
            .expect("the older build should run without replacing the newer target");
        h.wait_until(|| h.execution.head() == parent.digest()).await;
    });
}

#[test_traced]
fn invalid_verification_leaves_its_parent_eligible_for_delivery() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        let parent = make_block(1, 1, GENESIS);
        let candidate = make_block(2, 2, parent.digest());
        h.execution.script_new_payload(
            candidate.digest(),
            Ok(PayloadStatusEnum::Invalid {
                validation_error: "invalid candidate".into(),
            }),
        );
        assert!(
            h.verify(round(2), candidate.clone())
                .await
                .unwrap()
                .is_none()
        );

        h.wait_until(|| {
            h.marshal
                .fulfill_subscription(parent.digest(), parent.clone())
        })
        .await;
        h.wait_until(|| h.execution.head() == parent.digest()).await;
        assert_eq!(
            h.execution.new_payloads(),
            vec![candidate.digest(), parent.digest()]
        );
        assert!(
            h.execution
                .fcus()
                .iter()
                .all(|(head, _, _)| *head != candidate.digest())
        );
    });
}

#[test_traced]
fn finalized_tip_takes_over_an_independent_head_walk() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);
        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let candidate = make_block(3, 3, b2.digest());
        let (d1, d2, d3) = (b1.digest(), b2.digest(), candidate.digest());
        let mut verify = Box::pin(h.verify(round(3), candidate));
        assert!(futures::poll!(&mut verify).is_pending());
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(d2, round(2))])
            .await;
        drop(verify);
        // Convergence shares the fetch for the pending head b2 and keeps it
        // open after the verification is gone.
        h.run_for(Duration::from_millis(10)).await;
        assert_eq!(h.marshal.open_subscriptions(), vec![(d2, round(2))]);
        assert_eq!(h.marshal.subscribe_log().len(), 1);
        assert!(h.marshal.fulfill_subscription(d2, b2.clone()));
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(d1, round(1))])
            .await;

        h.deliver_tip(round(2), 2, d2);
        h.wait_until(|| h.marshal.open_subscriptions().is_empty())
            .await;
        assert_eq!(h.execution.new_payloads(), vec![d3, d2]);
        assert_eq!(h.execution.head(), GENESIS);

        h.deliver_finalized(b1).await.unwrap();
        h.deliver_finalized(b2).await.unwrap();
        assert_eq!(h.execution.new_payloads(), vec![d3, d2, d1, d2]);
        assert_eq!(h.execution.head(), d2);
        assert_eq!(h.execution.finalized(), Some((2, d2)));
        assert_eq!(h.marshal.subscribe_log().len(), 2);
    });
}

#[test_traced]
fn a_build_on_another_branch_leaves_a_waiting_verification_alone() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        let other_parent = make_block(1, 1, GENESIS);
        let other_digest = other_parent.digest();
        h.execution
            .script_built_payload(built_payload(&other_parent));
        h.build(round(1), GENESIS).await.unwrap();

        let missing = make_block(2, 1, GENESIS);
        let candidate = make_block(3, 2, missing.digest());
        let mut verify = Box::pin(h.verify(round(3), candidate));
        assert!(futures::poll!(&mut verify).is_pending());
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(missing.digest(), round(2))])
            .await;

        let proposal = make_block(4, 2, other_digest);
        h.execution.script_built_payload(built_payload(&proposal));
        let mut build = h.build_on(round(4), 1, other_digest);
        h.wait_until(|| h.execution.head() == other_digest).await;
        h.wait_until(|| h.execution.fcus().contains(&(other_digest, GENESIS, true)))
            .await;
        assert!(build.try_recv().unwrap().is_some());
        assert!(
            futures::poll!(&mut verify).is_pending(),
            "the build does not displace the verification"
        );
        assert_eq!(
            h.marshal.open_subscriptions(),
            vec![(missing.digest(), round(2))],
            "the verification keeps waiting for its ancestor"
        );
        drop(verify);
        // Queued cancellations are reaped on the next actor iteration.
        drop(h.build_on(round(5), 1, other_digest));
        h.wait_until(|| h.marshal.open_subscriptions().is_empty())
            .await;
    });
}
#[test_traced]
fn a_build_keeps_the_execution_slot_while_a_verification_waits_for_its_ancestor() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        let parent = make_block(1, 1, GENESIS);
        let candidate = make_block(2, 2, parent.digest());
        let candidate_digest = candidate.digest();
        let mut verify = Box::pin(h.verify(round(2), candidate));
        assert!(futures::poll!(&mut verify).is_pending());
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(parent.digest(), round(1))])
            .await;

        let other = make_block(3, 1, GENESIS);
        let proposal = make_block(4, 2, other.digest());
        h.execution.script_built_payload(built_payload(&proposal));
        let build = h.build(round(4), other.digest());
        h.wait_until(|| {
            h.marshal.open_subscriptions()
                == vec![(parent.digest(), round(1)), (other.digest(), round(3))]
        })
        .await;
        // The build owns the execution slot while waiting for its parent.
        h.run_for(Duration::from_millis(20)).await;
        assert!(futures::poll!(&mut verify).is_pending());
        assert_eq!(h.execution.new_payloads(), vec![candidate_digest]);
        assert!(
            h.marshal
                .fulfill_subscription(other.digest(), other.clone())
        );
        build.await.unwrap();
        h.run_for(Duration::from_millis(20)).await;
        assert_eq!(h.execution.head(), other.digest());

        // The verification resumes once its ancestor arrives.
        assert!(
            h.marshal
                .fulfill_subscription(parent.digest(), parent.clone())
        );
        assert!(verify.await.unwrap().is_some());
        assert_eq!(
            h.execution.new_payloads(),
            vec![
                candidate_digest,
                other.digest(),
                parent.digest(),
                candidate_digest
            ]
        );
        assert_eq!(
            h.execution.head(),
            other.digest(),
            "the older verification does not move the head off the newer parent"
        );
    });
}
#[test_traced]
fn a_newer_verification_probes_while_the_older_walk_waits_for_its_ancestor() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        let parent = make_block(1, 1, GENESIS);
        let candidate = make_block(2, 2, parent.digest());
        let old_digest = candidate.digest();
        let mut verify = Box::pin(h.verify(round(2), candidate));
        assert!(futures::poll!(&mut verify).is_pending());
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(parent.digest(), round(1))])
            .await;

        // The older walk is waiting for its ancestor, so a newer request is
        // probed right away. It runs its own walk and waits for its own
        // parent alongside.
        let other = make_block(3, 1, GENESIS);
        let candidate = make_block(4, 2, other.digest());
        let new_digest = candidate.digest();
        let mut newer = Box::pin(h.verify(round(4), candidate));
        assert!(futures::poll!(&mut newer).is_pending());
        h.wait_until(|| {
            h.marshal.open_subscriptions()
                == vec![(parent.digest(), round(1)), (other.digest(), round(3))]
        })
        .await;
        assert_eq!(h.execution.new_payloads(), vec![old_digest, new_digest]);

        assert!(
            h.marshal
                .fulfill_subscription(parent.digest(), parent.clone())
        );
        // Both verifications are queued, and convergence waits on the newer
        // branch. This parent delivery alone must wake the older walk, well
        // before the harness's one-hour heartbeat.
        h.wait_until(|| h.execution.new_payloads().len() == 4).await;
        verify.await.unwrap().unwrap();
        assert_eq!(
            h.execution.new_payloads(),
            vec![old_digest, new_digest, parent.digest(), old_digest]
        );

        assert!(
            h.marshal
                .fulfill_subscription(other.digest(), other.clone())
        );
        newer.await.unwrap().unwrap();
        h.wait_until(|| h.execution.head() == other.digest()).await;
        assert_eq!(
            h.execution.new_payloads(),
            vec![
                old_digest,
                new_digest,
                parent.digest(),
                old_digest,
                other.digest(),
                new_digest,
                other.digest(),
            ]
        );
        assert_eq!(
            h.marshal.subscribe_log(),
            vec![(parent.digest(), round(1)), (other.digest(), round(3))]
        );
    });
}
#[test_traced]
fn simultaneously_fetched_parents_resume_the_newest_verification_first() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        let parent = make_block(1, 1, GENESIS);
        let candidate = make_block(2, 2, parent.digest());
        let old_digest = candidate.digest();
        let mut older = Box::pin(h.verify(round(2), candidate));
        assert!(futures::poll!(&mut older).is_pending());
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(parent.digest(), round(1))])
            .await;

        let other = make_block(3, 1, GENESIS);
        let candidate = make_block(4, 2, other.digest());
        let new_digest = candidate.digest();
        let mut newer = Box::pin(h.verify(round(4), candidate));
        assert!(futures::poll!(&mut newer).is_pending());
        h.wait_until(|| {
            h.marshal.open_subscriptions()
                == vec![(parent.digest(), round(1)), (other.digest(), round(3))]
        })
        .await;

        // Wake the older subscription first, without yielding before the
        // newer one is ready. Pool completion order must not pick the slot.
        assert!(
            h.marshal
                .fulfill_subscription(parent.digest(), parent.clone())
        );
        assert!(
            h.marshal
                .fulfill_subscription(other.digest(), other.clone())
        );
        h.wait_until(|| h.execution.new_payloads().len() >= 6).await;
        newer.await.unwrap().unwrap();
        older.await.unwrap().unwrap();
        assert_eq!(
            &h.execution.new_payloads()[..6],
            &[
                old_digest,
                new_digest,
                other.digest(),
                new_digest,
                parent.digest(),
                old_digest,
            ],
        );
    });
}

#[test_traced]
fn each_request_for_the_same_block_gets_its_own_delivery_and_verdict() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        let block = make_block(1, 1, GENESIS);
        let digest = block.digest();
        let old_reply = h
            .execution
            .script_delayed_new_payload(digest, Ok(PayloadStatusEnum::Valid));
        let new_reply = h
            .execution
            .script_delayed_new_payload(digest, Ok(PayloadStatusEnum::Valid));
        let mut verify = Box::pin(h.verify(round(1), block.clone()));
        assert!(futures::poll!(&mut verify).is_pending());
        h.wait_until(|| h.execution.new_payloads() == vec![digest])
            .await;
        let mut newer = Box::pin(h.verify(round(2), block));
        assert!(futures::poll!(&mut newer).is_pending());
        h.run_for(Duration::from_millis(1)).await;
        old_reply.send(()).unwrap();
        verify
            .await
            .unwrap()
            .expect("the old request gets its own verdict");
        h.wait_until(|| h.execution.new_payloads() == vec![digest, digest])
            .await;
        assert!(futures::poll!(&mut newer).is_pending());
        new_reply.send(()).unwrap();
        newer.await.unwrap().unwrap();
        assert!(h.marshal.subscribe_log().is_empty());
    });
}
#[test_traced]
fn a_canceled_delivery_cannot_complete_a_retry_in_the_same_round() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        let block = make_block(1, 1, GENESIS);
        let digest = block.digest();
        let old_reply = h
            .execution
            .script_delayed_new_payload(digest, Ok(PayloadStatusEnum::Valid));
        let new_reply = h
            .execution
            .script_delayed_new_payload(digest, Ok(PayloadStatusEnum::Valid));
        let mut verify = Box::pin(h.verify(round(1), block.clone()));
        assert!(futures::poll!(&mut verify).is_pending());
        h.wait_until(|| h.execution.new_payloads() == vec![digest])
            .await;
        drop(verify);
        h.run_for(Duration::from_millis(1)).await;

        let mut retry = Box::pin(h.verify(round(1), block));
        assert!(futures::poll!(&mut retry).is_pending());
        h.run_for(Duration::from_millis(1)).await;
        assert_eq!(h.execution.new_payloads(), vec![digest]);
        old_reply
            .send(())
            .expect("delivery must still be waiting for the EL");
        h.wait_until(|| h.execution.new_payloads() == vec![digest, digest])
            .await;
        assert!(futures::poll!(&mut retry).is_pending());
        new_reply.send(()).unwrap();
        retry.await.unwrap().unwrap();
        assert!(h.marshal.subscribe_log().is_empty());
    });
}

#[test_traced]
fn a_waiting_verification_does_not_wake_a_rejected_pending_head_early() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);
        let finalized = make_block(1, 1, GENESIS);
        h.deliver_tip(round(1), 1, finalized.digest());
        let candidate = make_block(2, 2, finalized.digest());
        let mut verify = Box::pin(h.verify(round(2), candidate));
        assert!(futures::poll!(&mut verify).is_pending());

        let parent = make_block(3, 2, finalized.digest());
        let digest = parent.digest();
        h.execution.script_new_payload(
            digest,
            Ok(PayloadStatusEnum::Invalid {
                validation_error: "retry later".into(),
            }),
        );
        h.execution
            .script_new_payload(digest, Ok(PayloadStatusEnum::Valid));
        drop(h.build(round(4), digest));
        h.wait_until(|| h.marshal.fulfill_subscription(digest, parent.clone()))
            .await;
        h.wait_until(|| h.execution.new_payloads().contains(&digest))
            .await;
        h.run_for(Duration::from_secs(2)).await;
        assert_eq!(
            h.execution
                .new_payloads()
                .iter()
                .filter(|d| **d == digest)
                .count(),
            1
        );

        h.deliver_finalized(finalized).await.unwrap();
        verify.await.unwrap().unwrap();
        h.wait_until(|| h.execution.head() == digest).await;
        assert_eq!(h.execution.head(), digest);
    });
}

#[test_traced]
fn a_walk_waiting_for_its_parent_yields_the_slot() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        // B's parent is missing: B probes, subscribes for the parent, and
        // leaves the slot while it waits.
        let parent_b = make_block(4, 1, GENESIS);
        let candidate_b = make_block(5, 2, parent_b.digest());
        let (pb, b) = (parent_b.digest(), candidate_b.digest());
        let mut verify_b = Box::pin(h.verify(round(5), candidate_b));
        assert!(futures::poll!(&mut verify_b).is_pending());
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(pb, round(4))])
            .await;
        assert_eq!(h.execution.new_payloads(), vec![b]);

        // Two more candidates arrive: an older one with a long missing
        // ancestry, which probes as soon as it arrives and then waits for
        // its parent too, and a newer one on genesis, which completes.
        let a1 = make_block(1, 1, GENESIS);
        let a2 = make_block(2, 2, a1.digest());
        let a3 = make_block(3, 3, a2.digest());
        let (d1, d2, d3) = (a1.digest(), a2.digest(), a3.digest());
        let mut verify_a = Box::pin(h.verify(round(3), a3));
        assert!(futures::poll!(&mut verify_a).is_pending());
        let candidate_c = make_block(6, 1, GENESIS);
        let c = candidate_c.digest();
        let mut verify_c = Box::pin(h.verify(round(6), candidate_c));
        assert!(futures::poll!(&mut verify_c).is_pending());
        assert!(verify_c.await.unwrap().is_some());
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(pb, round(4)), (d2, round(2))])
            .await;
        assert_eq!(h.execution.new_payloads(), vec![b, d3, c]);
        assert!(futures::poll!(&mut verify_b).is_pending());
        assert!(futures::poll!(&mut verify_a).is_pending());

        // B's parent arrives: B takes the slot back and finishes. A's
        // ancestry then arrives one fetch at a time.
        assert!(h.marshal.fulfill_subscription(pb, parent_b.clone()));
        assert!(verify_b.await.unwrap().is_some());
        assert_eq!(h.execution.new_payloads(), vec![b, d3, c, pb, b]);
        assert!(h.marshal.fulfill_subscription(d2, a2.clone()));
        h.wait_until(|| h.marshal.fulfill_subscription(d1, a1.clone()))
            .await;
        assert!(verify_a.await.unwrap().is_some());
        assert_eq!(
            h.execution.new_payloads(),
            vec![b, d3, c, pb, b, d2, d1, d3]
        );
        assert_eq!(
            h.marshal.subscribe_log(),
            vec![(pb, round(4)), (d2, round(2)), (d1, round(1))]
        );
    });
}
#[test_traced]
fn canceling_the_active_verification_releases_its_ancestor_at_once() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);
        let finalized = make_block(1, 1, GENESIS);
        let a1 = make_block(2, 2, finalized.digest());
        let a2 = make_block(3, 3, a1.digest());
        let (d1, d2) = (a1.digest(), a2.digest());

        // The walk waits for its missing parent.
        let mut verify = Box::pin(h.verify(round(3), a2));
        assert!(futures::poll!(&mut verify).is_pending());
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(d1, round(2))])
            .await;

        // A finalization takes the execution slot, so the walk sits on the
        // fetched ancestor above finality without being able to probe it.
        let f = finalized.digest();
        let release = h
            .execution
            .script_delayed_new_payload(f, Ok(PayloadStatusEnum::Valid));
        h.deliver_tip(round(1), 1, f);
        // Keep convergence on finality so only the verification owns the ancestor.
        drop(h.build_on(round(4), 1, f));
        let acknowledged = h.deliver_finalized(finalized);
        h.wait_until(|| h.execution.new_payloads() == vec![d2, f])
            .await;
        let delivered = Arc::new(a1.clone());
        let weak = Arc::downgrade(&delivered);
        assert!(h.marshal.fulfill_subscription(d1, delivered));
        h.run_for(Duration::from_millis(10)).await;
        assert!(
            weak.upgrade().is_some(),
            "the active walk holds its ancestor"
        );

        // Its requester going away is noticed without any other event.
        drop(verify);
        h.wait_until(|| weak.upgrade().is_none()).await;

        release.send(()).unwrap();
        acknowledged.await.unwrap();
        assert_eq!(h.execution.new_payloads(), vec![d2, f]);
    });
}

#[test_traced]
fn syncing_walks_backward_one_response_at_a_time_then_reprobes_the_candidate() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let b3 = make_block(3, 3, b2.digest());
        let (d1, d2, d3) = (b1.digest(), b2.digest(), b3.digest());
        let release_candidate = h
            .execution
            .script_delayed_new_payload(d3, Ok(PayloadStatusEnum::Syncing));
        h.execution
            .script_new_payload(d3, Ok(PayloadStatusEnum::Valid));
        let release = h
            .execution
            .script_delayed_new_payload(d2, Ok(PayloadStatusEnum::Syncing));
        h.execution
            .script_new_payload(d2, Ok(PayloadStatusEnum::Valid));

        let mut verify = Box::pin(h.verify(round(3), b3));
        assert!(futures::poll!(&mut verify).is_pending());
        h.wait_until(|| h.execution.new_payloads() == vec![d3])
            .await;
        assert_eq!(
            h.marshal.subscribe_log(),
            vec![(d2, round(2))],
            "the candidate is sent directly; only convergence fetches its parent, the pending head"
        );
        release_candidate.send(()).unwrap();
        // The verification joins the fetch convergence already opened.
        h.wait_until(|| h.marshal.waiters(d2) == 2).await;
        assert_eq!(h.marshal.open_subscriptions(), vec![(d2, round(2))]);
        assert_eq!(h.execution.new_payloads(), vec![d3]);
        assert!(h.marshal.fulfill_subscription(d2, b2.clone()));
        h.wait_until(|| h.execution.new_payloads() == vec![d3, d2])
            .await;
        assert!(
            h.marshal.open_subscriptions().is_empty(),
            "no ancestor fetch before the engine answers"
        );

        release.send(()).unwrap();
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(d1, round(1))])
            .await;
        assert!(h.marshal.fulfill_subscription(d1, b1));
        assert!(verify.await.unwrap().is_some());
        // Convergence received b2 through the shared fetch and probed it
        // once the verification's walk parked; its VALID made b2 HEAD.
        h.wait_until(|| h.execution.head() == d2).await;
        assert_eq!(h.execution.new_payloads(), vec![d3, d2, d2, d1, d3]);
        assert_eq!(
            h.marshal.subscribe_log(),
            vec![(d2, round(2)), (d1, round(1))]
        );
        assert!(h.execution.fcus().iter().all(|(head, _, _)| *head != d3));
    });
}

#[test_traced]
fn valid_ancestor_stops_the_walk_above_the_finalized_tip() {
    deterministic::Runner::default().start(|context| async move {
        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let b3 = make_block(3, 3, b2.digest());
        let (d2, d3) = (b2.digest(), b3.digest());
        let execution = FakeExecution::new();
        execution.seed_canonical_block(&b1);
        let h = Harness::builder().execution(execution).start(&context);

        let mut verify = Box::pin(h.verify(round(3), b3));
        assert!(futures::poll!(&mut verify).is_pending());
        h.wait_until(|| h.marshal.fulfill_subscription(d2, b2.clone()))
            .await;
        assert!(verify.await.unwrap().is_some());
        h.wait_until(|| h.execution.head() == d2).await;
        assert_eq!(h.execution.new_payloads(), vec![d3, d2, d3, d2]);
        assert_eq!(
            h.marshal.subscribe_log(),
            vec![(d2, round(2))],
            "VALID b2 makes fetching b1 unnecessary"
        );
    });
}

#[test_traced]
fn syncing_with_a_conflicting_finalized_parent_is_rejected() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);
        let finalized = make_block(1, 1, GENESIS);
        let other = make_block(2, 1, GENESIS);
        let candidate = make_block(3, 2, other.digest());
        let digest = candidate.digest();
        h.deliver_tip(round(1), 1, finalized.digest());
        // Keep independent HEAD convergence on the finalized branch.
        drop(h.build_on(round(4), 1, finalized.digest()));
        h.execution
            .script_new_payload(digest, Ok(PayloadStatusEnum::Syncing));

        assert!(h.verify(round(3), candidate).await.unwrap().is_none());
        assert_eq!(h.execution.new_payloads(), vec![digest]);
        assert!(h.marshal.subscribe_log().is_empty());
        assert_eq!(h.execution.head(), GENESIS);
    });
}

#[test_traced]
fn verification_walk_rejects_an_ancestor_on_a_conflicting_branch() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);
        let finalized = make_block(1, 1, GENESIS);
        let other = make_block(2, 1, GENESIS);
        let parent = make_block(3, 2, other.digest());
        let candidate = make_block(4, 3, parent.digest());
        let (p, c) = (parent.digest(), candidate.digest());
        h.deliver_tip(round(1), 1, finalized.digest());
        drop(h.build_on(round(5), 1, finalized.digest()));

        let mut verify = Box::pin(h.verify(round(4), candidate));
        assert!(futures::poll!(&mut verify).is_pending());
        h.wait_until(|| h.marshal.fulfill_subscription(p, parent.clone()))
            .await;
        assert!(verify.await.unwrap().is_none());
        assert_eq!(h.execution.new_payloads(), vec![c, p]);
        assert_eq!(h.marshal.subscribe_log(), vec![(p, round(3))]);
        assert_eq!(h.execution.head(), GENESIS);
    });
}

#[test_traced]
fn syncing_redelivers_the_parent_even_if_a_previous_verification_said_valid() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        h.verify(round(1), b1).await.unwrap().unwrap();
        let b2 = make_block(2, 2, d1);
        let d2 = b2.digest();
        h.execution
            .script_new_payload(d2, Ok(PayloadStatusEnum::Syncing));
        h.execution
            .script_new_payload(d2, Ok(PayloadStatusEnum::Valid));
        h.verify(round(2), b2).await.unwrap().unwrap();
        h.wait_until(|| h.execution.head() == d1).await;
        assert_eq!(h.execution.new_payloads(), vec![d1, d2, d1, d2, d1]);
        assert!(h.marshal.subscribe_log().is_empty());
    });
}

#[test_traced]
fn a_valid_ancestor_leaves_the_verdict_to_the_candidate() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        // Keep independent HEAD convergence out of the verdict check.
        drop(h.build(round(3), GENESIS));
        let parent = make_block(1, 1, GENESIS);
        let candidate = make_block(2, 2, parent.digest());
        let (parent_digest, candidate_digest) = (parent.digest(), candidate.digest());
        h.execution
            .script_new_payload(candidate_digest, Ok(PayloadStatusEnum::Syncing));
        h.execution.script_new_payload(
            candidate_digest,
            Ok(PayloadStatusEnum::Invalid {
                validation_error: "invalid candidate".into(),
            }),
        );
        h.execution
            .script_new_payload(parent_digest, Ok(PayloadStatusEnum::Valid));
        let mut verify = Box::pin(h.verify(round(2), candidate));
        assert!(futures::poll!(&mut verify).is_pending());
        h.wait_until(|| {
            h.marshal
                .fulfill_subscription(parent_digest, parent.clone())
        })
        .await;
        assert!(verify.await.unwrap().is_none());
        assert_eq!(
            h.execution.new_payloads(),
            vec![candidate_digest, parent_digest, candidate_digest]
        );
        assert!(
            h.execution
                .fcus()
                .iter()
                .all(|(head, _, _)| *head != candidate_digest)
        );
    });
}

#[test_traced]
fn an_invalid_ancestor_is_the_candidates_verdict() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        // Keep independent HEAD convergence out of the verdict check.
        drop(h.build(round(3), GENESIS));
        let parent = make_block(1, 1, GENESIS);
        let candidate = make_block(2, 2, parent.digest());
        let (parent_digest, candidate_digest) = (parent.digest(), candidate.digest());
        h.execution
            .script_new_payload(candidate_digest, Ok(PayloadStatusEnum::Syncing));
        h.execution.script_new_payload(
            parent_digest,
            Ok(PayloadStatusEnum::Invalid {
                validation_error: "bad ancestor".into(),
            }),
        );
        let mut verify = Box::pin(h.verify(round(2), candidate));
        assert!(futures::poll!(&mut verify).is_pending());
        h.wait_until(|| {
            h.marshal
                .fulfill_subscription(parent_digest, parent.clone())
        })
        .await;
        assert!(verify.await.unwrap().is_none());
        assert_eq!(
            h.execution.new_payloads(),
            vec![candidate_digest, parent_digest],
            "the rejected ancestor decides; the candidate is not probed again",
        );
        assert!(
            h.execution
                .fcus()
                .iter()
                .all(|(head, _, _)| *head != candidate_digest)
        );
    });
}

#[test_traced]
fn syncing_restarts_the_entire_walk_without_retaining_previous_ancestors() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        let mut parent = GENESIS;
        let ancestors = (1..=16)
            .map(|height| {
                let block = make_block(height, height, parent);
                parent = block.digest();
                block
            })
            .collect::<Vec<_>>();
        let candidate = make_block(17, 17, parent);
        let c = candidate.digest();
        h.execution.add_body(ancestors[0].clone());
        for _ in 0..3 {
            h.execution
                .script_new_payload(c, Ok(PayloadStatusEnum::Syncing));
            for ancestor in &ancestors[1..] {
                h.execution
                    .script_new_payload(ancestor.digest(), Ok(PayloadStatusEnum::Syncing));
            }
        }
        let release = h
            .execution
            .script_delayed_new_payload(c, Ok(PayloadStatusEnum::Valid));
        let mut verify = Box::pin(h.verify(round(17), candidate));
        assert!(futures::poll!(&mut verify).is_pending());
        h.wait_until(|| !h.marshal.open_subscriptions().is_empty())
            .await;
        // Keep independent HEAD convergence out of this verification walk.
        drop(h.build_on(round(18), 0, GENESIS));
        h.run_for(Duration::from_millis(1)).await;

        let mut expected = Vec::new();
        let mut previous: Option<std::sync::Weak<crate::consensus::block::Block>> = None;
        for _ in 0..3 {
            expected.push(c);
            for ancestor in ancestors[1..].iter().rev() {
                let digest = ancestor.digest();
                h.wait_until(|| {
                    h.marshal
                        .open_subscriptions()
                        .iter()
                        .any(|(d, _)| *d == digest)
                })
                .await;
                let block = Arc::new(ancestor.clone());
                let weak = Arc::downgrade(&block);
                assert!(h.marshal.fulfill_subscription(digest, block));
                expected.push(digest);
                h.wait_until(|| h.execution.new_payloads().len() >= expected.len())
                    .await;
                if let Some(previous) = previous.take() {
                    assert!(
                        previous.upgrade().is_none(),
                        "the previous ancestor must be released"
                    );
                }
                previous = Some(weak);
            }
            // The last ancestor's body comes from EL. Its VALID response
            // restarts at the candidate and releases the last held cursor.
            expected.push(ancestors[0].digest());
            h.wait_until(|| h.execution.new_payloads().len() > expected.len())
                .await;
            assert!(previous.take().unwrap().upgrade().is_none());
        }
        expected.push(c);
        assert_eq!(h.execution.new_payloads(), expected);
        assert_eq!(h.marshal.subscribe_log().len(), 3 * (ancestors.len() - 1));
        assert!(
            futures::poll!(&mut verify).is_pending(),
            "only the candidate's own verdict completes verification"
        );
        release.send(()).unwrap();
        assert!(verify.await.unwrap().is_some());
        assert_eq!(h.execution.head(), GENESIS);
    });
}

#[test_traced]
fn reaching_a_static_finalized_boundary_restarts_the_walk() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        let parent = make_block(1, 1, GENESIS);
        let candidate = make_block(2, 2, parent.digest());
        let (p, c) = (parent.digest(), candidate.digest());
        for status in [
            PayloadStatusEnum::Syncing,
            PayloadStatusEnum::Syncing,
            PayloadStatusEnum::Valid,
        ] {
            h.execution.script_new_payload(c, Ok(status));
        }
        h.execution
            .script_new_payload(p, Ok(PayloadStatusEnum::Syncing));
        h.execution
            .script_new_payload(p, Ok(PayloadStatusEnum::Valid));
        let mut verify = Box::pin(h.verify(round(2), candidate));
        assert!(futures::poll!(&mut verify).is_pending());
        h.wait_until(|| !h.marshal.open_subscriptions().is_empty())
            .await;
        drop(h.build_on(round(3), 0, GENESIS));
        h.run_for(Duration::from_millis(1)).await;
        h.wait_until(|| h.marshal.fulfill_subscription(p, parent.clone()))
            .await;

        // No finality update arrives. The walk reaches genesis, restarts
        // from the candidate and fetches the parent again after SYNCING.
        h.wait_until(|| h.marshal.subscribe_log().len() == 2).await;
        assert!(futures::poll!(&mut verify).is_pending());
        assert_eq!(h.execution.new_payloads(), vec![c, p, c]);
        assert!(h.marshal.fulfill_subscription(p, parent));
        assert!(verify.await.unwrap().is_some());
        assert_eq!(h.execution.new_payloads(), vec![c, p, c, p, c]);
        assert_eq!(h.marshal.subscribe_log(), vec![(p, round(1)); 2]);
        assert_eq!(h.execution.head(), GENESIS);
    });
}

#[test_traced]
fn advancing_finality_cancels_the_fetch_and_reprobes_the_candidate() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);
        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let b3 = make_block(3, 3, b2.digest());
        let (d1, d2, d3) = (b1.digest(), b2.digest(), b3.digest());
        let mut verify = Box::pin(h.verify(round(3), b3));
        assert!(futures::poll!(&mut verify).is_pending());
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(d2, round(2))])
            .await;

        h.deliver_tip(round(2), 2, d2);
        h.wait_until(|| {
            h.marshal.open_subscriptions().is_empty() && h.execution.new_payloads() == vec![d3, d3]
        })
        .await;
        assert!(futures::poll!(&mut verify).is_pending());
        // Reprobing reaches the new boundary and waits for its delivery.
        // Pruning again must not restart that wait on every loop iteration.
        h.deliver_finalized(b1).await.unwrap();
        assert!(futures::poll!(&mut verify).is_pending());
        assert_eq!(h.execution.new_payloads(), vec![d3, d3, d1]);
        h.deliver_finalized(b2).await.unwrap();
        verify.await.unwrap().unwrap();
        assert_eq!(h.marshal.subscribe_log(), vec![(d2, round(2))]);
        assert_eq!(
            h.execution
                .new_payloads()
                .iter()
                .filter(|d| **d == d1 || **d == d2)
                .copied()
                .collect::<Vec<_>>(),
            vec![d1, d2],
            "only finalization delivers blocks below the moving boundary"
        );
        assert!(h.execution.fcus().iter().all(|(head, _, _)| *head != d3));
    });
}

#[test_traced]
fn advancing_finalized_round_cancels_a_fetch_above_the_finalized_height() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);
        let b1 = make_block(1, 1, GENESIS);
        let parent = make_block(2, 2, b1.digest());
        let candidate = make_block(3, 3, parent.digest());
        let finalized = make_block(2, 1, GENESIS);
        let (p, c) = (parent.digest(), candidate.digest());
        let mut verify = Box::pin(h.verify(round(3), candidate));
        assert!(futures::poll!(&mut verify).is_pending());
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(p, round(2))])
            .await;

        // The candidate's round survives, but its missing parent's round
        // is covered even though that parent's height is above finality.
        h.deliver_tip(round(2), 1, finalized.digest());
        h.wait_until(|| {
            h.marshal.open_subscriptions().is_empty() && h.execution.new_payloads() == vec![c, c]
        })
        .await;
        assert!(verify.await.unwrap().is_none());
        h.run_for(Duration::from_millis(10)).await;
        assert_eq!(h.execution.new_payloads(), vec![c, c]);
        assert_eq!(h.marshal.subscribe_log(), vec![(p, round(2))]);
    });
}

#[test_traced]
fn advancing_finalized_round_discards_an_ancestor_above_the_finalized_height() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);
        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let parent = make_block(3, 3, b2.digest());
        let candidate = make_block(4, 4, parent.digest());
        let finalized1 = make_block(2, 1, GENESIS);
        let finalized2 = make_block(3, 2, finalized1.digest());
        let (p, c, f) = (parent.digest(), candidate.digest(), finalized1.digest());
        let mut verify = Box::pin(h.verify(round(4), candidate));
        assert!(futures::poll!(&mut verify).is_pending());
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(p, round(3))])
            .await;

        let release = h
            .execution
            .script_delayed_new_payload(f, Ok(PayloadStatusEnum::Valid));
        h.deliver_tip(round(2), 1, f);
        let acknowledged = h.deliver_finalized(finalized1);
        h.wait_until(|| h.execution.new_payloads() == vec![c, f])
            .await;
        let parent = Arc::new(parent);
        let weak = Arc::downgrade(&parent);
        assert!(h.marshal.fulfill_subscription(p, parent));
        h.run_for(Duration::from_millis(10)).await;
        assert!(weak.upgrade().is_some());

        // Finality covers the fetched cursor's round while its height is
        // still above the tip and finalization holds the engine slot.
        h.deliver_tip(round(3), 2, finalized2.digest());
        h.wait_until(|| weak.upgrade().is_none()).await;
        assert_eq!(h.execution.new_payloads(), vec![c, f]);
        release.send(()).unwrap();
        acknowledged.await.unwrap();
        assert!(verify.await.unwrap().is_none());
        assert_eq!(h.execution.new_payloads(), vec![c, f, c]);
        assert_eq!(h.marshal.subscribe_log(), vec![(p, round(3))]);
    });
}

#[test_traced]
fn advancing_finality_discards_an_ancestor_waiting_for_the_engine() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);
        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let b3 = make_block(3, 3, b2.digest());
        let (d1, d2, d3) = (b1.digest(), b2.digest(), b3.digest());
        let mut verify = Box::pin(h.verify(round(3), b3));
        assert!(futures::poll!(&mut verify).is_pending());
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(d2, round(2))])
            .await;

        let release = h
            .execution
            .script_delayed_new_payload(d1, Ok(PayloadStatusEnum::Valid));
        h.deliver_tip(round(1), 1, d1);
        let acknowledged = h.deliver_finalized(b1);
        h.wait_until(|| h.execution.new_payloads() == vec![d3, d1])
            .await;

        // The parent arrives while finalization holds the engine slot.
        let parent = Arc::new(b2.clone());
        let weak = Arc::downgrade(&parent);
        assert!(h.marshal.fulfill_subscription(d2, parent));
        h.run_for(Duration::from_millis(10)).await;
        assert!(weak.upgrade().is_some());

        // Finality overtakes the fetched cursor before it can be probed.
        h.deliver_tip(round(2), 2, d2);
        h.wait_until(|| weak.upgrade().is_none()).await;
        assert!(futures::poll!(&mut verify).is_pending());
        assert_eq!(h.execution.new_payloads(), vec![d3, d1]);

        release
            .send(())
            .expect("the engine call must remain in flight");
        acknowledged.await.unwrap();
        h.wait_until(|| h.execution.new_payloads() == vec![d3, d1, d3])
            .await;
        assert!(futures::poll!(&mut verify).is_pending());
        h.deliver_finalized(b2).await.unwrap();
        verify.await.unwrap().unwrap();
        assert_eq!(h.execution.new_payloads(), vec![d3, d1, d3, d2, d3]);
        assert_eq!(h.marshal.subscribe_log(), vec![(d2, round(2))]);
    });
}

#[test_traced]
fn canceling_a_walk_closes_an_obsolete_fetch() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        let parent = make_block(1, 1, GENESIS);
        let candidate = make_block(2, 2, parent.digest());
        let c = candidate.digest();
        let mut verify = Box::pin(h.verify(round(2), candidate));
        assert!(futures::poll!(&mut verify).is_pending());
        h.wait_until(|| !h.marshal.open_subscriptions().is_empty())
            .await;
        drop(h.build(round(3), GENESIS));
        h.run_for(Duration::from_millis(1)).await;
        assert!(futures::poll!(&mut verify).is_pending());
        assert_eq!(
            h.marshal.open_subscriptions(),
            vec![(parent.digest(), round(1))],
            "the older walk still needs its ancestor until its subscriber cancels",
        );
        drop(verify);
        // Queued cancellations are reaped on the next actor iteration.
        drop(h.build(round(4), GENESIS));
        h.wait_until(|| h.marshal.open_subscriptions().is_empty())
            .await;
        h.run_for(Duration::from_secs(2)).await;
        assert_eq!(h.execution.new_payloads(), vec![c]);
    });
}

#[test_traced]
fn dropped_ancestor_fetch_fails_verification() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        let parent = make_block(1, 1, GENESIS);
        let candidate = make_block(2, 2, parent.digest());
        let p = parent.digest();
        let mut verify = Box::pin(h.verify(round(2), candidate));
        assert!(futures::poll!(&mut verify).is_pending());
        h.wait_until(|| h.marshal.drop_subscription(p)).await;
        let _ = verify
            .await
            .expect_err("a dropped fetch fails the request without retrying");
        // Its pending HEAD can still converge independently.
        h.wait_until(|| h.marshal.fulfill_subscription(p, parent.clone()))
            .await;
        h.wait_until(|| h.execution.head() == p).await;
    });
}

#[test_traced]
fn an_ancestor_engine_error_is_fatal() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        let parent = make_block(1, 1, GENESIS);
        let candidate = make_block(2, 2, parent.digest());
        let p = parent.digest();
        h.execution
            .script_new_payload(p, Err("engine task stopped"));
        let mut verify = Box::pin(h.verify(round(2), candidate));
        assert!(futures::poll!(&mut verify).is_pending());
        h.wait_until(|| h.marshal.fulfill_subscription(p, parent.clone()))
            .await;
        let _ = verify
            .await
            .expect_err("a failed engine call must not produce a verdict");
        h.actor
            .await
            .expect("actor should shut down cleanly on a failed ancestor delivery");
    });
}
