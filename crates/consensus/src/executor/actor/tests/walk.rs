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
        assert_eq!(h.execution.new_payloads(), vec![d3, d2]);
        assert!(h.marshal.fulfill_subscription(d1, b1));

        verify
            .await
            .unwrap()
            .expect("verification should finish through the local parent");
        h.wait_until(|| h.execution.head() == d2).await;
        assert_eq!(h.marshal.subscribe_log(), vec![(d1, round(1))]);
        assert_eq!(h.execution.new_payloads(), vec![d3, d2, d1, d3, d2]);
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
        h.wait_until(|| h.marshal.subscribe_log().len() == 2).await;
        assert_eq!(
            h.marshal.open_subscriptions(),
            vec![(parent.digest(), round(1))]
        );
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
        h.wait_until(|| h.marshal.subscribe_log().len() == 2).await;
        assert_eq!(h.marshal.open_subscriptions(), vec![(d2, round(2))]);
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
        assert_eq!(h.marshal.subscribe_log().len(), 3);
    });
}

#[test_traced]
fn a_build_on_another_branch_supersedes_a_waiting_verification() {
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
        let _ = verify.await.expect_err("the build superseded verification");
        h.wait_until(|| h.marshal.open_subscriptions().is_empty())
            .await;
    });
}

#[test_traced]
fn a_superseding_build_reserves_the_execution_slot_while_fetching_its_parent() {
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
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(other.digest(), round(3))])
            .await;
        let _ = verify.await.expect_err("the build superseded verification");
        // The build owns the execution slot while waiting for its parent.
        h.run_for(Duration::from_millis(20)).await;
        assert_eq!(h.execution.new_payloads(), vec![candidate_digest]);
        assert!(
            h.marshal
                .fulfill_subscription(other.digest(), other.clone())
        );
        build.await.unwrap();
        h.run_for(Duration::from_millis(20)).await;
        assert_eq!(
            h.execution.head(),
            other.digest(),
            "the older verification cannot restore its parent target"
        );
    });
}

#[test_traced]
fn a_new_verification_replaces_a_walk_waiting_for_an_ancestor() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        let parent = make_block(1, 1, GENESIS);
        let candidate = make_block(2, 2, parent.digest());
        let old_digest = candidate.digest();
        let mut verify = Box::pin(h.verify(round(2), candidate));
        assert!(futures::poll!(&mut verify).is_pending());
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(parent.digest(), round(1))])
            .await;

        let other = make_block(3, 1, GENESIS);
        let candidate = make_block(4, 2, other.digest());
        let new_digest = candidate.digest();
        let release = h
            .execution
            .script_delayed_new_payload(new_digest, Ok(PayloadStatusEnum::Syncing));
        h.execution
            .script_new_payload(new_digest, Ok(PayloadStatusEnum::Valid));
        let mut newer = Box::pin(h.verify(round(4), candidate));
        assert!(futures::poll!(&mut newer).is_pending());
        h.wait_until(|| h.execution.new_payloads() == vec![old_digest, new_digest])
            .await;
        let _ = verify.await.expect_err("the old walk must be superseded");
        h.wait_until(|| h.marshal.open_subscriptions().is_empty())
            .await;
        release.send(()).unwrap();
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(other.digest(), round(3))])
            .await;
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
                other.digest(),
                new_digest,
                other.digest()
            ]
        );
        assert_eq!(
            h.marshal.subscribe_log(),
            vec![(parent.digest(), round(1)), (other.digest(), round(3))]
        );
    });
}

#[test_traced]
fn a_superseded_result_cannot_complete_a_new_request_for_the_same_block() {
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
        let _ = verify
            .await
            .expect_err("the old response belongs to the replaced request");
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
        assert!(
            h.marshal.subscribe_log().is_empty(),
            "the candidate is sent directly before fetching any ancestor"
        );
        release_candidate.send(()).unwrap();
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(d2, round(2))])
            .await;
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
        h.wait_until(|| h.marshal.fulfill_subscription(d2, b2.clone()))
            .await;
        h.wait_until(|| h.execution.head() == d2).await;
        assert_eq!(h.execution.new_payloads(), vec![d3, d2, d1, d3, d2]);
        assert_eq!(
            h.marshal.subscribe_log(),
            vec![(d2, round(2)), (d1, round(1)), (d2, round(2))]
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
fn an_ancestors_verdict_does_not_replace_the_candidates_verdict() {
    for ancestor_status in [
        PayloadStatusEnum::Valid,
        PayloadStatusEnum::Invalid {
            validation_error: "bad ancestor".into(),
        },
    ] {
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
                .script_new_payload(parent_digest, Ok(ancestor_status));
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
fn advancing_finality_leaves_the_fetch_pending_until_delivery() {
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
        h.run_for(Duration::from_millis(1)).await;
        assert_eq!(h.marshal.open_subscriptions(), vec![(d2, round(2))]);
        assert!(futures::poll!(&mut verify).is_pending());
        assert_eq!(h.execution.new_payloads(), vec![d3]);
        h.deliver_finalized(b1).await.unwrap();
        assert!(futures::poll!(&mut verify).is_pending());
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
fn an_ancestor_transport_error_fails_only_the_verification() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        let parent = make_block(1, 1, GENESIS);
        let candidate = make_block(2, 2, parent.digest());
        let p = parent.digest();
        h.execution.script_new_payload(p, Err("transport error"));
        let mut verify = Box::pin(h.verify(round(2), candidate));
        assert!(futures::poll!(&mut verify).is_pending());
        h.wait_until(|| h.marshal.fulfill_subscription(p, parent.clone()))
            .await;
        let _ = verify
            .await
            .expect_err("transport failure must release the request");
        let sibling = make_block(3, 1, GENESIS);
        h.verify(round(3), sibling).await.unwrap().unwrap();
    });
}
