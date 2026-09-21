//! Scenario tests for the slot shared by proposal building and validation:
//! only the newest queued consensus request survives, regardless of request
//! kind, while the current execution-layer task runs to completion.

use std::time::Duration;

use alloy_rpc_types_engine::PayloadStatusEnum;
use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, deterministic};

use super::harness::{GENESIS, Harness, built_payload, make_block, round};
use crate::consensus::Digest;

#[test_traced]
fn queued_verification_runs_after_a_newer_build() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        // Hold a validation open in the execution layer so it owns the
        // execution-task slot while later requests queue behind it.
        let active_block = make_block(1, 1, GENESIS);
        let active_digest = active_block.digest();
        let release_active = h
            .execution
            .script_delayed_new_payload(active_digest, Ok(PayloadStatusEnum::Valid));
        let mut active = Box::pin(h.verify(round(1), active_block));
        assert!(futures::poll!(&mut active).is_pending());
        h.wait_until(|| h.execution.new_payloads() == vec![active_digest])
            .await;

        // A second validation queues behind the active one.
        let queued_block = make_block(2, 1, GENESIS);
        let queued_digest = queued_block.digest();
        let mut queued = Box::pin(h.verify(round(2), queued_block));
        assert!(futures::poll!(&mut queued).is_pending());

        // A newer build queues as well. It does not displace the
        // verification, but it goes first once the slot frees up.
        let proposal = make_block(3, 1, GENESIS);
        let proposal_digest = proposal.digest();
        h.execution.script_built_payload(built_payload(&proposal));
        let build = h.build(round(3), GENESIS);
        h.run_for(Duration::from_millis(10)).await;
        assert_eq!(h.execution.new_payloads(), vec![active_digest]);

        release_active
            .send(())
            .expect("active validation should still be gated");
        assert!(active.await.unwrap().is_some());
        let payload = build.await.expect("the build should complete");
        let (block, _) = payload.into_execution_payload();
        assert_eq!(Digest(block.hash()), proposal_digest);
        assert!(queued.await.unwrap().is_some());
        assert_eq!(
            h.execution.new_payloads(),
            vec![active_digest, GENESIS, queued_digest],
            "the build delivers its parent before the queued verification probes",
        );
    });
}
#[test_traced]
fn a_newer_verification_leaves_a_queued_build_alone() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        // An active finalization holds the slot. The build stays queued
        // while a newer verification queues beside it.
        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        let candidate = make_block(3, 2, d1);
        let candidate_digest = candidate.digest();
        let proposal = make_block(2, 2, d1);
        let release = h
            .execution
            .script_delayed_new_payload(d1, Ok(PayloadStatusEnum::Valid));
        h.execution
            .script_new_payload(d1, Ok(PayloadStatusEnum::Valid));
        h.deliver_tip(round(1), 1, d1);
        let finalized = h.deliver_finalized(b1);
        h.wait_until(|| h.execution.new_payloads() == vec![d1])
            .await;

        h.execution.script_built_payload(built_payload(&proposal));
        let mut build = Box::pin(h.build(round(2), d1));
        let mut verify = Box::pin(h.verify(round(3), candidate));
        assert!(futures::poll!(&mut build).is_pending());
        assert!(futures::poll!(&mut verify).is_pending());
        h.run_for(Duration::from_millis(50)).await;
        assert!(futures::poll!(&mut build).is_pending());
        assert!(futures::poll!(&mut verify).is_pending());

        release
            .send(())
            .expect("finalization must still be running");
        finalized
            .await
            .expect("the finalized parent should be acknowledged");
        let payload = build.await.expect("the queued build should complete");
        let (block, _) = payload.into_execution_payload();
        assert_eq!(Digest(block.hash()), proposal.digest());
        assert!(verify.await.unwrap().is_some());
        assert_eq!(
            h.execution.new_payloads(),
            vec![d1, d1, candidate_digest],
            "the build delivers its parent before the verification probes",
        );
        assert!(
            h.execution
                .fcus()
                .iter()
                .any(|(.., with_attrs)| *with_attrs),
            "the build registers its payload job",
        );
    });
}
#[test_traced]
fn a_newer_verification_waits_for_the_in_flight_probe_then_goes_first() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        let parent = make_block(1, 1, GENESIS);
        let candidate = make_block(2, 2, parent.digest());
        let old_digest = candidate.digest();
        let release = h
            .execution
            .script_delayed_new_payload(old_digest, Ok(PayloadStatusEnum::Syncing));
        h.execution
            .script_new_payload(old_digest, Ok(PayloadStatusEnum::Valid));
        let mut old = Box::pin(h.verify(round(2), candidate));
        assert!(futures::poll!(&mut old).is_pending());
        h.wait_until(|| h.execution.new_payloads() == vec![old_digest])
            .await;

        let candidate = make_block(3, 1, GENESIS);
        let new_digest = candidate.digest();
        let mut new = Box::pin(h.verify(round(3), candidate));
        assert!(futures::poll!(&mut new).is_pending());
        h.run_for(Duration::from_millis(50)).await;
        assert!(futures::poll!(&mut old).is_pending());
        assert!(futures::poll!(&mut new).is_pending());
        assert_eq!(h.execution.new_payloads(), vec![old_digest]);

        // The old walk goes on to fetch its parent and yields the slot while
        // it waits; the new one is probed at once and completes.
        release
            .send(())
            .expect("the active engine call must not be canceled");
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(parent.digest(), round(1))])
            .await;
        new.await.unwrap().unwrap();
        assert_eq!(h.execution.new_payloads(), vec![old_digest, new_digest]);
        assert!(futures::poll!(&mut old).is_pending());
        assert!(
            h.marshal
                .fulfill_subscription(parent.digest(), parent.clone())
        );
        old.await.unwrap().unwrap();
        assert_eq!(
            h.execution.new_payloads(),
            vec![old_digest, new_digest, parent.digest(), old_digest]
        );
    });
}
#[test_traced]
fn same_round_verification_waits_for_an_active_build() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        let proposal = make_block(2, 2, d1);
        let candidate = make_block(2, 2, d1);
        h.deliver_tip(round(1), 1, d1);

        // Once the build starts, queue arbitration only considers queued
        // requests. Even a same-round verification can wait behind it.
        h.execution.script_built_payload(built_payload(&proposal));
        let build = h.build(round(2), d1);
        h.run_for(Duration::from_millis(50)).await;

        let mut verify = Box::pin(h.verify(round(2), candidate));
        assert!(futures::poll!(&mut verify).is_pending());
        h.run_for(Duration::from_millis(10)).await;
        assert!(h.execution.new_payloads().is_empty());

        assert!(h.marshal.fulfill_subscription(d1, b1.clone()));
        let payload = build.await.expect("the active build should complete");
        verify
            .await
            .expect("the queued verification should run next")
            .unwrap();
        h.deliver_finalized(b1)
            .await
            .expect("the deferred parent should be acknowledged");
        let (block, _) = payload.into_execution_payload();
        assert_eq!(Digest(block.hash()), proposal.digest());
        assert!(
            h.execution
                .fcus()
                .iter()
                .any(|(.., with_attrs)| *with_attrs),
            "the winning build must register its payload job",
        );
    });
}
