//! Scenario tests for the slot shared by proposal building and validation:
//! only the newest queued consensus request survives, regardless of request
//! kind, while the current execution-layer task runs to completion.

use std::time::Duration;

use alloy_rpc_types_engine::PayloadStatusEnum;
use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, deterministic};
use futures::future::Either;

use super::harness::{GENESIS, Harness, built_payload, make_block, round};
use crate::consensus::Digest;

#[test_traced]
fn build_supersedes_queued_verification_while_another_request_executes() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        // Hold a validation open in the execution layer so it owns the
        // execution-task slot while later requests arbitrate behind it.
        let active_block = make_block(1, 1, GENESIS);
        let active_digest = active_block.digest();
        let release_active = h
            .execution
            .script_delayed_new_payload(active_digest, Ok(PayloadStatusEnum::Valid));
        let active = h.verify(round(1), active_block);
        futures::pin_mut!(active);
        let deadline = h.run_for(Duration::from_millis(1));
        futures::pin_mut!(deadline);
        let active = match futures::future::select(active, deadline).await {
            Either::Left(_) => panic!("active verification completed before arbitration began"),
            Either::Right(((), active)) => active,
        };
        h.wait_until(|| h.execution.new_payloads() == vec![active_digest])
            .await;
        assert_eq!(h.execution.new_payloads(), vec![active_digest]);

        // A second validation queues behind the active one.
        let superseded_block = make_block(2, 1, GENESIS);
        let superseded = h.verify(round(2), superseded_block);
        futures::pin_mut!(superseded);
        let deadline = h.run_for(Duration::from_millis(1));
        futures::pin_mut!(deadline);
        let superseded = match futures::future::select(superseded, deadline).await {
            Either::Left(_) => panic!("queued verification completed while the slot was occupied"),
            Either::Right(((), superseded)) => superseded,
        };

        // The newer build replaces that queued verification, but cannot
        // interrupt the validation that is already executing.
        let proposal = make_block(3, 1, GENESIS);
        let proposal_digest = proposal.digest();
        h.execution.script_built_payload(built_payload(&proposal));
        let build = h.build(round(3), GENESIS);

        let _ = superseded
            .await
            .expect_err("the newer build must supersede the queued verification");
        release_active
            .send(())
            .expect("active validation should still be gated");
        let _ = active
            .await
            .expect_err("the replaced verification's result is discarded");
        let payload = build.await.expect("the superseding build should complete");
        let (block, _) = payload.into_execution_payload();
        assert_eq!(Digest(block.hash()), proposal_digest);
        assert_eq!(
            h.execution.new_payloads(),
            vec![active_digest, GENESIS],
            "the superseded verification must never reach the execution layer",
        );
    });
}

#[test_traced]
fn verification_supersedes_a_queued_build() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        // An active finalization holds the slot. The build remains queued
        // and can therefore be replaced by the newer verification.
        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        let candidate = make_block(3, 2, d1);
        let candidate_digest = candidate.digest();
        let release = h
            .execution
            .script_delayed_new_payload(d1, Ok(PayloadStatusEnum::Valid));
        h.deliver_tip(round(1), 1, d1);
        let finalized = h.deliver_finalized(b1);
        h.wait_until(|| h.execution.new_payloads() == vec![d1])
            .await;

        let build = h.build(round(2), d1);
        h.run_for(Duration::from_millis(50)).await;

        let verify = h.verify(round(3), candidate);
        futures::pin_mut!(verify);
        let deadline = h.run_for(Duration::from_millis(50));
        futures::pin_mut!(deadline);
        let verify = match futures::future::select(verify, deadline).await {
            Either::Left(_) => panic!("verification completed before its parent converged"),
            Either::Right(((), verify)) => verify,
        };

        build
            .await
            .expect_err("the newer verification must supersede the queued build");
        release
            .send(())
            .expect("finalization must still be running");
        finalized
            .await
            .expect("the finalized parent should be acknowledged");
        assert!(
            verify
                .await
                .expect("the superseding verification should complete")
                .is_some(),
        );
        assert_eq!(h.execution.new_payloads(), vec![d1, candidate_digest]);
        assert!(
            !h.execution
                .fcus()
                .iter()
                .any(|(.., with_attrs)| *with_attrs),
            "the superseded build must not register a payload job",
        );
    });
}

#[test_traced]
fn new_verification_replaces_the_request_but_waits_for_active_delivery() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        let parent = make_block(1, 1, GENESIS);
        let candidate = make_block(2, 2, parent.digest());
        let old_digest = candidate.digest();
        let release = h
            .execution
            .script_delayed_new_payload(old_digest, Ok(PayloadStatusEnum::Syncing));
        let mut old = Box::pin(h.verify(round(2), candidate));
        assert!(futures::poll!(&mut old).is_pending());
        h.wait_until(|| h.execution.new_payloads() == vec![old_digest])
            .await;

        let candidate = make_block(3, 1, GENESIS);
        let new_digest = candidate.digest();
        let mut new = Box::pin(h.verify(round(3), candidate));
        assert!(futures::poll!(&mut new).is_pending());
        h.run_for(Duration::from_millis(50)).await;
        let _ = old.await.expect_err("the old walk was superseded");
        assert!(futures::poll!(&mut new).is_pending());
        assert_eq!(h.execution.new_payloads(), vec![old_digest]);

        release
            .send(())
            .expect("the active engine call must not be canceled");
        new.await.unwrap().unwrap();
        assert_eq!(h.execution.new_payloads(), vec![old_digest, new_digest]);
        assert!(
            h.marshal.subscribe_log().is_empty(),
            "the old walk must not fetch its parent"
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
