//! Scenario tests for the slot shared by proposal building and validation:
//! only the newest queued consensus request survives, regardless of request
//! kind, while an already executing request runs to completion.

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
        assert!(
            active
                .await
                .expect("the active verification should complete")
                .is_some(),
        );
        let payload = build.await.expect("the superseding build should complete");
        let (block, _) = payload.into_execution_payload();
        assert_eq!(Digest(block.hash()), proposal_digest);
        assert_eq!(
            h.execution.new_payloads(),
            vec![active_digest],
            "the superseded verification must never reach the execution layer",
        );
    });
}

#[test_traced]
fn verification_supersedes_a_queued_build() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        // Both requests defer on b1 while marshal is about to finalize it,
        // forcing them to arbitrate in the shared pending slot.
        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        let candidate = make_block(3, 2, d1);
        let candidate_digest = candidate.digest();
        h.deliver_tip(round(1), 1, d1);

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
        h.deliver_finalized(b1)
            .await
            .expect("the deferred parent should be acknowledged");
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
fn same_round_verification_does_not_supersede_a_queued_build() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        let proposal = make_block(2, 2, d1);
        let candidate = make_block(2, 2, d1);
        h.deliver_tip(round(1), 1, d1);

        // Simplex views are strictly monotonically increasing, and propose and
        // verify are mutually exclusive within a view. A request from the same
        // view therefore cannot represent later consensus progress. The build
        // arrives first and defers on b1, so the same-view verification is
        // stale on arrival and must not supersede it.
        h.execution.script_built_payload(built_payload(&proposal));
        let build = h.build(round(2), d1);
        h.run_for(Duration::from_millis(50)).await;

        let _ = h
            .verify(round(2), candidate)
            .await
            .expect_err("a same-round verification must not replace the queued build");

        h.deliver_finalized(b1)
            .await
            .expect("the deferred parent should be acknowledged");
        let payload = build
            .await
            .expect("the first same-round request should win");
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
