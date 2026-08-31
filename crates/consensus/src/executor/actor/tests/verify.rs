//! Scenario tests for block-validation requests: latency-critical
//! new-payload probes whose responses consensus is waiting on to vote.

use std::time::Duration;

use alloy_primitives::B256;
use alloy_rpc_types_engine::PayloadStatusEnum;
use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, deterministic};
use futures::future::Either;

use super::harness::{GENESIS, Harness, make_block, round};

#[test_traced]
fn valid_block_resolves_with_a_duration() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let verdict = h
            .verify(round(1), b1.clone())
            .await
            .expect("verification should complete");
        assert!(
            verdict.is_some(),
            "a valid block resolves with its duration"
        );
        assert_eq!(h.execution.new_payloads(), vec![b1.digest()]);
    });
}

#[test_traced]
fn validator_set_reaches_new_payload_unchanged() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let validator_set = vec![B256::repeat_byte(0x11), B256::repeat_byte(0x22)];
        let verdict = h
            .verify_with_validator_set(round(1), b1.clone(), Some(validator_set.clone()))
            .await
            .expect("verification should complete");

        assert!(verdict.is_some());
        assert_eq!(
            h.execution.payload_validator_sets(),
            vec![(b1.digest(), Some(validator_set))],
        );
    });
}

#[test_traced]
fn invalid_block_resolves_with_a_rejection() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        h.execution.script_new_payload(
            b1.digest(),
            Ok(PayloadStatusEnum::Invalid {
                validation_error: "bad state root".into(),
            }),
        );

        let verdict = h
            .verify(round(1), b1)
            .await
            .expect("verification should complete");
        assert!(
            verdict.is_none(),
            "consensus treats the None verdict as a rejected proposal",
        );
    });
}

#[test_traced]
fn unknown_parent_fails_fast_when_no_convergence_is_expected() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        // b2's parent b1 was never seen: not the local tip, not being
        // finalized, not the pending head. The request must not be held
        // back; it runs, the execution layer reports SYNCING, and the
        // subscriber learns of the failure through the dropped channel.
        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let _ = h
            .verify(round(2), b2.clone())
            .await
            .expect_err("validation against an unknown parent must fail");

        assert_eq!(
            h.execution.new_payloads(),
            vec![b2.digest()],
            "fail-fast still probes the execution layer",
        );
        assert_eq!(h.execution.head(), GENESIS);
    });
}

#[test_traced]
fn request_is_deferred_while_its_parent_converges_just_in_time() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let (d1, d2) = (b1.digest(), b2.digest());

        // The network tip names b1 and marshal will deliver it imminently;
        // a validation on top of b1 must wait for that delivery instead of
        // failing fast.
        h.deliver_tip(round(1), 1, d1);

        let verify = h.verify(round(2), b2.clone());
        futures::pin_mut!(verify);
        let sleep = h.run_for(Duration::from_millis(500));
        futures::pin_mut!(sleep);
        let verify = match futures::future::select(verify, sleep).await {
            Either::Left((verdict, _)) => {
                panic!("verification resolved before the parent was delivered: {verdict:?}")
            }
            Either::Right(((), verify)) => verify,
        };
        assert!(
            h.execution.new_payloads().is_empty(),
            "the deferred request must not probe the execution layer",
        );

        // The finalized parent arrives; the executor forwards it and only
        // then runs the deferred validation on top of it.
        h.deliver_finalized(b1)
            .await
            .expect("finalized block should be acknowledged");
        let verdict = verify.await.expect("verification should complete");
        assert!(verdict.is_some(), "the deferred block validates cleanly");
        assert_eq!(h.execution.new_payloads(), vec![d1, d2]);
    });
}

#[test_traced]
fn accepted_payload_status_fails_the_validation() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        h.execution
            .script_new_payload(b1.digest(), Ok(PayloadStatusEnum::Accepted));
        h.execution
            .script_new_payload(b1.digest(), Ok(PayloadStatusEnum::Valid));
        let _ = h
            .verify(round(1), b1)
            .await
            .expect_err("ACCEPTED means the block was not actually executed");

        // The failure is not fatal: the actor keeps serving requests.
        let b1_again = make_block(1, 1, GENESIS);
        let verdict = h
            .verify(round(1), b1_again)
            .await
            .expect("verification should complete");
        assert!(verdict.is_some());
    });
}

#[test_traced]
fn new_payload_transport_error_fails_validation_but_is_not_fatal() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        h.execution
            .script_new_payload(b1.digest(), Err("connection closed"));
        h.execution
            .script_new_payload(b1.digest(), Ok(PayloadStatusEnum::Valid));
        let _ = h
            .verify(round(1), b1.clone())
            .await
            .expect_err("a new-payload transport error must fail validation");

        // Validation transport failures are request-local. Once the
        // execution layer recovers, the actor continues serving consensus.
        let verdict = h
            .verify(round(2), b1)
            .await
            .expect("verification should complete after the transport error");
        assert!(verdict.is_some());
    });
}

#[test_traced]
fn newer_round_supersedes_a_queued_request() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let b2a = make_block(2, 2, b1.digest());
        let b2b = make_block(3, 2, b1.digest());
        let d1 = b1.digest();

        // Both requests are held back by the just-in-time deferral on their
        // parent b1, so they meet in the consensus-request slot.
        h.deliver_tip(round(1), 1, d1);

        let stale = h.verify(round(2), b2a);
        futures::pin_mut!(stale);
        let sleep = h.run_for(Duration::from_millis(50));
        futures::pin_mut!(sleep);
        let stale = match futures::future::select(stale, sleep).await {
            Either::Left(_) => panic!("request resolved before being superseded"),
            Either::Right(((), stale)) => stale,
        };

        let newer = h.verify(round(3), b2b);
        futures::pin_mut!(newer);
        let sleep = h.run_for(Duration::from_millis(50));
        futures::pin_mut!(sleep);
        let newer = match futures::future::select(newer, sleep).await {
            Either::Left(_) => panic!("request resolved before the parent was delivered"),
            Either::Right(((), newer)) => newer,
        };

        // The newer round replaced the queued request, dropping its
        // response channel.
        let _ = stale.await.expect_err("the superseded request must fail");

        h.deliver_finalized(b1)
            .await
            .expect("finalized block should be acknowledged");
        let verdict = newer.await.expect("verification should complete");
        assert!(verdict.is_some(), "the superseding request wins the slot");
    });
}

#[test_traced]
fn cancellation_before_verification_delivery_still_leaves_the_body_for_convergence() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();

        // Start validation, then abandon it while newPayload is held open
        // (consensus moved on from the view). Dropping the future drops the
        // response receiver.
        let _release_validation = h
            .execution
            .script_delayed_new_payload(d1, Ok(PayloadStatusEnum::Valid));
        h.execution
            .script_new_payload(d1, Ok(PayloadStatusEnum::Valid));
        let verify = Box::pin(h.verify(round(1), b1));
        let sleep = Box::pin(h.run_for(Duration::from_millis(1)));
        let verify = match futures::future::select(verify, sleep).await {
            Either::Left(_) => panic!("verification resolved before it could be abandoned"),
            Either::Right(((), verify)) => verify,
        };
        h.wait_until(|| h.execution.new_payloads() == vec![d1])
            .await;
        assert_eq!(h.execution.new_payloads(), vec![d1]);
        drop(verify);
        h.run_for(Duration::from_millis(50)).await;

        // The recorded body still serves convergence: no fetch is needed
        // once the block is reported as the pending head.
        h.report_pending_head(2, 1, d1);
        h.wait_until(|| h.execution.head() == d1).await;
        assert!(h.marshal.subscribe_log().is_empty());
    });
}
