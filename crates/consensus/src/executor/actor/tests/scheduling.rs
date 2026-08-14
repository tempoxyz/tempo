//! Scenario tests for the actor's scheduling invariants: one execution-layer
//! task at a time, consensus requests before convergence before
//! finalization, the FCU heartbeat, and shutdown.

use std::time::Duration;

use alloy_rpc_types_engine::PayloadStatusEnum;
use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, deterministic};
use futures::future::Either;

use super::harness::{
    ElCall, FakeExecution, FakeMarshal, GENESIS, Harness, HarnessOptions, make_block, round,
};

#[test_traced]
fn one_execution_task_at_a_time_and_consensus_requests_win_the_next_slot() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let (d1, d2) = (b1.digest(), b2.digest());

        // A SYNCING status parks the finalization of b1 in its postpone
        // pause (1s), keeping the single execution-task slot occupied over
        // a long stretch of virtual time.
        h.execution
            .script_new_payload(d1, PayloadStatusEnum::Syncing);
        h.deliver_tip(round(1), 1, d1);
        let w1 = h.deliver_finalized(b1);
        h.wait_until(|| h.execution.new_payloads() == vec![d1]).await;

        // While the slot is held, a validation and another finalization
        // queue up. Nothing may reach the execution layer.
        let verify = h.verify(round(2), b2.clone());
        futures::pin_mut!(verify);
        let sleep = h.run_for(Duration::from_millis(10));
        futures::pin_mut!(sleep);
        let verify = match futures::future::select(verify, sleep).await {
            Either::Left(_) => panic!("verification resolved while the slot was held"),
            Either::Right(((), verify)) => verify,
        };
        h.deliver_tip(round(2), 2, d2);
        let w2 = h.deliver_finalized(b2);

        h.run_for(Duration::from_millis(500)).await;
        assert_eq!(
            h.execution.calls(),
            vec![ElCall::NewPayload(d1)],
            "the in-flight task must be the only execution-layer activity",
        );

        // The postponed finalization retries and completes; the queued
        // validation is latency-critical and wins the next slot over the
        // queued finalization of b2.
        w1.await.expect("first block should be acknowledged");
        let verdict = verify.await.expect("verification should complete");
        assert!(verdict.is_some());
        w2.await.expect("second block should be acknowledged");

        assert_eq!(
            h.execution.calls(),
            vec![
                ElCall::NewPayload(d1),
                ElCall::NewPayload(d1),
                ElCall::Fcu {
                    head: d1,
                    finalized: d1,
                    with_attrs: false
                },
                // The validation of b2 runs before b2's finalization: its
                // new-payload probe is not followed by a forkchoice update.
                ElCall::NewPayload(d2),
                ElCall::NewPayload(d2),
                ElCall::Fcu {
                    head: d2,
                    finalized: d2,
                    with_attrs: false
                },
            ],
        );
    });
}

#[test_traced]
fn idle_actor_sends_forkchoice_heartbeats_and_survives_their_failure() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start(
            &context,
            FakeExecution::new(),
            FakeMarshal::new(),
            HarnessOptions {
                fcu_heartbeat_interval: Duration::from_millis(300),
                ..Default::default()
            },
        );

        h.run_for(Duration::from_secs(1)).await;
        let heartbeats = h.execution.fcus();
        assert!(
            heartbeats.len() >= 2,
            "an idle actor must re-affirm the forkchoice state periodically, got {heartbeats:?}",
        );
        assert!(
            heartbeats
                .iter()
                .all(|fcu| *fcu == (GENESIS, GENESIS, false)),
            "heartbeats re-affirm the tracked state",
        );

        // Failing heartbeats are logged, not fatal.
        h.execution.reject_all_fcus(true);
        h.run_for(Duration::from_secs(1)).await;
        h.execution.reject_all_fcus(false);

        let b1 = make_block(1, 1, GENESIS);
        let verdict = h
            .verify(round(1), b1)
            .await
            .expect("the actor must still be serving requests");
        assert!(verdict.is_some());
    });
}

#[test_traced]
fn actor_exits_when_the_mailbox_closes() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        drop(h.mailbox);
        h.actor
            .await
            .expect("actor should exit cleanly when all mailbox handles are gone");
    });
}
