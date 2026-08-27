//! Scenario tests for the actor's scheduling invariants: one execution-layer
//! task at a time, consensus requests before convergence before
//! finalization, the FCU heartbeat, and shutdown.

use std::time::Duration;

use alloy_rpc_types_engine::{ForkchoiceState, PayloadStatusEnum};
use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, Spawner as _, Supervisor as _, deterministic};
use futures::future::Either;

use super::harness::{
    ElCall, ForkchoiceStateExt as _, GENESIS, Harness, HarnessOptions, built_payload, make_block,
    round,
};

#[test_traced]
fn slow_marshal_fetch_does_not_block_validation() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        // Leave the missing pending head's marshal subscription unresolved.
        let pending = make_block(1, 1, GENESIS);
        let pending_digest = pending.digest();
        h.report_pending_head(2, 1, pending_digest);
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(pending_digest, round(1))])
            .await;

        // The body fetch has its own slot in the actor loop. An unrelated
        // validation against the known finalized parent must still run.
        let candidate = make_block(3, 1, GENESIS);
        let candidate_digest = candidate.digest();
        let verify = h.verify(round(3), candidate);
        futures::pin_mut!(verify);
        let deadline = h.run_for(Duration::from_millis(100));
        futures::pin_mut!(deadline);
        let verdict = match futures::future::select(verify, deadline).await {
            Either::Left((verdict, _deadline)) => {
                verdict.expect("verification should complete while the fetch is pending")
            }
            Either::Right(((), _verify)) => {
                panic!("the pending marshal fetch blocked validation")
            }
        };

        assert!(verdict.is_some());
        assert_eq!(h.execution.new_payloads(), vec![candidate_digest]);
        assert_eq!(
            h.marshal.open_subscriptions(),
            vec![(pending_digest, round(1))],
            "validation must not cancel or consume the independent body fetch",
        );
    });
}

#[test_traced]
fn slow_marshal_fetch_does_not_block_building() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        // Leave the missing pending head's marshal subscription unresolved.
        let pending = make_block(1, 1, GENESIS);
        let pending_digest = pending.digest();
        h.report_pending_head(2, 1, pending_digest);
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(pending_digest, round(1))])
            .await;

        // A proposal build on the known local head must be registered and
        // delivered independently of the pending body fetch.
        let proposal = make_block(3, 1, GENESIS);
        let proposal_digest = proposal.digest();
        h.execution.script_built_payload(built_payload(&proposal));
        let build = h.build(round(3), GENESIS);
        futures::pin_mut!(build);
        let deadline = h.run_for(Duration::from_millis(100));
        futures::pin_mut!(deadline);
        let payload = match futures::future::select(build, deadline).await {
            Either::Left((payload, _deadline)) => {
                payload.expect("build should complete while the fetch is pending")
            }
            Either::Right(((), _build)) => {
                panic!("the pending marshal fetch blocked building")
            }
        };

        let (block, _) = payload.into_execution_payload();
        assert_eq!(block.hash(), proposal_digest.0);
        assert!(
            h.execution.fcus().contains(&(GENESIS, GENESIS, true)),
            "the attribute-carrying build FCU must reach the execution layer",
        );
        assert_eq!(
            h.marshal.open_subscriptions(),
            vec![(pending_digest, round(1))],
            "building must not cancel or consume the independent body fetch",
        );
    });
}

#[test_traced]
fn payload_resolution_does_not_occupy_the_execution_task_slot() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        // Register a build without scripting its result, leaving the payload
        // resolution pending after the attribute-carrying FCU completes.
        let proposal = make_block(1, 1, GENESIS);
        let proposal_digest = proposal.digest();
        let build = h.build(round(1), GENESIS);
        h.wait_until(|| {
            h.execution
                .calls()
                .iter()
                .any(|call| matches!(call, ElCall::Resolve(_)))
        })
        .await;
        let payload_id = h.execution.pending_payload_jobs()[0];

        // Validation uses the single execution-task slot. Seeing its
        // new-payload call while resolution remains pending proves that the
        // payload job is driven independently of that slot.
        let candidate = make_block(2, 1, GENESIS);
        let candidate_digest = candidate.digest();
        let verify = h.verify(round(2), candidate);
        let verify = h
            .context
            .child("verify_during_payload_resolution")
            .spawn(move |_| verify);
        h.run_for(Duration::from_millis(5)).await;

        assert_eq!(h.execution.new_payloads(), vec![candidate_digest]);
        assert_eq!(h.execution.pending_payload_jobs(), vec![payload_id]);

        // Release the fake payload builder so both in-flight operations can
        // finish normally.
        h.execution
            .deliver_payload(payload_id, built_payload(&proposal));
        let verdict = verify
            .await
            .expect("verification task should finish")
            .expect("verification should complete");
        assert!(verdict.is_some());
        let payload = build.await.expect("build should complete");
        let (block, _) = payload.into_execution_payload();
        assert_eq!(block.hash(), proposal_digest.0);
    });
}

#[test_traced]
fn multiple_payload_jobs_can_complete_out_of_order() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let first_proposal = make_block(1, 1, GENESIS);
        let first_digest = first_proposal.digest();
        let mut first = h.build(round(1), GENESIS);
        h.wait_until(|| {
            h.execution
                .calls()
                .iter()
                .filter(|call| matches!(call, ElCall::Resolve(_)))
                .count()
                == 1
        })
        .await;

        let second_proposal = make_block(2, 1, GENESIS);
        let second_digest = second_proposal.digest();
        let second = h.build(round(2), GENESIS);
        h.wait_until(|| {
            h.execution
                .calls()
                .iter()
                .filter(|call| matches!(call, ElCall::Resolve(_)))
                .count()
                == 2
        })
        .await;

        let resolution_ids = h
            .execution
            .calls()
            .into_iter()
            .filter_map(|call| match call {
                ElCall::Resolve(payload_id) => Some(payload_id),
                _ => None,
            })
            .collect::<Vec<_>>();
        let [first_id, second_id] = resolution_ids.as_slice() else {
            panic!("expected exactly two payload resolutions");
        };

        // Complete the later build first. Its subscriber must receive the
        // matching payload while the earlier build remains unresolved.
        h.execution
            .deliver_payload(*second_id, built_payload(&second_proposal));
        futures::pin_mut!(second);
        let deadline = h.run_for(Duration::from_secs(1));
        futures::pin_mut!(deadline);
        let second = futures::future::select(second, deadline).await;
        let Either::Left((second, _deadline)) = second else {
            panic!("second payload was not delivered ahead of the first");
        };
        let second = second.expect("second build should complete");
        let (block, _) = second.into_execution_payload();
        assert_eq!(block.hash(), second_digest.0);
        assert!(
            first
                .try_recv()
                .expect("first build should remain subscribed")
                .is_none(),
            "the first build must still be unresolved",
        );

        h.execution
            .deliver_payload(*first_id, built_payload(&first_proposal));
        futures::pin_mut!(first);
        let deadline = h.run_for(Duration::from_secs(1));
        futures::pin_mut!(deadline);
        let first = futures::future::select(first, deadline).await;
        let Either::Left((first, _deadline)) = first else {
            panic!("first payload was not delivered after it resolved");
        };
        let first = first.expect("first build should complete");
        let (block, _) = first.into_execution_payload();
        assert_eq!(block.hash(), first_digest.0);
        assert!(h.execution.canceled_payload_jobs().is_empty());
    });
}

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
            .script_new_payload(d1, Ok(PayloadStatusEnum::Syncing));
        h.execution
            .script_new_payload(d1, Ok(PayloadStatusEnum::Valid));
        h.deliver_tip(round(1), 1, d1);
        let w1 = h.deliver_finalized(b1);
        h.wait_until(|| h.execution.new_payloads() == vec![d1])
            .await;

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
fn consensus_work_takes_priority_over_ready_convergence() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        // Deliberately trigger the retry-on-SYNCING mechanism that tolerates
        // Reth rebuilding its indexes, using its retry pause to hold the
        // execution-task slot with a postponed finalization of b1.
        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        h.execution
            .script_new_payload(d1, Ok(PayloadStatusEnum::Syncing));
        h.execution
            .script_new_payload(d1, Ok(PayloadStatusEnum::Valid));
        h.deliver_tip(round(1), 1, d1);
        let finalized = h.deliver_finalized(b1);
        h.wait_until(|| h.execution.new_payloads() == vec![d1])
            .await;

        // Make convergence onto b2 ready while finalization still owns the
        // slot: its pending-head report and body are both already in hand.
        let b2 = make_block(2, 2, d1);
        let d2 = b2.digest();
        h.report_pending_head(3, 2, d2);
        h.wait_until(|| h.marshal.fulfill_subscription(d2, b2.clone()))
            .await;
        h.run_for(Duration::from_millis(10)).await;

        // Queue a validation that also becomes runnable once b1 is finalized.
        // It must stay queued until the occupied slot becomes available.
        let candidate = make_block(3, 2, d1);
        let candidate_digest = candidate.digest();
        let verify = h.verify(round(3), candidate);
        futures::pin_mut!(verify);
        let deadline = h.run_for(Duration::from_millis(10));
        futures::pin_mut!(deadline);
        let verify = match futures::future::select(verify, deadline).await {
            Either::Left(_) => panic!("verification resolved while the slot was held"),
            Either::Right(((), verify)) => verify,
        };

        finalized.await.expect("first block should be acknowledged");
        assert!(
            verify
                .await
                .expect("verification should complete")
                .is_some(),
            "candidate should be valid",
        );
        h.wait_until(|| h.execution.head() == d2).await;

        assert_eq!(
            h.execution.calls(),
            vec![
                ElCall::NewPayload(d1),
                ElCall::NewPayload(d1),
                ElCall::Fcu {
                    head: d1,
                    finalized: d1,
                    with_attrs: false,
                },
                // Both operations were ready when finalization released the
                // slot, but latency-critical consensus work ran first.
                ElCall::NewPayload(candidate_digest),
                ElCall::NewPayload(d2),
                ElCall::Fcu {
                    head: d2,
                    finalized: d1,
                    with_attrs: false,
                },
            ],
        );
    });
}

#[test_traced]
fn convergence_takes_priority_over_queued_finalization() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        // This deliberately exploits an implementation detail of the current
        // retry-on-SYNCING path: finalization stalls internally before it
        // returns its postponed outcome, retaining the execution-task slot
        // while both kinds of work are queued. Replace this setup once that
        // retry relinquishes the slot before waiting.
        h.execution
            .script_new_payload(d1, Ok(PayloadStatusEnum::Syncing));
        h.execution
            .script_new_payload(d1, Ok(PayloadStatusEnum::Valid));
        h.execution
            .script_new_payload(d1, Ok(PayloadStatusEnum::Valid));
        h.deliver_tip(round(1), 1, d1);
        let first_finalization = h.deliver_finalized(b1.clone());
        h.wait_until(|| h.execution.new_payloads() == vec![d1])
            .await;

        // Make convergence onto b2 ready above the finalized boundary.
        let b2 = make_block(2, 2, d1);
        let d2 = b2.digest();
        h.report_pending_head(3, 2, d2);
        h.wait_until(|| h.marshal.fulfill_subscription(d2, b2.clone()))
            .await;
        h.run_for(Duration::from_millis(10)).await;

        // Queue a valid finalization redelivery. Once the first delivery
        // advances local finality to b1, this and convergence are both ready.
        let redelivery = h.deliver_finalized(b1);
        h.run_for(Duration::from_millis(10)).await;

        first_finalization
            .await
            .expect("first delivery should be acknowledged");
        redelivery.await.expect("redelivery should be acknowledged");

        assert_eq!(
            h.execution.calls(),
            vec![
                ElCall::NewPayload(d1),
                ElCall::NewPayload(d1),
                ElCall::Fcu {
                    head: d1,
                    finalized: d1,
                    with_attrs: false,
                },
                // Convergence wins the newly available slot.
                ElCall::NewPayload(d2),
                ElCall::Fcu {
                    head: d2,
                    finalized: d1,
                    with_attrs: false,
                },
                // Only then is the queued finalization redelivery handled.
                ElCall::NewPayload(d1),
                ElCall::Fcu {
                    head: d2,
                    finalized: d1,
                    with_attrs: false,
                },
            ],
        );
    });
}

#[test_traced]
fn heartbeats_are_disarmed_while_work_is_active_or_queued() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::builder()
            .harness_options(HarnessOptions {
                fcu_heartbeat_interval: Duration::from_millis(300),
                ..Default::default()
            })
            .start(&context);

        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        // Temporarily exploit finalization retaining the execution slot while
        // it stalls internally before returning its postponed SYNCING outcome.
        h.execution
            .script_new_payload(d1, Ok(PayloadStatusEnum::Syncing));
        h.execution
            .script_new_payload(d1, Ok(PayloadStatusEnum::Valid));
        h.deliver_tip(round(1), 1, d1);
        let finalized = h.deliver_finalized(b1);
        h.wait_until(|| h.execution.new_payloads() == vec![d1])
            .await;

        // Keep consensus work queued behind the active finalization.
        let candidate = make_block(2, 2, d1);
        let verify = h.verify(round(2), candidate);
        futures::pin_mut!(verify);
        let deadline = h.run_for(Duration::from_millis(10));
        futures::pin_mut!(deadline);
        let verify = match futures::future::select(verify, deadline).await {
            Either::Left(_) => panic!("verification resolved while finalization was active"),
            Either::Right(((), verify)) => verify,
        };

        // More than two heartbeat intervals pass while one request is active
        // and another is queued. No heartbeat may contend for the slot.
        h.run_for(Duration::from_millis(800)).await;
        assert!(
            h.execution.fcus().is_empty(),
            "heartbeats must remain disarmed while execution work is active or queued",
        );

        finalized
            .await
            .expect("finalization should eventually complete");
        assert!(
            verify
                .await
                .expect("queued verification should complete")
                .is_some(),
        );
    });
}

#[test_traced]
fn heartbeat_timer_is_rearmed_after_work_finishes() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::builder()
            .harness_options(HarnessOptions {
                fcu_heartbeat_interval: Duration::from_millis(300),
                ..Default::default()
            })
            .start(&context);

        // Let most of the idle interval elapse, then run consensus work. The
        // old timer has only 50ms left and must be discarded by that work.
        h.run_for(Duration::from_millis(250)).await;
        let candidate = make_block(1, 1, GENESIS);
        assert!(
            h.verify(round(1), candidate)
                .await
                .expect("verification should complete")
                .is_some(),
        );
        assert!(h.execution.fcus().is_empty());

        // A stale timer would fire during this window. A correctly rearmed
        // timer instead grants a fresh 300ms interval after work finishes.
        h.run_for(Duration::from_millis(100)).await;
        assert!(
            h.execution.fcus().is_empty(),
            "the pre-work heartbeat deadline must not survive",
        );

        h.run_for(Duration::from_millis(250)).await;
        h.wait_until(|| h.execution.fcus().len() == 1).await;
        assert_eq!(h.execution.fcus(), vec![(GENESIS, GENESIS, false)]);
    });
}

#[test_traced]
fn idle_actor_sends_forkchoice_heartbeats_and_survives_their_failure() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::builder()
            .harness_options(HarnessOptions {
                fcu_heartbeat_interval: Duration::from_millis(300),
                ..Default::default()
            })
            .start(&context);

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
fn idle_actor_survives_heartbeat_transport_error() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::builder()
            .harness_options(HarnessOptions {
                fcu_heartbeat_interval: Duration::from_millis(300),
                ..Default::default()
            })
            .start(&context);
        h.execution.script_fcu(
            ForkchoiceState::from_finalized_head(GENESIS, GENESIS),
            [Err("connection closed"), Ok(PayloadStatusEnum::Valid)],
        );

        h.wait_until(|| h.execution.fcus().len() == 2).await;
        assert_eq!(
            h.execution.fcus(),
            vec![(GENESIS, GENESIS, false), (GENESIS, GENESIS, false)],
            "a failed heartbeat must not stop the explicitly accepted next heartbeat",
        );

        let b1 = make_block(1, 1, GENESIS);
        let verdict = h
            .verify(round(1), b1)
            .await
            .expect("actor must keep serving after a heartbeat transport error");
        assert!(verdict.is_some());
    });
}

#[test_traced]
fn actor_exits_when_its_mailbox_closes_during_an_execution_task() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        // SYNCING moves finalization into its one-second retry pause, keeping
        // the execution-task slot occupied without an unresolved EL future.
        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        h.execution
            .script_new_payload(d1, Ok(PayloadStatusEnum::Syncing));
        h.deliver_tip(round(1), 1, d1);
        let acknowledgement = h.deliver_finalized(b1);
        h.wait_until(|| h.execution.new_payloads() == vec![d1])
            .await;

        let execution = h.execution.clone();
        drop(h.mailbox);
        h.actor
            .await
            .expect("actor should exit when the mailbox closes");

        acknowledgement
            .await
            .expect_err("shutdown must cancel the in-flight finalization");
        assert!(
            execution.fcus().is_empty(),
            "the canceled finalization must not reach its forkchoice update",
        );
    });
}

#[test_traced]
fn actor_exits_when_its_mailbox_closes_while_a_payload_job_is_active() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        // Keep the build subscriber alive while its payload remains unresolved.
        // Closing the actor's mailbox must independently tear down both sides
        // of the in-flight build.
        let build = h.build(round(1), GENESIS);
        h.wait_until(|| {
            h.execution
                .calls()
                .iter()
                .any(|call| matches!(call, ElCall::Resolve(_)))
        })
        .await;
        let payload_id = h.execution.pending_payload_jobs()[0];

        let execution = h.execution.clone();
        drop(h.mailbox);
        h.actor
            .await
            .expect("actor should exit when the mailbox closes");

        build
            .await
            .expect_err("shutdown must close the build subscription");
        assert_eq!(execution.canceled_payload_jobs(), vec![payload_id]);
        assert!(
            execution.pending_payload_jobs().is_empty(),
            "shutdown must remove the underlying payload job",
        );
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
