//! Scenario tests for the actor's scheduling invariants: one execution-layer
//! task at a time, consensus requests before finality work before notarized
//! convergence, the FCU heartbeat, and shutdown.

use std::time::Duration;

use alloy_rpc_types_engine::{ForkchoiceState, PayloadStatusEnum};
use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, Spawner as _, Supervisor as _, deterministic};
use futures::future::Either;

use super::harness::{
    ElCall, FakeExecution, ForkchoiceStateExt as _, GENESIS, Harness, HarnessOptions, STARTUP_FCU,
    STARTUP_FCU_CALL, built_payload, make_block, round,
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

        let release_finalization = h
            .execution
            .script_delayed_new_payload(d1, Ok(PayloadStatusEnum::Valid));
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
            vec![STARTUP_FCU_CALL, ElCall::NewPayload(d1)],
            "the in-flight task must be the only execution-layer activity",
        );

        // Releasing finalization makes the slot available; the queued
        // validation is latency-critical and wins it over finalization of b2.
        release_finalization
            .send(())
            .expect("finalization should still be gated");
        w1.await.expect("first block should be acknowledged");
        let verdict = verify.await.expect("verification should complete");
        assert!(verdict.is_some());
        w2.await.expect("second block should be acknowledged");

        assert_eq!(
            h.execution.calls(),
            vec![
                STARTUP_FCU_CALL,
                ElCall::NewPayload(d1),
                // The validation of b2 runs before b2's finalization and
                // before the forkchoice update finalizing b1: its
                // new-payload probe wins the slot as soon as it is free.
                ElCall::NewPayload(d2),
                // b2 was pruned from the tree by the tip covering it, so its
                // finalization delivers it again ...
                ElCall::NewPayload(d2),
                // ... and one forkchoice update finalizes both blocks.
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

        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        let release_finalization = h
            .execution
            .script_delayed_new_payload(d1, Ok(PayloadStatusEnum::Valid));
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

        release_finalization
            .send(())
            .expect("finalization should still be gated");
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
                STARTUP_FCU_CALL,
                ElCall::NewPayload(d1),
                // Both operations were ready when the delivery of b1
                // released the slot, but latency-critical consensus work
                // ran first. Finality is locked in next, before notarized
                // convergence delivers b2 and moves the head onto it.
                ElCall::NewPayload(candidate_digest),
                ElCall::Fcu {
                    head: d1,
                    finalized: d1,
                    with_attrs: false,
                },
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
fn finality_is_locked_in_before_notarized_convergence() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let (d1, d2) = (b1.digest(), b2.digest());
        let release_finalization = h
            .execution
            .script_delayed_new_payload(d1, Ok(PayloadStatusEnum::Valid));
        h.deliver_tip(round(2), 2, d2);
        let w1 = h.deliver_finalized(b1);
        h.wait_until(|| h.execution.new_payloads() == vec![d1])
            .await;

        // Make convergence onto the notarized n3 ready above the finalized
        // boundary while the first finalized delivery still owns the slot,
        // and queue the second finalized block behind it.
        let n3 = make_block(3, 3, d2);
        let d3 = n3.digest();
        h.report_pending_head(4, 3, d3);
        h.wait_until(|| h.marshal.fulfill_subscription(d3, n3.clone()))
            .await;
        h.run_for(Duration::from_millis(10)).await;
        let w2 = h.deliver_finalized(b2);
        h.run_for(Duration::from_millis(10)).await;

        release_finalization
            .send(())
            .expect("finalization should still be gated");
        w1.await.expect("first block should be acknowledged");
        w2.await.expect("second block should be acknowledged");
        h.wait_until(|| h.execution.head() == d3).await;

        assert_eq!(
            h.execution.calls(),
            vec![
                STARTUP_FCU_CALL,
                ElCall::NewPayload(d1),
                // The queued finalized range is drained and locked in with
                // one forkchoice update before the notarized block is
                // delivered, even though n3 was ready first.
                ElCall::NewPayload(d2),
                ElCall::Fcu {
                    head: d2,
                    finalized: d2,
                    with_attrs: false,
                },
                ElCall::NewPayload(d3),
                ElCall::Fcu {
                    head: d3,
                    finalized: d2,
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
        let release_finalization = h
            .execution
            .script_delayed_new_payload(d1, Ok(PayloadStatusEnum::Valid));
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
        assert_eq!(
            h.execution.fcus(),
            vec![STARTUP_FCU],
            "heartbeats must remain disarmed while execution work is active or queued",
        );

        release_finalization
            .send(())
            .expect("finalization should still be gated");
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
        assert_eq!(h.execution.fcus(), vec![STARTUP_FCU]);

        // A stale timer would fire during this window. A correctly rearmed
        // timer instead grants a fresh 300ms interval after work finishes.
        h.run_for(Duration::from_millis(100)).await;
        assert_eq!(
            h.execution.fcus(),
            vec![STARTUP_FCU],
            "the pre-work heartbeat deadline must not survive",
        );

        h.run_for(Duration::from_millis(250)).await;
        h.wait_until(|| h.execution.fcus().len() == 2).await;
        assert_eq!(
            h.execution.fcus(),
            vec![STARTUP_FCU, (GENESIS, GENESIS, false)]
        );
    });
}

#[test_traced]
fn idle_actor_sends_forkchoice_heartbeats() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::builder()
            .harness_options(HarnessOptions {
                fcu_heartbeat_interval: Duration::from_millis(300),
                ..Default::default()
            })
            .start(&context);

        h.run_for(Duration::from_secs(1)).await;
        let fcus = h.execution.fcus();
        let (startup, heartbeats) = fcus.split_first().expect("startup must send an FCU");
        assert_eq!(*startup, STARTUP_FCU);
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
    });
}

#[test_traced]
fn rejected_heartbeat_is_fatal() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::builder()
            .harness_options(HarnessOptions {
                fcu_heartbeat_interval: Duration::from_millis(300),
                ..Default::default()
            })
            .start(&context);

        // A heartbeat re-affirms the state the execution layer last
        // accepted. Rejecting it means the execution layer no longer agrees
        // with the executor about its own state. (The startup readiness
        // probe must pass first.)
        h.wait_until(|| h.execution.fcus().len() == 1).await;
        h.execution.reject_all_fcus(true);
        h.actor
            .await
            .expect("actor should shut down cleanly on a rejected heartbeat");
        assert_eq!(
            h.execution.fcus(),
            vec![STARTUP_FCU, (GENESIS, GENESIS, false)]
        );
    });
}

#[test_traced]
fn heartbeat_transport_error_is_fatal() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::builder()
            .harness_options(HarnessOptions {
                fcu_heartbeat_interval: Duration::from_millis(300),
                ..Default::default()
            })
            .start(&context);
        let state = ForkchoiceState::from_finalized_head(GENESIS, GENESIS);
        h.execution.script_fcu(state, Err("connection closed"));

        h.actor
            .await
            .expect("actor should shut down cleanly on a heartbeat transport error");
        assert_eq!(
            h.execution.fcus(),
            vec![STARTUP_FCU, (GENESIS, GENESIS, false)]
        );
    });
}

#[test_traced]
fn actor_exits_when_its_mailbox_closes_during_an_execution_task() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        let _release_finalization = h
            .execution
            .script_delayed_new_payload(d1, Ok(PayloadStatusEnum::Valid));
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
        assert_eq!(
            execution.fcus(),
            vec![STARTUP_FCU],
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

#[test_traced]
fn held_build_is_rescheduled_after_a_stale_repoint() {
    deterministic::Runner::default().start(|context| async move {
        // A restored consensus snapshot anchors the floor at height 1 while
        // the execution layer is final at height 2: every forkchoice update
        // onto the tracked finality is stale and folds without an engine
        // call.
        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let (d1, d2) = (b1.digest(), b2.digest());
        let execution = FakeExecution::new();
        execution.seed_canonical_block(&b1);
        execution.seed_canonical_block(&b2);
        execution.set_finalized(2, d2);
        let h = Harness::builder()
            .execution(execution)
            .harness_options(HarnessOptions {
                finalized_floor: 1,
                finalized_tip: (round(1), 1, d1),
                ..Default::default()
            })
            .start(&context);

        // Strand the tracked head on a notarized sibling of b2.
        let a2 = make_block(3, 2, d1);
        let da2 = a2.digest();
        h.verify(round(3), a2)
            .await
            .expect("verification should complete")
            .expect("a2 should be valid");
        h.report_pending_head(4, 3, da2);

        // Hold the execution slot with a validation (held itself until the
        // head is on a2) so that the re-anchor on the finalized tip and the
        // build on it queue up behind it.
        let a3 = make_block(4, 3, da2);
        let da3 = a3.digest();
        let release = h
            .execution
            .script_delayed_new_payload(da3, Ok(PayloadStatusEnum::Valid));
        let validation = h.verify(round(4), a3);
        futures::pin_mut!(validation);
        let deadline = h.run_for(Duration::from_millis(1));
        futures::pin_mut!(deadline);
        let validation = match futures::future::select(validation, deadline).await {
            Either::Left(_) => panic!("the gated validation completed early"),
            Either::Right(((), validation)) => validation,
        };
        h.wait_until(|| h.execution.new_payloads().last() == Some(&da3))
            .await;
        h.report_pending_head(5, 1, d1);
        let build = h.build(round(5), d1);
        futures::pin_mut!(build);
        release.send(()).expect("validation should still be gated");
        validation
            .await
            .expect("validation should complete")
            .expect("a3 should be valid");

        // The build is held while the head is expected to be repointed
        // onto the tip; the repoint is stale and submits nothing. The held
        // build must be re-examined once the repoint completes and fail
        // fast (it is below the execution layer's finality), rather than
        // wait for an unrelated event.
        let deadline = h.run_for(Duration::from_millis(100));
        futures::pin_mut!(deadline);
        match futures::future::select(build, deadline).await {
            Either::Left((result, _deadline)) => {
                result.expect_err("a build below the execution layer's finality must fail");
            }
            Either::Right(((), _build)) => {
                panic!("the held build was not re-examined after the stale repoint")
            }
        }
        assert!(
            !h.execution.fcus().iter().any(|(.., attrs)| *attrs),
            "no payload may be registered below the execution layer's finality",
        );
    });
}
