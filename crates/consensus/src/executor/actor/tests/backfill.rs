//! Scenario tests for the startup backfill: before entering its loop, the
//! executor climbs from the execution layer's finalized tip to the
//! consensus finalized floor, sourcing blocks from the marshal actor (or
//! the execution layer itself), and handles snapshot-restored states whose
//! floor sits below the execution layer's finality.

use alloy_rpc_types_engine::{ForkchoiceState, PayloadStatusEnum};
use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, deterministic};

use super::harness::{
    FakeExecution, FakeMarshal, ForkchoiceStateExt as _, GENESIS, Harness, HarnessOptions,
    make_block, round,
};

#[test_traced]
fn no_backfill_when_already_at_the_floor() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        // Entering the loop without touching marshal: a validation works
        // right away.
        let b1 = make_block(1, 1, GENESIS);
        let verdict = h
            .verify(round(1), b1)
            .await
            .expect("verification should complete");
        assert!(verdict.is_some());
        assert!(h.marshal.get_block_log().is_empty());
    });
}

#[test_traced]
fn backfills_to_the_floor_from_marshal() {
    deterministic::Runner::default().start(|context| async move {
        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let (d1, d2) = (b1.digest(), b2.digest());

        let marshal = FakeMarshal::new();
        marshal.add_block(b1);
        marshal.add_block(b2);

        let h = Harness::builder()
            .marshal(marshal)
            .harness_options(HarnessOptions {
                finalized_floor: 2,
                finalized_tip: (round(2), 2, d2),
                ..Default::default()
            })
            .start(&context);

        h.wait_until(|| h.execution.finalized() == Some((2, d2)))
            .await;
        assert_eq!(h.marshal.get_block_log(), vec![1, 2]);
        assert_eq!(h.execution.new_payloads(), vec![d1, d2]);
        assert_eq!(h.execution.head(), d2);
    });
}

#[test_traced]
fn backfill_then_converges_onto_a_notarized_extension() {
    deterministic::Runner::default().start(|context| async move {
        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let b3 = make_block(3, 3, b2.digest());
        let b4 = make_block(4, 4, b3.digest());
        let (d1, d2, d3, d4) = (b1.digest(), b2.digest(), b3.digest(), b4.digest());

        let marshal = FakeMarshal::new();
        marshal.add_block(b1);
        marshal.add_block(b2);

        let h = Harness::builder()
            .marshal(marshal)
            .harness_options(HarnessOptions {
                finalized_floor: 2,
                finalized_tip: (round(2), 2, d2),
                ..Default::default()
            })
            .start(&context);

        // Startup first moves the local head and finality to the floor. The
        // tree's pending head remains anchored at the network finalized tip,
        // so normal notarized convergence can extend from that boundary.
        h.wait_until(|| h.execution.finalized() == Some((2, d2)))
            .await;
        assert_eq!(h.execution.head(), d2);

        // Report a pending head two blocks above the backfilled boundary.
        // Supplying only that block first makes the actor discover and fetch
        // the missing ancestor before forwarding both blocks bottom-up.
        h.report_pending_head(5, 4, d4);
        h.wait_until(|| h.marshal.fulfill_subscription(d4, b4.clone()))
            .await;
        h.wait_until(|| h.marshal.fulfill_subscription(d3, b3.clone()))
            .await;
        h.wait_until(|| h.execution.head() == d4).await;

        assert_eq!(h.marshal.get_block_log(), vec![1, 2]);
        assert_eq!(
            h.marshal.subscribe_log(),
            vec![(d4, round(4)), (d3, round(3))],
        );
        assert_eq!(h.execution.new_payloads(), vec![d1, d2, d3, d4]);
        assert_eq!(
            h.execution.fcus(),
            vec![
                (d1, d1, false),
                (d2, d2, false),
                (d3, d2, false),
                (d4, d2, false),
            ],
            "notarized convergence must preserve the backfilled finalized boundary",
        );
        assert_eq!(h.execution.finalized(), Some((2, d2)));
    });
}

#[test_traced]
fn backfill_falls_back_to_the_execution_layer_for_missing_blocks() {
    deterministic::Runner::default().start(|context| async move {
        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();

        // Marshal no longer stores the block body but still knows the
        // finalized digest; the execution layer has the block.
        let marshal = FakeMarshal::new();
        marshal.add_info(1, d1);
        let execution = FakeExecution::new();
        execution.add_body(b1);

        let h = Harness::builder()
            .execution(execution)
            .marshal(marshal)
            .harness_options(HarnessOptions {
                finalized_floor: 1,
                finalized_tip: (round(1), 1, d1),
                ..Default::default()
            })
            .start(&context);

        h.wait_until(|| h.execution.finalized() == Some((1, d1)))
            .await;
        assert_eq!(h.marshal.get_block_log(), vec![1]);
        assert_eq!(h.execution.new_payloads(), vec![d1]);
    });
}

#[test_traced]
fn execution_layer_body_lookup_error_fails_startup() {
    deterministic::Runner::default().start(|context| async move {
        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();

        let marshal = FakeMarshal::new();
        marshal.add_info(1, d1);
        let execution = FakeExecution::new();
        execution.script_block_by_digest(d1, Err("database unavailable"));

        let h = Harness::builder()
            .execution(execution)
            .marshal(marshal)
            .harness_options(HarnessOptions {
                finalized_floor: 1,
                finalized_tip: (round(1), 1, d1),
                ..Default::default()
            })
            .start(&context);

        h.actor
            .await
            .expect("actor should shut down cleanly when the body lookup fails");
        assert!(h.execution.new_payloads().is_empty());
        assert!(h.execution.fcus().is_empty());
    });
}

#[test_traced]
fn execution_layer_missing_body_from_finalization_info_fails_startup() {
    deterministic::Runner::default().start(|context| async move {
        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();

        // Marshal knows which block was finalized but no longer has its body,
        // and the execution layer cannot supply the body either.
        let marshal = FakeMarshal::new();
        marshal.add_info(1, d1);

        let h = Harness::builder()
            .marshal(marshal)
            .harness_options(HarnessOptions {
                finalized_floor: 1,
                finalized_tip: (round(1), 1, d1),
                ..Default::default()
            })
            .start(&context);

        h.actor
            .await
            .expect("actor should shut down cleanly when no block body is available");
        assert_eq!(h.marshal.get_block_log(), vec![1]);
        assert!(h.execution.new_payloads().is_empty());
        assert!(h.execution.fcus().is_empty());
    });
}

#[test_traced]
fn unsourceable_backfill_block_fails_startup() {
    deterministic::Runner::default().start(|context| async move {
        // Neither marshal nor the execution layer can produce the block at
        // the floor: the executor must refuse to start.
        let h = Harness::builder()
            .harness_options(HarnessOptions {
                finalized_floor: 1,
                finalized_tip: (round(1), 1, make_block(1, 1, GENESIS).digest()),
                ..Default::default()
            })
            .start(&context);

        h.actor
            .await
            .expect("actor should shut down cleanly when the backfill fails");
        assert!(h.execution.fcus().is_empty());
    });
}

#[test_traced]
fn canonical_hash_read_error_fails_initialization() {
    deterministic::Runner::default().start(|context| async move {
        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let d2 = b2.digest();

        // A snapshot floor below execution finality requires a canonical-hash
        // read so the actor can reconstruct its starting finalized state.
        let execution = FakeExecution::new();
        execution.seed_canonical_block(&b1);
        execution.seed_canonical_block(&b2);
        execution.set_finalized(2, d2);
        execution.script_canonical_block_hash(1, Err("database unavailable"));

        let result = Harness::builder()
            .execution(execution)
            .harness_options(HarnessOptions {
                finalized_floor: 1,
                finalized_tip: (round(2), 2, d2),
                ..Default::default()
            })
            .try_start(&context);

        let Err(error) = result else {
            panic!("actor initialization should fail");
        };
        let error = format!("{error:#}");
        assert!(
            error.contains(
                "failed reading canonical execution block hash at the finalized floor height `1`"
            ),
            "unexpected error: {error}",
        );
        assert!(
            error.contains("database unavailable"),
            "unexpected error: {error}",
        );
    });
}

#[test_traced]
fn finalized_tip_below_the_floor_fails_initialization() {
    deterministic::Runner::default().start(|context| async move {
        let b1 = make_block(1, 1, GENESIS);

        let result = Harness::builder()
            .harness_options(HarnessOptions {
                finalized_floor: 2,
                finalized_tip: (round(1), 1, b1.digest()),
                ..Default::default()
            })
            .try_start(&context);

        let Err(error) = result else {
            panic!("actor initialization should reject a finalized tip below its floor");
        };
        assert_eq!(
            format!("{error:#}"),
            "failed initializing actor: finalized tip height `1` is below the finalized floor `2`",
        );
    });
}

#[test_traced]
fn snapshot_restore_replays_below_execution_finality_without_forkchoice_updates() {
    deterministic::Runner::default().start(|context| async move {
        // A restored consensus snapshot anchors the floor at height 1 while
        // the execution database is already final at height 2. Marshal
        // re-delivers from the floor; the executor acknowledges the
        // already-final block without submitting a stale forkchoice state,
        // then catches up through the re-delivery.
        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let (d1, d2) = (b1.digest(), b2.digest());

        let execution = FakeExecution::new();
        execution.seed_canonical_block(&b1);
        execution.seed_canonical_block(&b2);
        execution.set_finalized(2, d2);

        let mut h = Harness::builder()
            .execution(execution)
            .harness_options(HarnessOptions {
                finalized_floor: 1,
                finalized_tip: (round(2), 2, d2),
                ..Default::default()
            })
            .start(&context);

        // Re-delivery of the block at the floor: acknowledged, but no
        // forkchoice update is submitted for the stale state.
        h.deliver_finalized(b1)
            .await
            .expect("the re-delivered block should be acknowledged");
        assert_eq!(h.execution.new_payloads(), vec![d1]);
        assert_eq!(
            h.execution.fcus(),
            vec![],
            "a forkchoice state below the execution layer's finality is stale \
            and must not be submitted",
        );

        // The next re-delivered block reaches the execution layer's
        // finality; from here on forkchoice updates flow again.
        h.deliver_finalized(b2)
            .await
            .expect("the block at the execution finality should be acknowledged");
        assert_eq!(h.execution.fcus(), vec![(d2, d2, false)]);
        assert_eq!(h.execution.finalized(), Some((2, d2)));
    });
}

#[test_traced]
fn invalid_payload_fails_startup_backfill() {
    deterministic::Runner::default().start(|context| async move {
        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();

        let marshal = FakeMarshal::new();
        marshal.add_block(b1);
        let execution = FakeExecution::new();
        execution.script_new_payload(
            d1,
            Ok(PayloadStatusEnum::Invalid {
                validation_error: "bad backfill block".into(),
            }),
        );

        let h = Harness::builder()
            .execution(execution)
            .marshal(marshal)
            .harness_options(HarnessOptions {
                finalized_floor: 1,
                finalized_tip: (round(1), 1, d1),
                ..Default::default()
            })
            .start(&context);

        h.actor
            .await
            .expect("actor should shut down cleanly when a backfill payload is invalid");
        assert_eq!(h.execution.new_payloads(), vec![d1]);
        assert!(h.execution.fcus().is_empty());
    });
}

#[test_traced]
fn rejected_forkchoice_update_fails_startup_backfill() {
    deterministic::Runner::default().start(|context| async move {
        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();

        let marshal = FakeMarshal::new();
        marshal.add_block(b1);
        let execution = FakeExecution::new();
        execution.script_fcu(
            ForkchoiceState::from_finalized_head(d1, d1),
            [Ok(PayloadStatusEnum::Invalid {
                validation_error: "rejected backfill forkchoice".into(),
            })],
        );

        let h = Harness::builder()
            .execution(execution)
            .marshal(marshal)
            .harness_options(HarnessOptions {
                finalized_floor: 1,
                finalized_tip: (round(1), 1, d1),
                ..Default::default()
            })
            .start(&context);

        h.actor
            .await
            .expect("actor should shut down cleanly when the backfill FCU is rejected");
        assert_eq!(h.execution.new_payloads(), vec![d1]);
        assert_eq!(h.execution.fcus(), vec![(d1, d1, false)]);
        assert_eq!(h.execution.head(), GENESIS);
        assert_eq!(h.execution.finalized(), None);
    });
}

#[test_traced]
fn syncing_execution_layer_stalls_the_backfill_until_it_recovers() {
    deterministic::Runner::default().start(|context| async move {
        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();

        let marshal = FakeMarshal::new();
        marshal.add_block(b1);
        let execution = FakeExecution::new();
        // The execution layer is not ready once (e.g. rebuilding indices),
        // then accepts the explicit retry.
        execution.script_new_payload(d1, Ok(PayloadStatusEnum::Syncing));
        execution.script_new_payload(d1, Ok(PayloadStatusEnum::Valid));

        let h = Harness::builder()
            .execution(execution)
            .marshal(marshal)
            .harness_options(HarnessOptions {
                finalized_floor: 1,
                finalized_tip: (round(1), 1, d1),
                ..Default::default()
            })
            .start(&context);

        h.wait_until(|| h.execution.finalized() == Some((1, d1)))
            .await;
        assert_eq!(
            h.execution.new_payloads(),
            vec![d1, d1],
            "the backfill must retry the postponed block until it is accepted",
        );
    });
}

#[test_traced]
fn new_payload_transport_error_fails_startup() {
    deterministic::Runner::default().start(|context| async move {
        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();

        let marshal = FakeMarshal::new();
        marshal.add_block(b1);
        let execution = FakeExecution::new();
        execution.script_new_payload(d1, Err("connection closed"));

        let h = Harness::builder()
            .execution(execution)
            .marshal(marshal)
            .harness_options(HarnessOptions {
                finalized_floor: 1,
                finalized_tip: (round(1), 1, d1),
                ..Default::default()
            })
            .start(&context);

        h.actor
            .await
            .expect("actor should shut down cleanly when startup forwarding fails");
        assert_eq!(h.execution.new_payloads(), vec![d1]);
        assert!(h.execution.fcus().is_empty());
    });
}
