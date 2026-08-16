//! Scenario tests for the startup backfill: before entering its loop, the
//! executor climbs from the execution layer's finalized tip to the
//! consensus finalized floor, sourcing blocks from the marshal actor (or
//! the execution layer itself), and handles snapshot-restored states whose
//! floor sits below the execution layer's finality.

use alloy_rpc_types_engine::PayloadStatusEnum;
use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, deterministic};

use super::harness::{FakeExecution, FakeMarshal, GENESIS, Harness, HarnessOptions, make_block, round};

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

        let h = Harness::start(
            &context,
            FakeExecution::new(),
            marshal,
            HarnessOptions {
                finalized_floor: 2,
                finalized_tip: (round(2), 2, d2),
                ..Default::default()
            },
        );

        h.wait_until(|| h.execution.finalized() == Some((2, d2)))
            .await;
        assert_eq!(h.marshal.get_block_log(), vec![1, 2]);
        assert_eq!(h.execution.new_payloads(), vec![d1, d2]);
        assert_eq!(h.execution.head(), d2);
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

        let h = Harness::start(
            &context,
            execution,
            marshal,
            HarnessOptions {
                finalized_floor: 1,
                finalized_tip: (round(1), 1, d1),
                ..Default::default()
            },
        );

        h.wait_until(|| h.execution.finalized() == Some((1, d1)))
            .await;
        assert_eq!(h.marshal.get_block_log(), vec![1]);
        assert_eq!(h.execution.new_payloads(), vec![d1]);
    });
}

#[test_traced]
fn unsourceable_backfill_block_fails_startup() {
    deterministic::Runner::default().start(|context| async move {
        // Neither marshal nor the execution layer can produce the block at
        // the floor: the executor must refuse to start.
        let h = Harness::start(
            &context,
            FakeExecution::new(),
            FakeMarshal::new(),
            HarnessOptions {
                finalized_floor: 1,
                finalized_tip: (round(1), 1, make_block(1, 1, GENESIS).digest()),
                ..Default::default()
            },
        );

        h.actor
            .await
            .expect("actor should shut down cleanly when the backfill fails");
        assert!(h.execution.fcus().is_empty());
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

        let mut h = Harness::start(
            &context,
            execution,
            FakeMarshal::new(),
            HarnessOptions {
                finalized_floor: 1,
                finalized_tip: (round(2), 2, d2),
                ..Default::default()
            },
        );

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
fn syncing_execution_layer_stalls_the_backfill_until_it_recovers() {
    deterministic::Runner::default().start(|context| async move {
        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();

        let marshal = FakeMarshal::new();
        marshal.add_block(b1);
        let execution = FakeExecution::new();
        // The execution layer is not ready once (e.g. rebuilding indices).
        execution.script_new_payload(d1, Ok(PayloadStatusEnum::Syncing));

        let h = Harness::start(
            &context,
            execution,
            marshal,
            HarnessOptions {
                finalized_floor: 1,
                finalized_tip: (round(1), 1, d1),
                ..Default::default()
            },
        );

        h.wait_until(|| h.execution.finalized() == Some((1, d1)))
            .await;
        assert_eq!(
            h.execution.new_payloads(),
            vec![d1, d1],
            "the backfill must retry the postponed block until it is accepted",
        );
    });
}
