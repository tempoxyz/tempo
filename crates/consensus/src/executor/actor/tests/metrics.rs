//! Actor-level coverage for the executor's runtime metrics. The notarized
//! tree unit tests cover the arithmetic; these tests prove that the actor
//! publishes the measures after processing real messages and EL outcomes.

use alloy_rpc_types_engine::{ForkchoiceState, PayloadStatusEnum};
use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, deterministic};

use super::harness::{ForkchoiceStateExt as _, GENESIS, Harness, make_block, round};

fn gauge(h: &Harness, name: &str) -> i64 {
    let name = format!("executor_{name}");
    h.metrics()
        .lines()
        .find_map(|line| {
            let (published, value) = line.split_once(' ')?;
            (published == name).then(|| value.parse().expect("gauge should contain an integer"))
        })
        .unwrap_or_else(|| panic!("gauge `{name}` should be published"))
}

#[test_traced]
fn notarized_tree_blocks_tracks_retained_and_pruned_bodies() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);
        assert_eq!(gauge(&h, "notarized_tree_blocks"), 0);

        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let d1 = b1.digest();
        h.verify(round(1), b1)
            .await
            .expect("b1 verification should complete")
            .expect("b1 should be valid");
        h.verify(round(2), b2)
            .await
            .expect("b2 verification should complete")
            .expect("b2 should be valid");

        h.wait_until(|| gauge(&h, "notarized_tree_blocks") == 2)
            .await;

        // Advancing the network-finalized boundary prunes the covered body,
        // while the body above it remains available for convergence.
        h.deliver_tip(round(1), 1, d1);
        h.wait_until(|| gauge(&h, "notarized_tree_blocks") == 1)
            .await;
    });
}

#[test_traced]
fn finalization_lag_tracks_the_undelivered_finalized_backlog() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);
        assert_eq!(gauge(&h, "finalization_lag"), 0);

        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let d2 = b2.digest();
        h.deliver_tip(round(2), 2, d2);
        h.wait_until(|| gauge(&h, "finalization_lag") == 2).await;

        h.deliver_finalized(b1)
            .await
            .expect("b1 should be acknowledged");
        h.wait_until(|| gauge(&h, "finalization_lag") == 1).await;

        h.deliver_finalized(b2)
            .await
            .expect("b2 should be acknowledged");
        h.wait_until(|| gauge(&h, "finalization_lag") == 0).await;
    });
}

#[test_traced]
fn convergence_depth_tracks_known_and_unknown_pending_heads() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        // The default pending head is genesis, whose height is known and
        // matches the local head.
        assert_eq!(gauge(&h, "convergence_depth"), 0);

        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let d1 = b1.digest();
        let d2 = b2.digest();

        // Before its body arrives, the pending head's height is unknown. The
        // actor keeps the last published value rather than inventing a depth.
        h.report_pending_head(3, 2, d2);
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(d2, round(2))])
            .await;
        assert_eq!(gauge(&h, "convergence_depth"), 0);

        // Once b2 arrives its height is known. Its missing parent keeps
        // convergence stalled, exposing the positive two-block backlog.
        assert!(h.marshal.fulfill_subscription(d2, b2));
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(d1, round(1))])
            .await;
        h.wait_until(|| gauge(&h, "convergence_depth") == 2).await;

        // Move to another pending head whose body has not arrived. Unknown
        // depth must preserve the last known value, including a non-zero one.
        let unknown = make_block(3, 3, GENESIS).digest();
        h.report_pending_head(4, 3, unknown);
        h.wait_until(|| h.marshal.open_subscriptions() == vec![(unknown, round(3))])
            .await;
        assert_eq!(gauge(&h, "convergence_depth"), 2);
    });
}

#[test_traced]
fn convergence_depth_is_negative_while_reanchoring_below_the_local_head() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);

        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let (d1, d2) = (b1.digest(), b2.digest());
        for (view, block, digest) in [(1, b1, d1), (2, b2, d2)] {
            h.verify(round(view), block)
                .await
                .expect("verification should complete")
                .expect("block should be valid");
            h.report_pending_head(view + 1, view, digest);
            h.wait_until(|| h.execution.head() == digest).await;
        }
        h.wait_until(|| gauge(&h, "convergence_depth") == 0).await;

        // Keep the re-anchor from completing so the signed distance remains
        // observable: the pending head is b1 at height 1 while the accepted
        // local head remains b2 at height 2.
        h.execution.script_fcu(
            ForkchoiceState::from_finalized_head(GENESIS, d1),
            Ok(PayloadStatusEnum::Invalid {
                validation_error: "re-anchor rejected by test".into(),
            }),
        );
        h.report_pending_head(4, 1, d1);
        h.wait_until(|| gauge(&h, "convergence_depth") == -1).await;
        assert_eq!(h.execution.head(), d2);
    });
}
