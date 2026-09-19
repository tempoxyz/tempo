//! Actor-level coverage for the executor's runtime metrics. The notarized
//! tree unit tests cover the arithmetic; these tests prove that the actor
//! publishes the measures after processing real messages and EL outcomes.

use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, deterministic};

use super::harness::{GENESIS, Harness, make_block, round};

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
        let b3 = make_block(3, 3, b2.digest());
        let (d1, d2, d3) = (b1.digest(), b2.digest(), b3.digest());
        for (view, block, digest) in [(1, b1, d1), (2, b2, d2), (3, b3, d3)] {
            h.verify(round(view), block)
                .await
                .expect("verification should complete")
                .expect("block should be valid");
            h.report_pending_head(view + 1, view, digest);
            h.wait_until(|| h.execution.head() == digest).await;
        }
        h.wait_until(|| gauge(&h, "convergence_depth") == 0).await;

        // Re-anchor onto a2 on a side branch at height 2 while its parent
        // a1 is missing: the ancestry is not walkable, so the head stays at
        // b3 and the signed distance is observable.
        let a1 = make_block(4, 1, GENESIS);
        let a2 = make_block(5, 2, a1.digest());
        let da2 = a2.digest();
        h.report_pending_head(6, 5, da2);
        h.wait_until(|| h.marshal.fulfill_subscription(da2, a2.clone()))
            .await;
        h.wait_until(|| gauge(&h, "convergence_depth") == -1).await;
        assert_eq!(h.execution.head(), d3);
    });
}

#[test_traced]
fn uncanonicalized_blocks_tracks_delivered_blocks_off_the_canonical_chain() {
    deterministic::Runner::default().start(|context| async move {
        let h = Harness::start_at_genesis(&context);
        assert_eq!(gauge(&h, "uncanonicalized_blocks"), 0);

        // A validated block is known to the execution layer but not its
        // head yet.
        let b1 = make_block(1, 1, GENESIS);
        let d1 = b1.digest();
        h.verify(round(1), b1)
            .await
            .expect("verification should complete")
            .expect("block should be valid");
        h.wait_until(|| gauge(&h, "uncanonicalized_blocks") == 1)
            .await;

        // Moving the head onto it canonicalizes it.
        h.report_pending_head(2, 1, d1);
        h.wait_until(|| h.execution.head() == d1).await;
        h.wait_until(|| gauge(&h, "uncanonicalized_blocks") == 0)
            .await;

        // A validated sibling stays on a side branch.
        let a1 = make_block(3, 1, GENESIS);
        h.verify(round(3), a1)
            .await
            .expect("verification should complete")
            .expect("block should be valid");
        h.wait_until(|| gauge(&h, "uncanonicalized_blocks") == 1)
            .await;
    });
}
