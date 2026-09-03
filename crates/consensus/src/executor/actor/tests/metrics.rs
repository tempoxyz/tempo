//! Runtime metrics after processing consensus messages and EL outcomes.

use alloy_rpc_types_engine::{ForkchoiceState, PayloadStatusEnum};
use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, deterministic};

use super::harness::{ForkchoiceStateExt as _, GENESIS, Harness, built_payload, make_block, round};

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
fn finalization_lag_tracks_the_undelivered_finalized_backlog() {
    deterministic::Runner::default().start(|context| async move {
        let mut h = Harness::start_at_genesis(&context);
        assert_eq!(gauge(&h, "finalization_lag"), 0);

        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let d2 = b2.digest();
        h.deliver_tip(round(2), 2, d2);
        h.wait_until(|| gauge(&h, "finalization_lag") == 2).await;
        assert_eq!(gauge(&h, "convergence_depth"), 2);

        h.deliver_finalized(b1)
            .await
            .expect("b1 should be acknowledged");
        h.wait_until(|| gauge(&h, "finalization_lag") == 1).await;

        h.deliver_finalized(b2)
            .await
            .expect("b2 should be acknowledged");
        h.wait_until(|| gauge(&h, "finalization_lag") == 0).await;
        assert_eq!(gauge(&h, "convergence_depth"), 0);
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
        drop(h.build(round(3), d2));
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
        drop(h.build(round(4), unknown));
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
        let d3 = b3.digest();
        for (view, block) in [(1, b1), (2, b2), (3, b3)] {
            h.verify(round(view), block)
                .await
                .expect("verification should complete")
                .expect("block should be valid");
        }
        let proposal = make_block(4, 4, d3);
        h.execution.script_built_payload(built_payload(&proposal));
        h.build(round(4), d3)
            .await
            .expect("build on branch B should complete");
        h.wait_until(|| h.execution.head() == d3).await;
        h.wait_until(|| gauge(&h, "convergence_depth") == 0).await;

        // Hold the fallback FCU open while the lower target's body arrives,
        // so the signed distance from the previous HEAD is observable.
        let release_fcu = h.execution.script_delayed_fcu(
            ForkchoiceState::from_finalized_head(GENESIS, GENESIS),
            Ok(PayloadStatusEnum::Valid),
        );
        let a1 = make_block(4, 1, GENESIS);
        let a2 = make_block(5, 2, a1.digest());
        let da2 = a2.digest();
        drop(h.build(round(6), da2));
        h.wait_until(|| h.marshal.fulfill_subscription(da2, a2.clone()))
            .await;
        h.wait_until(|| gauge(&h, "convergence_depth") == -1).await;
        assert_eq!(h.execution.head(), d3);
        release_fcu.send(()).unwrap();
        h.wait_until(|| gauge(&h, "convergence_depth") == 2).await;
        assert_eq!(h.execution.head(), GENESIS);
    });
}
