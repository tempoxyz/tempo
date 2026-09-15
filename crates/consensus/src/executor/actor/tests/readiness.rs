use std::time::Duration;

use commonware_consensus::{Reporter as _, Reporters};
use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
use futures::FutureExt as _;

use crate::epoch::manager::Readiness;

use super::harness::{FakeMarshal, GENESIS, Harness, HarnessOptions, make_block, round};

#[test_traced]
fn readiness_releases_backfill_and_queued_blocks_for_all_listeners() {
    deterministic::Runner::default().start(|context| async move {
        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let (d1, d2) = (b1.digest(), b2.digest());
        let mut listeners = Vec::new();
        for name in ["first", "second"] {
            let marshal = FakeMarshal::new();
            marshal.add_block(b1.clone());
            let mut harness = Harness::builder()
                .marshal(marshal)
                .harness_options(HarnessOptions {
                    finalized_floor: 1,
                    finalized_tip: (round(1), 1, d1),
                    ..Default::default()
                })
                .defer_readiness()
                .start(&context.child(name));
            harness.deliver_tip(round(2), 2, d2);
            let ack = harness.deliver_finalized(b2.clone());
            listeners.push((harness, Box::pin(ack)));
        }

        listeners[0].0.run_for(Duration::from_secs(1)).await;
        for (harness, ack) in &mut listeners {
            assert!(harness.execution.calls().is_empty());
            assert!(harness.marshal.get_block_log().is_empty());
            assert!(ack.as_mut().now_or_never().is_none());
        }

        let mut reporter = Reporters::from((
            listeners[0].0.mailbox.readiness_reporter(),
            listeners[1].0.mailbox.readiness_reporter(),
        ));
        assert!(reporter.report(Readiness).accepted());

        for (harness, ack) in listeners {
            ack.await.expect("queued finalization must be acknowledged");
            assert_eq!(harness.execution.new_payloads(), vec![d1, d2]);
            assert_eq!(harness.execution.finalized(), Some((2, d2)));
            assert_eq!(harness.marshal.get_block_log(), vec![1]);
        }
    });
}

#[test_traced]
fn closing_before_readiness_drops_queued_blocks_without_execution() {
    deterministic::Runner::default().start(|context| async move {
        let mut harness = Harness::builder().defer_readiness().start(&context);
        let b1 = make_block(1, 1, GENESIS);
        let ack = harness.deliver_finalized(b1);
        drop(harness.mailbox);
        harness
            .actor
            .await
            .expect("executor must exit when its mailbox closes before readiness");
        assert!(ack.await.is_err());
        assert!(harness.execution.calls().is_empty());
        assert!(harness.marshal.get_block_log().is_empty());
    });
}

#[test_traced]
fn startup_drain_keeps_finalizations_ordered_and_supersedes_stale_requests() {
    deterministic::Runner::default().start(|context| async move {
        let b1 = make_block(1, 1, GENESIS);
        let b2 = make_block(2, 2, b1.digest());
        let b3 = make_block(3, 3, b2.digest());
        let candidate = make_block(5, 4, b3.digest());
        let (d1, d2, d3, candidate_digest) =
            (b1.digest(), b2.digest(), b3.digest(), candidate.digest());
        let marshal = FakeMarshal::new();
        marshal.add_block(b1);
        let mut harness = Harness::builder()
            .marshal(marshal)
            .harness_options(HarnessOptions {
                finalized_floor: 1,
                finalized_tip: (round(1), 1, d1),
                ..Default::default()
            })
            .defer_readiness()
            .start(&context);

        harness.deliver_tip(round(3), 3, d3);
        let ack2 = harness.deliver_finalized(b2);
        let ack3 = harness.deliver_finalized(b3);
        let build = harness.build(round(4), d3);
        let verify = harness.verify(round(5), candidate);
        futures::pin_mut!(ack2, ack3, verify);
        // Poll once to enqueue the validation request on the same mailbox.
        assert!(verify.as_mut().now_or_never().is_none());

        // Draining uses ordinary request arbitration without starting execution.
        build
            .await
            .expect_err("the newer validation must supersede the queued build");
        assert!(verify.as_mut().now_or_never().is_none());
        assert!(ack2.as_mut().now_or_never().is_none());
        assert!(ack3.as_mut().now_or_never().is_none());
        assert!(harness.execution.calls().is_empty());
        assert!(harness.marshal.get_block_log().is_empty());

        assert!(
            harness
                .mailbox
                .readiness_reporter()
                .report(Readiness)
                .accepted()
        );
        ack2.await.expect("first queued finalization");
        ack3.await.expect("second queued finalization");
        assert!(
            verify
                .await
                .expect("queued validation must run after its parent is finalized")
                .is_some()
        );
        assert_eq!(
            harness.execution.new_payloads(),
            vec![d1, d2, d3, candidate_digest]
        );
        assert_eq!(harness.execution.finalized(), Some((3, d3)));
        assert!(
            !harness
                .execution
                .fcus()
                .iter()
                .any(|(.., with_attrs)| *with_attrs)
        );
    });
}
