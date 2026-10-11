//! Standalone follower executor actor tests.

mod utils;

use std::{num::NonZeroU64, time::Duration};

use alloy_primitives::B256;
use commonware_consensus::{
    Reporter as _,
    marshal::Update,
    types::{Epoch, FixedEpocher, Height, Round, View},
};
use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
use commonware_utils::{Acknowledgement as _, acknowledgement::Exact};

use super::*;
use crate::consensus::Digest;
use utils::{StubExecutionProvider, StubMarshal, make_block, make_block_at_round};

const EPOCH_LENGTH: NonZeroU64 = NonZeroU64::new(10).expect("epoch length is nonzero");
const HEARTBEAT_INTERVAL: Duration = Duration::from_millis(5);
const WAIT_ATTEMPTS: usize = 100;

async fn wait_until<T: commonware_runtime::Clock>(context: &T, mut cond: impl FnMut() -> bool) {
    for _ in 0..WAIT_ATTEMPTS {
        if cond() {
            return;
        }

        context.sleep(Duration::from_millis(1)).await;
    }

    assert!(cond(), "condition was not met before the test deadline");
}

fn round(view: u64) -> Round {
    Round::new(Epoch::zero(), View::new(view))
}

fn digest(byte: u8) -> Digest {
    Digest(B256::with_last_byte(byte))
}

#[test_traced]
fn block_is_executed_canonicalized_acknowledged_and_advances_floor_to_deep_candidate() {
    deterministic::Runner::default().start(|context| async move {
        let finalized_height = EPOCH_LENGTH.get() * 2;
        let expected_floor = finalized_height - EPOCH_LENGTH.get() - 1;
        let block_height = finalized_height + 1;
        let provider = StubExecutionProvider::default();
        provider.set_finalized(finalized_height, B256::with_last_byte(20), Round::zero());
        provider.set_durable(expected_floor, B256::with_last_byte(9));

        let marshal = StubMarshal::default();

        let (actor, mut mailbox) = init(
            context.child("follower_executor"),
            Config {
                execution_provider: provider.clone(),
                execution_engine: provider.clone(),
                marshal: marshal.clone(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
                floor: Height::zero(),
                fcu_heartbeat_interval: Duration::from_secs(60),
            },
        );

        actor.start();

        for height in [expected_floor, expected_floor + 1, finalized_height] {
            assert!(
                mailbox
                    .report(Update::Tip(
                        Round::zero(),
                        Height::new(height),
                        Digest(B256::with_last_byte(height as u8)),
                    ))
                    .accepted()
            );
        }

        let block = make_block_at_round(block_height, B256::with_last_byte(20), round(1));
        let block_hash = block.digest().0;
        let (ack, waiter) = Exact::handle();
        assert!(mailbox.report(Update::Block(block.into(), ack)).accepted());
        waiter.await.expect("valid payload should be acknowledged");

        wait_until(&context, || marshal.floor() == Height::new(expected_floor)).await;

        assert_eq!(marshal.floor(), Height::new(expected_floor));
        assert_eq!(provider.payload_count(), 1);
        assert_eq!(
            provider.forkchoices(),
            vec![alloy_rpc_types_engine::ForkchoiceState {
                head_block_hash: block_hash,
                safe_block_hash: block_hash,
                finalized_block_hash: block_hash,
            }]
        );
    });
}

#[test_traced]
fn floor_candidate_uses_execution_depth_and_next_tip_starts_new_cycle() {
    deterministic::Runner::default().start(|context| async move {
        let provider = StubExecutionProvider::default();
        provider.set_finalized(18, B256::with_last_byte(18), Round::zero());
        provider.set_durable(9, B256::with_last_byte(9));

        let marshal = StubMarshal::default();
        let (actor, mut mailbox) = init(
            context.child("follower_executor"),
            Config {
                execution_provider: provider.clone(),
                execution_engine: provider.clone(),
                marshal: marshal.clone(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
                floor: Height::zero(),
                fcu_heartbeat_interval: Duration::from_secs(60),
            },
        );

        actor.start();

        for height in [9, 18] {
            assert!(
                mailbox
                    .report(Update::Tip(
                        Round::zero(),
                        Height::new(height),
                        Digest(B256::with_last_byte(height as u8)),
                    ))
                    .accepted()
            );
        }

        let (ack, waiter) = Exact::handle();
        assert!(
            mailbox
                .report(Update::Block(
                    make_block_at_round(19, B256::with_last_byte(18), round(1)).into(),
                    ack,
                ))
                .accepted()
        );
        waiter.await.expect("valid payload should be acknowledged");
        context.sleep(Duration::from_millis(1)).await;
        assert_eq!(marshal.floor(), Height::zero());

        provider.set_finalized(19, B256::with_last_byte(19), Round::zero());
        let (ack, waiter) = Exact::handle();
        assert!(
            mailbox
                .report(Update::Block(
                    make_block_at_round(20, B256::with_last_byte(19), round(2)).into(),
                    ack,
                ))
                .accepted()
        );
        waiter.await.expect("valid payload should be acknowledged");
        wait_until(&context, || marshal.floor() == Height::new(9)).await;

        provider.set_finalized(39, B256::with_last_byte(39), Round::zero());
        provider.set_durable(29, B256::with_last_byte(29));
        assert!(
            mailbox
                .report(Update::Tip(
                    round(3),
                    Height::new(29),
                    Digest(B256::with_last_byte(29)),
                ))
                .accepted()
        );
        wait_until(&context, || marshal.floor() == Height::new(29)).await;
    });
}

#[test_traced]
fn block_at_or_below_finalized_tip_does_not_regress_forkchoice() {
    deterministic::Runner::default().start(|context| async move {
        let finalized_height = EPOCH_LENGTH.get();
        let provider = StubExecutionProvider::default();
        provider.set_finalized(finalized_height, B256::with_last_byte(20), Round::zero());

        let (actor, mut mailbox) = init(
            context.child("follower_executor"),
            Config {
                execution_provider: provider.clone(),
                execution_engine: provider.clone(),
                marshal: StubMarshal::default(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
                floor: Height::zero(),
                fcu_heartbeat_interval: Duration::from_secs(60),
            },
        );

        actor.start();

        let block = make_block(finalized_height - 1, B256::with_last_byte(10));
        let (ack, waiter) = Exact::handle();
        assert!(mailbox.report(Update::Block(block.into(), ack)).accepted());
        waiter.await.expect("valid payload should be acknowledged");

        assert_eq!(provider.payload_count(), 1);
        assert!(provider.forkchoices().is_empty());
    });
}

#[test_traced]
fn floor_does_not_advance_until_its_execution_block_is_durable() {
    deterministic::Runner::default().start(|context| async move {
        let finalized_height = EPOCH_LENGTH.get() * 2;
        let block_height = finalized_height + 1;
        let provider = StubExecutionProvider::default();
        provider.set_finalized(finalized_height, B256::with_last_byte(20), Round::zero());

        let marshal = StubMarshal::default();
        let (actor, mut mailbox) = init(
            context.child("follower_executor"),
            Config {
                execution_provider: provider.clone(),
                execution_engine: provider,
                marshal: marshal.clone(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
                floor: Height::zero(),
                fcu_heartbeat_interval: Duration::from_secs(60),
            },
        );

        actor.start();

        let floor_candidate = finalized_height - EPOCH_LENGTH.get();
        assert!(
            mailbox
                .report(Update::Tip(
                    Round::zero(),
                    Height::new(floor_candidate),
                    Digest(B256::with_last_byte(floor_candidate as u8)),
                ))
                .accepted()
        );
        assert!(
            mailbox
                .report(Update::Tip(
                    Round::zero(),
                    Height::new(finalized_height),
                    Digest(B256::with_last_byte(finalized_height as u8)),
                ))
                .accepted()
        );

        let block = make_block(block_height, B256::with_last_byte(20));
        let (ack, waiter) = Exact::handle();
        assert!(mailbox.report(Update::Block(block.into(), ack)).accepted());
        waiter.await.expect("valid payload should be acknowledged");
        context.sleep(Duration::from_millis(1)).await;

        assert_eq!(marshal.floor(), Height::zero());
    });
}

#[test_traced]
fn invalid_payload_exits_without_acknowledging_or_canonicalizing() {
    deterministic::Runner::default().start(|context| async move {
        let provider = StubExecutionProvider::default();
        provider.reject_payloads();

        let (actor, mut mailbox) = init(
            context.child("follower_executor"),
            Config {
                execution_provider: provider.clone(),
                execution_engine: provider.clone(),
                marshal: StubMarshal::default(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
                floor: Height::zero(),
                fcu_heartbeat_interval: Duration::from_secs(60),
            },
        );

        let actor_handle = actor.start();

        let block = make_block(1, B256::with_last_byte(1));
        let (ack, waiter) = Exact::handle();
        assert!(mailbox.report(Update::Block(block.into(), ack)).accepted());

        assert!(waiter.await.is_err(), "invalid payload must cancel its ack");
        actor_handle
            .await
            .expect("invalid payload should make the actor exit cleanly");

        assert_eq!(provider.payload_count(), 1);
        assert!(provider.forkchoices().is_empty());
    });
}

#[test_traced]
fn forkchoice_failure_exits_without_acknowledging_block() {
    deterministic::Runner::default().start(|context| async move {
        let provider = StubExecutionProvider::default();
        provider.reject_forkchoices();

        let (actor, mut mailbox) = init(
            context.child("follower_executor"),
            Config {
                execution_provider: provider.clone(),
                execution_engine: provider.clone(),
                marshal: StubMarshal::default(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
                floor: Height::zero(),
                fcu_heartbeat_interval: Duration::from_secs(60),
            },
        );
        let actor_handle = actor.start();

        let block = make_block(1, B256::with_last_byte(1));
        let (ack, waiter) = Exact::handle();
        assert!(mailbox.report(Update::Block(block.into(), ack)).accepted());

        assert!(waiter.await.is_err(), "rejected FCU must cancel the ack");
        actor_handle
            .await
            .expect("rejected FCU should make the actor exit cleanly");

        assert_eq!(provider.payload_count(), 1);
        assert_eq!(provider.forkchoices().len(), 1);
    });
}

#[test_traced]
fn tips_are_monotonic_and_coalesced_while_forkchoice_is_in_flight() {
    deterministic::Runner::default().start(|context| async move {
        let provider = StubExecutionProvider::default();
        let release_forkchoice = provider.pause_next_forkchoice();

        let (actor, mut mailbox) = init(
            context.child("follower_executor"),
            Config {
                execution_provider: provider.clone(),
                execution_engine: provider.clone(),
                marshal: StubMarshal::default(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
                floor: Height::zero(),
                fcu_heartbeat_interval: Duration::from_secs(60),
            },
        );

        actor.start();

        let first_digest = Digest(B256::with_last_byte(1));
        let first_tip = Update::Tip(round(1), Height::new(1), first_digest);
        assert!(mailbox.report(first_tip).accepted());
        wait_until(&context, || provider.forkchoices().len() == 1).await;

        let highest_digest = Digest(B256::with_last_byte(4));
        let higher_tip = Update::Tip(round(3), Height::new(3), Digest(B256::with_last_byte(3)));
        assert!(mailbox.report(higher_tip).accepted());

        let lower_tip = Update::Tip(round(2), Height::new(2), Digest(B256::with_last_byte(2)));
        assert!(mailbox.report(lower_tip).accepted());

        let highest_tip = Update::Tip(round(4), Height::new(4), highest_digest);
        assert!(mailbox.report(highest_tip).accepted());

        context.sleep(Duration::from_millis(1)).await;
        assert_eq!(provider.forkchoices().len(), 1);

        release_forkchoice
            .send(())
            .expect("the in-flight FCU should still be waiting");

        wait_until(&context, || provider.forkchoices().len() == 2).await;

        let forkchoices = provider.forkchoices();
        assert_eq!(forkchoices[0].head_block_hash, first_digest.0);
        assert_eq!(forkchoices[1].head_block_hash, highest_digest.0);
        assert_eq!(forkchoices[1].safe_block_hash, highest_digest.0);
        assert_eq!(forkchoices[1].finalized_block_hash, highest_digest.0);
    });
}

// Marshal emits a tip before it delivers the block, so a tip can advance
// forkchoice before execution receives that block.
#[test_traced]
fn tip_drives_forkchoice_by_round() {
    deterministic::Runner::default().start(|context| async move {
        let provider = StubExecutionProvider::default();

        let (actor, mut mailbox) = init(
            context.child("follower_executor"),
            Config {
                execution_provider: provider.clone(),
                execution_engine: provider.clone(),
                marshal: StubMarshal::default(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
                floor: Height::zero(),
                fcu_heartbeat_interval: Duration::from_secs(60),
            },
        );
        actor.start();

        let first = Digest(B256::with_last_byte(1));
        let _ = mailbox.report(Update::Tip(round(1), Height::new(1), first));
        wait_until(&context, || provider.forkchoices().len() == 1).await;

        let finalized = Digest(B256::with_last_byte(9));
        let _ = mailbox.report(Update::Tip(round(2), Height::new(9), finalized));
        wait_until(&context, || provider.forkchoices().len() == 2).await;

        let _ = mailbox.report(Update::Tip(
            round(1),
            Height::new(2),
            Digest(B256::with_last_byte(2)),
        ));
        context.sleep(Duration::from_millis(5)).await;

        let forkchoices = provider.forkchoices();
        assert_eq!(forkchoices.len(), 2);
        assert_eq!(forkchoices[1].head_block_hash, finalized.0);
        assert_eq!(forkchoices[1].safe_block_hash, finalized.0);
        assert_eq!(forkchoices[1].finalized_block_hash, finalized.0);
    });
}

/// An older finalization received while a block FCU is in flight must not
/// become the next forkchoice target.
#[test_traced]
fn delayed_tip_does_not_regress_newer_block_forkchoice() {
    deterministic::Runner::default().start(|context| async move {
        let current = Digest(B256::with_last_byte(10));
        let provider = StubExecutionProvider::default();
        provider.set_finalized(100, current.0, round(10));
        let release_block_forkchoice = provider.pause_next_forkchoice();

        let (actor, mut mailbox) = init(
            context.child("follower_executor"),
            Config {
                execution_provider: provider.clone(),
                execution_engine: provider.clone(),
                marshal: StubMarshal::default(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
                floor: Height::zero(),
                fcu_heartbeat_interval: HEARTBEAT_INTERVAL,
            },
        );
        actor.start();

        let block = make_block_at_round(101, current.0, round(13));
        let newest = block.digest();
        let (ack, waiter) = Exact::handle();
        let _ = mailbox.report(Update::Block(block.into(), ack));
        wait_until(&context, || {
            provider.payload_count() == 1 && provider.forkchoices().len() == 1
        })
        .await;

        let delayed = Digest(B256::with_last_byte(12));
        let _ = mailbox.report(Update::Tip(round(12), Height::new(101), delayed));
        context.sleep(Duration::from_millis(1)).await;

        release_block_forkchoice
            .send(())
            .expect("the block FCU should still be waiting");
        waiter.await.expect("valid payload should be acknowledged");
        context.sleep(Duration::from_millis(1)).await;

        let forkchoices = provider.forkchoices();
        assert_eq!(forkchoices.len(), 1);
        assert_eq!(forkchoices[0].head_block_hash, newest.0);

        wait_until(&context, || provider.forkchoices().len() == 2).await;
        assert_eq!(provider.forkchoices()[1].head_block_hash, newest.0);
    });
}

#[test_traced]
fn execution_tip_round_orders_finalizations_after_restart() {
    deterministic::Runner::default().start(|context| async move {
        let provider = StubExecutionProvider::default();
        provider.set_finalized(100, digest(100).0, round(7));

        let (actor, mut mailbox) = init(
            context.child("follower_executor"),
            Config {
                execution_provider: provider.clone(),
                execution_engine: provider.clone(),
                marshal: StubMarshal::default(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
                floor: Height::zero(),
                fcu_heartbeat_interval: Duration::from_secs(60),
            },
        );
        actor.start();

        let _ = mailbox.report(Update::Tip(round(6), Height::new(101), digest(101)));
        context.sleep(Duration::from_millis(5)).await;
        assert!(provider.forkchoices().is_empty());

        let newer = digest(102);
        let _ = mailbox.report(Update::Tip(round(8), Height::new(102), newer));
        wait_until(&context, || !provider.forkchoices().is_empty()).await;
        assert_eq!(provider.forkchoices()[0].head_block_hash, newer.0);
    });
}

#[test_traced]
fn tip_supersedes_roundless_prefork_execution_tip() {
    deterministic::Runner::default().start(|context| async move {
        let provider = StubExecutionProvider::default();
        provider.set_prefork_finalized(100, digest(100).0);

        let (actor, mut mailbox) = init(
            context.child("follower_executor"),
            Config {
                execution_provider: provider.clone(),
                execution_engine: provider.clone(),
                marshal: StubMarshal::default(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
                floor: Height::zero(),
                fcu_heartbeat_interval: Duration::from_secs(60),
            },
        );
        actor.start();

        context.sleep(Duration::from_millis(1)).await;
        assert!(provider.forkchoices().is_empty());

        let finalized = digest(101);
        let _ = mailbox.report(Update::Tip(round(1), Height::new(101), finalized));
        wait_until(&context, || !provider.forkchoices().is_empty()).await;
        assert_eq!(provider.forkchoices()[0].head_block_hash, finalized.0);
    });
}

#[test_traced]
fn tip_is_driven_to_from_genesis() {
    deterministic::Runner::default().start(|context| async move {
        let provider = StubExecutionProvider::default();

        let (actor, mut mailbox) = init(
            context.child("follower_executor"),
            Config {
                execution_provider: provider.clone(),
                execution_engine: provider.clone(),
                marshal: StubMarshal::default(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
                floor: Height::zero(),
                fcu_heartbeat_interval: Duration::from_secs(60),
            },
        );
        actor.start();

        let finalized = Digest(B256::with_last_byte(9));
        let _ = mailbox.report(Update::Tip(round(5), Height::new(9), finalized));

        wait_until(&context, || !provider.forkchoices().is_empty()).await;
        let forkchoices = provider.forkchoices();
        assert_eq!(forkchoices.len(), 1);
        assert_eq!(
            forkchoices[0].head_block_hash, finalized.0,
            "nothing is below genesis, so the tip is driven directly",
        );
    });
}

#[test_traced]
fn heartbeat_resubmits_latest_tip_after_interval() {
    deterministic::Runner::default().start(|context| async move {
        let provider = StubExecutionProvider::default();

        let (actor, mut mailbox) = init(
            context.child("follower_executor"),
            Config {
                execution_provider: provider.clone(),
                execution_engine: provider.clone(),
                marshal: StubMarshal::default(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
                floor: Height::zero(),
                fcu_heartbeat_interval: HEARTBEAT_INTERVAL,
            },
        );

        actor.start();

        let digest = Digest(B256::with_last_byte(1));
        let tip = Update::Tip(Round::zero(), Height::new(1), digest);
        assert!(mailbox.report(tip).accepted());
        wait_until(&context, || provider.forkchoices().len() == 1).await;

        context.sleep(Duration::from_millis(1)).await;
        assert_eq!(provider.forkchoices().len(), 1);
        wait_until(&context, || provider.forkchoices().len() == 2).await;

        let forkchoices = provider.forkchoices();
        assert_eq!(forkchoices[0], forkchoices[1]);
        assert_eq!(forkchoices[1].head_block_hash, digest.0);
    });
}

#[test_traced]
fn heartbeat_waits_for_in_flight_execution() {
    deterministic::Runner::default().start(|context| async move {
        let provider = StubExecutionProvider::default();
        let release_forkchoice = provider.pause_next_forkchoice();

        let (actor, mut mailbox) = init(
            context.child("follower_executor"),
            Config {
                execution_provider: provider.clone(),
                execution_engine: provider.clone(),
                marshal: StubMarshal::default(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
                floor: Height::zero(),
                fcu_heartbeat_interval: HEARTBEAT_INTERVAL,
            },
        );

        actor.start();

        let digest = Digest(B256::with_last_byte(1));
        let tip = Update::Tip(Round::zero(), Height::new(1), digest);
        assert!(mailbox.report(tip).accepted());
        wait_until(&context, || provider.forkchoices().len() == 1).await;

        context.sleep(HEARTBEAT_INTERVAL * 2).await;
        assert_eq!(provider.forkchoices().len(), 1);

        release_forkchoice
            .send(())
            .expect("the in-flight FCU should still be waiting");

        context.sleep(Duration::from_millis(1)).await;
        assert_eq!(provider.forkchoices().len(), 1);

        wait_until(&context, || provider.forkchoices().len() == 2).await;
    });
}

#[test_traced]
fn durable_block_read_failure_does_not_exit_actor() {
    deterministic::Runner::default().start(|context| async move {
        let finalized_height = EPOCH_LENGTH.get() * 2;
        let provider = StubExecutionProvider::default();
        provider.set_finalized(finalized_height, B256::with_last_byte(20), Round::zero());
        provider.fail_durable_reads();
        let marshal = StubMarshal::default();

        let (actor, mut mailbox) = init(
            context.child("follower_executor"),
            Config {
                execution_provider: provider.clone(),
                execution_engine: provider.clone(),
                marshal: marshal.clone(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
                floor: Height::zero(),
                fcu_heartbeat_interval: Duration::from_secs(60),
            },
        );

        actor.start();

        for (block_height, block_round) in [
            (finalized_height + 1, round(1)),
            (finalized_height + 2, round(2)),
        ] {
            let block = make_block_at_round(block_height, B256::with_last_byte(20), block_round);
            let (ack, waiter) = Exact::handle();
            assert!(mailbox.report(Update::Block(block.into(), ack)).accepted());

            waiter
                .await
                .expect("durability read errors must not stop block execution");

            context.sleep(Duration::from_millis(1)).await;
        }

        assert_eq!(provider.payload_count(), 2);
        assert_eq!(provider.forkchoices().len(), 2);
        assert_eq!(marshal.floor(), Height::zero());
    });
}

#[test_traced]
fn startup_uses_execution_finalized_tip_without_immediate_forkchoice() {
    deterministic::Runner::default().start(|context| async move {
        let provider = StubExecutionProvider::default();
        let finalized_hash = B256::with_last_byte(10);
        provider.set_finalized(EPOCH_LENGTH.get(), finalized_hash, round(10));

        let (actor, _mailbox) = init(
            context.child("follower_executor"),
            Config {
                execution_provider: provider.clone(),
                execution_engine: provider.clone(),
                marshal: StubMarshal::default(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
                floor: Height::zero(),
                fcu_heartbeat_interval: HEARTBEAT_INTERVAL,
            },
        );

        actor.start();

        context.sleep(Duration::from_millis(1)).await;
        assert!(provider.forkchoices().is_empty());
        wait_until(&context, || !provider.forkchoices().is_empty()).await;

        let forkchoice = provider.forkchoices()[0];
        assert_eq!(forkchoice.head_block_hash, finalized_hash);
        assert_eq!(forkchoice.safe_block_hash, finalized_hash);
        assert_eq!(forkchoice.finalized_block_hash, finalized_hash);
    });
}

#[test_traced]
fn snapshot_catch_up_canonicalizes_blocks_below_syncing_tip() {
    deterministic::Runner::default().start(|context| async move {
        let provider = StubExecutionProvider::default();
        let snapshot = digest(100);
        provider.set_finalized(100, snapshot.0, round(10));
        provider.sync_unknown_forkchoices();

        let first = make_block_at_round(101, snapshot.0, round(11));
        let second = make_block_at_round(102, first.digest().0, round(12));
        let third = make_block_at_round(103, second.digest().0, round(13));
        let tip = third.digest();

        let (actor, mut mailbox) = init(
            context.child("follower_executor"),
            Config {
                execution_provider: provider.clone(),
                execution_engine: provider.clone(),
                marshal: StubMarshal::default(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
                floor: Height::zero(),
                fcu_heartbeat_interval: HEARTBEAT_INTERVAL,
            },
        );
        actor.start();

        assert!(
            mailbox
                .report(Update::Tip(round(13), Height::new(103), tip))
                .accepted()
        );
        wait_until(&context, || provider.forkchoices().len() == 1).await;
        context.sleep(Duration::from_millis(1)).await;
        assert_eq!(
            provider.forkchoices().len(),
            1,
            "SYNCING must not cause a retry loop"
        );
        assert_eq!(provider.finalized_header().unwrap().hash(), snapshot.0);

        for block in [first.clone(), second] {
            let hash = block.digest().0;
            let (ack, waiter) = Exact::handle();
            assert!(mailbox.report(Update::Block(block.into(), ack)).accepted());
            waiter.await.expect("catch-up block should be acknowledged");
            assert_eq!(provider.finalized_header().unwrap().hash(), hash);
        }

        // Catch-up must not replace the newer requested tip with an older block.
        wait_until(&context, || provider.forkchoices().len() == 4).await;
        assert_eq!(provider.forkchoices()[3].head_block_hash, tip.0);
        assert_eq!(provider.finalized_header().unwrap().inner.number, 102);

        let (ack, waiter) = Exact::handle();
        assert!(mailbox.report(Update::Block(third.into(), ack)).accepted());
        waiter
            .await
            .expect("latest tip should become canonical once executed");
        assert_eq!(provider.finalized_header().unwrap().hash(), tip.0);

        let count = provider.forkchoices().len();
        let (ack, waiter) = Exact::handle();
        assert!(mailbox.report(Update::Block(first.into(), ack)).accepted());
        waiter
            .await
            .expect("already canonicalized block should be acknowledged");
        assert_eq!(
            provider.forkchoices().len(),
            count,
            "accepted forkchoice must not regress"
        );
        assert_eq!(provider.finalized_header().unwrap().hash(), tip.0);

        wait_until(&context, || provider.forkchoices().len() > count).await;
        assert_eq!(
            provider.forkchoices().last().unwrap().head_block_hash,
            tip.0
        );
    });
}

#[test_traced]
fn syncing_block_forkchoice_does_not_skip_older_catch_up_block() {
    deterministic::Runner::default().start(|context| async move {
        let provider = StubExecutionProvider::default();
        let snapshot = digest(100);
        provider.set_finalized(100, snapshot.0, round(10));
        provider.sync_unknown_forkchoices();
        provider.sync_next_forkchoice();

        let first = make_block_at_round(101, snapshot.0, round(11));
        let second = make_block_at_round(102, first.digest().0, round(12));
        let second_hash = second.digest().0;
        let (actor, mut mailbox) = init(
            context.child("follower_executor"),
            Config {
                execution_provider: provider.clone(),
                execution_engine: provider.clone(),
                marshal: StubMarshal::default(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
                floor: Height::zero(),
                fcu_heartbeat_interval: Duration::from_secs(60),
            },
        );
        actor.start();

        // The first block request itself returns SYNCING, as during gap repair.
        let (ack, waiter) = Exact::handle();
        assert!(
            mailbox
                .report(Update::Block(second.clone().into(), ack))
                .accepted()
        );
        waiter
            .await
            .expect("SYNCING forkchoice should not exit the actor");
        assert_eq!(provider.finalized_header().unwrap().hash(), snapshot.0);

        let first_hash = first.digest().0;
        let (ack, waiter) = Exact::handle();
        assert!(mailbox.report(Update::Block(first.into(), ack)).accepted());
        waiter
            .await
            .expect("older catch-up block should be canonicalized");
        assert_eq!(provider.finalized_header().unwrap().hash(), first_hash);

        // A repeated block at the requested round must still advance accepted state.
        let (ack, waiter) = Exact::handle();
        assert!(mailbox.report(Update::Block(second.into(), ack)).accepted());
        waiter
            .await
            .expect("previously syncing block should now be canonicalized");
        assert_eq!(provider.finalized_header().unwrap().hash(), second_hash);
        assert_eq!(provider.forkchoices().len(), 3);
    });
}

#[test_traced]
fn pipeline_completion_does_not_regress_finalized_forkchoice() {
    deterministic::Runner::default().start(|context| async move {
        let provider = StubExecutionProvider::default();
        let snapshot = digest(100);
        let finalized = digest(103);
        provider.set_finalized(100, snapshot.0, round(10));
        provider.sync_unknown_forkchoices();

        let (actor, mut mailbox) = init(
            context.child("follower_executor"),
            Config {
                execution_provider: provider.clone(),
                execution_engine: provider.clone(),
                marshal: StubMarshal::default(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
                floor: Height::zero(),
                fcu_heartbeat_interval: HEARTBEAT_INTERVAL,
            },
        );
        actor.start();

        assert!(
            mailbox
                .report(Update::Tip(round(13), Height::new(103), finalized))
                .accepted()
        );
        wait_until(&context, || provider.forkchoices().len() == 1).await;
        context.sleep(Duration::from_millis(1)).await;

        // Reth finishes syncing the requested tip without returning VALID to the actor.
        provider.set_finalized(103, finalized.0, round(13));
        let block = make_block_at_round(101, snapshot.0, round(11));
        let (ack, waiter) = Exact::handle();
        assert!(mailbox.report(Update::Block(block.into(), ack)).accepted());
        waiter
            .await
            .expect("already finalized history should be acknowledged");
        assert_eq!(
            provider.forkchoices().len(),
            1,
            "catch-up must not reorg below Reth finality"
        );
        assert_eq!(provider.finalized_header().unwrap().hash(), finalized.0);

        wait_until(&context, || provider.forkchoices().len() == 2).await;
        assert_eq!(provider.forkchoices()[1].head_block_hash, finalized.0);
    });
}

#[test_traced]
fn too_deep_reorg_is_tolerated_only_when_pipeline_advanced_finality() {
    for advanced in [false, true] {
        deterministic::Runner::default().start(|context| async move {
            let provider = StubExecutionProvider::default();
            let snapshot = digest(100);
            provider.set_finalized(100, snapshot.0, round(10));
            let finalized = if advanced { digest(103) } else { snapshot };
            let height = if advanced { 103 } else { 100 };
            let finalized_round = if advanced { round(13) } else { round(10) };
            provider.finalize_during_next_forkchoice(height, finalized.0, finalized_round);

            let (actor, mut mailbox) = init(
                context.child("follower_executor"),
                Config {
                    execution_provider: provider.clone(),
                    execution_engine: provider.clone(),
                    marshal: StubMarshal::default(),
                    epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
                    floor: Height::zero(),
                    fcu_heartbeat_interval: Duration::from_secs(60),
                },
            );
            let handle = actor.start();

            let block = make_block_at_round(101, snapshot.0, round(11));
            let (ack, waiter) = Exact::handle();
            assert!(mailbox.report(Update::Block(block.into(), ack)).accepted());
            assert_eq!(waiter.await.is_ok(), advanced);
            assert_eq!(provider.finalized_header().unwrap().hash(), finalized.0);

            if advanced {
                let block = make_block_at_round(102, snapshot.0, round(12));
                let (ack, waiter) = Exact::handle();
                assert!(mailbox.report(Update::Block(block.into(), ack)).accepted());
                waiter
                    .await
                    .expect("actor should keep acknowledging finalized history");
            } else {
                handle
                    .await
                    .expect("unconfirmed deep reorg should stop the actor");
            }
            assert_eq!(provider.forkchoices().len(), 1);
        });
    }
}
