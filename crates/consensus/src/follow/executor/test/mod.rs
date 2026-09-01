//! Standalone follower executor actor tests.

mod utils;

use std::{num::NonZeroU64, time::Duration};

use alloy_primitives::B256;
use alloy_rpc_types_engine::ForkchoiceState;
use commonware_consensus::{
    Reporter as _,
    marshal::Update,
    types::{Epoch, FixedEpocher, Height, Round, View},
};
use commonware_macros::test_traced;
use commonware_runtime::{Clock as _, Runner as _, Supervisor as _, deterministic};
use commonware_utils::{Acknowledgement as _, acknowledgement::Exact};

use super::{Config, init};
use crate::consensus::Digest;
use utils::{
    StubExecutionProvider, StubMarshal, make_block, make_block_at_round, make_roundless_block,
};

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

fn forkchoice(head: B256, finalized: B256) -> ForkchoiceState {
    ForkchoiceState {
        head_block_hash: head,
        safe_block_hash: finalized,
        finalized_block_hash: finalized,
    }
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
        let block_hash = block.block_hash();
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
fn syncing_block_is_requeued_ahead_of_later_blocks() {
    deterministic::Runner::default().start(|context| async move {
        let provider = StubExecutionProvider::default();
        provider.sync_payloads(1);
        provider.sync_forkchoices(1);

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

        let first = make_block_at_round(1, B256::ZERO, round(1));
        let first_hash = first.block_hash();
        let second = make_block_at_round(2, first_hash, round(2));
        let second_hash = second.block_hash();
        let (first_ack, first_waiter) = Exact::handle();
        let (second_ack, second_waiter) = Exact::handle();
        assert!(
            mailbox
                .report(Update::Block(first.into(), first_ack))
                .accepted()
        );
        assert!(
            mailbox
                .report(Update::Block(second.into(), second_ack))
                .accepted()
        );

        context.sleep(Duration::from_secs(1)).await;
        first_waiter
            .await
            .expect("postponed block should be acknowledged");
        second_waiter
            .await
            .expect("later block should be acknowledged");

        assert_eq!(provider.payload_count(), 4);
        let forkchoices = provider.forkchoices();
        assert_eq!(forkchoices[0].head_block_hash, first_hash);
        assert_eq!(forkchoices[1].head_block_hash, first_hash);
        assert_eq!(forkchoices[2].head_block_hash, second_hash);
    });
}

#[test_traced]
fn block_queue_preserves_the_sync_target_before_sending_the_latest_head() {
    deterministic::Runner::default().start(|context| async move {
        let provider = StubExecutionProvider::default();
        provider.sync_forkchoices(1);

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

        let first_head = digest(2);
        mailbox.finalization(round(2), first_head);
        wait_until(&context, || provider.forkchoices().len() == 1).await;
        context.sleep(Duration::from_millis(21)).await;

        let block = make_block_at_round(1, B256::ZERO, round(1));
        let block_hash = block.block_hash();
        let (ack, waiter) = Exact::handle();
        assert!(mailbox.report(Update::Block(block.into(), ack)).accepted());

        let latest_head = digest(3);
        mailbox.finalization(round(3), latest_head);

        waiter.await.expect("queued block should be acknowledged");
        wait_until(&context, || provider.forkchoices().len() == 3).await;

        assert_eq!(
            provider.forkchoices(),
            vec![
                forkchoice(first_head.0, B256::ZERO),
                forkchoice(first_head.0, block_hash),
                forkchoice(latest_head.0, block_hash),
            ]
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

        let block = make_block_at_round(finalized_height - 1, B256::with_last_byte(10), round(1));
        let (ack, waiter) = Exact::handle();
        assert!(mailbox.report(Update::Block(block.into(), ack)).accepted());
        waiter.await.expect("valid payload should be acknowledged");

        assert_eq!(provider.payload_count(), 1);
        assert!(provider.forkchoices().is_empty());
    });
}

#[test_traced]
fn roundless_block_advances_finality_by_height() {
    deterministic::Runner::default().start(|context| async move {
        let current = B256::with_last_byte(100);
        let provider = StubExecutionProvider::default();
        provider.set_prefork_finalized(100, current);

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

        let block = make_roundless_block(101, current);
        let block_hash = block.block_hash();
        let (ack, waiter) = Exact::handle();
        assert!(mailbox.report(Update::Block(block.into(), ack)).accepted());
        waiter
            .await
            .expect("valid roundless block should be acknowledged");

        assert_eq!(provider.payload_count(), 1);
        assert_eq!(
            provider.forkchoices(),
            vec![forkchoice(block_hash, block_hash)]
        );
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
        assert_eq!(forkchoices[0], forkchoice(first_digest.0, B256::ZERO));
        assert_eq!(forkchoices[1], forkchoice(highest_digest.0, B256::ZERO));
    });
}

// A finalization can advance forkchoice before execution receives its block.
#[test_traced]
fn finalization_drives_forkchoice_by_round() {
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

        let block = make_block_at_round(1, B256::ZERO, round(2));
        let block_digest = Digest(block.block_hash());
        mailbox.finalization(round(2), block_digest);
        wait_until(&context, || provider.forkchoices().len() == 1).await;

        let forkchoices = provider.forkchoices();
        assert_eq!(forkchoices.len(), 1);
        assert_eq!(forkchoices[0], forkchoice(block_digest.0, B256::ZERO));

        let (ack, waiter) = Exact::handle();
        assert!(mailbox.report(Update::Block(block.into(), ack)).accepted());
        waiter.await.expect("durable block should be acknowledged");

        let forkchoices = provider.forkchoices();
        assert_eq!(forkchoices[1], forkchoice(block_digest.0, block_digest.0));
    });
}

#[test_traced]
fn certificate_head_is_preserved_when_block_advances_finality() {
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

        let future_head = digest(9);
        mailbox.finalization(round(2), future_head);
        wait_until(&context, || provider.forkchoices().len() == 1).await;

        let block = make_block_at_round(1, B256::ZERO, round(1));
        let finalized = block.block_hash();
        let (ack, waiter) = Exact::handle();
        assert!(mailbox.report(Update::Block(block.into(), ack)).accepted());
        waiter
            .await
            .expect("known certificate head should finalize the delivered block");

        assert_eq!(
            provider.forkchoices(),
            vec![
                forkchoice(future_head.0, B256::ZERO),
                forkchoice(future_head.0, finalized),
            ]
        );
    });
}

/// An older finalization received while a block FCU is in flight must not
/// become the next forkchoice target.
#[test_traced]
fn delayed_finalization_does_not_regress_newer_block_forkchoice() {
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
        let newest = Digest(block.block_hash());
        let (ack, waiter) = Exact::handle();
        let _ = mailbox.report(Update::Block(block.into(), ack));
        wait_until(&context, || {
            provider.payload_count() == 1 && provider.forkchoices().len() == 1
        })
        .await;

        let delayed = Digest(B256::with_last_byte(12));
        mailbox.finalization(round(12), delayed);
        context.sleep(Duration::from_millis(1)).await;

        release_block_forkchoice
            .send(())
            .expect("the block FCU should still be waiting");
        waiter.await.expect("valid payload should be acknowledged");
        context.sleep(Duration::from_millis(1)).await;

        let expected = forkchoice(newest.0, newest.0);
        assert_eq!(provider.forkchoices(), vec![expected]);

        wait_until(&context, || provider.forkchoices().len() == 2).await;
        assert_eq!(provider.forkchoices(), vec![expected, expected]);
    });
}

#[test_traced]
fn execution_tip_round_orders_finalizations_after_restart() {
    deterministic::Runner::default().start(|context| async move {
        let provider = StubExecutionProvider::default();
        let current = digest(100);
        provider.set_finalized(100, current.0, round(7));

        let (actor, mailbox) = init(
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

        mailbox.finalization(round(6), digest(101));
        context.sleep(Duration::from_millis(5)).await;
        assert!(provider.forkchoices().is_empty());

        let newer = digest(102);
        mailbox.finalization(round(8), newer);
        wait_until(&context, || !provider.forkchoices().is_empty()).await;
        assert_eq!(provider.forkchoices(), vec![forkchoice(newer.0, current.0)]);
    });
}

#[test_traced]
fn finalization_supersedes_roundless_prefork_execution_tip() {
    deterministic::Runner::default().start(|context| async move {
        let provider = StubExecutionProvider::default();
        let current = digest(100);
        provider.set_prefork_finalized(100, current.0);

        let (actor, mailbox) = init(
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

        let certified_head = digest(101);
        mailbox.finalization(round(1), certified_head);
        wait_until(&context, || !provider.forkchoices().is_empty()).await;
        assert_eq!(
            provider.forkchoices(),
            vec![forkchoice(certified_head.0, current.0)]
        );
    });
}

#[test_traced]
fn finalization_is_driven_to_from_genesis() {
    deterministic::Runner::default().start(|context| async move {
        let provider = StubExecutionProvider::default();

        let (actor, mailbox) = init(
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
        mailbox.finalization(round(5), finalized);

        wait_until(&context, || !provider.forkchoices().is_empty()).await;
        assert_eq!(
            provider.forkchoices(),
            vec![forkchoice(finalized.0, B256::ZERO)]
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
        let tip = Update::Tip(round(1), Height::new(1), digest);
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
fn startup_backfills_when_marshal_floor_is_ahead_of_execution() {
    deterministic::Runner::default().start(|context| async move {
        let provider = StubExecutionProvider::default();
        let marshal = StubMarshal::default();
        let first = make_block_at_round(1, B256::ZERO, round(1));
        let first_hash = first.block_hash();
        let second = make_block_at_round(2, first_hash, round(2));
        let second_hash = second.block_hash();
        marshal.set_block(first);
        marshal.set_block(second);

        let (actor, _mailbox) = init(
            context.child("follower_executor"),
            Config {
                execution_provider: provider.clone(),
                execution_engine: provider.clone(),
                marshal,
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
                floor: Height::new(2),
                fcu_heartbeat_interval: Duration::from_secs(60),
            },
        );
        actor.start();

        wait_until(&context, || provider.forkchoices().len() == 2).await;

        assert_eq!(provider.payload_count(), 2);
        let forkchoices = provider.forkchoices();
        assert_eq!(forkchoices[0].head_block_hash, first_hash);
        assert_eq!(forkchoices[0].finalized_block_hash, first_hash);
        assert_eq!(forkchoices[1].head_block_hash, second_hash);
        assert_eq!(forkchoices[1].finalized_block_hash, second_hash);
    });
}

#[test_traced]
fn startup_backfill_fails_if_payload_is_syncing_after_readiness() {
    deterministic::Runner::default().start(|context| async move {
        let provider = StubExecutionProvider::default();
        provider.sync_payloads(1);
        let marshal = StubMarshal::default();
        let block = make_block_at_round(1, B256::ZERO, round(1));
        marshal.set_block(block);

        let (actor, _mailbox) = init(
            context.child("follower_executor"),
            Config {
                execution_provider: provider.clone(),
                execution_engine: provider.clone(),
                marshal,
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
                floor: Height::new(1),
                fcu_heartbeat_interval: Duration::from_secs(60),
            },
        );
        let actor_handle = actor.start();
        actor_handle
            .await
            .expect("syncing startup payload should make the actor exit cleanly");

        assert_eq!(provider.payload_count(), 1);
        assert!(provider.forkchoices().is_empty());
    });
}

#[test_traced]
fn startup_waits_for_execution_readiness_before_backfill() {
    deterministic::Runner::default().start(|context| async move {
        let provider = StubExecutionProvider::default();
        provider.sync_readiness_probes(1);
        let marshal = StubMarshal::default();
        marshal.set_block(make_block_at_round(1, B256::ZERO, round(1)));

        let (actor, _mailbox) = init(
            context.child("follower_executor"),
            Config {
                execution_provider: provider.clone(),
                execution_engine: provider.clone(),
                marshal,
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
                floor: Height::new(1),
                fcu_heartbeat_interval: Duration::from_secs(60),
            },
        );
        actor.start();

        wait_until(&context, || provider.readiness_probes() == 1).await;
        assert_eq!(provider.payload_count(), 0);

        context.sleep(Duration::from_secs(1)).await;
        wait_until(&context, || provider.payload_count() == 1).await;
        assert_eq!(provider.readiness_probes(), 2);
    });
}

#[test_traced]
fn startup_backfills_when_only_the_floor_block_is_missing() {
    deterministic::Runner::default().start(|context| async move {
        let provider = StubExecutionProvider::default();
        let execution_hash = B256::with_last_byte(1);
        provider.set_finalized(1, execution_hash, round(1));
        let marshal = StubMarshal::default();
        let block = make_block_at_round(2, execution_hash, round(2));
        let block_hash = block.block_hash();
        marshal.set_block(block);

        let (actor, _mailbox) = init(
            context.child("follower_executor"),
            Config {
                execution_provider: provider.clone(),
                execution_engine: provider.clone(),
                marshal,
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
                floor: Height::new(2),
                fcu_heartbeat_interval: Duration::from_secs(60),
            },
        );
        actor.start();

        wait_until(&context, || provider.forkchoices().len() == 1).await;

        assert_eq!(provider.payload_count(), 1);
        assert_eq!(provider.forkchoices()[0].finalized_block_hash, block_hash);
    });
}

#[test_traced]
fn startup_uses_execution_finalized_tip() {
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
        assert_eq!(provider.readiness_probes(), 1);
    });
}
