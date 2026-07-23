//! Standalone follower executor actor tests.

mod utils;

use std::{num::NonZeroU64, time::Duration};

use alloy_primitives::B256;
use commonware_consensus::{
    Reporter as _,
    marshal::Update,
    types::{FixedEpocher, Height, Round},
};
use commonware_macros::test_traced;
use commonware_runtime::{Clock as _, Metrics as _, Runner as _, deterministic};
use commonware_utils::{Acknowledgement as _, acknowledgement::Exact};

use super::{Config, init};
use crate::consensus::Digest;
use utils::{StubExecutionProvider, StubMarshal, make_block};

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

#[test_traced]
fn block_is_executed_canonicalized_acknowledged_and_advances_floor() {
    deterministic::Runner::default().start(|context| async move {
        let finalized_height = EPOCH_LENGTH.get() * 2;
        let expected_floor = finalized_height - EPOCH_LENGTH.get();
        let block_height = finalized_height + 1;
        let provider = StubExecutionProvider::default();
        provider.set_finalized(finalized_height, B256::with_last_byte(20));
        provider.set_durable(expected_floor, B256::with_last_byte(10));

        let marshal = StubMarshal::default();

        let (actor, mut mailbox) = init(
            context.with_label("follower_executor"),
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

        let block = make_block(block_height, B256::with_last_byte(20));
        let block_hash = block.block_hash();
        let (ack, waiter) = Exact::handle();
        mailbox.report(Update::Block(block, ack)).await;
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
fn block_at_or_below_finalized_tip_does_not_regress_forkchoice() {
    deterministic::Runner::default().start(|context| async move {
        let finalized_height = EPOCH_LENGTH.get();
        let provider = StubExecutionProvider::default();
        provider.set_finalized(finalized_height, B256::with_last_byte(20));

        let (actor, mut mailbox) = init(
            context.with_label("follower_executor"),
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
        mailbox.report(Update::Block(block, ack)).await;
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
        provider.set_finalized(finalized_height, B256::with_last_byte(20));

        let marshal = StubMarshal::default();
        let (actor, mut mailbox) = init(
            context.with_label("follower_executor"),
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

        let block = make_block(block_height, B256::with_last_byte(20));
        let (ack, waiter) = Exact::handle();
        mailbox.report(Update::Block(block, ack)).await;
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
            context.with_label("follower_executor"),
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
        mailbox.report(Update::Block(block, ack)).await;

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
            context.with_label("follower_executor"),
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
        mailbox.report(Update::Block(block, ack)).await;

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
            context.with_label("follower_executor"),
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
        let first_tip = Update::Tip(Round::zero(), Height::new(1), first_digest);
        mailbox.report(first_tip).await;
        wait_until(&context, || provider.forkchoices().len() == 1).await;

        let highest_digest = Digest(B256::with_last_byte(4));
        let higher_tip = Update::Tip(
            Round::zero(),
            Height::new(3),
            Digest(B256::with_last_byte(3)),
        );
        mailbox.report(higher_tip).await;

        let lower_tip = Update::Tip(
            Round::zero(),
            Height::new(2),
            Digest(B256::with_last_byte(2)),
        );
        mailbox.report(lower_tip).await;

        let highest_tip = Update::Tip(Round::zero(), Height::new(4), highest_digest);
        mailbox.report(highest_tip).await;

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

#[test_traced]
fn heartbeat_resubmits_latest_tip_after_interval() {
    deterministic::Runner::default().start(|context| async move {
        let provider = StubExecutionProvider::default();

        let (actor, mut mailbox) = init(
            context.with_label("follower_executor"),
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
        mailbox.report(tip).await;
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
            context.with_label("follower_executor"),
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
        mailbox.report(tip).await;
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
        provider.set_finalized(finalized_height, B256::with_last_byte(20));
        provider.fail_durable_reads();
        let marshal = StubMarshal::default();

        let (actor, mut mailbox) = init(
            context.with_label("follower_executor"),
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

        for block_height in [finalized_height + 1, finalized_height + 2] {
            let block = make_block(block_height, B256::with_last_byte(20));
            let (ack, waiter) = Exact::handle();
            mailbox.report(Update::Block(block, ack)).await;

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
        provider.set_finalized(EPOCH_LENGTH.get(), finalized_hash);

        let (actor, _mailbox) = init(
            context.with_label("follower_executor"),
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
