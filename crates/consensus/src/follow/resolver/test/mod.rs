//! Standalone follower resolver actor tests.

mod utils;

use std::time::Duration;

use alloy_primitives::B256;
use commonware_codec::Encode as _;
use commonware_consensus::{
    marshal::resolver::handler,
    types::{Epoch, Height, Round, View},
};
use commonware_macros::test_traced;
use commonware_resolver::Resolver as _;
use commonware_runtime::{Clock as _, Metrics as _, Runner as _, deterministic};
use commonware_utils::channel::mpsc;

use super::{Config, actor, try_init};
use crate::consensus::Digest;
use utils::{StubBlockProvider, StubUpstream, make_block, make_certified_block};

const WAIT_ATTEMPTS: usize = 100;
const MAILBOX_SIZE: usize = 16;

async fn wait_until<T: commonware_runtime::Clock>(context: &T, mut cond: impl FnMut() -> bool) {
    for _ in 0..WAIT_ATTEMPTS {
        if cond() {
            return;
        }
        context.sleep(Duration::from_millis(1)).await;
    }

    assert!(cond(), "condition was not met before the test deadline");
}

async fn receive_delivery(
    receiver: &mut mpsc::Receiver<handler::Message<Digest>>,
) -> eyre::Result<(handler::Request<Digest>, bytes::Bytes)> {
    let message = receiver
        .recv()
        .await
        .ok_or_else(|| eyre::eyre!("resolver stopped before delivering a value"))?;

    match message {
        handler::Message::Deliver { key, value, .. } => Ok((key, value)),
        handler::Message::Produce { .. } => {
            Err(eyre::eyre!("resolver unexpectedly requested a value"))
        }
    }
}

#[test_traced]
fn local_block_is_delivered_without_upstream_lookup() {
    deterministic::Runner::default()
        .start(|context| async move {
            let block = make_block(1);
            let key = handler::Request::Block(block.digest());
            let provider = StubBlockProvider::default();
            provider.add_block(&block);

            let upstream = StubUpstream::default();
            let (actor, mut mailbox, mut receiver) = try_init(
                context.with_label("resolver"),
                Config {
                    execution_provider: provider.clone(),
                    upstream: upstream.clone(),
                    mailbox_size: MAILBOX_SIZE,
                },
            );

            actor.start();

            mailbox.fetch(key.clone()).await;
            let (delivered_key, value) = receive_delivery(&mut receiver).await?;

            assert_eq!(delivered_key, key);
            assert_eq!(value, block.encode());
            assert_eq!(provider.reads(), 1);
            assert_eq!(upstream.block_reads(), 0);
            Ok::<(), eyre::Report>(())
        })
        .expect("resolver test should succeed");
}

#[test_traced]
fn local_miss_falls_back_to_upstream_block() {
    deterministic::Runner::default()
        .start(|context| async move {
            let block = make_block(1);
            let key = handler::Request::Block(block.digest());
            let provider = StubBlockProvider::default();
            let upstream = StubUpstream::default();
            upstream.add_block(block.clone());

            let (actor, mut mailbox, mut receiver) = try_init(
                context.with_label("resolver"),
                Config {
                    execution_provider: provider.clone(),
                    upstream: upstream.clone(),
                    mailbox_size: MAILBOX_SIZE,
                },
            );

            actor.start();

            mailbox.fetch(key.clone()).await;
            let (delivered_key, value) = receive_delivery(&mut receiver).await?;

            assert_eq!(delivered_key, key);
            assert_eq!(value, block.encode());
            assert_eq!(provider.reads(), 1);
            assert_eq!(upstream.block_reads(), 1);
            Ok::<(), eyre::Report>(())
        })
        .expect("resolver test should succeed");
}

#[test_traced]
fn missing_block_retries_and_eventually_delivers() {
    deterministic::Runner::default()
        .start(|context| async move {
            let block = make_block(1);
            let key = handler::Request::Block(block.digest());
            let provider = StubBlockProvider::default();
            let upstream = StubUpstream::default();
            let (actor, mut mailbox, mut receiver) = try_init(
                context.with_label("resolver"),
                Config {
                    execution_provider: provider.clone(),
                    upstream: upstream.clone(),
                    mailbox_size: MAILBOX_SIZE,
                },
            );

            actor.start();

            mailbox.fetch(key.clone()).await;
            wait_until(&context, || upstream.block_reads() == 1).await;

            upstream.add_block(block.clone());
            context.sleep(actor::retry_delay(1)).await;

            let (delivered_key, value) = receive_delivery(&mut receiver).await?;

            assert_eq!(delivered_key, key);
            assert_eq!(value, block.encode());
            assert_eq!(provider.reads(), 2);
            assert_eq!(upstream.block_reads(), 2);
            Ok::<(), eyre::Report>(())
        })
        .expect("resolver test should succeed");
}

#[test_traced]
fn duplicate_block_fetch_is_coalesced() {
    deterministic::Runner::default()
        .start(|context| async move {
            let block = make_block(1);
            let key = handler::Request::Block(block.digest());
            let provider = StubBlockProvider::default();
            let upstream = StubUpstream::default();
            upstream.add_block(block.clone());

            let release = upstream.pause_next_block_read();
            let (actor, mut mailbox, mut receiver) = try_init(
                context.with_label("resolver"),
                Config {
                    execution_provider: provider.clone(),
                    upstream: upstream.clone(),
                    mailbox_size: MAILBOX_SIZE,
                },
            );

            actor.start();

            mailbox.fetch(key.clone()).await;
            wait_until(&context, || upstream.block_reads() == 1).await;

            mailbox.fetch(key.clone()).await;
            context.sleep(Duration::from_millis(1)).await;

            assert_eq!(provider.reads(), 1);
            assert_eq!(upstream.block_reads(), 1);

            release
                .send(())
                .expect("block read should still be in flight");

            let (delivered_key, value) = receive_delivery(&mut receiver).await?;
            assert_eq!(delivered_key, key);
            assert_eq!(value, block.encode());

            Ok::<(), eyre::Report>(())
        })
        .expect("resolver test should succeed");
}

#[test_traced]
fn cancel_aborts_in_flight_block_fetch() {
    deterministic::Runner::default().start(|context| async move {
        let block = make_block(1);
        let key = handler::Request::Block(block.digest());
        let provider = StubBlockProvider::default();
        let upstream = StubUpstream::default();
        upstream.add_block(block);
        let _release = upstream.pause_next_block_read();
        let (actor, mut mailbox, _receiver) = try_init(
            context.with_label("resolver"),
            Config {
                execution_provider: provider,
                upstream: upstream.clone(),
                mailbox_size: MAILBOX_SIZE,
            },
        );

        actor.start();

        mailbox.fetch(key.clone()).await;
        wait_until(&context, || upstream.block_reads() == 1).await;

        mailbox.cancel(key.clone()).await;
        context.sleep(Duration::from_millis(1)).await;

        mailbox.fetch(key).await;
        wait_until(&context, || upstream.block_reads() == 2).await;
    });
}

#[test_traced]
fn local_read_error_retries_without_querying_upstream() {
    deterministic::Runner::default().start(|context| async move {
        let key = handler::Request::Block(Digest(B256::with_last_byte(1)));
        let provider = StubBlockProvider::default();
        provider.fail_reads();

        let upstream = StubUpstream::default();
        let (actor, mut mailbox, _receiver) = try_init(
            context.with_label("resolver"),
            Config {
                execution_provider: provider.clone(),
                upstream: upstream.clone(),
                mailbox_size: MAILBOX_SIZE,
            },
        );

        actor.start();

        mailbox.fetch(key).await;
        wait_until(&context, || provider.reads() == 1).await;

        context.sleep(actor::retry_delay(1)).await;
        wait_until(&context, || provider.reads() == 2).await;

        assert_eq!(upstream.block_reads(), 0);
    });
}

#[test_traced]
fn finalized_request_delivers_certificate_and_block() {
    deterministic::Runner::default()
        .start(|context| async move {
            let height = Height::new(1);
            let key = handler::Request::Finalized { height };
            let (certified, expected) = make_certified_block(height);
            let provider = StubBlockProvider::default();
            let upstream = StubUpstream::default();
            upstream.add_finalization(height, certified);

            let (actor, mut mailbox, mut receiver) = try_init(
                context.with_label("resolver"),
                Config {
                    execution_provider: provider.clone(),
                    upstream: upstream.clone(),
                    mailbox_size: MAILBOX_SIZE,
                },
            );

            actor.start();

            mailbox.fetch(key.clone()).await;
            let (delivered_key, value) = receive_delivery(&mut receiver).await?;

            assert_eq!(delivered_key, key);
            assert_eq!(value, expected);
            assert_eq!(provider.reads(), 0);
            assert_eq!(upstream.finalization_reads(), 1);
            Ok::<(), eyre::Report>(())
        })
        .expect("resolver test should succeed");
}

#[test_traced]
fn missing_finalization_retries_and_eventually_delivers() {
    deterministic::Runner::default()
        .start(|context| async move {
            let height = Height::new(1);
            let key = handler::Request::Finalized { height };
            let (certified, expected) = make_certified_block(height);
            let provider = StubBlockProvider::default();
            let upstream = StubUpstream::default();
            let (actor, mut mailbox, mut receiver) = try_init(
                context.with_label("resolver"),
                Config {
                    execution_provider: provider,
                    upstream: upstream.clone(),
                    mailbox_size: MAILBOX_SIZE,
                },
            );

            actor.start();

            mailbox.fetch(key.clone()).await;
            wait_until(&context, || upstream.finalization_reads() == 1).await;
            upstream.add_finalization(height, certified);
            context.sleep(actor::retry_delay(1)).await;
            let (delivered_key, value) = receive_delivery(&mut receiver).await?;

            assert_eq!(delivered_key, key);
            assert_eq!(value, expected);
            assert_eq!(upstream.finalization_reads(), 2);
            Ok::<(), eyre::Report>(())
        })
        .expect("resolver test should succeed");
}

#[test_traced]
fn malformed_finalization_is_not_retried() {
    deterministic::Runner::default().start(|context| async move {
        let height = Height::new(1);
        let key = handler::Request::Finalized { height };

        let (mut certified, _) = make_certified_block(height);
        certified.certificate = "not hex".into();

        let upstream = StubUpstream::default();
        upstream.add_finalization(height, certified);

        let (actor, mut mailbox, mut receiver) = try_init(
            context.with_label("resolver"),
            Config {
                execution_provider: StubBlockProvider::default(),
                upstream: upstream.clone(),
                mailbox_size: MAILBOX_SIZE,
            },
        );

        actor.start();

        mailbox.fetch(key).await;
        wait_until(&context, || upstream.finalization_reads() == 1).await;
        context
            .sleep(actor::retry_delay(1) + Duration::from_millis(1))
            .await;

        assert_eq!(upstream.finalization_reads(), 1);
        assert!(receiver.try_recv().is_err());
    });
}

#[test_traced]
fn notarized_request_is_ignored() {
    deterministic::Runner::default().start(|context| async move {
        let provider = StubBlockProvider::default();
        let upstream = StubUpstream::default();
        let (actor, mut mailbox, mut receiver) = try_init(
            context.with_label("resolver"),
            Config {
                execution_provider: provider.clone(),
                upstream: upstream.clone(),
                mailbox_size: MAILBOX_SIZE,
            },
        );

        actor.start();

        let round = Round::new(Epoch::zero(), View::new(1));
        mailbox.fetch(handler::Request::Notarized { round }).await;
        context.sleep(Duration::from_millis(1)).await;

        assert_eq!(provider.reads(), 0);
        assert_eq!(upstream.block_reads(), 0);
        assert_eq!(upstream.finalization_reads(), 0);
        assert!(receiver.try_recv().is_err());
    });
}

#[test]
fn retry_delay_grows_exponentially_and_caps() {
    assert_eq!(actor::retry_delay(0), Duration::ZERO);
    assert_eq!(actor::retry_delay(1), Duration::from_millis(250));
    assert_eq!(actor::retry_delay(2), Duration::from_millis(500));
    assert_eq!(actor::retry_delay(3), Duration::from_secs(1));
    assert_eq!(actor::retry_delay(7), Duration::from_secs(16));
    assert_eq!(actor::retry_delay(8), actor::MAX_RETRY_DELAY);
    assert_eq!(actor::retry_delay(u32::MAX), actor::MAX_RETRY_DELAY);
}
