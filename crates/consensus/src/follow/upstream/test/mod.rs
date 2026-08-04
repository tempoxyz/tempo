//! Standalone websocket upstream actor tests.

mod utils;

use std::time::Duration;

use alloy_primitives::B256;
use commonware_macros::test_traced;
use commonware_runtime::{Clock as _, Runner as _, Spawner as _, Supervisor as _, deterministic};
use tempo_node::rpc::consensus::Event;

use super::actor;
use crate::consensus::Digest;
use utils::{StubClient, StubConnector, StubReporter};

const WAIT_ATTEMPTS: usize = 100;

fn no_jitter() -> Duration {
    Duration::ZERO
}

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
fn forwards_subscription_events_to_reporter() {
    deterministic::Runner::default().start(|context| async move {
        let client = StubClient::connected();
        client.queue_event(Event::Nullified {
            epoch: 3,
            view: 7,
            seen: 11,
        });
        let connector = StubConnector::new(client.clone());
        let reporter = StubReporter::default();
        let (actor, _mailbox) = actor::init(context.child("upstream"), connector, no_jitter);

        actor.start(reporter.clone());
        wait_until(&context, || client.subscriptions() == 1).await;
        wait_until(&context, || reporter.events().len() == 1).await;

        assert!(matches!(
            reporter.events().as_slice(),
            [Event::Nullified {
                epoch: 3,
                view: 7,
                seen: 11
            }]
        ));
    });
}

#[test_traced]
fn queues_requests_until_subscription_is_ready() {
    deterministic::Runner::default().start(|context| async move {
        let client = StubClient::connected();
        let release_subscription = client.queue_paused_subscription();
        let connector = StubConnector::new(client.clone());
        let (actor, mailbox) = actor::init(context.child("upstream"), connector, no_jitter);
        actor.start(StubReporter::default());

        let (response, received) = tokio::sync::oneshot::channel();
        context.child("request").spawn(move |_| async move {
            let block = mailbox.get_block(Digest(B256::with_last_byte(1))).await;
            let _ = response.send(block);
        });

        wait_until(&context, || client.subscriptions() == 1).await;
        assert_eq!(client.block_reads(), 0);

        release_subscription
            .send(())
            .expect("subscription should still be pending");
        assert!(
            received
                .await
                .expect("request task should respond")
                .is_none()
        );
        assert_eq!(client.block_reads(), 1);
    });
}

#[test_traced]
fn failed_connection_retries_after_backoff() {
    deterministic::Runner::default().start(|context| async move {
        let client = StubClient::connected();
        client.queue_subscription();
        let connector = StubConnector::new(client.clone());
        connector.fail_connections(1);
        let (actor, _mailbox) =
            actor::init(context.child("upstream"), connector.clone(), no_jitter);
        actor.start(StubReporter::default());

        wait_until(&context, || connector.attempts() == vec![1]).await;

        context.sleep(actor::reconnect_backoff(1)).await;
        wait_until(&context, || client.subscriptions() == 1).await;

        assert_eq!(connector.attempts(), vec![1, 2]);
    });
}

#[test_traced]
fn subscription_failure_reconnects_and_subscribes_again() {
    deterministic::Runner::default().start(|context| async move {
        let client = StubClient::connected();
        client.queue_subscription_error();
        client.queue_subscription();
        let connector = StubConnector::new(client.clone());
        let (actor, _mailbox) =
            actor::init(context.child("upstream"), connector.clone(), no_jitter);
        actor.start(StubReporter::default());

        wait_until(&context, || client.subscriptions() == 2).await;

        assert_eq!(connector.attempts(), vec![1, 1]);
    });
}

#[test_traced]
fn terminated_event_stream_is_resubscribed() {
    deterministic::Runner::default().start(|context| async move {
        let client = StubClient::connected();
        client.queue_terminated_subscription();
        client.queue_event(Event::Nullified {
            epoch: 1,
            view: 2,
            seen: 3,
        });
        let connector = StubConnector::new(client.clone());
        let reporter = StubReporter::default();
        let (actor, _mailbox) =
            actor::init(context.child("upstream"), connector.clone(), no_jitter);
        actor.start(reporter.clone());

        wait_until(&context, || client.subscriptions() == 2).await;
        wait_until(&context, || reporter.events().len() == 1).await;

        assert_eq!(connector.attempts(), vec![1]);
    });
}

#[test_traced]
fn event_stream_error_resubscribes_without_reconnecting() {
    deterministic::Runner::default().start(|context| async move {
        let client = StubClient::connected();
        client.queue_event_stream_error();
        client.queue_subscription();
        let connector = StubConnector::new(client.clone());
        let (actor, _mailbox) =
            actor::init(context.child("upstream"), connector.clone(), no_jitter);
        actor.start(StubReporter::default());

        wait_until(&context, || client.subscriptions() == 2).await;

        assert_eq!(connector.attempts(), vec![1]);
    });
}

#[test_traced]
fn disconnected_client_reconnects_before_resubscribing() {
    deterministic::Runner::default().start(|context| async move {
        let disconnected_client = StubClient::connected();
        let terminate_stream = disconnected_client.queue_gated_termination();
        let replacement_client = StubClient::connected();
        replacement_client.queue_subscription();

        let connector = StubConnector::new(disconnected_client.clone());
        connector.replace_client_on_reconnect(replacement_client.clone());
        let (actor, _mailbox) =
            actor::init(context.child("upstream"), connector.clone(), no_jitter);
        actor.start(StubReporter::default());

        wait_until(&context, || disconnected_client.subscriptions() == 1).await;
        disconnected_client.set_connected(false);
        terminate_stream
            .send(())
            .expect("event stream should still be active");
        wait_until(&context, || replacement_client.subscriptions() == 1).await;

        assert_eq!(connector.attempts(), vec![1, 1]);
    });
}
