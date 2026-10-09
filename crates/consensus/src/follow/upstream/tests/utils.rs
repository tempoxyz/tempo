use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use commonware_actor::Feedback;
use commonware_consensus::{Reporter, types::Height};
use futures::{FutureExt as _, StreamExt as _, future::BoxFuture, stream};
use parking_lot::Mutex;
use tempo_node::rpc::consensus::{CertifiedBlock, Event};
use tokio::sync::oneshot;
use url::Url;

use super::super::{Connector, EventStream, UpstreamClient};
use crate::consensus::{Block, Digest};

struct SubscriptionPlan {
    gate: Option<oneshot::Receiver<()>>,
    result: eyre::Result<EventStream>,
}

#[derive(Clone)]
pub(super) struct StubConnector {
    inner: Arc<StubConnectorInner>,
}

struct StubConnectorInner {
    endpoint: Url,
    client: StubClient,
    replacement_client: Mutex<Option<StubClient>>,
    failures_remaining: Mutex<usize>,
    attempts: Mutex<Vec<u64>>,
}

impl StubConnector {
    pub(super) fn new(client: StubClient) -> Self {
        Self {
            inner: Arc::new(StubConnectorInner {
                endpoint: Url::parse("ws://upstream.test").expect("valid test URL"),
                client,
                replacement_client: Mutex::new(None),
                failures_remaining: Mutex::new(0),
                attempts: Mutex::new(Vec::new()),
            }),
        }
    }

    pub(super) fn fail_connections(&self, count: usize) {
        *self.inner.failures_remaining.lock() = count;
    }

    pub(super) fn attempts(&self) -> Vec<u64> {
        self.inner.attempts.lock().clone()
    }

    pub(super) fn replace_client_on_reconnect(&self, client: StubClient) {
        self.inner.replacement_client.lock().replace(client);
    }
}

impl Connector for StubConnector {
    type Client = StubClient;

    fn connect(&self, attempts: u64) -> BoxFuture<'static, (u64, eyre::Result<Self::Client>)> {
        let connection_count = {
            let mut recorded_attempts = self.inner.attempts.lock();
            recorded_attempts.push(attempts);
            recorded_attempts.len()
        };
        let fail = {
            let mut failures_remaining = self.inner.failures_remaining.lock();
            let fail = *failures_remaining > 0;
            *failures_remaining = failures_remaining.saturating_sub(1);
            fail
        };
        let client = if connection_count > 1 {
            self.inner
                .replacement_client
                .lock()
                .take()
                .unwrap_or_else(|| self.inner.client.clone())
        } else {
            self.inner.client.clone()
        };
        async move {
            if fail {
                (attempts, Err(eyre::eyre!("connection failed")))
            } else {
                (attempts, Ok(client))
            }
        }
        .boxed()
    }

    fn endpoint(&self) -> &Url {
        &self.inner.endpoint
    }
}

#[derive(Clone, Default)]
pub(super) struct StubClient {
    inner: Arc<StubClientInner>,
}

#[derive(Default)]
struct StubClientInner {
    connected: AtomicBool,
    subscriptions: AtomicUsize,
    subscription_plans: Mutex<VecDeque<SubscriptionPlan>>,
    block_reads: AtomicUsize,
    finalization_reads: AtomicUsize,
}

impl StubClient {
    pub(super) fn connected() -> Self {
        let client = Self::default();
        client.inner.connected.store(true, Ordering::SeqCst);
        client
    }

    pub(super) fn set_connected(&self, connected: bool) {
        self.inner.connected.store(connected, Ordering::SeqCst);
    }

    pub(super) fn queue_subscription(&self) {
        self.inner
            .subscription_plans
            .lock()
            .push_back(SubscriptionPlan {
                gate: None,
                result: Ok(stream::pending().boxed()),
            });
    }

    pub(super) fn queue_event(&self, event: Event) {
        self.inner
            .subscription_plans
            .lock()
            .push_back(SubscriptionPlan {
                gate: None,
                result: Ok(stream::once(async move { Ok(event) })
                    .chain(stream::pending())
                    .boxed()),
            });
    }

    pub(super) fn queue_terminated_subscription(&self) {
        self.inner
            .subscription_plans
            .lock()
            .push_back(SubscriptionPlan {
                gate: None,
                result: Ok(stream::empty().boxed()),
            });
    }

    pub(super) fn queue_gated_termination(&self) -> oneshot::Sender<()> {
        let (release, gate) = oneshot::channel();
        self.inner
            .subscription_plans
            .lock()
            .push_back(SubscriptionPlan {
                gate: None,
                result: Ok(stream::unfold(Some(gate), |gate| async move {
                    let _ = gate.expect("gate is present on first poll").await;
                    None::<(eyre::Result<Event>, Option<oneshot::Receiver<()>>)>
                })
                .boxed()),
            });
        release
    }

    pub(super) fn queue_event_stream_error(&self) {
        self.inner
            .subscription_plans
            .lock()
            .push_back(SubscriptionPlan {
                gate: None,
                result: Ok(stream::once(async {
                    Err::<Event, _>(eyre::eyre!("event stream failed"))
                })
                .boxed()),
            });
    }

    pub(super) fn queue_paused_subscription(&self) -> oneshot::Sender<()> {
        let (release, gate) = oneshot::channel();
        self.inner
            .subscription_plans
            .lock()
            .push_back(SubscriptionPlan {
                gate: Some(gate),
                result: Ok(stream::pending().boxed()),
            });
        release
    }

    pub(super) fn queue_subscription_error(&self) {
        self.inner
            .subscription_plans
            .lock()
            .push_back(SubscriptionPlan {
                gate: None,
                result: Err(eyre::eyre!("subscription failed")),
            });
    }

    pub(super) fn subscriptions(&self) -> usize {
        self.inner.subscriptions.load(Ordering::SeqCst)
    }

    pub(super) fn block_reads(&self) -> usize {
        self.inner.block_reads.load(Ordering::SeqCst)
    }
}

impl UpstreamClient for StubClient {
    fn is_connected(&self) -> bool {
        self.inner.connected.load(Ordering::SeqCst)
    }

    fn subscribe_events(&self) -> BoxFuture<'static, eyre::Result<EventStream>> {
        self.inner.subscriptions.fetch_add(1, Ordering::SeqCst);
        let plan = self.inner.subscription_plans.lock().pop_front();
        async move {
            let Some(plan) = plan else {
                return Err(eyre::eyre!("no subscription plan"));
            };
            if let Some(gate) = plan.gate {
                let _ = gate.await;
            }
            plan.result
        }
        .boxed()
    }

    fn get_finalization(
        &self,
        _height: Height,
    ) -> BoxFuture<'static, eyre::Result<Option<CertifiedBlock>>> {
        self.inner.finalization_reads.fetch_add(1, Ordering::SeqCst);
        async { Ok(None) }.boxed()
    }

    fn get_block(&self, _digest: Digest) -> BoxFuture<'static, eyre::Result<Option<Block>>> {
        self.inner.block_reads.fetch_add(1, Ordering::SeqCst);
        async { Ok(None) }.boxed()
    }
}

#[derive(Clone, Default)]
pub(super) struct StubReporter {
    events: Arc<Mutex<Vec<Event>>>,
}

impl StubReporter {
    pub(super) fn events(&self) -> Vec<Event> {
        self.events.lock().clone()
    }
}

impl Reporter for StubReporter {
    type Activity = Event;

    fn report(&mut self, event: Event) -> Feedback {
        self.events.lock().push(event);
        Feedback::Ok
    }
}
