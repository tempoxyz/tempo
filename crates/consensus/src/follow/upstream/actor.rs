use std::{future::Future, sync::Arc, time::Duration};

use alloy_rpc_types_eth::{Block as RpcBlock, Transaction};
use commonware_consensus::{Reporter, types::Height};
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner, spawn_cell};
use eyre::{Report, WrapErr as _, ensure};
use futures::{FutureExt as _, StreamExt as _, future::BoxFuture};
use jsonrpsee::{
    core::client::{ClientT as _, Subscription},
    rpc_params,
    ws_client::{PingConfig, WsClient, WsClientBuilder},
};
use rand_08::Rng as _;
use reth_primitives_traits::{SealedBlock, SealedOrRecoveredBlock};
use tempo_node::rpc::consensus::{CertifiedBlock, Event, Query, TempoConsensusApiClient};
use tempo_primitives::{TempoHeader, TempoTxEnvelope};
use tempo_telemetry_util::display_duration;
use tokio::{
    select,
    sync::{mpsc, oneshot},
};
use tracing::{debug, debug_span, instrument, warn, warn_span};
use url::Url;

use crate::{
    consensus::{Block, Digest},
    utils::OptionFuture,
};

use super::{Connector, EventStream, UpstreamClient};

const RECONNECT_BACKOFF_FACTOR: u64 = 2;
const RECONNECT_MAX_BACKOFF: Duration = Duration::from_secs(20);
const RECONNECT_JITTER: Duration = Duration::from_secs(1);

/// How often websocket pings are sent to keep the connection to the upstream
/// node alive (and to detect dead connections, triggering a reconnect).
const PING_INTERVAL: Duration = Duration::from_secs(5);
/// How long the connection may stay inactive (no pongs or other messages)
/// before it is considered dead and closed.
const PING_INACTIVE_LIMIT: Duration = Duration::from_secs(10);
/// How many times the connection may exceed the inactivity limit before it is
/// closed.
const PING_MAX_FAILURES: usize = 1;

/// Manages the connection to the upstream node.
///
/// This actor holds the websocket connection to the upstream node, reconnecting
/// it if necessary.
pub(crate) struct Actor<TContext, TConnector = WebSocketConnector>
where
    TConnector: Connector,
{
    pub(super) context: ContextCell<TContext>,
    pub(super) connector: TConnector,
    pub(super) connection: Option<TConnector::Client>,
    pub(super) mailbox: mpsc::UnboundedReceiver<super::ingress::Message>,
    pub(super) pending_connect:
        OptionFuture<BoxFuture<'static, (u64, eyre::Result<TConnector::Client>)>>,
    pub(super) pending_stream: OptionFuture<BoxFuture<'static, eyre::Result<EventStream>>>,
    pub(super) event_stream: Option<EventStream>,
    pub(super) reconnect_jitter: fn() -> Duration,
    pub(super) retry_attempt: u64,
    /// Requests waiting for the actor to establish a connection.
    pub(super) waiters: Vec<super::ingress::Message>,
}

pub(super) fn init<TContext, TConnector>(
    context: TContext,
    connector: TConnector,
    reconnect_jitter: fn() -> Duration,
) -> (Actor<TContext, TConnector>, super::Mailbox)
where
    TConnector: Connector,
{
    let (tx, rx) = mpsc::unbounded_channel();
    let actor = Actor {
        context: ContextCell::new(context),
        connector,
        connection: None,
        mailbox: rx,
        pending_connect: OptionFuture::none(),
        pending_stream: OptionFuture::none(),
        event_stream: None,
        reconnect_jitter,
        retry_attempt: 1,
        waiters: Vec::new(),
    };

    (actor, super::Mailbox::new(tx))
}

impl<TContext, TConnector> Actor<TContext, TConnector>
where
    TContext: Clock + Metrics + Spawner,
    TConnector: Connector,
{
    pub(crate) fn start(
        mut self,
        reporter: impl Reporter<Activity = Event>,
    ) -> commonware_runtime::Handle<()> {
        spawn_cell!(self.context, self.run(reporter))
    }

    async fn run(mut self, mut reporter: impl Reporter<Activity = Event>) {
        loop {
            self.reconnect_or_resubscribe();
            self.drain_waiters();

            select!(
                biased;

                (attempts, client) = &mut self.pending_connect => {
                    self.retry_attempt = attempts;
                    match client {
                        Ok(client) => {
                            self.connection.replace(client);
                        }
                        Err(reason) => {
                            let reconnect_in = self.retry_connection();
                            warn_span!("reconnect").in_scope(|| warn!(
                                %reason,
                                attempts,
                                reconnect_in = %display_duration(reconnect_in),
                                url = %self.connector.endpoint(),
                                "connecting to upstream node failed, attempting again",
                            ));
                        }
                    }
                }

                stream = &mut self.pending_stream => {
                    match stream {
                        Ok(stream) => {
                        debug_span!("consensus_event_subscription")
                            .in_scope(|| debug!("subscription for consensus events established"));
                            self.event_stream = Some(stream);
                        }
                        Err(error) => {
                            self.connection.take();
                            self.event_stream = None;
                            let reconnect_in = self.retry_connection();
                            warn_span!("event_subscription").in_scope(|| warn!(
                                reason = %error,
                                reconnect_in = %display_duration(reconnect_in),
                                "failed subscribing to events; reconnecting to upstream node",
                            ));
                        }
                    }
                }

                event = next_event(&mut self.event_stream) => {
                    match event {
                        Some(Ok(event)) => {
                            // A handshake and subscription response alone do not prove recovery.
                            self.retry_attempt = 0;
                            debug_span!("consensus_event").in_scope(|| debug!(
                                ?event, "received consensus event, forwarding to reporter"
                            ));
                            let _ = reporter.report(event);
                        }
                        Some(Err(error)) => {
                            let reconnect_in = self.retry_event_stream();
                            warn_span!("event").in_scope(|| warn!(
                                %error,
                                reconnect_in = %display_duration(reconnect_in),
                                "event stream encountered an error",
                            ));
                        }
                        None => {
                            let reconnect_in = self.retry_event_stream();
                            warn_span!("event_subscription").in_scope(|| warn!(
                                url = %self.connector.endpoint(),
                                reconnect_in = %display_duration(reconnect_in),
                                "event stream terminated",
                            ));
                        }
                    }
                }

                request = self.mailbox.recv() => {
                    let Some(request) = request else {
                        return;
                    };
                    self.waiters.push(request);
                }
            );
        }
    }

    #[instrument(skip_all)]
    fn reconnect_or_resubscribe(&mut self) {
        if self.pending_connect.is_some() || self.pending_stream.is_some() {
            return;
        }

        let Some(client) = self.connection.clone() else {
            self.retry_attempt = self.retry_attempt.max(1);
            self.pending_connect
                .replace(self.connector.connect(self.retry_attempt));
            return;
        };

        if self.event_stream.is_some() {
            return;
        }

        if client.is_connected() {
            self.pending_stream.replace(client.subscribe_events());
        } else {
            self.connection.take();
            let reconnect_in = self.retry_connection();
            warn!(
                url = %self.connector.endpoint(),
                reconnect_in = %display_duration(reconnect_in),
                "upstream client disconnected, reconnecting",
            );
        }
    }

    fn retry_event_stream(&mut self) -> Duration {
        self.event_stream = None;
        let Some(client) = self.connection.clone() else {
            return self.retry_connection();
        };

        if client.is_connected() {
            self.retry_subscription(client)
        } else {
            self.connection.take();
            self.retry_connection()
        }
    }

    fn retry_connection(&mut self) -> Duration {
        let reconnect_in = self.begin_retry();
        let sleep = self.context.sleep(reconnect_in);
        let connector = self.connector.clone();
        let attempts = self.retry_attempt;
        self.pending_connect.replace(
            async move {
                sleep.await;
                connector.connect(attempts).await
            }
            .boxed(),
        );
        reconnect_in
    }

    fn retry_subscription(&mut self, client: TConnector::Client) -> Duration {
        let reconnect_in = self.begin_retry();
        let sleep = self.context.sleep(reconnect_in);
        self.pending_stream.replace(
            async move {
                sleep.await;
                client.subscribe_events().await
            }
            .boxed(),
        );
        reconnect_in
    }

    fn begin_retry(&mut self) -> Duration {
        let reconnect_in = reconnect_backoff(self.retry_attempt);
        let reconnect_in = if reconnect_in.is_zero() {
            reconnect_in
        } else {
            reconnect_in + (self.reconnect_jitter)()
        };
        self.retry_attempt = self.retry_attempt.saturating_add(1);
        reconnect_in
    }

    /// Drains the waiters by fetching the data they are waiting for.
    ///
    /// Only executes if a client is present and connected.
    fn drain_waiters(&mut self) {
        if self.pending_connect.is_some()
            || self.pending_stream.is_some()
            || self.event_stream.is_none()
        {
            return;
        }

        let Some(client) = &self.connection else {
            return;
        };
        if !client.is_connected() {
            return;
        }

        for request in self.waiters.drain(..) {
            match request {
                super::ingress::Message::GetFinalization { height, response } => {
                    let client = client.clone();
                    self.context.child("get_finalization").spawn(move |_| {
                        respond_until_closed(response, client.get_finalization(height))
                    });
                }
                super::ingress::Message::GetBlock { digest, response } => {
                    let client = client.clone();
                    self.context
                        .child("get_block")
                        .spawn(move |_| respond_until_closed(response, client.get_block(digest)));
                }
            }
        }
    }
}

async fn next_event(stream: &mut Option<EventStream>) -> Option<eyre::Result<Event>> {
    match stream {
        Some(stream) => stream.next().await,
        None => std::future::pending().await,
    }
}

pub(super) fn reconnect_backoff(attempts: u64) -> Duration {
    let backoff_secs = attempts.saturating_mul(RECONNECT_BACKOFF_FACTOR);
    let backoff = Duration::from_secs(backoff_secs);

    backoff.min(RECONNECT_MAX_BACKOFF)
}

pub(super) fn random_jitter() -> Duration {
    let max_jitter_millis = RECONNECT_JITTER.as_millis() as u64;
    Duration::from_millis(rand_08::thread_rng().gen_range(0..=max_jitter_millis))
}

#[derive(Clone)]
pub(crate) struct WebSocketConnector {
    url: Arc<Url>,
}

impl WebSocketConnector {
    pub(super) fn new(url: Url) -> Self {
        Self { url: Arc::new(url) }
    }
}

impl Connector for WebSocketConnector {
    type Client = Arc<WsClient>;

    fn connect(&self, attempts: u64) -> BoxFuture<'static, (u64, eyre::Result<Self::Client>)> {
        let url = self.url.clone();
        async move {
            let client = WsClientBuilder::default()
                .enable_ws_ping(
                    PingConfig::new()
                        .ping_interval(PING_INTERVAL)
                        .inactive_limit(PING_INACTIVE_LIMIT)
                        .max_failures(PING_MAX_FAILURES),
                )
                .build(url.as_ref())
                .await
                .map(Arc::new)
                .map_err(Report::new);
            (attempts, client)
        }
        .boxed()
    }

    fn endpoint(&self) -> &Url {
        &self.url
    }
}

impl UpstreamClient for Arc<WsClient> {
    fn is_connected(&self) -> bool {
        WsClient::is_connected(self)
    }

    fn subscribe_events(&self) -> BoxFuture<'static, eyre::Result<EventStream>> {
        let client = self.clone();
        async move {
            let stream: Subscription<Event> =
                TempoConsensusApiClient::subscribe_events(client.as_ref()).await?;
            Ok(stream.map(|event| event.map_err(Report::new)).boxed())
        }
        .boxed()
    }

    fn get_finalization(
        &self,
        height: Height,
    ) -> BoxFuture<'static, eyre::Result<Option<CertifiedBlock>>> {
        let client = self.clone();
        async move { get_finalization(client, height).await }.boxed()
    }

    fn get_block(&self, digest: Digest) -> BoxFuture<'static, eyre::Result<Option<Block>>> {
        let client = self.clone();
        async move { get_block(client, digest).await }.boxed()
    }
}

/// Polls the request and sends its result while the receiver remains open.
///
/// Drops the request future if the receiver closes first.
async fn respond_until_closed<T>(
    mut response: oneshot::Sender<T>,
    request: impl Future<Output = eyre::Result<T>>,
) -> eyre::Result<()> {
    select! {
        biased;
        () = response.closed() => Ok(()),
        result = request => response
            .send(result?)
            .map_err(|_| eyre::eyre!("receiver went away")),
    }
}

#[instrument(skip_all, fields(%height), err)]
async fn get_finalization(
    client: Arc<WsClient>,
    height: Height,
) -> eyre::Result<Option<CertifiedBlock>> {
    TempoConsensusApiClient::get_finalization(client.as_ref(), Query::Height(height.get()))
        .await
        .map(Some)
        .wrap_err("failed getting finalization")
}

/// Fetches a full consensus block from the upstream node.
#[instrument(skip_all, fields(%digest), err)]
async fn get_block(client: Arc<WsClient>, digest: Digest) -> eyre::Result<Option<Block>> {
    let block = client
        .request::<Option<RpcBlock<Transaction<TempoTxEnvelope>, TempoHeader>>, _>(
            "eth_getBlockByHash",
            rpc_params![digest.0, true],
        )
        .await
        .wrap_err("failed getting block by hash")?
        .map(|block| {
            SealedOrRecoveredBlock::from(SealedBlock::seal_slow(
                block
                    .into_consensus_block()
                    .map_transactions(|transaction| transaction.into_inner()),
            ))
        });

    let block = block
        .map(|block| {
            ensure!(block.hash() == digest.0, "mismatched block hash");
            Block::try_from_execution_block(block, None)
                .wrap_err("upstream block or consensus sidecar is invalid")
        })
        .transpose()?;

    Ok(block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct DropGuard(Arc<AtomicBool>);

    impl Drop for DropGuard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn reconnect_backoff_linearly_increases_and_caps() {
        assert_eq!(reconnect_backoff(0), Duration::from_secs(0));
        assert_eq!(reconnect_backoff(1), Duration::from_secs(2));
        assert_eq!(reconnect_backoff(2), Duration::from_secs(4));
        assert_eq!(reconnect_backoff(3), Duration::from_secs(6));
        assert_eq!(reconnect_backoff(4), Duration::from_secs(8));
        assert_eq!(reconnect_backoff(5), Duration::from_secs(10));
        assert_eq!(reconnect_backoff(10), RECONNECT_MAX_BACKOFF);
        assert_eq!(reconnect_backoff(u64::MAX), RECONNECT_MAX_BACKOFF);
    }

    #[tokio::test]
    async fn closing_response_cancels_request() {
        let (response, receiver) = oneshot::channel::<()>();
        let (started_tx, started_rx) = oneshot::channel();
        let dropped = Arc::new(AtomicBool::new(false));
        let request_dropped = dropped.clone();

        let task = tokio::spawn(async move {
            let request = async move {
                let _guard = DropGuard(request_dropped);
                let _ = started_tx.send(());
                std::future::pending::<eyre::Result<()>>().await
            };
            respond_until_closed(response, request).await
        });

        started_rx.await.unwrap();
        drop(receiver);

        task.await.unwrap().unwrap();
        assert!(dropped.load(Ordering::SeqCst));
    }
}
