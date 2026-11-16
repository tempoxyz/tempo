use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use alloy_provider::{Provider as _, RootProvider};
use alloy_pubsub::{ConnectionHandle, PubSubConnect};
use alloy_rpc_client::{RpcClient, WsConnect};
use alloy_rpc_types_eth::{Block as RpcBlock, Transaction};
use alloy_transport::{TransportErrorKind, TransportResult};
use commonware_consensus::{Reporter, types::Height};
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner, spawn_cell};
use eyre::{Report, WrapErr as _, ensure};
use futures::{FutureExt as _, StreamExt as _, future::BoxFuture};
use rand_08::Rng as _;
use reth_primitives_traits::{SealedBlock, SealedOrRecoveredBlock};
use tempo_alloy::TempoNetwork;
use tempo_node::rpc::consensus::{CertifiedBlock, Event, Query, TempoConsensusApiClient};
use tempo_primitives::{TempoHeader, TempoTxEnvelope};
use tempo_telemetry_util::display_duration;
use tokio::{
    select,
    sync::{mpsc, oneshot},
};
use tower::Service as _;
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

/// How often websocket pings are sent while the connection to the upstream node is idle. A ping
/// that is not answered before the next one is due closes the connection, triggering a reconnect.
const PING_INTERVAL: Duration = Duration::from_secs(5);
/// How long the upstream node may take to answer a heartbeat before the connection is
/// considered dead.
///
/// alloy only pings after a quiet interval with no outbound frames, so steady requests to a
/// half-open connection would hide it; the heartbeat needs an answer from the upstream.
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long connecting to the upstream node, including the websocket handshake, may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the upstream node may take to answer `consensus_subscribe`.
const SUBSCRIBE_TIMEOUT: Duration = Duration::from_secs(60);

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
    type Client = WsClient;

    fn connect(&self, attempts: u64) -> BoxFuture<'static, (u64, eyre::Result<Self::Client>)> {
        let url = self.url.clone();
        async move {
            let connect = NoReconnect(
                WsConnect::new(url.as_str())
                    .with_keepalive_interval(PING_INTERVAL)
                    // alloy already stops at the first non-retryable reconnect error; this keeps
                    // it from waiting between attempts if that ever changes.
                    .with_max_retries(0),
            );
            let client = tokio::time::timeout(CONNECT_TIMEOUT, RpcClient::connect_pubsub(connect))
                .await
                .map_err(|_| eyre::eyre!("timed out connecting to upstream node"))
                .and_then(|client| client.map_err(Report::new))
                .map(|client| WsClient {
                    provider: RootProvider::new(client),
                    stream_dropped: Arc::new(AtomicBool::new(false)),
                });
            (attempts, client)
        }
        .boxed()
    }

    fn endpoint(&self) -> &Url {
        &self.url
    }
}

/// The websocket connection to the upstream node.
#[derive(Clone, Debug)]
pub(crate) struct WsClient {
    provider: RootProvider<TempoNetwork>,
    /// Set once an event stream of this connection is dropped.
    ///
    /// alloy cannot send `consensus_unsubscribe`, so the upstream only releases a subscription
    /// when its connection closes. Reporting the connection as lost once its stream is dropped
    /// makes the actor reconnect instead of resubscribing next to the old subscription.
    stream_dropped: Arc<AtomicBool>,
}

impl UpstreamClient for WsClient {
    fn is_connected(&self) -> bool {
        if self.stream_dropped.load(Ordering::Acquire) {
            return false;
        }
        // alloy has no connection getter; its pubsub frontend stops being ready once the
        // websocket service has shut down.
        self.provider
            .client()
            .pubsub_frontend()
            .is_some_and(|frontend| {
                matches!(
                    frontend
                        .clone()
                        .poll_ready(&mut Context::from_waker(Waker::noop())),
                    Poll::Ready(Ok(()))
                )
            })
    }

    fn subscribe_events(&self) -> BoxFuture<'static, eyre::Result<EventStream>> {
        let client = self.clone();
        async move {
            let subscription = tokio::time::timeout(
                SUBSCRIBE_TIMEOUT,
                TempoConsensusApiClient::subscribe_events(&client.provider).into_future(),
            )
            .await
            .map_err(|_| eyre::eyre!("timed out subscribing to consensus events"))??;
            let on_drop = SetOnDrop(client.stream_dropped);
            let events = subscription
                .into_result_stream()
                .map(move |event| {
                    let _ = &on_drop;
                    Some(event.map_err(Report::new))
                })
                .chain(futures::stream::once(async { None }));
            let heartbeat = futures::stream::unfold(client.provider, |provider| async move {
                tokio::time::sleep(PING_INTERVAL).await;
                let failure = heartbeat_failure(&provider).await;
                Some((failure, provider))
            })
            .filter_map(|failure| async move { failure.map(|error| Some(Err(error))) });
            // Ends with the event stream; the heartbeat only adds errors.
            Ok(futures::stream::select(events, heartbeat)
                .take_while(|item| futures::future::ready(item.is_some()))
                .filter_map(futures::future::ready)
                .boxed())
        }
        .boxed()
    }

    fn get_finalization(
        &self,
        height: Height,
    ) -> BoxFuture<'static, eyre::Result<Option<CertifiedBlock>>> {
        let client = self.provider.clone();
        async move { get_finalization(client, height).await }.boxed()
    }

    fn get_block(&self, digest: Digest) -> BoxFuture<'static, eyre::Result<Option<Block>>> {
        let client = self.provider.clone();
        async move { get_block(client, digest).await }.boxed()
    }
}

/// Asks the upstream for its chain ID and returns why the connection looks dead, if it does.
///
/// Any JSON-RPC answer, including an error, shows the connection is alive.
async fn heartbeat_failure(provider: &RootProvider<TempoNetwork>) -> Option<Report> {
    match tokio::time::timeout(HEARTBEAT_TIMEOUT, provider.get_chain_id()).await {
        Ok(Ok(_)) => None,
        Ok(Err(error)) if error.as_error_resp().is_some() => None,
        Ok(Err(error)) => Some(Report::new(error).wrap_err("upstream heartbeat failed")),
        Err(_) => Some(eyre::eyre!("upstream did not answer the heartbeat in time")),
    }
}

/// Sets the flag when dropped.
struct SetOnDrop(Arc<AtomicBool>);

impl Drop for SetOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// A websocket connector whose dropped connections alloy never reconnects.
///
/// alloy would otherwise reconnect and resubscribe on its own, and a rejected resubscription
/// leaves the event stream pending while the client still looks connected. Ending the client
/// instead ends its event stream, so the actor reconnects and resubscribes with its backoff.
struct NoReconnect(WsConnect);

impl PubSubConnect for NoReconnect {
    fn is_local(&self) -> bool {
        self.0.is_local()
    }

    fn connect(&self) -> impl Future<Output = TransportResult<ConnectionHandle>> + Send {
        self.0.connect()
    }

    async fn try_reconnect(&self) -> TransportResult<ConnectionHandle> {
        Err(TransportErrorKind::non_retryable_str(
            "upstream connection dropped; the follower reconnects itself",
        ))
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
    client: RootProvider<TempoNetwork>,
    height: Height,
) -> eyre::Result<Option<CertifiedBlock>> {
    TempoConsensusApiClient::get_finalization(&client, Query::Height(height.get()))
        .await
        .map(Some)
        .wrap_err("failed getting finalization")
}

/// Fetches a full consensus block from the upstream node.
#[instrument(skip_all, fields(%digest), err)]
async fn get_block(
    client: RootProvider<TempoNetwork>,
    digest: Digest,
) -> eyre::Result<Option<Block>> {
    let block = client
        .client()
        .request::<_, Option<RpcBlock<Transaction<TempoTxEnvelope>, TempoHeader>>>(
            "eth_getBlockByHash",
            (digest.0, true),
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
            Block::try_from_execution_block(block).wrap_err("upstream block is invalid")
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

    #[tokio::test]
    async fn websocket_client_reports_disconnect() {
        let server = jsonrpsee::server::Server::builder()
            .build("127.0.0.1:0")
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let handle = server.start(jsonrpsee::RpcModule::new(()));

        let connector = WebSocketConnector::new(format!("ws://{addr}").parse().unwrap());
        let (_, client) = connector.connect(0).await;
        let client = client.unwrap();
        assert!(client.is_connected());

        handle.stop().unwrap();
        handle.stopped().await;
        tokio::time::timeout(Duration::from_secs(10), async {
            while client.is_connected() {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("client must report the upstream connection as closed");
    }

    #[tokio::test]
    async fn server_ended_subscription_ends_event_stream() {
        let mut module = jsonrpsee::RpcModule::new(());
        module
            .register_subscription(
                "consensus_subscribe",
                "consensus_event",
                "consensus_unsubscribe",
                |_, pending, _| async move {
                    let _sink = pending.accept().await?;
                    // Let the client finish setting up the subscription before closing it.
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    Err("consensus feed closed".into())
                },
            )
            .unwrap();
        let server = jsonrpsee::server::Server::builder()
            .build("127.0.0.1:0")
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let _handle = server.start(module);

        let connector = WebSocketConnector::new(format!("ws://{addr}").parse().unwrap());
        let (_, client) = connector.connect(0).await;
        let mut events = UpstreamClient::subscribe_events(&client.unwrap())
            .await
            .unwrap();
        // The close notification drops the connection, which must end the stream instead of
        // alloy reconnecting and resubscribing behind the actor's back.
        let next = tokio::time::timeout(Duration::from_secs(10), events.next())
            .await
            .expect("event stream must end once the server closes the subscription");
        assert!(next.is_none(), "expected the stream to end, got {next:?}");
    }

    #[tokio::test]
    async fn dropped_event_stream_reports_disconnect() {
        let mut module = jsonrpsee::RpcModule::new(());
        module
            .register_subscription(
                "consensus_subscribe",
                "consensus_event",
                "consensus_unsubscribe",
                |_, pending, _| async move {
                    let sink = pending.accept().await?;
                    let undecodable = jsonrpsee::SubscriptionMessage::new(
                        sink.method_name(),
                        sink.subscription_id().clone(),
                        &"not an event",
                    )
                    .unwrap();
                    sink.send(undecodable).await?;
                    sink.closed().await;
                    Ok(())
                },
            )
            .unwrap();
        let server = jsonrpsee::server::Server::builder()
            .build("127.0.0.1:0")
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let _handle = server.start(module);

        let connector = WebSocketConnector::new(format!("ws://{addr}").parse().unwrap());
        let (_, client) = connector.connect(0).await;
        let client = client.unwrap();
        let mut events = UpstreamClient::subscribe_events(&client).await.unwrap();
        let next = tokio::time::timeout(Duration::from_secs(10), events.next())
            .await
            .expect("the undecodable event must arrive");
        assert!(
            matches!(next, Some(Err(_))),
            "expected a decode error, got {next:?}"
        );
        assert!(client.is_connected());

        // The actor drops the stream to retry. The client must then report the connection as
        // lost, so the actor reconnects rather than resubscribing next to the old subscription.
        drop(events);
        assert!(!client.is_connected());
    }

    #[tokio::test]
    async fn unanswered_heartbeat_fails_event_stream() {
        let mut module = jsonrpsee::RpcModule::new(());
        module
            .register_subscription(
                "consensus_subscribe",
                "consensus_event",
                "consensus_unsubscribe",
                |_, pending, _| async move {
                    let sink = pending.accept().await?;
                    sink.closed().await;
                    Ok(())
                },
            )
            .unwrap();
        // Stands in for a half-open connection: requests are sent but never answered.
        module
            .register_async_method("eth_chainId", |_, _| {
                std::future::pending::<jsonrpsee::core::RpcResult<u64>>()
            })
            .unwrap();
        let server = jsonrpsee::server::Server::builder()
            .build("127.0.0.1:0")
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let _handle = server.start(module);

        let connector = WebSocketConnector::new(format!("ws://{addr}").parse().unwrap());
        let (_, client) = connector.connect(0).await;
        let mut events = UpstreamClient::subscribe_events(&client.unwrap())
            .await
            .unwrap();
        let next = tokio::time::timeout(
            PING_INTERVAL + HEARTBEAT_TIMEOUT + Duration::from_secs(5),
            events.next(),
        )
        .await
        .expect("the heartbeat must fail the event stream");
        let error = next
            .expect("expected an error, not the end of the stream")
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "upstream did not answer the heartbeat in time"
        );
    }

    #[tokio::test]
    async fn heartbeat_error_response_keeps_connection() {
        let server = jsonrpsee::server::Server::builder()
            .build("127.0.0.1:0")
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        // No eth_chainId: the upstream answers with method not found.
        let _handle = server.start(jsonrpsee::RpcModule::new(()));

        let connector = WebSocketConnector::new(format!("ws://{addr}").parse().unwrap());
        let (_, client) = connector.connect(0).await;
        assert!(heartbeat_failure(&client.unwrap().provider).await.is_none());
    }

    #[tokio::test]
    async fn websocket_connector_never_reconnects() {
        let err = NoReconnect(WsConnect::new("ws://127.0.0.1:1"))
            .try_reconnect()
            .await
            .expect_err("alloy must not reconnect on its own");
        assert!(matches!(
            err,
            alloy_transport::RpcError::Transport(TransportErrorKind::NonRetryable(_))
        ));
    }

    #[tokio::test]
    async fn websocket_connect_times_out_without_handshake() {
        // Accepts TCP but never answers the websocket upgrade.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _accept = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });

        let connector = WebSocketConnector::new(format!("ws://{addr}").parse().unwrap());
        let (_, client) = tokio::time::timeout(CONNECT_TIMEOUT * 2, connector.connect(0))
            .await
            .expect("connect must give up on its own");
        let err = client.expect_err("a stalled handshake must fail");
        assert_eq!(err.to_string(), "timed out connecting to upstream node");
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
