//! Upstream node abstraction for follow mode.
//!
//! Defines the [`UpstreamNode`] trait that captures the operations the follow
//! engine needs from an upstream node, and provides two implementations:
//!
//! - [`WsUpstream`]: WebSocket RPC for production use.
//! - [`LocalUpstream`]: Direct access for testing network I/O.

use std::{sync::Arc, time::Duration};

use commonware_consensus::{Reporter, types::Height};
use commonware_runtime::{Clock, ContextCell, Spawner, spawn_cell};
use eyre::Report;
use futures::{
    FutureExt as _,
    future::BoxFuture,
    stream::{self, BoxStream, Fuse, StreamExt as _},
};
use jsonrpsee::{
    core::{client, client::Subscription},
    ws_client::{WsClient, WsClientBuilder},
};
use tempo_node::rpc::consensus::{CertifiedBlock, Event, Query, TempoConsensusApiClient};
use tempo_primitives::Block;
use tempo_telemetry_util::display_duration;
use tokio::{
    select,
    sync::{mpsc, oneshot},
};
use tracing::{warn, warn_span};

use crate::utils::OptionFuture;

// type TempoRpcBlock =
//     AlloyRpcBlock<alloy_rpc_types_eth::Transaction<TempoTxEnvelope>, TempoHeaderResponse>;

// const RECONNECT_BASE_MS: u64 = 500;
// const RECONNECT_MAX_MS: u64 = 30_000;

pub(super) fn init<TContext>(context: TContext, config: Config) -> (Actor<TContext>, Mailbox) {
    let (tx, rx) = mpsc::unbounded_channel();
    let mailbox = Mailbox(tx);

    let url = Box::leak(Box::<str>::from(config.upstream_url.clone()));
    let actor = Actor {
        context: ContextCell::new(context),
        connection: None,
        mailbox: rx,
        url,
        pending_connect: OptionFuture::none(),
        pending_stream: OptionFuture::none(),
        event_stream: stream::empty::<Result<Event, serde_json::Error>>()
            .boxed()
            .fuse(),
        waiters: Vec::new(),
    };

    (actor, mailbox)
}

#[derive(thiserror::Error, Debug)]
pub(super) enum Error {
    #[error("no connection to the upstream node")]
    NotConnected,
    #[error(transparent)]
    Connection(#[from] client::Error),
    #[error("the actor is dead and no more responses will be forthcoming")]
    Dead,
}

impl Error {
    fn dead<T>(_: T) -> Self {
        Self::Dead
    }
}

impl From<tokio::sync::oneshot::error::RecvError> for Error {
    fn from(_: tokio::sync::oneshot::error::RecvError) -> Self {
        Self::Dead
    }
}

pub(super) struct Config {
    /// The URL to connect to.
    pub(super) upstream_url: String,
}

enum Message {
    /// Request for a finalization of a given height.
    GetFinalization {
        height: Height,
        response: oneshot::Sender<Result<Option<CertifiedBlock>, Error>>,
    },
    /// Subscription to wait until the actor established a connection to the
    /// upstream node.
    SubscribeConnection { response: oneshot::Sender<()> },
}

/// Mailbox to the Upstream actor to issue requests to.
#[derive(Clone)]
pub(super) struct Mailbox(mpsc::UnboundedSender<Message>);

impl Mailbox {
    pub(super) async fn get_finalization(
        &self,
        height: Height,
    ) -> Result<Option<CertifiedBlock>, Error> {
        let (response, rx) = oneshot::channel();
        self.0
            .send(Message::GetFinalization { height, response })
            .map_err(Error::dead)?;
        rx.await?
    }

    pub(super) async fn subscribe_connection(&self) -> Result<(), Error> {
        let (response, rx) = oneshot::channel();
        self.0
            .send(Message::SubscribeConnection { response })
            .map_err(Error::dead)?;
        rx.await.map_err(Error::dead)
    }
}

type EventStream = Fuse<BoxStream<'static, Result<Event, serde_json::Error>>>;

/// Manages the connection to the upstream node.
///
/// This actor holds the websocket connection to the upstream node, reconnecting
/// it if necessary.
pub(super) struct Actor<TContext> {
    context: ContextCell<TContext>,
    connection: Option<Arc<WsClient>>,
    mailbox: mpsc::UnboundedReceiver<Message>,
    url: &'static str,
    pending_connect: OptionFuture<BoxFuture<'static, (u64, eyre::Result<WsClient>)>>,
    pending_stream: OptionFuture<BoxFuture<'static, Result<Subscription<Event>, client::Error>>>,
    event_stream: EventStream,
    /// Subscribers waiting to be notified that a new connection was established.
    waiters: Vec<oneshot::Sender<()>>,
}

impl<TContext> Actor<TContext>
where
    TContext: Spawner + Clock,
{
    pub(super) fn start(
        mut self,
        reporter: impl Reporter<Activity = Event>,
    ) -> commonware_runtime::Handle<()> {
        spawn_cell!(self.context, self.run(reporter).await)
    }

    async fn run(mut self, mut reporter: impl Reporter<Activity = Event>) {
        self.pending_connect.replace({
            let url = self.url;
            async move {
                (
                    1,
                    WsClientBuilder::default()
                        .build(&url)
                        .await
                        .map_err(Report::new),
                )
            }
            .boxed()
        });
        loop {
            select!(
                biased;

                error = OptionFuture::new(self.connection.as_ref().map(|c| c.on_disconnect()))
                => {
                    warn_span!("connection").in_scope(|| warn!(
                        reason = %Report::new(error),
                        url = self.url,
                        "connection to upstream node disconnected, attempting reconnect",
                    ));
                    self.connection.take();
                    self.pending_stream.take();
                    self.pending_connect.replace({
                        let url = self.url;
                        async move {
                             (1, WsClientBuilder::default().build(&url).await.map_err(Report::new))
                        }.boxed()
                    });
                    for waiter in self.waiters.drain(..) {
                        let _ = waiter.send(());
                    }
                }

                (attempts, client) = &mut self.pending_connect => {
                    match client {
                        Ok(client) => {
                            let client = Arc::new(client);
                            self.connection.replace(client.clone());
                            self.pending_stream.replace(async move {
                                client.subscribe_events().await
                            }.boxed());
                        }
                        Err(reason) => {
                            let reconnect_in = Duration::from_secs(attempts.saturating_mul(1).min(20));
                            warn_span!("reconnect").in_scope(|| warn!(
                                %reason,
                                attempts,
                                reconnect_in = %display_duration(reconnect_in),
                                url = self.url,
                                "connecting to upstream node failed, attempting again",
                            ));
                            self.pending_connect.replace({
                                let context = self.context.clone();
                                let url = self.url;
                                async move {
                                    context.sleep(reconnect_in).await;
                                    (1, WsClientBuilder::default().build(&url).await.map_err(Report::new))
                                }.boxed()
                            });
                        }
                    }
                }

                stream = &mut self.pending_stream => {
                    match stream {
                        Ok(stream) => self.event_stream = stream.boxed().fuse(),
                        Err(error) => {
                            warn_span!("event_subscription").in_scope(|| warn!(
                                reason = %Report::new(error),
                                "failed subscribing to events; retrying"
                            ));
                            if let Some(client) = self.connection.clone() {
                                self.pending_stream.replace(async move {
                                    client.subscribe_events().await
                                }.boxed());
                            }
                        }
                    }
                }

                Some(event) = self.event_stream.next() => {
                    match event {
                        Ok(event) => reporter.report(event).await,
                        Err(error) => warn_span!("event").in_scope(|| warn!(
                            %error,
                            "event stream encountered an error",
                        )),
                    }
                }

                Some(msg) = self.mailbox.recv() => {
                    match msg {
                        Message::GetFinalization { height, response, } => {
                            if let Some(client) = self.connection.clone() {
                                self.context.clone().spawn(move |_| async move {
                                    let rsp = client.get_finalization(Query::Height(height.get())).await;
                                    let _ = response.send(rsp.map_err(Error::from));
                                });
                            } else {
                                let _ = response.send(Err(Error::NotConnected));
                            }
                        }
                        Message::SubscribeConnection { response } => {
                            if self.connection.is_some() {
                                let _ = response.send(());
                            } else {
                                self.waiters.push(response);
                            }
                        }
                    }
                }
            )
        }
    }
}

/// Abstraction over the upstream node that a follower syncs from.
///
/// In production this is backed by a WebSocket RPC connection ([`WsUpstream`]).
/// In tests it can be backed by in-process direct access to another node's
/// feed state and execution provider.
pub trait UpstreamNode: Clone + Send + Sync + 'static {
    fn subscribe_events(
        &self,
    ) -> impl std::future::Future<Output = eyre::Result<BoxStream<'static, eyre::Result<Event>>>> + Send;

    fn get_finalization(
        &self,
        query: Query,
    ) -> impl std::future::Future<Output = eyre::Result<Option<CertifiedBlock>>> + Send;

    fn get_block_by_number(
        &self,
        height: u64,
    ) -> impl std::future::Future<Output = eyre::Result<Option<Block>>> + Send;

    fn get_block_by_hash(
        &self,
        hash: alloy_primitives::B256,
    ) -> impl std::future::Future<Output = eyre::Result<Option<Block>>> + Send;
}

// /// WebSocket-based upstream node for production use.
// ///
// /// Owns a persistent WebSocket connection to the upstream node with
// /// transparent reconnection.
// #[derive(Clone)]
// pub(crate) struct WsUpstream<TContext> {
//     context: TContext,
//     url: String,
//     client: Arc<Mutex<Option<Arc<WsClient>>>>,
// }

// impl<TContext: Clock> WsUpstream<TContext> {
//     pub(crate) fn new(context: TContext, url: String) -> Self {
//         Self {
//             context,
//             url,
//             client: Arc::new(Mutex::new(None)),
//         }
//     }

//     async fn client(&self) -> eyre::Result<Arc<WsClient>> {
//         let mut guard = self.client.lock().await;
//         if let Some(c) = guard.as_ref()
//             && c.is_connected()
//         {
//             return Ok(c.clone());
//         }

//         let mut attempts: u32 = 0;
//         loop {
//             match WsClientBuilder::default().build(&self.url).await {
//                 Ok(c) => {
//                     let c = Arc::new(c);
//                     guard.replace(c.clone());
//                     if attempts > 0 {
//                         debug!(attempts, "reconnected to upstream WebSocket");
//                     }

//                     return Ok(c);
//                 }
//                 Err(e) => {
//                     attempts += 1;
//                     let delay_ms =
//                         (RECONNECT_BASE_MS * 2u64.pow(attempts.min(6))).min(RECONNECT_MAX_MS);

//                     warn_span!("follow_ws_upstream").in_scope(|| {
//                         warn!(
//                             error = %e,
//                             attempt = attempts,
//                             retry_in_ms = delay_ms,
//                             "failed to connect to upstream"
//                         );
//                     });

//                     self.context.sleep(Duration::from_millis(delay_ms)).await;
//                 }
//             }
//         }
//     }

//     fn convert_rpc_block(rpc_block: TempoRpcBlock) -> Block {
//         rpc_block
//             .into_consensus_block()
//             .map_header(|h| h.inner.inner)
//             .map_transactions(|tx: alloy_rpc_types_eth::Transaction<TempoTxEnvelope>| {
//                 tx.into_inner()
//             })
//     }
// }

// impl<C: Clock> UpstreamNode for WsUpstream<C> {
//     async fn subscribe_events(&self) -> eyre::Result<BoxStream<'static, eyre::Result<Event>>> {
//         let client = self.client().await?;
//         let sub = client.subscribe_events().await.wrap_err("rpc error")?;
//         Ok(sub.map(|item| item.wrap_err("subscription error")).boxed())
//     }

//     async fn get_finalization(&self, query: Query) -> eyre::Result<Option<CertifiedBlock>> {
//         let client = self.client().await?;
//         client.get_finalization(query).await.wrap_err("rpc error")
//     }

//     async fn get_block_by_number(&self, height: u64) -> eyre::Result<Option<Block>> {
//         let client = self.client().await?;
//         let rpc_block: Option<TempoRpcBlock> = client
//             .request(
//                 "eth_getBlockByNumber",
//                 rpc_params![format!("0x{:x}", height), true],
//             )
//             .await
//             .wrap_err("rpc error")?;

//         Ok(rpc_block.map(Self::convert_rpc_block))
//     }

//     async fn get_block_by_hash(&self, hash: alloy_primitives::B256) -> eyre::Result<Option<Block>> {
//         let client = self.client().await?;
//         let rpc_block: Option<TempoRpcBlock> = client
//             .request("eth_getBlockByHash", rpc_params![hash, true])
//             .await
//             .wrap_err("rpc error")?;

//         Ok(rpc_block.map(Self::convert_rpc_block))
//     }
// }

// /// Upstream backed by direct state access
// ///
// /// Avoids WebSocket I/O, allowing the follow engine to run in a
// /// deterministic runtime for testing.
// #[derive(Clone)]
// pub struct LocalUpstream {
//     feed: FeedStateHandle,
//     execution_node: TempoFullNode,
// }

// impl LocalUpstream {
//     pub fn new(feed: FeedStateHandle, execution_node: TempoFullNode) -> Self {
//         Self {
//             feed,
//             execution_node,
//         }
//     }
// }

// impl UpstreamNode for LocalUpstream {
//     async fn subscribe_events(&self) -> eyre::Result<BoxStream<'static, eyre::Result<Event>>> {
//         let rx = self
//             .feed
//             .subscribe()
//             .await
//             .ok_or_else(|| eyre::eyre!("feed not ready for subscription"))?;

//         let stream = futures::stream::unfold(rx, |mut rx| async {
//             match rx.recv().await {
//                 Ok(event) => Some((Ok(event), rx)),
//                 Err(tokio::sync::broadcast::error::RecvError::Closed) => None,
//                 Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
//                     Some((Err(eyre::eyre!("lagged by {n} events")), rx))
//                 }
//             }
//         })
//         .boxed();

//         Ok(stream)
//     }

//     async fn get_finalization(&self, query: Query) -> eyre::Result<Option<CertifiedBlock>> {
//         Ok(self.feed.get_finalization(query).await)
//     }

//     async fn get_block_by_number(
//         &self,
//         height: u64,
//     ) -> eyre::Result<Option<tempo_primitives::Block>> {
//         self.execution_node
//             .provider
//             .block_by_number(height)
//             .wrap_err("provider error")
//     }

//     async fn get_block_by_hash(
//         &self,
//         hash: alloy_primitives::B256,
//     ) -> eyre::Result<Option<tempo_primitives::Block>> {
//         self.execution_node
//             .provider
//             .find_block_by_hash(hash, BlockSource::Any)
//             .wrap_err("provider error")
//     }
// }

// impl<U> UpstreamNode for Arc<U>
// where
//     U: UpstreamNode,
// {
//     fn subscribe_events(
//         &self,
//     ) -> impl std::future::Future<Output = eyre::Result<BoxStream<'static, eyre::Result<Event>>>> + Send
//     {
//         (**self).subscribe_events()
//     }

//     fn get_finalization(
//         &self,
//         query: Query,
//     ) -> impl std::future::Future<Output = eyre::Result<Option<CertifiedBlock>>> + Send {
//         (**self).get_finalization(query)
//     }

//     fn get_block_by_number(
//         &self,
//         height: u64,
//     ) -> impl std::future::Future<Output = eyre::Result<Option<Block>>> + Send {
//         (**self).get_block_by_number(height)
//     }

//     fn get_block_by_hash(
//         &self,
//         hash: alloy_primitives::B256,
//     ) -> impl std::future::Future<Output = eyre::Result<Option<Block>>> + Send {
//         (**self).get_block_by_hash(hash)
//     }
// }
