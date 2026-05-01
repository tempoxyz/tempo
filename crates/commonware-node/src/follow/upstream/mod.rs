//! Upstream node abstraction for follow mode.
//!
//! Defines the [`UpstreamNode`] trait that captures the operations the follow
//! engine needs from an upstream node, and provides two implementations:
//!
//! - [`WsUpstream`]: WebSocket RPC for production use.
//! - [`LocalUpstream`]: Direct access for testing network I/O.

use commonware_runtime::ContextCell;
use futures::stream;
use futures::stream::{BoxStream, StreamExt as _};
use jsonrpsee::core::client;
use tempo_node::rpc::consensus::{CertifiedBlock, Event, Query};
use tempo_primitives::Block;
use tokio::sync::mpsc;

use crate::utils::OptionFuture;

mod actor;
mod ingress;

pub(crate) use actor::Actor;
pub(crate) use ingress::Mailbox;

// type TempoRpcBlock =
//     AlloyRpcBlock<alloy_rpc_types_eth::Transaction<TempoTxEnvelope>, TempoHeaderResponse>;

// const RECONNECT_BASE_MS: u64 = 500;
// const RECONNECT_MAX_MS: u64 = 30_000;

pub(super) fn init<TContext>(
    context: TContext,
    config: Config,
) -> (Actor<TContext>, ingress::Mailbox) {
    let (tx, rx) = mpsc::unbounded_channel();
    let mailbox = ingress::Mailbox::new(tx);

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
