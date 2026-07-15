use std::{sync::Arc, time::Duration};

use alloy_rpc_types_eth::{Block as RpcBlock, Transaction};
use commonware_consensus::{Reporter, types::Height};
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner, spawn_cell};
use eyre::{Report, WrapErr as _, ensure};
use futures::{
    FutureExt as _, StreamExt as _,
    future::{BoxFuture, Either},
    stream::{self, Fuse, FusedStream},
};
use jsonrpsee::{
    core::{
        client,
        client::{ClientT as _, Subscription},
    },
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

pub(super) type EventStream =
    Either<stream::Empty<Result<Event, serde_json::Error>>, Fuse<Subscription<Event>>>;

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
pub(crate) struct Actor<TContext> {
    pub(super) context: ContextCell<TContext>,
    pub(super) connection: Option<Arc<WsClient>>,
    pub(super) mailbox: mpsc::UnboundedReceiver<super::ingress::Message>,
    pub(super) url: &'static Url,
    pub(super) pending_connect: OptionFuture<BoxFuture<'static, (u64, eyre::Result<WsClient>)>>,
    pub(super) pending_stream:
        OptionFuture<BoxFuture<'static, Result<Subscription<Event>, client::Error>>>,
    pub(super) event_stream: EventStream,
    /// Requests waiting for the actor to establish a connection.
    pub(super) waiters: Vec<super::ingress::Message>,
}

impl<TContext> Actor<TContext>
where
    TContext: Clock + Metrics + Spawner,
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
                    match client {
                        Ok(client) => {
                            let client = Arc::new(client);
                            self.connection.replace(client);
                        }
                        Err(reason) => {
                            let reconnect_in = reconnect_delay(attempts);
                            warn_span!("reconnect").in_scope(|| warn!(
                                %reason,
                                attempts,
                                reconnect_in = %display_duration(reconnect_in),
                                url = %self.url,
                                "connecting to upstream node failed, attempting again",
                            ));
                            self.pending_connect.replace({
                                let context = self.context.clone();
                                let url = self.url;
                                async move {
                                    context.sleep(reconnect_in).await;
                                    connect(url, attempts.saturating_add(1)).await
                                }.boxed()
                            });
                        }
                    }
                }

                stream = &mut self.pending_stream => {
                    match stream {
                        Ok(stream) => {
                        debug_span!("consensus_event_subscription")
                            .in_scope(|| debug!("subscription for consensus events established"));
                            self.event_stream = active_event_stream(stream);
                        }
                        Err(error) => {
                            warn_span!("event_subscription").in_scope(|| warn!(
                                reason = %Report::new(error),
                                "failed subscribing to events; reconnecting to upstream node"
                            ));
                            self.connection.take();
                            self.event_stream = inactive_event_stream();
                        }
                    }
                }

                event = self.event_stream.next(), if !self.event_stream.is_terminated() => {
                    match event {
                        Some(Ok(event)) => {
                            debug_span!("consensus_event").in_scope(|| debug!(
                                ?event, "received consensus event, forwarding to reporter"
                            ));
                            reporter.report(event).await;
                        }
                        Some(Err(error)) => {
                            warn_span!("event").in_scope(|| warn!(
                                %error,
                                "event stream encountered an error",
                            ));
                            self.event_stream = inactive_event_stream();
                        }
                        None => {
                            warn_span!("event_subscription").in_scope(|| warn!(
                                url = %self.url,
                                "event stream terminated",
                            ));
                            self.event_stream = inactive_event_stream();
                        }
                    }
                }

                Some(request) = self.mailbox.recv() => {
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
            self.pending_connect.replace(connect(self.url, 1));
            return;
        };

        if !self.event_stream.is_terminated() {
            return;
        }

        if client.is_connected() {
            self.pending_stream.replace(subscribe(client));
        } else {
            warn!(url = %self.url, "upstream client disconnected, reconnecting");
            self.connection.take();
            self.pending_connect.replace(connect(self.url, 1));
        }
    }

    /// Drains the waiters by fetching the data they are waiting for.
    ///
    /// Only executes if a client is present and connected.
    fn drain_waiters(&mut self) {
        if self.pending_connect.is_some()
            || self.pending_stream.is_some()
            || self.event_stream.is_terminated()
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
                    self.context
                        .with_label("get_finalization")
                        .spawn(move |_| get_finalization(client, height, response));
                }
                super::ingress::Message::GetBlock { digest, response } => {
                    let client = client.clone();
                    self.context
                        .with_label("get_block")
                        .spawn(move |_| get_block(client, digest, response));
                }
            }
        }
    }
}

fn connect(url: &'static Url, attempts: u64) -> BoxFuture<'static, (u64, eyre::Result<WsClient>)> {
    async move {
        (
            attempts,
            WsClientBuilder::default()
                .enable_ws_ping(
                    PingConfig::new()
                        .ping_interval(PING_INTERVAL)
                        .inactive_limit(PING_INACTIVE_LIMIT)
                        .max_failures(PING_MAX_FAILURES),
                )
                .build(url)
                .await
                .map_err(Report::new),
        )
    }
    .boxed()
}

fn subscribe(
    client: Arc<WsClient>,
) -> BoxFuture<'static, Result<Subscription<Event>, client::Error>> {
    async move { client.subscribe_events().await }.boxed()
}

pub(super) fn inactive_event_stream() -> EventStream {
    Either::Left(stream::empty())
}

fn active_event_stream(stream: Subscription<Event>) -> EventStream {
    Either::Right(stream.fuse())
}

fn reconnect_delay(attempts: u64) -> Duration {
    reconnect_backoff(attempts) + random_jitter()
}

fn reconnect_backoff(attempts: u64) -> Duration {
    let backoff_secs = attempts.saturating_mul(RECONNECT_BACKOFF_FACTOR);
    let backoff = Duration::from_secs(backoff_secs);

    backoff.min(RECONNECT_MAX_BACKOFF)
}

fn random_jitter() -> Duration {
    let max_jitter_millis = RECONNECT_JITTER.as_millis() as u64;
    Duration::from_millis(rand_08::thread_rng().gen_range(0..=max_jitter_millis))
}

#[instrument(skip_all, fields(%height), err)]
async fn get_finalization(
    client: Arc<WsClient>,
    height: Height,
    response: oneshot::Sender<Option<CertifiedBlock>>,
) -> eyre::Result<()> {
    // TODO: right now, the response channel would just drop and an error
    // emitted here. Should this failure be propagated upstream?
    let finalization = client
        .get_finalization(Query::Height(height.get()))
        .await
        .wrap_err("failed getting finalization")?;
    response
        .send(Some(finalization))
        .map_err(|_| eyre::eyre!("receiver went away"))
}

/// Fetches a full consensus block from the upstream node.
#[instrument(skip_all, fields(%digest), err)]
async fn get_block(
    client: Arc<WsClient>,
    digest: Digest,
    response: oneshot::Sender<Option<Block>>,
) -> eyre::Result<()> {
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
            Ok(Block::from_execution_block_unchecked(block, None))
        })
        .transpose()?;

    response
        .send(block)
        .map_err(|_| eyre::eyre!("receiver went away"))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
