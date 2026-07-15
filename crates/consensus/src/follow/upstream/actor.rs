use std::{pin::Pin, sync::Arc, time::Duration};

use alloy_primitives::B256;
use alloy_rpc_client::{ClientBuilder, RpcClient, WsConnect};
use alloy_rpc_types_eth::{Block as RpcBlock, Transaction};
use commonware_consensus::{Reporter, types::Height};
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner, spawn_cell};
use eyre::{Report, WrapErr as _, ensure};
use futures::{FutureExt as _, Stream, StreamExt as _, future::BoxFuture, stream};
use reth_primitives_traits::{SealedBlock, SealedOrRecoveredBlock};
use tempo_node::rpc::consensus::{CertifiedBlock, Event, Query};
use tempo_primitives::{TempoHeader, TempoTxEnvelope};
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

type EventStream = Pin<Box<dyn Stream<Item = Event> + Send>>;

/// Alloy sends a ping after this period without outbound traffic. If the peer
/// does not pong before the next interval, Alloy closes and reconnects the
/// transport, then replays pending requests and active subscriptions.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
const RECONNECT_RETRY_INTERVAL: Duration = Duration::from_secs(2);

struct Connected {
    client: Arc<RpcClient>,
    events: EventStream,
}

/// Manages communication with the upstream node.
///
/// Alloy owns websocket keepalive, reconnects, pending-request replay, and
/// resubscription. This actor only establishes the initial client and forwards
/// requests and subscription events.
pub(crate) struct Actor<TContext> {
    pub(super) context: ContextCell<TContext>,
    client: Option<Arc<RpcClient>>,
    pub(super) mailbox: mpsc::UnboundedReceiver<super::ingress::Message>,
    pub(super) url: Url,
    pending_connect: OptionFuture<BoxFuture<'static, eyre::Result<Connected>>>,
    event_stream: EventStream,
    /// Requests waiting for the initial connection.
    pub(super) waiters: Vec<super::ingress::Message>,
}

impl<TContext> Actor<TContext>
where
    TContext: Clock + Metrics + Spawner,
{
    pub(crate) fn new(
        context: ContextCell<TContext>,
        mailbox: mpsc::UnboundedReceiver<super::ingress::Message>,
        url: Url,
    ) -> Self {
        Self {
            context,
            client: None,
            mailbox,
            url,
            pending_connect: OptionFuture::none(),
            event_stream: inactive_event_stream(),
            waiters: Vec::new(),
        }
    }

    pub(crate) fn start(
        mut self,
        reporter: impl Reporter<Activity = Event>,
    ) -> commonware_runtime::Handle<()> {
        spawn_cell!(self.context, self.run(reporter))
    }

    async fn run(mut self, mut reporter: impl Reporter<Activity = Event>) {
        loop {
            self.ensure_connected();
            self.drain_waiters();

            select!(
                biased;

                connected = &mut self.pending_connect => {
                    match connected {
                        Ok(connected) => {
                            debug_span!("consensus_event_subscription")
                                .in_scope(|| debug!("connected and subscribed to upstream node"));
                            self.client = Some(connected.client);
                            self.event_stream = connected.events;
                        }
                        Err(reason) => {
                            warn_span!("connect").in_scope(|| warn!(
                                %reason,
                                url = %self.url,
                                "connecting to upstream node failed, attempting again",
                            ));
                        }
                    }
                }

                event = self.event_stream.next() => {
                    match event {
                        Some(event) => {
                            debug_span!("consensus_event").in_scope(|| debug!(
                                ?event, "received consensus event, forwarding to reporter"
                            ));
                            reporter.report(event).await;
                        }
                        None => {
                            warn!(url = %self.url, "upstream subscription terminated");
                            self.client = None;
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

    fn ensure_connected(&mut self) {
        if self.client.is_some() || self.pending_connect.is_some() {
            return;
        }

        let url = self.url.clone();
        let context = self.context.clone();
        self.pending_connect.replace(
            async move {
                loop {
                    match connect(url.clone()).await {
                        Ok(connected) => return Ok(connected),
                        Err(error) => {
                            warn!(%error, %url, "initial upstream connection failed; retrying");
                            context.sleep(RECONNECT_RETRY_INTERVAL).await;
                        }
                    }
                }
            }
            .boxed(),
        );
    }

    fn drain_waiters(&mut self) {
        let Some(client) = &self.client else {
            return;
        };

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

async fn connect(url: Url) -> eyre::Result<Connected> {
    let connector = WsConnect::new(url.to_string())
        .with_keepalive_interval(KEEPALIVE_INTERVAL)
        .with_retry_interval(RECONNECT_RETRY_INTERVAL)
        .with_max_retries(u32::MAX);
    let client = Arc::new(
        ClientBuilder::default()
            .ws(connector)
            .await
            .map_err(Report::new)?,
    );

    let mut call = client.request_noparams::<B256>("consensus_subscribe");
    call.set_is_subscription();
    let subscription_id = call.await.map_err(Report::new)?;
    let subscription = client.get_subscription::<Event>(subscription_id).await;

    Ok(Connected {
        client,
        events: Box::pin(subscription.into_stream()),
    })
}

fn inactive_event_stream() -> EventStream {
    Box::pin(stream::pending())
}

#[instrument(skip_all, fields(%height), err)]
async fn get_finalization(
    client: Arc<RpcClient>,
    height: Height,
    response: oneshot::Sender<Option<CertifiedBlock>>,
) -> eyre::Result<()> {
    let finalization = client
        .request("consensus_getFinalization", (Query::Height(height.get()),))
        .await
        .wrap_err("failed getting finalization")?;
    response
        .send(Some(finalization))
        .map_err(|_| eyre::eyre!("receiver went away"))
}

/// Fetches a full consensus block from the upstream node.
#[instrument(skip_all, fields(%digest), err)]
async fn get_block(
    client: Arc<RpcClient>,
    digest: Digest,
    response: oneshot::Sender<Option<Block>>,
) -> eyre::Result<()> {
    let block = client
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
            Ok(Block::from_execution_block_unchecked(block, None))
        })
        .transpose()?;

    response
        .send(block)
        .map_err(|_| eyre::eyre!("receiver went away"))
}
