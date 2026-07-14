//! An upstream provider to be used in e2e tests The [`jsonrpsee`] stack used by
//! the standard websocket based provider requires a tokio runtime, which the tests
//! runtime does not provide.

use std::{sync::Arc, time::Duration};

use commonware_consensus::{Reporter, types::Height};
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner, spawn_cell};
use futures::{
    FutureExt as _, StreamExt as _,
    stream::{self, BoxStream, Fuse},
};
use reth_provider::{BlockReader as _, BlockSource};
use tempo_node::{
    TempoFullNode,
    rpc::consensus::{CertifiedBlock, ConsensusFeed as _, Event, Query},
};
use tokio::{
    select,
    sync::{mpsc, oneshot},
};
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tracing::{debug, debug_span, info, instrument};

use crate::{
    consensus::{Block, Digest},
    feed::FeedStateHandle,
    utils::OptionFuture,
};

use super::ingress::{Mailbox, Message};

pub struct Config {
    pub execution_node: Arc<TempoFullNode>,
    pub feed: FeedStateHandle,
}

pub fn init<TContext>(context: TContext, config: Config) -> (Actor<TContext>, Mailbox) {
    let (tx, rx) = mpsc::unbounded_channel();
    let mailbox = Mailbox::new(tx);

    let actor = Actor {
        context: ContextCell::new(context),
        config,
        event_stream: stream::empty::<Result<Event, BroadcastStreamRecvError>>()
            .boxed()
            .fuse(),
        mailbox: rx,
        waiters: Vec::new(),
    };
    (actor, mailbox)
}

pub struct Actor<TContext> {
    context: ContextCell<TContext>,
    config: Config,
    event_stream: Fuse<BoxStream<'static, Result<Event, BroadcastStreamRecvError>>>,
    mailbox: mpsc::UnboundedReceiver<Message>,
    waiters: Vec<Message>,
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
        let feed = self.config.feed.clone();
        let context = self.context.clone();
        let mut pending_subscription = OptionFuture::some(
            async move {
                loop {
                    if let Some(subscription) = feed.subscribe().await {
                        break subscription;
                    }
                    info!("feed state not yet ready, retrying in 1s");
                    context.sleep(Duration::from_secs(1)).await;
                }
            }
            .boxed(),
        );
        let mut connected = false;
        loop {
            select!(
                biased;

                stream = &mut pending_subscription, if pending_subscription.is_some() => {
                    debug_span!("consensus_event_subscription")
                        .in_scope(|| debug!("subscription for consensus events established"));
                    self.event_stream = tokio_stream::wrappers::BroadcastStream::new(stream).boxed().fuse();
                    connected = true;
                }

                Some(event) = self.event_stream.next() => {
                    debug_span!("consensus_event").in_scope(|| debug!(
                        ?event, "received consensus event, forwarding to reporter"
                    ));
                    match event {
                        Ok(event) => reporter.report(event).await,
                        Err(BroadcastStreamRecvError::Lagged(events_skipped)) => {
                            debug_span!("subscription").in_scope(|| debug!(
                                events_skipped,
                                "lagged behind and skipped some events",
                            ));
                        },
                    }
                }

                Some(request) = self.mailbox.recv() => {
                    self.waiters.push(request);
                }
            );
            if connected {
                for request in self.waiters.drain(..) {
                    match request {
                        Message::GetFinalization { height, response } => {
                            let feed = self.config.feed.clone();
                            self.context
                                .with_label("get_finalization")
                                .spawn(move |_| get_finalization(feed, height, response));
                        }
                        Message::GetBlock { digest, response } => {
                            let execution_node = self.config.execution_node.clone();
                            self.context
                                .with_label("get_block")
                                .spawn(move |_| get_block(execution_node, digest, response));
                        }
                    }
                }
            }
        }
    }
}

#[instrument(skip_all, fields(%height), err)]
async fn get_finalization(
    client: FeedStateHandle,
    height: Height,
    response: oneshot::Sender<Option<CertifiedBlock>>,
) -> eyre::Result<()> {
    // TODO: right now, the response channel would just drop and an error
    // emitted here. Should this failure be propagated upstream?
    let finalization = match client.get_finalization(Query::Height(height.get())).await {
        tempo_node::rpc::consensus::types::Response::Success(val) => Some(val),
        tempo_node::rpc::consensus::types::Response::NotReady => {
            panic!("for in-process execution the feed should be immediately available")
        }
        tempo_node::rpc::consensus::types::Response::Missing(_) => None,
    };
    response
        .send(finalization)
        .map_err(|_| eyre::eyre!("receiver went away"))
}

#[instrument(skip_all, fields(%digest), err)]
async fn get_block(
    execution_node: Arc<TempoFullNode>,
    digest: Digest,
    response: oneshot::Sender<Option<Block>>,
) -> eyre::Result<()> {
    let block = execution_node
        .provider
        .find_sealed_or_recovered_block(digest.0, BlockSource::Any)
        .map_err(eyre::Report::new)?
        .map(|block| Block::from_execution_block_unchecked(block, None));
    response
        .send(block)
        .map_err(|_| eyre::eyre!("receiver went away"))
}
