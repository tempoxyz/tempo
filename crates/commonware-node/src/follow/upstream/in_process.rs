use std::{sync::Arc, time::Duration};

use commonware_consensus::{Reporter, types::Height};
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner, spawn_cell};
use eyre::OptionExt as _;
use futures::{
    FutureExt as _, StreamExt as _,
    stream::{self, BoxStream, Fuse},
};
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

use crate::{feed::FeedStateHandle, utils::OptionFuture};

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

    waiters: Vec<(Height, oneshot::Sender<Option<CertifiedBlock>>)>,
}

impl<TContext> Actor<TContext>
where
    TContext: Clock + Metrics + Spawner,
{
    pub(crate) fn start(
        mut self,
        reporter: impl Reporter<Activity = Event>,
    ) -> commonware_runtime::Handle<()> {
        spawn_cell!(self.context, self.run(reporter).await)
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
                        "received consensus event, forwarding to reporter"
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

                Some(msg) = self.mailbox.recv() => {
                    match msg {
                        super::ingress::Message::GetFinalization { height, response, } => {
                            self.waiters.push((height, response));
                        }
                    }
                }
            );
            if connected {
                for (height, response) in self.waiters.drain(..) {
                    let feed = self.config.feed.clone();
                    self.context
                        .with_label("get_finalization")
                        .spawn(move |_| get_finalization(feed, height, response));
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
    let finalization = client
        .get_finalization(Query::Height(height.get()))
        .await
        .ok_or_eyre("failed getting finalization because feed state was not connected")?;
    response
        .send(Some(finalization))
        .map_err(|_| eyre::eyre!("receiver went away"))
}
