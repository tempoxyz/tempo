use std::{borrow::Cow, sync::Arc, time::Duration};

use alloy_provider::{Provider as _, RootProvider, WsConnect};
use alloy_rpc_client::{ClientBuilder, NoParams};
use commonware_consensus::{Reporter, types::Height};
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner, spawn_cell};
use eyre::{Report, WrapErr as _};
use futures::{
    FutureExt as _, StreamExt as _,
    future::{BoxFuture, Either},
    stream::{self, Fuse, FusedStream},
};
use tempo_node::rpc::consensus::{CertifiedBlock, Event, Query};
use tokio::{
    select,
    sync::{mpsc, oneshot},
};
use tracing::{debug, debug_span, instrument, warn, warn_span};

use crate::utils::OptionFuture;

pub(super) type EventStream =
    Either<stream::Empty<Event>, Fuse<alloy_pubsub::SubscriptionStream<Event>>>;

const RECONNECT_MAX_RETRIES: u32 = u32::MAX;
const RECONNECT_RETRY_INTERVAL: Duration = Duration::from_secs(2);

/// Manages the connection to the upstream node.
///
/// This actor holds the websocket connection to the upstream node, reconnecting
/// it if necessary.
pub(crate) struct Actor<TContext> {
    pub(super) context: ContextCell<TContext>,
    pub(super) connection: Option<Arc<RootProvider>>,
    pub(super) mailbox: mpsc::UnboundedReceiver<super::ingress::Message>,
    pub(super) url: &'static str,
    pub(super) pending_connect: OptionFuture<BoxFuture<'static, eyre::Result<RootProvider>>>,
    pub(super) pending_stream: OptionFuture<
        BoxFuture<'static, alloy_transport::TransportResult<alloy_pubsub::Subscription<Event>>>,
    >,
    pub(super) event_stream: EventStream,
    /// Requests for blocks while the actor is trying to establish a connection.
    pub(super) waiters: Vec<(Height, oneshot::Sender<Option<CertifiedBlock>>)>,
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

                client = &mut self.pending_connect => {
                    match client {
                        Ok(client) => {
                            let client = Arc::new(client);
                            self.connection.replace(client);
                        }
                        Err(reason) => {
                            warn_span!("reconnect").in_scope(|| warn!(
                                %reason,
                                url = self.url,
                                "connecting to upstream node failed",
                            ));
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
                        Some(event) => {
                            debug_span!("consensus_event").in_scope(|| debug!(
                                ?event, "received consensus event, forwarding to reporter"
                            ));
                            reporter.report(event).await;
                        }
                        None => {
                            warn_span!("event_subscription").in_scope(|| warn!(
                                url = self.url,
                                "event stream terminated",
                            ));
                            self.event_stream = inactive_event_stream();
                        }
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
        }
    }

    #[instrument(skip_all)]
    fn reconnect_or_resubscribe(&mut self) {
        if self.pending_connect.is_some() || self.pending_stream.is_some() {
            return;
        }

        let Some(client) = self.connection.clone() else {
            self.pending_connect.replace(connect(self.url));
            return;
        };

        if !self.event_stream.is_terminated() {
            return;
        }

        self.pending_stream.replace(subscribe(client));
    }

    /// Drains the waiters by fetching the finalizations they are waiting for.
    ///
    /// Only executes if a client is present and connected.
    fn drain_waiters(&mut self) {
        if self.pending_connect.is_some() || self.pending_stream.is_some() {
            return;
        }

        let Some(client) = &self.connection else {
            return;
        };
        for (height, response) in self.waiters.drain(..) {
            let client = client.clone();
            self.context
                .with_label("get_finalization")
                .spawn(move |_| get_finalization(client, height, response));
        }
    }
}

fn connect(url: &'static str) -> BoxFuture<'static, eyre::Result<RootProvider>> {
    async move {
        let ws = WsConnect::new(url)
            .with_max_retries(RECONNECT_MAX_RETRIES)
            .with_retry_interval(RECONNECT_RETRY_INTERVAL);
        ClientBuilder::default()
            .ws(ws)
            .await
            .map(RootProvider::new)
            .map_err(Report::new)
    }
    .boxed()
}

fn subscribe(
    client: Arc<RootProvider>,
) -> BoxFuture<'static, alloy_transport::TransportResult<alloy_pubsub::Subscription<Event>>> {
    async move {
        let id = client
            .raw_request(Cow::Borrowed("consensus_subscribe"), NoParams::default())
            .await?;
        client.get_subscription(id).await
    }
    .boxed()
}

pub(super) fn inactive_event_stream() -> EventStream {
    Either::Left(stream::empty())
}

fn active_event_stream(stream: alloy_pubsub::Subscription<Event>) -> EventStream {
    Either::Right(stream.into_stream().fuse())
}

#[instrument(skip_all, fields(%height), err)]
async fn get_finalization(
    client: Arc<RootProvider>,
    height: Height,
    response: oneshot::Sender<Option<CertifiedBlock>>,
) -> eyre::Result<()> {
    // TODO: right now, the response channel would just drop and an error
    // emitted here. Should this failure be propagated upstream?
    let finalization = client
        .raw_request(
            Cow::Borrowed("consensus_getFinalization"),
            (Query::Height(height.get()),),
        )
        .await
        .wrap_err("failed getting finalization")?;
    response
        .send(Some(finalization))
        .map_err(|_| eyre::eyre!("receiver went away"))
}
