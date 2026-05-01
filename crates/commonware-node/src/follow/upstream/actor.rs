use std::{sync::Arc, time::Duration};

use commonware_consensus::{Reporter, types::Height};
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner, spawn_cell};
use eyre::{Report, WrapErr as _};
use futures::{
    FutureExt as _, StreamExt as _,
    future::BoxFuture,
    stream::{BoxStream, Fuse},
};
use jsonrpsee::{
    core::{client, client::Subscription},
    ws_client::{WsClient, WsClientBuilder},
};
use tempo_node::rpc::consensus::{CertifiedBlock, Event, Query, TempoConsensusApiClient};
use tempo_telemetry_util::display_duration;
use tokio::{
    select,
    sync::{mpsc, oneshot},
};
use tracing::{debug, debug_span, instrument, warn, warn_span};

use crate::utils::OptionFuture;

type EventStream = Fuse<BoxStream<'static, Result<Event, serde_json::Error>>>;

/// Manages the connection to the upstream node.
///
/// This actor holds the websocket connection to the upstream node, reconnecting
/// it if necessary.
pub(crate) struct Actor<TContext> {
    pub(super) context: ContextCell<TContext>,
    pub(super) connection: Option<Arc<WsClient>>,
    pub(super) mailbox: mpsc::UnboundedReceiver<super::ingress::Message>,
    pub(super) url: &'static str,
    pub(super) pending_connect: OptionFuture<BoxFuture<'static, (u64, eyre::Result<WsClient>)>>,
    pub(super) pending_stream:
        OptionFuture<BoxFuture<'static, Result<Subscription<Event>, client::Error>>>,
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
                        Ok(stream) => {
                        debug_span!("consensus_event_subscription")
                            .in_scope(|| debug!("subscription for consensus events established"));
                            self.event_stream = stream.boxed().fuse();
                        }
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
                    debug_span!("consensus_event").in_scope(|| debug!(
                        "received consensus event, forwarding to reporter"
                    ));
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
                        super::ingress::Message::GetFinalization { height, response, } => {
                            self.waiters.push((height, response));
                        }
                    }
                }
            );

            if let Some(client) = &self.connection {
                for (height, response) in self.waiters.drain(..) {
                    let client = client.clone();
                    self.context
                        .with_label("get_finalization")
                        .spawn(move |_| get_finalization(client, height, response));
                }
            }
        }
    }
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
        .send(finalization)
        .map_err(|_| eyre::eyre!("receiver went away"))
}
