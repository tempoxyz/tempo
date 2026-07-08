use std::{sync::Arc, time::Duration};

use alloy_primitives::B256;
use alloy_rpc_client::{RpcClient, WsConnect};
use alloy_transport::{RpcError, TransportError};
use commonware_consensus::{Reporter, types::Height};
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner, spawn_cell};
use eyre::{Report, WrapErr as _};
use futures::{
    FutureExt as _, StreamExt as _,
    future::{BoxFuture, Either},
    stream::{self, Fuse, FusedStream},
};
use rand_08::Rng as _;
use tempo_node::rpc::consensus::{CertifiedBlock, Event, Query};
use tempo_telemetry_util::display_duration;
use tokio::{
    select,
    sync::{mpsc, oneshot},
};
use tracing::{debug, debug_span, instrument, warn, warn_span};
use url::Url;

use crate::utils::OptionFuture;

pub(super) type EventStream =
    Either<stream::Empty<serde_json::Result<Event>>, Fuse<alloy_pubsub::SubResultStream<Event>>>;
type SubscriptionAttempt = (
    u64,
    Result<alloy_pubsub::Subscription<Event>, TransportError>,
);

const FEED_RETRY_BACKOFF_FACTOR: u64 = 2;
const FEED_RETRY_MAX_BACKOFF: Duration = Duration::from_secs(20);
const FEED_RETRY_JITTER: Duration = Duration::from_secs(1);

/// Manages the connection to the upstream node.
///
/// Establishes the upstream event feed and forwards consensus events. After the
/// feed is active, reconnects and resubscription are handled by the RPC layer.
pub(crate) struct Actor<TContext> {
    pub(super) context: ContextCell<TContext>,
    pub(super) connection: Option<Arc<RpcClient>>,
    pub(super) mailbox: mpsc::UnboundedReceiver<super::ingress::Message>,
    pub(super) url: &'static Url,
    pub(super) pending_connect:
        OptionFuture<BoxFuture<'static, (u64, Result<RpcClient, TransportError>)>>,
    pub(super) pending_stream: OptionFuture<BoxFuture<'static, SubscriptionAttempt>>,
    pub(super) event_stream: EventStream,
    /// Requests for blocks while the actor is trying to establish the feed.
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
            self.ensure_feed();
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
                            if is_non_retryable(&reason) {
                                warn_span!("feed_retry").in_scope(|| warn!(
                                    %reason,
                                    url = %self.url,
                                    "starting upstream event feed failed permanently; stopping",
                                ));
                                return;
                            }

                            let retry_in = feed_retry_delay(attempts);
                            warn_span!("feed_retry").in_scope(|| warn!(
                                %reason,
                                attempts,
                                retry_in = %display_duration(retry_in),
                                url = %self.url,
                                "starting upstream event feed failed, retrying",
                            ));
                            self.pending_connect.replace({
                                let context = self.context.clone();
                                let url = self.url;
                                async move {
                                    context.sleep(retry_in).await;
                                    connect(url, attempts.saturating_add(1)).await
                                }.boxed()
                            });
                        }
                    }
                }

                (attempts, stream) = &mut self.pending_stream => {
                    match stream {
                        Ok(stream) => {
                        debug_span!("consensus_event_subscription")
                            .in_scope(|| debug!("subscription for consensus events established"));
                            self.event_stream = active_event_stream(stream);
                        }
                        Err(error) => {
                            if is_non_retryable(&error) {
                                warn_span!("event_subscription").in_scope(|| warn!(
                                    reason = %Report::new(error),
                                    "subscribing to upstream events failed permanently; stopping"
                                ));
                                return;
                            }

                            let retry_in = feed_retry_delay(attempts);
                            warn_span!("event_subscription").in_scope(|| warn!(
                                reason = %Report::new(error),
                                attempts,
                                retry_in = %display_duration(retry_in),
                                "failed subscribing to upstream events; retrying"
                            ));
                            self.event_stream = inactive_event_stream();
                            if let Some(client) = self.connection.clone() {
                                self.pending_stream.replace({
                                    let context = self.context.clone();
                                    async move {
                                        context.sleep(retry_in).await;
                                        subscribe(client, attempts.saturating_add(1)).await
                                    }.boxed()
                                });
                            }
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
    fn ensure_feed(&mut self) {
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

        self.pending_stream.replace(subscribe(client, 1));
    }

    /// Drains the waiters by fetching the finalizations they are waiting for.
    ///
    /// Only executes after the upstream event feed is active.
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

        for (height, response) in self.waiters.drain(..) {
            let client = client.clone();
            self.context
                .with_label("get_finalization")
                .spawn(move |_| get_finalization(client, height, response));
        }
    }
}

fn connect(
    url: &'static Url,
    attempts: u64,
) -> BoxFuture<'static, (u64, Result<RpcClient, TransportError>)> {
    async move {
        (
            attempts,
            RpcClient::connect_pubsub(WsConnect::new(url.to_string()).with_max_retries(u32::MAX))
                .await,
        )
    }
    .boxed()
}

fn subscribe(client: Arc<RpcClient>, attempts: u64) -> BoxFuture<'static, SubscriptionAttempt> {
    async move {
        let mut subscription = client.request_noparams("consensus_subscribe");
        subscription.set_is_subscription();

        let result = async {
            let subscription_id: B256 = subscription.await?;
            Ok(client.get_subscription(subscription_id).await)
        }
        .await;

        (attempts, result)
    }
    .boxed()
}

pub(super) fn inactive_event_stream() -> EventStream {
    Either::Left(stream::empty())
}

fn active_event_stream(stream: alloy_pubsub::Subscription<Event>) -> EventStream {
    Either::Right(stream.into_result_stream().fuse())
}

fn is_non_retryable(error: &TransportError) -> bool {
    matches!(error, RpcError::Transport(kind) if kind.is_non_retryable())
}

fn feed_retry_delay(attempts: u64) -> Duration {
    feed_retry_backoff(attempts) + random_jitter()
}

fn feed_retry_backoff(attempts: u64) -> Duration {
    let backoff_secs = attempts.saturating_mul(FEED_RETRY_BACKOFF_FACTOR);
    let backoff = Duration::from_secs(backoff_secs);

    backoff.min(FEED_RETRY_MAX_BACKOFF)
}

fn random_jitter() -> Duration {
    let max_jitter_millis = FEED_RETRY_JITTER.as_millis() as u64;
    Duration::from_millis(rand_08::thread_rng().gen_range(0..=max_jitter_millis))
}

#[instrument(skip_all, fields(%height), err)]
async fn get_finalization(
    client: Arc<RpcClient>,
    height: Height,
    response: oneshot::Sender<Option<CertifiedBlock>>,
) -> eyre::Result<()> {
    // TODO: right now, the response channel would just drop and an error
    // emitted here. Should this failure be propagated upstream?
    let finalization = client
        .request("consensus_getFinalization", (Query::Height(height.get()),))
        .await
        .wrap_err("failed getting finalization")?;
    response
        .send(Some(finalization))
        .map_err(|_| eyre::eyre!("receiver went away"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feed_retry_backoff_linearly_increases_and_caps() {
        assert_eq!(feed_retry_backoff(0), Duration::from_secs(0));
        assert_eq!(feed_retry_backoff(1), Duration::from_secs(2));
        assert_eq!(feed_retry_backoff(2), Duration::from_secs(4));
        assert_eq!(feed_retry_backoff(3), Duration::from_secs(6));
        assert_eq!(feed_retry_backoff(4), Duration::from_secs(8));
        assert_eq!(feed_retry_backoff(5), Duration::from_secs(10));
        assert_eq!(feed_retry_backoff(10), FEED_RETRY_MAX_BACKOFF);
        assert_eq!(feed_retry_backoff(u64::MAX), FEED_RETRY_MAX_BACKOFF);
    }
}
