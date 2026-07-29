//! Actors to communicate with the upstream node.
//!
//! Maintains a regular connection to an upstream node over websocker
//! or `in_process::Actor` as an in-process actor working off of channels.

use std::collections::VecDeque;

use alloy_rpc_client::BuiltInConnectionString;
use commonware_consensus::Reporter;
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner};
use eyre::WrapErr as _;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use tempo_node::rpc::consensus::Event;
use tokio::sync::mpsc;
use url::Url;

use crate::utils::OptionFuture;

mod actor;
pub mod in_process;
mod ingress;

pub(crate) use actor::Actor;
pub use ingress::Mailbox;

/// An actor that can be started with reporters that receive consensus RPC events.
pub trait UpstreamActor: Send + 'static {
    fn start(self, reporter: impl Reporter<Activity = Event>) -> commonware_runtime::Handle<()>;
}

impl<TContext> UpstreamActor for Actor<TContext>
where
    TContext: Clock + Metrics + Spawner,
{
    fn start(self, reporter: impl Reporter<Activity = Event>) -> commonware_runtime::Handle<()> {
        self.start(reporter)
    }
}

impl<TContext> UpstreamActor for in_process::Actor<TContext>
where
    TContext: Clock + Metrics + Spawner,
{
    fn start(self, reporter: impl Reporter<Activity = Event>) -> commonware_runtime::Handle<()> {
        self.start(reporter)
    }
}

pub(crate) fn init<TContext>(
    context: TContext,
    config: Config,
) -> eyre::Result<(Actor<TContext>, ingress::Mailbox)>
where
    TContext: Metrics,
{
    let (tx, rx) = mpsc::unbounded_channel();
    let mailbox = ingress::Mailbox::new(tx);

    let url = Box::leak(Box::from(
        parse_upstream_url(&config.upstream_url).wrap_err_with(|| {
            format!(
                "failed parsing upstream location as websocket URL: `{}`",
                config.upstream_url
            )
        })?,
    ));
    let waiters = Waiters::new(&context, config.max_waiters);
    let actor = Actor {
        context: ContextCell::new(context),
        connection: None,
        mailbox: rx,
        url,
        pending_connect: OptionFuture::none(),
        pending_stream: OptionFuture::none(),
        event_stream: actor::inactive_event_stream(),
        waiters,
    };

    Ok((actor, mailbox))
}

pub(crate) struct Config {
    /// The URL to connect to.
    pub(crate) upstream_url: String,
    /// Maximum number of pending upstream requests to retain before dropping the oldest.
    pub(crate) max_waiters: usize,
}

/// Bounded queue for requests that cannot be dispatched immediately.
///
/// Closed requests are pruned first; if the queue remains full, the oldest request is dropped.
struct Waiters {
    requests: VecDeque<ingress::Message>,
    capacity: usize,
    depth: Gauge,
    dropped: Counter,
}

impl Waiters {
    fn new(context: &impl Metrics, capacity: usize) -> Self {
        assert!(capacity > 0, "upstream waiter capacity must be non-zero");

        let depth = Gauge::default();
        context.register(
            "waiters_depth",
            "number of queued upstream requests",
            depth.clone(),
        );
        let dropped = Counter::default();
        context.register(
            "waiters_dropped",
            "number of upstream requests dropped because the waiter queue was full",
            dropped.clone(),
        );

        Self {
            requests: VecDeque::with_capacity(capacity),
            capacity,
            depth,
            dropped,
        }
    }

    fn push(&mut self, request: ingress::Message) {
        self.remove_closed();
        if self.requests.len() == self.capacity {
            self.requests.pop_front();
            self.dropped.inc();
        }
        self.requests.push_back(request);
        self.update_depth();
    }

    fn take(&mut self) -> VecDeque<ingress::Message> {
        self.remove_closed();
        let requests =
            std::mem::replace(&mut self.requests, VecDeque::with_capacity(self.capacity));
        self.update_depth();
        requests
    }

    fn remove_closed(&mut self) {
        self.requests
            .retain(|request| !request.response_is_closed());
    }

    fn update_depth(&self) {
        self.depth.set(self.requests.len() as i64);
    }
}

fn parse_upstream_url(url: &str) -> eyre::Result<Url> {
    let BuiltInConnectionString::Ws(url, _) = BuiltInConnectionString::try_as_ws(url)? else {
        unreachable!("try_as_ws always returns a websocket connection string on success")
    };
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::Digest;
    use alloy_primitives::B256;
    use commonware_runtime::{Runner as _, deterministic};
    use tokio::sync::oneshot::error::TryRecvError;

    #[test]
    fn parse_upstream_url_preserves_explicit_url() {
        assert_eq!(
            parse_upstream_url("wss://upstream.example:8546")
                .unwrap()
                .to_string(),
            "wss://upstream.example:8546/"
        );
    }

    #[test]
    fn parse_upstream_url_prefixes_localhost_and_socketaddr() {
        assert_eq!(
            parse_upstream_url("localhost:8546").unwrap().to_string(),
            "ws://localhost:8546/"
        );
        assert_eq!(
            parse_upstream_url("127.0.0.1:8546").unwrap().to_string(),
            "ws://127.0.0.1:8546/"
        );
    }

    #[test]
    fn parse_upstream_url_rejects_non_ws_schemes() {
        assert!(parse_upstream_url("http://upstream.example:8546").is_err());
    }

    #[test]
    fn parse_upstream_url_rejects_non_url_values() {
        assert!(parse_upstream_url("not a url").is_err());
        assert!(parse_upstream_url("localhost").is_err());
    }

    #[test]
    fn waiters_drop_the_oldest_request_at_capacity() {
        deterministic::Runner::default().start(|context| async move {
            let mut waiters = Waiters::new(&context, 2);
            let (first_response, first_receiver) = tokio::sync::oneshot::channel();
            let (second_response, mut second_receiver) = tokio::sync::oneshot::channel();
            let (third_response, mut third_receiver) = tokio::sync::oneshot::channel();

            waiters.push(ingress::Message::GetBlock {
                digest: Digest(B256::with_last_byte(1)),
                response: first_response,
            });
            waiters.push(ingress::Message::GetBlock {
                digest: Digest(B256::with_last_byte(2)),
                response: second_response,
            });
            waiters.push(ingress::Message::GetBlock {
                digest: Digest(B256::with_last_byte(3)),
                response: third_response,
            });

            assert!(first_receiver.await.is_err());
            assert!(matches!(
                second_receiver.try_recv(),
                Err(TryRecvError::Empty)
            ));
            assert!(matches!(
                third_receiver.try_recv(),
                Err(TryRecvError::Empty)
            ));

            let metrics = context.encode();
            assert!(metrics.lines().any(|line| line == "waiters_depth 2"));
            assert!(
                metrics
                    .lines()
                    .any(|line| line == "waiters_dropped_total 1")
            );
        });
    }
}
