//! Actors to communicate with the upstream node.
//!
//! Maintains a regular connection to an upstream node over websocker
//! or `in_process::Actor` as an in-process actor working off of channels.

use alloy_rpc_client::BuiltInConnectionString;
use commonware_consensus::{Reporter, types::Height};
use commonware_runtime::{Clock, Metrics, Spawner};
use eyre::WrapErr as _;
use futures::{future::BoxFuture, stream::BoxStream};
use tempo_node::rpc::consensus::{CertifiedBlock, Event};
use url::Url;

use crate::consensus::{Block, Digest};

mod actor;
pub mod in_process;
mod ingress;

#[cfg(test)]
mod tests;

pub(crate) use actor::Actor;
pub use ingress::Mailbox;

pub(crate) type EventStream = BoxStream<'static, eyre::Result<Event>>;

pub(crate) trait Connector: Clone + Send + Sync + 'static {
    type Client: UpstreamClient;

    fn connect(&self, attempts: u64) -> BoxFuture<'static, (u64, eyre::Result<Self::Client>)>;

    fn endpoint(&self) -> &Url;
}

pub(crate) trait UpstreamClient: Clone + Send + Sync + 'static {
    fn is_connected(&self) -> bool;

    fn subscribe_events(&self) -> BoxFuture<'static, eyre::Result<EventStream>>;

    fn get_finalization(
        &self,
        height: Height,
    ) -> BoxFuture<'static, eyre::Result<Option<CertifiedBlock>>>;

    fn get_block(&self, digest: Digest) -> BoxFuture<'static, eyre::Result<Option<Block>>>;
}

/// An actor that can be started with reporters that receive consensus RPC events.
pub trait UpstreamActor: Send + 'static {
    fn start(self, reporter: impl Reporter<Activity = Event>) -> commonware_runtime::Handle<()>;
}

impl<TContext, TConnector> UpstreamActor for Actor<TContext, TConnector>
where
    TContext: Clock + Metrics + Spawner,
    TConnector: Connector,
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
) -> eyre::Result<(Actor<TContext>, ingress::Mailbox)> {
    let url = parse_upstream_url(&config.upstream_url).wrap_err_with(|| {
        format!(
            "failed parsing upstream location as websocket URL: `{}`",
            config.upstream_url
        )
    })?;
    Ok(actor::init(
        context,
        actor::WebSocketConnector::new(url),
        actor::random_jitter,
    ))
}

pub(crate) struct Config {
    /// The URL to connect to.
    pub(crate) upstream_url: String,
}

fn parse_upstream_url(url: &str) -> eyre::Result<Url> {
    let BuiltInConnectionString::Ws(url, _) = BuiltInConnectionString::try_as_ws(url)? else {
        unreachable!("try_as_ws always returns a websocket connection string on success")
    };
    Ok(url)
}
