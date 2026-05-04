//! Actors to communicate with the upstream node.
//!
//! Provides [`Actor`] as a regular connection to an upstream node over
//! websocket, and `in_process::Actor` as an in-process actor working off of
//! channels.

use commonware_consensus::Reporter;
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner};
use futures::{stream, stream::StreamExt as _};
use tempo_node::rpc::consensus::Event;
use tokio::sync::mpsc;

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
) -> (Actor<TContext>, ingress::Mailbox) {
    let (tx, rx) = mpsc::unbounded_channel();
    let mailbox = ingress::Mailbox::new(tx);

    let url = Box::leak(Box::<str>::from(config.upstream_url));
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

pub(crate) struct Config {
    /// The URL to connect to.
    pub(crate) upstream_url: String,
}
