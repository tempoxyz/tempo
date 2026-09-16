//! An upstream provider to be used in e2e tests The [`jsonrpsee`] stack used by
//! the standard websocket based provider requires a tokio runtime, which the tests
//! runtime does not provide.

use std::sync::Arc;

use tempo_node::TempoFullNode;
use tokio::sync::mpsc;

use crate::feed::FeedStateHandle;

use super::ingress::Mailbox;

mod actor;

pub use actor::Actor;

pub struct Config {
    pub execution_node: Arc<TempoFullNode>,
    pub feed: FeedStateHandle,
}

pub fn init<TContext>(context: TContext, config: Config) -> (Actor<TContext>, Mailbox) {
    let (tx, rx) = mpsc::unbounded_channel();
    let mailbox = Mailbox::new(tx);
    let actor = Actor::new(context, config, rx);
    (actor, mailbox)
}
