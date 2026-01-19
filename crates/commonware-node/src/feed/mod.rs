//! Feed module for consensus event tracking and RPC.
//!
//! Architecture:
//! - `Mailbox` implements `Reporter` and sends Activity to the actor
//! - `Actor` processes Activity and updates shared [`FeedStateHandle`]
//! - [`FeedStateHandle`] implements `ConsensusFeed` for RPC access
//!
//! This design ensures RPC traffic cannot block consensus activity processing.

mod actor;
mod ingress;
mod state;

use commonware_runtime::Spawner;
use futures::channel::mpsc;

use crate::{alias::marshal, epoch::SchemeProvider};
pub(crate) use actor::Actor;
pub(crate) use ingress::Mailbox;
pub use state::FeedStateHandle;

/// Initialize the feed actor and mailbox.
pub(crate) fn init<TContext: Spawner>(
    context: TContext,
    marshal: marshal::Mailbox,
    state: FeedStateHandle,
    scheme_provider: SchemeProvider,
) -> (Actor<TContext>, Mailbox) {
    let (tx, rx) = mpsc::unbounded();
    let mailbox = Mailbox::new(tx);
    let actor = Actor::new(context, marshal, rx, state, scheme_provider);
    (actor, mailbox)
}
