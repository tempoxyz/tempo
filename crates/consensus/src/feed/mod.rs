//! Feed module for consensus event tracking and RPC.
//!
//! Architecture:
//! - `Mailbox` implements `Reporter` for marshal updates, forwards finalized
//!   tips, and immediately acknowledges gap-free block updates
//! - `Actor` resolves and publishes finalized tips and updates shared
//!   [`FeedStateHandle`]
//! - [`FeedStateHandle`] implements `ConsensusFeed` for RPC access
//!
//! This design ensures RPC traffic cannot block consensus activity processing.

mod actor;
mod ingress;
mod state;

use commonware_runtime::Spawner;
use futures::channel::mpsc;

use crate::alias::marshal;
pub(crate) use actor::Actor;
pub(crate) use ingress::Mailbox;
pub use state::FeedStateHandle;

/// Initialize the feed actor and mailbox.
pub(crate) fn init<TContext: Spawner>(
    context: TContext,
    marshal: marshal::Mailbox,
    state: FeedStateHandle,
) -> (Actor<TContext>, Mailbox) {
    let (tx, rx) = mpsc::unbounded();
    let mailbox = Mailbox::new(tx);
    let actor = Actor::new(context, marshal, rx, state);
    (actor, mailbox)
}
