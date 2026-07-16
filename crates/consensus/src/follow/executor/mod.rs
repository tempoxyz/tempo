//! Execution-layer synchronization for follow mode.
//!
//! This is intentionally smaller than the validator executor: it receives
//! already-verified finalized tips, drives forkchoice updates, and advances
//! marshal's floor after execution-layer progress is durable.

use std::sync::Arc;

use commonware_consensus::types::{FixedEpocher, Height};
use commonware_runtime::{Clock, Pacer, Spawner};
use futures::channel::mpsc;
use tempo_node::TempoFullNode;

mod actor;
mod ingress;

pub(crate) use actor::Actor;
pub(crate) use ingress::Mailbox;

pub(crate) struct Config {
    pub(crate) execution_node: Arc<TempoFullNode>,
    pub(crate) marshal: crate::alias::marshal::Mailbox,
    pub(crate) epoch_strategy: FixedEpocher,
    pub(crate) floor: Height,
    pub(crate) fcu_heartbeat_interval: std::time::Duration,
}

pub(crate) fn init<TContext>(context: TContext, config: Config) -> (Actor<TContext>, Mailbox)
where
    TContext: Clock + Pacer + Spawner,
{
    let (sender, receiver) = mpsc::unbounded();
    (Actor::new(context, config, receiver), Mailbox::new(sender))
}
