//! The executor is sending fork-choice-updates to the execution layer.
use std::sync::Arc;

use commonware_consensus::types::Height;
use commonware_cryptography::ed25519::PublicKey;
use commonware_runtime::{Clock, Metrics, Pacer, Spawner};

mod actor;
mod ingress;

pub(crate) use actor::Actor;
use eyre::WrapErr as _;
use futures::channel::mpsc;
pub(crate) use ingress::Mailbox;
use tempo_node::TempoFullNode;

pub(crate) fn init<TContext>(
    context: TContext,
    config: Config,
) -> eyre::Result<(Actor<TContext>, Mailbox)>
where
    TContext: Clock + Metrics + Pacer + Spawner,
{
    let (tx, rx) = mpsc::unbounded();
    let mailbox = Mailbox { inner: tx };
    let actor = Actor::init(context, config, rx).wrap_err("failed initializing actor")?;
    Ok((actor, mailbox))
}

pub(crate) struct Config {
    /// A handle to the execution node layer. Used to forward finalized blocks
    /// and to update the canonical chain by sending forkchoice updates.
    pub(crate) execution_node: Arc<TempoFullNode>,

    /// The last finalized height according to the consensus layer.
    /// If on startup there is a mismatch between the execution layer and the
    /// consensus, then the node will fill the gap by backfilling blocks to
    /// the execution layer until `last_finalized_height` is reached.
    pub(crate) last_finalized_height: Height,

    /// The mailbox of the marshal actor. Used to backfill blocks.
    pub(crate) marshal: crate::alias::marshal::Mailbox,

    /// The interval at which to send a forkchoice update heartbeat to the
    /// execution layer.
    pub(crate) fcu_heartbeat_interval: std::time::Duration,

    /// The node's ed25519 public key if the node is participating in
    /// consensus. Not set if not, for example for followers.
    pub(crate) public_key: Option<PublicKey>,
}
