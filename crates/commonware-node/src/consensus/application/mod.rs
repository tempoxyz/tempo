//! Drives the execution engine by forwarding consensus messages.

use std::time::Duration;

use commonware_runtime::{Metrics, Pacer, Spawner, Storage};

use eyre::WrapErr as _;
use rand::{CryptoRng, Rng};
use tempo_node::TempoFullNode;

mod executor;

mod actor;
mod ingress;

pub(super) use actor::Actor;
pub(crate) use ingress::Mailbox;

pub(super) async fn init<TContext>(
    config: Config<TContext>,
) -> eyre::Result<(Actor<TContext>, Mailbox)>
where
    TContext: Pacer + governor::clock::Clock + Rng + CryptoRng + Spawner + Storage + Metrics,
{
    let actor = Actor::init(config)
        .await
        .wrap_err("failed initializing actor")?;
    let mailbox = actor.mailbox().clone();
    Ok((actor, mailbox))
}

pub(super) struct Config<TContext> {
    /// The execution context of the commonwarexyz application (tokio runtime, etc).
    pub(super) context: TContext,

    /// Used as PayloadAttributes.suggested_fee_recipient
    pub(super) fee_recipient: alloy_primitives::Address,

    /// Number of messages from consensus to hold in our backlog
    /// before blocking.
    pub(super) mailbox_size: usize,

    /// For subscribing to blocks distributed via the consensus p2p network.
    pub(super) marshal: crate::alias::marshal::Mailbox,

    /// A handle to the execution node to verify and create new payloads.
    pub(super) execution_node: TempoFullNode,

    /// The minimum amount of time to wait before resolving a new payload from the builder
    pub(super) new_payload_wait_time: Duration,

    /// The number of heights H in an epoch. For a given epoch E, all heights
    /// `E*H+1` to and including `(E+1)*H` make up the epoch. The block at
    /// `E*H` is said to be the genesis (or parent) of the epoch.
    pub(super) epoch_length: u64,
}
