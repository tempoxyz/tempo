//! The interface between the consensus layer and the execution layer.
//!
//! The application actor implements the [`commonware_consensus::Automaton`]
//! trait to propose and verify blocks.

use std::time::Duration;

use commonware_consensus::types::FixedEpocher;
use commonware_runtime::{Metrics, Pacer, Spawner, Storage};

use eyre::WrapErr as _;
use rand_08::{CryptoRng, Rng};
use tempo_node::TempoFullNode;

mod actor;
mod ingress;

pub(super) use actor::Actor;
pub(crate) use ingress::Mailbox;

use crate::{epoch::SchemeProvider, subblocks};

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

    pub(super) executor: crate::executor::Mailbox,

    /// A handle to the execution node to verify and create new payloads.
    pub(super) execution_node: TempoFullNode,

    /// A handle to the subblocks service to get subblocks for proposals.
    pub(crate) subblocks: subblocks::Mailbox,

    /// The minimum amount of time to wait before resolving a new payload from the builder
    pub(super) new_payload_wait_time: Duration,

    /// The epoch strategy used by tempo, to map block heights to epochs.
    pub(super) epoch_strategy: FixedEpocher,

    /// The scheme provider to use for the application.
    pub(crate) scheme_provider: SchemeProvider,
}
