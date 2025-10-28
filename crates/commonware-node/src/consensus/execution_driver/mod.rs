//! Drives the execution engine by forwarding consensus messages.
//!
//! # On the usage of the commonware-pacer
//!
//! The execution driver will contain `Pacer::pace` calls for all interactions
//! with the execution layer. This is a no-op in production because the
//! commonware tokio runtime ignores these. However, these are critical in
//! e2e tests using the commonware deterministic runtime: since the execution
//! layer is still running on the tokio runtime, these calls signal the
//! deterministic runtime to spend real life time to wait for the execution
//! layer calls to complete.

use std::time::Duration;

use commonware_runtime::{Metrics, Pacer, Spawner, Storage};

use eyre::WrapErr as _;
use rand::{CryptoRng, Rng};
use tempo_node::TempoFullNode;

mod executor;

mod actor;
mod ingress;

pub(super) use actor::ExecutionDriver;
pub(crate) use ingress::ExecutionDriverMailbox;

pub(super) async fn init<TContext>(
    config: Config<TContext>,
) -> eyre::Result<(ExecutionDriver<TContext>, ExecutionDriverMailbox)>
where
    TContext: Pacer + governor::clock::Clock + Rng + CryptoRng + Spawner + Storage + Metrics,
{
    let execution_driver = ExecutionDriver::init(config)
        .await
        .wrap_err("failed initializing actor")?;
    let mailbox = execution_driver.mailbox().clone();
    Ok((execution_driver, mailbox))
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
