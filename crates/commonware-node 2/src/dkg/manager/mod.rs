use commonware_consensus::types::FixedEpocher;
use commonware_cryptography::{bls12381::primitives::group::Share, ed25519::PrivateKey};
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage};
use eyre::WrapErr as _;
use futures::channel::mpsc;
use rand_core::CryptoRngCore;
use tempo_node::TempoFullNode;

mod actor;
mod ingress;
mod validators;

pub(crate) use actor::Actor;
pub(crate) use ingress::Mailbox;

use crate::epoch;

use ingress::{Command, Message};

pub(crate) async fn init<TContext>(
    context: TContext,
    config: Config,
) -> eyre::Result<(Actor<TContext>, Mailbox)>
where
    TContext: BufferPooler + Clock + CryptoRngCore + Metrics + Spawner + Storage,
{
    let (tx, rx) = mpsc::unbounded();

    let actor = Actor::new(config, context, rx)
        .await
        .wrap_err("failed initializing actor")?;
    let mailbox = Mailbox::new(tx);
    Ok((actor, mailbox))
}

pub(crate) struct Config {
    pub(crate) epoch_strategy: FixedEpocher,

    pub(crate) epoch_manager: epoch::manager::Mailbox,

    /// The namespace the dkg manager will use when sending messages during
    /// a dkg ceremony.
    pub(crate) namespace: Vec<u8>,

    pub(crate) me: PrivateKey,

    pub(crate) mailbox_size: usize,

    /// The mailbox to the marshal actor. Used to determine if an epoch
    /// can be started at startup.
    pub(crate) marshal: crate::alias::marshal::Mailbox,

    /// The partition prefix to use when persisting ceremony metadata during
    /// rounds.
    pub(crate) partition_prefix: String,

    /// The full execution layer node. On init, used to read the initial set
    /// of peers and public polynomial.
    ///
    /// During normal operation, used to read the validator config at the end
    /// of each epoch.
    pub(crate) execution_node: TempoFullNode,

    /// This node's initial share of the bls12381 private key.
    pub(crate) initial_share: Option<Share>,
}
