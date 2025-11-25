use std::net::SocketAddr;

use commonware_cryptography::{
    bls12381::primitives::{group::Share, poly::Public, variant::MinSig},
    ed25519::{PrivateKey, PublicKey},
};
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_utils::set::OrderedAssociated;
use eyre::WrapErr as _;
use futures::channel::mpsc;
use rand_core::CryptoRngCore;
use tempo_node::TempoFullNode;

mod actor;
mod ingress;
mod validators;

pub(crate) use actor::Actor;
pub(crate) use ingress::Mailbox;

use ingress::{Command, Message};

use crate::epoch;

pub(crate) async fn init<TContext, TPeerManager>(
    context: TContext,
    config: Config<TPeerManager>,
) -> eyre::Result<(Actor<TContext, TPeerManager>, Mailbox)>
where
    TContext: Clock + CryptoRngCore + Metrics + Spawner + Storage,
    TPeerManager: commonware_p2p::Manager<
            PublicKey = PublicKey,
            Peers = OrderedAssociated<PublicKey, SocketAddr>,
        >,
{
    let (tx, rx) = mpsc::unbounded();

    let actor = Actor::new(config, context, rx)
        .await
        .wrap_err("failed initializing actor")?;
    let mailbox = Mailbox { inner: tx };
    Ok((actor, mailbox))
}

pub(crate) struct Config<TPeerManager> {
    pub(crate) epoch_manager: epoch::manager::Mailbox,

    /// The namespace the dkg manager will use when sending messages during
    /// a dkg ceremony.
    pub(crate) namespace: Vec<u8>,

    pub(crate) me: PrivateKey,

    /// The number of heights per epoch.
    pub(crate) epoch_length: u64,

    pub(crate) mailbox_size: usize,

    /// The mailbox to the marshal actor. Used to determine if an epoch
    /// can be started at startup.
    pub(crate) marshal: crate::alias::marshal::Mailbox,

    /// The partition prefix to use when persisting ceremony metadata during
    /// rounds.
    pub(crate) partition_prefix: String,

    /// The full execution layer node. Used to read the initial set of peers
    /// from chainspec.
    pub(crate) execution_node: TempoFullNode,

    /// The initial participants in the DKG ceremony.
    ///
    /// Pre the allegretto hardfork, this initial set are the dealers and players
    /// in a ceremony.
    pub(crate) initial_validators: OrderedAssociated<PublicKey, SocketAddr>,

    /// The initial public polynomial, passed in through config.
    pub(crate) initial_public_polynomial: Public<MinSig>,

    /// This node's initial share of the bls12381 private key.
    pub(crate) initial_share: Option<Share>,

    /// The peer manager on which the dkg actor will register new peers for a
    /// given epoch after reading them from the smart contract.
    pub(crate) peer_manager: TPeerManager,
}
