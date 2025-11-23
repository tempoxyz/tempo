use commonware_cryptography::{
    bls12381::primitives::{group::Share, poly::Public, variant::MinSig},
    ed25519::{PrivateKey, PublicKey},
};
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_utils::set::Ordered;

mod actor;
mod ingress;

pub(crate) use actor::Actor;
use futures::channel::mpsc;
pub(crate) use ingress::Mailbox;

use ingress::{Command, Message};
use rand_core::CryptoRngCore;

use crate::epoch;

pub(crate) async fn init<TContext>(context: TContext, config: Config) -> (Actor<TContext>, Mailbox)
where
    TContext: Clock + CryptoRngCore + Metrics + Spawner + Storage,
{
    let (tx, rx) = mpsc::unbounded();

    let actor = Actor::init(config, context, rx).await;
    let mailbox = Mailbox { inner: tx };
    (actor, mailbox)
}
pub(crate) struct Config {
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

    /// The participants in the dkg.
    ///
    /// For now, only a fixed set is supported, with dealers == players.
    pub(crate) initial_participants: Ordered<PublicKey>,

    /// The initial bls12381 public key.
    pub(crate) initial_public: Public<MinSig>,

    /// This node's initial share of the bls12381 private key.
    pub(crate) initial_share: Option<Share>,
}
