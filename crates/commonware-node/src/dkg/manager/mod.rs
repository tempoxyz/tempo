use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use commonware_consensus::simplex::signing_scheme::bls12381_threshold;
use commonware_cryptography::{
    bls12381::primitives::{group::Share, poly::Public, variant::MinSig},
    ed25519::{PrivateKey, PublicKey},
};
use commonware_runtime::{ContextCell, Spawner};
use commonware_utils::set::Set;

mod actor;
mod ingress;

pub(crate) use actor::Actor;
use futures::channel::mpsc;
use governor::Quota;
pub(crate) use ingress::Mailbox;

use ingress::{Command, Message};

pub(crate) fn init<TContext>(context: TContext, config: Config) -> (Actor<TContext>, Mailbox)
where
    TContext: Spawner,
{
    let (tx, rx) = mpsc::unbounded();
    let initial_scheme = Arc::new(bls12381_threshold::Scheme::new(
        config.participants.as_ref(),
        &config.public,
        config.share.clone(),
    ));
    let schemes_per_epoch = Arc::new(Mutex::new(HashMap::from([(0u64, initial_scheme)])));

    let actor = Actor {
        config,
        context: ContextCell::new(context),
        mailbox: rx,
        schemes_per_epoch: schemes_per_epoch.clone(),
    };
    let mailbox = Mailbox {
        inner: tx,
        per_epoch_schemes: schemes_per_epoch.clone(),
    };
    (actor, mailbox)
}
pub(crate) struct Config {
    /// The namespace the dkg manager will use when sending messages during
    /// a dkg ceremony.
    pub(crate) namespace: Vec<u8>,

    pub(crate) me: PrivateKey,

    /// The number of heights per epoch.
    pub(crate) heights_per_epoch: u64,

    /// The partition prefix to use when persisting ceremony metadata during
    /// rounds.
    pub(crate) partition_prefix: String,

    /// The participants in the dkg.
    ///
    /// For now, only a fixed set is supported, with dealers == players.
    pub(crate) participants: Set<PublicKey>,

    /// The initial bls12381 public key.
    pub(crate) public: Public<MinSig>,

    /// The rate limiting to apply during a DKG ceremony.
    pub(crate) rate_limit: Quota,

    /// This node's initial share of the bls12381 private key.
    pub(crate) share: Share,
}
