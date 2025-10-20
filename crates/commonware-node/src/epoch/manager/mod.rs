mod actor;
mod ingress;
mod scheme_provider;

use std::time::Duration;

pub(crate) use actor::Actor;
use commonware_consensus::simplex::signing_scheme::bls12381_threshold;
use commonware_cryptography::bls12381::primitives::variant::MinSig;
use commonware_cryptography::ed25519::PrivateKey;
use commonware_cryptography::ed25519::PublicKey;
use commonware_utils::set::Set;
pub(crate) use ingress::Mailbox;

// TODO(janis): feels likel these make no sense here. Move them out.
pub(crate) use scheme_provider::Coordinator;
pub(crate) use scheme_provider::SchemeProvider;

use commonware_consensus::marshal;
use commonware_p2p::Blocker;
use commonware_runtime::{Clock, Metrics, Network, Spawner, Storage, buffer::PoolRef};
use rand::{CryptoRng, Rng};

use crate::consensus::block::Block;

pub(crate) struct Config<TBlocker> {
    pub(crate) application: crate::consensus::execution_driver::ExecutionDriverMailbox,
    pub(crate) blocker: TBlocker,
    pub(crate) buffer_pool: PoolRef,
    pub(crate) time_for_peer_response: Duration,
    pub(crate) time_to_propose: Duration,
    pub(crate) mailbox_size: usize,
    pub(crate) marshal: marshal::Mailbox<bls12381_threshold::Scheme<MinSig>, Block>,
    pub(crate) me: PrivateKey,
    pub(crate) participants: Set<PublicKey>,
    pub(crate) time_to_collect_notarizations: Duration,
    pub(crate) time_to_retry_nullify_broadcast: Duration,
    pub(crate) partition_prefix: String,
    pub(crate) scheme_provider: SchemeProvider,
    pub(crate) views_to_track: u64,
    pub(crate) views_until_leader_skip: u64,

    /// The number of heights H in an epoch. For a given epoch E, all heights
    /// `E*H+1` to and including `(E+1)*H` make up the epoch. The block at
    /// `E*H` is said to be the genesis (or parent) of the epoch.
    pub(crate) heights_per_epoch: u64,
}

pub(crate) fn init<TBlocker, TContext>(
    config: Config<TBlocker>,
    context: TContext,
) -> (Actor<TBlocker, TContext>, Mailbox)
where
    TBlocker: Blocker<PublicKey = PublicKey>,
    TContext:
        Spawner + Metrics + Rng + CryptoRng + Clock + governor::clock::Clock + Storage + Network,
{
    let (tx, rx) = futures::channel::mpsc::unbounded();
    let actor = Actor::new(config, context, rx);
    let mailbox = Mailbox::new(tx);
    (actor, mailbox)
}
