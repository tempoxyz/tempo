//! Epoch logic used by tempo.
//!
//! All logic is written with the assumption that there are at least 3 heights
//! per epoch. Having less heights per epoch will not immediately break the
//! logic, but it might lead to strange behavior and is not supported.
//!
//! Note that either way, 3 blocks per epoch is a highly unreasonable number.

use std::{num::NonZeroUsize, sync::Arc, time::Duration};

use commonware_consensus::types::{FixedEpocher, ViewDelta};
use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::Blocker;
use commonware_runtime::{
    BufferPooler, Clock, Metrics, Network, Spawner, Storage, buffer::paged::CacheRef,
};
use rand_core::{CryptoRng, Rng};
use tempo_node::TempoFullNode;

mod actor;
mod ingress;
mod scheme_provider;

pub(crate) use actor::Actor;
pub(crate) use ingress::Mailbox;
pub(crate) use scheme_provider::SchemeProvider;

pub(crate) struct Config<TBlocker> {
    pub(crate) application: crate::consensus::application::Mailbox,
    pub(crate) execution_node: Arc<TempoFullNode>,
    pub(crate) blocker: TBlocker,
    pub(crate) page_cache: CacheRef,
    pub(crate) epoch_strategy: FixedEpocher,
    pub(crate) time_for_peer_response: Duration,
    pub(crate) time_to_propose: Duration,
    pub(crate) mailbox_size: NonZeroUsize,
    pub(crate) marshal: crate::alias::marshal::Mailbox,
    pub(crate) scheme_provider: SchemeProvider,
    pub(crate) time_to_collect_notarizations: Duration,
    pub(crate) time_to_retry_nullify_broadcast: Duration,
    pub(crate) partition_prefix: String,
    pub(crate) views_to_track: ViewDelta,
    pub(crate) inactive_time_before_leader_skip: Duration,
}

pub(crate) fn init<TContext, TBlocker>(
    context: TContext,
    config: Config<TBlocker>,
) -> (Actor<TContext, TBlocker>, Mailbox)
where
    TBlocker: Blocker<PublicKey = PublicKey>,
    TContext: BufferPooler
        + Spawner
        + Metrics
        + Rng
        + CryptoRng
        + Clock
        + governor::clock::Clock
        + Storage
        + Network,
{
    let (tx, rx) = futures::channel::mpsc::unbounded();
    let actor = Actor::new(config, context, rx);
    let mailbox = Mailbox::new(tx);
    (actor, mailbox)
}
