mod actor;
pub(super) mod ingress;

use std::{num::NonZeroUsize, sync::Arc, time::Duration};

pub(crate) use actor::Actor;
use commonware_cryptography::ed25519::PublicKey;
pub(crate) use ingress::Mailbox;

use commonware_consensus::types::{FixedEpocher, Height, ViewDelta};
use commonware_p2p::Blocker;
use commonware_runtime::{Clock, Metrics, Network, Spawner, Storage, buffer::paged::CacheRef};
use rand_core::{CryptoRng, Rng};
use tempo_node::TempoFullNode;

use crate::{
    consensus::{Digest, application::TempoFactory},
    epoch::scheme_provider::SchemeProvider,
};

pub(crate) struct Config<TContext, TBlocker>
where
    TContext: Rng + Spawner + Metrics + Clock,
{
    pub(crate) application: TempoFactory<TContext>,
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
    /// The recovery boundary, which the execution layer finalized without a certificate, or
    /// `None` without a chain recovery. Used as the floor of the epoch after it until marshal
    /// finalizes it.
    pub(crate) recovery_boundary: Option<(Height, Digest)>,
}

pub(crate) fn init<TContext, TBlocker>(
    context: TContext,
    config: Config<TContext, TBlocker>,
) -> (Actor<TContext, TBlocker>, Mailbox)
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
