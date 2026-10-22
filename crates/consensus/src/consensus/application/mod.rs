//! The interface between the consensus layer and the execution layer.
//!
//! [`Inner`] implements [`commonware_consensus::Application`]. [`Application`]
//! constructs an inline or deferred wrapper for each epoch's simplex engine
//! using its preceding boundary timestamp. Marshal's reporter prunes the gates
//! of active epochs; wrappers are released when their epoch exits.
//! The wrappers fetch parents, re-propose epoch boundary blocks, check epoch
//! membership and parent linkage, persist verified blocks, broadcast proposals,
//! and gate finalize votes on durability. [`Inner`] builds blocks through the
//! executor and checks proposals before this node votes for them.

mod r#impl;
mod parent_state;

pub(super) use r#impl::Config;
pub(crate) use r#impl::Inner;
pub(super) use parent_state::TempoParentState;

use std::{collections::BTreeMap, sync::Arc};

use commonware_actor::Feedback;
use commonware_consensus::{
    Automaton, CertifiableAutomaton, Relay, Reporter,
    marshal::{
        Update,
        core::Mailbox,
        standard::{Deferred, Inline, Standard},
    },
    simplex::{Plan, scheme::bls12381_threshold::vrf::Scheme, types::Context},
    types::{Epoch, FixedEpocher, Round},
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_runtime::{Clock, Spawner};
use commonware_utils::channel::oneshot;
use parking_lot::Mutex;
use rand_core::Rng;

use crate::consensus::{Digest, block::Block};

/// Factory and marshal reporter for the active epochs' verification wrappers.
pub(crate) struct Application<E>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
{
    inner: Inner,
    marshal: Mailbox<Scheme<PublicKey, MinSig>, Standard<Block>>,
    epocher: FixedEpocher,
    active: Arc<Mutex<BTreeMap<Epoch, EpochApplication<E>>>>,
}

impl<E> Clone for Application<E>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            marshal: self.marshal.clone(),
            epocher: self.epocher.clone(),
            active: self.active.clone(),
        }
    }
}

impl<E> Application<E>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
{
    pub(crate) fn new(
        inner: Inner,
        marshal: Mailbox<Scheme<PublicKey, MinSig>, Standard<Block>>,
        epocher: FixedEpocher,
    ) -> Self {
        Self {
            inner,
            marshal,
            epocher,
            active: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Constructs an immediate wrapper and registers it for finalized-tip reports.
    pub(crate) fn to_immediate(&self, context: E, epoch: Epoch) -> EpochApplication<E> {
        let application = EpochApplication::Immediate(Inline::new(
            context,
            self.inner.clone(),
            self.marshal.clone(),
            self.epocher.clone(),
        ));
        self.active.lock().insert(epoch, application.clone());
        application
    }

    /// Constructs a deferred wrapper and registers it for finalized-tip reports.
    pub(crate) fn to_deferred(&self, context: E, epoch: Epoch) -> EpochApplication<E> {
        let application = EpochApplication::Deferred(Deferred::new(
            context,
            self.inner.clone(),
            self.marshal.clone(),
            self.epocher.clone(),
        ));
        self.active.lock().insert(epoch, application.clone());
        application
    }

    /// Releases the reporter's wrapper after the epoch's engine has stopped.
    pub(crate) fn exit(&self, epoch: Epoch) {
        self.active.lock().remove(&epoch);
    }
}

impl<E> Reporter for Application<E>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
{
    type Activity = Update<Block>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        // Prune every active epoch, but acknowledge each delivered block only once.
        if let Update::Tip(..) = &activity {
            for application in self.active.lock().values_mut() {
                application.report(activity.clone());
            }
        }
        self.inner.report(activity)
    }
}

/// Verification policy fixed for the lifetime of a simplex epoch.
pub(crate) enum EpochApplication<E>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
{
    Deferred(Deferred<E, Scheme<PublicKey, MinSig>, Inner, Block, FixedEpocher>),
    Immediate(Inline<E, Scheme<PublicKey, MinSig>, Inner, Block, FixedEpocher>),
}

impl<E> Clone for EpochApplication<E>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
{
    fn clone(&self) -> Self {
        match self {
            Self::Deferred(application) => Self::Deferred(application.clone()),
            Self::Immediate(application) => Self::Immediate(application.clone()),
        }
    }
}

impl<E> Automaton for EpochApplication<E>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
{
    type Context = Context<Digest, PublicKey>;
    type Digest = Digest;

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        match self {
            Self::Deferred(application) => application.propose(context).await,
            Self::Immediate(application) => application.propose(context).await,
        }
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        match self {
            Self::Deferred(application) => application.verify(context, payload).await,
            Self::Immediate(application) => application.verify(context, payload).await,
        }
    }
}

impl<E> CertifiableAutomaton for EpochApplication<E>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
{
    async fn certify(&mut self, round: Round, payload: Self::Digest) -> oneshot::Receiver<bool> {
        match self {
            Self::Deferred(application) => application.certify(round, payload).await,
            Self::Immediate(application) => application.certify(round, payload).await,
        }
    }
}

impl<E> Relay for EpochApplication<E>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
{
    type PublicKey = PublicKey;
    type Digest = Digest;
    type Plan = Plan<PublicKey>;

    fn broadcast(&mut self, payload: Self::Digest, plan: Self::Plan) -> Feedback {
        match self {
            Self::Deferred(application) => application.broadcast(payload, plan),
            Self::Immediate(application) => application.broadcast(payload, plan),
        }
    }
}

impl<E> Reporter for EpochApplication<E>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
{
    type Activity = Update<Block>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match self {
            Self::Deferred(application) => application.report(activity),
            Self::Immediate(application) => application.report(activity),
        }
    }
}
