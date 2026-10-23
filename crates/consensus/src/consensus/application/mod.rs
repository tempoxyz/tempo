//! The interface between the consensus layer and the execution layer.
//!
//! [`Inner`] implements [`commonware_consensus::Application`]. At startup the
//! engine wraps it in both an inline and a deferred marshal wrapper, held by
//! [`Factory`]. The factory is marshal's reporter and hands each epoch's
//! simplex engine the wrapper selected by the preceding epoch boundary
//! timestamp. The wrappers fetch parents, re-propose epoch boundary blocks,
//! check epoch membership and parent linkage, persist verified blocks,
//! broadcast proposals, and gate finalize votes on durability. [`Inner`] builds
//! blocks through the executor and checks proposals before this node votes for
//! them.

mod r#impl;
mod parent_state;

pub(super) use r#impl::Config;
pub(crate) use r#impl::Inner;
pub(super) use parent_state::TempoParentState;

use std::sync::Arc;

use commonware_actor::Feedback;
use commonware_consensus::{
    Automaton, CertifiableAutomaton, CertifiableBlock, Relay, Reporter,
    marshal::{
        Update,
        core::Mailbox,
        standard::{Deferred, Inline, Standard},
    },
    simplex::{Plan, scheme::bls12381_threshold::vrf::Scheme, types::Context},
    types::{Epocher, FixedEpocher, Round},
};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, certificate::Scheme as CertificateScheme,
    ed25519::PublicKey,
};
use commonware_runtime::{Clock, Spawner};
use commonware_utils::channel::oneshot;
use rand_core::Rng;
use tempo_chainspec::TempoChainSpec;

use crate::{VerificationMode, consensus::block::Block};

pub(crate) type TempoFactory<TContext> =
    Factory<TContext, Scheme<PublicKey, MinSig>, Inner, Block, FixedEpocher>;

/// Both verification wrappers, shared by marshal and every epoch's simplex engine.
pub(crate) struct Factory<E, S, A, B, ES>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
    S: CertificateScheme,
    A: commonware_consensus::Application<E>,
    B: CertifiableBlock + Clone,
    ES: Epocher,
{
    immediate: Inline<E, S, A, B, ES>,
    deferred: Deferred<E, S, A, B, ES>,
    chainspec: Arc<TempoChainSpec>,
    verification_mode: VerificationMode,
}

impl<E, S, A, B, ES> Clone for Factory<E, S, A, B, ES>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
    S: CertificateScheme,
    A: commonware_consensus::Application<E>,
    B: CertifiableBlock + Clone,
    ES: Epocher,
{
    fn clone(&self) -> Self {
        Self {
            immediate: self.immediate.clone(),
            deferred: self.deferred.clone(),
            chainspec: self.chainspec.clone(),
            verification_mode: self.verification_mode,
        }
    }
}

impl<E, S, A, B, ES> Factory<E, S, A, B, ES>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
    S: CertificateScheme,
    A: commonware_consensus::Application<
            E,
            Block = B,
            SigningScheme = S,
            Context = Context<B::Digest, S::PublicKey>,
            Input = (),
        >,
    B: CertifiableBlock<Context = <A as commonware_consensus::Application<E>>::Context> + Clone,
    ES: Epocher,
{
    /// Both wrappers register identical metrics under `context`, so they share
    /// the same `application_*` series.
    pub(crate) fn new(
        context: &E,
        inner: A,
        marshal: Mailbox<S, Standard<B>>,
        epocher: ES,
        chainspec: Arc<TempoChainSpec>,
        verification_mode: VerificationMode,
    ) -> Self {
        Self {
            immediate: Inline::new(
                context.child("application"),
                inner.clone(),
                marshal.clone(),
                epocher.clone(),
            ),
            deferred: Deferred::new(context.child("application"), inner, marshal, epocher),
            chainspec,
            verification_mode,
        }
    }

    /// Selects verification using the previous epoch boundary timestamp (genesis for epoch zero).
    pub(crate) fn for_timestamp(&self, timestamp: u64) -> Application<E, S, A, B, ES> {
        if self
            .verification_mode
            .is_deferred_at(&self.chainspec, timestamp)
        {
            Application::Deferred(self.deferred.clone())
        } else {
            Application::Immediate(self.immediate.clone())
        }
    }
}

impl<E, S, A, B, ES> Reporter for Factory<E, S, A, B, ES>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
    S: CertificateScheme,
    A: commonware_consensus::Application<E, Block = B, Context = Context<B::Digest, S::PublicKey>>
        + Reporter<Activity = Update<B>>,
    B: CertifiableBlock<Context = <A as commonware_consensus::Application<E>>::Context> + Clone,
    ES: Epocher,
{
    type Activity = Update<B>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        // Both wrappers prune their certification gates on tips, so both must
        // see every tip, including the idle one.
        //
        // Neither wrapper uses blocks: they only forward them to `Inner`, which
        // acknowledges them. Routing blocks through `deferred` alone is
        // therefore fine whichever wrapper is active.
        if let Update::Tip(..) = &activity {
            self.immediate.report(activity.clone());
        }
        self.deferred.report(activity)
    }
}

/// Verification policy fixed for the lifetime of a simplex epoch.
pub(crate) enum Application<E, S, A, B, ES>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
    S: CertificateScheme,
    A: commonware_consensus::Application<E>,
    B: CertifiableBlock + Clone,
    ES: Epocher,
{
    Deferred(Deferred<E, S, A, B, ES>),
    Immediate(Inline<E, S, A, B, ES>),
}

impl<E, S, A, B, ES> Clone for Application<E, S, A, B, ES>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
    S: CertificateScheme,
    A: commonware_consensus::Application<E>,
    B: CertifiableBlock + Clone,
    ES: Epocher,
{
    fn clone(&self) -> Self {
        match self {
            Self::Deferred(application) => Self::Deferred(application.clone()),
            Self::Immediate(application) => Self::Immediate(application.clone()),
        }
    }
}

impl<E, S, A, B, ES> Automaton for Application<E, S, A, B, ES>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
    S: CertificateScheme,
    A: commonware_consensus::Application<
            E,
            Block = B,
            SigningScheme = S,
            Context = Context<B::Digest, S::PublicKey>,
            Input = (),
        >,
    B: CertifiableBlock<Context = <A as commonware_consensus::Application<E>>::Context> + Clone,
    ES: Epocher,
{
    type Context = Context<B::Digest, S::PublicKey>;
    type Digest = B::Digest;

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

impl<E, S, A, B, ES> CertifiableAutomaton for Application<E, S, A, B, ES>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
    S: CertificateScheme,
    A: commonware_consensus::Application<
            E,
            Block = B,
            SigningScheme = S,
            Context = Context<B::Digest, S::PublicKey>,
            Input = (),
        >,
    B: CertifiableBlock<Context = <A as commonware_consensus::Application<E>>::Context> + Clone,
    ES: Epocher,
{
    async fn certify(&mut self, round: Round, payload: Self::Digest) -> oneshot::Receiver<bool> {
        match self {
            Self::Deferred(application) => application.certify(round, payload).await,
            Self::Immediate(application) => application.certify(round, payload).await,
        }
    }
}

impl<E, S, A, B, ES> Relay for Application<E, S, A, B, ES>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
    S: CertificateScheme,
    A: commonware_consensus::Application<E, Block = B, Context = Context<B::Digest, S::PublicKey>>,
    B: CertifiableBlock<Context = <A as commonware_consensus::Application<E>>::Context> + Clone,
    ES: Epocher,
{
    type PublicKey = S::PublicKey;
    type Digest = B::Digest;
    type Plan = Plan<S::PublicKey>;

    fn broadcast(&mut self, payload: Self::Digest, plan: Self::Plan) -> Feedback {
        match self {
            Self::Deferred(application) => application.broadcast(payload, plan),
            Self::Immediate(application) => application.broadcast(payload, plan),
        }
    }
}
