//! The interface between the consensus layer and the execution layer.
//!
//! [`Inner`] implements [`commonware_consensus::Application`]. At startup the
//! engine wraps it in [`Marshaled`], selecting inline or deferred verification
//! and sharing it with marshal's reporter and every epoch's simplex engine. The wrapper
//! owns everything between consensus and the block: it fetches the parent,
//! re-proposes epoch boundary blocks, checks epoch membership and parent
//! linkage, persists verified blocks, broadcasts proposals, and gates the
//! finalize vote on durability. What is left here is tempo's own view of a
//! block: how one is built through the executor, and which checks a
//! proposal must pass before this node votes for it.
//!

mod r#impl;
mod parent_state;

pub(super) use r#impl::Config;
pub(crate) use r#impl::Inner;
pub(super) use parent_state::TempoParentState;

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

use crate::{VerificationMode, consensus::block::Block};

pub(crate) type Application<TContext> =
    Marshaled<TContext, Scheme<PublicKey, MinSig>, Inner, Block, FixedEpocher>;

/// A shared application for marshal and every epoch's simplex engine.
pub(crate) enum Marshaled<E, S, A, B, ES>
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

impl<E, S, A, B, ES> Clone for Marshaled<E, S, A, B, ES>
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

impl<E, S, A, B, ES> Marshaled<E, S, A, B, ES>
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
    pub(crate) fn new(
        context: E,
        inner: A,
        marshal: Mailbox<S, Standard<B>>,
        epocher: ES,
        mode: VerificationMode,
    ) -> Self {
        match mode {
            VerificationMode::Deferred => {
                Self::Deferred(Deferred::new(context, inner, marshal, epocher))
            }
            VerificationMode::Immediate => {
                Self::Immediate(Inline::new(context, inner, marshal, epocher))
            }
        }
    }
}

impl<E, S, A, B, ES> Automaton for Marshaled<E, S, A, B, ES>
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

impl<E, S, A, B, ES> CertifiableAutomaton for Marshaled<E, S, A, B, ES>
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

impl<E, S, A, B, ES> Relay for Marshaled<E, S, A, B, ES>
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

impl<E, S, A, B, ES> Reporter for Marshaled<E, S, A, B, ES>
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
        match self {
            Self::Deferred(application) => application.report(activity),
            Self::Immediate(application) => application.report(activity),
        }
    }
}
