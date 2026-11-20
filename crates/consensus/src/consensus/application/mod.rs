//! The interface between the consensus layer and the execution layer.
//!
//! [`Inner`] implements [`commonware_consensus::Application`]. At startup the
//! engine wraps it in a deferred marshal wrapper, held by [`Factory`]. The
//! factory hands each epoch's simplex engine that wrapper, which the engine uses
//! as its automaton, relay and reporter; marshal reports finalized blocks to
//! [`Inner`] directly. The wrapper fetches parents, re-proposes epoch boundary blocks,
//! checks epoch membership and parent linkage, persists verified blocks,
//! broadcasts proposals, and gates finalize votes on durability. [`Inner`] builds
//! blocks through the executor and checks proposals before this node votes for
//! them.

mod r#impl;
mod parent_state;

pub(super) use r#impl::Config;
pub(crate) use r#impl::Inner;
pub(super) use parent_state::TempoParentState;

use commonware_actor::Feedback;
use commonware_codec::Codec;
use commonware_consensus::{
    CertifiableBlock, Reporter,
    marshal::{
        Update,
        core::Mailbox,
        standard::{Deferred, Standard},
    },
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Context},
    types::{Epocher, FixedEpocher},
};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, certificate::Scheme as CertificateScheme,
    ed25519::PublicKey,
};
use commonware_runtime::{Clock, Spawner};
use rand_core::Rng;

use crate::consensus::block::Block;

pub(crate) type TempoFactory<TContext> =
    Factory<TContext, Scheme<PublicKey, MinSig>, Inner, Block, FixedEpocher>;

/// The application as marshal and every epoch's simplex engine see it.
///
/// Simplex gets the deferred verification wrapper per epoch through [`Self::deferred`].
/// Marshal reports finalized blocks to the factory, which forwards them to the
/// application itself: the wrapper reports from simplex into marshal and takes
/// no part in that direction.
pub(crate) struct Factory<E, S, A, B, ES>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
    S: CertificateScheme,
    A: commonware_consensus::Application<E>,
    B: CertifiableBlock + Codec + Clone,
    ES: Epocher,
{
    application: A,
    deferred: Deferred<E, S, A, B, ES>,
}

impl<E, S, A, B, ES> Clone for Factory<E, S, A, B, ES>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
    S: CertificateScheme,
    A: commonware_consensus::Application<E>,
    B: CertifiableBlock + Codec + Clone,
    ES: Epocher,
{
    fn clone(&self) -> Self {
        Self {
            application: self.application.clone(),
            deferred: self.deferred.clone(),
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
    B: CertifiableBlock<Context = <A as commonware_consensus::Application<E>>::Context>
        + Codec
        + Clone,
    ES: Epocher,
{
    pub(crate) fn new(
        context: &E,
        inner: A,
        marshal: Mailbox<S, Standard<B>>,
        epocher: ES,
    ) -> Self {
        Self {
            application: inner.clone(),
            deferred: Deferred::new(context.child("application"), inner, marshal, epocher),
        }
    }

    /// The verification wrapper for a new simplex epoch.
    pub(crate) fn deferred(&self) -> Deferred<E, S, A, B, ES> {
        self.deferred.clone()
    }
}

impl<E, S, A, B, ES> Reporter for Factory<E, S, A, B, ES>
where
    E: Rng + Spawner + commonware_runtime::Metrics + Clock,
    S: CertificateScheme,
    A: commonware_consensus::Application<E> + Reporter<Activity = Update<B>>,
    B: CertifiableBlock + Codec + Clone,
    ES: Epocher,
{
    type Activity = Update<B>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        self.application.report(activity)
    }
}
