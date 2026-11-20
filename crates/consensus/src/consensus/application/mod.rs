//! The interface between the consensus layer and the execution layer.
//!
//! [`Inner`] implements [`commonware_consensus::Application`]. At startup the
//! engine wraps it in commonware's deferred marshal wrapper, [`Deferred`],
//! which every epoch's simplex engine uses as its automaton, relay and reporter;
//! marshal reports finalized blocks to [`Inner`] directly. The wrapper fetches
//! parents, re-proposes epoch boundary blocks, checks epoch membership and parent
//! linkage, persists verified blocks, broadcasts proposals, and gates finalize
//! votes on durability. [`Inner`] builds blocks through the executor and checks
//! proposals before this node votes for them.

mod r#impl;
mod parent_state;

pub(super) use r#impl::Config;
pub(crate) use r#impl::Inner;
pub(super) use parent_state::TempoParentState;

use commonware_consensus::{simplex::scheme::bls12381_threshold::vrf::Scheme, types::FixedEpocher};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};

use crate::consensus::block::Block;

/// [`Inner`] in commonware's deferred verification wrapper, as every epoch's
/// simplex engine uses it.
pub(crate) type Deferred<TContext> = commonware_consensus::marshal::standard::Deferred<
    TContext,
    Scheme<PublicKey, MinSig>,
    Inner,
    Block,
    FixedEpocher,
>;
