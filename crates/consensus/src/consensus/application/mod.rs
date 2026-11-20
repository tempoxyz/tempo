//! The interface between the consensus layer and the execution layer.
//!
//! [`Inner`] implements [`commonware_consensus::Application`]. At startup the
//! engine wraps it in commonware's deferred marshal wrapper, [`crate::alias::marshal::Deferred`],
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
