//! Ordered delivery of finalized blocks.
//!
//! # Architecture
//!
//! The core of the module is the unified [`core::Actor`]. It marshals finalized blocks into order by:
//!
//! - Receiving uncertified blocks from a broadcast mechanism
//! - Receiving notarizations and finalizations from consensus
//! - Reconstructing a total order of finalized blocks
//! - Providing a backfill mechanism for missing blocks
//!
//! The actor interacts with several components:
//! - [`crate::Reporter`]: Receives ordered, finalized blocks at-least-once
//! - [`crate::simplex`]: Provides consensus messages
//! - Application: Provides verified blocks
//! - [`commonware_broadcast::buffered`]: Provides uncertified blocks (standard mode)
//! - [`coding::shards::Engine`]: Provides erasure-coded shards (coding mode)
//! - [`resolver`]: Provides a backfill mechanism for missing blocks
//!
//! # Design
//!
//! ## Delivery
//!
//! The actor will deliver a block to the reporter at-least-once. The reporter should be prepared to
//! handle duplicate deliveries. However the blocks will be in order.
//!
//! ## Finalization
//!
//! The actor uses a view-based model to track the state of the chain. Each view corresponds
//! to a potential block in the chain. The actor will only finalize a block (and its ancestors)
//! if it has a corresponding finalization from consensus.
//!
//! _It is possible that there may exist multiple finalizations for the same block in different views. Marshal
//! only concerns itself with verifying a valid finalization exists for a block, not that a specific finalization
//! exists. This means different Marshals may have different finalizations for the same block persisted to disk._
//!
//! ## Backfill
//!
//! The actor provides a backfill mechanism for missing blocks. If the actor notices a gap in its
//! knowledge of finalized blocks, it will request the missing blocks from its peers. This ensures
//! that the actor can catch up to the rest of the network if it falls behind.
//!
//! ## Storage
//!
//! The actor uses a combination of internal and external ([`store::Certificates`], [`store::Blocks`]) storage
//! to store blocks and finalizations. Internal storage (in-memory caches) is used for data that is only
//! needed for a short period of time, such as unverified blocks or notarizations. External storage
//! (archive backends) is used to persist finalized blocks and certificates indefinitely.
//!
//! Marshal will store all blocks after a configurable starting height (or, floor) onward.
//! This allows for state sync from a specific height rather than from genesis. The floor
//! is supplied as a finalization; marshal fetches the corresponding block asynchronously
//! before dispatching application blocks above it. When updating the starting height,
//! marshal will attempt to prune blocks in external storage that are no longer needed, if
//! the backing [`store::Blocks`] supports pruning.
//!
//! _Setting a configurable starting height will prevent others from backfilling blocks below said height. This
//! feature is only recommended for applications that support state sync (i.e., those that don't require full
//! block history to participate in consensus)._
//!
//! ## Limitations and Future Work
//!
//! - Only works with [crate::simplex] rather than general consensus.
//! - Assumes at-most one notarization per view, incompatible with some consensus protocols.
//! - Uses [`broadcast::buffered`](`commonware_broadcast::buffered`) for broadcasting and receiving
//!   uncertified blocks from the network.

use crate::{
    types::{Height, Round},
    Block,
};
use commonware_cryptography::Digest;
use commonware_storage::archive;
use commonware_utils::{acknowledgement::Exact, Acknowledgement};
use std::sync::Arc;

mod config;
pub use config::{Config, Start};

pub mod ancestry;
pub mod core;
pub mod resolver;
pub mod standard;
pub mod store;

#[cfg(all(test, feature = "arbitrary"))]
mod conformance;

commonware_macros::stability_scope!(ALPHA {
    pub(crate) mod application;
    pub mod coding;
});

#[cfg(test)]
pub mod mocks;

/// An identifier for a block request.
pub enum Identifier<D: Digest> {
    /// The height of the block to retrieve.
    Height(Height),
    /// The digest of the block to retrieve.
    Digest(D),
    /// The highest finalized block. It may be the case that marshal does not have some of the
    /// blocks below this height.
    Latest,
}

// Allows using u64 directly for convenience.
impl<D: Digest> From<Height> for Identifier<D> {
    fn from(src: Height) -> Self {
        Self::Height(src)
    }
}

// Allows using &Digest directly for convenience.
impl<D: Digest> From<&D> for Identifier<D> {
    fn from(src: &D) -> Self {
        Self::Digest(*src)
    }
}

// Allows using archive identifiers directly for convenience.
impl<D: Digest> From<archive::Identifier<'_, D>> for Identifier<D> {
    fn from(src: archive::Identifier<'_, D>) -> Self {
        match src {
            archive::Identifier::Index(index) => Self::Height(Height::new(index)),
            archive::Identifier::Key(key) => Self::Digest(*key),
        }
    }
}

/// An update reported to the application, either a new finalized tip or a finalized block.
///
/// Finalized tips are reported as soon as known, whether or not we hold all blocks up to that height.
/// Finalized blocks are reported to the application in monotonically increasing order (no gaps permitted).
#[derive(Clone, Debug)]
pub enum Update<B: Block, A: Acknowledgement = Exact> {
    /// A new finalized tip and the finalization round.
    Tip(Round, Height, B::Digest),
    /// A new finalized block and an [Acknowledgement] for the application to signal once processed.
    ///
    /// To ensure all blocks are delivered at least once, marshal waits to mark a block as delivered
    /// until the application explicitly acknowledges the update. If the [Acknowledgement] is dropped before
    /// handling, marshal will exit (assuming the application is shutting down).
    ///
    /// Cloning the update shares the immutable block, so applications can fan it out without requiring
    /// block clones. Marshal only considers the block delivered once every acknowledgement is handled.
    ///
    /// Marshal only emits a block after it has durably persisted the said block. This ensures applications
    /// that make stateful changes based on a block in other locations can access the same block on restart (often
    /// some logic on startup attempts on infallible read on the last processed block).
    Block(Arc<B>, A),
}
