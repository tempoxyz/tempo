//! The notarized tree: the executor's record of the chain above the
//! finalized tip, of which of those blocks the execution layer has
//! accepted, of the forkchoice state the execution layer last accepted,
//! and of how far that state has converged onto the pending head's
//! ancestry.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime},
};

use alloy_rpc_types_engine::ForkchoiceState;
use commonware_consensus::{
    CertifiableBlock as _, Heightable as _,
    types::{Height, Round},
};
use tracing::debug;

use crate::consensus::{Digest, block::Block};

#[cfg(test)]
mod tests;

/// How long a notarized block the execution layer failed to process is
/// withheld from delivery and forkchoice updates before it becomes
/// eligible for a retry.
pub(super) const NOTARIZED_REJECTION_RETRY_DELAY: Duration = Duration::from_secs(10);

/// A block known to the executor together with what the execution layer
/// has said about it.
#[derive(Clone, Debug)]
pub(super) struct BlockEntry {
    pub(super) block: Arc<Block>,
    /// The execution layer accepted the block through a new-payload request.
    delivered: bool,
    rejected_at: Option<SystemTime>,
}

impl BlockEntry {
    /// Whether the block may be delivered or made the head at `now`: it is
    /// not withheld by a rejection younger than
    /// [`NOTARIZED_REJECTION_RETRY_DELAY`].
    fn forwardable(&self, now: SystemTime) -> bool {
        self.rejected_at
            .is_none_or(|rejected_at| now >= rejected_at + NOTARIZED_REJECTION_RETRY_DELAY)
    }

    /// The round the block's parent was notarized in, derived from the
    /// block's consensus context.
    fn parent_round(&self) -> Round {
        let context = self.block.context();
        Round::new(context.round.epoch(), context.parent.0)
    }
}

/// A snapshot of the execution layer's local state - its head and
/// finalized tip - for execution tasks to extend and report back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct LocalState {
    pub(super) head: (Height, Digest),
    pub(super) finalized: (Height, Digest),
}

impl LocalState {
    /// Transform a [`LocalState`] to a [`ForkchoiceState`] to submit to the
    /// execution layer.
    pub(super) fn to_forkchoice_state(self) -> ForkchoiceState {
        ForkchoiceState {
            head_block_hash: self.head.1.0,
            safe_block_hash: self.finalized.1.0,
            finalized_block_hash: self.finalized.1.0,
        }
    }

    /// Updates the finalized tip to `digest` at `height`.
    ///
    /// `height` must be ahead of the tracked finalized height; if it is
    /// not, this is a no-op. If `height` is at or ahead of the head
    /// height, the head is moved onto the finalized tip as well, so that
    /// the finalized tip is never ahead of the head.
    pub(super) fn update_finalized(self, height: Height, digest: Digest) -> Self {
        let mut this = self;
        if height > this.finalized.0 {
            this.finalized = (height, digest);
        }
        if height >= this.head.0 {
            this.head = (height, digest);
        }
        this
    }

    /// Updates the head to `digest` at `height`.
    ///
    /// The head only moves above the finalized tip (or back onto it);
    /// anything below is a no-op.
    pub(super) fn update_head(self, height: Height, digest: Digest) -> Self {
        let mut this = self;
        if height > this.finalized.0 || digest == this.finalized.1 {
            this.head = (height, digest);
        }
        this
    }
}

/// Tracks notarized blocks at the tip of the chain and returns which block
/// can be delivered to the execution layer next, and which block the
/// execution layer's head can be moved onto.
///
/// The canonical target is `pending_head`: the parent of the most recent
/// consensus context. This is expected to be reported by the simplex engine via
/// the application actor, and constitutes the view (/block) that simplex
/// expects to verify or build blocks on top of.
///
/// Contexts double as notarization proofs for their parents, but parents are
/// not monotonic: after nullifications, a later view may build on an *older*
/// notarized block than its predecessor. Reports arrive in consensus order,
/// so the last report wins, and the canonical path is the pending head's
/// ancestry rather than the highest known notarization's.
///
/// Block bodies are captured from validation requests and the node's own
/// builds (the proposer never verifies its own block) or fetched from the
/// marshal actor; combined with the reports, they reconstruct the
/// canonical path on top of the finalized tip.
///
/// The tree holds data strictly above the finalized *network* tip,
/// which it tracks itself: recording and pruning are guarded against it.
///
/// # Delivery and forkchoice are separate steps
///
/// [`Self::next_to_deliver`] hands out the next block whose parent the
/// execution layer *knows* (accepted through a delivery or validation, or
/// part of the tracked state) for a bare new-payload request.
/// [`Self::next_head`] names the highest known block on the pending head's
/// ancestry for a forkchoice update, so an update can never make the
/// execution layer sync. Both walk the ancestry fresh on every query.
///
/// Recording methods only insert primary state (the pending head, the
/// local state, bodies and their delivery status, guarded against the
/// finalized tip); [`Self::heal`], run by the actor once per event-loop
/// iteration, prunes what the advancing finalized tip covers.
#[derive(Debug)]
pub(super) struct NotarizedTree {
    /// The latest observed finalized tip of the network: the tree's
    /// lower bound. The tree only records notarized blocks above this finalized
    /// tip.
    network_finalized_tip: (Round, Height, Digest),
    /// The highest finalized block the execution layer accepted through a
    /// new-payload request: the finalized side of the next forkchoice
    /// update. Sits between `local_finalized_tip` and
    /// `network_finalized_tip`.
    delivered_finalized: (Height, Digest),
    /// The finalized tip as canonicalized on the execution layer: the
    /// finalized side of the last accepted forkchoice state. Trails
    /// `delivered_finalized` until the forkchoice update lands.
    local_finalized_tip: (Height, Digest),
    /// The pending head reported by the most recent consensus context: the
    /// tip of the canonical path the execution layer's head is converged
    /// onto. Points to the known network finalized tip if no pending head was
    /// reported yet or if it goes stale.
    pending_head: PendingHead,
    /// The execution layer's current head: the head side of the last
    /// accepted forkchoice state.
    local_head: (Height, Digest),
    /// Bodies of blocks at the tip of the chain, keyed by digest.
    blocks: HashMap<Digest, BlockEntry>,
}

/// A snapshot of the tree's convergence measures, returned by
/// [`NotarizedTree::depths`] and reported as metrics by the actor.
#[derive(Debug, Clone, Copy)]
pub(super) struct Depths {
    /// Number of block bodies held by the tree.
    pub(super) blocks: usize,
    /// Height distance from the locally canonicalized finalized tip up to
    /// the network's finalized tip: the undelivered finalized backlog.
    pub(super) finalization_lag: u64,
    /// Height distance from the execution layer's head to the pending
    /// head: the convergence backlog. Negative when consensus re-anchored
    /// below the head; `None` while the pending head's body - and with it
    /// its height - is unknown.
    pub(super) convergence_depth: Option<i64>,
    /// Number of held blocks the execution layer accepted that are not on
    /// its canonical chain: delivered above the head, or on other branches.
    pub(super) uncanonicalized_blocks: usize,
}

/// The parent of the most recent consensus context: the notarized block
/// consensus reports building on, and hence the block the execution
/// layer's head must converge to.
#[derive(Clone, Copy, Debug)]
struct PendingHead {
    /// The round the parent was notarized in (its view within the reporting
    /// context's epoch); the fetch hint for a missing body.
    notarized_in: Round,
    digest: Digest,
}

impl PendingHead {
    /// The default convergence target: the network's finalized tip.
    fn finalized_tip(network_finalized_tip: (Round, Height, Digest)) -> Self {
        let (round, _, digest) = network_finalized_tip;
        Self {
            notarized_in: round,
            digest,
        }
    }
}

impl NotarizedTree {
    pub(super) fn new(
        network_finalized_tip: (Round, Height, Digest),
        local_state: LocalState,
    ) -> Self {
        Self {
            network_finalized_tip,
            delivered_finalized: local_state.finalized,
            local_finalized_tip: local_state.finalized,
            pending_head: PendingHead::finalized_tip(network_finalized_tip),
            local_head: local_state.head,
            blocks: HashMap::new(),
        }
    }

    /// The block consensus reported building on: the convergence target.
    pub(super) fn pending_head(&self) -> Digest {
        self.pending_head.digest
    }

    /// A snapshot of the latest forkchoice state accepted by the execution
    /// layer, for execution tasks to extend. States the execution layer
    /// accepts are reported back via [`Self::set_local_state`].
    pub(super) fn local_state(&self) -> LocalState {
        LocalState {
            head: self.local_head,
            finalized: self.local_finalized_tip,
        }
    }

    /// The highest finalized block the execution layer accepted: the
    /// finalized target of the next forkchoice update.
    pub(super) fn delivered_finalized(&self) -> (Height, Digest) {
        self.delivered_finalized
    }

    /// A snapshot of the tree's convergence measures, for metrics.
    pub(super) fn depths(&self) -> Depths {
        let (_, network_finalized_height, network_finalized_digest) = self.network_finalized_tip;
        let pending_height = if self.pending_head.digest == network_finalized_digest {
            Some(network_finalized_height)
        } else if self.pending_head.digest == self.local_head.1 {
            Some(self.local_head.0)
        } else {
            self.blocks
                .get(&self.pending_head.digest)
                .map(|entry| entry.block.height())
        };
        // The head's ancestry held by the tree is the canonical part.
        let mut canonical = std::collections::HashSet::new();
        let mut digest = self.local_head.1;
        while let Some(entry) = self.blocks.get(&digest) {
            canonical.insert(digest);
            digest = entry.block.parent_digest();
        }
        let uncanonicalized_blocks = self
            .blocks
            .iter()
            .filter(|(digest, entry)| entry.delivered && !canonical.contains(digest))
            .count();
        Depths {
            blocks: self.blocks.len(),
            finalization_lag: network_finalized_height
                .get()
                .saturating_sub(self.local_finalized_tip.0.get()),
            convergence_depth: pending_height
                .map(|height| height.get() as i64 - self.local_head.0.get() as i64),
            uncanonicalized_blocks,
        }
    }

    /// Whether the execution layer has `digest`: the tracked head or
    /// finalized block, the delivered finalized block, or a delivered entry.
    pub(super) fn is_known(&self, digest: Digest) -> bool {
        self.known_height(digest).is_some()
    }

    /// Returns if `digest` is at the head of the tracked EL state.
    pub(super) fn is_local_head(&self, digest: Digest) -> bool {
        self.local_head.1 == digest
    }

    /// The height of `digest` if the execution layer has it.
    pub(super) fn known_height(&self, digest: Digest) -> Option<Height> {
        if self.local_head.1 == digest {
            return Some(self.local_head.0);
        }
        if self.local_finalized_tip.1 == digest {
            return Some(self.local_finalized_tip.0);
        }
        if self.delivered_finalized.1 == digest {
            return Some(self.delivered_finalized.0);
        }
        self.blocks
            .get(&digest)
            .filter(|entry| entry.delivered)
            .map(|entry| entry.block.height())
    }

    /// Whether `digest` is the next thing convergence does: the head target
    /// of the next forkchoice update, the next block to deliver, or the next
    /// finalized block the marshal actor delivers.
    pub(super) fn converges_imminently(&self, digest: Digest, now: SystemTime) -> bool {
        self.next_head(now).is_some_and(|(_, head)| head == digest)
            || self
                .next_to_deliver(now)
                .is_some_and(|block| block.digest() == digest)
            || (self.network_finalized_tip.2 == digest
                && self.delivered_finalized.0.next() == self.network_finalized_tip.1)
    }

    /// Records an accepted forkchoice state. A finalized block the tree did
    /// not see delivered (startup backfill) advances the delivered one too.
    pub(super) fn set_local_state(&mut self, local_state: LocalState) {
        self.local_head = local_state.head;
        self.local_finalized_tip = local_state.finalized;
        if local_state.finalized.0 > self.delivered_finalized.0 {
            self.delivered_finalized = local_state.finalized;
        }
    }

    /// Records a finalized block the execution layer accepted; a no-op at
    /// or below the tracked height.
    pub(super) fn set_delivered_finalized(&mut self, height: Height, digest: Digest) {
        if height > self.delivered_finalized.0 {
            self.delivered_finalized = (height, digest);
        }
    }

    /// Records a consensus context's parent as the pending head of the
    /// chain, superseding any previous report.
    pub(super) fn set_pending_head(&mut self, notarized_in: Round, digest: Digest) {
        self.pending_head = PendingHead {
            notarized_in,
            digest,
        };
    }

    /// Records the body of a block unless the finalized tip covers its
    /// height. Such a stale block is expunged so that it is neither
    /// fetched nor forwarded again.
    ///
    /// Re-recording clears a rejection but keeps the delivery status.
    pub(super) fn record_block(&mut self, block: Arc<Block>) {
        if block.height() <= self.network_finalized_tip.1 {
            debug!(
                digest = %block.digest(),
                height = %block.height(),
                "block is at or below the finalized tip; dropping it from the tree",
            );
            self.remove(&block.digest());
            return;
        }
        let digest = block.digest();
        let delivered = self
            .blocks
            .get(&digest)
            .is_some_and(|entry| entry.delivered);
        self.blocks.insert(
            digest,
            BlockEntry {
                block,
                delivered,
                rejected_at: None,
            },
        );
    }

    /// Converges the tree's stored state onto the advancing finalized tip
    /// of the network: bodies at or below it, and a pending head it
    /// covers, are dropped. The actor runs this once per event-loop
    /// iteration, before any scheduling decision reads the tree, which
    /// keeps the recording methods simple inserts.
    ///
    /// Nothing else is pruned. Off-path bodies stay: a body off the
    /// canonical path today may be built on again tomorrow (deleting it
    /// would force a re-fetch). In particular, should the network
    /// flip-flop between branches of the notarized tree, every branch
    /// stays resident and each re-root recovers without fetching - memory
    /// traded for recovery speed, bounded by the advancing finalized tip,
    /// which sweeps everything it passes.
    pub(super) fn heal(&mut self) {
        // `first_missing_ancestor`, `next_to_deliver` and `next_head` bound
        // their walks by the network's finalized tip, which is only correct
        // while the locally canonicalized finalized tip does not run ahead
        // of it. The marshal actor upholds this: it reports a finalized tip
        // before delivering the finalized blocks covered by it.
        debug_assert!(
            self.local_finalized_tip.0 <= self.network_finalized_tip.1,
            "the locally canonicalized finalized tip must never run ahead of \
            the observed finalized tip of the network",
        );

        let (finalized_round, finalized_height, finalized_digest) = self.network_finalized_tip;
        self.blocks
            .retain(|_, entry| entry.block.height() > finalized_height);
        // A pending head the finalized tip covers is stale: the tip itself
        // becomes the convergence target, until a newer report supersedes
        // it.
        if self.pending_head.notarized_in <= finalized_round
            && self.pending_head.digest != finalized_digest
        {
            self.pending_head = PendingHead::finalized_tip(self.network_finalized_tip);
        }
    }

    /// Marks the block as accepted by the execution layer, clearing any
    /// rejection.
    pub(super) fn mark_delivered(&mut self, digest: &Digest) {
        if let Some(entry) = self.blocks.get_mut(digest) {
            entry.delivered = true;
            entry.rejected_at = None;
        }
    }

    /// Withholds the block from delivery for [`NOTARIZED_REJECTION_RETRY_DELAY`]
    /// after `now` and revokes its delivery status. Returns whether the tree
    /// holds the block.
    pub(super) fn mark_rejected(&mut self, digest: &Digest, now: SystemTime) -> bool {
        let Some(entry) = self.blocks.get_mut(digest) else {
            return false;
        };
        entry.rejected_at = Some(now);
        entry.delivered = false;
        true
    }

    /// Removes a block from the tree, re-setting a pending head naming it
    /// to the finalized tip, so that nothing keeps fetching or forwarding
    /// it.
    fn remove(&mut self, digest: &Digest) {
        self.blocks.remove(digest);
        if self.pending_head.digest == *digest {
            self.pending_head = PendingHead::finalized_tip(self.network_finalized_tip);
        }
    }

    /// Advances the finalized tip of the network, the tree's ownership
    /// boundary with the finalization pipeline. Dropping the data the new
    /// tip covers is [`Self::heal`]'s job.
    ///
    /// Tips at or below the already tracked round (a tip replayed on
    /// startup) are ignored, so the boundary never regresses. The marshal
    /// actor guarantees that a newer round never finalizes a lower height.
    pub(super) fn set_network_finalized_tip(
        &mut self,
        round: Round,
        height: Height,
        digest: Digest,
    ) {
        if round > self.network_finalized_tip.0 {
            self.network_finalized_tip = (round, height, digest);
        } else {
            debug!(
                %round,
                %height,
                %digest,
                "ignoring finalized tip that does not advance the tracked one",
            );
        }
    }

    /// The lowest block on the pending head's ancestry the execution layer
    /// does not have but whose parent it has, if the ancestry is walkable
    /// and no block on the way is withheld.
    pub(super) fn next_to_deliver(&self, now: SystemTime) -> Option<Arc<Block>> {
        let (_, finalized_height, _) = self.network_finalized_tip;

        let mut candidate: Option<&BlockEntry> = None;
        let mut digest = self.pending_head.digest;
        while !self.is_known(digest) {
            let entry = self.blocks.get(&digest)?;
            if entry.block.height() <= finalized_height || !entry.forwardable(now) {
                return None;
            }
            candidate = Some(entry);
            digest = entry.block.parent_digest();
        }
        candidate.map(|entry| entry.block.clone())
    }

    /// The highest block on the pending head's ancestry the execution layer
    /// has, if it is not the head already, the ancestry down to it is
    /// walkable, and no block on the way is withheld. Bottoming out on the
    /// finalized tip repoints onto it.
    pub(super) fn next_head(&self, now: SystemTime) -> Option<(Height, Digest)> {
        let (_, finalized_height, _) = self.network_finalized_tip;

        let mut digest = self.pending_head.digest;
        loop {
            if digest == self.local_head.1 {
                return None;
            }
            if let Some(height) = self.known_height(digest) {
                return Some((height, digest));
            }
            let entry = self.blocks.get(&digest)?;
            if entry.block.height() <= finalized_height || !entry.forwardable(now) {
                return None;
            }
            digest = entry.block.parent_digest();
        }
    }

    /// Returns the first missing ancestor on the pending head's path,
    /// together with the round it was notarized in.
    ///
    /// A notarization implies the notarization of all its ancestors up to
    /// the finalized tip, so a missing ancestor body must be fetched even if
    /// no explicit notarization fact was observed for it.
    pub(super) fn first_missing_ancestor(&self) -> Option<(Round, Digest)> {
        let (finalized_round, finalized_height, finalized_digest) = self.network_finalized_tip;
        // The round of the pending head comes from the context that
        // reported it; further down the path it is derived from the context
        // of the child walked through.
        let mut round = self.pending_head.notarized_in;
        let mut digest = self.pending_head.digest;
        // The stop conditions are evaluated for every candidate digest
        // before it can be reported missing; otherwise the walk would
        // report the finalized tip itself (whose body is deliberately never
        // recorded) as a gap.
        while digest != finalized_digest && round > finalized_round {
            let Some(entry) = self.blocks.get(&digest) else {
                return Some((round, digest));
            };
            if entry.block.height() <= finalized_height {
                break;
            }
            round = entry.parent_round();
            digest = entry.block.parent_digest();
        }
        None
    }
}
