//! The notarized tree: the executor's record of the chain above the
//! finalized tip, of the forkchoice state the execution layer last
//! accepted, and of how far that state has converged onto the pending
//! head's ancestry.

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
/// withheld from forwarding before it becomes eligible for a retry.
pub(super) const NOTARIZED_REJECTION_RETRY_DELAY: Duration = Duration::from_secs(10);

/// A block known to the executor together with the validator set to validate
/// it against.
#[derive(Clone, Debug)]
pub(super) struct BlockEntry {
    pub(super) block: Arc<Block>,
    rejected_at: Option<SystemTime>,
}

impl BlockEntry {
    /// Whether the block may be forwarded at `now`: it is not withheld by
    /// a rejection younger than [`NOTARIZED_REJECTION_RETRY_DELAY`].
    fn forwardable(&self, now: SystemTime) -> bool {
        self.rejected_at
            .is_none_or(|rejected_at| now >= rejected_at + NOTARIZED_REJECTION_RETRY_DELAY)
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

/// Tracks notarized blocks at the tip of the chain and returns which block can
/// be forwarded to the EL next.
///
/// The canonical target is `pending_head`: the parent of the most recent
/// consensus context. This is expected to be reported by the simplex engine via
/// the application actor, and constitutes the view (/block) that simplex
/// expects to verify or build blocks on top of.
///
/// Contexts double as notarization proofs for their parents, but parents are
/// not monotonic: after nullifications, a later view may build on an *older*
/// notarized block than its predecessor, and so supersession is arbitrated by
/// the round of the *reporting* context, and the canonical path is the pending
/// head's ancestry rather than the highest known notarization's.
///
/// Block bodies are captured from validation requests and the node's own
/// builds (the proposer never verifies its own block) or fetched from the
/// marshal actor; combined with the reports, they reconstruct the
/// canonical path on top of the finalized tip.
///
/// The tree holds data strictly above the finalized *network* tip,
/// which it tracks itself: recording and pruning are guarded against it.
///
/// The tree is self-canonicalizing: [`Self::next_to_forward`] walks the
/// pending head's ancestry down to the nearest *anchor* the execution
/// layer provably has - its own head, or the network's finalized tip -
/// and hands out the block directly above it, derived fresh on every
/// query. There is no cached convergence state that could go stale
/// against a fork.
///
/// Recording methods only insert primary state (the pending head, the
/// local state, and bodies, guarded against the finalized tip);
/// [`Self::heal`], run by the actor once per event-loop iteration, prunes
/// what the advancing finalized tip covers.
#[derive(Debug)]
pub(super) struct NotarizedTree {
    /// The latest observed finalized tip of the network: the tree's
    /// lower bound. The tree only records notarized blocks above this finalized
    /// tip.
    network_finalized_tip: (Round, Height, Digest),
    /// The finalized tip as canonicalized on the execution layer: the
    /// finalized side of the last accepted forkchoice state. Trails
    /// `network_finalized_tip` until the finalization pipeline catches up,
    /// which forwarding is gated on.
    local_finalized_tip: (Height, Digest),
    /// The pending head reported by the most recent consensus context, if
    /// any: the tip of the canonical path the execution layer's head is
    /// converged onto. `None` until the first report after startup, or
    /// after the finalized tip swept the last one.
    pending_head: Option<PendingHead>,
    /// The execution layer's current head: the head side of the last
    /// accepted forkchoice state.
    local_head: (Height, Digest),
    /// Bodies of blocks at the tip of the chain, keyed by digest.
    blocks: HashMap<Digest, BlockEntry>,
}

/// The parent of the most recent consensus context: the notarized block
/// consensus reports building on, and hence the block the execution
/// layer's head must converge to.
#[derive(Clone, Copy, Debug)]
struct PendingHead {
    /// The round of the context that reported this parent. Arbitrates
    /// supersession: parents are not monotonic, reports are.
    reported_in: Round,
    /// The round the parent was notarized in (its view within the reporting
    /// context's epoch); the fetch hint for a missing body.
    notarized_in: Round,
    digest: Digest,
}

impl NotarizedTree {
    pub(super) fn new(
        network_finalized_tip: (Round, Height, Digest),
        local_state: LocalState,
    ) -> Self {
        Self {
            network_finalized_tip,
            local_finalized_tip: local_state.finalized,
            pending_head: None,
            local_head: local_state.head,
            blocks: HashMap::new(),
        }
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

    /// Whether `digest` is the execution layer's current head.
    pub(super) fn is_execution_head(&self, digest: Digest) -> bool {
        self.local_head.1 == digest
    }

    /// Records a forkchoice state newly accepted by the execution layer.
    pub(super) fn set_local_state(&mut self, local_state: LocalState) {
        self.local_head = local_state.head;
        self.local_finalized_tip = local_state.finalized;
    }

    /// Records a consensus context's parent as the pending head of the
    /// chain, superseding the report of any older context.
    ///
    /// Supersession is arbitrated by `reported_in` - the round of the
    /// reporting context - because parents themselves are not monotonic:
    /// after nullifications, a later view may build on an older notarized
    /// block than its predecessor did. Parents covered by the finalized
    /// tip are not recorded; the finalization pipeline owns them.
    pub(super) fn set_pending_head(
        &mut self,
        reported_in: Round,
        notarized_in: Round,
        digest: Digest,
    ) {
        let (finalized_round, _, finalized_digest) = self.network_finalized_tip;
        if notarized_in <= finalized_round || digest == finalized_digest {
            return;
        }
        if self
            .pending_head
            .as_ref()
            .is_none_or(|pending| reported_in > pending.reported_in)
        {
            self.pending_head = Some(PendingHead {
                reported_in,
                notarized_in,
                digest,
            });
        }
    }

    /// Records the body of a block unless the finalized tip covers its
    /// height. Such a stale block is expunged so that it is neither
    /// fetched nor forwarded again.
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
        self.blocks.insert(
            block.digest(),
            BlockEntry {
                block,
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
        // `first_missing_ancestor` and `next_to_forward` bound their walks
        // by the network's finalized tip, which is only correct while the
        // locally canonicalized finalized tip does not run ahead of it. The
        // marshal actor upholds this: it reports a finalized tip before
        // delivering the finalized blocks covered by it.
        debug_assert!(
            self.local_finalized_tip.0 <= self.network_finalized_tip.1,
            "the locally canonicalized finalized tip must never run ahead of \
            the observed finalized tip of the network",
        );

        let (finalized_round, finalized_height, _) = self.network_finalized_tip;
        self.blocks
            .retain(|_, entry| entry.block.height() > finalized_height);
        if self
            .pending_head
            .as_ref()
            .is_some_and(|pending| pending.notarized_in <= finalized_round)
        {
            self.pending_head = None;
        }
    }

    /// Marks the block as rejected by the execution layer at `now`,
    /// excluding it from forwarding until
    /// [`NOTARIZED_REJECTION_RETRY_DELAY`] has elapsed or the entry is
    /// expunged.
    pub(super) fn mark_rejected(&mut self, digest: &Digest, now: SystemTime) {
        if let Some(entry) = self.blocks.get_mut(digest) {
            entry.rejected_at = Some(now);
        }
    }

    /// Removes a block from the tree, including a pending head naming
    /// it, so that nothing keeps fetching or forwarding it.
    fn remove(&mut self, digest: &Digest) {
        self.blocks.remove(digest);
        if self
            .pending_head
            .as_ref()
            .is_some_and(|pending| pending.digest == *digest)
        {
            self.pending_head = None;
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

    /// Returns the next notarized block to forward to the execution layer:
    /// the block directly above the first *anchor* - the local head or the
    /// network's finalized tip, both provably known to the execution layer
    /// - that the walk down the pending head's ancestry reaches.
    ///
    /// A head off the ancestry is no anchor: the walk runs to the
    /// finalized tip and forwarding replays the path from there (replayed
    /// blocks are answered from the execution layer's caches, and the
    /// forkchoice update may move the head backwards - which is also how
    /// the head is repointed after consensus switched to building on an
    /// older notarized block).
    pub(super) fn next_to_forward(&self, now: SystemTime) -> Option<&BlockEntry> {
        if self.local_finalized_tip.0 < self.network_finalized_tip.1 {
            return None;
        }
        let pending = self.pending_head.as_ref()?;
        let (_, finalized_height, finalized_digest) = self.network_finalized_tip;

        let mut child: Option<&BlockEntry> = None;
        let mut digest = pending.digest;
        while digest != self.local_head.1 && digest != finalized_digest {
            let entry = self.blocks.get(&digest)?;
            if entry.block.height() <= finalized_height {
                return None;
            }
            child = Some(entry);
            digest = entry.block.parent_digest();
        }
        child.filter(|entry| entry.forwardable(now))
    }

    /// Returns the first missing ancestor on the pending head's path,
    /// together with the round it was notarized in.
    ///
    /// A notarization implies the notarization of all its ancestors up to
    /// the finalized tip, so a missing ancestor body must be fetched even if
    /// no explicit notarization fact was observed for it.
    pub(super) fn first_missing_ancestor(&self) -> Option<(Round, Digest)> {
        let (finalized_round, finalized_height, finalized_digest) = self.network_finalized_tip;
        let pending = self.pending_head.as_ref()?;
        // The round of the pending head comes from the context that
        // reported it; further down the path it is derived from the context
        // of the child walked through.
        let mut round = pending.notarized_in;
        let mut digest = pending.digest;
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
            let context = entry.block.context();
            round = Round::new(context.round.epoch(), context.parent.0);
            digest = entry.block.parent_digest();
        }
        None
    }
}
