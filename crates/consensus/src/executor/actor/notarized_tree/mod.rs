//! The notarized tree: the executor's record of the chain above the
//! finalized tip, and of how far the execution layer has converged onto
//! the pending head's ancestry.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime},
};

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

/// Tracks notarized blocks at the tip of the chain and returns which block can
/// be forwarded to the EL next.
///
/// The canonical target `pending_head`: the parent of the most recent consensus
/// context. This is expected to be reported by the simplex engine via the
/// application actor, and consitutes the view (/block) that simplex expects to
/// verify or build blocks on top of.
///
/// Contexts double as notarization proofs for their parents, but parents are
/// not monotonic: after nullifications, a later view may build on an *older*
/// notarized block than its predecssor, and so supersession is arbitrated by
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
/// The tree is self-canonicalizing: it tracks how far along the
/// canonical notarized path the execution layer's head has been advanced
/// (the `notarized_cursor`) and hands out the block directly above the
/// cursor as the next to forward.
///
/// Recording methods only insert primary state (the pending head and
/// bodies, guarded against the finalized tip). Everything derived from it - pruning what
/// the finalized tip covers, and sinking a cursor whose block was forked
/// out to the fork point (a block the execution layer provably has, so the
/// common trunk is never re-forwarded) - is re-established by
/// [`Self::heal`], which the actor runs once per event-loop iteration,
/// before any scheduling decision reads the tree.
#[derive(Debug)]
pub(super) struct NotarizedTree {
    /// The latest observed finalized tip of the network: the tree's
    /// lower bound. Data at or below it is never recorded, and recorded data
    /// is pruned once the tip moves past it.
    finalized_tip: (Round, Height, Digest),
    /// The canonicalization cursor: the most recent block on the canonical
    /// notarized path that the execution layer provably has. Blocks are
    /// forwarded strictly above it.
    ///
    /// The cursor never runs ahead of the execution layer's head, but it may
    /// trail it: when the canonical path forks away, the cursor sinks to
    /// the fork point (an ancestor of the head, hence still known to the
    /// execution layer), and when the finalized tip advances past it, it is
    /// reset to that tip - which the execution layer only knows once the
    /// finalization pipeline has caught up, so the caller must gate
    /// forwarding on that (see [`super::Actor::next_notarized_forward`]).
    notarized_cursor: (Height, Digest),
    /// The pending head reported by the most recent consensus context, if
    /// any: the tip of the canonical path the execution layer's head is
    /// converged onto. `None` until the first report after startup, or
    /// after the finalized tip swept the last one.
    pending_head: Option<PendingHead>,
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
        finalized_tip: (Round, Height, Digest),
        notarized_cursor: (Height, Digest),
    ) -> Self {
        Self {
            finalized_tip,
            notarized_cursor,
            pending_head: None,
            blocks: HashMap::new(),
        }
    }

    /// Records a consensus context's parent as the pending head of the
    /// chain, superseding the report of any older context.
    ///
    /// Supersession is arbitrated by `reported_in` - the round of the
    /// reporting context - because parents themselves are not monotonic:
    /// after nullifications, a later view may build on an older notarized
    /// block than its predecessor did. Parents covered by the finalized
    /// tip are not recorded; the finalization pipeline owns them.
    pub(super) fn record_reported_parent(
        &mut self,
        reported_in: Round,
        notarized_in: Round,
        digest: Digest,
    ) {
        let (finalized_round, _, finalized_digest) = self.finalized_tip;
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
        if block.height() <= self.finalized_tip.1 {
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

    /// Records the execution layer's canonical head, advancing the
    /// canonicalization cursor when the head sits on the canonical notarized
    /// path above the cursor.
    ///
    /// Anything else is ignored: the cursor must never name a block off the
    /// canonical path, and it only ever moves backwards through
    /// [`Self::heal`], which upholds that.
    pub(super) fn record_execution_notarized(&mut self, height: Height, head: Digest) {
        if height <= self.notarized_cursor.0 || head == self.notarized_cursor.1 {
            return;
        }
        let Some(pending) = &self.pending_head else {
            return;
        };
        let mut digest = pending.digest;
        while digest != self.notarized_cursor.1 {
            if digest == head {
                self.notarized_cursor = (height, head);
                return;
            }
            let Some(entry) = self.blocks.get(&digest) else {
                return;
            };
            digest = entry.block.parent_digest();
        }
    }

    /// Converges the tree's derived state onto its primary state (the
    /// pending head, bodies, finalized tip, and execution heads recorded
    /// since the last pass). The actor runs this once per event-loop iteration,
    /// before any scheduling decision reads the tree, which keeps the
    /// recording methods simple inserts.
    ///
    /// Idempotent, in two steps:
    ///
    /// 1. The finalized tip's ownership boundary is enforced: data at or
    ///    below it is dropped, and a cursor it overtook is reset to it
    ///    (the execution layer only knows the tip once the finalization
    ///    pipeline has caught up, which forwarding is gated on - see
    ///    [`super::Actor::next_notarized_forward`]).
    /// 2. A cursor whose block is off the pending head's ancestry sinks to
    ///    the fork point: first against the pending head itself (consensus
    ///    builds on the pending head, so nothing above it is currently
    ///    built on), then along its ancestry for strandings below it (see
    ///    [`Self::sink_stranded_cursor`]). This step needs the pending
    ///    head's height and waits until its body has arrived.
    ///
    /// Nothing beyond the finalized tip's sweep is pruned. Off-path
    /// bodies stay: a body off the
    /// canonical path today may be built on again tomorrow (deleting it
    /// would force a re-fetch). In particular, should the network
    /// flip-flop between branches of the notarized tree, every branch
    /// stays resident and each re-root recovers without fetching - memory
    /// traded for recovery speed, bounded by the advancing finalized tip,
    /// which sweeps everything it passes.
    pub(super) fn heal(&mut self) {
        let (finalized_round, finalized_height, finalized_digest) = self.finalized_tip;
        self.blocks
            .retain(|_, entry| entry.block.height() > finalized_height);
        if self
            .pending_head
            .as_ref()
            .is_some_and(|pending| pending.notarized_in <= finalized_round)
        {
            self.pending_head = None;
        }
        if self.notarized_cursor.0 <= finalized_height {
            self.notarized_cursor = (finalized_height, finalized_digest);
        }

        let Some(pending) = &self.pending_head else {
            return;
        };
        let pending_digest = pending.digest;
        let Some(entry) = self.blocks.get(&pending_digest) else {
            return;
        };
        let pending_height = entry.block.height();
        self.sink_cursor(pending_height, pending_digest);
        self.sink_stranded_cursor();
    }

    /// Sinks the canonicalization cursor below `height` when the caller has
    /// proven that `canonical` - a different block - holds that height on
    /// the canonical notarized path.
    ///
    /// Each step moves the cursor to the parent of its current block - an
    /// ancestor of the execution layer's head, hence known to it. Repeated
    /// sinking converges on the fork point level by level as the forked-out
    /// blocks are discovered. If a body is missing the cursor stays put and
    /// forwarding stalls until the finalized tip catches up and resets it.
    fn sink_cursor(&mut self, height: Height, canonical: Digest) {
        while self.notarized_cursor.0 >= height && self.notarized_cursor.1 != canonical {
            let Some(entry) = self.blocks.get(&self.notarized_cursor.1) else {
                return;
            };
            let Some(parent_height) = entry.block.height().previous() else {
                return;
            };
            self.notarized_cursor = (parent_height, entry.block.parent_digest());
        }
    }

    /// Re-roots a canonicalization cursor stranded on a sibling of the
    /// pending head's ancestry.
    ///
    /// Walks the walkable prefix of the ancestry; a visited height claimed
    /// by the cursor under a different digest proves the cursor's block off
    /// the canonical path, and the cursor sinks toward the fork point. This
    /// covers strandings strictly below the pending head's height - which
    /// [`Self::heal`]'s sink against the pending head itself cannot see -
    /// for example after a fork whose blocks were all cached (by
    /// validations or the node's own builds) before they became canonical,
    /// so that no fetch ever repaired a gap. Without this walk, the cursor
    /// would stay stranded, unreachable from the pending head, until the
    /// finalized tip overtakes it.
    fn sink_stranded_cursor(&mut self) {
        let Some(pending) = &self.pending_head else {
            return;
        };
        let mut digest = pending.digest;
        while digest != self.finalized_tip.2 && digest != self.notarized_cursor.1 {
            let Some(entry) = self.blocks.get(&digest) else {
                return;
            };
            let height = entry.block.height();
            if height <= self.finalized_tip.1 {
                return;
            }
            let parent = entry.block.parent_digest();
            if self.notarized_cursor.0 == height {
                self.sink_cursor(height, digest);
            }
            digest = parent;
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
    /// tip covers - and resetting a cursor it overtook - is
    /// [`Self::heal`]'s job.
    ///
    /// Tips at or below the already tracked round (a tip replayed on
    /// startup) are ignored, so the boundary never regresses. The marshal
    /// actor guarantees that a newer round never finalizes a lower height.
    pub(super) fn advance_finalized(&mut self, round: Round, height: Height, digest: Digest) {
        if round > self.finalized_tip.0 {
            self.finalized_tip = (round, height, digest);
        } else {
            debug!(
                %round,
                %height,
                %digest,
                "ignoring finalized tip that does not advance the tracked one",
            );
        }
    }

    /// Returns the next notarized block to forward to the execution layer,
    /// if any: the block directly above the canonicalization cursor on the
    /// canonical notarized path.
    ///
    /// Returns nothing if we don't have the block yet - or if the block failed
    /// execution and not enough time has passed between rejection and `now`.
    pub(super) fn next_to_forward(&self, now: SystemTime) -> Option<&BlockEntry> {
        let mut digest = self.pending_head.as_ref()?.digest;
        let mut child: Option<&BlockEntry> = None;
        while digest != self.notarized_cursor.1 {
            let entry = self.blocks.get(&digest)?;
            child = Some(entry);
            digest = entry.block.parent_digest();
        }
        child.filter(|entry| entry.forwardable(now))
    }

    /// Returns the pending head when the execution layer's head must be
    /// repointed at it: convergence is complete (the cursor sits on the
    /// pending head, so the execution layer provably has the block), yet
    /// `head` is a different block. This happens when consensus switches
    /// to building on an *older* notarized block - abandoning a
    /// notarized-but-uncertified child the head was already advanced to -
    /// and only a forkchoice update moves the head back.
    ///
    /// The returned block goes through the ordinary forwarding machinery
    /// (its new-payload request is answered from the execution layer's
    /// cache, the forkchoice update repoints the head), so rejection
    /// pacing applies as usual.
    pub(super) fn pending_head_to_repoint(
        &self,
        head: Digest,
        now: SystemTime,
    ) -> Option<&BlockEntry> {
        let pending = self.pending_head.as_ref()?;
        if pending.digest == head || self.notarized_cursor.1 != pending.digest {
            return None;
        }
        self.blocks
            .get(&pending.digest)
            .filter(|entry| entry.forwardable(now))
    }

    /// Returns the first missing ancestor on the pending head's path,
    /// together with the round it was notarized in.
    ///
    /// A notarization implies the notarization of all its ancestors up to
    /// the finalized tip, so a missing ancestor body must be fetched even if
    /// no explicit notarization fact was observed for it.
    pub(super) fn first_missing_ancestor(&self) -> Option<(Round, Digest)> {
        let (finalized_round, finalized_height, finalized_digest) = self.finalized_tip;
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

impl NotarizedTree {
    /// The height of the latest observed finalized tip of the network.
    pub(super) fn finalized_tip_height(&self) -> Height {
        self.finalized_tip.1
    }
}
