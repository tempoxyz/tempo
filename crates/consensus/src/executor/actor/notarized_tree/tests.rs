use alloy_primitives::B256;
use commonware_consensus::types::{Epoch, Height, Round, View};
use reth_node_core::primitives::SealedBlock;
use tempo_primitives::{Block as TempoBlock, TempoConsensusContext, TempoHeader};

use commonware_consensus::{CertifiableBlock as _, Heightable as _};

use std::time::{Duration, SystemTime};

use super::{LocalState, NOTARIZED_REJECTION_RETRY_DELAY, NextToForward, NotarizedTree};
use crate::consensus::{Digest, block::Block};

/// The reference "now" for tree queries; tests state rejection times
/// relative to it.
const T0: SystemTime = SystemTime::UNIX_EPOCH;

/// A tree whose observed finalized network tip is `finalized` at
/// height 10, round 0 — as for an execution layer whose head sits at the
/// finalized tip.
fn empty_tree(finalized: Digest) -> NotarizedTree {
    NotarizedTree::new(
        (round(0), Height::new(10), finalized),
        LocalState {
            head: (Height::new(10), finalized),
            finalized: (Height::new(10), finalized),
        },
    )
}

fn round(view: u64) -> Round {
    Round::new(Epoch::zero(), View::new(view))
}

/// Builds a block constructed in `view` at `height` on top of `parent`.
/// Siblings that share height and parent are told apart by their views,
/// like in the real protocol.
///
/// The consensus context claims a parent from view `view - 1` (blocks
/// must carry a context; consensus rejects them otherwise).
fn block(view: u64, height: u64, parent: Digest) -> Block {
    Block::from_execution_block_unchecked(
        SealedBlock::seal_slow(TempoBlock {
            header: TempoHeader {
                inner: alloy_consensus::Header {
                    number: height,
                    parent_hash: parent.0,
                    ..Default::default()
                },
                consensus_context: Some(TempoConsensusContext {
                    epoch: 0,
                    view,
                    parent_view: view - 1,
                    proposer: tempo_primitives::ed25519::PublicKey::from_seed(42),
                }),
                ..Default::default()
            },
            body: Default::default(),
        }),
        None,
    )
}

/// Reports `block` as the notarized parent of a consensus context — as
/// simplex does when a proposal builds on it.
fn report_parent(tree: &mut NotarizedTree, block: &Block) {
    tree.set_pending_head(block.context().round, block.digest());
}

/// Reports the block as the parent of a consensus context — as simplex
/// does when the next proposal builds on it — and records its body, then
/// heals, mirroring the actor's event loop running between messages.
fn record(tree: &mut NotarizedTree, block: &Block) {
    report_parent(tree, block);
    tree.record_block(block.clone().into());
    tree.heal();
}

/// The next block to forward, if any; panics if the next convergence step
/// is a repoint instead of a block.
fn next_block(tree: &NotarizedTree, now: SystemTime) -> Option<std::sync::Arc<Block>> {
    match tree.next_to_forward(now) {
        Some(NextToForward::Block(block)) => Some(block),
        Some(NextToForward::Repoint(height, digest)) => {
            panic!("expected a block to forward, got a repoint to `{digest}` at `{height}`")
        }
        None => None,
    }
}

/// Simulates the completed forward of `block`: the execution layer
/// accepted it as its new head, and the resulting forkchoice state is
/// reported back into the tree.
fn forwarded(tree: &mut NotarizedTree, block: &Block) {
    let local_state = tree
        .local_state()
        .update_head(block.height(), block.digest());
    tree.set_local_state(local_state);
}

#[test]
fn forwards_chain_on_top_of_finalized_tip_in_order() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    let a = block(1, 11, finalized);
    let b = block(2, 12, a.digest());
    record(&mut tree, &a);
    record(&mut tree, &b);

    let next = next_block(&tree, T0).expect("chain start");
    assert_eq!(next.digest(), a.digest());

    forwarded(&mut tree, &a);
    let next = next_block(&tree, T0).expect("chain continues");
    assert_eq!(next.digest(), b.digest());

    forwarded(&mut tree, &b);
    assert!(next_block(&tree, T0).is_none());
}

#[test]
fn sibling_notarized_in_later_round_supersedes() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    let a1 = block(1, 11, finalized);
    let a2 = block(2, 11, finalized);
    record(&mut tree, &a1);
    // The stale sibling was forwarded and become the head ...
    forwarded(&mut tree, &a1);

    // ... but a report of its sibling redefines the canonical path; the
    // walk anchors at the finalized tip, and the superseding sibling is
    // forwarded next.
    record(&mut tree, &a2);
    let next = next_block(&tree, T0).expect("supersede fork");
    assert_eq!(next.digest(), a2.digest());
}

#[test]
fn fork_replays_from_the_nearest_anchor() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    // F - N0 - N1 - N2 is forwarded in full ...
    let n0 = block(1, 11, finalized);
    let n1 = block(2, 12, n0.digest());
    let n2 = block(3, 13, n1.digest());
    record(&mut tree, &n0);
    record(&mut tree, &n1);
    record(&mut tree, &n2);
    forwarded(&mut tree, &n2);
    assert!(next_block(&tree, T0).is_none());

    // ... when F - N0 - N1' - N3 becomes the canonical chain. The report
    // arrives before the bodies; forwarding stalls until the ancestry
    // is walkable.
    let n1p = block(4, 12, n0.digest());
    let n3 = block(5, 13, n1p.digest());
    report_parent(&mut tree, &n3);
    tree.heal();
    assert!(next_block(&tree, T0).is_none());

    // N3's body arrives, but its parent N1' is still missing: the
    // ancestry does not reach down to a block the execution layer has.
    tree.record_block(n3.clone().into());
    tree.heal();
    assert!(next_block(&tree, T0).is_none());

    // N1' arrives via the fetch machinery, completing the ancestry. The
    // head (N2) sits off the new canonical path and is no anchor, so the
    // walk runs to the finalized tip and the path is replayed from there:
    // the trunk block N0 - already known to the execution layer, which
    // answers it from its caches - comes first, then the fork branch.
    tree.record_block(n1p.clone().into());
    tree.heal();

    let next = next_block(&tree, T0).expect("trunk replay");
    assert_eq!(next.digest(), n0.digest());
    forwarded(&mut tree, &n0);
    let next = next_block(&tree, T0).expect("fork branch");
    assert_eq!(next.digest(), n1p.digest());
    forwarded(&mut tree, &n1p);
    let next = next_block(&tree, T0).expect("fork tip");
    assert_eq!(next.digest(), n3.digest());
}

#[test]
fn fork_during_ancestor_fetch_keeps_the_fetch_target() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    // F - N1 - N2 is forwarded in full ...
    let n1 = block(1, 11, finalized);
    let n2 = block(2, 12, n1.digest());
    record(&mut tree, &n1);
    record(&mut tree, &n2);
    forwarded(&mut tree, &n2);

    // ... when the chain forks to F - N3 - N4. N3's report arrives first
    // (from the context preceding N4's validation) and becomes the
    // fetch target; N4's body arrives through its validation.
    let n3 = block(3, 11, finalized);
    let n4 = block(4, 12, n3.digest());
    report_parent(&mut tree, &n3);
    tree.heal();
    assert_eq!(tree.first_missing_ancestor(), Some((round(3), n3.digest())),);
    tree.record_block(n4.clone().into());
    tree.heal();

    // N4's report supersedes ...
    report_parent(&mut tree, &n4);
    tree.heal();

    // ... and the fetch target is unchanged — N3, re-derived from N4's
    // context — so the in-flight fetch for N3 is kept, and forwarding
    // stalls on the gap meanwhile.
    assert_eq!(tree.first_missing_ancestor(), Some((round(3), n3.digest())),);
    assert!(next_block(&tree, T0).is_none());

    // The landed fetch delivers N3's body, completing the ancestry down
    // to the finalized tip - the anchor while the head sits on the
    // orphaned branch.
    tree.record_block(n3.clone().into());
    tree.heal();

    let next = next_block(&tree, T0).expect("fork branch");
    assert_eq!(next.digest(), n3.digest());
    forwarded(&mut tree, &n3);
    let next = next_block(&tree, T0).expect("fork tip");
    assert_eq!(next.digest(), n4.digest());
    forwarded(&mut tree, &n4);
    assert!(next_block(&tree, T0).is_none());
}

#[test]
fn heads_off_the_canonical_path_are_no_anchor() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    let a = block(1, 11, finalized);
    let b1 = block(2, 12, a.digest());
    let b2 = block(3, 12, a.digest());
    record(&mut tree, &a);
    record(&mut tree, &b1);
    record(&mut tree, &b2);

    // A head off the canonical path (b1 was superseded by b2) is no
    // anchor: the walk runs to the finalized tip, and the path is
    // replayed from there - the common parent a first (a cached no-op
    // for the execution layer), then the superseding sibling.
    forwarded(&mut tree, &a);
    forwarded(&mut tree, &b1);
    let next = next_block(&tree, T0).expect("replayed parent");
    assert_eq!(next.digest(), a.digest());
    forwarded(&mut tree, &a);
    let next = next_block(&tree, T0).expect("chain continues");
    assert_eq!(next.digest(), b2.digest());
}

#[test]
fn missing_body_caps_the_chain() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    let a = block(1, 11, finalized);
    let b = block(2, 12, a.digest());
    let c = block(3, 13, b.digest());
    record(&mut tree, &a);
    // b's notarization is known but its body is not.
    report_parent(&mut tree, &b);
    record(&mut tree, &c);

    forwarded(&mut tree, &a);
    assert!(next_block(&tree, T0).is_none());
}

#[test]
fn finalized_tip_bounds_recording() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    let a = block(5, 11, finalized);
    let b = block(6, 12, a.digest());
    tree.set_network_finalized_tip(round(5), Height::new(11), a.digest());
    tree.heal();

    // Recording is unconditional - the last report wins - and the heal
    // pass re-sets a pending head notarized at or below the finalized
    // round back onto the finalized tip, the default convergence target.
    tree.set_pending_head(round(5), b.digest());
    assert_eq!(tree.pending_head.digest, b.digest());
    tree.heal();
    assert_eq!(tree.pending_head.digest, a.digest());
    tree.set_pending_head(round(5), a.digest());
    tree.heal();
    assert_eq!(
        tree.pending_head.digest,
        a.digest(),
        "a pending head naming the finalized tip must survive healing",
    );
    tree.set_pending_head(round(6), b.digest());
    assert_eq!(tree.pending_head.digest, b.digest());

    // A body at or below the finalized height is rejected and takes a
    // pending head naming it along, so that it is neither fetched nor
    // forwarded.
    let stale = block(7, 11, finalized);
    tree.set_pending_head(round(7), stale.digest());
    tree.record_block(stale.clone().into());
    assert!(!tree.blocks.contains_key(&stale.digest()));
    assert_eq!(tree.pending_head.digest, a.digest());

    tree.record_block(b.clone().into());
    assert!(tree.blocks.contains_key(&b.digest()));
}

#[test]
fn recognizes_finalized_tip_without_block_body() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);
    let next = block(1, 11, finalized);

    tree.set_network_finalized_tip(round(1), next.height(), next.digest());

    assert_eq!(tree.network_finalized_tip.2, next.digest());
    assert!(!tree.blocks.contains_key(&next.digest()));
}

#[test]
fn advance_finalized_drops_stale_entries() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    let a = block(1, 11, finalized);
    let b = block(2, 12, a.digest());
    record(&mut tree, &a);
    record(&mut tree, &b);

    tree.set_network_finalized_tip(round(1), Height::new(11), a.digest());
    tree.heal();

    assert!(!tree.blocks.contains_key(&a.digest()));
    assert!(tree.blocks.contains_key(&b.digest()));
    // The pending head - b, notarized above the new finalized round -
    // survives the sweep.
    assert_eq!(tree.pending_head.digest, b.digest());
}

#[test]
fn finalized_tip_never_regresses() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    let a = block(1, 11, finalized);
    let b = block(2, 12, a.digest());
    record(&mut tree, &a);
    record(&mut tree, &b);
    tree.set_network_finalized_tip(round(1), Height::new(11), a.digest());
    tree.heal();
    forwarded(&mut tree, &b);

    // A tip below the tracked one (replayed on startup) is ignored: the
    // boundary, the tree's data, and the local head stay untouched.
    let old = Digest(B256::repeat_byte(0xee));
    tree.set_network_finalized_tip(round(0), Height::new(9), old);
    tree.heal();
    assert_eq!(
        tree.network_finalized_tip,
        (round(1), Height::new(11), a.digest()),
    );
    assert!(tree.blocks.contains_key(&b.digest()));
    assert_eq!(tree.local_head, (Height::new(12), b.digest()));

    // A re-report of the tracked tip itself is a no-op as well.
    tree.set_network_finalized_tip(round(1), Height::new(11), a.digest());
    tree.heal();
    assert_eq!(tree.local_head, (Height::new(12), b.digest()));
}

#[test]
fn finalized_tip_advances_by_round_at_equal_height() {
    // The boundary is ordered by round alone: a tip with a newer round
    // advances it even at the tracked height. This covers a tree
    // seeded with the zero round (genesis, whose digest doubles as the
    // tip until the first finalization is reported).
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    tree.set_network_finalized_tip(round(2), Height::new(10), finalized);
    assert_eq!(
        tree.network_finalized_tip,
        (round(2), Height::new(10), finalized),
    );
}

#[test]
fn first_missing_ancestor_walks_the_latest_notarization_backwards() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    let a = block(1, 11, finalized);
    let b = block(2, 12, a.digest());
    let c = block(3, 13, b.digest());
    record(&mut tree, &a);
    // Only c's notarization is observed; b is implied by it.
    report_parent(&mut tree, &c);
    tree.heal();

    // The gap is discovered from the latest notarization down: first c
    // itself (round taken from the report) ...
    assert_eq!(tree.first_missing_ancestor(), Some((round(3), c.digest())),);

    // ... then its implied ancestor b, whose round is derived from c's
    // consensus context (c was constructed in view 3 on a parent from
    // view 2).
    tree.record_block(c.into());
    tree.heal();
    assert_eq!(tree.first_missing_ancestor(), Some((round(2), b.digest())),);

    tree.record_block(b.into());
    tree.heal();
    assert_eq!(tree.first_missing_ancestor(), None);
}

#[test]
fn validation_cached_ancestors_complete_the_ancestry_without_a_fetch() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    // The old fork F - A is forwarded in full ...
    let a = block(1, 11, finalized);
    record(&mut tree, &a);
    forwarded(&mut tree, &a);
    assert!(next_block(&tree, T0).is_none());

    // ... while the winning fork's ancestor B1 is cached by its validation
    // — a body without any report; it is never named a pending head.
    let b1 = block(2, 11, finalized);
    let b2 = block(3, 12, b1.digest());
    tree.record_block(b1.clone().into());
    tree.heal();

    // B2's notarization and body complete the new ancestry without a
    // single fetch, so the fetch machinery never gets to prove B1
    // canonical ...
    report_parent(&mut tree, &b2);
    tree.record_block(b2.clone().into());
    tree.heal();
    assert_eq!(tree.first_missing_ancestor(), None);

    // ... but the heal pass walks the ancestry and re-roots the stranded
    // meet down to the fork point, and the fork branch is forwarded
    // from its start.
    let next = next_block(&tree, T0).expect("fork branch");
    assert_eq!(next.digest(), b1.digest());
    forwarded(&mut tree, &b1);
    let next = next_block(&tree, T0).expect("fork tip");
    assert_eq!(next.digest(), b2.digest());
}

#[test]
fn finalized_tip_reroots_a_head_stranded_on_an_orphaned_branch() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    // The fork F - A1 - A2 is reported and forwarded in full ...
    let a1 = block(1, 11, finalized);
    let a2 = block(2, 12, a1.digest());
    record(&mut tree, &a1);
    record(&mut tree, &a2);
    forwarded(&mut tree, &a2);

    // ... when the network finalizes B1, A1's sibling, orphaning the
    // branch the head sits on. The heal pass re-sets the fork's pending
    // head onto the new finalized tip.
    let b1 = block(3, 11, finalized);
    let b2 = block(4, 12, b1.digest());
    tree.set_network_finalized_tip(round(3), Height::new(11), b1.digest());
    tree.heal();
    assert_eq!(tree.pending_head.digest, b1.digest());

    // The finalization pipeline delivers B1; the head - sitting on the
    // orphaned branch - is rebased onto it (mirroring
    // `forward_finalized`), which also reopens the forwarding gate.
    let local_state = tree
        .local_state()
        .update_finalized(Height::new(11), b1.digest())
        .update_head(Height::new(11), b1.digest());
    tree.set_local_state(local_state);

    // The next report builds on B2: the rebased head B1 anchors the
    // walk, so B2 is forwarded without any fetch.
    report_parent(&mut tree, &b2);
    tree.record_block(b2.clone().into());
    tree.heal();
    let next = next_block(&tree, T0).expect("fork branch");
    assert_eq!(next.digest(), b2.digest());
}

/// The deferral predicate for consensus requests: a parent converges
/// imminently when the execution layer already has it (head or finalized
/// tip), or when it is the pending head, its body in hand, one forward
/// step above a converged anchor - and does not when it is further out,
/// its body needs a fetch, or it belongs to a superseded report.
#[test]
fn convergence_is_imminent_only_one_step_from_an_anchor() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    // The delivered finalized tip is converged already.
    assert!(tree.converges_imminently(finalized));

    // A pending head whose recorded body sits directly on the head (here
    // still the finalized tip) is one forward step away ...
    let a = block(1, 11, finalized);
    record(&mut tree, &a);
    assert!(tree.converges_imminently(a.digest()));

    // ... but two steps away is not imminent: b needs a forwarded first.
    let b = block(2, 12, a.digest());
    record(&mut tree, &b);
    assert!(!tree.converges_imminently(b.digest()));
    forwarded(&mut tree, &a);
    assert!(tree.converges_imminently(b.digest()));
    // The superseded a stays imminent only because the head sits on it.
    assert!(tree.converges_imminently(a.digest()));

    // A pending head whose body is not in hand needs a fetch first: the
    // report alone does not make it imminent.
    let c = block(3, 13, b.digest());
    report_parent(&mut tree, &c);
    tree.heal();
    assert!(!tree.converges_imminently(c.digest()));

    // A sibling fork one step above the finalized tip is imminent even
    // though it is not the head's child: the replay from the tip anchor
    // hands it out directly.
    let a2 = block(4, 11, finalized);
    record(&mut tree, &a2);
    assert!(tree.converges_imminently(a2.digest()));
}

/// The tree's convergence measures: block-body count, the undelivered
/// finalized backlog, and the (signed) distance from the local head to
/// the pending head.
#[test]
fn depths_measure_backlogs() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    // Converged and empty: everything is zero.
    let depths = tree.depths();
    assert_eq!(depths.blocks, 0);
    assert_eq!(depths.finalization_lag, 0);
    assert_eq!(depths.convergence_depth, Some(0));

    // Two recorded blocks, the pending head two above the local head.
    let a = block(1, 11, finalized);
    let b = block(2, 12, a.digest());
    record(&mut tree, &a);
    record(&mut tree, &b);
    let depths = tree.depths();
    assert_eq!(depths.blocks, 2);
    assert_eq!(depths.convergence_depth, Some(2));

    // A pending head without a body has no known height.
    let c = block(3, 13, b.digest());
    report_parent(&mut tree, &c);
    assert_eq!(tree.depths().convergence_depth, None);

    // A re-anchor below the head measures negative.
    forwarded(&mut tree, &b);
    tree.set_pending_head(round(4), a.digest());
    assert_eq!(tree.depths().convergence_depth, Some(-1));

    // An undelivered network tip is the finalization lag.
    let tip = block(5, 13, b.digest());
    tree.set_network_finalized_tip(round(5), Height::new(13), tip.digest());
    assert_eq!(tree.depths().finalization_lag, 3);
}

/// The finalized tip is imminent while it is at most one delivery away.
#[test]
fn next_finalized_delivery_is_imminent() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    // One above the local finalized tip: the marshal's next dispatch is
    // the tip itself.
    let next = block(1, 11, finalized);
    tree.set_network_finalized_tip(round(1), Height::new(11), next.digest());
    tree.heal();
    assert!(tree.converges_imminently(next.digest()));

    // Two above: an undelivered block sits below the tip.
    let above = block(2, 12, next.digest());
    tree.set_network_finalized_tip(round(2), Height::new(12), above.digest());
    tree.heal();
    assert!(!tree.converges_imminently(above.digest()));

    // The gap closes as deliveries land.
    let local_state = tree
        .local_state()
        .update_finalized(Height::new(11), next.digest())
        .update_head(Height::new(11), next.digest());
    tree.set_local_state(local_state);
    assert!(tree.converges_imminently(above.digest()));
}

/// A head stranded on an abandoned notarized branch while consensus
/// re-anchors on the (already forwarded) finalized tip itself: the walk in
/// `next_to_forward` cannot reach an anchor - it only hands out blocks
/// strictly above one - so `repoint_to_finalized_tip` must take over and
/// report the tip to repoint the head onto.
#[test]
fn stranded_head_is_repointed_onto_the_finalized_tip() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    // No convergence step while the head sits on the finalized tip.
    assert!(tree.next_to_forward(T0).is_none());

    // A block is notarized and forwarded, then its view nullifies and the
    // network abandons it; consensus re-anchors on the finalized tip.
    let abandoned = block(1, 11, finalized);
    record(&mut tree, &abandoned);
    forwarded(&mut tree, &abandoned);
    tree.set_pending_head(round(0), finalized);
    tree.heal();

    // There is no block above the anchor to hand out; the step is the
    // repoint.
    let Some(NextToForward::Repoint(height, digest)) = tree.next_to_forward(T0) else {
        panic!("stranded head must be repointed");
    };
    assert_eq!((height, digest), (Height::new(10), finalized));

    // The repoint forkchoice update is accepted: the head is back on the
    // tip and there is nothing left to do.
    let local_state = tree.local_state().update_head(height, digest);
    tree.set_local_state(local_state);
    assert_eq!(tree.local_state().head, (Height::new(10), finalized));
    assert!(tree.next_to_forward(T0).is_none());
}

/// No repoint while the finalized-block delivery for the tip is still
/// outstanding: the finalization pipeline moves the head then.
#[test]
fn no_repoint_while_the_finalized_tip_delivery_is_outstanding() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    let a1 = block(1, 11, finalized);
    record(&mut tree, &a1);
    forwarded(&mut tree, &a1);

    // A sibling of the forwarded block finalizes; its delivery has not
    // arrived yet. A report re-anchoring on it must not trigger a repoint.
    let b1 = block(2, 11, finalized);
    tree.set_network_finalized_tip(round(2), Height::new(11), b1.digest());
    tree.set_pending_head(round(2), b1.digest());
    tree.heal();
    assert!(tree.next_to_forward(T0).is_none());

    // The delivery lands (mirroring `forward_finalized`), rebasing the
    // head; there is nothing left to repoint.
    let local_state = tree
        .local_state()
        .update_finalized(Height::new(11), b1.digest())
        .update_head(Height::new(11), b1.digest());
    tree.set_local_state(local_state);
    assert!(tree.next_to_forward(T0).is_none());
}

#[test]
fn reported_parents_supersede_by_report_order_not_notarization_order() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    // X and its child Y are forwarded in full ...
    let x = block(1, 11, finalized);
    let y = block(2, 12, x.digest());
    record(&mut tree, &x);
    record(&mut tree, &y);
    forwarded(&mut tree, &y);
    assert!(next_block(&tree, T0).is_none());

    // ... but Y never certifies, and a later context reports the *older*
    // X as the parent being built on. With the head still on Y - not on
    // X's ancestry - the walk anchors at the finalized tip and hands out
    // X itself, so that its forkchoice update repoints the head.
    report_parent(&mut tree, &x);
    tree.heal();
    let next = next_block(&tree, T0).expect("repoint to older parent");
    assert_eq!(next.digest(), x.digest());
    // Once the head is X, there is nothing left to do.
    forwarded(&mut tree, &x);
    assert!(next_block(&tree, T0).is_none());

    // A context building on Y again re-roots forward: Y is the pending
    // head once more and, with the head on X, is simply the next block
    // to forward.
    report_parent(&mut tree, &y);
    tree.heal();
    let next = next_block(&tree, T0).expect("flip back");
    assert_eq!(next.digest(), y.digest());
}

#[test]
fn head_reported_while_the_ancestry_was_unwalkable_is_found() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    // A is picked up for forwarding ...
    let a = block(1, 11, finalized);
    record(&mut tree, &a);
    let next = next_block(&tree, T0).expect("chain start");
    assert_eq!(next.digest(), a.digest());

    // ... and while the forward is in flight, B's report arrives without
    // its body. The completed forward makes A the head, but the pending
    // head's ancestry is not walkable yet, so nothing can be handed out.
    let b = block(2, 12, a.digest());
    report_parent(&mut tree, &b);
    tree.heal();
    forwarded(&mut tree, &a);
    assert!(next_block(&tree, T0).is_none());

    // B's body closes the gap: the head A - derived fresh as the anchor
    // - is found, and B is the next block to forward. (A cached
    // convergence position would have missed A's head report while the
    // ancestry was unwalkable and re-selected A forever.)
    tree.record_block(b.clone().into());
    tree.heal();
    let next = next_block(&tree, T0).expect("gap closed");
    assert_eq!(next.digest(), b.digest());
}

#[test]
fn rejected_blocks_are_withheld_until_the_retry_delay_elapses() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    let a = block(1, 11, finalized);
    let b = block(2, 12, a.digest());
    record(&mut tree, &a);
    record(&mut tree, &b);

    // The rejected candidate halts forwarding until the retry delay has
    // fully elapsed.
    tree.mark_rejected(&a.digest(), T0);
    assert!(next_block(&tree, T0).is_none());
    let just_before_retry = T0 + NOTARIZED_REJECTION_RETRY_DELAY - Duration::from_millis(1);
    assert!(next_block(&tree, just_before_retry).is_none());
    let next = next_block(&tree, T0 + NOTARIZED_REJECTION_RETRY_DELAY).expect("rejection expired");
    assert_eq!(next.digest(), a.digest());

    // Re-recording the body clears the timestamp.
    tree.mark_rejected(&a.digest(), T0);
    tree.record_block(a.clone().into());
    tree.heal();
    let next = next_block(&tree, T0).expect("timestamp cleared");
    assert_eq!(next.digest(), a.digest());

    // Blocks above the rejected one are unaffected once the head is
    // past it.
    tree.mark_rejected(&a.digest(), T0);
    forwarded(&mut tree, &a);
    let next = next_block(&tree, T0).expect("chain continues");
    assert_eq!(next.digest(), b.digest());
}

#[test]
fn reaffirmed_finalized_tip_needs_no_fetch() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    let a = block(1, 11, finalized);
    record(&mut tree, &a);
    // A context re-affirming the finalized tip as parent is recorded as
    // the repoint target, but the tip needs no body: no fetch is
    // triggered.
    tree.set_pending_head(round(2), finalized);

    assert_eq!(tree.first_missing_ancestor(), None);
}
