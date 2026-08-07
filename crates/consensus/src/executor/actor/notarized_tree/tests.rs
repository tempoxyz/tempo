use alloy_primitives::B256;
use commonware_consensus::types::{Epoch, Height, Round, View};
use reth_node_core::primitives::SealedBlock;
use tempo_primitives::{Block as TempoBlock, TempoConsensusContext, TempoHeader};

use commonware_consensus::{CertifiableBlock as _, Heightable as _};

use std::time::{Duration, SystemTime};

use super::{LocalState, NOTARIZED_REJECTION_RETRY_DELAY, NotarizedTree};
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

/// Reports `block` as the notarized parent of a consensus context in
/// `view` — as simplex does when the proposal of `view` builds on it.
fn report_parent(tree: &mut NotarizedTree, view: u64, block: &Block) {
    tree.set_pending_head(round(view), block.context().round, block.digest());
}

/// Reports the block as the parent of a context in the view after its own
/// — as simplex does when the next proposal builds on it — and records its
/// body, then heals, mirroring the actor's event loop running between
/// messages.
fn record(tree: &mut NotarizedTree, block: &Block) {
    let view = block.context().round.view().get() + 1;
    report_parent(tree, view, block);
    tree.record_block(block.clone().into());
    tree.heal();
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

    let next = tree.next_to_forward(T0).expect("chain start");
    assert_eq!(next.block.digest(), a.digest());

    forwarded(&mut tree, &a);
    let next = tree.next_to_forward(T0).expect("chain continues");
    assert_eq!(next.block.digest(), b.digest());

    forwarded(&mut tree, &b);
    assert!(tree.next_to_forward(T0).is_none());
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
    let next = tree.next_to_forward(T0).expect("supersede fork");
    assert_eq!(next.block.digest(), a2.digest());
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
    assert!(tree.next_to_forward(T0).is_none());

    // ... when F - N0 - N1' - N3 becomes the canonical chain. The report
    // arrives before the bodies; forwarding stalls until the ancestry
    // is walkable.
    let n1p = block(4, 12, n0.digest());
    let n3 = block(5, 13, n1p.digest());
    report_parent(&mut tree, 6, &n3);
    tree.heal();
    assert!(tree.next_to_forward(T0).is_none());

    // N3's body arrives, but its parent N1' is still missing: the
    // ancestry does not reach down to a block the execution layer has.
    tree.record_block(n3.clone().into());
    tree.heal();
    assert!(tree.next_to_forward(T0).is_none());

    // N1' arrives via the fetch machinery, completing the ancestry. The
    // head (N2) sits off the new canonical path and is no anchor, so the
    // walk runs to the finalized tip and the path is replayed from there:
    // the trunk block N0 - already known to the execution layer, which
    // answers it from its caches - comes first, then the fork branch.
    tree.record_block(n1p.clone().into());
    tree.heal();

    let next = tree.next_to_forward(T0).expect("trunk replay");
    assert_eq!(next.block.digest(), n0.digest());
    forwarded(&mut tree, &n0);
    let next = tree.next_to_forward(T0).expect("fork branch");
    assert_eq!(next.block.digest(), n1p.digest());
    forwarded(&mut tree, &n1p);
    let next = tree.next_to_forward(T0).expect("fork tip");
    assert_eq!(next.block.digest(), n3.digest());
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
    report_parent(&mut tree, 4, &n3);
    tree.heal();
    assert_eq!(tree.first_missing_ancestor(), Some((round(3), n3.digest())),);
    tree.record_block(n4.clone().into());
    tree.heal();

    // N4's report supersedes ...
    report_parent(&mut tree, 5, &n4);
    tree.heal();

    // ... and the fetch target is unchanged — N3, re-derived from N4's
    // context — so the in-flight fetch for N3 is kept, and forwarding
    // stalls on the gap meanwhile.
    assert_eq!(tree.first_missing_ancestor(), Some((round(3), n3.digest())),);
    assert!(tree.next_to_forward(T0).is_none());

    // The landed fetch delivers N3's body, completing the ancestry down
    // to the finalized tip - the anchor while the head sits on the
    // orphaned branch.
    tree.record_block(n3.clone().into());
    tree.heal();

    let next = tree.next_to_forward(T0).expect("fork branch");
    assert_eq!(next.block.digest(), n3.digest());
    forwarded(&mut tree, &n3);
    let next = tree.next_to_forward(T0).expect("fork tip");
    assert_eq!(next.block.digest(), n4.digest());
    forwarded(&mut tree, &n4);
    assert!(tree.next_to_forward(T0).is_none());
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
    let next = tree.next_to_forward(T0).expect("replayed parent");
    assert_eq!(next.block.digest(), a.digest());
    forwarded(&mut tree, &a);
    let next = tree.next_to_forward(T0).expect("chain continues");
    assert_eq!(next.block.digest(), b2.digest());
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
    report_parent(&mut tree, 3, &b);
    record(&mut tree, &c);

    forwarded(&mut tree, &a);
    assert!(tree.next_to_forward(T0).is_none());
}

#[test]
fn finalized_tip_bounds_recording() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    let a = block(5, 11, finalized);
    let b = block(6, 12, a.digest());
    tree.set_network_finalized_tip(round(5), Height::new(11), a.digest());
    tree.heal();

    // Parents notarized at or below the finalized round, or re-affirming
    // the finalized tip itself, do not become the pending head.
    tree.set_pending_head(round(6), round(5), b.digest());
    tree.set_pending_head(round(7), round(6), a.digest());
    assert!(tree.pending_head.is_none());
    tree.set_pending_head(round(7), round(6), b.digest());
    assert!(
        tree.pending_head
            .is_some_and(|pending| pending.digest == b.digest())
    );

    // A body at or below the finalized height is rejected and takes a
    // pending head naming it along, so that it is neither fetched nor
    // forwarded.
    let stale = block(7, 11, finalized);
    tree.set_pending_head(round(8), round(7), stale.digest());
    tree.record_block(stale.clone().into());
    assert!(!tree.blocks.contains_key(&stale.digest()));
    assert!(tree.pending_head.is_none());

    tree.record_block(b.clone().into());
    assert!(tree.blocks.contains_key(&b.digest()));
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
    assert!(
        tree.pending_head
            .is_some_and(|pending| pending.digest == b.digest())
    );
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
    report_parent(&mut tree, 4, &c);
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
    assert!(tree.next_to_forward(T0).is_none());

    // ... while the winning fork's ancestor B1 is cached by its validation
    // — a body without any report; it is never named a pending head.
    let b1 = block(2, 11, finalized);
    let b2 = block(3, 12, b1.digest());
    tree.record_block(b1.clone().into());
    tree.heal();

    // B2's notarization and body complete the new ancestry without a
    // single fetch, so the fetch machinery never gets to prove B1
    // canonical ...
    report_parent(&mut tree, 4, &b2);
    tree.record_block(b2.clone().into());
    tree.heal();
    assert_eq!(tree.first_missing_ancestor(), None);

    // ... but the heal pass walks the ancestry and re-roots the stranded
    // meet down to the fork point, and the fork branch is forwarded
    // from its start.
    let next = tree.next_to_forward(T0).expect("fork branch");
    assert_eq!(next.block.digest(), b1.digest());
    forwarded(&mut tree, &b1);
    let next = tree.next_to_forward(T0).expect("fork tip");
    assert_eq!(next.block.digest(), b2.digest());
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
    // branch the head sits on. The heal pass drops the fork's pending
    // head.
    let b1 = block(3, 11, finalized);
    let b2 = block(4, 12, b1.digest());
    tree.set_network_finalized_tip(round(3), Height::new(11), b1.digest());
    tree.heal();
    assert!(tree.pending_head.is_none());

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
    report_parent(&mut tree, 5, &b2);
    tree.record_block(b2.clone().into());
    tree.heal();
    let next = tree.next_to_forward(T0).expect("fork branch");
    assert_eq!(next.block.digest(), b2.digest());
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
    assert!(tree.next_to_forward(T0).is_none());

    // ... but Y never certifies, and a later context reports the *older*
    // X as the parent being built on. With the head still on Y - not on
    // X's ancestry - the walk anchors at the finalized tip and hands out
    // X itself, so that its forkchoice update repoints the head.
    report_parent(&mut tree, 7, &x);
    tree.heal();
    let next = tree.next_to_forward(T0).expect("repoint to older parent");
    assert_eq!(next.block.digest(), x.digest());
    // Once the head is X, there is nothing left to do.
    forwarded(&mut tree, &x);
    assert!(tree.next_to_forward(T0).is_none());

    // A delayed report from an older context does not supersede.
    report_parent(&mut tree, 5, &y);
    tree.heal();
    assert!(tree.next_to_forward(T0).is_none());

    // A newer context building on Y again re-roots forward: Y is the
    // pending head once more and, with the head on X, is simply the next
    // block to forward.
    report_parent(&mut tree, 8, &y);
    tree.heal();
    let next = tree.next_to_forward(T0).expect("flip back");
    assert_eq!(next.block.digest(), y.digest());
}

#[test]
fn head_reported_while_the_ancestry_was_unwalkable_is_found() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    // A is picked up for forwarding ...
    let a = block(1, 11, finalized);
    record(&mut tree, &a);
    let next = tree.next_to_forward(T0).expect("chain start");
    assert_eq!(next.block.digest(), a.digest());

    // ... and while the forward is in flight, B's report arrives without
    // its body. The completed forward makes A the head, but the pending
    // head's ancestry is not walkable yet, so nothing can be handed out.
    let b = block(2, 12, a.digest());
    report_parent(&mut tree, 3, &b);
    tree.heal();
    forwarded(&mut tree, &a);
    assert!(tree.next_to_forward(T0).is_none());

    // B's body closes the gap: the head A - derived fresh as the anchor
    // - is found, and B is the next block to forward. (A cached
    // convergence position would have missed A's head report while the
    // ancestry was unwalkable and re-selected A forever.)
    tree.record_block(b.clone().into());
    tree.heal();
    let next = tree.next_to_forward(T0).expect("gap closed");
    assert_eq!(next.block.digest(), b.digest());
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
    assert!(tree.next_to_forward(T0).is_none());
    let just_before_retry = T0 + NOTARIZED_REJECTION_RETRY_DELAY - Duration::from_millis(1);
    assert!(tree.next_to_forward(just_before_retry).is_none());
    let next = tree
        .next_to_forward(T0 + NOTARIZED_REJECTION_RETRY_DELAY)
        .expect("rejection expired");
    assert_eq!(next.block.digest(), a.digest());

    // Re-recording the body clears the timestamp.
    tree.mark_rejected(&a.digest(), T0);
    tree.record_block(a.clone().into());
    tree.heal();
    let next = tree.next_to_forward(T0).expect("timestamp cleared");
    assert_eq!(next.block.digest(), a.digest());

    // Blocks above the rejected one are unaffected once the head is
    // past it.
    tree.mark_rejected(&a.digest(), T0);
    forwarded(&mut tree, &a);
    let next = tree.next_to_forward(T0).expect("chain continues");
    assert_eq!(next.block.digest(), b.digest());
}

#[test]
fn reaffirmed_finalized_tip_needs_no_fetch() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    let a = block(1, 11, finalized);
    record(&mut tree, &a);
    // A context re-affirming the finalized tip as parent is not
    // recorded (its digest is the tree's tip), so it neither
    // becomes the latest notarization nor triggers a fetch.
    tree.set_pending_head(round(3), round(2), finalized);

    assert_eq!(tree.first_missing_ancestor(), None);
}
