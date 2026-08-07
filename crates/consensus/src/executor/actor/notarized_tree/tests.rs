use alloy_primitives::B256;
use commonware_consensus::types::{Epoch, Height, Round, View};
use reth_node_core::primitives::SealedBlock;
use tempo_primitives::{Block as TempoBlock, TempoConsensusContext, TempoHeader};

use commonware_consensus::CertifiableBlock as _;

use std::time::{Duration, SystemTime};

use super::{NOTARIZED_REJECTION_RETRY_DELAY, NotarizedTree};
use crate::consensus::{Digest, block::Block};

/// The reference "now" for tree queries; tests state rejection times
/// relative to it.
const T0: SystemTime = SystemTime::UNIX_EPOCH;

/// A tree whose observed finalized network tip is `finalized` at
/// height 10, round 0, with the canonicalization cursor starting there
/// as well — as for an execution layer whose head is at the finalized
/// tip.
fn empty_tree(finalized: Digest) -> NotarizedTree {
    NotarizedTree::new(
        (round(0), Height::new(10), finalized),
        (Height::new(10), finalized),
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
    tree.record_reported_parent(round(view), block.context().round, block.digest());
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

    tree.record_execution_notarized(Height::new(11), a.digest());
    let next = tree.next_to_forward(T0).expect("chain continues");
    assert_eq!(next.block.digest(), b.digest());

    tree.record_execution_notarized(Height::new(12), b.digest());
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
    tree.record_execution_notarized(Height::new(11), a1.digest());

    // ... but a notarization of its sibling re-roots the cursor to the
    // finalized tip, and the superseding sibling is forwarded next.
    record(&mut tree, &a2);
    let next = tree.next_to_forward(T0).expect("supersede fork");
    assert_eq!(next.block.digest(), a2.digest());
}

#[test]
fn fork_reroots_cursor_to_the_fork_point() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    // F - N0 - N1 - N2 is forwarded in full ...
    let n0 = block(1, 11, finalized);
    let n1 = block(2, 12, n0.digest());
    let n2 = block(3, 13, n1.digest());
    record(&mut tree, &n0);
    record(&mut tree, &n1);
    record(&mut tree, &n2);
    tree.record_execution_notarized(Height::new(13), n2.digest());
    assert!(tree.next_to_forward(T0).is_none());

    // ... when F - N0 - N1' - N3 becomes the canonical chain. The report
    // arrives before the bodies; the cursor stays put until the fork is
    // resolved level by level.
    let n1p = block(4, 12, n0.digest());
    let n3 = block(5, 13, n1p.digest());
    report_parent(&mut tree, 6, &n3);
    tree.heal();
    assert!(tree.next_to_forward(T0).is_none());

    // N3's body proves everything at or above its height forked out; the
    // heal pass sinks the cursor below N2.
    tree.record_block(n3.clone().into());
    tree.heal();
    assert_eq!(tree.notarized_cursor, (Height::new(12), n1.digest()));
    assert!(tree.next_to_forward(T0).is_none());

    // N1' arrives via the fetch machinery; the heal pass walks the
    // now-complete ancestry and sinks the cursor past the forked-out
    // sibling N1 to the fork point N0.
    tree.record_block(n1p.clone().into());
    tree.heal();
    assert_eq!(tree.notarized_cursor, (Height::new(11), n0.digest()));

    // The common trunk is not replayed: the fork branch is forwarded
    // directly.
    let next = tree.next_to_forward(T0).expect("fork branch");
    assert_eq!(next.block.digest(), n1p.digest());
    tree.record_execution_notarized(Height::new(12), n1p.digest());
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
    tree.record_execution_notarized(Height::new(12), n2.digest());

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

    // N4's report supersedes: the heal pass sinks the cursor below its
    // forked-out sibling N2 ...
    report_parent(&mut tree, 5, &n4);
    tree.heal();
    assert_eq!(tree.notarized_cursor, (Height::new(11), n1.digest()));

    // ... and the fetch target is unchanged — N3, re-derived from N4's
    // context — so the in-flight fetch for N3 is kept, and forwarding
    // stalls on the gap meanwhile.
    assert_eq!(tree.first_missing_ancestor(), Some((round(3), n3.digest())),);
    assert!(tree.next_to_forward(T0).is_none());

    // The landed fetch delivers N3's body; the heal pass sinks the cursor
    // past the forked-out sibling N1 to the fork point F.
    tree.record_block(n3.clone().into());
    tree.heal();
    assert_eq!(tree.notarized_cursor, (Height::new(10), finalized));

    let next = tree.next_to_forward(T0).expect("fork branch");
    assert_eq!(next.block.digest(), n3.digest());
    tree.record_execution_notarized(Height::new(11), n3.digest());
    let next = tree.next_to_forward(T0).expect("fork tip");
    assert_eq!(next.block.digest(), n4.digest());
    tree.record_execution_notarized(Height::new(12), n4.digest());
    assert!(tree.next_to_forward(T0).is_none());
}

#[test]
fn stale_heads_do_not_advance_the_cursor() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    let a = block(1, 11, finalized);
    let b1 = block(2, 12, a.digest());
    let b2 = block(3, 12, a.digest());
    record(&mut tree, &a);
    record(&mut tree, &b1);
    record(&mut tree, &b2);

    // A head off the canonical path (b1 was superseded by b2) is
    // ignored; forwarding continues from the fork point a.
    tree.record_execution_notarized(Height::new(11), a.digest());
    tree.record_execution_notarized(Height::new(12), b1.digest());
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

    tree.record_execution_notarized(Height::new(11), a.digest());
    assert!(tree.next_to_forward(T0).is_none());
}

#[test]
fn finalized_tip_bounds_recording() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    let a = block(5, 11, finalized);
    let b = block(6, 12, a.digest());
    tree.advance_finalized(round(5), Height::new(11), a.digest());
    tree.heal();

    // Parents notarized at or below the finalized round, or re-affirming
    // the finalized tip itself, do not become the pending head.
    tree.record_reported_parent(round(6), round(5), b.digest());
    tree.record_reported_parent(round(7), round(6), a.digest());
    assert!(tree.pending_head.is_none());
    tree.record_reported_parent(round(7), round(6), b.digest());
    assert!(
        tree.pending_head
            .is_some_and(|pending| pending.digest == b.digest())
    );

    // A body at or below the finalized height is rejected and takes a
    // pending head naming it along, so that it is neither fetched nor
    // forwarded.
    let stale = block(7, 11, finalized);
    tree.record_reported_parent(round(8), round(7), stale.digest());
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

    tree.advance_finalized(round(1), Height::new(11), a.digest());
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
    tree.advance_finalized(round(1), Height::new(11), a.digest());
    tree.heal();
    tree.record_execution_notarized(Height::new(12), b.digest());

    // A tip below the tracked one (replayed on startup) is ignored: the
    // boundary, the tree's data, and the cursor stay untouched.
    let old = Digest(B256::repeat_byte(0xee));
    tree.advance_finalized(round(0), Height::new(9), old);
    tree.heal();
    assert_eq!(tree.finalized_tip, (round(1), Height::new(11), a.digest()),);
    assert!(tree.blocks.contains_key(&b.digest()));
    assert_eq!(tree.notarized_cursor, (Height::new(12), b.digest()));

    // A re-report of the tracked tip itself is a no-op as well.
    tree.advance_finalized(round(1), Height::new(11), a.digest());
    tree.heal();
    assert_eq!(tree.notarized_cursor, (Height::new(12), b.digest()));
}

#[test]
fn finalized_tip_advances_by_round_at_equal_height() {
    // The boundary is ordered by round alone: a tip with a newer round
    // advances it even at the tracked height. This covers a tree
    // seeded with the zero round (genesis, whose digest doubles as the
    // tip until the first finalization is reported).
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    tree.advance_finalized(round(2), Height::new(10), finalized);
    assert_eq!(tree.finalized_tip, (round(2), Height::new(10), finalized),);
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
fn validation_cached_ancestors_reroot_the_cursor() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    // The old fork F - A is forwarded in full ...
    let a = block(1, 11, finalized);
    record(&mut tree, &a);
    tree.record_execution_notarized(Height::new(11), a.digest());
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
    // cursor to the fork point, and the fork branch is forwarded from its
    // start.
    let next = tree.next_to_forward(T0).expect("fork branch");
    assert_eq!(next.block.digest(), b1.digest());
    tree.record_execution_notarized(Height::new(11), b1.digest());
    let next = tree.next_to_forward(T0).expect("fork tip");
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
    tree.record_execution_notarized(Height::new(12), y.digest());
    assert!(tree.next_to_forward(T0).is_none());

    // ... but Y never certifies, and a later context reports the *older*
    // X as the parent being built on. The cursor sinks back onto X ...
    report_parent(&mut tree, 7, &x);
    tree.heal();
    assert_eq!(tree.notarized_cursor, (Height::new(11), x.digest()));
    // ... nothing needs forwarding (the execution layer has X) ...
    assert!(tree.next_to_forward(T0).is_none());
    // ... but the head — still Y — must be repointed at X.
    let next = tree
        .pending_head_to_repoint(y.digest(), T0)
        .expect("repoint to older parent");
    assert_eq!(next.block.digest(), x.digest());
    // Once the head is X, there is nothing left to do.
    assert!(tree.pending_head_to_repoint(x.digest(), T0).is_none());

    // A delayed report from an older context does not supersede.
    report_parent(&mut tree, 5, &y);
    tree.heal();
    assert!(tree.pending_head_to_repoint(x.digest(), T0).is_none());

    // A newer context building on Y again re-roots forward: Y is the
    // pending head once more and, with the cursor still on X, is simply
    // the next block to forward.
    report_parent(&mut tree, 8, &y);
    tree.heal();
    let next = tree.next_to_forward(T0).expect("flip back");
    assert_eq!(next.block.digest(), y.digest());
}

#[test]
fn cursor_catches_up_with_a_head_it_could_not_be_placed_on() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut tree = empty_tree(finalized);

    // A is picked up for forwarding ...
    let a = block(1, 11, finalized);
    record(&mut tree, &a);
    let next = tree.next_to_forward(T0).expect("chain start");
    assert_eq!(next.block.digest(), a.digest());

    // ... and while the forward is in flight, B's notarization arrives
    // without its body. The completed forward reports A as the head, but
    // the walk from the bodiless latest notarization dead-ends, so the
    // head cannot be placed on the canonical path and the cursor stays
    // put.
    let b = block(2, 12, a.digest());
    report_parent(&mut tree, 3, &b);
    tree.heal();
    tree.record_execution_notarized(Height::new(11), a.digest());
    assert!(tree.next_to_forward(T0).is_none());

    // B's body closes the gap; the candidate is A — already the head. The
    // actor re-reports the unchanged head after the no-op forward, which
    // now walks through to A and advances the cursor past it instead of
    // re-selecting A forever.
    tree.record_block(b.clone().into());
    tree.heal();
    let next = tree.next_to_forward(T0).expect("gap closed");
    assert_eq!(next.block.digest(), a.digest());
    tree.record_execution_notarized(Height::new(11), a.digest());
    let next = tree.next_to_forward(T0).expect("cursor caught up");
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

    // Blocks above the rejected one are unaffected once the cursor is
    // past it.
    tree.mark_rejected(&a.digest(), T0);
    tree.record_execution_notarized(Height::new(11), a.digest());
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
    tree.record_reported_parent(round(3), round(2), finalized);

    assert_eq!(tree.first_missing_ancestor(), None);
}
