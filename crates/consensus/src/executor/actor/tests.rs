use alloy_primitives::B256;
use commonware_consensus::types::{Epoch, Height, Round, View};
use reth_node_core::primitives::SealedBlock;
use tempo_primitives::{Block as TempoBlock, TempoConsensusContext, TempoHeader};

use commonware_consensus::{CertifiableBlock as _, Heightable as _};

use std::time::{Duration, SystemTime};

use super::{
    ConsensusRequest, NOTARIZED_REJECTION_RETRY_DELAY, NotarizedFactsDirectory,
    ValidateBlockRequest, queue_consensus_request,
};
use crate::consensus::{Digest, block::Block};

/// The reference "now" for directory queries; tests state rejection times
/// relative to it.
const T0: SystemTime = SystemTime::UNIX_EPOCH;

/// A directory whose observed finalized network tip is `finalized` at
/// height 10, round 0, with the canonicalization cursor starting there
/// as well — as for an execution layer whose head is at the finalized
/// tip.
fn empty_directory(finalized: Digest) -> NotarizedFactsDirectory {
    NotarizedFactsDirectory::new(
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

/// Records the block's notarization fact — at the round its consensus
/// context names — and its body.
fn record(directory: &mut NotarizedFactsDirectory, block: &Block) {
    directory.record_notarized(block.context().round, block.digest());
    directory.record_block(block.clone().into());
}

#[test]
fn forwards_chain_on_top_of_finalized_tip_in_order() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut directory = empty_directory(finalized);

    let a = block(1, 11, finalized);
    let b = block(2, 12, a.digest());
    record(&mut directory, &a);
    record(&mut directory, &b);

    let next = directory.next_to_forward(T0).expect("chain start");
    assert_eq!(next.block.digest(), a.digest());

    directory.record_execution_notarized(Height::new(11), a.digest());
    let next = directory.next_to_forward(T0).expect("chain continues");
    assert_eq!(next.block.digest(), b.digest());

    directory.record_execution_notarized(Height::new(12), b.digest());
    assert!(directory.next_to_forward(T0).is_none());
}

#[test]
fn sibling_notarized_in_later_round_supersedes() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut directory = empty_directory(finalized);

    let a1 = block(1, 11, finalized);
    let a2 = block(2, 11, finalized);
    record(&mut directory, &a1);
    // The stale sibling was forwarded and become the head ...
    directory.record_execution_notarized(Height::new(11), a1.digest());

    // ... but a notarization of its sibling re-roots the cursor to the
    // finalized tip, and the superseding sibling is forwarded next.
    record(&mut directory, &a2);
    let next = directory.next_to_forward(T0).expect("supersede fork");
    assert_eq!(next.block.digest(), a2.digest());
}

#[test]
fn fork_reroots_cursor_to_the_fork_point() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut directory = empty_directory(finalized);

    // F - N0 - N1 - N2 is forwarded in full ...
    let n0 = block(1, 11, finalized);
    let n1 = block(2, 12, n0.digest());
    let n2 = block(3, 13, n1.digest());
    record(&mut directory, &n0);
    record(&mut directory, &n1);
    record(&mut directory, &n2);
    directory.record_execution_notarized(Height::new(13), n2.digest());
    assert!(directory.next_to_forward(T0).is_none());

    // ... when F - N0 - N1' - N3 becomes the canonical chain. The fact
    // arrives before the bodies; the cursor stays put until the fork is
    // resolved level by level.
    let n1p = block(4, 12, n0.digest());
    let n3 = block(5, 13, n1p.digest());
    directory.record_notarized(round(5), n3.digest());
    assert!(directory.next_to_forward(T0).is_none());

    // N3's body proves everything at or above its height forked out;
    // the cursor sinks below N2.
    directory.record_block(n3.clone().into());
    assert!(!directory.blocks.contains_key(&n2.digest()));
    assert!(directory.next_to_forward(T0).is_none());

    // N1' arrives via the fetch machinery, proving its sibling N1
    // forked out; the cursor sinks to the fork point N0.
    directory.record_fetched_block(n1p.clone().into());
    assert!(!directory.blocks.contains_key(&n1.digest()));
    // The fetch also derived N1's sibling's notarization fact from its
    // consensus context.
    assert_eq!(directory.notarized.get(&round(4)), Some(&n1p.digest()));

    // The common trunk is not replayed: the fork branch is forwarded
    // directly.
    let next = directory.next_to_forward(T0).expect("fork branch");
    assert_eq!(next.block.digest(), n1p.digest());
    directory.record_execution_notarized(Height::new(12), n1p.digest());
    let next = directory.next_to_forward(T0).expect("fork tip");
    assert_eq!(next.block.digest(), n3.digest());
}

#[test]
fn fork_during_ancestor_fetch_keeps_the_fetch_target() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut directory = empty_directory(finalized);

    // F - N1 - N2 is forwarded in full ...
    let n1 = block(1, 11, finalized);
    let n2 = block(2, 12, n1.digest());
    record(&mut directory, &n1);
    record(&mut directory, &n2);
    directory.record_execution_notarized(Height::new(12), n2.digest());

    // ... when the chain forks to F - N3 - N4. N3's fact arrives first
    // (from the context preceding N4's validation) and becomes the
    // fetch target; N4's body arrives through its validation.
    let n3 = block(3, 11, finalized);
    let n4 = block(4, 12, n3.digest());
    directory.record_notarized(round(3), n3.digest());
    assert_eq!(
        directory.first_missing_ancestor(),
        Some((round(3), n3.digest())),
    );
    directory.record_block(n4.clone().into());

    // N4's fact deletes its forked-out sibling N2 and sweeps N3's
    // bodiless fact ...
    directory.record_notarized(round(4), n4.digest());
    assert!(!directory.blocks.contains_key(&n2.digest()));
    assert!(!directory.notarized.contains_key(&round(3)));

    // ... but the fetch target is unchanged — same digest, round
    // re-derived from N4's context — so the in-flight fetch for N3
    // is kept, and forwarding stalls on the gap meanwhile.
    assert_eq!(
        directory.first_missing_ancestor(),
        Some((round(3), n3.digest())),
    );
    assert!(directory.next_to_forward(T0).is_none());

    // The landed fetch restores N3's fact, deletes the forked-out
    // sibling N1, and sinks the cursor to the fork point F.
    directory.record_fetched_block(n3.clone().into());
    assert_eq!(directory.notarized.get(&round(3)), Some(&n3.digest()));
    assert!(!directory.blocks.contains_key(&n1.digest()));

    let next = directory.next_to_forward(T0).expect("fork branch");
    assert_eq!(next.block.digest(), n3.digest());
    directory.record_execution_notarized(Height::new(11), n3.digest());
    let next = directory.next_to_forward(T0).expect("fork tip");
    assert_eq!(next.block.digest(), n4.digest());
    directory.record_execution_notarized(Height::new(12), n4.digest());
    assert!(directory.next_to_forward(T0).is_none());
}

#[test]
fn stale_heads_do_not_advance_the_cursor() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut directory = empty_directory(finalized);

    let a = block(1, 11, finalized);
    let b1 = block(2, 12, a.digest());
    let b2 = block(3, 12, a.digest());
    record(&mut directory, &a);
    record(&mut directory, &b1);
    record(&mut directory, &b2);

    // A head off the canonical path (b1 was superseded by b2) is
    // ignored; forwarding continues from the fork point a.
    directory.record_execution_notarized(Height::new(11), a.digest());
    directory.record_execution_notarized(Height::new(12), b1.digest());
    let next = directory.next_to_forward(T0).expect("chain continues");
    assert_eq!(next.block.digest(), b2.digest());
}

#[test]
fn missing_body_caps_the_chain() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut directory = empty_directory(finalized);

    let a = block(1, 11, finalized);
    let b = block(2, 12, a.digest());
    let c = block(3, 13, b.digest());
    record(&mut directory, &a);
    // b's notarization is known but its body is not.
    directory.record_notarized(round(2), b.digest());
    record(&mut directory, &c);

    directory.record_execution_notarized(Height::new(11), a.digest());
    assert!(directory.next_to_forward(T0).is_none());
}

#[test]
fn finalized_tip_bounds_recording() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut directory = empty_directory(finalized);

    let a = block(5, 11, finalized);
    let b = block(6, 12, a.digest());
    directory.advance_finalized(round(5), Height::new(11), a.digest());

    // Notarizations at or below the finalized round, or re-affirming the
    // finalized tip itself, are not recorded.
    directory.record_notarized(round(5), b.digest());
    directory.record_notarized(round(6), a.digest());
    assert!(directory.notarized.is_empty());
    directory.record_notarized(round(6), b.digest());
    assert!(directory.notarized.contains_key(&round(6)));

    // A body at or below the finalized height is rejected and takes its
    // notarization fact with it.
    let stale = block(7, 11, finalized);
    directory.record_notarized(round(7), stale.digest());
    directory.record_block(stale.clone().into());
    assert!(!directory.blocks.contains_key(&stale.digest()));
    assert!(!directory.notarized.contains_key(&round(7)));

    directory.record_block(b.clone().into());
    assert!(directory.blocks.contains_key(&b.digest()));
}

#[test]
fn advance_finalized_drops_stale_entries() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut directory = empty_directory(finalized);

    let a = block(1, 11, finalized);
    let b = block(2, 12, a.digest());
    record(&mut directory, &a);
    record(&mut directory, &b);

    directory.advance_finalized(round(1), Height::new(11), a.digest());

    assert!(!directory.blocks.contains_key(&a.digest()));
    assert!(!directory.notarized.contains_key(&round(1)));
    assert!(directory.blocks.contains_key(&b.digest()));
    assert!(directory.notarized.contains_key(&round(2)));
}

#[test]
fn finalized_tip_never_regresses() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut directory = empty_directory(finalized);

    let a = block(1, 11, finalized);
    let b = block(2, 12, a.digest());
    record(&mut directory, &a);
    record(&mut directory, &b);
    directory.advance_finalized(round(1), Height::new(11), a.digest());
    directory.record_execution_notarized(Height::new(12), b.digest());

    // A tip below the tracked one (replayed on startup) is ignored: the
    // boundary, the directory's data, and the cursor stay untouched.
    let old = Digest(B256::repeat_byte(0xee));
    directory.advance_finalized(round(0), Height::new(9), old);
    assert_eq!(
        directory.finalized_tip,
        (round(1), Height::new(11), a.digest()),
    );
    assert!(directory.blocks.contains_key(&b.digest()));
    assert_eq!(directory.notarized_cursor, (Height::new(12), b.digest()));

    // A re-report of the tracked tip itself is a no-op as well.
    directory.advance_finalized(round(1), Height::new(11), a.digest());
    assert_eq!(directory.notarized_cursor, (Height::new(12), b.digest()));
}

#[test]
fn finalized_tip_advances_by_round_at_equal_height() {
    // The boundary is ordered by round alone: a tip with a newer round
    // advances it even at the tracked height. This covers a directory
    // seeded with the zero round (genesis, whose digest doubles as the
    // tip until the first finalization is reported).
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut directory = empty_directory(finalized);

    directory.advance_finalized(round(2), Height::new(10), finalized);
    assert_eq!(
        directory.finalized_tip,
        (round(2), Height::new(10), finalized),
    );
}

#[test]
fn first_missing_ancestor_walks_the_latest_notarization_backwards() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut directory = empty_directory(finalized);

    let a = block(1, 11, finalized);
    let b = block(2, 12, a.digest());
    let c = block(3, 13, b.digest());
    record(&mut directory, &a);
    // Only c's notarization is observed; b is implied by it.
    directory.record_notarized(round(3), c.digest());

    // The gap is discovered from the latest notarization down: first c
    // itself (round taken from the fact) ...
    assert_eq!(
        directory.first_missing_ancestor(),
        Some((round(3), c.digest())),
    );

    // ... then its implied ancestor b, whose round is derived from c's
    // consensus context (c was constructed in view 3 on a parent from
    // view 2).
    directory.record_block(c.into());
    assert_eq!(
        directory.first_missing_ancestor(),
        Some((round(2), b.digest())),
    );

    directory.record_block(b.into());
    assert_eq!(directory.first_missing_ancestor(), None);
}

#[test]
fn rejected_blocks_are_withheld_until_the_retry_delay_elapses() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut directory = empty_directory(finalized);

    let a = block(1, 11, finalized);
    let b = block(2, 12, a.digest());
    record(&mut directory, &a);
    record(&mut directory, &b);

    // The rejected candidate halts forwarding until the retry delay has
    // fully elapsed.
    directory.mark_rejected(&a.digest(), T0);
    assert!(directory.next_to_forward(T0).is_none());
    let just_before_retry = T0 + NOTARIZED_REJECTION_RETRY_DELAY - Duration::from_millis(1);
    assert!(directory.next_to_forward(just_before_retry).is_none());
    let next = directory
        .next_to_forward(T0 + NOTARIZED_REJECTION_RETRY_DELAY)
        .expect("rejection expired");
    assert_eq!(next.block.digest(), a.digest());

    // Re-recording the body clears the timestamp.
    directory.mark_rejected(&a.digest(), T0);
    directory.record_block(a.clone().into());
    let next = directory.next_to_forward(T0).expect("timestamp cleared");
    assert_eq!(next.block.digest(), a.digest());

    // Blocks above the rejected one are unaffected once the cursor is
    // past it.
    directory.mark_rejected(&a.digest(), T0);
    directory.record_execution_notarized(Height::new(11), a.digest());
    let next = directory.next_to_forward(T0).expect("chain continues");
    assert_eq!(next.block.digest(), b.digest());
}

#[test]
fn reaffirmed_finalized_tip_needs_no_fetch() {
    let finalized = Digest(B256::repeat_byte(0xff));
    let mut directory = empty_directory(finalized);

    let a = block(1, 11, finalized);
    record(&mut directory, &a);
    // A context re-affirming the finalized tip as parent is not
    // recorded (its digest is the directory's tip), so it neither
    // becomes the latest notarization nor triggers a fetch.
    directory.record_notarized(round(2), finalized);

    assert_eq!(directory.first_missing_ancestor(), None);
}

#[test]
fn consensus_requests_from_stale_rounds_are_dropped() {
    // The queue logic is agnostic to the request kind; validation requests
    // stand in for both.
    fn validate_request(view: u64, height: u64) -> ConsensusRequest {
        let (response, _rx) = futures::channel::oneshot::channel();
        ConsensusRequest::Validate(ValidateBlockRequest {
            cause: tracing::Span::none(),
            block: block(view, height, Digest(B256::ZERO)).into(),
            validator_set: None,
            response,
        })
    }

    fn queued_height(slot: &Option<(Round, ConsensusRequest)>) -> Option<u64> {
        slot.as_ref().map(|(_, request)| match request {
            ConsensusRequest::Validate(validate) => validate.block.height().get(),
            ConsensusRequest::Build { .. } => unreachable!("test only queues validations"),
        })
    }

    let mut slot = None;
    queue_consensus_request(&mut slot, round(2), validate_request(2, 2));
    assert_eq!(queued_height(&slot), Some(2));

    // Older and same rounds are dropped.
    queue_consensus_request(&mut slot, round(1), validate_request(1, 1));
    assert_eq!(queued_height(&slot), Some(2));
    queue_consensus_request(&mut slot, round(2), validate_request(2, 20));
    assert_eq!(queued_height(&slot), Some(2));

    // Newer rounds supersede.
    queue_consensus_request(&mut slot, round(3), validate_request(3, 3));
    assert_eq!(queued_height(&slot), Some(3));
}
