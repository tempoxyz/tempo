//! In-memory accumulators of blocks that are not yet persisted.

use crate::accumulator::LthashAccumulator;
use alloy_primitives::B256;
use std::collections::HashMap;

/// Lthash accumulators of recent blocks, keyed by the state root they hash to.
///
/// The lthash task records its result here on both the build and the validation path, and
/// parent lookups use the parent header's state root, so entries are self-certifying: a root
/// match is the right accumulator no matter which fork or code path produced it. The
/// persistence hook flushes entries to the database when block batches are saved and prunes
/// them afterwards by block number.
#[derive(Debug, Default)]
pub(crate) struct LthashAccumulatorOverlay {
    inner: std::sync::Mutex<OverlayInner>,
}

#[derive(Debug, Default)]
struct OverlayInner {
    entries: HashMap<B256, OverlayEntry>,
    /// Highest block number of the previously persisted batch. Pruning runs one batch late so
    /// overlay readers never race the database commit that follows the persistence hook.
    prune_below: Option<u64>,
}

#[derive(Debug)]
struct OverlayEntry {
    number: u64,
    accumulator: LthashAccumulator,
}

impl LthashAccumulatorOverlay {
    /// Returns the accumulator hashing to the given state root, if still in the overlay.
    pub(crate) fn lookup(&self, state_root: B256) -> Option<LthashAccumulator> {
        self.inner
            .lock()
            .expect("lthash overlay poisoned")
            .entries
            .get(&state_root)
            .map(|entry| entry.accumulator.clone())
    }

    /// Returns the accumulator bytes hashing to the given state root, for persistence.
    pub(crate) fn accumulator_bytes(&self, state_root: B256) -> Option<Vec<u8>> {
        self.lookup(state_root)
            .map(|accumulator| accumulator.to_bytes())
    }

    /// Records an accumulator under the state root it hashes to.
    pub(crate) fn insert(&self, state_root: B256, number: u64, accumulator: LthashAccumulator) {
        self.inner
            .lock()
            .expect("lthash overlay poisoned")
            .entries
            .insert(
                state_root,
                OverlayEntry {
                    number,
                    accumulator,
                },
            );
    }

    /// Notes that blocks up to `highest_number` were handed to the database and prunes entries
    /// from batches persisted before this one.
    pub(crate) fn on_batch_persisted(&self, highest_number: u64) {
        let mut inner = self.inner.lock().expect("lthash overlay poisoned");
        if let Some(threshold) = inner.prune_below.replace(highest_number) {
            inner.entries.retain(|_, entry| entry.number > threshold);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{accumulator::lthash_account_element, test_util::account};

    #[test]
    fn overlay_prunes_one_batch_late() {
        let overlay = LthashAccumulatorOverlay::default();
        let root_of = |n: u64| B256::repeat_byte(n as u8);

        for number in 1..=4 {
            overlay.insert(root_of(number), number, LthashAccumulator::zero());
        }

        // First persisted batch: nothing may be evicted yet, readers of the pending
        // commit still need these entries.
        overlay.on_batch_persisted(2);
        for number in 1..=4 {
            assert!(overlay.lookup(root_of(number)).is_some());
        }

        // Next batch prunes everything at or below the previous one.
        overlay.on_batch_persisted(4);
        assert!(overlay.lookup(root_of(1)).is_none());
        assert!(overlay.lookup(root_of(2)).is_none());
        assert!(overlay.lookup(root_of(3)).is_some());
        assert!(overlay.lookup(root_of(4)).is_some());
    }

    #[test]
    fn overlay_keeps_sibling_blocks() {
        let overlay = LthashAccumulatorOverlay::default();
        let mut sibling = LthashAccumulator::zero();
        sibling.add(lthash_account_element(B256::repeat_byte(0x66), account(1, 1)).unwrap());

        overlay.insert(B256::repeat_byte(0xaa), 7, LthashAccumulator::zero());
        overlay.insert(B256::repeat_byte(0xbb), 7, sibling.clone());

        assert_eq!(
            overlay.lookup(B256::repeat_byte(0xaa)),
            Some(LthashAccumulator::zero())
        );
        assert_eq!(overlay.lookup(B256::repeat_byte(0xbb)), Some(sibling));
    }

    /// A proposer building on its own block never runs the validation job for it, so the
    /// build path must also record its accumulator. This pins the mapping root -> parent
    /// accumulator that both paths rely on.
    #[test]
    fn overlay_entry_is_found_by_the_root_it_hashes_to() {
        let overlay = LthashAccumulatorOverlay::default();

        let mut accumulator = LthashAccumulator::zero();
        accumulator.add(lthash_account_element(B256::repeat_byte(0x77), account(3, 30)).unwrap());
        let root = accumulator.checksum();

        // As the task records it after finishing block N...
        overlay.insert(root, 5, accumulator.clone());

        // ...block N+1 seeds by its parent header's state root.
        assert_eq!(overlay.lookup(root), Some(accumulator));
    }
}
