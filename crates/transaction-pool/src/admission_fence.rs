//! Admission fence against canonical updates that land while transactions validate.
//!
//! Validation reads one state snapshot, and maintenance scans the pool once per canonical
//! update. A transaction validated before an update but inserted after its scan would stay
//! pooled though the update invalidated it. Maintenance publishes each update here before it
//! scans, and admission compares the generation it read before validating with the one after
//! inserting: the pool lock orders the insert against the scan, so either the scan sees the
//! transaction or admission sees the update. Admission never waits on maintenance.

use crate::{maintain::PoolInvalidations, metrics::AdmissionFenceMetrics};
use parking_lot::Mutex;
use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

/// Published updates kept for admissions still validating. An admission that missed more
/// revalidates everything it inserted.
pub(crate) const RECENT_UPDATES: usize = 64;

/// Recent canonical updates' invalidations, numbered by generation.
#[derive(Default)]
pub(crate) struct AdmissionFence {
    /// Number of updates published so far.
    generation: AtomicU64,
    /// The last [`RECENT_UPDATES`] updates with their generation, oldest first.
    recent: Mutex<VecDeque<(u64, Arc<PoolInvalidations>)>>,
    /// Admission fence metrics.
    pub(crate) metrics: AdmissionFenceMetrics,
}

impl AdmissionFence {
    /// The number of updates published so far. Admission reads it before it validates.
    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Publishes a canonical update's invalidations. Maintenance calls it before it scans
    /// the pool.
    pub(crate) fn publish(&self, invalidations: Arc<PoolInvalidations>) {
        let mut recent = self.recent.lock();
        // Only maintenance publishes, under the lock.
        let generation = self.generation.load(Ordering::SeqCst) + 1;
        if recent.len() == RECENT_UPDATES {
            recent.pop_front();
        }
        recent.push_back((generation, invalidations));
        self.generation.store(generation, Ordering::SeqCst);
    }

    /// The updates published after generation `since`, oldest first, or `None` when some of
    /// them are no longer kept.
    pub(crate) fn published_since(&self, since: u64) -> Option<Vec<Arc<PoolInvalidations>>> {
        let recent = self.recent.lock();
        let missed = self.generation.load(Ordering::SeqCst).checked_sub(since)?;
        if usize::try_from(missed).ok()? > recent.len() {
            return None;
        }
        Some(
            recent
                .iter()
                .filter(|(generation, _)| *generation > since)
                .map(|(_, invalidations)| Arc::clone(invalidations))
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_since_returns_updates_after_generation() {
        let fence = AdmissionFence::default();
        assert_eq!(fence.generation(), 0);
        assert_eq!(fence.published_since(0).unwrap().len(), 0);

        let first = Arc::new(PoolInvalidations::default());
        let second = Arc::new(PoolInvalidations::default());
        fence.publish(Arc::clone(&first));
        fence.publish(Arc::clone(&second));
        assert_eq!(fence.generation(), 2);

        let published = fence.published_since(0).unwrap();
        assert_eq!(published.len(), 2);
        assert!(Arc::ptr_eq(&published[0], &first));
        assert!(Arc::ptr_eq(&published[1], &second));

        let published = fence.published_since(1).unwrap();
        assert_eq!(published.len(), 1);
        assert!(Arc::ptr_eq(&published[0], &second));

        assert!(fence.published_since(2).unwrap().is_empty());
    }

    #[test]
    fn published_since_is_none_once_updates_are_dropped() {
        let fence = AdmissionFence::default();
        for _ in 0..=RECENT_UPDATES {
            fence.publish(Arc::new(PoolInvalidations::default()));
        }
        assert!(fence.published_since(0).is_none());
        assert_eq!(fence.published_since(1).unwrap().len(), RECENT_UPDATES);
    }
}
