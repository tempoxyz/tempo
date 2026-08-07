//! Progress the follower driver publishes.

use commonware_consensus::types::{Epoch, Round};
use parking_lot::RwLock;
use std::sync::Arc;
use tokio::sync::broadcast;

/// Progress the follower driver publishes for anything that follows it.
///
/// The driver is the only writer because it is the only component that applies
/// certificates. Other components receive clones that they can read.
///
/// The watermark is shared state because readers only need its latest value. A
/// scheme learned from an authenticated boundary is an event that must reach
/// components holding certificates for that epoch, so it is broadcast.
#[derive(Clone, Debug)]
pub(crate) struct FollowerProgress {
    watermark: Arc<RwLock<Round>>,
    boundary_schemes: broadcast::Sender<Epoch>,
}

/// Schemes change only at epoch boundaries. This queue only needs to hold the
/// schemes installed together during startup.
const SCHEME_BACKLOG: usize = 8;

impl FollowerProgress {
    pub(crate) fn new() -> Self {
        let (boundary_schemes, _) = broadcast::channel(SCHEME_BACKLOG);
        Self {
            watermark: Arc::new(RwLock::new(Round::zero())),
            boundary_schemes,
        }
    }

    /// Highest round the driver has applied.
    pub(crate) fn watermark(&self) -> Round {
        *self.watermark.read()
    }

    /// Records a round without allowing the watermark to move backward.
    pub(crate) fn advance(&self, round: Round) {
        let mut watermark = self.watermark.write();
        *watermark = (*watermark).max(round);
    }

    /// Reports that an authenticated boundary installed a scheme for its epoch.
    pub(crate) fn boundary_scheme_installed(&self, epoch: Epoch) {
        // The scheme is already installed; this notification only wakes gossip
        // retries. Ignore the error because gossip may be disabled with no receivers.
        let _ = self.boundary_schemes.send(epoch);
    }

    #[allow(
        dead_code,
        reason = "consumed by the gossip actor in a following commit"
    )]
    pub(crate) fn boundary_schemes(&self) -> broadcast::Receiver<Epoch> {
        self.boundary_schemes.subscribe()
    }
}
