//! Rotating settlement duty for Simplex-sequenced zones.
//!
//! Every Simplex sequencer prepares and proves every batch, but only the batch's owner submits it
//! right away. If the portal has not advanced past the batch, the next sequencer in rotation
//! submits it after one failover delay, the one after it after two, and so on, so a crashed owner
//! is usually replaced without duplicate submissions. A duplicate reverts on `prevBlockHash` and
//! the loser observes the portal advance. Withdrawal-queue slots rotate the same way.

use std::{sync::Arc, time::Duration};

use alloy_primitives::Address;

/// Which sequencer settles a batch or processes a withdrawal slot, and when others take over.
///
/// With duty configured, the monitor also prepares batches only from Simplex-finalized blocks.
#[derive(Debug, Clone)]
pub struct SettlementDuty {
    /// Individual sequencer addresses, sorted so every node derives the same rotation.
    participants: Arc<[Address]>,
    /// This node's position in `participants`.
    local: usize,
    failover: Duration,
}

impl SettlementDuty {
    /// Create the duty rotation over `participants`, which must include `local`.
    pub fn new(
        participants: impl IntoIterator<Item = Address>,
        local: Address,
        failover: Duration,
    ) -> eyre::Result<Self> {
        let mut participants: Vec<_> = participants.into_iter().collect();
        participants.sort_unstable();
        participants.dedup();
        let local = participants
            .binary_search(&local)
            .map_err(|_| eyre::eyre!("local sequencer {local} is not a settlement participant"))?;
        Ok(Self {
            participants: participants.into(),
            local,
            failover,
        })
    }

    /// Whether this node owns the duty for `index` (a withdrawal batch index or queue slot).
    pub(crate) fn owns(&self, index: u64) -> bool {
        self.owner_position(index) == self.local
    }

    /// The owner of `index`.
    pub(crate) fn owner(&self, index: u64) -> Address {
        self.participants[self.owner_position(index)]
    }

    /// How long this node waits before acting in place of the owner of `index`: one failover
    /// delay per sequencer between the owner and this node in rotation order. Zero for the owner.
    pub(crate) fn takeover_delay(&self, index: u64) -> Duration {
        let n = self.participants.len();
        let rank = (self.local + n - self.owner_position(index)) % n;
        self.failover
            .saturating_mul(u32::try_from(rank).unwrap_or(u32::MAX))
    }

    fn owner_position(&self, index: u64) -> usize {
        // The remainder is below the participant count, so it fits in `usize`.
        (index % self.participants.len() as u64) as usize
    }
}
