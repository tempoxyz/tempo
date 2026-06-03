//! Expiring nonce semantic action.

use crate::blockstm::{
    action::slots::{
        expiring_nonce_ring_key, expiring_nonce_ring_ptr_key, expiring_nonce_seen_key,
    },
    rw_set::{BlockStmAccessKey, BlockStmWriteSet},
};
use alloy_primitives::{B256, U256};
use std::collections::BTreeMap;
use tempo_precompiles::nonce::{EXPIRING_NONCE_MAX_EXPIRY_SECS, EXPIRING_NONCE_SET_CAPACITY};

/// Ordered use of an expiring nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpiringNonceUse {
    pub nonce_hash: B256,
    pub valid_before: u64,
    pub sequence_number: u64,
    pub assigned_ring_slot: u32,
}

impl ExpiringNonceUse {
    /// Creates an expiring nonce action from a base ring pointer and a deterministic sequence.
    pub fn new(nonce_hash: B256, valid_before: u64, sequence_number: u64, base_ptr: u32) -> Self {
        let assigned_ring_slot = ((u64::from(base_ptr) + sequence_number)
            % u64::from(EXPIRING_NONCE_SET_CAPACITY)) as u32;
        Self {
            nonce_hash,
            valid_before,
            sequence_number,
            assigned_ring_slot,
        }
    }

    /// Returns raw storage slots covered by ordered nonce resolution.
    pub fn covered_storage_slots(&self) -> Vec<BlockStmAccessKey> {
        vec![
            expiring_nonce_ring_ptr_key(),
            expiring_nonce_ring_key(self.assigned_ring_slot),
            expiring_nonce_seen_key(self.nonce_hash),
        ]
    }
}

/// Base state read by the ordered expiring nonce resolver.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExpiringNonceBaseState {
    pub ring_ptr: u32,
    pub seen: BTreeMap<B256, u64>,
    pub ring: BTreeMap<u32, B256>,
}

/// One successfully resolved nonce use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedExpiringNonceUse {
    pub nonce_hash: B256,
    pub valid_before: u64,
    pub assigned_ring_slot: u32,
}

/// Output of ordered nonce resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiringNonceResolution {
    pub accepted: Vec<ResolvedExpiringNonceUse>,
    pub final_ring_ptr: u32,
    pub writes: BlockStmWriteSet,
}

/// Ordered expiring nonce resolver error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiringNonceResolutionError {
    InvalidExpiry {
        nonce_hash: B256,
        valid_before: u64,
    },
    Replay {
        nonce_hash: B256,
    },
    RingSlotOccupied {
        ring_slot: u32,
        old_hash: B256,
        old_expiry: u64,
    },
}

/// Resolves expiring nonce actions in serial transaction order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiringNonceResolver {
    base: ExpiringNonceBaseState,
    block_timestamp: u64,
}

impl ExpiringNonceResolver {
    /// Creates a resolver from base nonce state and the block timestamp.
    pub const fn new(base: ExpiringNonceBaseState, block_timestamp: u64) -> Self {
        Self {
            base,
            block_timestamp,
        }
    }

    /// Resolves actions in the order provided.
    pub fn resolve(
        &self,
        actions: &[ExpiringNonceUse],
    ) -> Result<ExpiringNonceResolution, ExpiringNonceResolutionError> {
        let mut seen = self.base.seen.clone();
        let mut accepted = Vec::with_capacity(actions.len());
        let mut writes = BlockStmWriteSet::default();

        for action in actions {
            if action.valid_before <= self.block_timestamp
                || action.valid_before
                    > self
                        .block_timestamp
                        .saturating_add(EXPIRING_NONCE_MAX_EXPIRY_SECS)
            {
                return Err(ExpiringNonceResolutionError::InvalidExpiry {
                    nonce_hash: action.nonce_hash,
                    valid_before: action.valid_before,
                });
            }

            if seen
                .get(&action.nonce_hash)
                .copied()
                .is_some_and(|expiry| expiry > self.block_timestamp)
            {
                return Err(ExpiringNonceResolutionError::Replay {
                    nonce_hash: action.nonce_hash,
                });
            }

            let assigned_ring_slot = (u64::from(self.base.ring_ptr) + accepted.len() as u64)
                % u64::from(EXPIRING_NONCE_SET_CAPACITY);
            let assigned_ring_slot = assigned_ring_slot as u32;
            let old_hash = self
                .base
                .ring
                .get(&assigned_ring_slot)
                .copied()
                .unwrap_or_default();

            if old_hash != B256::ZERO {
                let old_expiry = seen.get(&old_hash).copied().unwrap_or_default();
                if old_expiry > self.block_timestamp {
                    return Err(ExpiringNonceResolutionError::RingSlotOccupied {
                        ring_slot: assigned_ring_slot,
                        old_hash,
                        old_expiry,
                    });
                }
                writes.record(expiring_nonce_seen_key(old_hash), U256::ZERO);
                seen.insert(old_hash, 0);
            }

            writes.record(
                expiring_nonce_ring_key(assigned_ring_slot),
                action.nonce_hash,
            );
            writes.record(
                expiring_nonce_seen_key(action.nonce_hash),
                U256::from(action.valid_before),
            );
            seen.insert(action.nonce_hash, action.valid_before);
            accepted.push(ResolvedExpiringNonceUse {
                nonce_hash: action.nonce_hash,
                valid_before: action.valid_before,
                assigned_ring_slot,
            });
        }

        let final_ring_ptr = (u64::from(self.base.ring_ptr) + accepted.len() as u64)
            % u64::from(EXPIRING_NONCE_SET_CAPACITY);
        let final_ring_ptr = final_ring_ptr as u32;
        writes.record(expiring_nonce_ring_ptr_key(), U256::from(final_ring_ptr));

        Ok(ExpiringNonceResolution {
            accepted,
            final_ring_ptr,
            writes,
        })
    }
}

impl From<u64> for ExpiringNonceBaseState {
    fn from(ring_ptr: u64) -> Self {
        Self {
            ring_ptr: ring_ptr as u32,
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockstm::{
        BlockStmValue,
        action::{BlockStmAction, BlockStmActionKind, BlockStmActionLog},
    };

    #[test]
    fn blockstm_actions_expiring_nonce_rejects_duplicate_hash() {
        let hash = B256::repeat_byte(0x11);
        let resolver = ExpiringNonceResolver::new(ExpiringNonceBaseState::default(), 100);
        let actions = [
            ExpiringNonceUse::new(hash, 110, 0, 0),
            ExpiringNonceUse::new(hash, 110, 1, 0),
        ];

        assert_eq!(
            resolver.resolve(&actions).unwrap_err(),
            ExpiringNonceResolutionError::Replay { nonce_hash: hash }
        );
    }

    #[test]
    fn blockstm_actions_expiring_nonce_checks_ring_eviction() {
        let old_hash = B256::repeat_byte(0xaa);
        let mut base = ExpiringNonceBaseState::default();
        base.ring.insert(0, old_hash);
        base.seen.insert(old_hash, 120);
        let resolver = ExpiringNonceResolver::new(base, 100);

        assert_eq!(
            resolver
                .resolve(&[ExpiringNonceUse::new(B256::repeat_byte(0xbb), 110, 0, 0)])
                .unwrap_err(),
            ExpiringNonceResolutionError::RingSlotOccupied {
                ring_slot: 0,
                old_hash,
                old_expiry: 120,
            }
        );
    }

    #[test]
    fn blockstm_actions_expiring_nonce_synthesizes_final_ring_ptr_once() {
        let resolver = ExpiringNonceResolver::new(ExpiringNonceBaseState::from(7), 100);
        let resolution = resolver
            .resolve(&[
                ExpiringNonceUse::new(B256::repeat_byte(0x01), 110, 0, 7),
                ExpiringNonceUse::new(B256::repeat_byte(0x02), 111, 1, 7),
            ])
            .unwrap();

        assert_eq!(resolution.final_ring_ptr, 9);
        assert_eq!(
            resolution.writes.get(&expiring_nonce_ring_ptr_key()),
            Some(BlockStmValue::from(U256::from(9)))
        );
    }

    #[test]
    fn blockstm_actions_expiring_nonce_covers_shared_ring_pointer() {
        let action = ExpiringNonceUse::new(B256::repeat_byte(0x01), 110, 0, 3);
        let mut log = BlockStmActionLog::default();
        log.push(BlockStmAction::new(
            0,
            0,
            BlockStmActionKind::ExpiringNonceUse(action),
            action.covered_storage_slots(),
        ));

        assert!(log.covers_storage_key(&expiring_nonce_ring_ptr_key()));
    }
}
