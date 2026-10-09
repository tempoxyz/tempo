//! Typed read-only access to protocol state.
//!
//! Callers enter a read-only [`tempo_precompiles::storage::StorageCtx`] through
//! `TempoStateAccess::with_read_only_storage_ctx`, then use these helpers to read the same
//! generated storage handlers used by protocol execution.

use alloy_primitives::{Address, B256};
use tempo_precompiles::error::Result;
use tempo_zone_contracts::IZoneOutbox;

use crate::{TempoState, ZoneFeeManager, ZoneInbox, ZoneOutbox};

/// Protocol commitments stored in Zone state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZoneStateSnapshot {
    pub tempo_block_hash: B256,
    pub tempo_block_number: u64,
    pub processed_deposit_queue_hash: B256,
    pub processed_deposit_number: u64,
    pub last_withdrawal_batch: IZoneOutbox::LastBatch,
    pub default_fee_token: Address,
}

impl ZoneStateSnapshot {
    /// Reads the current protocol commitments through generated storage handlers.
    pub fn read() -> Result<Self> {
        let mut tempo_state = TempoState::new();
        let inbox = ZoneInbox::new();
        let outbox = ZoneOutbox::new();
        let fee_manager = ZoneFeeManager::new();

        Ok(Self {
            tempo_block_hash: tempo_state.tempo_block_hash()?,
            tempo_block_number: tempo_state.tempo_block_number()?,
            processed_deposit_queue_hash: inbox.processed_deposit_queue_hash()?,
            processed_deposit_number: inbox.processed_deposit_number()?,
            last_withdrawal_batch: outbox.last_batch()?,
            default_fee_token: fee_manager.default_fee_token()?,
        })
    }
}
