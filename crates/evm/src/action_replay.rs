use std::collections::hash_map::Entry;

use crate::{TempoBlockExecutor, TempoTxResult};
use alloy_evm::{
    Database, Evm, RecoveredTx,
    block::{BlockExecutionError, BlockExecutor, ExecutableTx},
};
use alloy_primitives::{
    Address, B256, U256,
    map::{AddressMap, U256Map},
};
use reth_evm::block::InternalBlockExecutionError;
use reth_revm::{
    Database as _, Inspector, State,
    context::{Transaction as _, result::ExecutionResult},
    state::{Account, EvmState, EvmStorageSlot, TransactionId},
};
use tempo_precompiles::{
    NONCE_PRECOMPILE_ADDRESS,
    nonce::{EXPIRING_NONCE_MAX_EXPIRY_SECS, EXPIRING_NONCE_SET_CAPACITY, NonceManager},
    storage::StorageAction,
    tip_fee_manager::amm::{Pool, compute_amount_out},
};
use tempo_revm::{TempoHaltReason, evm::TempoContext};

impl<'a, DB, I> TempoBlockExecutor<'a, &'a mut State<DB>, I>
where
    DB: Database,
    I: Inspector<TempoContext<&'a mut State<DB>>>,
{
    /// Commits a precomputed transaction by replaying recorded storage actions.
    ///
    /// `result_closure` observes the synthesized result before the replayed state is committed.
    pub fn execute_transaction_with_actions(
        &mut self,
        tx: impl ExecutableTx<Self>,
        replay: StorageActionReplay,
        result_closure: impl FnOnce(&TempoTxResult),
        commit_reads: bool,
    ) -> Result<(), BlockExecutionError> {
        let (tx_env, recovered) = tx.into_parts();

        let StorageActionReplay {
            result,
            mut actions,
            expiring_nonce,
            validator_fee,
        } = replay;
        self.replay_state.reset_tx_changes();

        // TODO: handle reverted transactions
        if !result.is_success() {
            return Err(StorageActionReplayError::TransactionExecutionFailed.into());
        }

        let state = self
            .replay_actions(
                tx_env.caller(),
                actions.drain(..),
                commit_reads,
                expiring_nonce,
            )
            .inspect_err(|_| {
                self.replay_state.reset_tx_changes();
            })?;

        let cfg = self.inner.evm.cfg_env().clone();
        let gas = result.gas();
        let block_gas_used = if cfg.enable_amsterdam_eip8037 {
            gas.block_regular_gas_used()
        } else {
            gas.tx_gas_used()
        };
        let next_section = self
            .validate_tx(recovered.tx(), block_gas_used)
            .map_err(BlockExecutionError::from)?;

        let result = TempoTxResult::new_precomputed(
            recovered.tx(),
            result,
            state,
            next_section,
            self.is_payment(recovered.tx()),
            block_gas_used,
            validator_fee,
        );
        result_closure(&result);

        self.commit_transaction(result);

        Ok(())
    }

    fn replay_actions(
        &mut self,
        sender: Address,
        actions: impl IntoIterator<Item = StorageAction>,
        commit_reads: bool,
        expiring_nonce: Option<ExpiringNonceReplay>,
    ) -> Result<EvmState, BlockExecutionError> {
        let block_timestamp = self.inner.evm.block().timestamp.to::<u64>();
        let is_expiring_nonce = expiring_nonce.is_some();

        if let Some(expiring_nonce) = expiring_nonce {
            self.apply_expiring_nonce_replay(expiring_nonce, block_timestamp)?;
        }

        let db = self.inner.evm.db_mut();
        for action in actions {
            // Expiring nonces are handled above
            if is_expiring_nonce && action.address() == NONCE_PRECOMPILE_ADDRESS {
                continue;
            }

            match action {
                StorageAction::Sload(address, key, value) => {
                    // We don't need to check `replay_state.has_store` here,
                    // as `sload_exact` is already checking it
                    let _ = self.replay_state.sload_exact(db, address, key, value)?;
                }
                StorageAction::Sstore(address, key, value) => {
                    if self.replay_state.has_write(address, key) {
                        return Err(StorageActionReplayError::ActionConflict.into());
                    }
                    self.replay_state
                        .sstore(address, key, value, WriteKind::Store)?;
                }
                StorageAction::Sinc(address, key, delta) => {
                    if self.replay_state.has_store(address, key) {
                        return Err(StorageActionReplayError::ActionConflict.into());
                    }

                    let value = self
                        .replay_state
                        .sload_current(db, address, key)?
                        .checked_add(delta)
                        .ok_or(StorageActionReplayError::Overflow)?;
                    self.replay_state
                        .sstore(address, key, value, WriteKind::Delta)?;
                }
                StorageAction::Sdec(address, key, delta) => {
                    if self.replay_state.has_store(address, key) {
                        return Err(StorageActionReplayError::ActionConflict.into());
                    }

                    let value = self
                        .replay_state
                        .sload_current(db, address, key)?
                        .checked_sub(delta)
                        .ok_or(StorageActionReplayError::Underflow)?;
                    self.replay_state
                        .sstore(address, key, value, WriteKind::Delta)?;
                }
                StorageAction::FeeAmmSwap(address, key, amount_in) => {
                    if self.replay_state.has_store(address, key) {
                        return Err(StorageActionReplayError::ActionConflict.into());
                    }

                    let pool_slot = self.replay_state.sload_current(db, address, key)?;
                    let mut pool = Pool::decode_from_slot(pool_slot);
                    pool.apply_swap(
                        amount_in,
                        compute_amount_out(amount_in)
                            .map_err(|_| StorageActionReplayError::ActionConflict)?,
                    )
                    .map_err(|_| StorageActionReplayError::ActionConflict)?;
                    let value = pool
                        .encode_to_slot()
                        .map_err(|_| StorageActionReplayError::ActionConflict)?;
                    self.replay_state
                        .sstore(address, key, value, WriteKind::Delta)?;
                }
            }
        }

        let mut state = EvmState::default();

        if commit_reads {
            let account = db
                .basic(sender)
                .map_err(BlockExecutionError::other)?
                .unwrap_or_default();
            let mut account = Account::from(account);
            account.mark_touch();
            state.insert(sender, account);
        }

        for (address, slots) in self.replay_state.tx_changes.iter() {
            for (slot, change) in slots {
                if change.write_kind.is_none() && !commit_reads {
                    continue;
                }

                let account = match state.entry(*address) {
                    Entry::Occupied(e) => e.into_mut(),
                    Entry::Vacant(e) => {
                        let mut account = Account::from(
                            db.basic(*address)
                                .map_err(BlockExecutionError::other)?
                                .unwrap_or_default(),
                        );
                        account.mark_touch();
                        e.insert(account)
                    }
                };
                account.storage.insert(
                    *slot,
                    EvmStorageSlot::new_changed(
                        change.original,
                        change.current,
                        TransactionId::ZERO,
                    ),
                );
            }
        }

        Ok(state)
    }

    fn apply_expiring_nonce_replay(
        &mut self,
        expiring_nonce: ExpiringNonceReplay,
        block_timestamp: u64,
    ) -> Result<(), BlockExecutionError> {
        if expiring_nonce.valid_before <= block_timestamp
            || expiring_nonce.valid_before
                > block_timestamp.saturating_add(EXPIRING_NONCE_MAX_EXPIRY_SECS)
        {
            return Err(StorageActionReplayError::ActionConflict.into());
        }

        let db = self.inner.evm_mut().db_mut();

        let nonce_manager = NonceManager::new();
        let now = U256::from(block_timestamp);
        let ptr = self.replay_state.expiring_nonce.ring_ptr(db)?;

        let seen_slot = nonce_manager.expiring_nonce_seen[expiring_nonce.hash].slot();
        let seen_expiry = db
            .storage(NONCE_PRECOMPILE_ADDRESS, seen_slot)
            .map_err(BlockExecutionError::other)?;
        if !seen_expiry.is_zero() && seen_expiry > now {
            return Err(StorageActionReplayError::ActionConflict.into());
        }

        let ptr_u32 = ptr
            .try_into()
            .map_err(|_| StorageActionReplayError::ActionConflict)?;
        let ring_slot = nonce_manager.expiring_nonce_ring[ptr_u32].slot();
        let old_hash = db
            .storage(NONCE_PRECOMPILE_ADDRESS, ring_slot)
            .map_err(BlockExecutionError::other)?;
        if !old_hash.is_zero() {
            let old_seen_slot = nonce_manager.expiring_nonce_seen[B256::from(old_hash)].slot();
            let old_expiry = db
                .storage(NONCE_PRECOMPILE_ADDRESS, old_seen_slot)
                .map_err(BlockExecutionError::other)?;
            if !old_expiry.is_zero() && old_expiry > now {
                return Err(StorageActionReplayError::ActionConflict.into());
            }
            self.replay_state.record_sstore(
                NONCE_PRECOMPILE_ADDRESS,
                old_seen_slot,
                old_expiry,
                U256::ZERO,
                WriteKind::Store,
            );
        }

        self.replay_state.record_sstore(
            NONCE_PRECOMPILE_ADDRESS,
            ring_slot,
            old_hash,
            U256::from_be_slice(expiring_nonce.hash.as_slice()),
            WriteKind::Store,
        );
        self.replay_state.record_sstore(
            NONCE_PRECOMPILE_ADDRESS,
            seen_slot,
            seen_expiry,
            U256::from(expiring_nonce.valid_before),
            WriteKind::Store,
        );

        let next = ptr
            .checked_add(U256::ONE)
            .filter(|next| *next < EXPIRING_NONCE_SET_CAPACITY)
            .unwrap_or(U256::ZERO);
        self.replay_state.record_sstore(
            NONCE_PRECOMPILE_ADDRESS,
            nonce_manager.expiring_nonce_ring_ptr.slot(),
            ptr,
            next,
            WriteKind::Store,
        );
        self.replay_state.expiring_nonce.set_next_ring_ptr(next);

        Ok(())
    }
}

/// Result of replaying storage actions.
#[derive(Debug)]
pub struct StorageActionReplayOutcome {
    /// Empty actions buffer that can be reused for future executions.
    pub actions: Vec<StorageAction>,
    /// Result of the replay execution.
    pub result: Result<(), BlockExecutionError>,
}

/// Precomputed transaction execution result plus semantic precompile storage actions.
#[derive(Debug)]
pub struct StorageActionReplay {
    /// Precomputed transaction execution result that can be reused if actions are applied without conflicts.
    pub result: ExecutionResult<TempoHaltReason>,
    /// Actions to replay in order to get to the state after the transaction execution.
    pub actions: Vec<StorageAction>,
    /// Semantic replay data for expiring nonce transactions.
    pub expiring_nonce: Option<ExpiringNonceReplay>,
    /// Validator-credited fee amount
    pub validator_fee: U256,
}

/// Replay data for expiring nonce transactions.
#[derive(Debug, Clone, Copy)]
pub struct ExpiringNonceReplay {
    pub hash: B256,
    pub valid_before: u64,
}

/// Reason a precomputed storage-action replay cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StorageActionReplayError {
    #[error("transaction execution failed")]
    TransactionExecutionFailed,
    #[error("storage action conflict")]
    ActionConflict,
    #[error("storage action overflow")]
    Overflow,
    #[error("storage action underflow")]
    Underflow,
}

impl StorageActionReplayError {
    /// Returns the replay fallback reason carried by a [`BlockExecutionError`], if any.
    pub fn from_block_execution_error(error: &BlockExecutionError) -> Option<Self> {
        match error {
            BlockExecutionError::Internal(error) => {
                Self::from_internal_block_execution_error(error)
            }
            _ => None,
        }
    }

    /// Returns the replay fallback reason carried by an [`InternalBlockExecutionError`], if any.
    pub fn from_internal_block_execution_error(
        error: &InternalBlockExecutionError,
    ) -> Option<Self> {
        error.downcast_other::<Self>().copied()
    }
}

impl From<StorageActionReplayError> for BlockExecutionError {
    fn from(reason: StorageActionReplayError) -> Self {
        Self::other(reason)
    }
}

#[derive(Debug, Default)]
pub struct StorageActionReplayState {
    /// Writes recorded for all transactions.
    writes: AddressMap<U256Map<WriteKind>>,
    /// Changes for the current transaction.
    tx_changes: AddressMap<U256Map<SlotChange>>,
    /// Expiring nonce replay state.
    expiring_nonce: ExpiringNonceReplayState,
}

impl StorageActionReplayState {
    /// Clears cached expiring-nonce state after execution that did not go through action replay.
    pub fn invalidate_expiring_nonce_cache(&mut self) {
        self.expiring_nonce.invalidate_cache();
    }

    /// Returns whether the state has any write at the given address and slot.
    fn has_write(&self, address: Address, slot: U256) -> bool {
        self.writes
            .get(&address)
            .is_some_and(|slots| slots.contains_key(&slot))
    }

    /// Returns whether the state has a [store](`WriteKind::Store`) write at the given address and slot.
    fn has_store(&self, address: Address, slot: U256) -> bool {
        self.writes
            .get(&address)
            .and_then(|slots| slots.get(&slot))
            .is_some_and(|kind| *kind == WriteKind::Store)
    }

    /// Stores the value of a slot that has already been loaded for this transaction.
    fn sstore(
        &mut self,
        address: Address,
        slot: U256,
        value: U256,
        kind: WriteKind,
    ) -> Result<(), BlockExecutionError> {
        // `Sstore` actions record only the new value. The transaction-start
        // value must already be established by a load, otherwise replay would
        // invent `original` from current state and reuse gas/refund data from a
        // different storage transition.
        let change = self
            .tx_changes
            .get_mut(&address)
            .and_then(|slots| slots.get_mut(&slot))
            .ok_or(StorageActionReplayError::ActionConflict)?;
        change.current = value;

        // Absolute stores are non-commutative, so they dominate deltas when
        // recording cross-transaction conflict state.
        if change.write_kind.is_none() || kind == WriteKind::Store {
            change.write_kind = Some(kind);
        }

        Ok(())
    }

    /// Records a storage slot write with a known transaction-start value.
    fn record_sstore(
        &mut self,
        address: Address,
        slot: U256,
        original: U256,
        current: U256,
        kind: WriteKind,
    ) {
        self.tx_changes
            .entry(address)
            .or_default()
            .entry(slot)
            .and_modify(|change| {
                change.current = current;
                if change.write_kind.is_none() || kind == WriteKind::Store {
                    change.write_kind = Some(kind);
                }
            })
            .or_insert(SlotChange {
                original,
                current,
                write_kind: Some(kind),
            });
    }

    /// Returns the current value for a slot and validates that it matches the expected value.
    fn sload_exact<DB: Database>(
        &mut self,
        db: &mut State<DB>,
        address: Address,
        slot: U256,
        expected: U256,
    ) -> Result<U256, BlockExecutionError> {
        match self.tx_changes.entry(address).or_default().entry(slot) {
            Entry::Occupied(change) => {
                if change.get().current != expected {
                    return Err(StorageActionReplayError::ActionConflict.into());
                }
                Ok(change.get().current)
            }
            Entry::Vacant(change) => {
                // We can avoid querying the database at all here, and instead rely on
                // the EVM cache and expected value to determine the current value
                let current = db
                    .cache
                    .accounts
                    .get(&address)
                    .and_then(|cached_account| {
                        let Some(account) = cached_account.account.as_ref() else {
                            // Account is in cache and known to not exist, so all its storage is zero
                            return Some(U256::ZERO);
                        };

                        if let Some(slot) = account.storage.get(&slot).copied() {
                            // Account and slot is in cache
                            Some(slot)
                        } else {
                            // Account is in cache, but the slot is not. If the storage is reported to be fully known,
                            // it means the slot doesn't exist, and its value is zero
                            cached_account
                                .status
                                .is_storage_known()
                                .then_some(U256::ZERO)
                        }
                    })
                    // If the slot was not found in cache, it means it's the first access,
                    // and we can just use the expected value
                    .unwrap_or(expected);
                if current != expected {
                    return Err(StorageActionReplayError::ActionConflict.into());
                }

                change.insert(SlotChange {
                    original: current,
                    current,
                    write_kind: None,
                });
                Ok(current)
            }
        }
    }

    /// Returns the current value for a slot.
    ///
    /// If it was previously written, returns the value from the transaction change.
    /// Otherwise, returns the value from the database.
    fn sload_current<DB: Database>(
        &mut self,
        db: &mut State<DB>,
        address: Address,
        slot: U256,
    ) -> Result<U256, BlockExecutionError> {
        match self.tx_changes.entry(address).or_default().entry(slot) {
            Entry::Occupied(change) => Ok(change.get().current),
            Entry::Vacant(change) => {
                let current = db
                    .storage(address, slot)
                    .map_err(BlockExecutionError::other)?;
                change.insert(SlotChange {
                    original: current,
                    current,
                    write_kind: None,
                });
                Ok(current)
            }
        }
    }

    /// Resets the accumulated transaction changes.
    fn reset_tx_changes(&mut self) {
        self.tx_changes.clear();
        self.expiring_nonce.reset_pending_ring_ptr();
    }

    /// Commits the accumulated transaction changes to the state.
    pub(crate) fn commit_tx_changes(&mut self) {
        for (address, slots) in self.tx_changes.drain() {
            let account_writes = self.writes.entry(address).or_default();
            for (slot, change) in slots {
                if let Some(kind) = change.write_kind {
                    account_writes
                        .entry(slot)
                        .and_modify(|existing| {
                            if kind == WriteKind::Store {
                                *existing = WriteKind::Store;
                            }
                        })
                        .or_insert(kind);
                }
            }
        }
        self.expiring_nonce.commit_pending_ring_ptr();
    }
}

#[derive(Debug)]
struct SlotChange {
    original: U256,
    current: U256,
    write_kind: Option<WriteKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteKind {
    Store,
    Delta,
}

#[derive(Debug, Default)]
struct ExpiringNonceReplayState {
    /// Current cached ring pointer.
    ring_ptr: Option<U256>,
    /// Pending ring pointer to be committed by current transaction.
    pending_ring_ptr: Option<U256>,
}

impl ExpiringNonceReplayState {
    fn invalidate_cache(&mut self) {
        self.ring_ptr = None;
        self.reset_pending_ring_ptr();
    }

    fn reset_pending_ring_ptr(&mut self) {
        self.pending_ring_ptr = None;
    }

    fn commit_pending_ring_ptr(&mut self) {
        if let Some(ptr) = self.pending_ring_ptr.take() {
            self.ring_ptr = Some(ptr);
        }
    }

    fn ring_ptr<DB: Database>(&mut self, db: &mut State<DB>) -> Result<U256, BlockExecutionError> {
        Ok(match self.ring_ptr {
            Some(ptr) => ptr,
            None => {
                let ptr = db
                    .storage(
                        NONCE_PRECOMPILE_ADDRESS,
                        NonceManager::new().expiring_nonce_ring_ptr.slot(),
                    )
                    .map_err(BlockExecutionError::other)?;
                self.ring_ptr = Some(ptr);
                ptr
            }
        })
    }

    fn set_next_ring_ptr(&mut self, next: U256) {
        self.pending_ring_ptr = Some(next);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::{
        database::{CacheDB, EmptyDB},
        state::AccountInfo,
    };

    fn state_with_storage(address: Address, slot: U256, value: U256) -> State<EmptyDB> {
        let mut db = State::builder().with_database(EmptyDB::default()).build();
        db.insert_account_with_storage(
            address,
            AccountInfo::default(),
            [(slot, value)].into_iter().collect(),
        );
        db
    }

    #[test]
    fn recorded_sload_rejects_changed_database_value() {
        let address = Address::repeat_byte(0x42);
        let slot = U256::from(7);
        let mut db = state_with_storage(address, slot, U256::from(11));
        let mut replay_state = StorageActionReplayState::default();

        let err = replay_state
            .sload_exact(&mut db, address, slot, U256::from(10))
            .unwrap_err();
        assert_eq!(
            StorageActionReplayError::from_block_execution_error(&err),
            Some(StorageActionReplayError::ActionConflict)
        );
    }

    #[test]
    fn recorded_sload_uses_recorded_value_when_slot_is_not_cached() {
        let address = Address::repeat_byte(0x42);
        let slot = U256::from(7);
        let mut cache_db = CacheDB::new(EmptyDB::default());
        cache_db.insert_account_info(
            address,
            AccountInfo {
                nonce: 1,
                ..Default::default()
            },
        );
        cache_db
            .insert_account_storage(address, slot, U256::from(11))
            .expect("seed backing storage");
        let mut db = State::builder().with_database(cache_db).build();
        let mut replay_state = StorageActionReplayState::default();

        assert_eq!(
            replay_state
                .sload_exact(&mut db, address, slot, U256::from(10))
                .expect("recorded sload should avoid backing storage lookup"),
            U256::from(10),
        );
        let change = replay_state
            .tx_changes
            .get(&address)
            .and_then(|slots| slots.get(&slot))
            .expect("slot change recorded");
        assert_eq!(change.original, U256::from(10));
        assert_eq!(change.current, U256::from(10));
        assert_eq!(change.write_kind, None);
    }

    #[test]
    fn recorded_sload_rejects_changed_transaction_view() {
        let address = Address::repeat_byte(0x42);
        let slot = U256::from(7);
        let mut db = state_with_storage(address, slot, U256::from(10));
        let mut replay_state = StorageActionReplayState::default();

        assert_eq!(
            replay_state
                .sload_current(&mut db, address, slot)
                .expect("load current storage"),
            U256::from(10),
        );
        replay_state
            .sstore(address, slot, U256::from(11), WriteKind::Delta)
            .expect("store loaded slot");

        let err = replay_state
            .sload_exact(&mut db, address, slot, U256::from(10))
            .unwrap_err();
        assert_eq!(
            StorageActionReplayError::from_block_execution_error(&err),
            Some(StorageActionReplayError::ActionConflict)
        );
    }

    #[test]
    fn recorded_sload_does_not_rebase_on_committed_delta() {
        let address = Address::repeat_byte(0x42);
        let slot = U256::from(7);
        let mut db = state_with_storage(address, slot, U256::from(11));
        let mut replay_state = StorageActionReplayState::default();
        replay_state
            .writes
            .entry(address)
            .or_default()
            .insert(slot, WriteKind::Delta);

        let err = replay_state
            .sload_exact(&mut db, address, slot, U256::from(10))
            .unwrap_err();
        assert_eq!(
            StorageActionReplayError::from_block_execution_error(&err),
            Some(StorageActionReplayError::ActionConflict)
        );
    }

    #[test]
    fn sstore_requires_prior_load() {
        let address = Address::repeat_byte(0x42);
        let slot = U256::from(7);
        let mut replay_state = StorageActionReplayState::default();

        let err = replay_state
            .sstore(address, slot, U256::from(11), WriteKind::Store)
            .unwrap_err();
        assert_eq!(
            StorageActionReplayError::from_block_execution_error(&err),
            Some(StorageActionReplayError::ActionConflict)
        );
    }

    #[test]
    fn current_sload_allows_semantic_rebase() {
        let address = Address::repeat_byte(0x42);
        let slot = U256::from(7);
        let mut db = state_with_storage(address, slot, U256::from(11));
        let mut replay_state = StorageActionReplayState::default();

        let current = replay_state
            .sload_current(&mut db, address, slot)
            .expect("load current storage");
        replay_state
            .sstore(address, slot, current + U256::from(3), WriteKind::Delta)
            .expect("store loaded slot");

        let change = replay_state
            .tx_changes
            .get(&address)
            .and_then(|slots| slots.get(&slot))
            .expect("slot change recorded");
        assert_eq!(change.original, U256::from(11));
        assert_eq!(change.current, U256::from(14));
        assert_eq!(change.write_kind, Some(WriteKind::Delta));
    }
}
