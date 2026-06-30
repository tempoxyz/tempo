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
use reth_evm::block::StateDB;
use reth_revm::{
    Database as _, Inspector, State,
    context::{Transaction as _, result::ExecutionResult},
    state::{Account, AccountInfo, EvmState, EvmStorageSlot, TransactionId},
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
    /// Commits one precomputed transaction by replaying recorded storage actions.
    ///
    /// `should_commit` observes the result before state mutation. Returning `false` leaves
    /// executor state unchanged, allowing the payload builder to stop at the exact block gas
    /// boundary.
    pub fn execute_transaction_with_actions(
        &mut self,
        tx: impl ExecutableTx<Self>,
        replay: StorageActionReplay,
        replay_state: &mut StorageActionReplayState,
        transaction_index: usize,
        result_closure: impl FnOnce(&TempoTxResult),
        commit_reads: bool,
    ) -> StorageActionReplayOutcome {
        let (tx_env, recovered) = tx.into_parts();

        let StorageActionReplay {
            result,
            mut actions,
            expiring_nonce,
            validator_fee,
        } = replay;
        replay_state.reset_tx_changes();

        let result = (|| {
            if !result.is_success() {
                return Err(StorageActionReplayExecutionError::Fallback(
                    StorageActionReplayFallback::ActionExecutionFailed,
                ));
            }

            let state = self
                .replay_actions(
                    tx_env.caller(),
                    actions.drain(..),
                    replay_state,
                    commit_reads,
                    expiring_nonce,
                )
                .inspect_err(|_| {
                    replay_state.reset_tx_changes();
                })?;

            let cfg = self.inner.evm.cfg_env().clone();
            let gas = result.gas();
            let block_gas_used = if cfg.enable_amsterdam_eip8037 {
                gas.block_regular_gas_used()
            } else {
                gas.tx_gas_used()
            };
            let next_section =
                self.validate_tx(recovered.tx(), block_gas_used)
                    .map_err(|error| StorageActionReplayExecutionError::Validation {
                        transaction_index,
                        error: error.into(),
                    })?;

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
            replay_state.commit_tx_changes();
            Ok(())
        })();

        StorageActionReplayOutcome { actions, result }
    }

    fn replay_actions(
        &mut self,
        sender: Address,
        actions: impl IntoIterator<Item = StorageAction>,
        replay_state: &mut StorageActionReplayState,
        commit_reads: bool,
        expiring_nonce: Option<ExpiringNonceReplay>,
    ) -> Result<EvmState, StorageActionReplayExecutionError> {
        let block_timestamp = self.inner.evm.block().timestamp.to::<u64>();
        let is_expiring_nonce = expiring_nonce.is_some();

        if let Some(expiring_nonce) = expiring_nonce {
            self.apply_expiring_nonce_replay(replay_state, expiring_nonce, block_timestamp)?;
        }

        let db = self.inner.evm.db_mut();
        for action in actions {
            // Expiring nonces are handled above
            if is_expiring_nonce && action.address() == NONCE_PRECOMPILE_ADDRESS {
                continue;
            }

            match action {
                StorageAction::Sload(address, key, value) => {
                    if replay_state.has_store(address, key) {
                        return Err(StorageActionReplayFallback::ActionConflict.into());
                    }
                    let _ = replay_state.sload_exact(db, address, key, value)?;
                }
                StorageAction::Sstore(address, key, value) => {
                    if replay_state.has_write(address, key) {
                        return Err(StorageActionReplayFallback::ActionConflict.into());
                    }
                    replay_state.sstore(address, key, value, WriteKind::Store)?;
                }
                StorageAction::Sinc(address, key, delta) => {
                    if replay_state.has_store(address, key) {
                        return Err(StorageActionReplayFallback::ActionConflict.into());
                    }

                    let value = replay_state
                        .sload_current(db, address, key)?
                        .checked_add(delta)
                        .ok_or(StorageActionReplayFallback::Overflow)?;
                    replay_state.sstore(address, key, value, WriteKind::Delta)?;
                }
                StorageAction::Sdec(address, key, delta) => {
                    if replay_state.has_store(address, key) {
                        return Err(StorageActionReplayFallback::ActionConflict.into());
                    }

                    let value = replay_state
                        .sload_current(db, address, key)?
                        .checked_sub(delta)
                        .ok_or(StorageActionReplayFallback::Underflow)?;
                    replay_state.sstore(address, key, value, WriteKind::Delta)?;
                }
                StorageAction::FeeAmmSwap(address, key, amount_in) => {
                    if replay_state.has_store(address, key) {
                        return Err(StorageActionReplayFallback::ActionConflict.into());
                    }

                    let pool_slot = replay_state.sload_current(db, address, key)?;
                    let mut pool = Pool::decode_from_slot(pool_slot);
                    pool.apply_swap(
                        amount_in,
                        compute_amount_out(amount_in)
                            .map_err(|_| StorageActionReplayFallback::ActionConflict)?,
                    )
                    .map_err(|_| StorageActionReplayFallback::ActionConflict)?;
                    let value = pool
                        .encode_to_slot()
                        .map_err(|_| StorageActionReplayFallback::ActionConflict)?;
                    replay_state.sstore(address, key, value, WriteKind::Delta)?;
                }
            }
        }

        let mut state = EvmState::default();

        if commit_reads {
            let account = action_account_info(db, sender)?;
            let mut account = Account::from(account);
            account.mark_touch();
            state.insert(sender, account);
        }

        for (address, slots) in replay_state.tx_changes.iter() {
            for (slot, change) in slots {
                if change.write_kind.is_none() && !commit_reads {
                    continue;
                }

                if let Entry::Vacant(e) = state.entry(*address) {
                    let mut account = Account::from(action_account_info(db, *address)?);
                    account.mark_touch();
                    e.insert(account);
                }
                let account = state
                    .get_mut(address)
                    .expect("action replay account inserted");
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
        replay_state: &mut StorageActionReplayState,
        expiring_nonce: ExpiringNonceReplay,
        block_timestamp: u64,
    ) -> Result<(), StorageActionReplayExecutionError> {
        if expiring_nonce.valid_before <= block_timestamp
            || expiring_nonce.valid_before
                > block_timestamp.saturating_add(EXPIRING_NONCE_MAX_EXPIRY_SECS)
        {
            return Err(StorageActionReplayFallback::ActionConflict.into());
        }

        let db = self.evm_mut().db_mut();

        let nonce_manager = NonceManager::new();
        let now = U256::from(block_timestamp);
        let ptr = replay_state.expiring_nonce.ring_ptr(db)?;

        let seen_slot = nonce_manager.expiring_nonce_seen[expiring_nonce.hash].slot();
        let seen_expiry = state_storage(db, NONCE_PRECOMPILE_ADDRESS, seen_slot)?;
        if !seen_expiry.is_zero() && seen_expiry > now {
            return Err(StorageActionReplayFallback::ActionConflict.into());
        }

        let ptr_u32 = ptr
            .try_into()
            .map_err(|_| StorageActionReplayFallback::ActionConflict)?;
        let ring_slot = nonce_manager.expiring_nonce_ring[ptr_u32].slot();
        let old_hash = state_storage(db, NONCE_PRECOMPILE_ADDRESS, ring_slot)?;
        if !old_hash.is_zero() {
            let old_seen_slot = nonce_manager.expiring_nonce_seen[B256::from(old_hash)].slot();
            let old_expiry = state_storage(db, NONCE_PRECOMPILE_ADDRESS, old_seen_slot)?;
            if !old_expiry.is_zero() && old_expiry > now {
                return Err(StorageActionReplayFallback::ActionConflict.into());
            }
            replay_state.record_sstore(
                NONCE_PRECOMPILE_ADDRESS,
                old_seen_slot,
                old_expiry,
                U256::ZERO,
                WriteKind::Store,
            );
        }

        replay_state.record_sstore(
            NONCE_PRECOMPILE_ADDRESS,
            ring_slot,
            old_hash,
            U256::from_be_slice(expiring_nonce.hash.as_slice()),
            WriteKind::Store,
        );
        replay_state.record_sstore(
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
        replay_state.record_sstore(
            NONCE_PRECOMPILE_ADDRESS,
            nonce_manager.expiring_nonce_ring_ptr.slot(),
            ptr,
            next,
            WriteKind::Store,
        );
        replay_state.expiring_nonce.set_next_ring_ptr(next);

        Ok(())
    }
}

/// Result of replaying storage actions.
#[derive(Debug)]
pub struct StorageActionReplayOutcome {
    /// Empty actions buffer that can be reused for future executions.
    pub actions: Vec<StorageAction>,
    /// Result of the replay execution.
    pub result: Result<(), StorageActionReplayExecutionError>,
}

/// Error returned by the storage-action replay execution API.
#[derive(Debug)]
pub enum StorageActionReplayExecutionError {
    /// The precomputed replay cannot be used; no state was committed.
    Fallback(StorageActionReplayFallback),
    /// Synthetic validation rejected a transaction.
    Validation {
        /// Index of the failed transaction in the streaming sequence.
        transaction_index: usize,
        /// Execution error returned by synthetic result construction or block validation.
        error: BlockExecutionError,
    },
    /// Preflight failed while reading state; no state was committed.
    Database(BlockExecutionError),
}

impl From<StorageActionReplayFallback> for StorageActionReplayExecutionError {
    fn from(reason: StorageActionReplayFallback) -> Self {
        Self::Fallback(reason)
    }
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageActionReplayFallback {
    ActionExecutionFailed,
    ActionConflict,
    Overflow,
    Underflow,
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
    ) -> Result<(), StorageActionReplayExecutionError> {
        // `Sstore` actions record only the new value. The transaction-start
        // value must already be established by a load, otherwise replay would
        // invent `original` from current state and reuse gas/refund data from a
        // different storage transition.
        let change = self
            .tx_changes
            .get_mut(&address)
            .and_then(|slots| slots.get_mut(&slot))
            .ok_or(StorageActionReplayFallback::ActionConflict)?;
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
    ) -> Result<U256, StorageActionReplayExecutionError> {
        match self.tx_changes.entry(address).or_default().entry(slot) {
            Entry::Occupied(change) => {
                if change.get().current != expected {
                    return Err(StorageActionReplayFallback::ActionConflict.into());
                }
                Ok(change.get().current)
            }
            Entry::Vacant(change) => {
                let current = state_storage(db, address, slot)?;
                if current != expected {
                    return Err(StorageActionReplayFallback::ActionConflict.into());
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
    ) -> Result<U256, StorageActionReplayExecutionError> {
        match self.tx_changes.entry(address).or_default().entry(slot) {
            Entry::Occupied(change) => Ok(change.get().current),
            Entry::Vacant(change) => {
                let current = state_storage(db, address, slot)?;
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
    fn commit_tx_changes(&mut self) {
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

    fn ring_ptr<DB: Database>(
        &mut self,
        db: &mut State<DB>,
    ) -> Result<U256, StorageActionReplayExecutionError> {
        Ok(match self.ring_ptr {
            Some(ptr) => ptr,
            None => {
                let ptr = state_storage(
                    db,
                    NONCE_PRECOMPILE_ADDRESS,
                    NonceManager::new().expiring_nonce_ring_ptr.slot(),
                )?;
                self.ring_ptr = Some(ptr);
                ptr
            }
        })
    }

    fn set_next_ring_ptr(&mut self, next: U256) {
        self.pending_ring_ptr = Some(next);
    }
}

fn state_storage<DB: Database>(
    db: &mut State<DB>,
    address: Address,
    slot: U256,
) -> Result<U256, StorageActionReplayExecutionError> {
    db.storage(address, slot)
        .map_err(BlockExecutionError::other)
        .map_err(StorageActionReplayExecutionError::Database)
}

fn action_account_info<DB: StateDB>(
    db: &mut DB,
    address: Address,
) -> Result<AccountInfo, StorageActionReplayExecutionError> {
    db.basic(address)
        .map_err(BlockExecutionError::other)
        .map_err(StorageActionReplayExecutionError::Database)
        .map(|account| account.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::database::EmptyDB;
    use std::assert_matches;

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

        assert_matches!(
            replay_state.sload_exact(&mut db, address, slot, U256::from(10)),
            Err(StorageActionReplayExecutionError::Fallback(
                StorageActionReplayFallback::ActionConflict
            ))
        );
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

        assert_matches!(
            replay_state.sload_exact(&mut db, address, slot, U256::from(10)),
            Err(StorageActionReplayExecutionError::Fallback(
                StorageActionReplayFallback::ActionConflict
            ))
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

        assert_matches!(
            replay_state.sload_exact(&mut db, address, slot, U256::from(10)),
            Err(StorageActionReplayExecutionError::Fallback(
                StorageActionReplayFallback::ActionConflict
            ))
        );
    }

    #[test]
    fn sstore_requires_prior_load() {
        let address = Address::repeat_byte(0x42);
        let slot = U256::from(7);
        let mut replay_state = StorageActionReplayState::default();

        assert_matches!(
            replay_state.sstore(address, slot, U256::from(11), WriteKind::Store,),
            Err(StorageActionReplayExecutionError::Fallback(
                StorageActionReplayFallback::ActionConflict
            ))
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
