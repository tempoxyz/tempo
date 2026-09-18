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
    context::{
        Transaction as _,
        result::{ExecutionResult, HaltReason},
    },
    state::{Account, EvmState, EvmStorageSlot, TransactionId},
};
use tempo_precompiles::{
    EXPIRING_NONCE_PRECOMPILE_ADDRESS,
    expiring_nonce::ExpiringNonceManager,
    storage::StorageAction,
    tip_fee_manager::amm::{Pool, compute_amount_out},
};
use tempo_revm::evm::TempoContext;

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
        self.apply_nonce_pruning(false)?;
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
            tx_env.execution_context,
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
            if is_expiring_nonce && action.address() == EXPIRING_NONCE_PRECOMPILE_ADDRESS {
                continue;
            }

            match action {
                StorageAction::Sload(address, key, value) => {
                    let _ = self.replay_state.sload_exact(db, address, key, value)?;
                }
                StorageAction::Sstore(address, key, sload_value, value) => {
                    self.replay_state
                        .sstore_exact(db, address, key, sload_value, value)?;
                }
                StorageAction::Sinc(address, key, sload_value, delta) => {
                    let current =
                        self.replay_state
                            .sload_current_or(db, address, key, sload_value)?;
                    let value = current
                        .checked_add(delta)
                        .ok_or(StorageActionReplayError::Overflow)?;
                    self.replay_state.sstore(address, key, value)?;
                }
                StorageAction::Sdec(address, key, sload_value, delta) => {
                    let current =
                        self.replay_state
                            .sload_current_or(db, address, key, sload_value)?;
                    let value = current
                        .checked_sub(delta)
                        .ok_or(StorageActionReplayError::Underflow)?;
                    self.replay_state.sstore(address, key, value)?;
                }
                StorageAction::FeeAmmSwap(key, sload_value, amount_in) => {
                    let pool_slot = self.replay_state.sload_current_or(
                        db,
                        action.address(),
                        key,
                        sload_value,
                    )?;
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
                    self.replay_state.sstore(action.address(), key, value)?;
                }
                StorageAction::FeeAmmLiquidityCheck(
                    key,
                    sload_value,
                    amount_out,
                    has_enough_liquidity,
                ) => {
                    let pool_slot = self.replay_state.sload_current_or(
                        db,
                        action.address(),
                        key,
                        sload_value,
                    )?;
                    let pool = Pool::decode_from_slot(pool_slot);
                    if pool.has_enough_reserve_validator_token(amount_out) != has_enough_liquidity {
                        return Err(StorageActionReplayError::ActionConflict.into());
                    }
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
                if !change.written && !commit_reads {
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
        let spec = self.inner.evm.ctx().cfg.spec;
        let max_expiry_secs = spec.expiring_nonce_max_expiry_secs();
        let block_number = self.inner.evm.block().number.saturating_to::<u64>();
        if expiring_nonce.valid_before <= block_timestamp
            || expiring_nonce.valid_before > block_timestamp.saturating_add(max_expiry_secs)
        {
            return Err(StorageActionReplayError::ActionConflict.into());
        }

        let db = self.inner.evm_mut().db_mut();

        let nonce_manager = ExpiringNonceManager::new();
        let now = U256::from(block_timestamp);
        let count = self
            .replay_state
            .expiring_nonce
            .bucket_count(db, block_number)?;

        let seen_slot = nonce_manager.seen[expiring_nonce.hash].slot();
        let seen_expiry = db
            .storage(EXPIRING_NONCE_PRECOMPILE_ADDRESS, seen_slot)
            .map_err(BlockExecutionError::other)?;
        if !seen_expiry.is_zero() && seen_expiry > now {
            return Err(StorageActionReplayError::ActionConflict.into());
        }

        let index: u64 = count
            .try_into()
            .map_err(|_| StorageActionReplayError::ActionConflict)?;
        let bucket_slot = nonce_manager.bucket[block_number][index].slot();
        let original = db
            .storage(EXPIRING_NONCE_PRECOMPILE_ADDRESS, bucket_slot)
            .map_err(BlockExecutionError::other)?;
        self.replay_state.record_sstore(
            EXPIRING_NONCE_PRECOMPILE_ADDRESS,
            bucket_slot,
            original,
            U256::from_be_slice(expiring_nonce.hash.as_slice()),
        );
        self.replay_state.record_sstore(
            EXPIRING_NONCE_PRECOMPILE_ADDRESS,
            seen_slot,
            seen_expiry,
            U256::from(expiring_nonce.valid_before),
        );

        let next = U256::from(
            index
                .checked_add(1)
                .ok_or(StorageActionReplayError::ActionConflict)?,
        );
        self.replay_state.record_sstore(
            EXPIRING_NONCE_PRECOMPILE_ADDRESS,
            nonce_manager.bucket_count[block_number].slot(),
            count,
            next,
        );
        let max_expiry_slot = nonce_manager.bucket_max_expiry[block_number].slot();
        let max_expiry = db
            .storage(EXPIRING_NONCE_PRECOMPILE_ADDRESS, max_expiry_slot)
            .map_err(BlockExecutionError::other)?;
        let expiry = U256::from(expiring_nonce.valid_before);
        if expiry > max_expiry {
            self.replay_state.record_sstore(
                EXPIRING_NONCE_PRECOMPILE_ADDRESS,
                max_expiry_slot,
                max_expiry,
                expiry,
            );
        }
        self.replay_state.expiring_nonce.set_next_bucket_count(next);

        Ok(())
    }

    /// Invalidates the expiring nonce cache after execution that did not go through action replay.
    pub fn invalidate_expiring_nonce_cache(&mut self) {
        self.replay_state.invalidate_expiring_nonce_cache();
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
    pub result: ExecutionResult<HaltReason>,
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

    /// Stores the value of a slot that has already been loaded for this transaction.
    fn sstore(
        &mut self,
        address: Address,
        slot: U256,
        value: U256,
    ) -> Result<(), BlockExecutionError> {
        // This helper only updates an already loaded tx-local slot value. First-touch
        // absolute stores must go through `sstore_exact` with the action's recorded
        // pre-store value; otherwise replay would invent `original` and reuse
        // gas/refund data from a different storage transition.
        let change = self
            .tx_changes
            .get_mut(&address)
            .and_then(|slots| slots.get_mut(&slot))
            .ok_or(StorageActionReplayError::ActionConflict)?;
        change.current = value;
        change.written = true;

        Ok(())
    }

    /// Stores the value of a slot after establishing its exact replay view.
    ///
    /// Uses [`Self::sload_exact`] to validate the recorded pre-store value against
    /// the tx-local/cache view when available, then records the store.
    fn sstore_exact<DB: Database>(
        &mut self,
        db: &mut State<DB>,
        address: Address,
        slot: U256,
        expected: U256,
        value: U256,
    ) -> Result<(), BlockExecutionError> {
        // TODO: we can save on `self.tx_changes` lookup here
        // by returning an entry from `self.sload_exact`
        self.sload_exact(db, address, slot, expected)?;
        self.sstore(address, slot, value)
    }

    /// Records a storage slot write with a known transaction-start value.
    fn record_sstore(&mut self, address: Address, slot: U256, original: U256, current: U256) {
        self.tx_changes
            .entry(address)
            .or_default()
            .entry(slot)
            .and_modify(|change| {
                change.current = current;
                change.written = true;
            })
            .or_insert(SlotChange {
                original,
                current,
                written: true,
            });
    }

    fn cached_storage_value<DB: Database>(
        db: &State<DB>,
        address: Address,
        slot: U256,
    ) -> Option<U256> {
        db.cache.accounts.get(&address).and_then(|cached_account| {
            let Some(account) = cached_account.account.as_ref() else {
                // Account is in cache and known to not exist, so all its storage is zero.
                return Some(U256::ZERO);
            };

            if let Some(slot) = account.storage.get(&slot).copied() {
                // Account and slot are in cache.
                Some(slot)
            } else {
                // Account is in cache, but the slot is not. If the storage is reported to be fully known,
                // it means the slot doesn't exist, and its value is zero.
                cached_account
                    .status
                    .is_storage_known()
                    .then_some(U256::ZERO)
            }
        })
    }

    /// Returns the current slot value for exact replay.
    ///
    /// If the tx has already touched the slot, validates that the current value matches `expected`.
    /// On first touch, uses the EVM state cache when available and requires it to match `expected`.
    /// When the slot is not cached, records `expected` as the current value.
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
                let current = Self::cached_storage_value(db, address, slot)
                    // If the slot was not found in cache, it means it's the first access,
                    // and we can just use the expected value.
                    .unwrap_or(expected);
                if current != expected {
                    return Err(StorageActionReplayError::ActionConflict.into());
                }

                change.insert(SlotChange {
                    original: current,
                    current,
                    written: false,
                });
                Ok(current)
            }
        }
    }

    /// Returns the current slot value for semantic replay.
    ///
    /// Falls back to `fallback` when the current value is not already known.
    fn sload_current_or<DB: Database>(
        &mut self,
        db: &mut State<DB>,
        address: Address,
        slot: U256,
        fallback: U256,
    ) -> Result<U256, BlockExecutionError> {
        match self.tx_changes.entry(address).or_default().entry(slot) {
            Entry::Occupied(change) => Ok(change.get().current),
            Entry::Vacant(change) => {
                let current = Self::cached_storage_value(db, address, slot).unwrap_or(fallback);
                change.insert(SlotChange {
                    original: current,
                    current,
                    written: false,
                });
                Ok(current)
            }
        }
    }

    /// Resets the accumulated transaction changes.
    fn reset_tx_changes(&mut self) {
        self.tx_changes.clear();
        self.expiring_nonce.reset_pending_bucket_count();
    }

    /// Commits the accumulated transaction changes to the state.
    pub(crate) fn commit_tx_changes(&mut self) {
        self.tx_changes.clear();
        self.expiring_nonce.commit_pending_bucket_count();
    }
}

#[derive(Debug)]
struct SlotChange {
    original: U256,
    current: U256,
    written: bool,
}

#[derive(Debug, Default)]
struct ExpiringNonceReplayState {
    /// Current cached bucket count.
    bucket_count: Option<U256>,
    /// Pending bucket count to be committed by current transaction.
    pending_bucket_count: Option<U256>,
}

impl ExpiringNonceReplayState {
    fn invalidate_cache(&mut self) {
        self.bucket_count = None;
        self.reset_pending_bucket_count();
    }

    fn reset_pending_bucket_count(&mut self) {
        self.pending_bucket_count = None;
    }

    fn commit_pending_bucket_count(&mut self) {
        if let Some(count) = self.pending_bucket_count.take() {
            self.bucket_count = Some(count);
        }
    }

    fn bucket_count<DB: Database>(
        &mut self,
        db: &mut State<DB>,
        block_number: u64,
    ) -> Result<U256, BlockExecutionError> {
        Ok(match self.bucket_count {
            Some(count) => count,
            None => {
                let count = db
                    .storage(
                        EXPIRING_NONCE_PRECOMPILE_ADDRESS,
                        ExpiringNonceManager::new().bucket_count[block_number].slot(),
                    )
                    .map_err(BlockExecutionError::other)?;
                self.bucket_count = Some(count);
                count
            }
        })
    }

    fn set_next_bucket_count(&mut self, next: U256) {
        self.pending_bucket_count = Some(next);
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
    fn expiring_nonce_replay_appends_and_rejects_duplicates() {
        use crate::test_utils::{TestExecutorBuilder, test_chainspec};
        use revm::DatabaseCommit;
        let chainspec = test_chainspec();
        let mut db = State::builder().with_bundle_update().build();
        let mut executor = TestExecutorBuilder::default()
            .with_parent_beacon_block_root(B256::ZERO)
            .build(&mut db, &chainspec);
        executor.evm_mut().ctx_mut().block.timestamp = U256::from(1000);
        executor.apply_pre_execution_changes().unwrap();
        let manager = ExpiringNonceManager::new();
        for (i, expiry) in [1020, 1030, 1010].into_iter().enumerate() {
            let i = i as u64;
            let hash = B256::repeat_byte(i as u8 + 1);
            executor.replay_state.reset_tx_changes();
            let state = executor
                .replay_actions(
                    Address::ZERO,
                    [],
                    false,
                    Some(ExpiringNonceReplay {
                        hash,
                        valid_before: expiry,
                    }),
                )
                .unwrap();
            let account = &state[&EXPIRING_NONCE_PRECOMPILE_ADDRESS];
            assert_eq!(
                account.storage[&manager.bucket[1][i].slot()].present_value,
                U256::from_be_bytes(hash.0)
            );
            assert_eq!(
                account.storage[&manager.bucket_count[1].slot()].present_value,
                U256::from(i + 1)
            );
            executor.evm_mut().db_mut().commit(state);
            executor.replay_state.commit_tx_changes();
            assert_eq!(
                executor
                    .evm_mut()
                    .db_mut()
                    .storage(
                        EXPIRING_NONCE_PRECOMPILE_ADDRESS,
                        manager.bucket_max_expiry[1].slot(),
                    )
                    .unwrap(),
                U256::from(if i == 0 { 1020 } else { 1030 })
            );
        }
        executor.replay_state.reset_tx_changes();
        assert!(
            executor
                .replay_actions(
                    Address::ZERO,
                    [],
                    false,
                    Some(ExpiringNonceReplay {
                        hash: B256::repeat_byte(1),
                        valid_before: 1020
                    })
                )
                .is_err()
        );
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
        assert!(!change.written);
    }

    #[test]
    fn current_sload_uses_recorded_value_when_slot_is_not_cached() {
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
                .sload_current_or(&mut db, address, slot, U256::from(10))
                .expect("uncached semantic sload should use recorded value"),
            U256::from(10),
        );
        let change = replay_state
            .tx_changes
            .get(&address)
            .and_then(|slots| slots.get(&slot))
            .expect("slot change recorded");
        assert_eq!(change.original, U256::from(10));
        assert_eq!(change.current, U256::from(10));
        assert!(!change.written);
    }

    #[test]
    fn recorded_sload_rejects_changed_transaction_view() {
        let address = Address::repeat_byte(0x42);
        let slot = U256::from(7);
        let mut db = state_with_storage(address, slot, U256::from(10));
        let mut replay_state = StorageActionReplayState::default();

        assert_eq!(
            replay_state
                .sload_exact(&mut db, address, slot, U256::from(10))
                .expect("load exact storage"),
            U256::from(10),
        );
        replay_state
            .sstore(address, slot, U256::from(11))
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

        let err = replay_state
            .sload_exact(&mut db, address, slot, U256::from(10))
            .unwrap_err();
        assert_eq!(
            StorageActionReplayError::from_block_execution_error(&err),
            Some(StorageActionReplayError::ActionConflict)
        );
    }

    #[test]
    fn first_touch_sstore_uses_recorded_prewrite_value() {
        let address = Address::repeat_byte(0x42);
        let slot = U256::from(7);
        let mut db = state_with_storage(address, slot, U256::from(10));
        let mut replay_state = StorageActionReplayState::default();

        replay_state
            .sstore_exact(&mut db, address, slot, U256::from(10), U256::from(11))
            .expect("first-touch store should establish the slot view");

        let change = replay_state
            .tx_changes
            .get(&address)
            .and_then(|slots| slots.get(&slot))
            .expect("slot change recorded");
        assert_eq!(change.original, U256::from(10));
        assert_eq!(change.current, U256::from(11));
        assert!(change.written);
    }

    #[test]
    fn sstore_requires_prior_load() {
        let address = Address::repeat_byte(0x42);
        let slot = U256::from(7);
        let mut replay_state = StorageActionReplayState::default();

        let err = replay_state
            .sstore(address, slot, U256::from(11))
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
            .sload_current_or(&mut db, address, slot, U256::from(10))
            .expect("load current storage");
        replay_state
            .sstore(address, slot, current + U256::from(3))
            .expect("store loaded slot");

        let change = replay_state
            .tx_changes
            .get(&address)
            .and_then(|slots| slots.get(&slot))
            .expect("slot change recorded");
        assert_eq!(change.original, U256::from(11));
        assert_eq!(change.current, U256::from(14));
        assert!(change.written);
    }
}
