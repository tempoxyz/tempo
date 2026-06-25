use std::collections::hash_map::Entry;

use crate::{TempoBlockExecutor, TempoTxResult};
use alloy_evm::{
    Database, Evm, RecoveredTx,
    block::{BlockExecutionError, BlockExecutor, ExecutableTx},
};
use alloy_primitives::{Address, B256, U256, map::AddressMap};
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
};
use tempo_revm::{TempoHaltReason, evm::TempoContext};

/// Precomputed transaction result plus semantic precompile storage actions.
#[derive(Debug)]
pub struct StorageActionReplay {
    pub result: ExecutionResult<TempoHaltReason>,
    pub actions: Vec<StorageAction>,
    pub validator_fee: U256,
    pub state: EvmState,
    pub expiring_nonce: Option<ExpiringNonceReplay>,
}

/// Semantic replay data for expiring nonce transactions.
#[derive(Debug, Clone, Copy)]
pub struct ExpiringNonceReplay {
    pub hash: B256,
    pub valid_before: u64,
}

/// Result of executing a storage-action replay, including the reusable action buffer.
#[derive(Debug)]
pub struct StorageActionReplayExecutionOutcome {
    pub actions: Vec<StorageAction>,
    pub result: Result<(), StorageActionReplayExecutionError>,
}

/// Reason a precomputed storage-action replay cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageActionReplayFallback {
    ActionExecutionFailed,
    MissingActions,
    ActionConflict,
    BalanceOverflow,
    InsufficientBalance,
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

#[derive(Debug, Default)]
pub struct StorageActionReplayState {
    writes: AddressMap<alloy_primitives::map::U256Map<WriteKind>>,
    tx_changes: AddressMap<alloy_primitives::map::U256Map<SlotChange>>,
    expiring_nonce: ExpiringNonceReplayState,
}

impl StorageActionReplayState {
    /// Clears cached expiring-nonce state after execution that did not go through action replay.
    pub fn invalidate_expiring_nonce_cache(&mut self) {
        self.expiring_nonce.invalidate_cache();
    }

    fn has_write(&self, address: Address, slot: U256) -> bool {
        self.writes
            .get(&address)
            .is_some_and(|slots| slots.contains_key(&slot))
    }

    fn has_store(&self, address: Address, slot: U256) -> bool {
        self.writes
            .get(&address)
            .and_then(|slots| slots.get(&slot))
            .is_some_and(|kind| *kind == WriteKind::Store)
    }

    fn reset_tx_changes(&mut self) {
        self.tx_changes.clear();
        self.expiring_nonce.reset_tx_changes();
    }

    fn commit_tx_changes(&mut self) {
        for (address, slots) in self.tx_changes.drain() {
            for (slot, change) in slots {
                if let Some(kind) = change.write_kind {
                    merge_committed_write_kind(&mut self.writes, address, slot, kind);
                }
            }
        }
        self.expiring_nonce.commit_tx_changes(&mut self.writes);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteKind {
    Store,
    Delta,
}

#[derive(Debug)]
struct SlotChange {
    original: U256,
    current: U256,
    write_kind: Option<WriteKind>,
}

#[derive(Debug, Default)]
struct ExpiringNonceReplayState {
    ring_ptr: Option<U256>,
    pending_ring_ptr: Option<U256>,
    tx_changes: Vec<(U256, SlotChange)>,
}

impl ExpiringNonceReplayState {
    fn invalidate_cache(&mut self) {
        self.ring_ptr = None;
        self.reset_tx_changes();
    }

    fn reset_tx_changes(&mut self) {
        self.pending_ring_ptr = None;
        self.tx_changes.clear();
    }

    fn commit_tx_changes(
        &mut self,
        writes: &mut AddressMap<alloy_primitives::map::U256Map<WriteKind>>,
    ) {
        for (slot, change) in self.tx_changes.drain(..) {
            if let Some(kind) = change.write_kind {
                merge_committed_write_kind(writes, NONCE_PRECOMPILE_ADDRESS, slot, kind);
            }
        }
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

    fn store(&mut self, slot: U256, original: U256, current: U256) {
        self.tx_changes.push((
            slot,
            SlotChange {
                original,
                current,
                write_kind: Some(WriteKind::Store),
            },
        ));
    }

    fn set_next_ring_ptr(&mut self, next: U256) {
        self.pending_ring_ptr = Some(next);
    }
}

impl<'a, DB, I> TempoBlockExecutor<'a, &'a mut State<DB>, I>
where
    DB: Database,
    I: Inspector<TempoContext<&'a mut State<DB>>>,
{
    /// Commits one precomputed transaction by replaying recorded precompile storage actions.
    ///
    /// `should_commit` observes the result before state mutation. Returning `false` leaves
    /// executor state unchanged, allowing the payload builder to stop at the exact block gas
    /// boundary.
    pub fn execute_storage_action_replay_tx(
        &mut self,
        tx: impl ExecutableTx<Self>,
        replay: StorageActionReplay,
        replay_state: &mut StorageActionReplayState,
        transaction_index: usize,
        should_commit: impl FnOnce(&TempoTxResult) -> bool,
        commit_reads: bool,
    ) -> StorageActionReplayExecutionOutcome {
        let (tx_env, recovered) = tx.into_parts();

        let StorageActionReplay {
            result: execution_result,
            actions,
            validator_fee,
            state,
            expiring_nonce,
        } = replay;
        replay_state.reset_tx_changes();

        let result = (|| {
            if !execution_result.is_success() {
                return Err(StorageActionReplayExecutionError::Fallback(
                    StorageActionReplayFallback::ActionExecutionFailed,
                ));
            }

            let cfg = self.inner.evm.cfg_env().clone();
            let gas = execution_result.gas();
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
            let block_timestamp = self.inner.evm.block().timestamp.to::<u64>();
            let state = match action_replay_state(
                tx_env.caller(),
                self.inner.evm.db_mut(),
                &actions,
                replay_state,
                state,
                commit_reads,
                expiring_nonce,
                block_timestamp,
            ) {
                Ok(applied) => applied,
                Err(error) => {
                    replay_state.reset_tx_changes();
                    return Err(error);
                }
            };
            let result = TempoTxResult::new_precomputed(
                recovered.tx(),
                execution_result,
                state,
                next_section,
                self.is_payment(recovered.tx()),
                block_gas_used,
                validator_fee,
            );
            if !should_commit(&result) {
                replay_state.reset_tx_changes();
                return Ok(());
            }

            self.commit_transaction(result);
            replay_state.commit_tx_changes();
            Ok(())
        })();

        StorageActionReplayExecutionOutcome { actions, result }
    }
}

fn action_replay_state<DB: Database>(
    sender: Address,
    db: &mut State<DB>,
    actions: &[StorageAction],
    replay_state: &mut StorageActionReplayState,
    mut state: EvmState,
    commit_reads: bool,
    expiring_nonce: Option<ExpiringNonceReplay>,
    block_timestamp: u64,
) -> Result<EvmState, StorageActionReplayExecutionError> {
    if actions.is_empty() && expiring_nonce.is_none() {
        return Err(StorageActionReplayExecutionError::Fallback(
            StorageActionReplayFallback::MissingActions,
        ));
    }

    if let Some(expiring_nonce) = expiring_nonce {
        apply_expiring_nonce_replay(
            db,
            &mut replay_state.expiring_nonce,
            expiring_nonce,
            block_timestamp,
        )?;
    }

    for action in actions {
        if expiring_nonce.is_some() && is_nonce_manager_action(action) {
            continue;
        }

        match *action {
            StorageAction::Sload(address, slot, value) => {
                if replay_state.has_store(address, slot) {
                    return Err(StorageActionReplayFallback::ActionConflict.into());
                }
                let _ = action_current_value(
                    db,
                    &mut replay_state.tx_changes,
                    address,
                    slot,
                    Some(value),
                )?;
            }
            StorageAction::Sstore(address, slot, value) => {
                if replay_state.has_write(address, slot) {
                    return Err(StorageActionReplayFallback::ActionConflict.into());
                }
                action_write_value(
                    db,
                    &mut replay_state.tx_changes,
                    address,
                    slot,
                    value,
                    WriteKind::Store,
                )?;
            }
            StorageAction::Sinc(address, slot, delta) => {
                if replay_state.has_store(address, slot) {
                    return Err(StorageActionReplayFallback::ActionConflict.into());
                }

                let value =
                    action_current_value(db, &mut replay_state.tx_changes, address, slot, None)?
                        .checked_add(delta)
                        .ok_or(StorageActionReplayFallback::BalanceOverflow)?;
                action_write_value(
                    db,
                    &mut replay_state.tx_changes,
                    address,
                    slot,
                    value,
                    WriteKind::Delta,
                )?;
            }
            StorageAction::Sdec(address, slot, delta) => {
                if replay_state.has_store(address, slot) {
                    return Err(StorageActionReplayFallback::ActionConflict.into());
                }

                let value =
                    action_current_value(db, &mut replay_state.tx_changes, address, slot, None)?
                        .checked_sub(delta)
                        .ok_or(StorageActionReplayFallback::InsufficientBalance)?;
                action_write_value(
                    db,
                    &mut replay_state.tx_changes,
                    address,
                    slot,
                    value,
                    WriteKind::Delta,
                )?;
            }
        }
    }

    apply_expiring_nonce_state_changes(db, &mut state, &replay_state.expiring_nonce.tx_changes)?;

    if commit_reads {
        let account = action_account_info(db, sender)?;
        let mut account = Account::from(account);
        account.mark_touch();
        state.insert(sender, account);

        for (address, slots) in replay_state.tx_changes.iter() {
            for (slot, change) in slots {
                if change.write_kind.is_none() {
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
        }
    }

    for (address, slots) in replay_state.tx_changes.iter() {
        for (slot, change) in slots {
            if change.write_kind.is_none() {
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
                EvmStorageSlot::new_changed(change.original, change.current, TransactionId::ZERO),
            );
        }
    }

    Ok(state)
}

fn apply_expiring_nonce_replay<DB: Database>(
    db: &mut State<DB>,
    replay_state: &mut ExpiringNonceReplayState,
    expiring_nonce: ExpiringNonceReplay,
    block_timestamp: u64,
) -> Result<(), StorageActionReplayExecutionError> {
    if expiring_nonce.valid_before <= block_timestamp
        || expiring_nonce.valid_before
            > block_timestamp.saturating_add(EXPIRING_NONCE_MAX_EXPIRY_SECS)
    {
        return Err(StorageActionReplayFallback::ActionConflict.into());
    }

    let nonce_manager = NonceManager::new();
    let now = U256::from(block_timestamp);
    let ptr = replay_state.ring_ptr(db)?;

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
        replay_state.store(old_seen_slot, old_expiry, U256::ZERO);
    }

    replay_state.store(
        ring_slot,
        old_hash,
        U256::from_be_slice(expiring_nonce.hash.as_slice()),
    );
    replay_state.store(
        seen_slot,
        seen_expiry,
        U256::from(expiring_nonce.valid_before),
    );

    let next = ptr
        .checked_add(U256::ONE)
        .filter(|next| *next < EXPIRING_NONCE_SET_CAPACITY)
        .unwrap_or(U256::ZERO);
    replay_state.store(nonce_manager.expiring_nonce_ring_ptr.slot(), ptr, next);
    replay_state.set_next_ring_ptr(next);

    Ok(())
}

fn apply_expiring_nonce_state_changes<DB: Database>(
    db: &mut State<DB>,
    state: &mut EvmState,
    changes: &[(U256, SlotChange)],
) -> Result<(), StorageActionReplayExecutionError> {
    if changes.is_empty() {
        return Ok(());
    }

    if let Entry::Vacant(e) = state.entry(NONCE_PRECOMPILE_ADDRESS) {
        let mut account = Account::from(action_account_info(db, NONCE_PRECOMPILE_ADDRESS)?);
        account.mark_touch();
        e.insert(account);
    }
    let account = state
        .get_mut(&NONCE_PRECOMPILE_ADDRESS)
        .expect("nonce precompile account inserted");
    for (slot, change) in changes {
        account.storage.insert(
            *slot,
            EvmStorageSlot::new_changed(change.original, change.current, TransactionId::ZERO),
        );
    }

    Ok(())
}

fn is_nonce_manager_action(action: &StorageAction) -> bool {
    let address = match *action {
        StorageAction::Sload(address, ..)
        | StorageAction::Sstore(address, ..)
        | StorageAction::Sinc(address, ..)
        | StorageAction::Sdec(address, ..) => address,
    };
    address == NONCE_PRECOMPILE_ADDRESS
}

fn action_current_value<DB: Database>(
    db: &mut State<DB>,
    changes: &mut AddressMap<alloy_primitives::map::U256Map<SlotChange>>,
    address: Address,
    slot: U256,
    sload_value: Option<U256>,
) -> Result<U256, StorageActionReplayExecutionError> {
    if let Some(change) = changes.get(&address).and_then(|slots| slots.get(&slot)) {
        return Ok(change.current);
    }

    if let Some(original) = sload_value {
        let cached_value = db
            .cache
            .accounts
            .get(&address)
            .and_then(|account| account.account.as_ref())
            .and_then(|account| account.storage.get(&slot).copied());

        let value = cached_value.unwrap_or(original);
        changes.entry(address).or_default().insert(
            slot,
            SlotChange {
                original: value,
                current: value,
                write_kind: None,
            },
        );
        return Ok(value);
    }

    let value = state_storage(db, address, slot)?;

    changes.entry(address).or_default().insert(
        slot,
        SlotChange {
            original: value,
            current: value,
            write_kind: None,
        },
    );
    Ok(value)
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

fn action_write_value<DB: Database>(
    db: &mut State<DB>,
    changes: &mut AddressMap<alloy_primitives::map::U256Map<SlotChange>>,
    address: Address,
    slot: U256,
    value: U256,
    kind: WriteKind,
) -> Result<(), StorageActionReplayExecutionError> {
    let _ = action_current_value(db, changes, address, slot, None)?;
    let change = changes
        .get_mut(&address)
        .and_then(|slots| slots.get_mut(&slot))
        .expect("action replay slot change inserted");
    change.current = value;
    merge_write_kind(&mut change.write_kind, kind);
    Ok(())
}

fn merge_write_kind(existing: &mut Option<WriteKind>, kind: WriteKind) {
    if existing.is_none() || kind == WriteKind::Store {
        *existing = Some(kind);
    }
}

fn merge_committed_write_kind(
    writes: &mut AddressMap<alloy_primitives::map::U256Map<WriteKind>>,
    address: Address,
    slot: U256,
    kind: WriteKind,
) {
    writes
        .entry(address)
        .or_default()
        .entry(slot)
        .and_modify(|existing| {
            if kind == WriteKind::Store {
                *existing = WriteKind::Store;
            }
        })
        .or_insert(kind);
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
