use std::collections::hash_map::Entry;

use crate::{TempoBlockExecutor, TempoTxResult};
use alloy_evm::{
    Database, Evm, RecoveredTx,
    block::{BlockExecutionError, BlockExecutor, ExecutableTx},
};
use alloy_primitives::{Address, U256, map::AddressMap};
use reth_evm::block::StateDB;
use reth_revm::{
    Database as _, Inspector, State,
    context::{Transaction as _, result::ExecutionResult},
    state::{Account, AccountInfo, EvmState, EvmStorageSlot, TransactionId},
};
use tempo_precompiles::storage::StorageAction;
use tempo_revm::{TempoHaltReason, evm::TempoContext};

/// Precomputed transaction result plus semantic precompile storage actions.
#[derive(Debug)]
pub struct StorageActionReplay {
    pub result: ExecutionResult<TempoHaltReason>,
    pub actions: Vec<StorageAction>,
    pub validator_fee: U256,
    pub state: EvmState,
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

impl StorageActionReplayFallback {
    /// Returns the stable metric label for this fallback reason.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActionExecutionFailed => "action_execution_failed",
            Self::MissingActions => "missing_actions",
            Self::ActionConflict => "action_conflict",
            Self::BalanceOverflow => "balance_overflow",
            Self::InsufficientBalance => "insufficient_balance",
        }
    }
}

/// Error returned by the storage-action replay execution API.
#[derive(Debug)]
pub enum StorageActionReplayExecutionError {
    /// The precomputed replay cannot be used; no state was committed.
    Fallback(StorageActionReplayFallback),
    /// Synthetic validation rejected a transaction.
    Execution {
        /// Index of the failed transaction in the streaming sequence.
        transaction_index: usize,
        /// Execution error returned by synthetic result construction or block validation.
        error: BlockExecutionError,
    },
    /// Preflight failed while reading state; no state was committed.
    Database(BlockExecutionError),
}

#[derive(Debug, Default)]
pub struct StorageActionReplayState {
    writes: AddressMap<alloy_primitives::map::U256Map<WriteKind>>,
    tx_changes: AddressMap<alloy_primitives::map::U256Map<SlotChange>>,
}

impl StorageActionReplayState {
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
    }

    fn commit_tx_changes(&mut self) {
        for (address, slots) in self.tx_changes.drain() {
            for (slot, change) in slots {
                if let Some(kind) = change.write_kind {
                    merge_committed_write_kind(&mut self.writes, address, slot, kind);
                }
            }
        }
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

struct AppliedActionReplay {
    state: EvmState,
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
    ) -> Result<(), StorageActionReplayExecutionError> {
        let (tx_env, recovered) = tx.into_parts();

        let StorageActionReplay {
            result,
            actions,
            validator_fee,
            state,
        } = replay;
        replay_state.reset_tx_changes();

        if !result.is_success() {
            return Err(StorageActionReplayExecutionError::Fallback(
                StorageActionReplayFallback::ActionExecutionFailed,
            ));
        }

        let cfg = self.inner.evm.cfg_env().clone();
        let gas = result.gas();
        let block_gas_used = if cfg.enable_amsterdam_eip8037 {
            gas.block_regular_gas_used()
        } else {
            gas.tx_gas_used()
        };
        let next_section = self
            .validate_tx(recovered.tx(), block_gas_used)
            .map_err(|error| StorageActionReplayExecutionError::Execution {
                transaction_index,
                error: error.into(),
            })?;
        let applied = match action_replay_state(
            tx_env.caller(),
            self.inner.evm.db_mut(),
            &actions,
            replay_state,
            state,
            commit_reads,
        ) {
            Ok(applied) => applied,
            Err(error) => {
                replay_state.reset_tx_changes();
                return Err(error);
            }
        };
        let result = TempoTxResult::new_precomputed(
            recovered.tx(),
            result,
            applied.state,
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
    }
}

fn action_replay_state<DB: Database>(
    sender: Address,
    db: &mut State<DB>,
    actions: &[StorageAction],
    replay_state: &mut StorageActionReplayState,
    mut state: EvmState,
    commit_reads: bool,
) -> Result<AppliedActionReplay, StorageActionReplayExecutionError> {
    if actions.is_empty() {
        return Err(StorageActionReplayExecutionError::Fallback(
            StorageActionReplayFallback::MissingActions,
        ));
    }

    for action in actions {
        match *action {
            StorageAction::Sload(address, slot, value) => {
                if replay_state.has_store(address, slot) {
                    return Err(action_conflict());
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
                    return Err(action_conflict());
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
                    return Err(action_conflict());
                }

                let value =
                    action_current_value(db, &mut replay_state.tx_changes, address, slot, None)?
                        .checked_add(delta)
                        .ok_or_else(balance_overflow)?;
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
                    return Err(action_conflict());
                }

                let value =
                    action_current_value(db, &mut replay_state.tx_changes, address, slot, None)?
                        .checked_sub(delta)
                        .ok_or_else(insufficient_balance)?;
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

    Ok(AppliedActionReplay { state })
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

    let value = db
        .storage(address, slot)
        .map_err(BlockExecutionError::other)
        .map_err(StorageActionReplayExecutionError::Database)?;

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

fn action_conflict() -> StorageActionReplayExecutionError {
    StorageActionReplayExecutionError::Fallback(StorageActionReplayFallback::ActionConflict)
}

fn balance_overflow() -> StorageActionReplayExecutionError {
    StorageActionReplayExecutionError::Fallback(StorageActionReplayFallback::BalanceOverflow)
}

fn insufficient_balance() -> StorageActionReplayExecutionError {
    StorageActionReplayExecutionError::Fallback(StorageActionReplayFallback::InsufficientBalance)
}
