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
    nonce::NonceManager,
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
    /// If speculative actions conflict with canonical state, executes the transaction normally.
    /// `result_closure` observes exactly one execution result before it is committed.
    /// Returns `true` if replay was committed, or `false` if canonical execution was used.
    pub fn execute_transaction_with_actions(
        &mut self,
        tx: impl ExecutableTx<Self>,
        replay: StorageActionReplay,
        result_closure: impl FnOnce(&TempoTxResult),
        commit_reads: bool,
    ) -> Result<bool, BlockExecutionError> {
        let (tx_env, recovered) = tx.into_parts();

        let StorageActionReplay {
            result,
            mut actions,
            expiring_nonce,
            validator_fee,
        } = replay;
        self.replay_state.reset_tx_changes();

        // A speculative failure can become valid after earlier transactions execute.
        let replayed_state = if result.is_success() {
            self.replay_actions(
                tx_env.caller(),
                actions.drain(..),
                commit_reads,
                expiring_nonce,
            )
        } else {
            Err(StorageActionReplayError::TransactionExecutionFailed.into())
        };
        let state = match replayed_state {
            Ok(state) => state,
            Err(error) => {
                // Replay has not committed state or invoked the callback. Discard tentative
                // writes and the pending nonce pointer before considering canonical execution.
                self.replay_state.reset_tx_changes();
                let Some(reason) = StorageActionReplayError::from_block_execution_error(&error)
                else {
                    return Err(error);
                };
                tracing::trace!(?reason, "falling back to canonical transaction execution");
                self.invalidate_expiring_nonce_cache();
                return self
                    .execute_transaction_with_result_closure((tx_env, recovered), result_closure)
                    .map(|_| false);
            }
        };

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

        Ok(true)
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
        let capacity = spec.expiring_nonce_set_capacity();
        if expiring_nonce.valid_before <= block_timestamp
            || expiring_nonce.valid_before > block_timestamp.saturating_add(max_expiry_secs)
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
            );
        }

        self.replay_state.record_sstore(
            NONCE_PRECOMPILE_ADDRESS,
            ring_slot,
            old_hash,
            U256::from_be_slice(expiring_nonce.hash.as_slice()),
        );
        self.replay_state.record_sstore(
            NONCE_PRECOMPILE_ADDRESS,
            seen_slot,
            seen_expiry,
            U256::from(expiring_nonce.valid_before),
        );

        let next = ptr
            .checked_add(U256::ONE)
            .filter(|next| *next < capacity)
            .unwrap_or(U256::ZERO);
        self.replay_state.record_sstore(
            NONCE_PRECOMPILE_ADDRESS,
            nonce_manager.expiring_nonce_ring_ptr.slot(),
            ptr,
            next,
        );
        self.replay_state.expiring_nonce.set_next_ring_ptr(next);

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
        self.expiring_nonce.reset_pending_ring_ptr();
    }

    /// Commits the accumulated transaction changes to the state.
    pub(crate) fn commit_tx_changes(&mut self) {
        self.tx_changes.clear();
        self.expiring_nonce.commit_pending_ring_ptr();
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
    fn conflicting_mint_replay_falls_back_to_serial_without_double_accounting() {
        use alloy_consensus::transaction::Recovered;
        use alloy_primitives::{Signature, TxKind};
        use alloy_sol_types::SolCall;
        use reth_revm::DatabaseCommit;
        use tempo_chainspec::{hardfork::TempoHardfork, spec::DEV};
        use tempo_precompiles::{
            PATH_USD_ADDRESS,
            storage::{StorageActions, StorageCtx},
            test_util::TIP20Setup,
            tip20::ITIP20,
        };
        use tempo_primitives::{
            TempoTxEnvelope,
            transaction::{AASigned, Call, PrimitiveSignature, TempoSignature, TempoTransaction},
        };
        let chainspec = DEV.clone();
        let sender = Address::repeat_byte(0x01);
        let mut cfg = revm::context::CfgEnv::default();
        cfg.spec = TempoHardfork::T12;
        let mut evm = crate::TempoEvm::new(
            CacheDB::new(EmptyDB::default()),
            alloy_evm::EvmEnv {
                cfg_env: cfg,
                block_env: tempo_revm::TempoBlockEnv {
                    inner: revm::context::BlockEnv {
                        basefee: 1,
                        gas_limit: 30_000_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            },
        );
        for (address, _) in tempo_contracts::precompiles::SYSTEM_PRECOMPILES {
            evm.db_mut().insert_account_info(
                *address,
                AccountInfo::default().with_code(revm::state::Bytecode::new_raw(
                    alloy_primitives::Bytes::from_static(&[0xef]),
                )),
            );
        }
        StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
            TIP20Setup::path_usd(sender)
                .with_issuer(sender)
                .with_mint(sender, U256::from(1_000_000_000_000_000u64))
                .apply()
        })
        .unwrap();
        let setup = evm.ctx_mut().journaled_state.finalize();
        evm.db_mut().commit(setup);
        let backing = evm.db_mut().clone();
        let env = evm.evm_env();
        let transactions = (2..=3)
            .map(|recipient| {
                let transaction = AASigned::new_unhashed(
                    TempoTransaction {
                        chain_id: evm.ctx().cfg.chain_id,
                        fee_token: Some(PATH_USD_ADDRESS),
                        max_fee_per_gas: 1_000_000_000,
                        max_priority_fee_per_gas: 1,
                        gas_limit: 1_000_000,
                        calls: vec![Call {
                            to: TxKind::Call(PATH_USD_ADDRESS),
                            value: U256::ZERO,
                            input: ITIP20::mintCall {
                                to: Address::repeat_byte(recipient),
                                amount: U256::from(1000),
                            }
                            .abi_encode()
                            .into(),
                        }],
                        nonce_key: U256::MAX,
                        valid_before: Some(20.try_into().unwrap()),
                        ..Default::default()
                    },
                    TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                        Signature::test_signature(),
                    )),
                );
                let nonce_hash = transaction.expiring_nonce_hash(sender);
                let recovered = Recovered::new_unchecked(TempoTxEnvelope::AA(transaction), sender);
                let mut tx_env: crate::TempoTxEnv =
                    alloy_evm::IntoTxEnv::into_tx_env(recovered.clone());
                tx_env.tempo_tx_env.as_mut().unwrap().expiring_nonce_idx = Some(0);
                let mut prewarmer =
                    crate::TempoEvm::new(backing.clone(), env.clone()).with_actions();
                let prewarmed = prewarmer.transact_raw(tx_env).unwrap();
                assert!(prewarmed.result.is_success());
                let replay = StorageActionReplay {
                    validator_fee: prewarmer.validator_fee(),
                    result: prewarmed.result,
                    actions: prewarmer.take_actions().unwrap(),
                    expiring_nonce: Some(ExpiringNonceReplay {
                        hash: nonce_hash,
                        valid_before: 20,
                    }),
                };
                (recovered, replay)
            })
            .collect::<Vec<_>>();
        let mut serial_db = State::builder().with_database(backing.clone()).build();
        let mut replay_db = State::builder().with_database(backing).build();
        let mut serial = crate::test_utils::TestExecutorBuilder::default()
            .with_spec(TempoHardfork::T12)
            .build(&mut serial_db, &chainspec);
        let mut replayed = crate::test_utils::TestExecutorBuilder::default()
            .with_spec(TempoHardfork::T12)
            .build(&mut replay_db, &chainspec);
        let snapshot = |result: &TempoTxResult| {
            use alloy_evm::block::TxResult as _;
            let writes = result
                .result()
                .state
                .iter()
                .flat_map(|(address, account)| {
                    account
                        .storage
                        .iter()
                        .filter(|(_, slot)| slot.is_changed())
                        .map(move |(key, slot)| ((*address, *key), slot.present_value))
                })
                .collect::<std::collections::BTreeMap<_, _>>();
            (writes, result.block_gas_used(), result.validator_fee())
        };
        let mut serial_results = Vec::new();
        let mut replay_results = Vec::new();
        for (index, (tx, replay)) in transactions.into_iter().enumerate() {
            serial
                .execute_transaction_with_result_closure(tx.clone(), |result| {
                    serial_results.push(snapshot(result));
                })
                .unwrap();
            if index == 1 {
                // Both mints were speculated against the same parent. The first mint changed
                // an exact-read slot, so the second trace cannot be applied as recorded.
                let error = replayed
                    .replay_actions(sender, replay.actions.clone(), false, replay.expiring_nonce)
                    .unwrap_err();
                assert_eq!(
                    StorageActionReplayError::from_block_execution_error(&error),
                    Some(StorageActionReplayError::ActionConflict)
                );
            }
            let duplicate_replay = (index == 1).then(|| StorageActionReplay {
                result: replay.result.clone(),
                actions: replay.actions.clone(),
                expiring_nonce: replay.expiring_nonce,
                validator_fee: replay.validator_fee,
            });
            let used_replay = replayed
                .execute_transaction_with_actions(
                    tx.clone(),
                    replay,
                    |result| {
                        replay_results.push(snapshot(result));
                    },
                    false,
                )
                .unwrap();
            assert_eq!(used_replay, index == 0);
            assert_eq!(replayed.receipts(), serial.receipts());
            assert_eq!(replay_results, serial_results);
            assert_eq!(replay_results.len(), index + 1);
            assert!(replayed.replay_state.tx_changes.is_empty());
            if let Some(replay) = duplicate_replay {
                let committed_before = replayed.evm_mut().db_mut().cache.clone();
                // A true invalid transaction still fails normal nonce validation. Neither
                // its speculative nonce writes nor an extra callback/receipt may survive.
                let error = replayed
                    .execute_transaction_with_actions(
                        tx,
                        replay,
                        |_| panic!("invalid transaction invoked result callback"),
                        false,
                    )
                    .unwrap_err();
                assert!(
                    matches!(error, BlockExecutionError::Validation(_)),
                    "{error:?}"
                );
                assert_eq!(replayed.receipts(), serial.receipts());
                assert_eq!(replayed.evm_mut().db_mut().cache, committed_before);
                assert!(replayed.replay_state.tx_changes.is_empty());
                assert!(
                    replayed
                        .replay_state
                        .expiring_nonce
                        .pending_ring_ptr
                        .is_none()
                );
            }
            let slot = NonceManager::new().expiring_nonce_ring_ptr.slot();
            let serial_ptr = serial
                .evm_mut()
                .db_mut()
                .storage(NONCE_PRECOMPILE_ADDRESS, slot)
                .unwrap();
            let replay_ptr = replayed
                .evm_mut()
                .db_mut()
                .storage(NONCE_PRECOMPILE_ADDRESS, slot)
                .unwrap();
            assert_eq!(replay_ptr, serial_ptr);
            assert_eq!(replay_ptr, U256::from(index + 1));
        }
        assert_eq!(serial_results.len(), 2);
    }

    #[test]
    fn replay_database_failure_is_not_retried_as_a_transaction() {
        use alloy_consensus::{Signed, TxLegacy, transaction::Recovered};
        use alloy_primitives::Signature;
        use revm::{database_interface::DBErrorMarker, state::Bytecode};
        use std::{cell::Cell, rc::Rc};
        use tempo_primitives::TempoTxEnvelope;

        #[derive(Debug, thiserror::Error)]
        #[error("replay database failure")]
        struct Failure;
        impl DBErrorMarker for Failure {}
        #[derive(Debug)]
        struct FailingDb(Rc<Cell<usize>>);
        impl revm::Database for FailingDb {
            type Error = Failure;
            fn basic(&mut self, _: Address) -> Result<Option<AccountInfo>, Self::Error> {
                self.0.set(self.0.get() + 1);
                Err(Failure)
            }
            fn code_by_hash(&mut self, _: B256) -> Result<Bytecode, Self::Error> {
                panic!("must not retry database errors")
            }
            fn storage(&mut self, _: Address, _: U256) -> Result<U256, Self::Error> {
                panic!("must not retry database errors")
            }
            fn block_hash(&mut self, _: u64) -> Result<B256, Self::Error> {
                panic!("must not retry database errors")
            }
        }
        let reads = Rc::new(Cell::new(0));
        let chainspec = tempo_chainspec::spec::DEV.clone();
        let mut db = State::builder()
            .with_database(FailingDb(reads.clone()))
            .build();
        let mut executor =
            crate::test_utils::TestExecutorBuilder::default().build(&mut db, &chainspec);
        let tx = Recovered::new_unchecked(
            TempoTxEnvelope::Legacy(Signed::new_unhashed(
                TxLegacy::default(),
                Signature::test_signature(),
            )),
            Address::ZERO,
        );
        let replay = StorageActionReplay {
            result: ExecutionResult::Success {
                reason: revm::context::result::SuccessReason::Return,
                gas: revm::context::result::ResultGas::default(),
                logs: vec![],
                output: revm::context::result::Output::Call(Default::default()),
            },
            actions: vec![StorageAction::Sstore(
                Address::repeat_byte(1),
                U256::ZERO,
                U256::ZERO,
                U256::ONE,
            )],
            expiring_nonce: None,
            validator_fee: U256::ZERO,
        };
        let error = executor
            .execute_transaction_with_actions(
                tx,
                replay,
                |_| panic!("failed replay invoked callback"),
                false,
            )
            .unwrap_err();
        assert!(
            error.to_string().contains("replay database failure"),
            "{error:?}"
        );
        assert_eq!(
            StorageActionReplayError::from_block_execution_error(&error),
            None
        );
        assert_eq!(reads.get(), 1);
        assert!(executor.receipts().is_empty());
        assert!(executor.replay_state.tx_changes.is_empty());
        assert!(executor.evm_mut().db_mut().cache.accounts.is_empty());
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
