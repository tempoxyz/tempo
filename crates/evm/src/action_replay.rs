use crate::{TempoBlockExecutor, TempoEvmTypes, TempoTxResult};
use alloy_primitives::{
    Address, B256, U256,
    map::{AddressMap, U256Map, hash_map::Entry},
};
use evm2::{
    TxResult,
    evm::{CacheDB, DynDatabase, PendingState},
};
use reth_evm::{
    BlockExecutionError, BlockExecutor, ExecutorTx, InternalBlockExecutionError, RecoveredTx,
};
use tempo_precompiles::{
    NONCE_PRECOMPILE_ADDRESS,
    nonce::NonceManager,
    storage::StorageAction,
    tip_fee_manager::amm::{Pool, compute_amount_out},
};

impl TempoBlockExecutor<'_> {
    /// Commits a precomputed transaction by replaying recorded storage actions.
    ///
    /// `result_closure` observes the synthesized result before the replayed state is committed.
    pub fn execute_transaction_with_actions(
        &mut self,
        transaction: impl ExecutorTx<Self>,
        replay: StorageActionReplay,
        result_closure: impl FnOnce(&TempoTxResult),
        commit_reads: bool,
    ) -> Result<(), BlockExecutionError> {
        let (tx, recovered) = transaction.into_parts();
        let original = recovered.tx();

        let StorageActionReplay {
            result,
            mut actions,
            expiring_nonce,
            validator_fee,
        } = replay;
        self.replay_state.reset_tx_changes();

        // TODO: handle reverted transactions
        if !result.status {
            return Err(StorageActionReplayError::TransactionExecutionFailed.into());
        }

        let state = self
            .replay_actions(
                tx.inner().evm_tx().signer(),
                actions.drain(..),
                commit_reads,
                expiring_nonce,
            )
            .inspect_err(|_| {
                self.replay_state.reset_tx_changes();
            })?;

        let cfg = self.evm().version();
        let gas = &result;
        let block_gas_used = if cfg.feature(evm2::EvmFeatures::EIP8037) {
            gas.execution_gas_spent()
        } else {
            gas.tx_gas_used()
        };
        let next_section = self
            .validate_tx(original, block_gas_used)
            .map_err(BlockExecutionError::from)?;

        let result = TempoTxResult::new_precomputed(
            original,
            result,
            state,
            next_section,
            self.is_payment(original),
            block_gas_used,
            validator_fee,
        );
        result_closure(&result);

        self.commit_transaction(result)?;

        Ok(())
    }

    fn replay_actions(
        &mut self,
        sender: Address,
        actions: impl IntoIterator<Item = StorageAction>,
        commit_reads: bool,
        expiring_nonce: Option<ExpiringNonceReplay>,
    ) -> Result<PendingState, BlockExecutionError> {
        let block_timestamp = self.evm().block().timestamp.to::<u64>();
        let is_expiring_nonce = expiring_nonce.is_some();

        if let Some(expiring_nonce) = expiring_nonce {
            self.apply_expiring_nonce_replay(expiring_nonce, block_timestamp)?;
        }

        let db = self.inner.evm_mut().overlay_db_mut();
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

        let mut state = PendingState::default();

        if commit_reads {
            let original = db
                .get_account(&sender)
                .map_err(|code| BlockExecutionError::other(db.error(code)))?;
            state.insert_account(sender, original.clone(), original);
        }

        for (address, slots) in self.replay_state.tx_changes.iter() {
            let mut inserted_account = false;
            for (slot, change) in slots {
                if !change.written && !commit_reads {
                    continue;
                }

                if !inserted_account {
                    let original = db
                        .get_account(address)
                        .map_err(|code| BlockExecutionError::other(db.error(code)))?;
                    state.insert_account(*address, original.clone(), original);
                    inserted_account = true;
                }
                state.insert_storage(*address, *slot, change.original, change.current);
            }
        }

        Ok(state)
    }

    fn apply_expiring_nonce_replay(
        &mut self,
        expiring_nonce: ExpiringNonceReplay,
        block_timestamp: u64,
    ) -> Result<(), BlockExecutionError> {
        let spec = self.inner.evm().config_spec_id();
        let max_expiry_secs = spec.expiring_nonce_max_expiry_secs();
        let capacity = spec.expiring_nonce_set_capacity();
        if expiring_nonce.valid_before <= block_timestamp
            || expiring_nonce.valid_before > block_timestamp.saturating_add(max_expiry_secs)
        {
            return Err(StorageActionReplayError::ActionConflict.into());
        }
        let db = self.inner.evm_mut().overlay_db_mut();

        let nonce_manager = NonceManager::new();
        let now = U256::from(block_timestamp);
        let ptr = self.replay_state.expiring_nonce.ring_ptr(db)?;

        let seen_slot = nonce_manager.expiring_nonce_seen[expiring_nonce.hash].slot();
        let seen_expiry = db
            .get_storage(&NONCE_PRECOMPILE_ADDRESS, &seen_slot)
            .map_err(|code| BlockExecutionError::other(db.error(code)))?;
        if !seen_expiry.is_zero() && seen_expiry > now {
            return Err(StorageActionReplayError::ActionConflict.into());
        }

        let ptr_u32 = ptr
            .try_into()
            .map_err(|_| StorageActionReplayError::ActionConflict)?;
        let ring_slot = nonce_manager.expiring_nonce_ring[ptr_u32].slot();
        let old_hash = db
            .get_storage(&NONCE_PRECOMPILE_ADDRESS, &ring_slot)
            .map_err(|code| BlockExecutionError::other(db.error(code)))?;
        if !old_hash.is_zero() {
            let old_seen_slot = nonce_manager.expiring_nonce_seen[B256::from(old_hash)].slot();
            let old_expiry = db
                .get_storage(&NONCE_PRECOMPILE_ADDRESS, &old_seen_slot)
                .map_err(|code| BlockExecutionError::other(db.error(code)))?;
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
    pub result: TxResult<TempoEvmTypes>,
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
    fn sstore_exact<DB>(
        &mut self,
        db: &CacheDB<DB>,
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

    fn cached_storage_value<DB>(db: &CacheDB<DB>, address: Address, slot: U256) -> Option<U256> {
        // Match CacheDB's read order: locally committed slots remain authoritative even when
        // the account is absent or has not been loaded. A wipe only zeroes uncached slots.
        if let Some(cached_storage) = db.cache.storage.get(&address) {
            if let Some(slot) = cached_storage.slots.get(&slot).copied() {
                return Some(slot);
            }
            if cached_storage.wiped {
                return Some(U256::ZERO);
            }
        }

        // Known account absence suppresses backing-storage reads, but only after checking writes.
        db.cache
            .accounts
            .get(&address)
            .is_some_and(Option::is_none)
            .then_some(U256::ZERO)
    }

    /// Returns the current slot value for exact replay.
    ///
    /// If the tx has already touched the slot, validates that the current value matches `expected`.
    /// On first touch, uses the EVM state cache when available and requires it to match `expected`.
    /// When the slot is not cached, records `expected` as the current value.
    fn sload_exact<DB>(
        &mut self,
        db: &CacheDB<DB>,
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
    fn sload_current_or<DB>(
        &mut self,
        db: &CacheDB<DB>,
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

    fn ring_ptr<DB: DynDatabase>(
        &mut self,
        db: &mut CacheDB<DB>,
    ) -> Result<U256, BlockExecutionError> {
        Ok(match self.ring_ptr {
            Some(ptr) => ptr,
            None => {
                let ptr = db
                    .get_storage(
                        &NONCE_PRECOMPILE_ADDRESS,
                        &NonceManager::new().expiring_nonce_ring_ptr.slot(),
                    )
                    .map_err(|code| BlockExecutionError::other(db.error(code)))?;
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
    use crate::{TempoBlockEnv, TempoEvm, TempoEvmExt, build_tempo_evm};
    use evm2::evm::{AccountInfo, InMemoryDB, precompile::NoPrecompiles};
    use tempo_chainspec::hardfork::TempoHardfork;

    fn empty_evm(database: InMemoryDB) -> TempoEvm<'static> {
        build_tempo_evm(
            TempoHardfork::T7,
            1,
            TempoBlockEnv::default(),
            database,
            NoPrecompiles::default(),
            TempoEvmExt::default(),
        )
    }

    fn state_with_storage(address: Address, slot: U256, value: U256) -> TempoEvm<'static> {
        let mut evm = empty_evm(InMemoryDB::default());
        evm.overlay_db_mut()
            .insert_account_info(&address, AccountInfo::default());
        evm.overlay_db_mut()
            .insert_account_storage(&address, &slot, &value);
        evm
    }

    #[test]
    fn expiring_nonce_mint_replay_matches_serial_state() {
        use alloy_consensus::transaction::Recovered;
        use alloy_primitives::{Signature, TxKind};
        use alloy_sol_types::SolCall;
        use evm2::evm::StateChangeSource;
        use reth_execution_types::HashedPostStateSink;
        use tempo_chainspec::spec::DEV;
        use tempo_precompiles::{
            PATH_USD_ADDRESS, storage::StorageCtx, test_util::TIP20Setup, tip20::ITIP20,
        };
        use tempo_primitives::{
            TempoTxEnvelope,
            transaction::{AASigned, Call, PrimitiveSignature, TempoSignature, TempoTransaction},
        };

        let chainspec = DEV.clone();
        let sender = Address::repeat_byte(0x01);
        let recipient = Address::repeat_byte(0x02);
        let mut executor = crate::test_utils::TestExecutorBuilder::default()
            .with_spec(TempoHardfork::T12)
            .build(InMemoryDB::default(), &chainspec);
        let evm = executor.evm_mut();
        let mut block = *evm.block();
        block.basefee = U256::from(1_000_000_000u64);
        evm.set_block(block);
        crate::TempoEvmFactory::default().enable_storage_actions(evm);
        let actions = evm.ext().actions.clone();
        // Match genesis marker accounts. In particular, nonce storage starts empty while
        // its account exists, as at the captured failing funding block's parent.
        for (address, _) in tempo_contracts::precompiles::SYSTEM_PRECOMPILES {
            evm.overlay_db_mut().insert_account_info(
                address,
                AccountInfo::default().with_code(evm2::bytecode::Bytecode::new_raw(
                    alloy_primitives::Bytes::from_static(&[0xef]),
                )),
            );
        }
        actions.unrecorded(|| {
            StorageCtx::enter_evm_without_tip1060_accounting(evm, || {
                TIP20Setup::path_usd(sender)
                    .with_issuer(sender)
                    .with_mint(sender, U256::from(1_000_000_000_000_000u64))
                    .apply()
            })
            .unwrap();
        });
        evm.state_mut().commit_transaction();
        evm.state_mut().clear_transaction_state();
        let mut backing = InMemoryDB::default();
        backing.cache = evm.overlay_db().cache.clone();

        let transaction = AASigned::new_unhashed(
            TempoTransaction {
                chain_id: evm.version().chain_id,
                fee_token: Some(PATH_USD_ADDRESS),
                max_fee_per_gas: 1_000_000_000,
                max_priority_fee_per_gas: 1,
                gas_limit: 1_000_000,
                calls: vec![Call {
                    to: TxKind::Call(PATH_USD_ADDRESS),
                    value: U256::ZERO,
                    input: ITIP20::mintCall {
                        to: recipient,
                        amount: U256::from(1000),
                    }
                    .abi_encode()
                    .into(),
                }],
                nonce_key: U256::MAX,
                valid_before: Some(20.try_into().unwrap()),
                ..Default::default()
            },
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature())),
        );
        let nonce_hash = transaction.expiring_nonce_hash(sender);
        let tx: crate::TempoTxEnv =
            Recovered::new_unchecked(TempoTxEnvelope::AA(transaction), sender).into();
        let mut prewarm_tx = tx.clone();
        prewarm_tx.set_expiring_nonce_idx(Some(0));
        let prewarm = evm
            .transact(&Recovered::new_unchecked(prewarm_tx, sender))
            .unwrap()
            .detach();
        assert!(prewarm.result.status);
        let recorded_actions = actions.take().unwrap();
        let mut serial_executor = crate::test_utils::TestExecutorBuilder::default()
            .with_spec(TempoHardfork::T12)
            .build(backing.clone(), &chainspec);
        assert!(serial_executor.evm().overlay_db().cache.accounts.is_empty());
        serial_executor.evm_mut().set_block(block);
        let serial = serial_executor
            .evm_mut()
            .transact(&Recovered::new_unchecked(tx, sender))
            .unwrap()
            .detach();
        assert!(serial.result.status);
        let mut serial_hash = HashedPostStateSink::<reth_trie::KeccakKeyHasher>::default();
        serial.pending_state.visit(&mut serial_hash).unwrap();
        let serial_hash = serial_hash.into_hashed_post_state();
        for warm_replay_cache in [false, true] {
            let mut replay_executor = crate::test_utils::TestExecutorBuilder::default()
                .with_spec(TempoHardfork::T12)
                .build(backing.clone(), &chainspec);
            assert!(replay_executor.evm().overlay_db().cache.accounts.is_empty());
            replay_executor.evm_mut().set_block(block);
            if warm_replay_cache {
                replay_executor.evm_mut().overlay_db_mut().cache = backing.cache.clone();
            }
            let replay = replay_executor
                .replay_actions(
                    sender,
                    recorded_actions.clone(),
                    false,
                    Some(ExpiringNonceReplay {
                        hash: nonce_hash,
                        valid_before: 20,
                    }),
                )
                .unwrap();
            let mut replay_hash = HashedPostStateSink::<reth_trie::KeccakKeyHasher>::default();
            replay.visit(&mut replay_hash).unwrap();
            assert_eq!(
                serial_hash,
                replay_hash.into_hashed_post_state(),
                "replay cache warm={warm_replay_cache}"
            );
        }
    }

    #[test]
    fn replay_cache_matches_committed_storage_with_absent_or_uncached_account() {
        let address = Address::repeat_byte(0x42);
        let slot = U256::from(7);
        for account_known_absent in [false, true] {
            let mut evm = empty_evm(InMemoryDB::default());
            let db = evm.overlay_db_mut();
            if account_known_absent {
                db.cache.accounts.insert(address, None);
            }
            let mut pending = PendingState::default();
            pending.insert_storage(address, slot, U256::ZERO, U256::from(11));
            db.commit_pending(&pending);

            let actual = db.get_storage(&address, &slot).unwrap();
            assert_eq!(actual, U256::from(11));
            assert_eq!(
                StorageActionReplayState::cached_storage_value(db, address, slot),
                Some(actual)
            );
            let mut replay = StorageActionReplayState::default();
            assert_eq!(
                replay
                    .sload_current_or(db, address, slot, U256::from(3))
                    .unwrap(),
                actual
            );
            assert!(
                replay
                    .sload_exact(db, address, slot, U256::from(3))
                    .is_err()
            );
        }
    }

    #[test]
    fn replay_cache_preserves_storage_wipes_and_absent_backing_semantics() {
        let address = Address::repeat_byte(0x42);
        let slot = U256::from(7);
        let other_slot = U256::from(8);
        let mut evm = state_with_storage(address, slot, U256::from(5));
        let db = evm.overlay_db_mut();
        let original = db.get_account(&address).unwrap();
        let mut deletion = PendingState::default();
        deletion.insert_account(address, original, None);
        db.commit_pending(&deletion);
        assert_eq!(
            StorageActionReplayState::cached_storage_value(db, address, slot),
            Some(U256::ZERO)
        );
        assert_eq!(db.get_storage(&address, &slot).unwrap(), U256::ZERO);

        // A later committed write takes precedence even while the account is absent and the
        // storage cache retains the wipe marker; untouched slots still read as zero.
        let mut write = PendingState::default();
        write.insert_storage(address, slot, U256::ZERO, U256::from(9));
        db.commit_pending(&write);
        assert_eq!(
            StorageActionReplayState::cached_storage_value(db, address, slot),
            Some(U256::from(9))
        );
        assert_eq!(db.get_storage(&address, &slot).unwrap(), U256::from(9));
        assert_eq!(
            StorageActionReplayState::cached_storage_value(db, address, other_slot),
            Some(U256::ZERO)
        );
        assert_eq!(db.get_storage(&address, &other_slot).unwrap(), U256::ZERO);
    }

    #[test]
    fn replay_cache_does_not_read_backing_storage_for_known_absent_account() {
        let address = Address::repeat_byte(0x42);
        let slot = U256::from(7);
        let mut backing = InMemoryDB::default();
        backing.insert_account_info(&address, AccountInfo::default().with_nonce(1));
        backing.insert_account_storage(&address, &slot, &U256::from(99));
        let mut evm = empty_evm(backing);
        let db = evm.overlay_db_mut();
        db.cache.accounts.insert(address, None);
        assert_eq!(
            StorageActionReplayState::cached_storage_value(db, address, slot),
            Some(U256::ZERO)
        );
        assert_eq!(db.get_storage(&address, &slot).unwrap(), U256::ZERO);
    }

    #[test]
    fn recorded_sload_rejects_changed_database_value() {
        let address = Address::repeat_byte(0x42);
        let slot = U256::from(7);
        let evm = state_with_storage(address, slot, U256::from(11));
        let mut replay_state = StorageActionReplayState::default();

        let err = replay_state
            .sload_exact(evm.overlay_db(), address, slot, U256::from(10))
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
        let mut cache_db = InMemoryDB::default();
        cache_db.insert_account_info(&address, AccountInfo::default().with_nonce(1));
        cache_db.insert_account_storage(&address, &slot, &U256::from(11));
        let evm = empty_evm(cache_db);
        let mut replay_state = StorageActionReplayState::default();

        assert_eq!(
            replay_state
                .sload_exact(evm.overlay_db(), address, slot, U256::from(10))
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
        let mut cache_db = InMemoryDB::default();
        cache_db.insert_account_info(&address, AccountInfo::default().with_nonce(1));
        cache_db.insert_account_storage(&address, &slot, &U256::from(11));
        let evm = empty_evm(cache_db);
        let mut replay_state = StorageActionReplayState::default();

        assert_eq!(
            replay_state
                .sload_current_or(evm.overlay_db(), address, slot, U256::from(10))
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
        let evm = state_with_storage(address, slot, U256::from(10));
        let mut replay_state = StorageActionReplayState::default();

        assert_eq!(
            replay_state
                .sload_exact(evm.overlay_db(), address, slot, U256::from(10))
                .expect("load exact storage"),
            U256::from(10),
        );
        replay_state
            .sstore(address, slot, U256::from(11))
            .expect("store loaded slot");

        let err = replay_state
            .sload_exact(evm.overlay_db(), address, slot, U256::from(10))
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
        let evm = state_with_storage(address, slot, U256::from(11));
        let mut replay_state = StorageActionReplayState::default();

        let err = replay_state
            .sload_exact(evm.overlay_db(), address, slot, U256::from(10))
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
        let evm = state_with_storage(address, slot, U256::from(10));
        let mut replay_state = StorageActionReplayState::default();

        replay_state
            .sstore_exact(
                evm.overlay_db(),
                address,
                slot,
                U256::from(10),
                U256::from(11),
            )
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
        let evm = state_with_storage(address, slot, U256::from(11));
        let mut replay_state = StorageActionReplayState::default();

        let current = replay_state
            .sload_current_or(evm.overlay_db(), address, slot, U256::from(10))
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
