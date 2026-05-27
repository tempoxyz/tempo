//! Production semantic action capture and write synthesis.

use crate::blockstm::{
    action::{
        BlockStmAction, BlockStmActionKind, BlockStmActionLog,
        fee_manager::CollectedFeesDelta,
        nonce::ExpiringNonceUse,
        slots::{
            expiring_nonce_ring_key, expiring_nonce_ring_ptr_key, expiring_nonce_seen_key,
            fee_manager_collected_fees_key, tip20_balance_key,
        },
        tip20::{Tip20FeeEscrowDelta, Tip20TransferDelta},
    },
    rw_set::{BlockStmAccessKey, BlockStmWriteSet},
    state_view::write_set_from_evm_state,
};
use alloy_consensus::Transaction;
use alloy_primitives::{
    Address, B256, TxKind, U256,
    map::{HashMap, HashSet},
};
use alloy_sol_types::SolInterface;
use reth_evm::{Database, block::TxResult};
use reth_revm::state::{EvmStorageSlot, TransactionId};
use reth_transaction_pool::PoolTransaction;
use std::fmt;
use tempo_evm::TempoTxResult;
use tempo_precompiles::{
    DEFAULT_FEE_TOKEN, NONCE_PRECOMPILE_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
    nonce::{EXPIRING_NONCE_MAX_EXPIRY_SECS, EXPIRING_NONCE_SET_CAPACITY},
    tip20::ITIP20,
};
use tempo_primitives::{TempoAddressExt, transaction::calc_gas_balance_spending};
use tempo_transaction_pool::transaction::TempoPooledTransaction;

/// Semantic plan captured from a successful real execution attempt.
#[derive(Debug, Clone)]
pub struct BlockStmSemanticPlan {
    action_log: BlockStmActionLog,
    covered_keys: HashSet<BlockStmAccessKey>,
    semantic_prefix_reads: usize,
}

impl BlockStmSemanticPlan {
    /// Keys whose speculative reads and writes are resolved by ordered semantic replay.
    pub fn covered_keys(&self) -> &HashSet<BlockStmAccessKey> {
        &self.covered_keys
    }

    /// Number of actions captured for metrics and tests.
    pub fn action_count(&self) -> usize {
        self.action_log.actions().len() + self.semantic_prefix_reads
    }
}

/// Online ordered semantic state for the block prefix already committed.
#[derive(Debug, Default)]
pub struct BlockStmSemanticState {
    values: HashMap<BlockStmAccessKey, U256>,
}

/// Semantic replay failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockStmSemanticError {
    Database(String),
    InvalidExpiry {
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
    InsufficientBalance {
        key: BlockStmAccessKey,
        available: U256,
        required: U256,
    },
    Overflow {
        key: BlockStmAccessKey,
    },
    FeeEscrowInvariant,
}

impl fmt::Display for BlockStmSemanticError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(err) => write!(f, "semantic state read failed: {err}"),
            Self::InvalidExpiry { valid_before } => {
                write!(f, "invalid expiring nonce expiry {valid_before}")
            }
            Self::Replay { nonce_hash } => write!(f, "duplicate expiring nonce {nonce_hash:?}"),
            Self::RingSlotOccupied {
                ring_slot,
                old_hash,
                old_expiry,
            } => write!(
                f,
                "expiring nonce ring slot {ring_slot} holds unexpired {old_hash:?} until {old_expiry}"
            ),
            Self::InsufficientBalance {
                key,
                available,
                required,
            } => write!(
                f,
                "insufficient semantic balance for {key:?}: available {available}, required {required}"
            ),
            Self::Overflow { key } => write!(f, "semantic value overflow for {key:?}"),
            Self::FeeEscrowInvariant => {
                write!(f, "fee escrow spending plus refund differs from precharge")
            }
        }
    }
}

impl std::error::Error for BlockStmSemanticError {}

/// Captures the pure TIP20 fast-path actions from a successful real EVM attempt.
pub fn capture_tip20_semantic_plan(
    tx_index: usize,
    tx: &TempoPooledTransaction,
    result: &TempoTxResult,
    write_set: &BlockStmWriteSet,
    beneficiary: Address,
) -> Option<BlockStmSemanticPlan> {
    if !result.result().result.is_success() {
        return None;
    }

    let sender = tx.sender();
    let fee_payer = tx.inner().fee_payer(sender).ok()?;
    let fee_token = tx.effective_fee_token();
    if fee_token != DEFAULT_FEE_TOKEN || !fee_token.is_tip20() {
        return None;
    }

    let transfers = simple_tip20_transfers(tx, sender)?;
    if transfers.is_empty() {
        return None;
    }
    if transfers
        .iter()
        .any(|transfer| transfer.token != fee_token || !transfer.token.is_tip20())
    {
        return None;
    }

    let max_fee_precharge = calc_gas_balance_spending(tx.gas_limit(), tx.max_fee_per_gas());
    let actual_spending = result.validator_fee();
    let refund_amount = max_fee_precharge.checked_sub(actual_spending)?;

    let mut action_log = BlockStmActionLog::default();
    let mut covered_keys = HashSet::default();
    let mut op_index = 0u32;

    if tx.is_expiring_nonce() {
        let nonce_hash = tx.expiring_nonce_hash()?;
        let valid_before = tx.inner().as_aa()?.tx().valid_before?.get();
        let nonce = ExpiringNonceUse::new(nonce_hash, valid_before, 0, 0);
        let mut covered = nonce.covered_storage_slots();
        for (key, _) in write_set.iter() {
            if matches!(
                key,
                BlockStmAccessKey::Storage {
                    address: NONCE_PRECOMPILE_ADDRESS,
                    ..
                }
            ) {
                covered.push(*key);
            }
        }
        covered_keys.extend(covered.iter().copied());
        action_log.push(BlockStmAction::new(
            tx_index,
            op_index,
            BlockStmActionKind::ExpiringNonceUse(nonce),
            covered,
        ));
        op_index += 1;
    }

    let fee = Tip20FeeEscrowDelta {
        token: fee_token,
        fee_payer,
        fee_manager: TIP_FEE_MANAGER_ADDRESS,
        max_fee_precharge,
        actual_spending,
        refund_amount,
    };
    let covered = fee.covered_storage_slots();
    covered_keys.extend(covered.iter().copied());
    action_log.push(BlockStmAction::new(
        tx_index,
        op_index,
        BlockStmActionKind::Tip20FeeEscrowDelta(fee),
        covered,
    ));
    op_index += 1;

    let semantic_prefix_reads = 1;

    for transfer in transfers {
        let covered = transfer.covered_storage_slots();
        covered_keys.extend(covered.iter().copied());
        action_log.push(BlockStmAction::new(
            tx_index,
            op_index,
            BlockStmActionKind::Tip20TransferDelta(transfer),
            covered,
        ));
        op_index += 1;
    }

    let collected = CollectedFeesDelta {
        beneficiary,
        validator_token: DEFAULT_FEE_TOKEN,
        amount: actual_spending,
    };
    let covered = collected.covered_storage_slots();
    covered_keys.extend(covered.iter().copied());
    action_log.push(BlockStmAction::new(
        tx_index,
        op_index,
        BlockStmActionKind::CollectedFeesDelta(collected),
        covered,
    ));

    if has_uncovered_hot_storage_write(write_set, fee_token, &covered_keys) {
        return None;
    }

    Some(BlockStmSemanticPlan {
        action_log,
        covered_keys,
        semantic_prefix_reads,
    })
}

impl BlockStmSemanticState {
    /// Applies a captured plan to the ordered prefix without rewriting a transaction result.
    ///
    /// This is useful for batch-oriented pure semantic domains where covered writes are
    /// synthesized once after all per-transaction receipts and accounting have been committed.
    pub fn apply_plan_to_prefix<DB>(
        &mut self,
        db: &mut DB,
        plan: &BlockStmSemanticPlan,
        block_timestamp: u64,
    ) -> Result<(), BlockStmSemanticError>
    where
        DB: Database,
        DB::Error: fmt::Display,
    {
        for action in plan.action_log.actions() {
            match action.kind {
                BlockStmActionKind::ExpiringNonceUse(action) => {
                    self.apply_expiring_nonce_to_prefix(db, action, block_timestamp)?;
                }
                BlockStmActionKind::Tip20FeeEscrowDelta(action) => {
                    if action
                        .actual_spending
                        .checked_add(action.refund_amount)
                        .map_or(true, |value| value != action.max_fee_precharge)
                    {
                        return Err(BlockStmSemanticError::FeeEscrowInvariant);
                    }
                    self.sub_storage_prefix(
                        db,
                        tip20_balance_key(action.token, action.fee_payer),
                        action.max_fee_precharge,
                    )?;
                    self.add_storage_prefix(
                        db,
                        tip20_balance_key(action.token, action.fee_manager),
                        action.max_fee_precharge,
                    )?;
                    self.sub_storage_prefix(
                        db,
                        tip20_balance_key(action.token, action.fee_manager),
                        action.refund_amount,
                    )?;
                    self.add_storage_prefix(
                        db,
                        tip20_balance_key(action.token, action.fee_payer),
                        action.refund_amount,
                    )?;
                }
                BlockStmActionKind::Tip20TransferDelta(action) => {
                    self.sub_storage_prefix(
                        db,
                        tip20_balance_key(action.token, action.sender),
                        action.amount,
                    )?;
                    self.add_storage_prefix(
                        db,
                        tip20_balance_key(action.token, action.recipient),
                        action.amount,
                    )?;
                }
                BlockStmActionKind::CollectedFeesDelta(action) => {
                    self.add_storage_prefix(
                        db,
                        fee_manager_collected_fees_key(action.beneficiary, action.validator_token),
                        action.amount,
                    )?;
                }
                BlockStmActionKind::SemanticPrefixRead(_) | BlockStmActionKind::Barrier => {}
            }
        }

        Ok(())
    }

    /// Returns the ordered-prefix semantic storage values accumulated so far.
    pub fn storage_values(&self) -> impl Iterator<Item = (&BlockStmAccessKey, &U256)> {
        self.values.iter()
    }

    /// Applies a captured plan to the ordered prefix and rewrites covered storage in `result`.
    pub fn apply_plan<DB>(
        &mut self,
        db: &mut DB,
        plan: &BlockStmSemanticPlan,
        result: &mut TempoTxResult,
        block_timestamp: u64,
    ) -> Result<BlockStmWriteSet, BlockStmSemanticError>
    where
        DB: Database,
        DB::Error: fmt::Display,
    {
        let mut final_writes = BlockStmWriteSet::default();
        let mut original_values = HashMap::default();

        for action in plan.action_log.actions() {
            match action.kind {
                BlockStmActionKind::ExpiringNonceUse(action) => {
                    self.apply_expiring_nonce(
                        db,
                        action,
                        block_timestamp,
                        &mut original_values,
                        &mut final_writes,
                    )?;
                }
                BlockStmActionKind::Tip20FeeEscrowDelta(action) => {
                    if action
                        .actual_spending
                        .checked_add(action.refund_amount)
                        .map_or(true, |value| value != action.max_fee_precharge)
                    {
                        return Err(BlockStmSemanticError::FeeEscrowInvariant);
                    }
                    self.sub_storage(
                        db,
                        tip20_balance_key(action.token, action.fee_payer),
                        action.max_fee_precharge,
                        &mut original_values,
                        &mut final_writes,
                    )?;
                    self.add_storage(
                        db,
                        tip20_balance_key(action.token, action.fee_manager),
                        action.max_fee_precharge,
                        &mut original_values,
                        &mut final_writes,
                    )?;
                    self.sub_storage(
                        db,
                        tip20_balance_key(action.token, action.fee_manager),
                        action.refund_amount,
                        &mut original_values,
                        &mut final_writes,
                    )?;
                    self.add_storage(
                        db,
                        tip20_balance_key(action.token, action.fee_payer),
                        action.refund_amount,
                        &mut original_values,
                        &mut final_writes,
                    )?;
                }
                BlockStmActionKind::Tip20TransferDelta(action) => {
                    self.sub_storage(
                        db,
                        tip20_balance_key(action.token, action.sender),
                        action.amount,
                        &mut original_values,
                        &mut final_writes,
                    )?;
                    self.add_storage(
                        db,
                        tip20_balance_key(action.token, action.recipient),
                        action.amount,
                        &mut original_values,
                        &mut final_writes,
                    )?;
                }
                BlockStmActionKind::CollectedFeesDelta(action) => {
                    self.add_storage(
                        db,
                        fee_manager_collected_fees_key(action.beneficiary, action.validator_token),
                        action.amount,
                        &mut original_values,
                        &mut final_writes,
                    )?;
                }
                BlockStmActionKind::SemanticPrefixRead(_) | BlockStmActionKind::Barrier => {}
            }
        }

        rewrite_covered_storage(result, plan.covered_keys(), &final_writes, &original_values);
        Ok(write_set_from_evm_state(&result.result().state))
    }

    fn apply_expiring_nonce<DB>(
        &mut self,
        db: &mut DB,
        action: ExpiringNonceUse,
        block_timestamp: u64,
        original_values: &mut HashMap<BlockStmAccessKey, U256>,
        final_writes: &mut BlockStmWriteSet,
    ) -> Result<(), BlockStmSemanticError>
    where
        DB: Database,
        DB::Error: fmt::Display,
    {
        if action.valid_before <= block_timestamp
            || action.valid_before > block_timestamp.saturating_add(EXPIRING_NONCE_MAX_EXPIRY_SECS)
        {
            return Err(BlockStmSemanticError::InvalidExpiry {
                valid_before: action.valid_before,
            });
        }

        let seen_key = expiring_nonce_seen_key(action.nonce_hash);
        let seen_expiry = self.read_storage(db, seen_key)?;
        if !seen_expiry.is_zero() && seen_expiry > U256::from(block_timestamp) {
            return Err(BlockStmSemanticError::Replay {
                nonce_hash: action.nonce_hash,
            });
        }

        let ptr_key = expiring_nonce_ring_ptr_key();
        let ptr = self.read_storage(db, ptr_key)?.to::<u32>();
        let ring_slot = ptr % EXPIRING_NONCE_SET_CAPACITY;
        let ring_key = expiring_nonce_ring_key(ring_slot);
        let old_hash = B256::from(self.read_storage(db, ring_key)?);

        if old_hash != B256::ZERO {
            let old_seen_key = expiring_nonce_seen_key(old_hash);
            let old_expiry = self.read_storage(db, old_seen_key)?;
            if !old_expiry.is_zero() && old_expiry > U256::from(block_timestamp) {
                return Err(BlockStmSemanticError::RingSlotOccupied {
                    ring_slot,
                    old_hash,
                    old_expiry: old_expiry.to::<u64>(),
                });
            }
            self.set_storage(
                db,
                old_seen_key,
                U256::ZERO,
                old_expiry,
                original_values,
                final_writes,
            );
        }

        self.set_storage(
            db,
            ring_key,
            U256::from_be_bytes(action.nonce_hash.0),
            U256::from_be_bytes(old_hash.0),
            original_values,
            final_writes,
        );
        self.set_storage(
            db,
            seen_key,
            U256::from(action.valid_before),
            seen_expiry,
            original_values,
            final_writes,
        );
        let next = if ring_slot + 1 >= EXPIRING_NONCE_SET_CAPACITY {
            0
        } else {
            ring_slot + 1
        };
        self.set_storage(
            db,
            ptr_key,
            U256::from(next),
            U256::from(ptr),
            original_values,
            final_writes,
        );
        Ok(())
    }

    fn apply_expiring_nonce_to_prefix<DB>(
        &mut self,
        db: &mut DB,
        action: ExpiringNonceUse,
        block_timestamp: u64,
    ) -> Result<(), BlockStmSemanticError>
    where
        DB: Database,
        DB::Error: fmt::Display,
    {
        if action.valid_before <= block_timestamp
            || action.valid_before > block_timestamp.saturating_add(EXPIRING_NONCE_MAX_EXPIRY_SECS)
        {
            return Err(BlockStmSemanticError::InvalidExpiry {
                valid_before: action.valid_before,
            });
        }

        let seen_key = expiring_nonce_seen_key(action.nonce_hash);
        let seen_expiry = self.read_storage(db, seen_key)?;
        if !seen_expiry.is_zero() && seen_expiry > U256::from(block_timestamp) {
            return Err(BlockStmSemanticError::Replay {
                nonce_hash: action.nonce_hash,
            });
        }

        let ptr_key = expiring_nonce_ring_ptr_key();
        let ptr = self.read_storage(db, ptr_key)?.to::<u32>();
        let ring_slot = ptr % EXPIRING_NONCE_SET_CAPACITY;
        let ring_key = expiring_nonce_ring_key(ring_slot);
        let old_hash = B256::from(self.read_storage(db, ring_key)?);

        if old_hash != B256::ZERO {
            let old_seen_key = expiring_nonce_seen_key(old_hash);
            let old_expiry = self.read_storage(db, old_seen_key)?;
            if !old_expiry.is_zero() && old_expiry > U256::from(block_timestamp) {
                return Err(BlockStmSemanticError::RingSlotOccupied {
                    ring_slot,
                    old_hash,
                    old_expiry: old_expiry.to::<u64>(),
                });
            }
            self.values.insert(old_seen_key, U256::ZERO);
        }

        self.values
            .insert(ring_key, U256::from_be_bytes(action.nonce_hash.0));
        self.values
            .insert(seen_key, U256::from(action.valid_before));
        let next = if ring_slot + 1 >= EXPIRING_NONCE_SET_CAPACITY {
            0
        } else {
            ring_slot + 1
        };
        self.values.insert(ptr_key, U256::from(next));
        Ok(())
    }

    fn add_storage_prefix<DB>(
        &mut self,
        db: &mut DB,
        key: BlockStmAccessKey,
        amount: U256,
    ) -> Result<(), BlockStmSemanticError>
    where
        DB: Database,
        DB::Error: fmt::Display,
    {
        let current = self.read_storage(db, key)?;
        let next = current
            .checked_add(amount)
            .ok_or(BlockStmSemanticError::Overflow { key })?;
        self.values.insert(key, next);
        Ok(())
    }

    fn sub_storage_prefix<DB>(
        &mut self,
        db: &mut DB,
        key: BlockStmAccessKey,
        amount: U256,
    ) -> Result<(), BlockStmSemanticError>
    where
        DB: Database,
        DB::Error: fmt::Display,
    {
        let current = self.read_storage(db, key)?;
        let next =
            current
                .checked_sub(amount)
                .ok_or(BlockStmSemanticError::InsufficientBalance {
                    key,
                    available: current,
                    required: amount,
                })?;
        self.values.insert(key, next);
        Ok(())
    }

    fn add_storage<DB>(
        &mut self,
        db: &mut DB,
        key: BlockStmAccessKey,
        amount: U256,
        original_values: &mut HashMap<BlockStmAccessKey, U256>,
        final_writes: &mut BlockStmWriteSet,
    ) -> Result<(), BlockStmSemanticError>
    where
        DB: Database,
        DB::Error: fmt::Display,
    {
        let current = self.read_storage(db, key)?;
        let next = current
            .checked_add(amount)
            .ok_or(BlockStmSemanticError::Overflow { key })?;
        self.set_storage(db, key, next, current, original_values, final_writes);
        Ok(())
    }

    fn sub_storage<DB>(
        &mut self,
        db: &mut DB,
        key: BlockStmAccessKey,
        amount: U256,
        original_values: &mut HashMap<BlockStmAccessKey, U256>,
        final_writes: &mut BlockStmWriteSet,
    ) -> Result<(), BlockStmSemanticError>
    where
        DB: Database,
        DB::Error: fmt::Display,
    {
        let current = self.read_storage(db, key)?;
        let next =
            current
                .checked_sub(amount)
                .ok_or(BlockStmSemanticError::InsufficientBalance {
                    key,
                    available: current,
                    required: amount,
                })?;
        self.set_storage(db, key, next, current, original_values, final_writes);
        Ok(())
    }

    fn set_storage<DB>(
        &mut self,
        _db: &mut DB,
        key: BlockStmAccessKey,
        value: U256,
        original: U256,
        original_values: &mut HashMap<BlockStmAccessKey, U256>,
        final_writes: &mut BlockStmWriteSet,
    ) where
        DB: Database,
        DB::Error: fmt::Display,
    {
        if !original_values.contains_key(&key) {
            original_values.insert(key, original);
        }
        self.values.insert(key, value);
        final_writes.record(key, value);
    }

    fn read_storage<DB>(
        &mut self,
        db: &mut DB,
        key: BlockStmAccessKey,
    ) -> Result<U256, BlockStmSemanticError>
    where
        DB: Database,
        DB::Error: fmt::Display,
    {
        if let Some(value) = self.values.get(&key) {
            return Ok(*value);
        }

        let BlockStmAccessKey::Storage { address, slot } = key else {
            return Ok(U256::ZERO);
        };
        db.storage(address, slot)
            .map_err(|err| BlockStmSemanticError::Database(err.to_string()))
    }
}

fn simple_tip20_transfers(
    tx: &TempoPooledTransaction,
    sender: Address,
) -> Option<Vec<Tip20TransferDelta>> {
    if !tx.is_payment() {
        return None;
    }

    let mut transfers = Vec::new();
    for (kind, input) in tx.inner().calls() {
        let token = kind.to().copied()?;
        if !matches!(kind, TxKind::Call(_)) || !token.is_tip20() {
            return None;
        }
        let transfer = match ITIP20::ITIP20Calls::abi_decode(input).ok()? {
            ITIP20::ITIP20Calls::transfer(call) => Tip20TransferDelta {
                token,
                sender,
                recipient: call.to,
                amount: call.amount,
            },
            ITIP20::ITIP20Calls::transferWithMemo(call) => Tip20TransferDelta {
                token,
                sender,
                recipient: call.to,
                amount: call.amount,
            },
            _ => return None,
        };
        transfers.push(transfer);
    }

    Some(transfers)
}

fn has_uncovered_hot_storage_write(
    write_set: &BlockStmWriteSet,
    fee_token: Address,
    covered_keys: &HashSet<BlockStmAccessKey>,
) -> bool {
    write_set.iter().any(|(key, _)| match key {
        BlockStmAccessKey::Storage { address, .. }
            if *address == fee_token
                || *address == TIP_FEE_MANAGER_ADDRESS
                || *address == NONCE_PRECOMPILE_ADDRESS =>
        {
            !covered_keys.contains(key)
        }
        _ => false,
    })
}

fn rewrite_covered_storage(
    result: &mut TempoTxResult,
    covered_keys: &HashSet<BlockStmAccessKey>,
    final_writes: &BlockStmWriteSet,
    original_values: &HashMap<BlockStmAccessKey, U256>,
) {
    let state = &mut result.result_mut().state;

    for key in covered_keys {
        let BlockStmAccessKey::Storage { address, slot } = *key else {
            continue;
        };

        if let Some(value) = final_writes.get(key) {
            let original = original_values
                .get(key)
                .copied()
                .or_else(|| {
                    state
                        .get(&address)
                        .and_then(|account| account.storage.get(&slot))
                        .map(|slot| slot.original_value())
                })
                .unwrap_or_default();
            let account = state.entry(address).or_default();
            account.mark_touch();
            account
                .storage
                .entry(slot)
                .and_modify(|storage_slot| {
                    storage_slot.original_value = original;
                    storage_slot.present_value = value.as_u256();
                })
                .or_insert_with(|| {
                    EvmStorageSlot::new_changed(original, value.as_u256(), TransactionId::ZERO)
                });
        } else if let Some(account) = state.get_mut(&address)
            && let Some(storage_slot) = account.storage.get_mut(&slot)
        {
            storage_slot.present_value = storage_slot.original_value();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockstm::BlockStmValue;
    use crate::blockstm::action::slots::{
        expiring_nonce_ring_key, expiring_nonce_ring_ptr_key, expiring_nonce_seen_key,
    };
    use alloy_primitives::address;
    use reth_revm::db::{CacheDB, EmptyDB};

    #[test]
    fn blockstm_actions_online_nonce_rejects_duplicate_hash() {
        let hash = B256::repeat_byte(0x11);
        let mut state = BlockStmSemanticState::default();
        let mut db = CacheDB::<EmptyDB>::default();
        let mut originals = HashMap::default();
        let mut writes = BlockStmWriteSet::default();
        let action = ExpiringNonceUse::new(hash, 110, 0, 0);

        state
            .apply_expiring_nonce(&mut db, action, 100, &mut originals, &mut writes)
            .unwrap();
        assert_eq!(
            state
                .apply_expiring_nonce(&mut db, action, 100, &mut originals, &mut writes)
                .unwrap_err(),
            BlockStmSemanticError::Replay { nonce_hash: hash }
        );
    }

    #[test]
    fn blockstm_actions_online_nonce_synthesizes_serial_ring_slots() {
        let hash1 = B256::repeat_byte(0x11);
        let hash2 = B256::repeat_byte(0x22);
        let mut state = BlockStmSemanticState::default();
        let mut db = CacheDB::<EmptyDB>::default();
        let mut originals = HashMap::default();
        let mut writes = BlockStmWriteSet::default();

        state
            .apply_expiring_nonce(
                &mut db,
                ExpiringNonceUse::new(hash1, 110, 0, 0),
                100,
                &mut originals,
                &mut writes,
            )
            .unwrap();
        state
            .apply_expiring_nonce(
                &mut db,
                ExpiringNonceUse::new(hash2, 110, 0, 0),
                100,
                &mut originals,
                &mut writes,
            )
            .unwrap();

        assert_eq!(
            writes.get(&expiring_nonce_ring_key(0)),
            Some(BlockStmValue::from(hash1))
        );
        assert_eq!(
            writes.get(&expiring_nonce_ring_key(1)),
            Some(BlockStmValue::from(hash2))
        );
        assert_eq!(
            writes.get(&expiring_nonce_ring_ptr_key()),
            Some(BlockStmValue::from(U256::from(2)))
        );
        assert_eq!(
            writes.get(&expiring_nonce_seen_key(hash2)),
            Some(BlockStmValue::from(U256::from(110)))
        );
    }

    #[test]
    fn blockstm_actions_online_fee_escrow_checks_precharge() {
        let token = DEFAULT_FEE_TOKEN;
        let payer = address!("0x00000000000000000000000000000000000000aa");
        let mut state = BlockStmSemanticState::default();
        let mut db = CacheDB::<EmptyDB>::default();
        let mut originals = HashMap::default();
        let mut writes = BlockStmWriteSet::default();

        state.set_storage(
            &mut db,
            tip20_balance_key(token, payer),
            U256::from(9),
            U256::ZERO,
            &mut originals,
            &mut writes,
        );

        assert!(matches!(
            state.sub_storage(
                &mut db,
                tip20_balance_key(token, payer),
                U256::from(10),
                &mut originals,
                &mut writes,
            ),
            Err(BlockStmSemanticError::InsufficientBalance { .. })
        ));
    }
}
