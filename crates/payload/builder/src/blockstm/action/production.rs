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
use reth_revm::state::{EvmState, EvmStorageSlot, TransactionId};
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
    prefix_originals: HashMap<BlockStmAccessKey, U256>,
    semantic_prefix_reads: usize,
    tip20_prefix: Option<BlockStmTip20PrefixPlan>,
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

    /// Original storage values observed by the successful EVM attempt for semantic keys.
    pub(crate) fn prefix_originals(&self) -> &HashMap<BlockStmAccessKey, U256> {
        &self.prefix_originals
    }
}

#[derive(Debug, Clone)]
struct BlockStmTip20PrefixPlan {
    nonce: Option<(B256, u64)>,
    fee: Tip20FeeEscrowDelta,
    transfers: Vec<Tip20TransferDelta>,
    collected: CollectedFeesDelta,
}

/// Online ordered semantic state for the block prefix already committed.
#[derive(Debug, Clone, Default)]
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

    let mut prefix_nonce = None;
    if tx.is_expiring_nonce() {
        let nonce_hash = tx.expiring_nonce_hash()?;
        let valid_before = tx.inner().as_aa()?.tx().valid_before?.get();
        prefix_nonce = Some((nonce_hash, valid_before));
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

    for transfer in transfers.iter().copied() {
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

    let prefix_originals = semantic_original_values(result, &covered_keys);
    let tip20_prefix = Some(BlockStmTip20PrefixPlan {
        nonce: prefix_nonce,
        fee,
        transfers,
        collected,
    });

    Some(BlockStmSemanticPlan {
        action_log,
        covered_keys,
        prefix_originals,
        semantic_prefix_reads,
        tip20_prefix,
    })
}

impl BlockStmSemanticState {
    /// Reserves space for additional ordered-prefix values.
    pub fn reserve(&mut self, additional: usize) {
        self.values.reserve(additional);
    }

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
        let mut record_write = |_: &HashMap<BlockStmAccessKey, U256>, _: BlockStmAccessKey| {};
        self.apply_plan_to_prefix_inner(db, plan, block_timestamp, &mut record_write)
    }

    /// Applies a captured plan to the ordered prefix and records touched storage keys.
    pub fn apply_plan_to_prefix_recording<DB>(
        &mut self,
        db: &mut DB,
        plan: &BlockStmSemanticPlan,
        block_timestamp: u64,
        touched_keys: &mut HashSet<BlockStmAccessKey>,
        rollback: &mut HashMap<BlockStmAccessKey, Option<U256>>,
    ) -> Result<(), BlockStmSemanticError>
    where
        DB: Database,
        DB::Error: fmt::Display,
    {
        let mut record_write = |values: &HashMap<BlockStmAccessKey, U256>,
                                key: BlockStmAccessKey| {
            if touched_keys.insert(key) {
                rollback.insert(key, values.get(&key).copied());
            }
        };
        self.apply_plan_to_prefix_inner(db, plan, block_timestamp, &mut record_write)
    }

    /// Applies a pure TIP20 batch to the ordered prefix, using a single nonce pointer write.
    pub fn apply_plans_to_prefix_recording<DB>(
        &mut self,
        db: &mut DB,
        plans: &[&BlockStmSemanticPlan],
        block_timestamp: u64,
        touched_keys: &mut HashSet<BlockStmAccessKey>,
        rollback: &mut HashMap<BlockStmAccessKey, Option<U256>>,
    ) -> Result<(), BlockStmSemanticError>
    where
        DB: Database,
        DB::Error: fmt::Display,
    {
        if plans.iter().any(|plan| plan.tip20_prefix.is_none()) {
            for plan in plans {
                self.apply_plan_to_prefix_recording(
                    db,
                    plan,
                    block_timestamp,
                    touched_keys,
                    rollback,
                )?;
            }
            return Ok(());
        }

        let mut record_write = |values: &HashMap<BlockStmAccessKey, U256>,
                                key: BlockStmAccessKey| {
            if touched_keys.insert(key) {
                rollback.insert(key, values.get(&key).copied());
            }
        };
        self.apply_plans_to_prefix_with_recorder(db, plans, block_timestamp, &mut record_write)
    }

    fn apply_plans_to_prefix_with_recorder<DB, RecordWrite>(
        &mut self,
        db: &mut DB,
        plans: &[&BlockStmSemanticPlan],
        block_timestamp: u64,
        record_write: &mut RecordWrite,
    ) -> Result<(), BlockStmSemanticError>
    where
        DB: Database,
        DB::Error: fmt::Display,
        RecordWrite: FnMut(&HashMap<BlockStmAccessKey, U256>, BlockStmAccessKey),
    {
        if self.batch_fee_manager_keys_overlap_transfers(plans) {
            return self.apply_plans_to_prefix_unaggregated(
                db,
                plans,
                block_timestamp,
                record_write,
            );
        }

        let ptr_key = expiring_nonce_ring_ptr_key();
        let mut next_nonce_ring_ptr = None::<u32>;
        let mut aggregate_base_values = HashMap::default();
        let mut fee_manager_deltas = Vec::new();
        let mut collected_fee_deltas = Vec::new();
        aggregate_base_values.reserve(plans.len().saturating_mul(2));
        fee_manager_deltas.reserve(2);
        collected_fee_deltas.reserve(2);

        for semantic_plan in plans {
            let plan = semantic_plan
                .tip20_prefix
                .as_ref()
                .expect("TIP20 prefix plan checked above");
            let base_values = &semantic_plan.prefix_originals;
            if let Some((nonce_hash, valid_before)) = plan.nonce {
                self.apply_expiring_nonce_to_prefix_cursor(
                    db,
                    nonce_hash,
                    valid_before,
                    block_timestamp,
                    ptr_key,
                    base_values,
                    &mut next_nonce_ring_ptr,
                    record_write,
                )?;
            }

            self.apply_tip20_plan_to_prefix(
                db,
                plan,
                base_values,
                &mut aggregate_base_values,
                &mut fee_manager_deltas,
                record_write,
            )?;
            let collected_key = fee_manager_collected_fees_key(
                plan.collected.beneficiary,
                plan.collected.validator_token,
            );
            if let Some(value) = base_values.get(&collected_key).copied() {
                aggregate_base_values.entry(collected_key).or_insert(value);
            }
            Self::add_batch_delta(
                &mut collected_fee_deltas,
                collected_key,
                plan.collected.amount,
            )?;
        }

        for (key, amount) in fee_manager_deltas {
            self.add_storage_prefix(db, key, amount, &aggregate_base_values, record_write)?;
        }
        for (key, amount) in collected_fee_deltas {
            self.add_storage_prefix(db, key, amount, &aggregate_base_values, record_write)?;
        }
        if let Some(next_nonce_ring_ptr) = next_nonce_ring_ptr {
            self.insert_prefix_value(ptr_key, U256::from(next_nonce_ring_ptr), record_write);
        }

        Ok(())
    }

    fn apply_plans_to_prefix_unaggregated<DB, RecordWrite>(
        &mut self,
        db: &mut DB,
        plans: &[&BlockStmSemanticPlan],
        block_timestamp: u64,
        record_write: &mut RecordWrite,
    ) -> Result<(), BlockStmSemanticError>
    where
        DB: Database,
        DB::Error: fmt::Display,
        RecordWrite: FnMut(&HashMap<BlockStmAccessKey, U256>, BlockStmAccessKey),
    {
        let ptr_key = expiring_nonce_ring_ptr_key();
        let mut next_nonce_ring_ptr = None::<u32>;

        for semantic_plan in plans {
            let plan = semantic_plan
                .tip20_prefix
                .as_ref()
                .expect("TIP20 prefix plan checked above");
            let base_values = &semantic_plan.prefix_originals;
            if let Some((nonce_hash, valid_before)) = plan.nonce {
                self.apply_expiring_nonce_to_prefix_cursor(
                    db,
                    nonce_hash,
                    valid_before,
                    block_timestamp,
                    ptr_key,
                    base_values,
                    &mut next_nonce_ring_ptr,
                    record_write,
                )?;
            }

            self.apply_fee_escrow_to_prefix(db, plan.fee, base_values, record_write)?;
            for transfer in plan.transfers.iter().copied() {
                self.sub_storage_prefix(
                    db,
                    tip20_balance_key(transfer.token, transfer.sender),
                    transfer.amount,
                    base_values,
                    record_write,
                )?;
                self.add_storage_prefix(
                    db,
                    tip20_balance_key(transfer.token, transfer.recipient),
                    transfer.amount,
                    base_values,
                    record_write,
                )?;
            }
            self.add_storage_prefix(
                db,
                fee_manager_collected_fees_key(
                    plan.collected.beneficiary,
                    plan.collected.validator_token,
                ),
                plan.collected.amount,
                base_values,
                record_write,
            )?;
        }

        if let Some(next_nonce_ring_ptr) = next_nonce_ring_ptr {
            self.insert_prefix_value(ptr_key, U256::from(next_nonce_ring_ptr), record_write);
        }

        Ok(())
    }

    fn batch_fee_manager_keys_overlap_transfers(&self, plans: &[&BlockStmSemanticPlan]) -> bool {
        plans.iter().any(|semantic_plan| {
            let plan = semantic_plan
                .tip20_prefix
                .as_ref()
                .expect("TIP20 prefix plan checked above");
            plan.transfers.iter().any(|transfer| {
                transfer.token == plan.fee.token
                    && (transfer.sender == plan.fee.fee_manager
                        || transfer.recipient == plan.fee.fee_manager)
            })
        })
    }

    /// Restores prefix values recorded by `apply_plan_to_prefix_recording`.
    pub fn rollback_prefix(&mut self, rollback: HashMap<BlockStmAccessKey, Option<U256>>) {
        for (key, value) in rollback {
            if let Some(value) = value {
                self.values.insert(key, value);
            } else {
                self.values.remove(&key);
            }
        }
    }

    fn apply_plan_to_prefix_inner<DB, RecordWrite>(
        &mut self,
        db: &mut DB,
        plan: &BlockStmSemanticPlan,
        block_timestamp: u64,
        record_write: &mut RecordWrite,
    ) -> Result<(), BlockStmSemanticError>
    where
        DB: Database,
        DB::Error: fmt::Display,
        RecordWrite: FnMut(&HashMap<BlockStmAccessKey, U256>, BlockStmAccessKey),
    {
        for action in plan.action_log.actions() {
            match action.kind {
                BlockStmActionKind::ExpiringNonceUse(action) => {
                    self.apply_expiring_nonce_to_prefix(
                        db,
                        action,
                        block_timestamp,
                        &plan.prefix_originals,
                        record_write,
                    )?;
                }
                BlockStmActionKind::Tip20FeeEscrowDelta(action) => {
                    self.apply_fee_escrow_to_prefix(
                        db,
                        action,
                        &plan.prefix_originals,
                        record_write,
                    )?;
                }
                BlockStmActionKind::Tip20TransferDelta(action) => {
                    self.sub_storage_prefix(
                        db,
                        tip20_balance_key(action.token, action.sender),
                        action.amount,
                        &plan.prefix_originals,
                        record_write,
                    )?;
                    self.add_storage_prefix(
                        db,
                        tip20_balance_key(action.token, action.recipient),
                        action.amount,
                        &plan.prefix_originals,
                        record_write,
                    )?;
                }
                BlockStmActionKind::CollectedFeesDelta(action) => {
                    self.add_storage_prefix(
                        db,
                        fee_manager_collected_fees_key(action.beneficiary, action.validator_token),
                        action.amount,
                        &plan.prefix_originals,
                        record_write,
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

    /// Returns a single ordered-prefix semantic storage value.
    pub fn storage_value(&self, key: &BlockStmAccessKey) -> Option<U256> {
        self.values.get(key).copied()
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
        let seen_expiry = self.read_storage_with_base(db, seen_key, &HashMap::default())?;
        if !seen_expiry.is_zero() && seen_expiry > U256::from(block_timestamp) {
            return Err(BlockStmSemanticError::Replay {
                nonce_hash: action.nonce_hash,
            });
        }

        let ptr_key = expiring_nonce_ring_ptr_key();
        let ptr = self
            .read_storage_with_base(db, ptr_key, &HashMap::default())?
            .to::<u32>();
        let ring_slot = ptr % EXPIRING_NONCE_SET_CAPACITY;
        let ring_key = expiring_nonce_ring_key(ring_slot);
        let old_hash =
            B256::from(self.read_storage_with_base(db, ring_key, &HashMap::default())?);

        if old_hash != B256::ZERO {
            let old_seen_key = expiring_nonce_seen_key(old_hash);
            let old_expiry = self.read_storage_with_base(db, old_seen_key, &HashMap::default())?;
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

    fn apply_expiring_nonce_to_prefix<DB, RecordWrite>(
        &mut self,
        db: &mut DB,
        action: ExpiringNonceUse,
        block_timestamp: u64,
        base_values: &HashMap<BlockStmAccessKey, U256>,
        record_write: &mut RecordWrite,
    ) -> Result<(), BlockStmSemanticError>
    where
        DB: Database,
        DB::Error: fmt::Display,
        RecordWrite: FnMut(&HashMap<BlockStmAccessKey, U256>, BlockStmAccessKey),
    {
        if action.valid_before <= block_timestamp
            || action.valid_before > block_timestamp.saturating_add(EXPIRING_NONCE_MAX_EXPIRY_SECS)
        {
            return Err(BlockStmSemanticError::InvalidExpiry {
                valid_before: action.valid_before,
            });
        }

        let seen_key = expiring_nonce_seen_key(action.nonce_hash);
        let seen_expiry = self.read_storage_with_base(db, seen_key, base_values)?;
        if !seen_expiry.is_zero() && seen_expiry > U256::from(block_timestamp) {
            return Err(BlockStmSemanticError::Replay {
                nonce_hash: action.nonce_hash,
            });
        }

        let ptr_key = expiring_nonce_ring_ptr_key();
        let ptr = self
            .read_storage_with_base(db, ptr_key, base_values)?
            .to::<u32>();
        let ring_slot = ptr % EXPIRING_NONCE_SET_CAPACITY;
        let ring_key = expiring_nonce_ring_key(ring_slot);
        let old_hash = B256::from(self.read_storage_with_base(db, ring_key, base_values)?);

        if old_hash != B256::ZERO {
            let old_seen_key = expiring_nonce_seen_key(old_hash);
            let old_expiry = self.read_storage_with_base(db, old_seen_key, base_values)?;
            if !old_expiry.is_zero() && old_expiry > U256::from(block_timestamp) {
                return Err(BlockStmSemanticError::RingSlotOccupied {
                    ring_slot,
                    old_hash,
                    old_expiry: old_expiry.to::<u64>(),
                });
            }
            self.insert_prefix_value(old_seen_key, U256::ZERO, record_write);
        }

        self.insert_prefix_value(
            ring_key,
            U256::from_be_bytes(action.nonce_hash.0),
            record_write,
        );
        self.insert_prefix_value(seen_key, U256::from(action.valid_before), record_write);
        let next = if ring_slot + 1 >= EXPIRING_NONCE_SET_CAPACITY {
            0
        } else {
            ring_slot + 1
        };
        self.insert_prefix_value(ptr_key, U256::from(next), record_write);
        Ok(())
    }

    fn apply_expiring_nonce_to_prefix_cursor<DB, RecordWrite>(
        &mut self,
        db: &mut DB,
        nonce_hash: B256,
        valid_before: u64,
        block_timestamp: u64,
        ptr_key: BlockStmAccessKey,
        base_values: &HashMap<BlockStmAccessKey, U256>,
        next_nonce_ring_ptr: &mut Option<u32>,
        record_write: &mut RecordWrite,
    ) -> Result<(), BlockStmSemanticError>
    where
        DB: Database,
        DB::Error: fmt::Display,
        RecordWrite: FnMut(&HashMap<BlockStmAccessKey, U256>, BlockStmAccessKey),
    {
        if valid_before <= block_timestamp
            || valid_before > block_timestamp.saturating_add(EXPIRING_NONCE_MAX_EXPIRY_SECS)
        {
            return Err(BlockStmSemanticError::InvalidExpiry { valid_before });
        }

        let seen_key = expiring_nonce_seen_key(nonce_hash);
        let seen_expiry = self.read_storage_with_base(db, seen_key, base_values)?;
        if !seen_expiry.is_zero() && seen_expiry > U256::from(block_timestamp) {
            return Err(BlockStmSemanticError::Replay { nonce_hash });
        }

        let ptr = match *next_nonce_ring_ptr {
            Some(ptr) => ptr,
            None => self
                .read_storage_with_base(db, ptr_key, base_values)?
                .to::<u32>(),
        };
        let ring_slot = ptr % EXPIRING_NONCE_SET_CAPACITY;
        let ring_key = expiring_nonce_ring_key(ring_slot);
        let old_hash = B256::from(self.read_storage_with_base(db, ring_key, base_values)?);

        if old_hash != B256::ZERO {
            let old_seen_key = expiring_nonce_seen_key(old_hash);
            let old_expiry = self.read_storage_with_base(db, old_seen_key, base_values)?;
            if !old_expiry.is_zero() && old_expiry > U256::from(block_timestamp) {
                return Err(BlockStmSemanticError::RingSlotOccupied {
                    ring_slot,
                    old_hash,
                    old_expiry: old_expiry.to::<u64>(),
                });
            }
            self.insert_prefix_value(old_seen_key, U256::ZERO, record_write);
        }

        self.insert_prefix_value(ring_key, U256::from_be_bytes(nonce_hash.0), record_write);
        self.insert_prefix_value(seen_key, U256::from(valid_before), record_write);
        let next = if ring_slot + 1 >= EXPIRING_NONCE_SET_CAPACITY {
            0
        } else {
            ring_slot + 1
        };
        *next_nonce_ring_ptr = Some(next);
        Ok(())
    }

    fn add_storage_prefix<DB, RecordWrite>(
        &mut self,
        db: &mut DB,
        key: BlockStmAccessKey,
        amount: U256,
        base_values: &HashMap<BlockStmAccessKey, U256>,
        record_write: &mut RecordWrite,
    ) -> Result<(), BlockStmSemanticError>
    where
        DB: Database,
        DB::Error: fmt::Display,
        RecordWrite: FnMut(&HashMap<BlockStmAccessKey, U256>, BlockStmAccessKey),
    {
        let current = self.read_storage_with_base(db, key, base_values)?;
        let next = current
            .checked_add(amount)
            .ok_or(BlockStmSemanticError::Overflow { key })?;
        self.insert_prefix_value(key, next, record_write);
        Ok(())
    }

    fn apply_fee_escrow_to_prefix<DB, RecordWrite>(
        &mut self,
        db: &mut DB,
        action: Tip20FeeEscrowDelta,
        base_values: &HashMap<BlockStmAccessKey, U256>,
        record_write: &mut RecordWrite,
    ) -> Result<(), BlockStmSemanticError>
    where
        DB: Database,
        DB::Error: fmt::Display,
        RecordWrite: FnMut(&HashMap<BlockStmAccessKey, U256>, BlockStmAccessKey),
    {
        if action
            .actual_spending
            .checked_add(action.refund_amount)
            .map_or(true, |value| value != action.max_fee_precharge)
        {
            return Err(BlockStmSemanticError::FeeEscrowInvariant);
        }

        let payer_key = tip20_balance_key(action.token, action.fee_payer);
        let payer_balance = self.read_storage_with_base(db, payer_key, base_values)?;
        let payer_precharged = payer_balance.checked_sub(action.max_fee_precharge).ok_or(
            BlockStmSemanticError::InsufficientBalance {
                key: payer_key,
                available: payer_balance,
                required: action.max_fee_precharge,
            },
        )?;
        let payer_next = payer_precharged
            .checked_add(action.refund_amount)
            .ok_or(BlockStmSemanticError::Overflow { key: payer_key })?;
        self.insert_prefix_value(payer_key, payer_next, record_write);

        let fee_manager_key = tip20_balance_key(action.token, action.fee_manager);
        let fee_manager_balance = self.read_storage_with_base(db, fee_manager_key, base_values)?;
        let fee_manager_precharged = fee_manager_balance
            .checked_add(action.max_fee_precharge)
            .ok_or(BlockStmSemanticError::Overflow {
                key: fee_manager_key,
            })?;
        let fee_manager_next = fee_manager_precharged
            .checked_sub(action.refund_amount)
            .ok_or(BlockStmSemanticError::InsufficientBalance {
                key: fee_manager_key,
                available: fee_manager_precharged,
                required: action.refund_amount,
            })?;
        self.insert_prefix_value(fee_manager_key, fee_manager_next, record_write);

        Ok(())
    }

    fn apply_fee_escrow_net_to_prefix<DB, RecordWrite>(
        &mut self,
        db: &mut DB,
        action: Tip20FeeEscrowDelta,
        base_values: &HashMap<BlockStmAccessKey, U256>,
        aggregate_base_values: &mut HashMap<BlockStmAccessKey, U256>,
        fee_manager_deltas: &mut Vec<(BlockStmAccessKey, U256)>,
        record_write: &mut RecordWrite,
    ) -> Result<(), BlockStmSemanticError>
    where
        DB: Database,
        DB::Error: fmt::Display,
        RecordWrite: FnMut(&HashMap<BlockStmAccessKey, U256>, BlockStmAccessKey),
    {
        if action
            .actual_spending
            .checked_add(action.refund_amount)
            .map_or(true, |value| value != action.max_fee_precharge)
        {
            return Err(BlockStmSemanticError::FeeEscrowInvariant);
        }

        let payer_key = tip20_balance_key(action.token, action.fee_payer);
        let payer_balance = self.read_storage_with_base(db, payer_key, base_values)?;
        if payer_balance < action.max_fee_precharge {
            return Err(BlockStmSemanticError::InsufficientBalance {
                key: payer_key,
                available: payer_balance,
                required: action.max_fee_precharge,
            });
        }
        let payer_next = payer_balance.checked_sub(action.actual_spending).ok_or(
            BlockStmSemanticError::InsufficientBalance {
                key: payer_key,
                available: payer_balance,
                required: action.actual_spending,
            },
        )?;
        self.insert_prefix_value(payer_key, payer_next, record_write);

        let fee_manager_key = tip20_balance_key(action.token, action.fee_manager);
        if let Some(value) = base_values.get(&fee_manager_key).copied() {
            aggregate_base_values
                .entry(fee_manager_key)
                .or_insert(value);
        }
        Self::add_batch_delta(fee_manager_deltas, fee_manager_key, action.actual_spending)?;

        Ok(())
    }

    fn apply_tip20_plan_to_prefix<DB, RecordWrite>(
        &mut self,
        db: &mut DB,
        plan: &BlockStmTip20PrefixPlan,
        base_values: &HashMap<BlockStmAccessKey, U256>,
        aggregate_base_values: &mut HashMap<BlockStmAccessKey, U256>,
        fee_manager_deltas: &mut Vec<(BlockStmAccessKey, U256)>,
        record_write: &mut RecordWrite,
    ) -> Result<(), BlockStmSemanticError>
    where
        DB: Database,
        DB::Error: fmt::Display,
        RecordWrite: FnMut(&HashMap<BlockStmAccessKey, U256>, BlockStmAccessKey),
    {
        let combine_payer_debits = plan.transfers.iter().all(|transfer| {
            transfer.token == plan.fee.token && transfer.sender == plan.fee.fee_payer
        });
        if !combine_payer_debits {
            self.apply_fee_escrow_net_to_prefix(
                db,
                plan.fee,
                base_values,
                aggregate_base_values,
                fee_manager_deltas,
                record_write,
            )?;
            for transfer in plan.transfers.iter().copied() {
                self.sub_storage_prefix(
                    db,
                    tip20_balance_key(transfer.token, transfer.sender),
                    transfer.amount,
                    base_values,
                    record_write,
                )?;
                self.add_storage_prefix(
                    db,
                    tip20_balance_key(transfer.token, transfer.recipient),
                    transfer.amount,
                    base_values,
                    record_write,
                )?;
            }
            return Ok(());
        }

        if plan
            .fee
            .actual_spending
            .checked_add(plan.fee.refund_amount)
            .map_or(true, |value| value != plan.fee.max_fee_precharge)
        {
            return Err(BlockStmSemanticError::FeeEscrowInvariant);
        }

        let payer_key = tip20_balance_key(plan.fee.token, plan.fee.fee_payer);
        let payer_balance = self.read_storage_with_base(db, payer_key, base_values)?;
        if payer_balance < plan.fee.max_fee_precharge {
            return Err(BlockStmSemanticError::InsufficientBalance {
                key: payer_key,
                available: payer_balance,
                required: plan.fee.max_fee_precharge,
            });
        }

        let mut payer_debit = plan.fee.actual_spending;
        for transfer in plan.transfers.iter().copied() {
            payer_debit = payer_debit
                .checked_add(transfer.amount)
                .ok_or(BlockStmSemanticError::Overflow { key: payer_key })?;
        }
        let payer_next = payer_balance.checked_sub(payer_debit).ok_or(
            BlockStmSemanticError::InsufficientBalance {
                key: payer_key,
                available: payer_balance,
                required: payer_debit,
            },
        )?;
        self.insert_prefix_value(payer_key, payer_next, record_write);

        let fee_manager_key = tip20_balance_key(plan.fee.token, plan.fee.fee_manager);
        if let Some(value) = base_values.get(&fee_manager_key).copied() {
            aggregate_base_values
                .entry(fee_manager_key)
                .or_insert(value);
        }
        Self::add_batch_delta(
            fee_manager_deltas,
            fee_manager_key,
            plan.fee.actual_spending,
        )?;

        for transfer in plan.transfers.iter().copied() {
            self.add_storage_prefix(
                db,
                tip20_balance_key(transfer.token, transfer.recipient),
                transfer.amount,
                base_values,
                record_write,
            )?;
        }

        Ok(())
    }

    fn add_batch_delta(
        deltas: &mut Vec<(BlockStmAccessKey, U256)>,
        key: BlockStmAccessKey,
        amount: U256,
    ) -> Result<(), BlockStmSemanticError> {
        if let Some((_, value)) = deltas
            .iter_mut()
            .find(|(existing_key, _)| *existing_key == key)
        {
            *value = value
                .checked_add(amount)
                .ok_or(BlockStmSemanticError::Overflow { key })?;
        } else {
            deltas.push((key, amount));
        }

        Ok(())
    }

    fn sub_storage_prefix<DB, RecordWrite>(
        &mut self,
        db: &mut DB,
        key: BlockStmAccessKey,
        amount: U256,
        base_values: &HashMap<BlockStmAccessKey, U256>,
        record_write: &mut RecordWrite,
    ) -> Result<(), BlockStmSemanticError>
    where
        DB: Database,
        DB::Error: fmt::Display,
        RecordWrite: FnMut(&HashMap<BlockStmAccessKey, U256>, BlockStmAccessKey),
    {
        let current = self.read_storage_with_base(db, key, base_values)?;
        let next =
            current
                .checked_sub(amount)
                .ok_or(BlockStmSemanticError::InsufficientBalance {
                    key,
                    available: current,
                    required: amount,
                })?;
        self.insert_prefix_value(key, next, record_write);
        Ok(())
    }

    fn insert_prefix_value<RecordWrite>(
        &mut self,
        key: BlockStmAccessKey,
        value: U256,
        record_write: &mut RecordWrite,
    ) where
        RecordWrite: FnMut(&HashMap<BlockStmAccessKey, U256>, BlockStmAccessKey),
    {
        record_write(&self.values, key);
        self.values.insert(key, value);
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

    fn read_storage_with_base<DB>(
        &mut self,
        db: &mut DB,
        key: BlockStmAccessKey,
        base_values: &HashMap<BlockStmAccessKey, U256>,
    ) -> Result<U256, BlockStmSemanticError>
    where
        DB: Database,
        DB::Error: fmt::Display,
    {
        if let Some(value) = self.values.get(&key) {
            return Ok(*value);
        }
        if let Some(value) = base_values.get(&key) {
            return Ok(*value);
        }

        self.read_storage(db, key)
    }
}

fn semantic_original_values(
    result: &TempoTxResult,
    keys: &HashSet<BlockStmAccessKey>,
) -> HashMap<BlockStmAccessKey, U256> {
    let mut originals = HashMap::default();
    let state = &result.result().state;

    for key in keys {
        let BlockStmAccessKey::Storage { address, slot } = *key else {
            continue;
        };
        let Some(value) = state
            .get(&address)
            .and_then(|account| account.storage.get(&slot))
        else {
            continue;
        };
        originals.insert(*key, value.original_value());
    }

    originals
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
    rewrite_covered_storage_state(state, covered_keys, final_writes, original_values);
}

fn rewrite_covered_storage_state(
    state: &mut EvmState,
    covered_keys: &HashSet<BlockStmAccessKey>,
    final_writes: &BlockStmWriteSet,
    original_values: &HashMap<BlockStmAccessKey, U256>,
) {
    for key in covered_keys {
        rewrite_semantic_storage_key(state, *key, final_writes, original_values);
    }

    for (key, _) in final_writes.ordered() {
        if !covered_keys.contains(&key) {
            rewrite_semantic_storage_key(state, key, final_writes, original_values);
        }
    }
}

fn rewrite_semantic_storage_key(
    state: &mut EvmState,
    key: BlockStmAccessKey,
    final_writes: &BlockStmWriteSet,
    original_values: &HashMap<BlockStmAccessKey, U256>,
) {
    let BlockStmAccessKey::Storage { address, slot } = key else {
        return;
    };

    if let Some(value) = final_writes.get(&key) {
        let original = original_values
            .get(&key)
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
    fn blockstm_actions_rewrite_materializes_resolved_nonce_slots() {
        let hash = B256::repeat_byte(0x42);
        let speculative_ring_key = expiring_nonce_ring_key(0);
        let resolved_ring_key = expiring_nonce_ring_key(1);
        let ptr_key = expiring_nonce_ring_ptr_key();
        let seen_key = expiring_nonce_seen_key(hash);
        let BlockStmAccessKey::Storage {
            address,
            slot: speculative_ring_slot,
        } = speculative_ring_key
        else {
            unreachable!("nonce ring key must be storage");
        };

        let mut evm_state = EvmState::default();
        evm_state.entry(address).or_default().storage.insert(
            speculative_ring_slot,
            EvmStorageSlot::new_changed(
                U256::ZERO,
                U256::from_be_bytes(hash.0),
                TransactionId::ZERO,
            ),
        );

        let mut covered_keys = HashSet::default();
        covered_keys.insert(speculative_ring_key);
        covered_keys.insert(ptr_key);
        covered_keys.insert(seen_key);

        let mut final_writes = BlockStmWriteSet::default();
        final_writes.record(resolved_ring_key, hash);
        final_writes.record(ptr_key, U256::from(2));
        final_writes.record(seen_key, U256::from(110));

        let mut original_values = HashMap::default();
        original_values.insert(speculative_ring_key, U256::ZERO);
        original_values.insert(resolved_ring_key, U256::ZERO);
        original_values.insert(ptr_key, U256::ZERO);
        original_values.insert(seen_key, U256::ZERO);

        rewrite_covered_storage_state(
            &mut evm_state,
            &covered_keys,
            &final_writes,
            &original_values,
        );

        assert_eq!(
            storage_present_value(&evm_state, speculative_ring_key),
            U256::ZERO
        );
        assert_eq!(
            storage_present_value(&evm_state, resolved_ring_key),
            U256::from_be_bytes(hash.0)
        );
        assert_eq!(storage_present_value(&evm_state, ptr_key), U256::from(2));
        assert_eq!(storage_present_value(&evm_state, seen_key), U256::from(110));
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

    #[test]
    fn blockstm_actions_semantic_prefix_rejects_overspend_after_ordered_conflicts() {
        let token = DEFAULT_FEE_TOKEN;
        let sender = address!("0x00000000000000000000000000000000000000a1");
        let recipient = address!("0x00000000000000000000000000000000000000b2");
        let balance_key = tip20_balance_key(token, sender);
        let BlockStmAccessKey::Storage { address, slot } = balance_key else {
            unreachable!("TIP20 balance key must be storage");
        };
        let mut db = CacheDB::new(EmptyDB::default());
        db.insert_account_storage(address, slot, U256::from(9))
            .expect("storage insert should succeed");
        let mut state = BlockStmSemanticState::default();

        for tx_index in 0..9 {
            let plan = transfer_plan(tx_index, token, sender, recipient, U256::from(1));
            state.apply_plan_to_prefix(&mut db, &plan, 100).unwrap();
        }

        let plan = transfer_plan(9, token, sender, recipient, U256::from(1));
        assert!(matches!(
            state
                .apply_plan_to_prefix(&mut db, &plan, 100)
                .unwrap_err(),
            BlockStmSemanticError::InsufficientBalance {
                available,
                required,
                ..
            } if available == U256::ZERO && required == U256::from(1)
        ));
    }

    #[test]
    fn blockstm_actions_tip20_prefix_combines_payer_fee_and_transfer_debit() {
        let token = DEFAULT_FEE_TOKEN;
        let payer = address!("0x00000000000000000000000000000000000000a1");
        let recipient = address!("0x00000000000000000000000000000000000000b2");
        let beneficiary = address!("0x00000000000000000000000000000000000000c3");
        let payer_key = tip20_balance_key(token, payer);
        let BlockStmAccessKey::Storage { address, slot } = payer_key else {
            unreachable!("TIP20 balance key must be storage");
        };
        let mut db = CacheDB::new(EmptyDB::default());
        db.insert_account_storage(address, slot, U256::from(20))
            .expect("storage insert should succeed");
        let mut state = BlockStmSemanticState::default();
        let mut touched_keys = HashSet::default();
        let mut rollback = HashMap::default();
        let plan = tip20_prefix_plan(
            token,
            payer,
            payer,
            recipient,
            beneficiary,
            U256::from(10),
            U256::from(2),
            U256::from(8),
            U256::from(5),
        );

        state
            .apply_plans_to_prefix_recording(
                &mut db,
                &[&plan],
                100,
                &mut touched_keys,
                &mut rollback,
            )
            .unwrap();

        assert_eq!(state.storage_value(&payer_key), Some(U256::from(13)));
        assert_eq!(
            state.storage_value(&tip20_balance_key(token, recipient)),
            Some(U256::from(5))
        );
        assert_eq!(
            state.storage_value(&tip20_balance_key(token, TIP_FEE_MANAGER_ADDRESS)),
            Some(U256::from(2))
        );
        assert_eq!(
            state.storage_value(&fee_manager_collected_fees_key(beneficiary, token)),
            Some(U256::from(2))
        );
    }

    #[test]
    fn blockstm_actions_tip20_prefix_combined_debit_still_checks_precharge() {
        let token = DEFAULT_FEE_TOKEN;
        let payer = address!("0x00000000000000000000000000000000000000a1");
        let recipient = address!("0x00000000000000000000000000000000000000b2");
        let beneficiary = address!("0x00000000000000000000000000000000000000c3");
        let payer_key = tip20_balance_key(token, payer);
        let BlockStmAccessKey::Storage { address, slot } = payer_key else {
            unreachable!("TIP20 balance key must be storage");
        };
        let mut db = CacheDB::new(EmptyDB::default());
        db.insert_account_storage(address, slot, U256::from(9))
            .expect("storage insert should succeed");
        let mut state = BlockStmSemanticState::default();
        let mut touched_keys = HashSet::default();
        let mut rollback = HashMap::default();
        let plan = tip20_prefix_plan(
            token,
            payer,
            payer,
            recipient,
            beneficiary,
            U256::from(10),
            U256::from(1),
            U256::from(9),
            U256::from(1),
        );

        assert!(matches!(
            state
                .apply_plans_to_prefix_recording(
                    &mut db,
                    &[&plan],
                    100,
                    &mut touched_keys,
                    &mut rollback,
                )
                .unwrap_err(),
            BlockStmSemanticError::InsufficientBalance {
                available,
                required,
                ..
            } if available == U256::from(9) && required == U256::from(10)
        ));
    }

    fn transfer_plan(
        tx_index: usize,
        token: Address,
        sender: Address,
        recipient: Address,
        amount: U256,
    ) -> BlockStmSemanticPlan {
        let transfer = Tip20TransferDelta {
            token,
            sender,
            recipient,
            amount,
        };
        let covered = transfer.covered_storage_slots();
        let mut covered_keys = HashSet::default();
        covered_keys.extend(covered.iter().copied());
        let mut action_log = BlockStmActionLog::default();
        action_log.push(BlockStmAction::new(
            tx_index,
            0,
            BlockStmActionKind::Tip20TransferDelta(transfer),
            covered,
        ));
        BlockStmSemanticPlan {
            action_log,
            covered_keys,
            prefix_originals: HashMap::default(),
            semantic_prefix_reads: 1,
            tip20_prefix: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn tip20_prefix_plan(
        token: Address,
        fee_payer: Address,
        sender: Address,
        recipient: Address,
        beneficiary: Address,
        max_fee_precharge: U256,
        actual_spending: U256,
        refund_amount: U256,
        transfer_amount: U256,
    ) -> BlockStmSemanticPlan {
        BlockStmSemanticPlan {
            action_log: BlockStmActionLog::default(),
            covered_keys: HashSet::default(),
            prefix_originals: HashMap::default(),
            semantic_prefix_reads: 1,
            tip20_prefix: Some(BlockStmTip20PrefixPlan {
                nonce: None,
                fee: Tip20FeeEscrowDelta {
                    token,
                    fee_payer,
                    fee_manager: TIP_FEE_MANAGER_ADDRESS,
                    max_fee_precharge,
                    actual_spending,
                    refund_amount,
                },
                transfers: vec![Tip20TransferDelta {
                    token,
                    sender,
                    recipient,
                    amount: transfer_amount,
                }],
                collected: CollectedFeesDelta {
                    beneficiary,
                    validator_token: token,
                    amount: actual_spending,
                },
            }),
        }
    }

    fn storage_present_value(state: &EvmState, key: BlockStmAccessKey) -> U256 {
        let BlockStmAccessKey::Storage { address, slot } = key else {
            return U256::ZERO;
        };

        state
            .get(&address)
            .and_then(|account| account.storage.get(&slot))
            .map(|slot| slot.present_value)
            .unwrap_or_default()
    }
}
