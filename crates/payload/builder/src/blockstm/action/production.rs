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
    Address, B256, IntoLogData, Log, TxKind, U256,
    map::{HashMap, HashSet},
};
use alloy_sol_types::SolInterface;
use rayon::prelude::*;
use reth_evm::{Database, block::TxResult};
use reth_revm::{
    revm::context::Transaction as RevmTransaction,
    state::{EvmState, EvmStorageSlot, TransactionId},
};
use reth_transaction_pool::PoolTransaction;
use std::{
    fmt,
    time::{Duration, Instant},
};
use tempo_chainspec::{
    constants::gas::tempo_t6_discounted_payment_effective_gas_price, hardfork::TempoHardfork,
};
use tempo_evm::{TempoStrippedTxCommit, TempoTxResult};
use tempo_precompiles::{
    DEFAULT_FEE_TOKEN, NONCE_PRECOMPILE_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
    nonce::{EXPIRING_NONCE_MAX_EXPIRY_SECS, EXPIRING_NONCE_SET_CAPACITY},
    tip20::{ITIP20, TIP20Event},
};
use tempo_primitives::{TempoAddressExt, TempoTxType, transaction::calc_gas_balance_spending};
use tempo_revm::{
    calculate_aa_batch_intrinsic_gas,
    gas_params::{SSTORE_SET_COST, tempo_gas_params_with_amsterdam},
    handler::EXPIRING_NONCE_GAS,
};
use tempo_transaction_pool::transaction::TempoPooledTransaction;

/// Semantic plan captured from a successful real execution attempt.
#[derive(Debug, Clone)]
pub struct BlockStmSemanticPlan {
    tx_index: usize,
    action_log: BlockStmActionLog,
    covered_keys: HashSet<BlockStmAccessKey>,
    prefix_originals: HashMap<BlockStmAccessKey, U256>,
    semantic_prefix_reads: usize,
    tip20_prefix: Option<BlockStmTip20PrefixPlan>,
}

impl BlockStmSemanticPlan {
    /// Transaction index this semantic plan was captured for.
    pub const fn tx_index(&self) -> usize {
        self.tx_index
    }

    /// Keys whose speculative reads and writes are resolved by ordered semantic replay.
    pub fn covered_keys(&self) -> &HashSet<BlockStmAccessKey> {
        &self.covered_keys
    }

    /// Number of actions captured for metrics and tests.
    pub fn action_count(&self) -> usize {
        self.action_log.actions().len() + self.semantic_prefix_reads
    }

    /// Converts this captured plan into an immutable semantic reduction record.
    pub fn to_record(&self, incarnation: usize) -> Option<BlockStmSemanticRecord> {
        let tip20 = self.tip20_prefix.clone()?;
        if tip20
            .fee
            .actual_spending
            .checked_add(tip20.fee.refund_amount)
            .map_or(true, |value| value != tip20.fee.max_fee_precharge)
        {
            return None;
        }

        Some(BlockStmSemanticRecord {
            tx_index: self.tx_index,
            incarnation,
            covered_keys: self.covered_keys.clone(),
            original_values: self.prefix_originals.clone(),
            tip20,
        })
    }
}

#[derive(Debug, Clone)]
struct BlockStmTip20PrefixPlan {
    nonce: Option<(B256, u64)>,
    fee: Tip20FeeEscrowDelta,
    transfers: Vec<Tip20TransferDelta>,
    collected: CollectedFeesDelta,
}

/// Template proven by one real EVM execution and reused for identical simple TIP20 payments.
#[derive(Debug, Clone)]
pub struct BlockStmDirectTip20Template {
    shape: BlockStmDirectTip20Shape,
    state_gas_used: u64,
    blob_gas_used: u64,
    execution_gas_delta: u64,
    discounted_fee_price: bool,
}

/// Direct semantic execution output for a simple TIP20 payment.
#[derive(Debug)]
pub struct BlockStmDirectTip20Execution {
    pub semantic_plan: BlockStmSemanticPlan,
    pub commit: TempoStrippedTxCommit,
    pub validator_fee: U256,
    pub block_gas_used: u64,
    pub state_gas_used: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BlockStmDirectTip20Shape {
    tx_type: TempoTxType,
    call_kinds: Vec<BlockStmDirectTip20CallKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockStmDirectTip20CallKind {
    Transfer,
    TransferWithMemo,
}

#[derive(Debug, Clone, Copy)]
struct SimpleTip20TransferCall {
    transfer: Tip20TransferDelta,
    memo: Option<B256>,
}

/// Immutable semantic record produced by one accepted speculative attempt.
#[derive(Debug, Clone)]
pub struct BlockStmSemanticRecord {
    tx_index: usize,
    incarnation: usize,
    covered_keys: HashSet<BlockStmAccessKey>,
    original_values: HashMap<BlockStmAccessKey, U256>,
    tip20: BlockStmTip20PrefixPlan,
}

impl BlockStmSemanticRecord {
    /// Transaction index for deterministic ordering.
    pub const fn tx_index(&self) -> usize {
        self.tx_index
    }

    /// Incarnation this record came from.
    pub const fn incarnation(&self) -> usize {
        self.incarnation
    }

    /// Covered semantic keys.
    pub fn covered_keys(&self) -> &HashSet<BlockStmAccessKey> {
        &self.covered_keys
    }
}

/// Timings collected while reducing semantic records.
#[derive(Debug, Clone, Copy, Default)]
pub struct BlockStmSemanticReductionTimings {
    pub lane_build_elapsed: Duration,
    pub lane_reduce_elapsed: Duration,
}

/// Final deterministic semantic reduction for a batch of records.
#[derive(Debug, Clone, Default)]
pub struct BlockStmSemanticReduction {
    values: HashMap<BlockStmAccessKey, U256>,
    touched_keys: HashSet<BlockStmAccessKey>,
    original_values: HashMap<BlockStmAccessKey, U256>,
    invalid_tx_indexes: HashSet<usize>,
    pub lane_count: usize,
    pub fixpoint_iterations: usize,
    pub timings: BlockStmSemanticReductionTimings,
}

impl BlockStmSemanticReduction {
    /// Returns all touched semantic keys.
    pub fn touched_keys(&self) -> &HashSet<BlockStmAccessKey> {
        &self.touched_keys
    }

    /// Returns original storage values for touched semantic keys.
    pub fn original_values(&self) -> &HashMap<BlockStmAccessKey, U256> {
        &self.original_values
    }

    /// Returns semantically invalid transaction indexes removed by the reducer.
    pub fn invalid_tx_indexes(&self) -> &HashSet<usize> {
        &self.invalid_tx_indexes
    }

    /// Returns a reduced storage value.
    pub fn storage_value(&self, key: &BlockStmAccessKey) -> Option<U256> {
        self.values.get(key).copied()
    }
}

#[derive(Debug, Clone, Copy)]
struct SemanticBalanceOp {
    tx_index: usize,
    record_index: usize,
    order: u32,
    kind: SemanticBalanceOpKind,
}

#[derive(Debug, Clone, Copy)]
enum SemanticBalanceOpKind {
    Debit(U256),
    Credit(U256),
}

#[derive(Debug, Clone)]
struct SemanticBalanceLane {
    key: BlockStmAccessKey,
    ops: Vec<SemanticBalanceOp>,
}

#[derive(Debug, Clone)]
struct SemanticLaneOutput {
    key: BlockStmAccessKey,
    value: U256,
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

    let actual_spending = result.validator_fee();
    let mut plan = build_tip20_semantic_plan(
        tx_index,
        tx,
        beneficiary,
        actual_spending,
        HashMap::default(),
        Some(write_set),
    )?;
    plan.prefix_originals = semantic_original_values(result, &plan.covered_keys);

    if has_uncovered_hot_storage_write(write_set, tx.effective_fee_token(), &plan.covered_keys) {
        return None;
    }

    Some(plan)
}

impl BlockStmDirectTip20Template {
    /// Creates a direct semantic template from one successful EVM execution.
    pub fn from_evm_result(
        tx: &TempoPooledTransaction,
        result: &TempoTxResult,
        base_fee: u64,
        spec: TempoHardfork,
        amsterdam_eip8037_enabled: bool,
    ) -> Option<Self> {
        if !result.result().result.is_success() || result.state_gas_used() != 0 {
            return None;
        }

        let sender = tx.sender();
        let calls = simple_tip20_transfer_calls(tx, sender)?;
        let shape = direct_tip20_shape(tx, sender, None)?;
        let tx_gas_used = result.result().result.tx_gas_used();
        let regular_gas_used = result.result().result.gas().block_regular_gas_used();
        let state_gas_used = result.result().result.gas().block_state_gas_used();
        let block_gas_used = result.block_gas_used();
        if tx_gas_used != regular_gas_used
            || regular_gas_used != block_gas_used
            || state_gas_used != 0
        {
            return None;
        }
        let initial_regular_gas =
            direct_tip20_initial_regular_gas(tx, spec, amsterdam_eip8037_enabled)?;
        let execution_gas_delta = tx_gas_used.checked_sub(initial_regular_gas)?;

        let normal_effective_price = tx.effective_gas_price(Some(base_fee));
        let normal_fee = calc_gas_balance_spending(tx_gas_used, normal_effective_price);
        let discounted_effective_price =
            tempo_t6_discounted_payment_effective_gas_price(normal_effective_price);
        let discounted_fee = calc_gas_balance_spending(tx_gas_used, discounted_effective_price);
        let validator_fee = result.validator_fee();
        let discounted_fee_price = if normal_fee == validator_fee {
            false
        } else if tx_gas_used <= SSTORE_SET_COST && discounted_fee == validator_fee {
            true
        } else {
            return None;
        };

        let expected_logs =
            tip20_semantic_logs(&calls, tx.inner().fee_payer(sender).ok()?, validator_fee);
        if result.result().result.logs() != expected_logs.as_slice() {
            return None;
        }

        Some(Self {
            shape,
            state_gas_used,
            blob_gas_used: 0,
            execution_gas_delta,
            discounted_fee_price,
        })
    }

    /// Executes an identical simple TIP20 payment directly through semantic actions.
    pub fn execute(
        &self,
        tx_index: usize,
        tx: &TempoPooledTransaction,
        beneficiary: Address,
        base_fee: u64,
        block_timestamp: u64,
        spec: TempoHardfork,
        amsterdam_eip8037_enabled: bool,
    ) -> Option<BlockStmDirectTip20Execution> {
        let sender = tx.sender();
        if direct_tip20_shape(tx, sender, Some(block_timestamp))? != self.shape {
            return None;
        }
        let calls = simple_tip20_transfer_calls(tx, sender)?;
        let fee_payer = tx.inner().fee_payer(sender).ok()?;
        let initial_regular_gas =
            direct_tip20_initial_regular_gas(tx, spec, amsterdam_eip8037_enabled)?;
        let tx_gas_used = initial_regular_gas.checked_add(self.execution_gas_delta)?;

        let mut effective_price = tx.effective_gas_price(Some(base_fee));
        if self.discounted_fee_price {
            effective_price = tempo_t6_discounted_payment_effective_gas_price(effective_price);
        }
        let actual_spending = calc_gas_balance_spending(tx_gas_used, effective_price);
        let semantic_plan = build_tip20_semantic_plan(
            tx_index,
            tx,
            beneficiary,
            actual_spending,
            HashMap::default(),
            None,
        )?;
        let logs = tip20_semantic_logs(&calls, fee_payer, actual_spending);
        let commit = TempoStrippedTxCommit::successful_non_shared_payment(
            tx.inner().tx_type(),
            tx_gas_used,
            tx_gas_used,
            self.state_gas_used,
            self.blob_gas_used,
            tx_gas_used,
            logs,
        );

        Some(BlockStmDirectTip20Execution {
            semantic_plan,
            commit,
            validator_fee: actual_spending,
            block_gas_used: tx_gas_used,
            state_gas_used: self.state_gas_used,
        })
    }
}

fn build_tip20_semantic_plan(
    tx_index: usize,
    tx: &TempoPooledTransaction,
    beneficiary: Address,
    actual_spending: U256,
    prefix_originals: HashMap<BlockStmAccessKey, U256>,
    write_set: Option<&BlockStmWriteSet>,
) -> Option<BlockStmSemanticPlan> {
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
        if let Some(write_set) = write_set {
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
    let tip20_prefix = Some(BlockStmTip20PrefixPlan {
        nonce: prefix_nonce,
        fee,
        transfers,
        collected,
    });

    Some(BlockStmSemanticPlan {
        tx_index,
        action_log,
        covered_keys,
        prefix_originals,
        semantic_prefix_reads,
        tip20_prefix,
    })
}

/// Reduces TIP20 semantic records through deterministic key lanes.
///
/// This keeps each semantic record immutable after worker execution, groups effects by touched
/// storage key, and serializes only the operations within a single key lane. Different lanes are
/// reduced concurrently by named semantic worker threads. Invalid records are removed
/// monotonically and the affected lanes are recomputed until a fixed point is reached.
pub fn reduce_tip20_semantic_records<DB>(
    db: &mut DB,
    records: &[BlockStmSemanticRecord],
    block_timestamp: u64,
    worker_count: usize,
) -> Result<BlockStmSemanticReduction, BlockStmSemanticError>
where
    DB: Database,
    DB::Error: fmt::Display,
{
    if records.is_empty() {
        return Ok(BlockStmSemanticReduction::default());
    }

    let lane_build_started = Instant::now();
    let mut original_values = collect_semantic_original_values(db, records)?;
    let lanes = build_semantic_balance_lanes(records, worker_count);
    hydrate_balance_lane_base_values(db, &lanes, &mut original_values)?;
    let lane_build_elapsed = lane_build_started.elapsed();

    let mut active = vec![true; records.len()];
    let mut invalid_tx_indexes = HashSet::default();
    let mut fixpoint_iterations = 0usize;
    let mut lane_reduce_elapsed = Duration::ZERO;

    loop {
        fixpoint_iterations += 1;
        let reduce_started = Instant::now();
        let (balance_outputs, mut invalid_record_indexes) =
            reduce_balance_lanes(&lanes, &original_values, &active, worker_count)?;
        let nonce_outputs = reduce_nonce_lane(
            db,
            records,
            &active,
            block_timestamp,
            &mut original_values,
            &mut invalid_record_indexes,
        )?;
        lane_reduce_elapsed += reduce_started.elapsed();

        if invalid_record_indexes.is_empty() {
            let mut values = HashMap::default();
            let mut touched_keys = HashSet::default();
            for output in balance_outputs.into_iter().chain(nonce_outputs.into_iter()) {
                touched_keys.insert(output.key);
                values.insert(output.key, output.value);
            }
            return Ok(BlockStmSemanticReduction {
                values,
                touched_keys,
                original_values,
                invalid_tx_indexes,
                lane_count: lanes.len() + 1,
                fixpoint_iterations,
                timings: BlockStmSemanticReductionTimings {
                    lane_build_elapsed,
                    lane_reduce_elapsed,
                },
            });
        }

        let mut removed_any = false;
        for record_index in invalid_record_indexes {
            if active[record_index] {
                active[record_index] = false;
                invalid_tx_indexes.insert(records[record_index].tx_index);
                removed_any = true;
            }
        }

        if !removed_any {
            let mut values = HashMap::default();
            let mut touched_keys = HashSet::default();
            for output in balance_outputs.into_iter().chain(nonce_outputs.into_iter()) {
                touched_keys.insert(output.key);
                values.insert(output.key, output.value);
            }
            return Ok(BlockStmSemanticReduction {
                values,
                touched_keys,
                original_values,
                invalid_tx_indexes,
                lane_count: lanes.len() + 1,
                fixpoint_iterations,
                timings: BlockStmSemanticReductionTimings {
                    lane_build_elapsed,
                    lane_reduce_elapsed,
                },
            });
        }
    }
}

fn collect_semantic_original_values<DB>(
    _db: &mut DB,
    records: &[BlockStmSemanticRecord],
) -> Result<HashMap<BlockStmAccessKey, U256>, BlockStmSemanticError>
where
    DB: Database,
    DB::Error: fmt::Display,
{
    let mut original_values = HashMap::default();
    for record in records {
        original_values.reserve(record.original_values.len());
        for (key, value) in &record.original_values {
            original_values.entry(*key).or_insert(*value);
        }
    }
    Ok(original_values)
}

fn hydrate_balance_lane_base_values<DB>(
    db: &mut DB,
    lanes: &[SemanticBalanceLane],
    original_values: &mut HashMap<BlockStmAccessKey, U256>,
) -> Result<(), BlockStmSemanticError>
where
    DB: Database,
    DB::Error: fmt::Display,
{
    for lane in lanes {
        read_semantic_base_value(db, lane.key, original_values)?;
    }
    Ok(())
}

fn read_semantic_base_value<DB>(
    db: &mut DB,
    key: BlockStmAccessKey,
    original_values: &mut HashMap<BlockStmAccessKey, U256>,
) -> Result<U256, BlockStmSemanticError>
where
    DB: Database,
    DB::Error: fmt::Display,
{
    if let Some(value) = original_values.get(&key).copied() {
        return Ok(value);
    }

    let value = match key {
        BlockStmAccessKey::Storage { address, slot } => db
            .storage(address, slot)
            .map_err(|err| BlockStmSemanticError::Database(err.to_string()))?,
        _ => U256::ZERO,
    };
    original_values.insert(key, value);
    Ok(value)
}

fn build_semantic_balance_lanes(
    records: &[BlockStmSemanticRecord],
    worker_count: usize,
) -> Vec<SemanticBalanceLane> {
    let worker_count = worker_count.max(1).min(records.len().max(1));
    let chunk_len = records.len().div_ceil(worker_count).max(1);
    let local_maps = records
        .par_chunks(chunk_len)
        .enumerate()
        .map(|(worker, chunk)| {
            let mut lanes = HashMap::<BlockStmAccessKey, Vec<SemanticBalanceOp>>::default();
            for (chunk_index, record) in chunk.iter().enumerate() {
                let record_index = worker * chunk_len + chunk_index;
                record_balance_ops(record_index, record, &mut lanes);
            }
            lanes
        })
        .collect::<Vec<_>>();

    let mut merged = HashMap::<BlockStmAccessKey, Vec<SemanticBalanceOp>>::default();
    for local in local_maps {
        for (key, ops) in local {
            merged.entry(key).or_default().extend(ops);
        }
    }

    let mut lanes = merged
        .into_iter()
        .map(|(key, mut ops)| {
            ops.sort_unstable_by_key(|op| (op.tx_index, op.order));
            SemanticBalanceLane { key, ops }
        })
        .collect::<Vec<_>>();
    lanes.sort_unstable_by_key(|lane| lane.key);
    lanes
}

fn record_balance_ops(
    record_index: usize,
    record: &BlockStmSemanticRecord,
    lanes: &mut HashMap<BlockStmAccessKey, Vec<SemanticBalanceOp>>,
) {
    let plan = &record.tip20;
    let mut order = 0u32;
    let mut push_op = |key: BlockStmAccessKey, kind: SemanticBalanceOpKind, order: u32| {
        lanes.entry(key).or_default().push(SemanticBalanceOp {
            tx_index: record.tx_index,
            record_index,
            order,
            kind,
        });
    };

    let payer_key = tip20_balance_key(plan.fee.token, plan.fee.fee_payer);
    let fee_manager_key = tip20_balance_key(plan.fee.token, plan.fee.fee_manager);
    push_op(
        payer_key,
        SemanticBalanceOpKind::Debit(plan.fee.max_fee_precharge),
        order,
    );
    order += 1;
    push_op(
        fee_manager_key,
        SemanticBalanceOpKind::Credit(plan.fee.max_fee_precharge),
        order,
    );
    order += 1;
    push_op(
        fee_manager_key,
        SemanticBalanceOpKind::Debit(plan.fee.refund_amount),
        order,
    );
    order += 1;
    push_op(
        payer_key,
        SemanticBalanceOpKind::Credit(plan.fee.refund_amount),
        order,
    );
    order += 1;

    for transfer in plan.transfers.iter().copied() {
        push_op(
            tip20_balance_key(transfer.token, transfer.sender),
            SemanticBalanceOpKind::Debit(transfer.amount),
            order,
        );
        order += 1;
        push_op(
            tip20_balance_key(transfer.token, transfer.recipient),
            SemanticBalanceOpKind::Credit(transfer.amount),
            order,
        );
        order += 1;
    }

    push_op(
        fee_manager_collected_fees_key(plan.collected.beneficiary, plan.collected.validator_token),
        SemanticBalanceOpKind::Credit(plan.collected.amount),
        order,
    );
}

fn reduce_balance_lanes(
    lanes: &[SemanticBalanceLane],
    original_values: &HashMap<BlockStmAccessKey, U256>,
    active: &[bool],
    worker_count: usize,
) -> Result<(Vec<SemanticLaneOutput>, HashSet<usize>), BlockStmSemanticError> {
    if lanes.is_empty() {
        return Ok((Vec::new(), HashSet::default()));
    }

    let worker_count = worker_count.max(1).min(lanes.len());
    let chunk_len = lanes.len().div_ceil(worker_count).max(1);
    let partials = lanes
        .par_chunks(chunk_len)
        .map(|chunk| {
            let mut outputs = Vec::with_capacity(chunk.len());
            let mut invalid = HashSet::<usize>::default();
            for lane in chunk {
                let (value, lane_invalid) = reduce_balance_lane(lane, original_values, active)?;
                outputs.push(SemanticLaneOutput {
                    key: lane.key,
                    value,
                });
                invalid.extend(lane_invalid);
            }
            Ok::<_, BlockStmSemanticError>((outputs, invalid))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut outputs = Vec::with_capacity(lanes.len());
    let mut invalid = HashSet::default();
    for (mut partial_outputs, partial_invalid) in partials {
        outputs.append(&mut partial_outputs);
        invalid.extend(partial_invalid);
    }
    outputs.sort_unstable_by_key(|output| output.key);
    Ok((outputs, invalid))
}

fn reduce_balance_lane(
    lane: &SemanticBalanceLane,
    original_values: &HashMap<BlockStmAccessKey, U256>,
    active: &[bool],
) -> Result<(U256, HashSet<usize>), BlockStmSemanticError> {
    let mut value = original_values.get(&lane.key).copied().unwrap_or_default();
    let mut invalid = HashSet::default();

    for op in &lane.ops {
        if !active[op.record_index] || invalid.contains(&op.record_index) {
            continue;
        }
        match op.kind {
            SemanticBalanceOpKind::Debit(amount) => {
                if value < amount {
                    invalid.insert(op.record_index);
                    continue;
                }
                value = value
                    .checked_sub(amount)
                    .expect("semantic balance debit checked above");
            }
            SemanticBalanceOpKind::Credit(amount) => {
                let Some(next) = value.checked_add(amount) else {
                    invalid.insert(op.record_index);
                    continue;
                };
                value = next;
            }
        }
    }

    Ok((value, invalid))
}

fn reduce_nonce_lane<DB>(
    db: &mut DB,
    records: &[BlockStmSemanticRecord],
    active: &[bool],
    block_timestamp: u64,
    original_values: &mut HashMap<BlockStmAccessKey, U256>,
    invalid_record_indexes: &mut HashSet<usize>,
) -> Result<Vec<SemanticLaneOutput>, BlockStmSemanticError>
where
    DB: Database,
    DB::Error: fmt::Display,
{
    let ptr_key = expiring_nonce_ring_ptr_key();
    let mut ptr = read_semantic_base_value(db, ptr_key, original_values)?.to::<u32>();
    let mut values = HashMap::<BlockStmAccessKey, U256>::default();
    values.insert(ptr_key, U256::from(ptr));

    for (record_index, record) in records.iter().enumerate() {
        if !active[record_index] {
            continue;
        }
        let Some((nonce_hash, valid_before)) = record.tip20.nonce else {
            continue;
        };

        if valid_before <= block_timestamp
            || valid_before > block_timestamp.saturating_add(EXPIRING_NONCE_MAX_EXPIRY_SECS)
        {
            invalid_record_indexes.insert(record_index);
            continue;
        }

        let seen_key = expiring_nonce_seen_key(nonce_hash);
        let seen_expiry = values
            .get(&seen_key)
            .copied()
            .unwrap_or(read_semantic_base_value(db, seen_key, original_values)?);
        if !seen_expiry.is_zero() && seen_expiry > U256::from(block_timestamp) {
            invalid_record_indexes.insert(record_index);
            continue;
        }

        let ring_slot = ptr % EXPIRING_NONCE_SET_CAPACITY;
        let ring_key = expiring_nonce_ring_key(ring_slot);
        let old_hash = B256::from(
            values
                .get(&ring_key)
                .copied()
                .unwrap_or(read_semantic_base_value(db, ring_key, original_values)?),
        );
        if old_hash != B256::ZERO {
            let old_seen_key = expiring_nonce_seen_key(old_hash);
            let old_expiry = values
                .get(&old_seen_key)
                .copied()
                .unwrap_or(read_semantic_base_value(db, old_seen_key, original_values)?);
            if !old_expiry.is_zero() && old_expiry > U256::from(block_timestamp) {
                invalid_record_indexes.insert(record_index);
                continue;
            }
            values.insert(old_seen_key, U256::ZERO);
        }

        values.insert(ring_key, U256::from_be_bytes(nonce_hash.0));
        values.insert(seen_key, U256::from(valid_before));
        ptr = if ring_slot + 1 >= EXPIRING_NONCE_SET_CAPACITY {
            0
        } else {
            ring_slot + 1
        };
        values.insert(ptr_key, U256::from(ptr));
    }

    let mut outputs = values
        .into_iter()
        .map(|(key, value)| SemanticLaneOutput { key, value })
        .collect::<Vec<_>>();
    outputs.sort_unstable_by_key(|output| output.key);
    Ok(outputs)
}

impl BlockStmSemanticState {
    /// Reserves space for additional ordered-prefix values.
    pub fn reserve(&mut self, additional: usize) {
        self.values.reserve(additional);
    }

    /// Merges a completed semantic reduction into the ordered prefix overlay.
    pub fn apply_reduction(&mut self, reduction: &BlockStmSemanticReduction) {
        self.values.reserve(reduction.touched_keys().len());
        for key in reduction.touched_keys() {
            if let Some(value) = reduction.storage_value(key) {
                self.values.insert(*key, value);
            }
        }
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

fn direct_tip20_shape(
    tx: &TempoPooledTransaction,
    sender: Address,
    block_timestamp: Option<u64>,
) -> Option<BlockStmDirectTip20Shape> {
    if tx.effective_fee_token() != DEFAULT_FEE_TOKEN || tx.inner().fee_payer(sender).ok()? != sender
    {
        return None;
    }
    if !tx.is_expiring_nonce() {
        return None;
    }

    let aa = tx.inner().as_aa()?.tx();
    if aa.key_authorization.is_some()
        || !aa.tempo_authorization_list.is_empty()
        || !aa.access_list.is_empty()
        || aa.calls.iter().any(|call| !call.value.is_zero())
    {
        return None;
    }
    if let Some(block_timestamp) = block_timestamp
        && aa
            .valid_after
            .is_some_and(|valid_after| valid_after.get() > block_timestamp)
    {
        return None;
    }

    let calls = simple_tip20_transfer_calls(tx, sender)?;
    if calls.is_empty()
        || calls.iter().any(|call| {
            call.transfer.token != DEFAULT_FEE_TOKEN
                || call.transfer.sender.is_zero()
                || call.transfer.sender.is_virtual()
                || call.transfer.recipient.is_zero()
                || call.transfer.recipient.is_virtual()
                || call.transfer.recipient == call.transfer.sender
        })
    {
        return None;
    }

    Some(BlockStmDirectTip20Shape {
        tx_type: tx.inner().tx_type(),
        call_kinds: calls
            .iter()
            .map(|call| {
                if call.memo.is_some() {
                    BlockStmDirectTip20CallKind::TransferWithMemo
                } else {
                    BlockStmDirectTip20CallKind::Transfer
                }
            })
            .collect(),
    })
}

fn direct_tip20_initial_regular_gas(
    tx: &TempoPooledTransaction,
    spec: TempoHardfork,
    amsterdam_eip8037_enabled: bool,
) -> Option<u64> {
    let tx_env = tx.tx_env();
    let aa_env = tx_env.tempo_tx_env.as_ref()?;
    if aa_env.nonce_key != tempo_primitives::transaction::TEMPO_EXPIRING_NONCE_KEY {
        return None;
    }

    let gas_params = tempo_gas_params_with_amsterdam(spec, amsterdam_eip8037_enabled);
    let gas =
        calculate_aa_batch_intrinsic_gas(aa_env, &gas_params, tx_env.access_list(), spec).ok()?;

    gas.initial_regular_gas.checked_add(EXPIRING_NONCE_GAS)
}

fn simple_tip20_transfer_calls(
    tx: &TempoPooledTransaction,
    sender: Address,
) -> Option<Vec<SimpleTip20TransferCall>> {
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
            ITIP20::ITIP20Calls::transfer(call) => SimpleTip20TransferCall {
                transfer: Tip20TransferDelta {
                    token,
                    sender,
                    recipient: call.to,
                    amount: call.amount,
                },
                memo: None,
            },
            ITIP20::ITIP20Calls::transferWithMemo(call) => SimpleTip20TransferCall {
                transfer: Tip20TransferDelta {
                    token,
                    sender,
                    recipient: call.to,
                    amount: call.amount,
                },
                memo: Some(call.memo),
            },
            _ => return None,
        };
        transfers.push(transfer);
    }

    Some(transfers)
}

fn simple_tip20_transfers(
    tx: &TempoPooledTransaction,
    sender: Address,
) -> Option<Vec<Tip20TransferDelta>> {
    Some(
        simple_tip20_transfer_calls(tx, sender)?
            .into_iter()
            .map(|call| call.transfer)
            .collect(),
    )
}

fn tip20_semantic_logs(
    calls: &[SimpleTip20TransferCall],
    fee_payer: Address,
    actual_spending: U256,
) -> Vec<Log> {
    let mut logs = Vec::with_capacity(calls.len().saturating_mul(2).saturating_add(1));
    for call in calls {
        let transfer = call.transfer;
        logs.push(tip20_log(
            transfer.token,
            TIP20Event::transfer(transfer.sender, transfer.recipient, transfer.amount),
        ));
        if let Some(memo) = call.memo {
            logs.push(tip20_log(
                transfer.token,
                TIP20Event::transfer_with_memo(
                    transfer.sender,
                    transfer.recipient,
                    transfer.amount,
                    memo,
                ),
            ));
        }
    }
    logs.push(tip20_log(
        DEFAULT_FEE_TOKEN,
        TIP20Event::transfer(fee_payer, TIP_FEE_MANAGER_ADDRESS, actual_spending),
    ));
    logs
}

fn tip20_log(address: Address, event: impl IntoLogData) -> Log {
    let data = event.into_log_data();
    Log::new_unchecked(address, data.topics().to_vec(), data.data.clone())
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
            0,
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
            0,
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

    #[test]
    fn blockstm_actions_tip20_semantic_record_is_deterministic() {
        let token = DEFAULT_FEE_TOKEN;
        let payer = address!("0x00000000000000000000000000000000000000a1");
        let recipient = address!("0x00000000000000000000000000000000000000b2");
        let beneficiary = address!("0x00000000000000000000000000000000000000c3");
        let plan = tip20_prefix_plan(
            7,
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

        let first = plan.to_record(3).expect("TIP20 plan must become record");
        let second = plan.to_record(3).expect("TIP20 plan must become record");

        assert_eq!(first.tx_index(), 7);
        assert_eq!(first.incarnation(), 3);
        assert_eq!(first.covered_keys(), second.covered_keys());
        assert_eq!(first.original_values, second.original_values);
        assert_eq!(first.tip20.transfers.len(), 1);
        assert_eq!(first.tip20.fee.max_fee_precharge, U256::from(10));
        assert_eq!(first.tip20.collected.amount, U256::from(2));
    }

    #[test]
    fn blockstm_actions_semantic_reduce_parallel_independent_spenders() {
        let token = DEFAULT_FEE_TOKEN;
        let recipient = address!("0x00000000000000000000000000000000000000b2");
        let beneficiary = address!("0x00000000000000000000000000000000000000c3");
        let mut db = CacheDB::new(EmptyDB::default());
        let mut records = Vec::new();

        for tx_index in 0..10 {
            let sender = Address::from([tx_index as u8 + 1; 20]);
            insert_storage(&mut db, tip20_balance_key(token, sender), U256::from(5));
            records.push(
                tip20_prefix_plan(
                    tx_index,
                    token,
                    sender,
                    sender,
                    recipient,
                    beneficiary,
                    U256::ZERO,
                    U256::ZERO,
                    U256::ZERO,
                    U256::from(1),
                )
                .to_record(0)
                .expect("TIP20 plan must become record"),
            );
        }

        let reduction = reduce_tip20_semantic_records(&mut db, &records, 100, 4).unwrap();

        assert!(reduction.lane_count > 1);
        assert!(reduction.invalid_tx_indexes().is_empty());
        assert_eq!(
            reduction.storage_value(&tip20_balance_key(token, recipient)),
            Some(U256::from(10))
        );
        for tx_index in 0..10 {
            let sender = Address::from([tx_index as u8 + 1; 20]);
            assert_eq!(
                reduction.storage_value(&tip20_balance_key(token, sender)),
                Some(U256::from(4))
            );
        }
    }

    #[test]
    fn blockstm_actions_semantic_reduce_rejects_first_ordered_overspend() {
        let token = DEFAULT_FEE_TOKEN;
        let sender = address!("0x00000000000000000000000000000000000000a1");
        let recipient = address!("0x00000000000000000000000000000000000000b2");
        let beneficiary = address!("0x00000000000000000000000000000000000000c3");
        let mut db = CacheDB::new(EmptyDB::default());
        insert_storage(&mut db, tip20_balance_key(token, sender), U256::from(9));
        let records = (0..10)
            .map(|tx_index| {
                tip20_prefix_plan(
                    tx_index,
                    token,
                    sender,
                    sender,
                    recipient,
                    beneficiary,
                    U256::ZERO,
                    U256::ZERO,
                    U256::ZERO,
                    U256::from(1),
                )
                .to_record(0)
                .expect("TIP20 plan must become record")
            })
            .collect::<Vec<_>>();

        let reduction = reduce_tip20_semantic_records(&mut db, &records, 100, 4).unwrap();

        assert_eq!(reduction.invalid_tx_indexes(), &HashSet::from_iter([9]));
        assert_eq!(
            reduction.storage_value(&tip20_balance_key(token, sender)),
            Some(U256::ZERO)
        );
        assert_eq!(
            reduction.storage_value(&tip20_balance_key(token, recipient)),
            Some(U256::from(9))
        );
        assert_eq!(reduction.fixpoint_iterations, 2);
    }

    #[test]
    fn blockstm_actions_semantic_reduce_checks_fee_precharge_before_refund() {
        let token = DEFAULT_FEE_TOKEN;
        let payer = address!("0x00000000000000000000000000000000000000a1");
        let recipient = address!("0x00000000000000000000000000000000000000b2");
        let beneficiary = address!("0x00000000000000000000000000000000000000c3");
        let mut db = CacheDB::new(EmptyDB::default());
        insert_storage(&mut db, tip20_balance_key(token, payer), U256::from(9));
        let record = tip20_prefix_plan(
            0,
            token,
            payer,
            payer,
            recipient,
            beneficiary,
            U256::from(10),
            U256::from(1),
            U256::from(9),
            U256::from(1),
        )
        .to_record(0)
        .expect("TIP20 plan must become record");

        let reduction = reduce_tip20_semantic_records(&mut db, &[record], 100, 4).unwrap();

        assert_eq!(reduction.invalid_tx_indexes(), &HashSet::from_iter([0]));
        assert_eq!(
            reduction.storage_value(&tip20_balance_key(token, payer)),
            Some(U256::from(9))
        );
        assert_eq!(
            reduction.storage_value(&tip20_balance_key(token, recipient)),
            Some(U256::ZERO)
        );
    }

    #[test]
    fn blockstm_actions_semantic_reduce_rejects_duplicate_nonce() {
        let token = DEFAULT_FEE_TOKEN;
        let sender = address!("0x00000000000000000000000000000000000000a1");
        let recipient = address!("0x00000000000000000000000000000000000000b2");
        let beneficiary = address!("0x00000000000000000000000000000000000000c3");
        let nonce_hash = B256::repeat_byte(0x42);
        let mut db = CacheDB::new(EmptyDB::default());
        insert_storage(&mut db, tip20_balance_key(token, sender), U256::from(10));
        let records = (0..2)
            .map(|tx_index| {
                tip20_prefix_plan_with_nonce(
                    tx_index,
                    token,
                    sender,
                    sender,
                    recipient,
                    beneficiary,
                    U256::ZERO,
                    U256::ZERO,
                    U256::ZERO,
                    U256::from(1),
                    nonce_hash,
                    110,
                )
                .to_record(0)
                .expect("TIP20 plan must become record")
            })
            .collect::<Vec<_>>();

        let reduction = reduce_tip20_semantic_records(&mut db, &records, 100, 4).unwrap();

        assert_eq!(reduction.invalid_tx_indexes(), &HashSet::from_iter([1]));
        assert_eq!(
            reduction.storage_value(&expiring_nonce_ring_key(0)),
            Some(U256::from_be_bytes(nonce_hash.0))
        );
        assert_eq!(
            reduction.storage_value(&expiring_nonce_ring_ptr_key()),
            Some(U256::from(1))
        );
        assert_eq!(
            reduction.storage_value(&tip20_balance_key(token, sender)),
            Some(U256::from(9))
        );
    }

    #[test]
    fn blockstm_actions_semantic_reduce_handles_shared_recipient_and_fee_payer() {
        let token = DEFAULT_FEE_TOKEN;
        let fee_payer = address!("0x00000000000000000000000000000000000000a1");
        let recipient = address!("0x00000000000000000000000000000000000000b2");
        let beneficiary = address!("0x00000000000000000000000000000000000000c3");
        let mut db = CacheDB::new(EmptyDB::default());
        insert_storage(
            &mut db,
            tip20_balance_key(token, fee_payer),
            U256::from(100),
        );
        let records = (0..10)
            .map(|tx_index| {
                let sender = Address::from([tx_index as u8 + 10; 20]);
                insert_storage(&mut db, tip20_balance_key(token, sender), U256::from(10));
                tip20_prefix_plan(
                    tx_index,
                    token,
                    fee_payer,
                    sender,
                    recipient,
                    beneficiary,
                    U256::from(1),
                    U256::from(1),
                    U256::ZERO,
                    U256::from(1),
                )
                .to_record(0)
                .expect("TIP20 plan must become record")
            })
            .collect::<Vec<_>>();

        let reduction = reduce_tip20_semantic_records(&mut db, &records, 100, 4).unwrap();

        assert!(reduction.invalid_tx_indexes().is_empty());
        assert_eq!(
            reduction.storage_value(&tip20_balance_key(token, fee_payer)),
            Some(U256::from(90))
        );
        assert_eq!(
            reduction.storage_value(&tip20_balance_key(token, recipient)),
            Some(U256::from(10))
        );
        assert_eq!(
            reduction.storage_value(&tip20_balance_key(token, TIP_FEE_MANAGER_ADDRESS)),
            Some(U256::from(10))
        );
        assert_eq!(
            reduction.storage_value(&fee_manager_collected_fees_key(beneficiary, token)),
            Some(U256::from(10))
        );
    }

    #[test]
    fn blockstm_actions_semantic_reduce_wraps_nonce_ring() {
        let token = DEFAULT_FEE_TOKEN;
        let sender = address!("0x00000000000000000000000000000000000000a1");
        let recipient = address!("0x00000000000000000000000000000000000000b2");
        let beneficiary = address!("0x00000000000000000000000000000000000000c3");
        let hash1 = B256::repeat_byte(0x41);
        let hash2 = B256::repeat_byte(0x42);
        let mut db = CacheDB::new(EmptyDB::default());
        insert_storage(&mut db, tip20_balance_key(token, sender), U256::from(10));
        insert_storage(
            &mut db,
            expiring_nonce_ring_ptr_key(),
            U256::from(EXPIRING_NONCE_SET_CAPACITY - 1),
        );
        let records = [
            tip20_prefix_plan_with_nonce(
                0,
                token,
                sender,
                sender,
                recipient,
                beneficiary,
                U256::ZERO,
                U256::ZERO,
                U256::ZERO,
                U256::from(1),
                hash1,
                110,
            )
            .to_record(0)
            .expect("TIP20 plan must become record"),
            tip20_prefix_plan_with_nonce(
                1,
                token,
                sender,
                sender,
                recipient,
                beneficiary,
                U256::ZERO,
                U256::ZERO,
                U256::ZERO,
                U256::from(1),
                hash2,
                111,
            )
            .to_record(0)
            .expect("TIP20 plan must become record"),
        ];

        let reduction = reduce_tip20_semantic_records(&mut db, &records, 100, 4).unwrap();

        assert!(reduction.invalid_tx_indexes().is_empty());
        assert_eq!(
            reduction.storage_value(&expiring_nonce_ring_key(EXPIRING_NONCE_SET_CAPACITY - 1)),
            Some(U256::from_be_bytes(hash1.0))
        );
        assert_eq!(
            reduction.storage_value(&expiring_nonce_ring_key(0)),
            Some(U256::from_be_bytes(hash2.0))
        );
        assert_eq!(
            reduction.storage_value(&expiring_nonce_ring_ptr_key()),
            Some(U256::from(1))
        );
    }

    #[test]
    fn blockstm_actions_semantic_reduce_rejects_unexpired_nonce_ring_eviction() {
        let token = DEFAULT_FEE_TOKEN;
        let sender = address!("0x00000000000000000000000000000000000000a1");
        let recipient = address!("0x00000000000000000000000000000000000000b2");
        let beneficiary = address!("0x00000000000000000000000000000000000000c3");
        let old_hash = B256::repeat_byte(0x31);
        let new_hash = B256::repeat_byte(0x41);
        let mut db = CacheDB::new(EmptyDB::default());
        insert_storage(&mut db, tip20_balance_key(token, sender), U256::from(10));
        insert_storage(
            &mut db,
            expiring_nonce_ring_key(0),
            U256::from_be_bytes(old_hash.0),
        );
        insert_storage(&mut db, expiring_nonce_seen_key(old_hash), U256::from(110));
        let record = tip20_prefix_plan_with_nonce(
            0,
            token,
            sender,
            sender,
            recipient,
            beneficiary,
            U256::ZERO,
            U256::ZERO,
            U256::ZERO,
            U256::from(1),
            new_hash,
            111,
        )
        .to_record(0)
        .expect("TIP20 plan must become record");

        let reduction = reduce_tip20_semantic_records(&mut db, &[record], 100, 4).unwrap();

        assert_eq!(reduction.invalid_tx_indexes(), &HashSet::from_iter([0]));
        assert_eq!(
            reduction.storage_value(&expiring_nonce_ring_ptr_key()),
            Some(U256::ZERO)
        );
    }

    #[test]
    fn blockstm_actions_semantic_reduce_matches_serial_prefix_for_mixed_tip20_block() {
        let token = DEFAULT_FEE_TOKEN;
        let beneficiary = address!("0x00000000000000000000000000000000000000c3");
        let mut reduce_db = CacheDB::new(EmptyDB::default());
        let mut serial_db = CacheDB::new(EmptyDB::default());
        let accounts = (0..12)
            .map(|index| Address::from([index as u8 + 1; 20]))
            .collect::<Vec<_>>();
        for account in &accounts {
            insert_storage(
                &mut reduce_db,
                tip20_balance_key(token, *account),
                U256::from(1_000),
            );
            insert_storage(
                &mut serial_db,
                tip20_balance_key(token, *account),
                U256::from(1_000),
            );
        }

        let plans = (0..64)
            .map(|tx_index| {
                let sender = accounts[tx_index % accounts.len()];
                let recipient = accounts[(tx_index * 7 + 3) % accounts.len()];
                let actual_fee = U256::from((tx_index % 3) as u64);
                let transfer_amount = U256::from((tx_index % 5 + 1) as u64);
                tip20_prefix_plan(
                    tx_index,
                    token,
                    sender,
                    sender,
                    recipient,
                    beneficiary,
                    actual_fee,
                    actual_fee,
                    U256::ZERO,
                    transfer_amount,
                )
            })
            .collect::<Vec<_>>();
        let records = plans
            .iter()
            .map(|plan| plan.to_record(0).expect("TIP20 plan must become record"))
            .collect::<Vec<_>>();
        let plan_refs = plans.iter().collect::<Vec<_>>();

        let reduction = reduce_tip20_semantic_records(&mut reduce_db, &records, 100, 6).unwrap();
        let mut serial_state = BlockStmSemanticState::default();
        let mut touched_keys = HashSet::default();
        let mut rollback = HashMap::default();
        serial_state
            .apply_plans_to_prefix_recording(
                &mut serial_db,
                &plan_refs,
                100,
                &mut touched_keys,
                &mut rollback,
            )
            .unwrap();

        assert!(reduction.invalid_tx_indexes().is_empty());
        for (key, value) in serial_state.storage_values() {
            assert_eq!(reduction.storage_value(key), Some(*value));
        }
        for key in reduction.touched_keys() {
            assert_eq!(
                Some(serial_state.storage_value(key).unwrap_or_default()),
                reduction.storage_value(key)
            );
        }
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
            tx_index,
            action_log,
            covered_keys,
            prefix_originals: HashMap::default(),
            semantic_prefix_reads: 1,
            tip20_prefix: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn tip20_prefix_plan(
        tx_index: usize,
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
        tip20_prefix_plan_inner(
            tx_index,
            token,
            fee_payer,
            sender,
            recipient,
            beneficiary,
            max_fee_precharge,
            actual_spending,
            refund_amount,
            transfer_amount,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn tip20_prefix_plan_with_nonce(
        tx_index: usize,
        token: Address,
        fee_payer: Address,
        sender: Address,
        recipient: Address,
        beneficiary: Address,
        max_fee_precharge: U256,
        actual_spending: U256,
        refund_amount: U256,
        transfer_amount: U256,
        nonce_hash: B256,
        valid_before: u64,
    ) -> BlockStmSemanticPlan {
        tip20_prefix_plan_inner(
            tx_index,
            token,
            fee_payer,
            sender,
            recipient,
            beneficiary,
            max_fee_precharge,
            actual_spending,
            refund_amount,
            transfer_amount,
            Some((nonce_hash, valid_before)),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn tip20_prefix_plan_inner(
        tx_index: usize,
        token: Address,
        fee_payer: Address,
        sender: Address,
        recipient: Address,
        beneficiary: Address,
        max_fee_precharge: U256,
        actual_spending: U256,
        refund_amount: U256,
        transfer_amount: U256,
        nonce: Option<(B256, u64)>,
    ) -> BlockStmSemanticPlan {
        let fee = Tip20FeeEscrowDelta {
            token,
            fee_payer,
            fee_manager: TIP_FEE_MANAGER_ADDRESS,
            max_fee_precharge,
            actual_spending,
            refund_amount,
        };
        let transfer = Tip20TransferDelta {
            token,
            sender,
            recipient,
            amount: transfer_amount,
        };
        let collected = CollectedFeesDelta {
            beneficiary,
            validator_token: token,
            amount: actual_spending,
        };
        let mut covered_keys = HashSet::default();
        covered_keys.extend(fee.covered_storage_slots());
        covered_keys.extend(transfer.covered_storage_slots());
        covered_keys.extend(collected.covered_storage_slots());
        if let Some((nonce_hash, _)) = nonce {
            covered_keys.insert(expiring_nonce_seen_key(nonce_hash));
            covered_keys.insert(expiring_nonce_ring_ptr_key());
            covered_keys.insert(expiring_nonce_ring_key(0));
        }

        BlockStmSemanticPlan {
            tx_index,
            action_log: BlockStmActionLog::default(),
            covered_keys,
            prefix_originals: HashMap::default(),
            semantic_prefix_reads: 1,
            tip20_prefix: Some(BlockStmTip20PrefixPlan {
                nonce,
                fee,
                transfers: vec![transfer],
                collected,
            }),
        }
    }

    fn insert_storage(db: &mut CacheDB<EmptyDB>, key: BlockStmAccessKey, value: U256) {
        let BlockStmAccessKey::Storage { address, slot } = key else {
            unreachable!("test storage key must be storage");
        };
        db.insert_account_storage(address, slot, value)
            .expect("storage insert should succeed");
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
