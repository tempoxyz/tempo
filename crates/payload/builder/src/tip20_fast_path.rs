//! Conservative TIP-20 transfer fast-path preflight.

use alloy_consensus::Transaction;
use alloy_primitives::{Address, B256, Bytes, IntoLogData, Log, LogData, U256};
use alloy_sol_types::SolCall;
use rayon::prelude::*;
use reth_evm::block::{BlockExecutionError, StateDB};
use reth_revm::{
    Inspector,
    context::journaled_state::JournalCheckpoint,
    context_interface::{
        Transaction as RevmTransaction,
        cfg::{GasParams, gas},
        context::SStoreResult,
    },
    interpreter::gas::GasTracker,
    state::{AccountInfo, Bytecode},
};
use reth_transaction_pool::ValidPoolTransaction;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use tempo_chainspec::{
    constants::gas::tempo_t6_discounted_payment_effective_gas_price, hardfork::TempoHardfork,
};
use tempo_contracts::precompiles::NonceEvent;
use tempo_evm::{
    TempoBlockExecutor, TempoSyntheticStorageDelta, TempoSyntheticStorageTxCommit,
    TempoSyntheticTxSummary,
};
use tempo_precompiles::{
    DEFAULT_FEE_TOKEN, NONCE_PRECOMPILE_ADDRESS, Precompile, TIP_FEE_MANAGER_ADDRESS,
    TIP403_REGISTRY_ADDRESS,
    error::TempoPrecompileError,
    nonce::{
        EXPIRING_NONCE_MAX_EXPIRY_SECS, EXPIRING_NONCE_SET_CAPACITY, NonceManager,
        slots as nonce_slots,
    },
    storage::{PrecompileStorageProvider, StorageCtx, StorageKey, packing::extract_from_word},
    tip_fee_manager::slots as fee_manager_slots,
    tip20::{ITIP20, TIP20Event, TIP20Token, U128_MAX, decode_tip20_balance, tip20_slots},
    tip403_registry::{ALLOW_ALL_POLICY_ID, tip403_registry_slots},
};
use tempo_primitives::{
    TempoAddressExt, TempoReceipt, TempoSignature, TempoTxEnvelope,
    transaction::{PrimitiveSignature, TEMPO_EXPIRING_NONCE_KEY, calc_gas_balance_spending},
};
use tempo_revm::{calculate_aa_initial_tx_gas_with_nonce, evm::TempoContext};
use tempo_transaction_pool::transaction::TempoPooledTransaction;

/// Fixed number of transactions considered by one fast-path preflight batch.
pub(crate) const FAST_TIP20_CHUNK_SIZE: usize = 256;

/// Static action information for a simple TIP-20 transfer candidate.
#[derive(Debug, Clone)]
pub(crate) struct Tip20TransferActionSet {
    #[allow(dead_code)]
    pub(crate) pool_tx: Arc<ValidPoolTransaction<TempoPooledTransaction>>,
    pub(crate) sender: Address,
    pub(crate) token: Address,
    pub(crate) recipient: Address,
    pub(crate) amount: U256,
    pub(crate) nonce_key: U256,
    pub(crate) nonce: u64,
    pub(crate) expiring_nonce_hash: Option<B256>,
    pub(crate) valid_before: Option<u64>,
    pub(crate) block_timestamp: u64,
    pub(crate) max_fee: U256,
}

impl Tip20TransferActionSet {
    fn is_expiring_nonce(&self) -> bool {
        self.expiring_nonce_hash.is_some()
    }

    fn calculate_initial_gas(
        &self,
        config: Tip20InitialGasConfig<'_>,
    ) -> Result<Tip20InitialGas, FastPathFallbackReason> {
        let tx_env = self.pool_tx.transaction.clone_tx_env();
        let mut initial_gas = calculate_aa_initial_tx_gas_with_nonce(
            &tx_env,
            config.gas_params,
            config.spec,
            config.max_initcode_size,
        )
        .map_err(|_| FastPathFallbackReason::InitialGas)?;

        if config.eip7623_disabled {
            initial_gas.floor_gas = 0;
        }

        let gas_limit = tx_env.gas_limit;
        if gas_limit < initial_gas.floor_gas {
            return Err(FastPathFallbackReason::GasLimit);
        }

        if config.amsterdam_eip8037_enabled
            && initial_gas.initial_regular_gas().max(initial_gas.floor_gas)
                > config.tx_gas_limit_cap
        {
            return Err(FastPathFallbackReason::GasLimit);
        }

        let (regular_gas_limit, reservoir) =
            if !config.spec.is_t0() && initial_gas.initial_total_gas() > gas_limit {
                (u64::MAX, 0)
            } else {
                initial_gas.initial_gas_and_reservoir(gas_limit, config.tx_gas_limit_cap)
            };

        Ok(Tip20InitialGas {
            tx_gas_limit: gas_limit,
            initial_regular_gas: initial_gas.initial_regular_gas,
            initial_state_gas: initial_gas.initial_state_gas,
            initial_total_gas: initial_gas.initial_total_gas(),
            floor_gas: initial_gas.floor_gas,
            regular_gas_limit,
            reservoir,
        })
    }
}

/// A preflighted fixed-size batch of simple TIP-20 transfers.
#[derive(Debug)]
pub(crate) struct Tip20TransferBatch {
    actions: Vec<Tip20TransferActionSet>,
}

impl Tip20TransferBatch {
    pub(crate) fn len(&self) -> usize {
        self.actions.len()
    }

    pub(crate) fn estimated_delta_count(&self) -> usize {
        self.actions
            .iter()
            .map(|action| {
                let _ = (
                    action.sender,
                    action.token,
                    action.recipient,
                    action.amount,
                    action.nonce_key,
                    action.nonce,
                    action.expiring_nonce_hash,
                    action.valid_before,
                    action.block_timestamp,
                    action.max_fee,
                );
                // sender balance, recipient balance, fee manager balance, and nonce-manager slots.
                if action.is_expiring_nonce() { 6 } else { 4 }
            })
            .sum()
    }

    pub(crate) fn validate_state(
        &self,
        beneficiary: Address,
        is_t6: bool,
    ) -> Result<Tip20DeltaBatch, FastPathFallbackReason> {
        Tip20Overlay::new(beneficiary, is_t6).validate(self)
    }

    #[allow(dead_code)]
    pub(crate) fn settle_state(
        &self,
        beneficiary: Address,
        is_t6: bool,
        gas_outcomes: &[Tip20GasOutcome],
    ) -> Result<Tip20SettledBatch, FastPathFallbackReason> {
        Tip20Overlay::new(beneficiary, is_t6).settle(self, gas_outcomes)
    }

    pub(crate) fn calculate_initial_gas(
        &self,
        config: Tip20InitialGasConfig<'_>,
    ) -> Result<Vec<Tip20InitialGas>, FastPathFallbackReason> {
        self.actions
            .par_iter()
            .map(|action| action.calculate_initial_gas(config))
            .collect()
    }

    #[allow(dead_code)]
    pub(crate) fn settle_state_with_calculated_gas(
        &self,
        beneficiary: Address,
        is_t6: bool,
        config: Tip20ExecutionGasConfig<'_>,
        initial_gas: &[Tip20InitialGas],
    ) -> Result<Tip20SettledBatch, FastPathFallbackReason> {
        if self.actions.len() != initial_gas.len() {
            return Err(FastPathFallbackReason::GasOutcomeMismatch);
        }

        if !config.spec.is_t6() || !is_t6 {
            return Err(FastPathFallbackReason::GasCalculatorUnsupported);
        }

        Tip20Overlay::new(beneficiary, is_t6).settle_with_calculated_gas(self, config, initial_gas)
    }
}

/// Provisional storage updates produced while validating a fast-path batch.
///
/// These prove the batch can satisfy the simple transfer and max-fee escrow
/// constraints. They are not final post-transaction deltas until exact gas and
/// refund settlement have been synthesized.
#[derive(Debug, Clone)]
pub(crate) struct Tip20DeltaBatch {
    storage: Vec<Tip20StorageDelta>,
    balance_updates: Vec<((Address, U256), U256)>,
}

impl Tip20DeltaBatch {
    pub(crate) fn len(&self) -> usize {
        self.storage.len()
    }

    pub(crate) fn balance_updates(&self) -> impl Iterator<Item = ((Address, U256), U256)> + '_ {
        self.balance_updates.iter().copied()
    }
}

/// One persistent storage write for a validated fast-path batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tip20StorageDelta {
    pub(crate) address: Address,
    pub(crate) slot: U256,
    pub(crate) original: U256,
    pub(crate) present: U256,
}

impl Tip20StorageDelta {
    #[allow(dead_code)]
    pub(crate) const fn into_synthetic_delta(self) -> TempoSyntheticStorageDelta {
        TempoSyntheticStorageDelta {
            address: self.address,
            slot: self.slot,
            original: self.original,
            present: self.present,
        }
    }
}

/// Gas data proven by the dedicated simple-transfer gas calculator.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tip20GasOutcome {
    /// Gas used for fee charging, matching `reimburse_caller`.
    pub(crate) charged_gas_used: u64,
    /// Receipt/cumulative gas increment.
    pub(crate) tx_gas_used: u64,
    /// Block-capacity regular gas increment.
    pub(crate) block_regular_gas_used: u64,
    /// State gas increment.
    pub(crate) block_state_gas_used: u64,
    /// Section-capacity gas consumed by this transaction.
    pub(crate) block_gas_used: u64,
    /// Effective fee-token price for this transaction.
    pub(crate) effective_gas_price: u128,
}

/// EVM cfg values required to calculate initial AA gas for fast-path candidates.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Tip20InitialGasConfig<'a> {
    pub(crate) gas_params: &'a GasParams,
    pub(crate) spec: TempoHardfork,
    pub(crate) eip7623_disabled: bool,
    pub(crate) amsterdam_eip8037_enabled: bool,
    pub(crate) tx_gas_limit_cap: u64,
    pub(crate) max_initcode_size: usize,
}

/// Runtime cfg values needed by the narrow simple-transfer gas calculator.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Tip20ExecutionGasConfig<'a> {
    pub(crate) gas_params: &'a GasParams,
    pub(crate) spec: TempoHardfork,
    pub(crate) amsterdam_eip8037_enabled: bool,
    pub(crate) basefee: u64,
    pub(crate) chain_id: u64,
    pub(crate) timestamp: U256,
    pub(crate) beneficiary: Address,
    pub(crate) block_number: u64,
}

/// Initial gas and reservoir data shared by the dedicated fast-path gas calculator.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tip20InitialGas {
    pub(crate) tx_gas_limit: u64,
    pub(crate) initial_regular_gas: u64,
    pub(crate) initial_state_gas: u64,
    pub(crate) initial_total_gas: u64,
    pub(crate) floor_gas: u64,
    pub(crate) regular_gas_limit: u64,
    pub(crate) reservoir: u64,
}

/// Final synthetic data for a validated simple TIP-20 transfer batch.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct Tip20SettledBatch {
    transactions: Vec<Tip20SettledTx>,
    storage: Vec<Tip20StorageDelta>,
    balance_updates: Vec<((Address, U256), U256)>,
}

#[allow(dead_code)]
impl Tip20SettledBatch {
    pub(crate) fn len(&self) -> usize {
        self.transactions.len()
    }

    pub(crate) fn transactions(&self) -> &[Tip20SettledTx] {
        &self.transactions
    }

    pub(crate) fn storage(&self) -> &[Tip20StorageDelta] {
        &self.storage
    }

    pub(crate) fn balance_updates(&self) -> impl Iterator<Item = ((Address, U256), U256)> + '_ {
        self.balance_updates.iter().copied()
    }

    pub(crate) fn commit_to_executor<DB, I>(
        &self,
        executor: &mut TempoBlockExecutor<'_, DB, I>,
    ) -> Result<Tip20CommittedBatch, BlockExecutionError>
    where
        DB: StateDB,
        I: Inspector<TempoContext<DB>>,
    {
        let mut summaries = Vec::with_capacity(self.transactions.len());
        let mut block_gas_used = 0u64;
        let mut state_gas_used = 0u64;
        let mut validator_fee = U256::ZERO;

        for tx in &self.transactions {
            let summary =
                executor.commit_synthetic_storage_non_shared_payment(tx.synthetic_commit())?;
            block_gas_used = block_gas_used.saturating_add(summary.block_gas_used);
            state_gas_used = state_gas_used.saturating_add(summary.state_gas_used);
            validator_fee = validator_fee.saturating_add(summary.validator_fee);
            summaries.push(summary);
        }

        Ok(Tip20CommittedBatch {
            summaries,
            block_gas_used,
            state_gas_used,
            validator_fee,
            balance_updates: self.state_aware_balance_updates(),
        })
    }

    fn state_aware_balance_updates(&self) -> Vec<((Address, U256), U256)> {
        let mut tracked = BTreeMap::new();

        for tx in &self.transactions {
            for delta in &tx.storage {
                if !delta.address.is_tip20() {
                    continue;
                }

                let key = (delta.address, delta.slot);
                let original_balance = decode_tip20_balance(delta.original);
                let present_balance = decode_tip20_balance(delta.present);
                if present_balance < original_balance {
                    tracked.insert(key, present_balance);
                } else if let Some(balance) = tracked.get_mut(&key) {
                    *balance = present_balance;
                }
            }
        }

        tracked.into_iter().collect()
    }
}

/// Commit summary for an already-settled fast-path batch.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct Tip20CommittedBatch {
    summaries: Vec<TempoSyntheticTxSummary>,
    block_gas_used: u64,
    state_gas_used: u64,
    validator_fee: U256,
    balance_updates: Vec<((Address, U256), U256)>,
}

#[allow(dead_code)]
impl Tip20CommittedBatch {
    pub(crate) fn summaries(&self) -> &[TempoSyntheticTxSummary] {
        &self.summaries
    }

    pub(crate) const fn block_gas_used(&self) -> u64 {
        self.block_gas_used
    }

    pub(crate) const fn state_gas_used(&self) -> u64 {
        self.state_gas_used
    }

    pub(crate) const fn validator_fee(&self) -> U256 {
        self.validator_fee
    }

    pub(crate) fn balance_updates(&self) -> impl Iterator<Item = ((Address, U256), U256)> + '_ {
        self.balance_updates.iter().copied()
    }
}

/// Final synthetic per-transaction data for the simple transfer shape.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct Tip20SettledTx {
    pub(crate) pool_tx: Arc<ValidPoolTransaction<TempoPooledTransaction>>,
    pub(crate) storage: Vec<Tip20StorageDelta>,
    pub(crate) balance_updates: Vec<((Address, U256), U256)>,
    pub(crate) logs: Vec<Log>,
    pub(crate) actual_fee: U256,
    pub(crate) refund: U256,
    pub(crate) validator_fee: U256,
    pub(crate) gas: Tip20GasOutcome,
}

#[allow(dead_code)]
impl Tip20SettledTx {
    pub(crate) fn storage(&self) -> &[Tip20StorageDelta] {
        &self.storage
    }

    pub(crate) fn synthetic_storage_deltas(
        &self,
    ) -> impl Iterator<Item = TempoSyntheticStorageDelta> + '_ {
        self.storage
            .iter()
            .copied()
            .map(Tip20StorageDelta::into_synthetic_delta)
    }

    pub(crate) fn synthetic_commit(&self) -> TempoSyntheticStorageTxCommit {
        TempoSyntheticStorageTxCommit {
            storage_deltas: self.synthetic_storage_deltas().collect(),
            receipt: TempoReceipt {
                tx_type: self.pool_tx.transaction.inner().inner().tx_type(),
                success: true,
                cumulative_gas_used: 0,
                logs: self.logs.clone(),
            },
            tx_gas_used: self.gas.tx_gas_used,
            block_regular_gas_used: self.gas.block_regular_gas_used,
            block_state_gas_used: self.gas.block_state_gas_used,
            block_gas_used: self.gas.block_gas_used,
            validator_fee: self.validator_fee,
        }
    }

    pub(crate) fn balance_updates(&self) -> impl Iterator<Item = ((Address, U256), U256)> + '_ {
        self.balance_updates.iter().copied()
    }
}

/// Reason a batch cannot use the TIP-20 transfer fast path.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FastPathFallbackReason {
    EmptyBatch,
    NotPublicPool,
    NotAa,
    Not2dNonce,
    ExpiringNonce,
    SponsoredFeePayer,
    KeyAuthorization,
    AuthorizationList,
    AccessList,
    NonPrimitiveSignature,
    MultiCall,
    CreateCall,
    CallValue,
    NotTransfer,
    MissingResolvedFeeToken,
    FeeTokenMismatch,
    InvalidValidityWindow,
    ValidatorTokenMismatch,
    Paused,
    TransferPolicy,
    ReceivePolicy,
    InvalidRecipient,
    RewardState,
    BalanceUnderflow,
    BalanceOverflow,
    NonceMismatch,
    NonceOverflow,
    StorageRead,
    InitialGas,
    GasLimit,
    RlpBlockSizeLimit,
    GasCalculatorUnsupported,
    GasOutcomeMismatch,
    GasOverflow,
    FeeOverflow,
    FeeUnderflow,
}

impl FastPathFallbackReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::EmptyBatch => "empty_batch",
            Self::NotPublicPool => "not_public_pool",
            Self::NotAa => "not_aa",
            Self::Not2dNonce => "not_2d_nonce",
            Self::ExpiringNonce => "expiring_nonce",
            Self::SponsoredFeePayer => "sponsored_fee_payer",
            Self::KeyAuthorization => "key_authorization",
            Self::AuthorizationList => "authorization_list",
            Self::AccessList => "access_list",
            Self::NonPrimitiveSignature => "non_primitive_signature",
            Self::MultiCall => "multi_call",
            Self::CreateCall => "create_call",
            Self::CallValue => "call_value",
            Self::NotTransfer => "not_transfer",
            Self::MissingResolvedFeeToken => "missing_resolved_fee_token",
            Self::FeeTokenMismatch => "fee_token_mismatch",
            Self::InvalidValidityWindow => "invalid_validity_window",
            Self::ValidatorTokenMismatch => "validator_token_mismatch",
            Self::Paused => "paused",
            Self::TransferPolicy => "transfer_policy",
            Self::ReceivePolicy => "receive_policy",
            Self::InvalidRecipient => "invalid_recipient",
            Self::RewardState => "reward_state",
            Self::BalanceUnderflow => "balance_underflow",
            Self::BalanceOverflow => "balance_overflow",
            Self::NonceMismatch => "nonce_mismatch",
            Self::NonceOverflow => "nonce_overflow",
            Self::StorageRead => "storage_read",
            Self::InitialGas => "initial_gas",
            Self::GasLimit => "gas_limit",
            Self::RlpBlockSizeLimit => "rlp_block_size_limit",
            Self::GasCalculatorUnsupported => "gas_calculator_unsupported",
            Self::GasOutcomeMismatch => "gas_outcome_mismatch",
            Self::GasOverflow => "gas_overflow",
            Self::FeeOverflow => "fee_overflow",
            Self::FeeUnderflow => "fee_underflow",
        }
    }
}

struct Tip20Overlay {
    beneficiary: Address,
    is_t6: bool,
    slots: BTreeMap<(Address, U256), SlotValue>,
    balance_updates: BTreeMap<(Address, U256), U256>,
}

#[derive(Debug, Clone, Copy)]
struct SlotValue {
    original: U256,
    present: U256,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tip20FeeSettlement {
    actual_fee: U256,
    refund: U256,
}

#[derive(Debug, Clone)]
struct Tip20MeteredTransfer {
    logs: Vec<Log>,
    gas_used: u64,
    state_gas_used: u64,
    gas_refunded: i64,
    reservoir: u64,
}

impl Tip20Overlay {
    fn new(beneficiary: Address, is_t6: bool) -> Self {
        Self {
            beneficiary,
            is_t6,
            slots: BTreeMap::new(),
            balance_updates: BTreeMap::new(),
        }
    }

    fn validate(
        mut self,
        batch: &Tip20TransferBatch,
    ) -> Result<Tip20DeltaBatch, FastPathFallbackReason> {
        for action in &batch.actions {
            self.validate_token(action)?;
            self.validate_recipient(action)?;
            self.validate_validator_token(action)?;
            let _ = self.apply_nonce(action)?;
            self.apply_fee_and_transfer(action)?;
        }

        let storage = self
            .slots
            .iter()
            .filter_map(|(&(address, slot), value)| {
                (value.original != value.present).then_some(Tip20StorageDelta {
                    address,
                    slot,
                    original: value.original,
                    present: value.present,
                })
            })
            .collect::<Vec<_>>();

        let balance_updates = self.balance_updates.into_iter().collect();

        Ok(Tip20DeltaBatch {
            storage,
            balance_updates,
        })
    }

    #[allow(dead_code)]
    fn settle(
        mut self,
        batch: &Tip20TransferBatch,
        gas_outcomes: &[Tip20GasOutcome],
    ) -> Result<Tip20SettledBatch, FastPathFallbackReason> {
        if batch.actions.len() != gas_outcomes.len() {
            return Err(FastPathFallbackReason::GasOutcomeMismatch);
        }

        let mut transactions = Vec::with_capacity(batch.actions.len());

        for (action, gas) in batch.actions.iter().zip(gas_outcomes) {
            let slots_before = self.slots.clone();
            let balance_updates_before = self.balance_updates.clone();

            self.validate_token(action)?;
            self.validate_recipient(action)?;
            self.validate_validator_token(action)?;
            let nonce_log = self.apply_nonce(action)?;
            let fee = self.apply_settled_fee_and_transfer(action, *gas)?;
            let storage = self.storage_deltas_since(&slots_before);
            let balance_updates = self.balance_updates_since(&balance_updates_before);

            let mut logs = Vec::with_capacity(3);
            logs.extend(nonce_log);
            logs.push(Log {
                address: action.token,
                data: TIP20Event::transfer(action.sender, action.recipient, action.amount)
                    .into_log_data(),
            });
            logs.push(Log {
                address: action.token,
                data: TIP20Event::transfer(action.sender, TIP_FEE_MANAGER_ADDRESS, fee.actual_fee)
                    .into_log_data(),
            });

            transactions.push(Tip20SettledTx {
                pool_tx: Arc::clone(&action.pool_tx),
                storage,
                balance_updates,
                logs,
                actual_fee: fee.actual_fee,
                refund: fee.refund,
                validator_fee: fee.actual_fee,
                gas: *gas,
            });
        }

        let storage = self
            .slots
            .iter()
            .filter_map(|(&(address, slot), value)| {
                (value.original != value.present).then_some(Tip20StorageDelta {
                    address,
                    slot,
                    original: value.original,
                    present: value.present,
                })
            })
            .collect::<Vec<_>>();

        let balance_updates = self.balance_updates.into_iter().collect();

        Ok(Tip20SettledBatch {
            transactions,
            storage,
            balance_updates,
        })
    }

    fn settle_with_calculated_gas(
        mut self,
        batch: &Tip20TransferBatch,
        config: Tip20ExecutionGasConfig<'_>,
        initial_gas: &[Tip20InitialGas],
    ) -> Result<Tip20SettledBatch, FastPathFallbackReason> {
        let mut transactions = Vec::with_capacity(batch.actions.len());

        for (action, initial_gas) in batch.actions.iter().zip(initial_gas) {
            let slots_before = self.slots.clone();
            let balance_updates_before = self.balance_updates.clone();

            self.validate_token(action)?;
            self.validate_recipient(action)?;
            self.validate_validator_token(action)?;
            let nonce_log = self.apply_nonce(action)?;
            self.apply_fee_pre_tx(action)?;
            let metered_transfer =
                self.execute_user_transfer(action, config, *initial_gas, &slots_before)?;
            let gas =
                calculate_tip20_transfer_gas(action, config, *initial_gas, &metered_transfer)?;
            let fee = self.apply_fee_post_tx(action, gas)?;
            let storage = self.storage_deltas_since(&slots_before);
            let balance_updates = self.balance_updates_since(&balance_updates_before);

            let mut logs = Vec::with_capacity(2 + metered_transfer.logs.len());
            logs.extend(nonce_log);
            logs.extend(metered_transfer.logs);
            if !fee.actual_fee.is_zero() || !fee.refund.is_zero() {
                logs.push(Log {
                    address: action.token,
                    data: TIP20Event::transfer(
                        action.sender,
                        TIP_FEE_MANAGER_ADDRESS,
                        fee.actual_fee,
                    )
                    .into_log_data(),
                });
            }

            transactions.push(Tip20SettledTx {
                pool_tx: Arc::clone(&action.pool_tx),
                storage,
                balance_updates,
                logs,
                actual_fee: fee.actual_fee,
                refund: fee.refund,
                validator_fee: fee.actual_fee,
                gas,
            });
        }

        let storage = self
            .slots
            .iter()
            .filter_map(|(&(address, slot), value)| {
                (value.original != value.present).then_some(Tip20StorageDelta {
                    address,
                    slot,
                    original: value.original,
                    present: value.present,
                })
            })
            .collect::<Vec<_>>();

        let balance_updates = self.balance_updates.into_iter().collect();

        Ok(Tip20SettledBatch {
            transactions,
            storage,
            balance_updates,
        })
    }

    fn storage_deltas_since(
        &self,
        before: &BTreeMap<(Address, U256), SlotValue>,
    ) -> Vec<Tip20StorageDelta> {
        self.slots
            .iter()
            .filter_map(|(&(address, slot), value)| {
                let original = before
                    .get(&(address, slot))
                    .map(|before| before.present)
                    .unwrap_or(value.original);
                (original != value.present).then_some(Tip20StorageDelta {
                    address,
                    slot,
                    original,
                    present: value.present,
                })
            })
            .collect()
    }

    fn balance_updates_since(
        &self,
        before: &BTreeMap<(Address, U256), U256>,
    ) -> Vec<((Address, U256), U256)> {
        self.balance_updates
            .iter()
            .filter_map(|(&key, &balance)| {
                before
                    .get(&key)
                    .is_none_or(|before| *before != balance)
                    .then_some((key, balance))
            })
            .collect()
    }

    fn validate_token(
        &mut self,
        action: &Tip20TransferActionSet,
    ) -> Result<(), FastPathFallbackReason> {
        if !self.read(action.token, tip20_slots::PAUSED)?.is_zero() {
            return Err(FastPathFallbackReason::Paused);
        }

        let policy_id: u64 = extract_from_word(
            self.read(action.token, tip20_slots::TRANSFER_POLICY_ID)?,
            tip20_slots::TRANSFER_POLICY_ID_OFFSET,
            8,
        )
        .map_err(|_| FastPathFallbackReason::StorageRead)?;
        if policy_id != ALLOW_ALL_POLICY_ID {
            return Err(FastPathFallbackReason::TransferPolicy);
        }

        if !self
            .read(action.token, tip20_slots::GLOBAL_REWARD_PER_TOKEN)?
            .is_zero()
            || !self
                .read(action.token, tip20_slots::OPTED_IN_SUPPLY)?
                .is_zero()
        {
            return Err(FastPathFallbackReason::RewardState);
        }

        Ok(())
    }

    fn validate_recipient(
        &mut self,
        action: &Tip20TransferActionSet,
    ) -> Result<(), FastPathFallbackReason> {
        if action.recipient.is_zero()
            || action.recipient.is_tip20()
            || action.recipient.is_virtual()
        {
            return Err(FastPathFallbackReason::InvalidRecipient);
        }

        if !self
            .read(
                TIP403_REGISTRY_ADDRESS,
                action
                    .recipient
                    .mapping_slot(tip403_registry_slots::RECEIVE_POLICIES),
            )?
            .is_zero()
        {
            return Err(FastPathFallbackReason::ReceivePolicy);
        }

        Ok(())
    }

    fn validate_validator_token(
        &mut self,
        action: &Tip20TransferActionSet,
    ) -> Result<(), FastPathFallbackReason> {
        let validator_token = self.read(
            TIP_FEE_MANAGER_ADDRESS,
            self.beneficiary
                .mapping_slot(tempo_precompiles::tip_fee_manager::slots::VALIDATOR_TOKENS),
        )?;
        let validator_token_address = if validator_token.is_zero() {
            DEFAULT_FEE_TOKEN
        } else {
            let bytes = validator_token.to_be_bytes::<32>();
            Address::from_slice(&bytes[12..])
        };
        if validator_token_address != action.token {
            return Err(FastPathFallbackReason::ValidatorTokenMismatch);
        }

        Ok(())
    }

    fn apply_nonce(
        &mut self,
        action: &Tip20TransferActionSet,
    ) -> Result<Option<Log>, FastPathFallbackReason> {
        if action.is_expiring_nonce() {
            self.apply_expiring_nonce(action)?;
            return Ok(None);
        }

        let slot = NonceManager::new().nonces[action.sender][action.nonce_key].slot();
        let current = self.read(NONCE_PRECOMPILE_ADDRESS, slot)?;
        if current != U256::from(action.nonce) {
            return Err(FastPathFallbackReason::NonceMismatch);
        }
        let next = action
            .nonce
            .checked_add(1)
            .ok_or(FastPathFallbackReason::NonceOverflow)?;
        self.write(NONCE_PRECOMPILE_ADDRESS, slot, U256::from(next))?;
        Ok(Some(Log {
            address: NONCE_PRECOMPILE_ADDRESS,
            data: NonceEvent::nonce_incremented(action.sender, action.nonce_key, next)
                .into_log_data(),
        }))
    }

    fn apply_expiring_nonce(
        &mut self,
        action: &Tip20TransferActionSet,
    ) -> Result<(), FastPathFallbackReason> {
        if action.nonce != 0 {
            return Err(FastPathFallbackReason::ExpiringNonce);
        }

        let hash = action
            .expiring_nonce_hash
            .ok_or(FastPathFallbackReason::ExpiringNonce)?;
        let valid_before = action
            .valid_before
            .ok_or(FastPathFallbackReason::ExpiringNonce)?;
        let max_valid_before = action
            .block_timestamp
            .saturating_add(EXPIRING_NONCE_MAX_EXPIRY_SECS);
        if valid_before <= action.block_timestamp || valid_before > max_valid_before {
            return Err(FastPathFallbackReason::ExpiringNonce);
        }

        let nonce_manager = NonceManager::new();
        let seen_slot = nonce_manager.expiring_nonce_seen[hash].slot();
        let seen_expiry = self.read(NONCE_PRECOMPILE_ADDRESS, seen_slot)?;
        if !seen_expiry.is_zero() && seen_expiry > U256::from(action.block_timestamp) {
            return Err(FastPathFallbackReason::ExpiringNonce);
        }

        let ptr_word = self.read(
            NONCE_PRECOMPILE_ADDRESS,
            nonce_slots::EXPIRING_NONCE_RING_PTR,
        )?;
        if ptr_word >= U256::from(EXPIRING_NONCE_SET_CAPACITY) {
            return Err(FastPathFallbackReason::ExpiringNonce);
        }
        let ptr = ptr_word.saturating_to::<u32>();
        let ring_slot = nonce_manager.expiring_nonce_ring[ptr].slot();
        let old_hash_word = self.read(NONCE_PRECOMPILE_ADDRESS, ring_slot)?;
        if !old_hash_word.is_zero() {
            let old_hash = B256::from(old_hash_word.to_be_bytes::<32>());
            let old_seen_slot = nonce_manager.expiring_nonce_seen[old_hash].slot();
            let old_expiry = self.read(NONCE_PRECOMPILE_ADDRESS, old_seen_slot)?;
            if !old_expiry.is_zero() && old_expiry > U256::from(action.block_timestamp) {
                return Err(FastPathFallbackReason::ExpiringNonce);
            }
            self.write(NONCE_PRECOMPILE_ADDRESS, old_seen_slot, U256::ZERO)?;
        }

        self.write(
            NONCE_PRECOMPILE_ADDRESS,
            ring_slot,
            U256::from_be_slice(hash.as_slice()),
        )?;
        self.write(
            NONCE_PRECOMPILE_ADDRESS,
            seen_slot,
            U256::from(valid_before),
        )?;
        let next = if ptr + 1 >= EXPIRING_NONCE_SET_CAPACITY {
            0
        } else {
            ptr + 1
        };
        self.write(
            NONCE_PRECOMPILE_ADDRESS,
            nonce_slots::EXPIRING_NONCE_RING_PTR,
            U256::from(next),
        )?;
        Ok(())
    }

    fn apply_fee_and_transfer(
        &mut self,
        action: &Tip20TransferActionSet,
    ) -> Result<(), FastPathFallbackReason> {
        let gas_fee = action.max_fee;
        let sender_delta = gas_fee
            .checked_add(action.amount)
            .ok_or(FastPathFallbackReason::BalanceOverflow)?;
        let sender_flag = self.resolve_transfer_reward_flag(action.token, action.sender)?;
        let recipient_flag = self.resolve_transfer_reward_flag(action.token, action.recipient)?;
        self.validate_non_opted_in_balance(action.token, TIP_FEE_MANAGER_ADDRESS)?;
        self.sub_balance_with_reward_flag(action.token, action.sender, sender_delta, sender_flag)?;
        self.add_balance_with_reward_flag(
            action.token,
            action.recipient,
            action.amount,
            recipient_flag,
        )?;
        self.add_balance(action.token, TIP_FEE_MANAGER_ADDRESS, gas_fee)?;

        Ok(())
    }

    fn apply_fee_pre_tx(
        &mut self,
        action: &Tip20TransferActionSet,
    ) -> Result<(), FastPathFallbackReason> {
        let sender_flag = self.resolve_transfer_reward_flag(action.token, action.sender)?;
        let _recipient_flag = self.resolve_transfer_reward_flag(action.token, action.recipient)?;
        self.validate_non_opted_in_balance(action.token, TIP_FEE_MANAGER_ADDRESS)?;
        self.sub_balance_with_reward_flag(
            action.token,
            action.sender,
            action.max_fee,
            sender_flag,
        )?;
        self.add_balance(action.token, TIP_FEE_MANAGER_ADDRESS, action.max_fee)?;
        Ok(())
    }

    fn apply_fee_post_tx(
        &mut self,
        action: &Tip20TransferActionSet,
        gas: Tip20GasOutcome,
    ) -> Result<Tip20FeeSettlement, FastPathFallbackReason> {
        let actual_fee = calc_gas_balance_spending(gas.charged_gas_used, gas.effective_gas_price);
        let refund = action
            .max_fee
            .checked_sub(actual_fee)
            .ok_or(FastPathFallbackReason::FeeUnderflow)?;

        let sender_flag = self.resolve_transfer_reward_flag(action.token, action.sender)?;
        self.validate_non_opted_in_balance(action.token, TIP_FEE_MANAGER_ADDRESS)?;

        if !refund.is_zero() {
            self.sub_balance(action.token, TIP_FEE_MANAGER_ADDRESS, refund)?;
            self.add_balance_with_reward_flag(action.token, action.sender, refund, sender_flag)?;
        }

        self.add_collected_fee(action, actual_fee)?;

        Ok(Tip20FeeSettlement { actual_fee, refund })
    }

    fn execute_user_transfer(
        &mut self,
        action: &Tip20TransferActionSet,
        config: Tip20ExecutionGasConfig<'_>,
        initial_gas: Tip20InitialGas,
        tx_slots_before: &BTreeMap<(Address, U256), SlotValue>,
    ) -> Result<Tip20MeteredTransfer, FastPathFallbackReason> {
        let mut provider =
            Tip20ExecutionGasProvider::new(self, action, config, initial_gas, tx_slots_before);
        let calldata = ITIP20::transferCall {
            to: action.recipient,
            amount: action.amount,
        }
        .abi_encode();

        let output = StorageCtx::enter(&mut provider, || {
            let mut token = TIP20Token::from_address(action.token)
                .map_err(|_| FastPathFallbackReason::GasOutcomeMismatch)?;
            token
                .call(&calldata, action.sender)
                .map_err(|_| FastPathFallbackReason::GasOutcomeMismatch)
        })?;

        if !output.is_success() {
            return Err(FastPathFallbackReason::GasOutcomeMismatch);
        }

        let (writes, metered_transfer) = provider.into_transfer_writes(action)?;
        for (address, slot, present) in writes {
            self.write(address, slot, present)?;
            if address == action.token {
                self.balance_updates
                    .insert((address, slot), decode_tip20_balance(present));
            }
        }

        Ok(metered_transfer)
    }

    #[allow(dead_code)]
    fn apply_settled_fee_and_transfer(
        &mut self,
        action: &Tip20TransferActionSet,
        gas: Tip20GasOutcome,
    ) -> Result<Tip20FeeSettlement, FastPathFallbackReason> {
        let actual_fee = calc_gas_balance_spending(gas.charged_gas_used, gas.effective_gas_price);
        let refund = action
            .max_fee
            .checked_sub(actual_fee)
            .ok_or(FastPathFallbackReason::FeeUnderflow)?;
        let sender_delta = action
            .max_fee
            .checked_add(action.amount)
            .ok_or(FastPathFallbackReason::FeeOverflow)?;

        let sender_flag = self.resolve_transfer_reward_flag(action.token, action.sender)?;
        let recipient_flag = self.resolve_transfer_reward_flag(action.token, action.recipient)?;
        self.validate_non_opted_in_balance(action.token, TIP_FEE_MANAGER_ADDRESS)?;
        self.sub_balance_with_reward_flag(action.token, action.sender, sender_delta, sender_flag)?;
        self.add_balance_with_reward_flag(
            action.token,
            action.recipient,
            action.amount,
            recipient_flag,
        )?;
        self.add_balance(action.token, TIP_FEE_MANAGER_ADDRESS, action.max_fee)?;

        if !refund.is_zero() {
            self.sub_balance(action.token, TIP_FEE_MANAGER_ADDRESS, refund)?;
            self.add_balance_with_reward_flag(action.token, action.sender, refund, sender_flag)?;
        }

        self.add_collected_fee(action, actual_fee)?;

        Ok(Tip20FeeSettlement { actual_fee, refund })
    }

    #[allow(dead_code)]
    fn add_collected_fee(
        &mut self,
        action: &Tip20TransferActionSet,
        amount: U256,
    ) -> Result<(), FastPathFallbackReason> {
        if amount.is_zero() {
            return Ok(());
        }
        let slot = action.token.mapping_slot(
            self.beneficiary
                .mapping_slot(fee_manager_slots::COLLECTED_FEES),
        );
        let current = self.read(TIP_FEE_MANAGER_ADDRESS, slot)?;
        let next = current
            .checked_add(amount)
            .ok_or(FastPathFallbackReason::FeeOverflow)?;
        self.write(TIP_FEE_MANAGER_ADDRESS, slot, next)?;
        Ok(())
    }

    fn add_balance(
        &mut self,
        token: Address,
        account: Address,
        amount: U256,
    ) -> Result<(), FastPathFallbackReason> {
        self.add_balance_with_reward_flag(token, account, amount, None)
    }

    fn add_balance_with_reward_flag(
        &mut self,
        token: Address,
        account: Address,
        amount: U256,
        reward_flag: Option<u8>,
    ) -> Result<(), FastPathFallbackReason> {
        if amount.is_zero() {
            return Ok(());
        }
        let slot = account.mapping_slot(tip20_slots::BALANCES);
        let raw = self.read(token, slot)?;
        let balance = decode_tip20_balance(raw);
        let next = balance
            .checked_add(amount)
            .filter(|value| *value <= U128_MAX)
            .ok_or(FastPathFallbackReason::BalanceOverflow)?;
        self.write(
            token,
            slot,
            replace_tip20_balance_and_reward_flag(raw, next, reward_flag),
        )?;
        self.balance_updates.insert((token, slot), next);
        Ok(())
    }

    fn resolve_transfer_reward_flag(
        &mut self,
        token: Address,
        account: Address,
    ) -> Result<Option<u8>, FastPathFallbackReason> {
        if !self.is_t6 {
            return Ok(None);
        }

        let raw = self.read(token, account.mapping_slot(tip20_slots::BALANCES))?;
        match tip20_reward_flag(raw) {
            REWARD_FLAG_OPTED_OUT => Ok(Some(REWARD_FLAG_OPTED_OUT)),
            REWARD_FLAG_UNINITIALIZED => {
                let reward_recipient =
                    self.read(token, account.mapping_slot(tip20_slots::USER_REWARD_INFO))?;
                if reward_recipient.is_zero() {
                    Ok(Some(REWARD_FLAG_OPTED_OUT))
                } else {
                    Err(FastPathFallbackReason::RewardState)
                }
            }
            REWARD_FLAG_OPTED_IN => Err(FastPathFallbackReason::RewardState),
            _ => Err(FastPathFallbackReason::RewardState),
        }
    }

    fn validate_non_opted_in_balance(
        &mut self,
        token: Address,
        account: Address,
    ) -> Result<(), FastPathFallbackReason> {
        if !self.is_t6 {
            return Ok(());
        }

        let raw = self.read(token, account.mapping_slot(tip20_slots::BALANCES))?;
        match tip20_reward_flag(raw) {
            REWARD_FLAG_UNINITIALIZED | REWARD_FLAG_OPTED_OUT => Ok(()),
            REWARD_FLAG_OPTED_IN => Err(FastPathFallbackReason::RewardState),
            _ => Err(FastPathFallbackReason::RewardState),
        }
    }

    fn sub_balance(
        &mut self,
        token: Address,
        account: Address,
        amount: U256,
    ) -> Result<(), FastPathFallbackReason> {
        self.sub_balance_with_reward_flag(token, account, amount, None)
    }

    fn sub_balance_with_reward_flag(
        &mut self,
        token: Address,
        account: Address,
        amount: U256,
        reward_flag: Option<u8>,
    ) -> Result<(), FastPathFallbackReason> {
        if amount.is_zero() {
            return Ok(());
        }
        let slot = account.mapping_slot(tip20_slots::BALANCES);
        let raw = self.read(token, slot)?;
        let balance = decode_tip20_balance(raw);
        let next = balance
            .checked_sub(amount)
            .ok_or(FastPathFallbackReason::BalanceUnderflow)?;
        self.write(
            token,
            slot,
            replace_tip20_balance_and_reward_flag(raw, next, reward_flag),
        )?;
        self.balance_updates.insert((token, slot), next);
        Ok(())
    }

    fn read(&mut self, address: Address, slot: U256) -> Result<U256, FastPathFallbackReason> {
        if let Some(value) = self.slots.get(&(address, slot)) {
            return Ok(value.present);
        }

        let value = self
            .storage()
            .sload(address, slot)
            .map_err(|_| FastPathFallbackReason::StorageRead)?;
        self.slots.insert(
            (address, slot),
            SlotValue {
                original: value,
                present: value,
            },
        );
        Ok(value)
    }

    fn write(
        &mut self,
        address: Address,
        slot: U256,
        present: U256,
    ) -> Result<(), FastPathFallbackReason> {
        let _ = self.read(address, slot)?;
        self.slots
            .get_mut(&(address, slot))
            .expect("slot was inserted by read")
            .present = present;
        Ok(())
    }
}

impl Tip20Overlay {
    fn storage(&self) -> StorageCtx {
        StorageCtx
    }
}

fn calculate_tip20_transfer_gas(
    action: &Tip20TransferActionSet,
    config: Tip20ExecutionGasConfig<'_>,
    initial_gas: Tip20InitialGas,
    metered_transfer: &Tip20MeteredTransfer,
) -> Result<Tip20GasOutcome, FastPathFallbackReason> {
    if metered_transfer.gas_refunded < 0 {
        return Err(FastPathFallbackReason::GasOutcomeMismatch);
    }

    let remaining = initial_gas
        .regular_gas_limit
        .checked_sub(metered_transfer.gas_used)
        .ok_or(FastPathFallbackReason::GasLimit)?;
    let mut total_gas_spent = initial_gas
        .tx_gas_limit
        .checked_sub(remaining)
        .and_then(|spent| spent.checked_sub(metered_transfer.reservoir))
        .ok_or(FastPathFallbackReason::GasOverflow)?;
    let state_gas_spent = initial_gas
        .initial_state_gas
        .checked_add(metered_transfer.state_gas_used)
        .ok_or(FastPathFallbackReason::GasOverflow)?;

    let mut refunded = (metered_transfer.gas_refunded as u64).min(total_gas_spent / 5);
    let mut charged_gas_used = total_gas_spent.saturating_sub(refunded);
    if charged_gas_used < initial_gas.floor_gas {
        total_gas_spent = initial_gas.floor_gas;
        refunded = 0;
        charged_gas_used = initial_gas.floor_gas;
    }

    let tx_gas_used = total_gas_spent
        .saturating_sub(refunded)
        .max(initial_gas.floor_gas);
    let block_regular_gas_used = total_gas_spent
        .saturating_sub(state_gas_spent)
        .max(initial_gas.floor_gas);
    let block_gas_used = if config.amsterdam_eip8037_enabled {
        block_regular_gas_used
    } else {
        tx_gas_used
    };

    let tx_env = action.pool_tx.transaction.clone_tx_env();
    let mut effective_gas_price = tx_env.effective_gas_price(config.basefee as u128);
    if config.spec.is_t6() && tx_env.is_discounted_payment() {
        effective_gas_price = tempo_t6_discounted_payment_effective_gas_price(effective_gas_price);
    }

    Ok(Tip20GasOutcome {
        charged_gas_used,
        tx_gas_used,
        block_regular_gas_used,
        block_state_gas_used: state_gas_spent,
        block_gas_used,
        effective_gas_price,
    })
}

struct Tip20ExecutionGasProvider<'a> {
    gas_params: &'a GasParams,
    spec: TempoHardfork,
    amsterdam_eip8037_enabled: bool,
    chain_id: u64,
    timestamp: U256,
    beneficiary: Address,
    block_number: u64,
    slots: BTreeMap<(Address, U256), SlotValue>,
    transient: BTreeMap<(Address, U256), U256>,
    accounts: BTreeMap<Address, AccountInfo>,
    warm_accounts: BTreeSet<Address>,
    warm_slots: BTreeSet<(Address, U256)>,
    written_slots: BTreeSet<(Address, U256)>,
    logs: Vec<Log>,
    gas_tracker: GasTracker,
    snapshots: Vec<Tip20ExecutionGasSnapshot>,
}

#[derive(Clone)]
struct Tip20ExecutionGasSnapshot {
    slots: BTreeMap<(Address, U256), SlotValue>,
    transient: BTreeMap<(Address, U256), U256>,
    accounts: BTreeMap<Address, AccountInfo>,
    warm_accounts: BTreeSet<Address>,
    warm_slots: BTreeSet<(Address, U256)>,
    written_slots: BTreeSet<(Address, U256)>,
    logs: Vec<Log>,
    gas_tracker: GasTracker,
}

impl<'a> Tip20ExecutionGasProvider<'a> {
    fn new(
        overlay: &Tip20Overlay,
        action: &Tip20TransferActionSet,
        config: Tip20ExecutionGasConfig<'a>,
        initial_gas: Tip20InitialGas,
        tx_slots_before: &BTreeMap<(Address, U256), SlotValue>,
    ) -> Self {
        let mut accounts = BTreeMap::new();
        accounts.insert(action.token, initialized_account_info());

        let mut warm_accounts = BTreeSet::new();
        warm_accounts.insert(action.token);

        let mut warm_slots = BTreeSet::new();
        warm_slots.insert((
            TIP_FEE_MANAGER_ADDRESS,
            config
                .beneficiary
                .mapping_slot(fee_manager_slots::VALIDATOR_TOKENS),
        ));
        warm_slots.insert((action.token, tip20_slots::TRANSFER_POLICY_ID));
        warm_slots.insert((action.token, tip20_slots::PAUSED));
        warm_slots.insert((
            action.token,
            action.sender.mapping_slot(tip20_slots::BALANCES),
        ));
        warm_slots.insert((
            action.token,
            TIP_FEE_MANAGER_ADDRESS.mapping_slot(tip20_slots::BALANCES),
        ));

        let mut slots = overlay.slots.clone();
        for (&key, before) in tx_slots_before {
            if let Some(value) = slots.get_mut(&key) {
                value.original = before.present;
            }
        }

        Self {
            gas_params: config.gas_params,
            spec: config.spec,
            amsterdam_eip8037_enabled: config.amsterdam_eip8037_enabled,
            chain_id: config.chain_id,
            timestamp: config.timestamp,
            beneficiary: config.beneficiary,
            block_number: config.block_number,
            slots,
            transient: BTreeMap::new(),
            accounts,
            warm_accounts,
            warm_slots,
            written_slots: BTreeSet::new(),
            logs: Vec::new(),
            gas_tracker: GasTracker::new(
                initial_gas.regular_gas_limit,
                initial_gas.regular_gas_limit,
                initial_gas.reservoir,
            ),
            snapshots: Vec::new(),
        }
    }

    fn into_transfer_writes(
        self,
        action: &Tip20TransferActionSet,
    ) -> Result<(Vec<(Address, U256, U256)>, Tip20MeteredTransfer), FastPathFallbackReason> {
        let sender_slot = action.sender.mapping_slot(tip20_slots::BALANCES);
        let recipient_slot = action.recipient.mapping_slot(tip20_slots::BALANCES);
        let mut writes = Vec::with_capacity(self.written_slots.len());

        for (address, slot) in &self.written_slots {
            if *address != action.token || (*slot != sender_slot && *slot != recipient_slot) {
                return Err(FastPathFallbackReason::GasOutcomeMismatch);
            }
            let value = self
                .slots
                .get(&(*address, *slot))
                .ok_or(FastPathFallbackReason::GasOutcomeMismatch)?;
            writes.push((*address, *slot, value.present));
        }

        let gas_used = self.gas_used();
        let state_gas_used = self.state_gas_used();
        let gas_refunded = self.gas_refunded();
        let reservoir = self.reservoir();

        Ok((
            writes,
            Tip20MeteredTransfer {
                logs: self.logs,
                gas_used,
                state_gas_used,
                gas_refunded,
                reservoir,
            },
        ))
    }

    fn missing_slot(address: Address, key: U256) -> TempoPrecompileError {
        TempoPrecompileError::Fatal(format!(
            "tip20 fast path gas calculator missing slot {address:?}:{key:?}"
        ))
    }

    fn deduct_state_gas(&mut self, gas: u64) -> Result<(), TempoPrecompileError> {
        if !self.gas_tracker.record_state_cost(gas) {
            return Err(TempoPrecompileError::OutOfGas);
        }
        Ok(())
    }

    fn snapshot(&self) -> Tip20ExecutionGasSnapshot {
        Tip20ExecutionGasSnapshot {
            slots: self.slots.clone(),
            transient: self.transient.clone(),
            accounts: self.accounts.clone(),
            warm_accounts: self.warm_accounts.clone(),
            warm_slots: self.warm_slots.clone(),
            written_slots: self.written_slots.clone(),
            logs: self.logs.clone(),
            gas_tracker: self.gas_tracker,
        }
    }
}

impl PrecompileStorageProvider for Tip20ExecutionGasProvider<'_> {
    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn timestamp(&self) -> U256 {
        self.timestamp
    }

    fn beneficiary(&self) -> Address {
        self.beneficiary
    }

    fn block_number(&self) -> u64 {
        self.block_number
    }

    fn set_code(&mut self, address: Address, code: Bytecode) -> Result<(), TempoPrecompileError> {
        let code_len = code.len();
        self.deduct_gas(self.gas_params.code_deposit_cost(code_len))?;
        self.deduct_state_gas(self.gas_params.code_deposit_state_gas(code_len))?;

        let was_empty = self
            .accounts
            .get(&address)
            .is_none_or(|account| account.is_empty());
        let account = self.accounts.entry(address).or_default();
        account.code_hash = code.hash_slow();
        account.code = Some(code);

        if self.amsterdam_eip8037_enabled && was_empty {
            self.deduct_gas(self.gas_params.create_cost())?;
            self.deduct_state_gas(self.gas_params.create_state_gas())?;
            self.deduct_gas(self.gas_params.keccak256_cost(code_len.div_ceil(32)))?;
        }

        Ok(())
    }

    fn with_account_info(
        &mut self,
        address: Address,
        f: &mut dyn FnMut(&AccountInfo),
    ) -> Result<(), TempoPrecompileError> {
        let additional_cost = self.gas_params.cold_account_additional_cost();
        if self.spec.is_t4() {
            self.deduct_gas(self.gas_params.warm_storage_read_cost())?;
        }

        let is_cold = self.warm_accounts.insert(address);
        if !self.spec.is_t4() {
            self.deduct_gas(self.gas_params.warm_storage_read_cost())?;
        }
        if is_cold {
            self.deduct_gas(additional_cost)?;
        }

        let account = self.accounts.entry(address).or_default();
        f(&*account);
        Ok(())
    }

    fn sload(&mut self, address: Address, key: U256) -> Result<U256, TempoPrecompileError> {
        let additional_cost = self.gas_params.cold_storage_additional_cost();
        if self.spec.is_t4() {
            self.deduct_gas(self.gas_params.warm_storage_read_cost())?;
        }

        let value = self
            .slots
            .get(&(address, key))
            .copied()
            .ok_or_else(|| Self::missing_slot(address, key))?
            .present;
        let is_cold = self.warm_slots.insert((address, key));

        if !self.spec.is_t4() {
            self.deduct_gas(self.gas_params.warm_storage_read_cost())?;
        }
        if is_cold {
            self.deduct_gas(additional_cost)?;
        }

        Ok(value)
    }

    fn tload(&mut self, address: Address, key: U256) -> Result<U256, TempoPrecompileError> {
        self.deduct_gas(self.gas_params.warm_storage_read_cost())?;
        Ok(self
            .transient
            .get(&(address, key))
            .copied()
            .unwrap_or(U256::ZERO))
    }

    fn sstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
    ) -> Result<(), TempoPrecompileError> {
        if self.spec.is_t4() {
            self.deduct_gas(self.gas_params.sstore_static_gas())?;
        }

        let current = self
            .slots
            .get(&(address, key))
            .copied()
            .ok_or_else(|| Self::missing_slot(address, key))?;
        let is_cold = self.warm_slots.insert((address, key));
        let result = SStoreResult {
            original_value: current.original,
            present_value: current.present,
            new_value: value,
        };

        if !self.spec.is_t4() {
            self.deduct_gas(self.gas_params.sstore_static_gas())?;
        }
        self.deduct_gas(self.gas_params.sstore_dynamic_gas(true, &result, is_cold))?;
        self.deduct_state_gas(self.gas_params.sstore_state_gas(&result))?;
        self.refund_gas(self.gas_params.sstore_refund(true, &result));

        self.slots
            .get_mut(&(address, key))
            .expect("slot existence checked above")
            .present = value;
        self.written_slots.insert((address, key));
        Ok(())
    }

    fn tstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
    ) -> Result<(), TempoPrecompileError> {
        self.deduct_gas(self.gas_params.warm_storage_read_cost())?;
        self.transient.insert((address, key), value);
        Ok(())
    }

    fn emit_event(&mut self, address: Address, event: LogData) -> Result<(), TempoPrecompileError> {
        self.deduct_gas(
            gas::LOG
                + self
                    .gas_params
                    .log_cost(event.topics().len() as u8, event.data.len() as u64),
        )?;
        self.logs.push(Log {
            address,
            data: event,
        });
        Ok(())
    }

    fn deduct_gas(&mut self, gas: u64) -> Result<(), TempoPrecompileError> {
        if !self.gas_tracker.record_regular_cost(gas) {
            return Err(TempoPrecompileError::OutOfGas);
        }
        Ok(())
    }

    fn refund_gas(&mut self, gas: i64) {
        self.gas_tracker.record_refund(gas);
    }

    fn gas_limit(&self) -> u64 {
        self.gas_tracker.limit()
    }

    fn gas_used(&self) -> u64 {
        self.gas_tracker.limit() - self.gas_tracker.remaining()
    }

    fn state_gas_used(&self) -> u64 {
        self.gas_tracker.state_gas_spent().max(0) as u64
    }

    fn gas_refunded(&self) -> i64 {
        self.gas_tracker.refunded()
    }

    fn reservoir(&self) -> u64 {
        self.gas_tracker.reservoir()
    }

    fn spec(&self) -> TempoHardfork {
        self.spec
    }

    fn amsterdam_eip8037_enabled(&self) -> bool {
        self.amsterdam_eip8037_enabled
    }

    fn is_static(&self) -> bool {
        false
    }

    fn checkpoint(&mut self) -> JournalCheckpoint {
        let checkpoint = JournalCheckpoint {
            log_i: self.logs.len(),
            journal_i: self.snapshots.len(),
            selfdestructed_i: 0,
        };
        self.snapshots.push(self.snapshot());
        checkpoint
    }

    fn checkpoint_commit(&mut self, checkpoint: JournalCheckpoint) {
        assert_eq!(
            checkpoint.journal_i,
            self.snapshots.len() - 1,
            "out-of-order fast-path gas checkpoint commit"
        );
        self.snapshots.pop();
    }

    fn checkpoint_revert(&mut self, checkpoint: JournalCheckpoint) {
        assert_eq!(
            checkpoint.journal_i,
            self.snapshots.len() - 1,
            "out-of-order fast-path gas checkpoint revert"
        );
        let snapshot = self
            .snapshots
            .pop()
            .expect("checkpoint existence checked above");
        self.slots = snapshot.slots;
        self.transient = snapshot.transient;
        self.accounts = snapshot.accounts;
        self.warm_accounts = snapshot.warm_accounts;
        self.warm_slots = snapshot.warm_slots;
        self.written_slots = snapshot.written_slots;
        self.logs = snapshot.logs;
        self.gas_tracker = snapshot.gas_tracker;
    }
}

fn initialized_account_info() -> AccountInfo {
    let code = Bytecode::new_legacy(Bytes::from_static(&[0x00]));
    let mut account = AccountInfo::default();
    account.code_hash = code.hash_slow();
    account.code = Some(code);
    account
}

fn replace_tip20_balance(raw: U256, balance: U256) -> U256 {
    (raw & !U128_MAX) | balance
}

fn replace_tip20_balance_and_reward_flag(
    raw: U256,
    balance: U256,
    reward_flag: Option<u8>,
) -> U256 {
    let raw = replace_tip20_balance(raw, balance);
    let Some(reward_flag) = reward_flag else {
        return raw;
    };

    let reward_flag_mask: U256 = U256::from(u8::MAX) << 128;
    (raw & !reward_flag_mask) | (U256::from(reward_flag) << 128)
}

const REWARD_FLAG_UNINITIALIZED: u8 = 0;
const REWARD_FLAG_OPTED_OUT: u8 = 1;
const REWARD_FLAG_OPTED_IN: u8 = 2;

fn tip20_reward_flag(raw: U256) -> u8 {
    u8::try_from((raw >> 128) & U256::from(u8::MAX)).unwrap_or(u8::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Signed, TxLegacy};
    use alloy_eips::{
        eip2930::{AccessList, AccessListItem},
        eip7702::Authorization,
    };
    use alloy_primitives::{B256, Bytes, Signature, TxKind};
    use core::num::NonZeroU64;
    use reth_evm::{
        Evm, EvmEnv, EvmFactory,
        block::{BlockExecutor, TxResult},
        eth::EthBlockExecutionCtx,
        execute::BlockExecutorFactory,
    };
    use reth_primitives_traits::Recovered;
    use reth_revm::{
        context::{BlockEnv, CfgEnv},
        db::{CacheDB, EmptyDB},
        inspector::NoOpInspector,
        state::AccountInfo,
    };
    use reth_transaction_pool::{PoolTransaction, TransactionOrigin, identifier::TransactionId};
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::Arc,
        time::Instant,
    };
    use tempo_chainspec::{TempoChainSpec, constants::gas::TEMPO_T1_BASE_FEE};
    use tempo_evm::{
        TempoBlockEnv, TempoBlockExecutionCtx, TempoEvmConfig, TempoEvmFactory, evm::TempoEvm,
    };
    use tempo_precompiles::storage::{PrecompileStorageProvider, hashmap::HashMapStorageProvider};
    use tempo_primitives::{
        AASigned, MasterId, SignatureType, TempoTransaction, TempoTxType, UserTag,
        transaction::{Call, KeyAuthorization, SignedKeyAuthorization, TempoSignedAuthorization},
    };
    use tempo_revm::gas_params::tempo_gas_params_with_amsterdam;

    fn action(
        sender: Address,
        recipient: Address,
        nonce: u64,
        amount: u64,
        max_fee: u64,
    ) -> Tip20TransferActionSet {
        Tip20TransferActionSet {
            pool_tx: test_pool_tx(sender, nonce),
            sender,
            token: DEFAULT_FEE_TOKEN,
            recipient,
            amount: U256::from(amount),
            nonce_key: U256::from(7),
            nonce,
            expiring_nonce_hash: None,
            valid_before: None,
            block_timestamp: 1,
            max_fee: U256::from(max_fee),
        }
    }

    fn expiring_action(
        sender: Address,
        recipient: Address,
        hash: B256,
        valid_before: u64,
    ) -> Tip20TransferActionSet {
        let mut action = action(sender, recipient, 0, 100, 10);
        action.nonce_key = TEMPO_EXPIRING_NONCE_KEY;
        action.expiring_nonce_hash = Some(hash);
        action.valid_before = Some(valid_before);
        action.block_timestamp = valid_before - 10;
        action
    }

    fn test_pool_tx(
        sender: Address,
        nonce: u64,
    ) -> Arc<ValidPoolTransaction<TempoPooledTransaction>> {
        let tx = TxLegacy {
            chain_id: Some(1),
            nonce,
            gas_price: 1,
            gas_limit: 21_000,
            to: TxKind::Call(Address::repeat_byte(0xee)),
            value: U256::ZERO,
            input: Bytes::new(),
        };
        let envelope =
            TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, Signature::test_signature()));
        let pooled = TempoPooledTransaction::new(Recovered::new_unchecked(envelope, sender));

        Arc::new(ValidPoolTransaction {
            transaction_id: TransactionId::new(0u64.into(), nonce),
            transaction: pooled,
            propagate: true,
            timestamp: Instant::now(),
            origin: TransactionOrigin::External,
            authority_ids: None,
        })
    }

    fn aa_pool_tx(
        sender: Address,
        nonce: u64,
        mutate: impl FnOnce(&mut TempoTransaction),
    ) -> Arc<ValidPoolTransaction<TempoPooledTransaction>> {
        aa_pool_tx_with_resolved_fee_token(sender, nonce, Some(DEFAULT_FEE_TOKEN), mutate)
    }

    fn aa_pool_tx_with_resolved_fee_token(
        sender: Address,
        nonce: u64,
        resolved_fee_token: Option<Address>,
        mutate: impl FnOnce(&mut TempoTransaction),
    ) -> Arc<ValidPoolTransaction<TempoPooledTransaction>> {
        aa_pool_tx_with_resolved_fee_token_and_origin(
            sender,
            nonce,
            resolved_fee_token,
            TransactionOrigin::External,
            mutate,
        )
    }

    fn aa_pool_tx_with_resolved_fee_token_and_origin(
        sender: Address,
        nonce: u64,
        resolved_fee_token: Option<Address>,
        origin: TransactionOrigin,
        mutate: impl FnOnce(&mut TempoTransaction),
    ) -> Arc<ValidPoolTransaction<TempoPooledTransaction>> {
        let recipient = Address::repeat_byte(0x77);
        let mut tx = TempoTransaction {
            chain_id: 1,
            fee_token: Some(DEFAULT_FEE_TOKEN),
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: ONE_TOKEN_GAS_PRICE,
            gas_limit: 100_000,
            calls: vec![Call {
                to: TxKind::Call(DEFAULT_FEE_TOKEN),
                value: U256::ZERO,
                input: Bytes::from(
                    ITIP20::transferCall {
                        to: recipient,
                        amount: U256::from(1),
                    }
                    .abi_encode(),
                ),
            }],
            nonce_key: U256::from(7),
            nonce,
            ..Default::default()
        };
        mutate(&mut tx);

        let envelope = TempoTxEnvelope::AA(AASigned::new_unhashed(
            tx,
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature())),
        ));
        let pooled = TempoPooledTransaction::new(Recovered::new_unchecked(envelope, sender));
        if let Some(fee_token) = resolved_fee_token {
            pooled.set_resolved_fee_token(fee_token);
        }

        Arc::new(ValidPoolTransaction {
            transaction_id: TransactionId::new(0u64.into(), nonce),
            transaction: pooled,
            propagate: true,
            timestamp: Instant::now(),
            origin,
            authority_ids: None,
        })
    }

    fn aa_transfer_pool_tx(
        sender: Address,
        nonce: u64,
        recipient: Address,
        amount: U256,
    ) -> Arc<ValidPoolTransaction<TempoPooledTransaction>> {
        aa_pool_tx(sender, nonce, |tx| {
            tx.gas_limit = 1_000_000;
            tx.max_fee_per_gas = ONE_TOKEN_GAS_PRICE;
            tx.max_priority_fee_per_gas = ONE_TOKEN_GAS_PRICE;
            tx.calls[0].input = Bytes::from(
                ITIP20::transferCall {
                    to: recipient,
                    amount,
                }
                .abi_encode(),
            );
        })
    }

    fn aa_expiring_transfer_pool_tx(
        sender: Address,
        recipient: Address,
        amount: U256,
        valid_before: u64,
    ) -> Arc<ValidPoolTransaction<TempoPooledTransaction>> {
        aa_pool_tx(sender, 0, |tx| {
            tx.gas_limit = 1_000_000;
            tx.max_fee_per_gas = ONE_TOKEN_GAS_PRICE;
            tx.max_priority_fee_per_gas = ONE_TOKEN_GAS_PRICE;
            tx.nonce_key = TEMPO_EXPIRING_NONCE_KEY;
            tx.nonce = 0;
            tx.valid_before = Some(nz(valid_before));
            tx.calls[0].input = Bytes::from(
                ITIP20::transferCall {
                    to: recipient,
                    amount,
                }
                .abi_encode(),
            );
        })
    }

    fn nonce_slot(sender: Address) -> U256 {
        NonceManager::new().nonces[sender][U256::from(7)].slot()
    }

    fn expiring_nonce_seen_slot(hash: B256) -> U256 {
        NonceManager::new().expiring_nonce_seen[hash].slot()
    }

    fn expiring_nonce_ring_slot(index: u32) -> U256 {
        NonceManager::new().expiring_nonce_ring[index].slot()
    }

    fn balance_slot(account: Address) -> U256 {
        account.mapping_slot(tip20_slots::BALANCES)
    }

    fn seed_allow_all_token(storage: &mut HashMapStorageProvider) {
        let policy_word =
            U256::from(ALLOW_ALL_POLICY_ID) << (tip20_slots::TRANSFER_POLICY_ID_OFFSET * 8);
        storage
            .sstore(
                DEFAULT_FEE_TOKEN,
                tip20_slots::TRANSFER_POLICY_ID,
                policy_word,
            )
            .unwrap();
    }

    fn delta_value(deltas: &Tip20DeltaBatch, address: Address, slot: U256) -> U256 {
        deltas
            .storage
            .iter()
            .find(|delta| delta.address == address && delta.slot == slot)
            .map(|delta| delta.present)
            .unwrap_or_else(|| panic!("missing delta for {address:?}:{slot:?}"))
    }

    fn settled_value(deltas: &Tip20SettledBatch, address: Address, slot: U256) -> U256 {
        deltas
            .storage()
            .iter()
            .find(|delta| delta.address == address && delta.slot == slot)
            .map(|delta| delta.present)
            .unwrap_or_else(|| panic!("missing settled delta for {address:?}:{slot:?}"))
    }

    fn tx_delta(deltas: &[Tip20StorageDelta], address: Address, slot: U256) -> Tip20StorageDelta {
        deltas
            .iter()
            .find(|delta| delta.address == address && delta.slot == slot)
            .copied()
            .unwrap_or_else(|| panic!("missing tx delta for {address:?}:{slot:?}"))
    }

    fn collected_fee_slot(beneficiary: Address, token: Address) -> U256 {
        token.mapping_slot(beneficiary.mapping_slot(fee_manager_slots::COLLECTED_FEES))
    }

    fn opted_out_balance(amount: U256) -> U256 {
        (U256::from(REWARD_FLAG_OPTED_OUT) << 128) | amount
    }

    fn opted_in_balance(amount: U256) -> U256 {
        (U256::from(REWARD_FLAG_OPTED_IN) << 128) | amount
    }

    fn usd_currency_value() -> U256 {
        // Short-string encoding: "USD" left-aligned, length * 2 in the low byte.
        (U256::from(0x555344u64) << 232) | U256::from(6)
    }

    fn seed_fast_path_hashmap_storage(entries: &[(Address, U256, U256)]) -> HashMapStorageProvider {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6)
            .with_amsterdam_eip8037_enabled(false);
        for &(address, slot, value) in entries {
            storage.sstore(address, slot, value).unwrap();
        }
        storage
    }

    fn seed_fast_path_cache_db(entries: &[(Address, U256, U256)]) -> CacheDB<EmptyDB> {
        let mut db = CacheDB::new(EmptyDB::default());
        for address in [
            DEFAULT_FEE_TOKEN,
            NONCE_PRECOMPILE_ADDRESS,
            TIP_FEE_MANAGER_ADDRESS,
            TIP403_REGISTRY_ADDRESS,
        ] {
            let info = if address == DEFAULT_FEE_TOKEN {
                initialized_account_info()
            } else {
                AccountInfo::default()
            };
            db.insert_account_info(address, info);
        }
        for &(address, slot, value) in entries {
            db.insert_account_storage(address, slot, value).unwrap();
        }
        db
    }

    fn t6_execution_env(
        beneficiary: Address,
        timestamp: u64,
    ) -> EvmEnv<TempoHardfork, TempoBlockEnv> {
        let mut cfg_env = CfgEnv::default();
        cfg_env.chain_id = 1;
        cfg_env.spec = TempoHardfork::T6;
        cfg_env.gas_params = tempo_gas_params_with_amsterdam(TempoHardfork::T6, false);
        cfg_env.tx_gas_limit_cap = TempoHardfork::T6.tx_gas_limit_cap();

        EvmEnv {
            cfg_env,
            block_env: TempoBlockEnv {
                inner: BlockEnv {
                    number: U256::from(1),
                    beneficiary,
                    timestamp: U256::from(timestamp),
                    basefee: TEMPO_T1_BASE_FEE,
                    gas_limit: 10_000_000,
                    ..Default::default()
                },
                timestamp_millis_part: 0,
            },
        }
    }

    fn t6_executor<'a>(
        config: &'a TempoEvmConfig,
        db: CacheDB<EmptyDB>,
        beneficiary: Address,
        timestamp: u64,
        tx_count: usize,
    ) -> tempo_evm::TempoBlockExecutor<'a, CacheDB<EmptyDB>, NoOpInspector> {
        let evm: TempoEvm<_, _> =
            TempoEvmFactory::default().create_evm(db, t6_execution_env(beneficiary, timestamp));
        let ctx = TempoBlockExecutionCtx {
            inner: EthBlockExecutionCtx {
                parent_hash: B256::ZERO,
                parent_beacon_block_root: Some(B256::ZERO),
                ommers: &[],
                withdrawals: None,
                extra_data: Bytes::new(),
                tx_count_hint: Some(tx_count),
                slot_number: None,
            },
            general_gas_limit: 10_000_000,
            shared_gas_limit: 0,
            validator_set: None,
            consensus_context: None,
            subblock_fee_recipients: Default::default(),
        };
        config.create_executor(evm, ctx)
    }

    fn storage_values(
        db: &CacheDB<EmptyDB>,
        addresses: impl IntoIterator<Item = Address>,
    ) -> BTreeMap<(Address, U256), U256> {
        addresses
            .into_iter()
            .flat_map(|address| {
                db.cache
                    .accounts
                    .get(&address)
                    .into_iter()
                    .flat_map(move |account| {
                        account
                            .storage
                            .iter()
                            .filter(|(_, value)| !value.is_zero())
                            .map(move |(&slot, &value)| ((address, slot), value))
                    })
            })
            .collect()
    }

    fn storage_value(db: &CacheDB<EmptyDB>, address: Address, slot: U256) -> U256 {
        db.cache
            .accounts
            .get(&address)
            .and_then(|account| account.storage.get(&slot).copied())
            .unwrap_or(U256::ZERO)
    }

    fn nz(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).expect("test timestamp must be non-zero")
    }

    fn signed_key_authorization() -> SignedKeyAuthorization {
        KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::repeat_byte(0x45))
            .into_signed(PrimitiveSignature::Secp256k1(Signature::test_signature()))
    }

    fn tempo_authorization() -> TempoSignedAuthorization {
        TempoSignedAuthorization::new_unchecked(
            Authorization {
                chain_id: U256::from(1),
                address: Address::repeat_byte(0x46),
                nonce: 0,
            },
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature())),
        )
    }

    const ONE_TOKEN_GAS_PRICE: u128 = 1_000_000_000_000;

    #[test]
    fn overlay_applies_repeated_balance_and_nonce_slots_in_transaction_order() {
        let sender = Address::repeat_byte(0x11);
        let recipient = Address::repeat_byte(0x22);
        let beneficiary = Address::repeat_byte(0x33);
        let mut storage = HashMapStorageProvider::new(1);

        seed_allow_all_token(&mut storage);
        storage
            .sstore(DEFAULT_FEE_TOKEN, balance_slot(sender), U256::from(1_000))
            .unwrap();
        storage
            .sstore(DEFAULT_FEE_TOKEN, balance_slot(recipient), U256::from(10))
            .unwrap();
        storage
            .sstore(NONCE_PRECOMPILE_ADDRESS, nonce_slot(sender), U256::ZERO)
            .unwrap();

        let batch = Tip20TransferBatch {
            actions: vec![
                action(sender, recipient, 0, 100, 10),
                action(sender, recipient, 1, 50, 5),
            ],
        };

        let deltas = StorageCtx::enter(&mut storage, || batch.validate_state(beneficiary, false))
            .expect("simple repeated transfers should validate");

        assert_eq!(
            delta_value(&deltas, DEFAULT_FEE_TOKEN, balance_slot(sender)),
            U256::from(835)
        );
        assert_eq!(
            delta_value(&deltas, DEFAULT_FEE_TOKEN, balance_slot(recipient)),
            U256::from(160)
        );
        assert_eq!(
            delta_value(
                &deltas,
                DEFAULT_FEE_TOKEN,
                balance_slot(TIP_FEE_MANAGER_ADDRESS)
            ),
            U256::from(15)
        );
        assert_eq!(
            delta_value(&deltas, NONCE_PRECOMPILE_ADDRESS, nonce_slot(sender)),
            U256::from(2)
        );
    }

    #[test]
    fn overlay_applies_expiring_nonce_ring_pointer_in_transaction_order() {
        let sender = Address::repeat_byte(0x11);
        let recipient = Address::repeat_byte(0x22);
        let beneficiary = Address::repeat_byte(0x33);
        let hash_a = B256::repeat_byte(0xa1);
        let hash_b = B256::repeat_byte(0xb2);
        let valid_before = 20;
        let mut storage = HashMapStorageProvider::new(1);

        seed_allow_all_token(&mut storage);
        storage
            .sstore(DEFAULT_FEE_TOKEN, balance_slot(sender), U256::from(1_000))
            .unwrap();

        let batch = Tip20TransferBatch {
            actions: vec![
                expiring_action(sender, recipient, hash_a, valid_before),
                expiring_action(sender, recipient, hash_b, valid_before),
            ],
        };

        let deltas = StorageCtx::enter(&mut storage, || batch.validate_state(beneficiary, false))
            .expect("valid expiring nonces should advance the local ring");

        assert_eq!(
            delta_value(
                &deltas,
                NONCE_PRECOMPILE_ADDRESS,
                expiring_nonce_seen_slot(hash_a)
            ),
            U256::from(valid_before)
        );
        assert_eq!(
            delta_value(
                &deltas,
                NONCE_PRECOMPILE_ADDRESS,
                expiring_nonce_seen_slot(hash_b)
            ),
            U256::from(valid_before)
        );
        assert_eq!(
            delta_value(
                &deltas,
                NONCE_PRECOMPILE_ADDRESS,
                expiring_nonce_ring_slot(0)
            ),
            U256::from_be_slice(hash_a.as_slice())
        );
        assert_eq!(
            delta_value(
                &deltas,
                NONCE_PRECOMPILE_ADDRESS,
                expiring_nonce_ring_slot(1)
            ),
            U256::from_be_slice(hash_b.as_slice())
        );
        assert_eq!(
            delta_value(
                &deltas,
                NONCE_PRECOMPILE_ADDRESS,
                nonce_slots::EXPIRING_NONCE_RING_PTR
            ),
            U256::from(2)
        );
    }

    #[test]
    fn overlay_rejects_expiring_nonce_replay_after_local_insert() {
        let sender = Address::repeat_byte(0x11);
        let recipient = Address::repeat_byte(0x22);
        let beneficiary = Address::repeat_byte(0x33);
        let hash = B256::repeat_byte(0xa1);
        let mut storage = HashMapStorageProvider::new(1);

        seed_allow_all_token(&mut storage);
        storage
            .sstore(DEFAULT_FEE_TOKEN, balance_slot(sender), U256::from(1_000))
            .unwrap();

        let batch = Tip20TransferBatch {
            actions: vec![
                expiring_action(sender, recipient, hash, 20),
                expiring_action(sender, recipient, hash, 20),
            ],
        };

        let err = StorageCtx::enter(&mut storage, || batch.validate_state(beneficiary, false))
            .expect_err("replaying an expiring nonce hash must invalidate the batch");
        assert_eq!(err, FastPathFallbackReason::ExpiringNonce);
    }

    #[test]
    fn overlay_rejects_unexpired_expiring_nonce_ring_entry() {
        let sender = Address::repeat_byte(0x11);
        let recipient = Address::repeat_byte(0x22);
        let beneficiary = Address::repeat_byte(0x33);
        let old_hash = B256::repeat_byte(0x0a);
        let new_hash = B256::repeat_byte(0x0b);
        let mut storage = HashMapStorageProvider::new(1);

        seed_allow_all_token(&mut storage);
        storage
            .sstore(DEFAULT_FEE_TOKEN, balance_slot(sender), U256::from(1_000))
            .unwrap();
        storage
            .sstore(
                NONCE_PRECOMPILE_ADDRESS,
                expiring_nonce_ring_slot(0),
                U256::from_be_slice(old_hash.as_slice()),
            )
            .unwrap();
        storage
            .sstore(
                NONCE_PRECOMPILE_ADDRESS,
                expiring_nonce_seen_slot(old_hash),
                U256::from(20),
            )
            .unwrap();

        let batch = Tip20TransferBatch {
            actions: vec![expiring_action(sender, recipient, new_hash, 20)],
        };

        let err = StorageCtx::enter(&mut storage, || batch.validate_state(beneficiary, false))
            .expect_err("unexpired ring slot must fall back to sequential execution");
        assert_eq!(err, FastPathFallbackReason::ExpiringNonce);
    }

    #[test]
    fn overlay_rejects_reused_2d_nonce_after_local_increment() {
        let sender = Address::repeat_byte(0x11);
        let recipient = Address::repeat_byte(0x22);
        let beneficiary = Address::repeat_byte(0x33);
        let mut storage = HashMapStorageProvider::new(1);

        seed_allow_all_token(&mut storage);
        storage
            .sstore(DEFAULT_FEE_TOKEN, balance_slot(sender), U256::from(1_000))
            .unwrap();
        storage
            .sstore(NONCE_PRECOMPILE_ADDRESS, nonce_slot(sender), U256::ZERO)
            .unwrap();

        let batch = Tip20TransferBatch {
            actions: vec![
                action(sender, recipient, 0, 100, 10),
                action(sender, recipient, 0, 50, 5),
            ],
        };

        let err = StorageCtx::enter(&mut storage, || batch.validate_state(beneficiary, false))
            .expect_err("reusing a nonce must invalidate the whole batch");
        assert_eq!(err, FastPathFallbackReason::NonceMismatch);
    }

    #[test]
    fn overlay_rejects_insufficient_balance_after_prior_local_debit() {
        let sender = Address::repeat_byte(0x11);
        let recipient = Address::repeat_byte(0x22);
        let beneficiary = Address::repeat_byte(0x33);
        let mut storage = HashMapStorageProvider::new(1);

        seed_allow_all_token(&mut storage);
        storage
            .sstore(DEFAULT_FEE_TOKEN, balance_slot(sender), U256::from(120))
            .unwrap();
        storage
            .sstore(NONCE_PRECOMPILE_ADDRESS, nonce_slot(sender), U256::ZERO)
            .unwrap();

        let batch = Tip20TransferBatch {
            actions: vec![
                action(sender, recipient, 0, 100, 10),
                action(sender, recipient, 1, 10, 10),
            ],
        };

        let err = StorageCtx::enter(&mut storage, || batch.validate_state(beneficiary, false))
            .expect_err("local balance overlay must catch the second debit");
        assert_eq!(err, FastPathFallbackReason::BalanceUnderflow);
    }

    #[test]
    fn overlay_rejects_token_and_recipient_policy_state() {
        let sender = Address::repeat_byte(0x11);
        let recipient = Address::repeat_byte(0x22);
        let beneficiary = Address::repeat_byte(0x33);

        for (slot, reason) in [
            (tip20_slots::PAUSED, FastPathFallbackReason::Paused),
            (
                tip20_slots::TRANSFER_POLICY_ID,
                FastPathFallbackReason::TransferPolicy,
            ),
            (
                tip20_slots::GLOBAL_REWARD_PER_TOKEN,
                FastPathFallbackReason::RewardState,
            ),
            (
                tip20_slots::OPTED_IN_SUPPLY,
                FastPathFallbackReason::RewardState,
            ),
        ] {
            let mut storage = HashMapStorageProvider::new(1);
            seed_allow_all_token(&mut storage);
            storage
                .sstore(DEFAULT_FEE_TOKEN, slot, U256::from(1))
                .unwrap();
            storage
                .sstore(DEFAULT_FEE_TOKEN, balance_slot(sender), U256::from(1_000))
                .unwrap();
            storage
                .sstore(NONCE_PRECOMPILE_ADDRESS, nonce_slot(sender), U256::ZERO)
                .unwrap();

            let batch = Tip20TransferBatch {
                actions: vec![action(sender, recipient, 0, 100, 10)],
            };
            let err = StorageCtx::enter(&mut storage, || batch.validate_state(beneficiary, true))
                .expect_err("policy state must reject fast path");
            assert_eq!(err, reason);
        }

        let mut storage = HashMapStorageProvider::new(1);
        seed_allow_all_token(&mut storage);
        storage
            .sstore(
                TIP403_REGISTRY_ADDRESS,
                recipient.mapping_slot(tip403_registry_slots::RECEIVE_POLICIES),
                U256::from(1),
            )
            .unwrap();
        storage
            .sstore(DEFAULT_FEE_TOKEN, balance_slot(sender), U256::from(1_000))
            .unwrap();
        storage
            .sstore(NONCE_PRECOMPILE_ADDRESS, nonce_slot(sender), U256::ZERO)
            .unwrap();

        let batch = Tip20TransferBatch {
            actions: vec![action(sender, recipient, 0, 100, 10)],
        };
        let err = StorageCtx::enter(&mut storage, || batch.validate_state(beneficiary, true))
            .expect_err("receive policy must reject fast path");
        assert_eq!(err, FastPathFallbackReason::ReceivePolicy);
    }

    #[test]
    fn overlay_accepts_uninitialized_default_reward_state_as_opted_out() {
        let sender = Address::repeat_byte(0x11);
        let recipient = Address::repeat_byte(0x22);
        let beneficiary = Address::repeat_byte(0x33);
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);

        seed_allow_all_token(&mut storage);
        storage
            .sstore(
                DEFAULT_FEE_TOKEN,
                balance_slot(sender),
                opted_out_balance(U256::from(1_000)),
            )
            .unwrap();
        storage
            .sstore(
                DEFAULT_FEE_TOKEN,
                balance_slot(TIP_FEE_MANAGER_ADDRESS),
                opted_out_balance(U256::ZERO),
            )
            .unwrap();
        storage
            .sstore(NONCE_PRECOMPILE_ADDRESS, nonce_slot(sender), U256::ZERO)
            .unwrap();

        let batch = Tip20TransferBatch {
            actions: vec![action(sender, recipient, 0, 100, 10)],
        };
        let deltas = StorageCtx::enter(&mut storage, || batch.validate_state(beneficiary, true))
            .expect("uninitialized zero-delegate recipient should validate");
        let recipient_raw = delta_value(&deltas, DEFAULT_FEE_TOKEN, balance_slot(recipient));

        assert_eq!(decode_tip20_balance(recipient_raw), U256::from(100));
        assert_eq!(tip20_reward_flag(recipient_raw), REWARD_FLAG_OPTED_OUT);
    }

    #[test]
    fn overlay_rejects_opted_in_or_delegated_reward_state() {
        let sender = Address::repeat_byte(0x11);
        let recipient = Address::repeat_byte(0x22);
        let beneficiary = Address::repeat_byte(0x33);

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        seed_allow_all_token(&mut storage);
        storage
            .sstore(
                DEFAULT_FEE_TOKEN,
                balance_slot(sender),
                opted_in_balance(U256::from(1_000)),
            )
            .unwrap();
        storage
            .sstore(NONCE_PRECOMPILE_ADDRESS, nonce_slot(sender), U256::ZERO)
            .unwrap();

        let batch = Tip20TransferBatch {
            actions: vec![action(sender, recipient, 0, 100, 10)],
        };
        let err = StorageCtx::enter(&mut storage, || batch.validate_state(beneficiary, true))
            .expect_err("opted-in sender must reject fast path");
        assert_eq!(err, FastPathFallbackReason::RewardState);

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        seed_allow_all_token(&mut storage);
        storage
            .sstore(
                DEFAULT_FEE_TOKEN,
                balance_slot(sender),
                opted_out_balance(U256::from(1_000)),
            )
            .unwrap();
        storage
            .sstore(
                DEFAULT_FEE_TOKEN,
                recipient.mapping_slot(tip20_slots::USER_REWARD_INFO),
                U256::from(1),
            )
            .unwrap();
        storage
            .sstore(NONCE_PRECOMPILE_ADDRESS, nonce_slot(sender), U256::ZERO)
            .unwrap();

        let batch = Tip20TransferBatch {
            actions: vec![action(sender, recipient, 0, 100, 10)],
        };
        let err = StorageCtx::enter(&mut storage, || batch.validate_state(beneficiary, true))
            .expect_err("delegated uninitialized recipient must reject fast path");
        assert_eq!(err, FastPathFallbackReason::RewardState);
    }

    #[test]
    fn overlay_rejects_virtual_recipient_and_validator_token_mismatch() {
        let sender = Address::repeat_byte(0x11);
        let beneficiary = Address::repeat_byte(0x33);
        let mut storage = HashMapStorageProvider::new(1);
        seed_allow_all_token(&mut storage);
        storage
            .sstore(DEFAULT_FEE_TOKEN, balance_slot(sender), U256::from(1_000))
            .unwrap();
        storage
            .sstore(NONCE_PRECOMPILE_ADDRESS, nonce_slot(sender), U256::ZERO)
            .unwrap();

        let batch = Tip20TransferBatch {
            actions: vec![action(
                sender,
                Address::new_virtual(MasterId::ZERO, UserTag::ZERO),
                0,
                100,
                10,
            )],
        };
        let err = StorageCtx::enter(&mut storage, || batch.validate_state(beneficiary, true))
            .expect_err("virtual recipient must reject fast path");
        assert_eq!(err, FastPathFallbackReason::InvalidRecipient);

        let recipient = Address::repeat_byte(0x22);
        let other_token = Address::repeat_byte(0x44);
        let mut storage = HashMapStorageProvider::new(1);
        seed_allow_all_token(&mut storage);
        storage
            .sstore(
                TIP_FEE_MANAGER_ADDRESS,
                beneficiary.mapping_slot(fee_manager_slots::VALIDATOR_TOKENS),
                U256::from_be_slice(other_token.as_slice()),
            )
            .unwrap();
        storage
            .sstore(DEFAULT_FEE_TOKEN, balance_slot(sender), U256::from(1_000))
            .unwrap();
        storage
            .sstore(NONCE_PRECOMPILE_ADDRESS, nonce_slot(sender), U256::ZERO)
            .unwrap();

        let batch = Tip20TransferBatch {
            actions: vec![action(sender, recipient, 0, 100, 10)],
        };
        let err = StorageCtx::enter(&mut storage, || batch.validate_state(beneficiary, true))
            .expect_err("validator token mismatch must reject fast path");
        assert_eq!(err, FastPathFallbackReason::ValidatorTokenMismatch);
    }

    #[test]
    fn settle_state_applies_refunds_collected_fees_and_log_order() {
        let sender = Address::repeat_byte(0x11);
        let recipient = Address::repeat_byte(0x22);
        let beneficiary = Address::repeat_byte(0x33);
        let mut storage = HashMapStorageProvider::new(1);

        seed_allow_all_token(&mut storage);
        storage
            .sstore(DEFAULT_FEE_TOKEN, balance_slot(sender), U256::from(1_000))
            .unwrap();
        storage
            .sstore(DEFAULT_FEE_TOKEN, balance_slot(recipient), U256::from(10))
            .unwrap();
        storage
            .sstore(NONCE_PRECOMPILE_ADDRESS, nonce_slot(sender), U256::ZERO)
            .unwrap();

        let batch = Tip20TransferBatch {
            actions: vec![action(sender, recipient, 0, 100, 10)],
        };
        let gas = [Tip20GasOutcome {
            charged_gas_used: 7,
            tx_gas_used: 21_000,
            block_regular_gas_used: 21_000,
            block_state_gas_used: 0,
            block_gas_used: 21_000,
            effective_gas_price: ONE_TOKEN_GAS_PRICE,
        }];

        let settled = StorageCtx::enter(&mut storage, || {
            batch.settle_state(beneficiary, false, &gas)
        })
        .expect("settled simple transfer should validate");

        assert_eq!(settled.len(), 1);
        assert_eq!(
            settled_value(&settled, DEFAULT_FEE_TOKEN, balance_slot(sender)),
            U256::from(893)
        );
        assert_eq!(
            settled_value(&settled, DEFAULT_FEE_TOKEN, balance_slot(recipient)),
            U256::from(110)
        );
        assert_eq!(
            settled_value(
                &settled,
                DEFAULT_FEE_TOKEN,
                balance_slot(TIP_FEE_MANAGER_ADDRESS)
            ),
            U256::from(7)
        );
        assert_eq!(
            settled_value(
                &settled,
                TIP_FEE_MANAGER_ADDRESS,
                collected_fee_slot(beneficiary, DEFAULT_FEE_TOKEN)
            ),
            U256::from(7)
        );
        assert_eq!(
            settled_value(&settled, NONCE_PRECOMPILE_ADDRESS, nonce_slot(sender)),
            U256::from(1)
        );

        let tx = &settled.transactions()[0];
        assert_eq!(tx.actual_fee, U256::from(7));
        assert_eq!(tx.refund, U256::from(3));
        assert_eq!(tx.validator_fee, U256::from(7));
        assert_eq!(tx.logs.len(), 3);
        assert_eq!(
            tx.logs[0],
            Log {
                address: NONCE_PRECOMPILE_ADDRESS,
                data: NonceEvent::nonce_incremented(sender, U256::from(7), 1).into_log_data(),
            }
        );
        assert_eq!(
            tx.logs[1],
            Log {
                address: DEFAULT_FEE_TOKEN,
                data: TIP20Event::transfer(sender, recipient, U256::from(100)).into_log_data(),
            }
        );
        assert_eq!(
            tx.logs[2],
            Log {
                address: DEFAULT_FEE_TOKEN,
                data: TIP20Event::transfer(sender, TIP_FEE_MANAGER_ADDRESS, U256::from(7))
                    .into_log_data(),
            }
        );

        let commit = tx.synthetic_commit();
        assert_eq!(commit.receipt.tx_type, TempoTxType::Legacy);
        assert!(commit.receipt.success);
        assert_eq!(commit.receipt.cumulative_gas_used, 0);
        assert_eq!(commit.receipt.logs, tx.logs);
        assert_eq!(commit.storage_deltas.len(), tx.storage().len());
        assert_eq!(commit.tx_gas_used, 21_000);
        assert_eq!(commit.block_gas_used, 21_000);
        assert_eq!(commit.validator_fee, U256::from(7));
    }

    #[test]
    fn settle_state_with_calculated_gas_runs_metered_t6_transfer() {
        let sender = Address::repeat_byte(0x11);
        let recipient = Address::repeat_byte(0x22);
        let beneficiary = Address::repeat_byte(0x33);
        let sender_start = 2_000_000u64;
        let recipient_start = 10u64;
        let max_fee = 500_000u64;
        let amount = 100u64;
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6)
            .with_amsterdam_eip8037_enabled(true);

        seed_allow_all_token(&mut storage);
        storage
            .sstore(
                DEFAULT_FEE_TOKEN,
                balance_slot(sender),
                opted_out_balance(U256::from(sender_start)),
            )
            .unwrap();
        storage
            .sstore(
                DEFAULT_FEE_TOKEN,
                balance_slot(recipient),
                opted_out_balance(U256::from(recipient_start)),
            )
            .unwrap();
        storage
            .sstore(
                DEFAULT_FEE_TOKEN,
                balance_slot(TIP_FEE_MANAGER_ADDRESS),
                opted_out_balance(U256::ZERO),
            )
            .unwrap();
        storage
            .sstore(NONCE_PRECOMPILE_ADDRESS, nonce_slot(sender), U256::ZERO)
            .unwrap();

        let batch = Tip20TransferBatch {
            actions: vec![action(sender, recipient, 0, amount, max_fee)],
        };
        let gas_params = tempo_gas_params_with_amsterdam(TempoHardfork::T6, true);
        let initial_gas = [Tip20InitialGas {
            tx_gas_limit: 1_000_000,
            initial_regular_gas: 21_000,
            initial_state_gas: 0,
            initial_total_gas: 21_000,
            floor_gas: 0,
            regular_gas_limit: 979_000,
            reservoir: 0,
        }];
        let config = Tip20ExecutionGasConfig {
            gas_params: &gas_params,
            spec: TempoHardfork::T6,
            amsterdam_eip8037_enabled: true,
            basefee: 0,
            chain_id: 1,
            timestamp: U256::from(1),
            beneficiary,
            block_number: 1,
        };

        let settled = StorageCtx::enter(&mut storage, || {
            batch.settle_state_with_calculated_gas(beneficiary, true, config, &initial_gas)
        })
        .expect("metered simple transfer should settle");

        assert_eq!(settled.len(), 1);
        let tx = &settled.transactions()[0];
        assert!(tx.gas.charged_gas_used > initial_gas[0].initial_total_gas);
        assert_eq!(tx.gas.effective_gas_price, 1);
        assert_eq!(
            tx.actual_fee,
            calc_gas_balance_spending(tx.gas.charged_gas_used, tx.gas.effective_gas_price)
        );
        assert!(tx.actual_fee < U256::from(max_fee));
        assert_eq!(tx.refund, U256::from(max_fee) - tx.actual_fee);
        assert_eq!(tx.validator_fee, tx.actual_fee);
        assert_eq!(tx.logs.len(), 3);
        assert_eq!(
            tx.logs[1],
            Log {
                address: DEFAULT_FEE_TOKEN,
                data: TIP20Event::transfer(sender, recipient, U256::from(amount)).into_log_data(),
            }
        );
        assert_eq!(
            tx.logs[2],
            Log {
                address: DEFAULT_FEE_TOKEN,
                data: TIP20Event::transfer(sender, TIP_FEE_MANAGER_ADDRESS, tx.actual_fee)
                    .into_log_data(),
            }
        );

        assert_eq!(
            decode_tip20_balance(settled_value(
                &settled,
                DEFAULT_FEE_TOKEN,
                balance_slot(sender)
            )),
            U256::from(sender_start) - U256::from(amount) - tx.actual_fee
        );
        assert_eq!(
            decode_tip20_balance(settled_value(
                &settled,
                DEFAULT_FEE_TOKEN,
                balance_slot(recipient)
            )),
            U256::from(recipient_start + amount)
        );
        assert_eq!(
            decode_tip20_balance(settled_value(
                &settled,
                DEFAULT_FEE_TOKEN,
                balance_slot(TIP_FEE_MANAGER_ADDRESS)
            )),
            tx.actual_fee
        );
        assert_eq!(
            settled_value(
                &settled,
                TIP_FEE_MANAGER_ADDRESS,
                collected_fee_slot(beneficiary, DEFAULT_FEE_TOKEN)
            ),
            tx.actual_fee
        );
        assert_eq!(
            settled_value(&settled, NONCE_PRECOMPILE_ADDRESS, nonce_slot(sender)),
            U256::from(1)
        );
        assert_eq!(tx.gas.block_gas_used, tx.gas.block_regular_gas_used);
        assert_eq!(tx.gas.block_state_gas_used, 0);
    }

    #[test]
    fn settle_state_with_calculated_gas_supports_current_t6_node_gas_config() {
        let sender = Address::repeat_byte(0x11);
        let recipient = Address::repeat_byte(0x22);
        let beneficiary = Address::repeat_byte(0x33);
        let amount = U256::from(100u64);
        let sender_start = U256::from(2_000_000_000_000_000_000u128);
        let recipient_start = U256::from(10u64);
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6)
            .with_amsterdam_eip8037_enabled(false);

        seed_allow_all_token(&mut storage);
        storage
            .sstore(
                DEFAULT_FEE_TOKEN,
                balance_slot(sender),
                opted_out_balance(sender_start),
            )
            .unwrap();
        storage
            .sstore(
                DEFAULT_FEE_TOKEN,
                balance_slot(recipient),
                opted_out_balance(recipient_start),
            )
            .unwrap();
        storage
            .sstore(
                DEFAULT_FEE_TOKEN,
                balance_slot(TIP_FEE_MANAGER_ADDRESS),
                opted_out_balance(U256::ZERO),
            )
            .unwrap();
        storage
            .sstore(NONCE_PRECOMPILE_ADDRESS, nonce_slot(sender), U256::from(1))
            .unwrap();

        let pool_tx = aa_pool_tx(sender, 1, |tx| {
            tx.gas_limit = 250_000;
            tx.max_fee_per_gas = ONE_TOKEN_GAS_PRICE;
            tx.max_priority_fee_per_gas = ONE_TOKEN_GAS_PRICE;
            tx.calls[0].input = Bytes::from(
                ITIP20::transferCall {
                    to: recipient,
                    amount,
                }
                .abi_encode(),
            );
        });
        let action =
            preflight_tip20_transfer(&pool_tx, 1).expect("simple AA transfer should preflight");
        let batch = Tip20TransferBatch {
            actions: vec![action],
        };

        let gas_params = tempo_gas_params_with_amsterdam(TempoHardfork::T6, false);
        let initial_gas = batch
            .calculate_initial_gas(Tip20InitialGasConfig {
                gas_params: &gas_params,
                spec: TempoHardfork::T6,
                eip7623_disabled: false,
                amsterdam_eip8037_enabled: false,
                tx_gas_limit_cap: TempoHardfork::T6
                    .tx_gas_limit_cap()
                    .expect("T6 has tx gas limit cap"),
                max_initcode_size: usize::MAX,
            })
            .expect("initial gas should be calculated for simple AA transfer");
        let config = Tip20ExecutionGasConfig {
            gas_params: &gas_params,
            spec: TempoHardfork::T6,
            amsterdam_eip8037_enabled: false,
            basefee: TEMPO_T1_BASE_FEE,
            chain_id: 1,
            timestamp: U256::from(1),
            beneficiary,
            block_number: 1,
        };

        let settled = StorageCtx::enter(&mut storage, || {
            batch.settle_state_with_calculated_gas(beneficiary, true, config, &initial_gas)
        })
        .expect("T6 without Amsterdam should settle with tx-gas block accounting");

        let tx = &settled.transactions()[0];
        assert_eq!(tx.synthetic_commit().receipt.tx_type, TempoTxType::AA);
        assert_eq!(tx.gas.block_gas_used, tx.gas.tx_gas_used);
        assert_eq!(tx.gas.block_state_gas_used, 0);
        assert_eq!(
            tx.gas.effective_gas_price,
            tempo_t6_discounted_payment_effective_gas_price(ONE_TOKEN_GAS_PRICE)
        );
        assert_eq!(
            tx.actual_fee,
            calc_gas_balance_spending(tx.gas.charged_gas_used, tx.gas.effective_gas_price)
        );
        assert_eq!(
            decode_tip20_balance(settled_value(
                &settled,
                DEFAULT_FEE_TOKEN,
                balance_slot(sender)
            )),
            sender_start - amount - tx.actual_fee
        );
        assert_eq!(
            decode_tip20_balance(settled_value(
                &settled,
                DEFAULT_FEE_TOKEN,
                balance_slot(recipient)
            )),
            recipient_start + amount
        );
    }

    #[test]
    fn settle_state_with_calculated_gas_supports_fresh_t6_recipient() {
        let sender = Address::repeat_byte(0x11);
        let recipient = Address::repeat_byte(0x22);
        let beneficiary = Address::repeat_byte(0x33);
        let amount = U256::from(100u64);
        let sender_start = U256::from(2_000_000_000_000_000_000u128);
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6)
            .with_amsterdam_eip8037_enabled(false);

        seed_allow_all_token(&mut storage);
        storage
            .sstore(
                DEFAULT_FEE_TOKEN,
                balance_slot(sender),
                opted_out_balance(sender_start),
            )
            .unwrap();
        storage
            .sstore(
                DEFAULT_FEE_TOKEN,
                balance_slot(TIP_FEE_MANAGER_ADDRESS),
                opted_out_balance(U256::ZERO),
            )
            .unwrap();
        storage
            .sstore(NONCE_PRECOMPILE_ADDRESS, nonce_slot(sender), U256::from(1))
            .unwrap();

        let pool_tx = aa_pool_tx(sender, 1, |tx| {
            tx.gas_limit = 1_000_000;
            tx.max_fee_per_gas = ONE_TOKEN_GAS_PRICE;
            tx.max_priority_fee_per_gas = ONE_TOKEN_GAS_PRICE;
            tx.calls[0].input = Bytes::from(
                ITIP20::transferCall {
                    to: recipient,
                    amount,
                }
                .abi_encode(),
            );
        });
        let action =
            preflight_tip20_transfer(&pool_tx, 1).expect("simple AA transfer should preflight");
        let batch = Tip20TransferBatch {
            actions: vec![action],
        };

        let gas_params = tempo_gas_params_with_amsterdam(TempoHardfork::T6, false);
        let initial_gas = batch
            .calculate_initial_gas(Tip20InitialGasConfig {
                gas_params: &gas_params,
                spec: TempoHardfork::T6,
                eip7623_disabled: false,
                amsterdam_eip8037_enabled: false,
                tx_gas_limit_cap: TempoHardfork::T6
                    .tx_gas_limit_cap()
                    .expect("T6 has tx gas limit cap"),
                max_initcode_size: usize::MAX,
            })
            .expect("initial gas should be calculated for simple AA transfer");
        let config = Tip20ExecutionGasConfig {
            gas_params: &gas_params,
            spec: TempoHardfork::T6,
            amsterdam_eip8037_enabled: false,
            basefee: TEMPO_T1_BASE_FEE,
            chain_id: 1,
            timestamp: U256::from(1),
            beneficiary,
            block_number: 1,
        };

        let settled = StorageCtx::enter(&mut storage, || {
            batch.settle_state_with_calculated_gas(beneficiary, true, config, &initial_gas)
        })
        .expect("fresh recipient should settle through the metered fast path");

        let tx = &settled.transactions()[0];
        let recipient_raw = settled_value(&settled, DEFAULT_FEE_TOKEN, balance_slot(recipient));
        assert_eq!(decode_tip20_balance(recipient_raw), amount);
        assert_eq!(tip20_reward_flag(recipient_raw), REWARD_FLAG_OPTED_OUT);
        assert_eq!(
            decode_tip20_balance(settled_value(
                &settled,
                DEFAULT_FEE_TOKEN,
                balance_slot(sender)
            )),
            sender_start - amount - tx.actual_fee
        );
    }

    #[test]
    fn fast_path_batch_matches_sequential_executor_for_simple_t6_transfers() {
        let sender_a = Address::repeat_byte(0x11);
        let sender_b = Address::repeat_byte(0x22);
        let recipient_c = Address::repeat_byte(0x44);
        let beneficiary = Address::repeat_byte(0x33);
        let block_timestamp = 1;
        let sender_a_start = U256::from(10_000_000_000_000_000_000u128);
        let sender_b_start = U256::from(10_000_000_000_000_000_000u128);

        let policy_word =
            U256::from(ALLOW_ALL_POLICY_ID) << (tip20_slots::TRANSFER_POLICY_ID_OFFSET * 8);
        let initial_storage = vec![
            (
                DEFAULT_FEE_TOKEN,
                tip20_slots::CURRENCY,
                usd_currency_value(),
            ),
            (
                DEFAULT_FEE_TOKEN,
                tip20_slots::TRANSFER_POLICY_ID,
                policy_word,
            ),
            (
                DEFAULT_FEE_TOKEN,
                balance_slot(sender_a),
                opted_out_balance(sender_a_start),
            ),
            (
                DEFAULT_FEE_TOKEN,
                balance_slot(sender_b),
                opted_out_balance(sender_b_start),
            ),
            (
                DEFAULT_FEE_TOKEN,
                balance_slot(TIP_FEE_MANAGER_ADDRESS),
                opted_out_balance(U256::ZERO),
            ),
            (NONCE_PRECOMPILE_ADDRESS, nonce_slot(sender_a), U256::ZERO),
            (NONCE_PRECOMPILE_ADDRESS, nonce_slot(sender_b), U256::ZERO),
        ];

        let pool_txs = vec![
            aa_transfer_pool_tx(sender_a, 0, sender_b, U256::from(100)),
            aa_transfer_pool_tx(sender_a, 1, recipient_c, U256::from(25)),
            aa_transfer_pool_tx(sender_b, 0, sender_a, U256::from(40)),
        ];

        let batch = preflight_tip20_transfer_batch(&pool_txs, block_timestamp)
            .expect("simple transfers should preflight");
        assert_eq!(batch.len(), pool_txs.len());
        assert_eq!(
            batch
                .actions
                .iter()
                .map(|action| *action.pool_tx.transaction.hash())
                .collect::<Vec<_>>(),
            pool_txs
                .iter()
                .map(|tx| *tx.transaction.hash())
                .collect::<Vec<_>>(),
            "fast path must preserve pool transaction order"
        );

        let gas_params = tempo_gas_params_with_amsterdam(TempoHardfork::T6, false);
        let initial_gas = batch
            .calculate_initial_gas(Tip20InitialGasConfig {
                gas_params: &gas_params,
                spec: TempoHardfork::T6,
                eip7623_disabled: false,
                amsterdam_eip8037_enabled: false,
                tx_gas_limit_cap: TempoHardfork::T6
                    .tx_gas_limit_cap()
                    .expect("T6 has tx gas limit cap"),
                max_initcode_size: usize::MAX,
            })
            .expect("initial gas should be calculated for simple transfer batch");
        let execution_config = Tip20ExecutionGasConfig {
            gas_params: &gas_params,
            spec: TempoHardfork::T6,
            amsterdam_eip8037_enabled: false,
            basefee: TEMPO_T1_BASE_FEE,
            chain_id: 1,
            timestamp: U256::from(block_timestamp),
            beneficiary,
            block_number: 1,
        };
        let mut fast_storage = seed_fast_path_hashmap_storage(&initial_storage);
        let settled = StorageCtx::enter(&mut fast_storage, || {
            batch.settle_state_with_calculated_gas(
                beneficiary,
                true,
                execution_config,
                &initial_gas,
            )
        })
        .expect("fast path should settle the simple transfer batch");

        let config = TempoEvmConfig::new(Arc::new(TempoChainSpec::moderato()));
        let mut sequential_executor = t6_executor(
            &config,
            seed_fast_path_cache_db(&initial_storage),
            beneficiary,
            block_timestamp,
            pool_txs.len(),
        );
        sequential_executor
            .apply_pre_execution_changes()
            .expect("sequential pre-execution changes should apply");

        let mut sequential_summaries = Vec::new();
        for (idx, pool_tx) in pool_txs.iter().enumerate() {
            let output = sequential_executor
                .execute_transaction_without_commit(pool_tx.transaction.executable())
                .expect("simple transfer should execute sequentially");
            assert!(
                output.result().result.is_success(),
                "sequential transfer {idx} should succeed"
            );

            let synthetic = settled.transactions()[idx].synthetic_commit();
            assert_eq!(
                synthetic.receipt.logs,
                output.result().result.logs(),
                "synthetic logs must match sequential logs for tx {idx}"
            );
            assert_eq!(
                synthetic.tx_gas_used,
                output.result().result.tx_gas_used(),
                "receipt gas must match for tx {idx}"
            );
            assert_eq!(
                synthetic.block_gas_used,
                output.block_gas_used(),
                "block gas must match for tx {idx}"
            );
            assert_eq!(
                synthetic.block_state_gas_used,
                output.state_gas_used(),
                "state gas must match for tx {idx}"
            );
            assert_eq!(
                synthetic.validator_fee,
                output.validator_fee(),
                "validator fee must match for tx {idx}"
            );
            sequential_summaries.push((
                output.block_gas_used(),
                output.state_gas_used(),
                output.validator_fee(),
            ));

            let gas_output = sequential_executor.commit_transaction(output);
            assert_eq!(gas_output.tx_gas_used(), synthetic.tx_gas_used);
            assert_eq!(gas_output.state_gas_used(), synthetic.block_state_gas_used);
        }

        let sequential_receipts = sequential_executor.receipts().to_vec();
        let (sequential_evm, sequential_result) = sequential_executor
            .finish()
            .expect("sequential executor should finish");
        let (sequential_db, _) = sequential_evm.finish();

        let mut synthetic_executor = t6_executor(
            &config,
            seed_fast_path_cache_db(&initial_storage),
            beneficiary,
            block_timestamp,
            pool_txs.len(),
        );
        synthetic_executor
            .apply_pre_execution_changes()
            .expect("synthetic pre-execution changes should apply");
        let committed = settled
            .commit_to_executor(&mut synthetic_executor)
            .expect("synthetic batch should commit");
        let synthetic_receipts = synthetic_executor.receipts().to_vec();
        let (synthetic_evm, synthetic_result) = synthetic_executor
            .finish()
            .expect("synthetic executor should finish");
        let (synthetic_db, _) = synthetic_evm.finish();

        assert_eq!(synthetic_receipts, sequential_receipts);
        assert_eq!(synthetic_result.gas_used, sequential_result.gas_used);
        assert_eq!(
            committed
                .summaries()
                .iter()
                .map(|summary| (
                    summary.block_gas_used,
                    summary.state_gas_used,
                    summary.validator_fee
                ))
                .collect::<Vec<_>>(),
            sequential_summaries
        );
        assert_eq!(
            committed.validator_fee(),
            sequential_summaries
                .iter()
                .fold(U256::ZERO, |acc, (_, _, fee)| acc + *fee)
        );
        for delta in settled.storage() {
            assert_eq!(
                storage_value(&sequential_db, delta.address, delta.slot),
                delta.present,
                "sequential final storage must match synthetic delta at {:?}:{:?}",
                delta.address,
                delta.slot
            );
        }

        let storage_addresses = BTreeSet::from([
            DEFAULT_FEE_TOKEN,
            NONCE_PRECOMPILE_ADDRESS,
            TIP_FEE_MANAGER_ADDRESS,
        ]);
        assert_eq!(
            storage_values(&synthetic_db, storage_addresses.iter().copied()),
            storage_values(&sequential_db, storage_addresses.iter().copied())
        );
    }

    #[test]
    fn fast_path_batch_matches_sequential_executor_for_expiring_nonce_t6_transfers() {
        let sender = Address::repeat_byte(0x11);
        let recipient_a = Address::repeat_byte(0x22);
        let recipient_b = Address::repeat_byte(0x44);
        let beneficiary = Address::repeat_byte(0x33);
        let block_timestamp = 10;
        let valid_before = block_timestamp + 20;
        let sender_start = U256::from(10_000_000_000_000_000_000u128);

        let policy_word =
            U256::from(ALLOW_ALL_POLICY_ID) << (tip20_slots::TRANSFER_POLICY_ID_OFFSET * 8);
        let initial_storage = vec![
            (
                DEFAULT_FEE_TOKEN,
                tip20_slots::CURRENCY,
                usd_currency_value(),
            ),
            (
                DEFAULT_FEE_TOKEN,
                tip20_slots::TRANSFER_POLICY_ID,
                policy_word,
            ),
            (
                DEFAULT_FEE_TOKEN,
                balance_slot(sender),
                opted_out_balance(sender_start),
            ),
            (
                DEFAULT_FEE_TOKEN,
                balance_slot(TIP_FEE_MANAGER_ADDRESS),
                opted_out_balance(U256::ZERO),
            ),
        ];

        let pool_txs = vec![
            aa_expiring_transfer_pool_tx(sender, recipient_a, U256::from(100), valid_before),
            aa_expiring_transfer_pool_tx(sender, recipient_b, U256::from(25), valid_before),
        ];

        let batch = preflight_tip20_transfer_batch(&pool_txs, block_timestamp)
            .expect("valid expiring nonce transfers should preflight");
        assert_eq!(batch.len(), pool_txs.len());

        let gas_params = tempo_gas_params_with_amsterdam(TempoHardfork::T6, false);
        let initial_gas = batch
            .calculate_initial_gas(Tip20InitialGasConfig {
                gas_params: &gas_params,
                spec: TempoHardfork::T6,
                eip7623_disabled: false,
                amsterdam_eip8037_enabled: false,
                tx_gas_limit_cap: TempoHardfork::T6
                    .tx_gas_limit_cap()
                    .expect("T6 has tx gas limit cap"),
                max_initcode_size: usize::MAX,
            })
            .expect("initial gas should include expiring nonce cost");
        let execution_config = Tip20ExecutionGasConfig {
            gas_params: &gas_params,
            spec: TempoHardfork::T6,
            amsterdam_eip8037_enabled: false,
            basefee: TEMPO_T1_BASE_FEE,
            chain_id: 1,
            timestamp: U256::from(block_timestamp),
            beneficiary,
            block_number: 1,
        };
        let mut fast_storage = seed_fast_path_hashmap_storage(&initial_storage);
        let settled = StorageCtx::enter(&mut fast_storage, || {
            batch.settle_state_with_calculated_gas(
                beneficiary,
                true,
                execution_config,
                &initial_gas,
            )
        })
        .expect("fast path should settle expiring nonce transfer batch");

        let config = TempoEvmConfig::new(Arc::new(TempoChainSpec::moderato()));
        let mut sequential_executor = t6_executor(
            &config,
            seed_fast_path_cache_db(&initial_storage),
            beneficiary,
            block_timestamp,
            pool_txs.len(),
        );
        sequential_executor
            .apply_pre_execution_changes()
            .expect("sequential pre-execution changes should apply");

        let mut sequential_summaries = Vec::new();
        for (idx, pool_tx) in pool_txs.iter().enumerate() {
            let output = sequential_executor
                .execute_transaction_without_commit(pool_tx.transaction.executable())
                .expect("expiring nonce transfer should execute sequentially");
            assert!(
                output.result().result.is_success(),
                "sequential transfer {idx} should succeed"
            );

            let synthetic = settled.transactions()[idx].synthetic_commit();
            assert_eq!(
                synthetic.receipt.logs,
                output.result().result.logs(),
                "synthetic logs must match sequential logs for tx {idx}"
            );
            assert_eq!(
                synthetic.tx_gas_used,
                output.result().result.tx_gas_used(),
                "receipt gas must match for tx {idx}"
            );
            assert_eq!(
                synthetic.block_gas_used,
                output.block_gas_used(),
                "block gas must match for tx {idx}"
            );
            assert_eq!(
                synthetic.block_state_gas_used,
                output.state_gas_used(),
                "state gas must match for tx {idx}"
            );
            assert_eq!(
                synthetic.validator_fee,
                output.validator_fee(),
                "validator fee must match for tx {idx}"
            );
            sequential_summaries.push((
                output.block_gas_used(),
                output.state_gas_used(),
                output.validator_fee(),
            ));

            let gas_output = sequential_executor.commit_transaction(output);
            assert_eq!(gas_output.tx_gas_used(), synthetic.tx_gas_used);
            assert_eq!(gas_output.state_gas_used(), synthetic.block_state_gas_used);
        }

        let sequential_receipts = sequential_executor.receipts().to_vec();
        let (sequential_evm, sequential_result) = sequential_executor
            .finish()
            .expect("sequential executor should finish");
        let (sequential_db, _) = sequential_evm.finish();

        let mut synthetic_executor = t6_executor(
            &config,
            seed_fast_path_cache_db(&initial_storage),
            beneficiary,
            block_timestamp,
            pool_txs.len(),
        );
        synthetic_executor
            .apply_pre_execution_changes()
            .expect("synthetic pre-execution changes should apply");
        let committed = settled
            .commit_to_executor(&mut synthetic_executor)
            .expect("synthetic batch should commit");
        let synthetic_receipts = synthetic_executor.receipts().to_vec();
        let (synthetic_evm, synthetic_result) = synthetic_executor
            .finish()
            .expect("synthetic executor should finish");
        let (synthetic_db, _) = synthetic_evm.finish();

        assert_eq!(synthetic_receipts, sequential_receipts);
        assert_eq!(synthetic_result.gas_used, sequential_result.gas_used);
        assert_eq!(
            committed
                .summaries()
                .iter()
                .map(|summary| (
                    summary.block_gas_used,
                    summary.state_gas_used,
                    summary.validator_fee
                ))
                .collect::<Vec<_>>(),
            sequential_summaries
        );
        for delta in settled.storage() {
            assert_eq!(
                storage_value(&sequential_db, delta.address, delta.slot),
                delta.present,
                "sequential final storage must match synthetic delta at {:?}:{:?}",
                delta.address,
                delta.slot
            );
        }

        let storage_addresses = BTreeSet::from([
            DEFAULT_FEE_TOKEN,
            NONCE_PRECOMPILE_ADDRESS,
            TIP_FEE_MANAGER_ADDRESS,
        ]);
        assert_eq!(
            storage_values(&synthetic_db, storage_addresses.iter().copied()),
            storage_values(&sequential_db, storage_addresses.iter().copied())
        );
        assert_eq!(
            storage_value(
                &synthetic_db,
                NONCE_PRECOMPILE_ADDRESS,
                nonce_slots::EXPIRING_NONCE_RING_PTR
            ),
            U256::from(pool_txs.len())
        );
    }

    #[test]
    fn settle_state_tracks_per_transaction_deltas_in_order() {
        let sender = Address::repeat_byte(0x11);
        let recipient = Address::repeat_byte(0x22);
        let beneficiary = Address::repeat_byte(0x33);
        let mut storage = HashMapStorageProvider::new(1);

        seed_allow_all_token(&mut storage);
        storage
            .sstore(DEFAULT_FEE_TOKEN, balance_slot(sender), U256::from(1_000))
            .unwrap();
        storage
            .sstore(DEFAULT_FEE_TOKEN, balance_slot(recipient), U256::from(10))
            .unwrap();
        storage
            .sstore(NONCE_PRECOMPILE_ADDRESS, nonce_slot(sender), U256::ZERO)
            .unwrap();

        let batch = Tip20TransferBatch {
            actions: vec![
                action(sender, recipient, 0, 100, 10),
                action(sender, recipient, 1, 50, 5),
            ],
        };
        let gas = [
            Tip20GasOutcome {
                charged_gas_used: 7,
                tx_gas_used: 21_000,
                block_regular_gas_used: 21_000,
                block_state_gas_used: 0,
                block_gas_used: 21_000,
                effective_gas_price: ONE_TOKEN_GAS_PRICE,
            },
            Tip20GasOutcome {
                charged_gas_used: 2,
                tx_gas_used: 21_000,
                block_regular_gas_used: 21_000,
                block_state_gas_used: 0,
                block_gas_used: 21_000,
                effective_gas_price: ONE_TOKEN_GAS_PRICE,
            },
        ];

        let settled = StorageCtx::enter(&mut storage, || {
            batch.settle_state(beneficiary, false, &gas)
        })
        .expect("settled repeated transfers should validate");
        let [first, second] = settled.transactions() else {
            panic!("expected two settled txs");
        };

        let sender_slot = balance_slot(sender);
        let recipient_slot = balance_slot(recipient);
        let fee_manager_slot = balance_slot(TIP_FEE_MANAGER_ADDRESS);
        let collected_slot = collected_fee_slot(beneficiary, DEFAULT_FEE_TOKEN);
        let nonce_slot = nonce_slot(sender);

        assert_eq!(
            tx_delta(first.storage(), DEFAULT_FEE_TOKEN, sender_slot),
            Tip20StorageDelta {
                address: DEFAULT_FEE_TOKEN,
                slot: sender_slot,
                original: U256::from(1_000),
                present: U256::from(893),
            }
        );
        assert_eq!(
            tx_delta(second.storage(), DEFAULT_FEE_TOKEN, sender_slot),
            Tip20StorageDelta {
                address: DEFAULT_FEE_TOKEN,
                slot: sender_slot,
                original: U256::from(893),
                present: U256::from(841),
            }
        );
        assert_eq!(
            tx_delta(second.storage(), DEFAULT_FEE_TOKEN, recipient_slot),
            Tip20StorageDelta {
                address: DEFAULT_FEE_TOKEN,
                slot: recipient_slot,
                original: U256::from(110),
                present: U256::from(160),
            }
        );
        assert_eq!(
            tx_delta(second.storage(), DEFAULT_FEE_TOKEN, fee_manager_slot),
            Tip20StorageDelta {
                address: DEFAULT_FEE_TOKEN,
                slot: fee_manager_slot,
                original: U256::from(7),
                present: U256::from(9),
            }
        );
        assert_eq!(
            tx_delta(second.storage(), TIP_FEE_MANAGER_ADDRESS, collected_slot),
            Tip20StorageDelta {
                address: TIP_FEE_MANAGER_ADDRESS,
                slot: collected_slot,
                original: U256::from(7),
                present: U256::from(9),
            }
        );
        assert_eq!(
            tx_delta(second.storage(), NONCE_PRECOMPILE_ADDRESS, nonce_slot),
            Tip20StorageDelta {
                address: NONCE_PRECOMPILE_ADDRESS,
                slot: nonce_slot,
                original: U256::from(1),
                present: U256::from(2),
            }
        );
        assert!(second.synthetic_storage_deltas().any(|delta| delta
            == TempoSyntheticStorageDelta {
                address: DEFAULT_FEE_TOKEN,
                slot: sender_slot,
                original: U256::from(893),
                present: U256::from(841),
            }));
        assert_eq!(
            settled_value(&settled, DEFAULT_FEE_TOKEN, sender_slot),
            U256::from(841)
        );
    }

    #[test]
    fn settled_state_aware_balance_updates_match_sequential_decrease_tracking() {
        let sender_a = Address::repeat_byte(0x11);
        let sender_b = Address::repeat_byte(0x22);
        let beneficiary = Address::repeat_byte(0x33);
        let mut storage = HashMapStorageProvider::new(1);

        seed_allow_all_token(&mut storage);
        storage
            .sstore(DEFAULT_FEE_TOKEN, balance_slot(sender_a), U256::from(1_000))
            .unwrap();
        storage
            .sstore(DEFAULT_FEE_TOKEN, balance_slot(sender_b), U256::from(200))
            .unwrap();
        storage
            .sstore(NONCE_PRECOMPILE_ADDRESS, nonce_slot(sender_a), U256::ZERO)
            .unwrap();
        storage
            .sstore(NONCE_PRECOMPILE_ADDRESS, nonce_slot(sender_b), U256::ZERO)
            .unwrap();

        let batch = Tip20TransferBatch {
            actions: vec![
                action(sender_a, sender_b, 0, 100, 10),
                action(sender_b, sender_a, 0, 20, 5),
            ],
        };
        let gas = [
            Tip20GasOutcome {
                charged_gas_used: 7,
                tx_gas_used: 21_000,
                block_regular_gas_used: 21_000,
                block_state_gas_used: 0,
                block_gas_used: 21_000,
                effective_gas_price: ONE_TOKEN_GAS_PRICE,
            },
            Tip20GasOutcome {
                charged_gas_used: 2,
                tx_gas_used: 21_000,
                block_regular_gas_used: 21_000,
                block_state_gas_used: 0,
                block_gas_used: 21_000,
                effective_gas_price: ONE_TOKEN_GAS_PRICE,
            },
        ];

        let settled = StorageCtx::enter(&mut storage, || {
            batch.settle_state(beneficiary, false, &gas)
        })
        .expect("cross-transfer batch should settle");

        let updates = settled.state_aware_balance_updates();
        assert_eq!(updates.len(), 2);
        assert!(updates.contains(&((DEFAULT_FEE_TOKEN, balance_slot(sender_a)), U256::from(913))));
        assert!(updates.contains(&((DEFAULT_FEE_TOKEN, balance_slot(sender_b)), U256::from(278))));
        assert!(!updates.iter().any(|((_, slot), _)| {
            *slot == TIP_FEE_MANAGER_ADDRESS.mapping_slot(tip20_slots::BALANCES)
        }));
    }

    #[test]
    fn settle_state_rejects_missing_gas_outcome() {
        let sender = Address::repeat_byte(0x11);
        let recipient = Address::repeat_byte(0x22);
        let beneficiary = Address::repeat_byte(0x33);
        let mut storage = HashMapStorageProvider::new(1);

        let batch = Tip20TransferBatch {
            actions: vec![action(sender, recipient, 0, 100, 10)],
        };

        let err = StorageCtx::enter(&mut storage, || batch.settle_state(beneficiary, false, &[]))
            .expect_err("missing gas data invalidates synthetic settlement");
        assert_eq!(err, FastPathFallbackReason::GasOutcomeMismatch);
    }

    #[test]
    fn settle_state_rejects_actual_fee_above_escrow() {
        let sender = Address::repeat_byte(0x11);
        let recipient = Address::repeat_byte(0x22);
        let beneficiary = Address::repeat_byte(0x33);
        let mut storage = HashMapStorageProvider::new(1);

        seed_allow_all_token(&mut storage);
        storage
            .sstore(DEFAULT_FEE_TOKEN, balance_slot(sender), U256::from(1_000))
            .unwrap();
        storage
            .sstore(NONCE_PRECOMPILE_ADDRESS, nonce_slot(sender), U256::ZERO)
            .unwrap();

        let batch = Tip20TransferBatch {
            actions: vec![action(sender, recipient, 0, 100, 10)],
        };
        let gas = [Tip20GasOutcome {
            charged_gas_used: 11,
            tx_gas_used: 21_000,
            block_regular_gas_used: 21_000,
            block_state_gas_used: 0,
            block_gas_used: 21_000,
            effective_gas_price: ONE_TOKEN_GAS_PRICE,
        }];

        let err = StorageCtx::enter(&mut storage, || {
            batch.settle_state(beneficiary, false, &gas)
        })
        .expect_err("actual fee above max escrow must reject");
        assert_eq!(err, FastPathFallbackReason::FeeUnderflow);
    }

    #[test]
    fn replace_tip20_balance_preserves_reward_metadata() {
        let raw = (U256::from(REWARD_FLAG_OPTED_OUT) << 128) | U256::from(10);

        assert_eq!(
            replace_tip20_balance(raw, U256::from(25)),
            (U256::from(REWARD_FLAG_OPTED_OUT) << 128) | U256::from(25)
        );
    }

    #[test]
    fn preflight_accepts_simple_sender_paid_tip20_transfer() {
        let sender = Address::repeat_byte(0x11);
        let tx = aa_pool_tx(sender, 3, |_| {});

        let action = preflight_tip20_transfer(&tx, 10).expect("simple transfer should preflight");

        assert_eq!(action.sender, sender);
        assert_eq!(action.token, DEFAULT_FEE_TOKEN);
        assert_eq!(action.nonce_key, U256::from(7));
        assert_eq!(action.nonce, 3);
        assert_eq!(action.amount, U256::from(1));
    }

    #[test]
    fn preflight_accepts_valid_expiring_nonce_tip20_transfer() {
        let sender = Address::repeat_byte(0x11);
        let tx = aa_pool_tx(sender, 0, |tx| {
            tx.nonce_key = TEMPO_EXPIRING_NONCE_KEY;
            tx.valid_before = Some(nz(20));
        });

        let action =
            preflight_tip20_transfer(&tx, 10).expect("valid expiring nonce should preflight");

        assert_eq!(action.sender, sender);
        assert_eq!(action.nonce_key, TEMPO_EXPIRING_NONCE_KEY);
        assert_eq!(action.nonce, 0);
        assert_eq!(action.valid_before, Some(20));
        assert_eq!(action.block_timestamp, 10);
        assert_eq!(
            action.expiring_nonce_hash,
            tx.transaction.expiring_nonce_hash()
        );
    }

    #[test]
    fn preflight_rejects_non_public_pool_transactions() {
        let sender = Address::repeat_byte(0x11);

        for origin in [TransactionOrigin::Local, TransactionOrigin::Private] {
            let tx = aa_pool_tx_with_resolved_fee_token_and_origin(
                sender,
                0,
                Some(DEFAULT_FEE_TOKEN),
                origin,
                |_| {},
            );
            let err =
                preflight_tip20_transfer(&tx, 10).expect_err("local/private pool tx must reject");
            assert_eq!(err, FastPathFallbackReason::NotPublicPool);
        }
    }

    #[test]
    fn preflight_rejects_non_transfer_tip20_calls() {
        let sender = Address::repeat_byte(0x11);
        for input in [
            Bytes::from(
                ITIP20::transferWithMemoCall {
                    to: Address::repeat_byte(0x22),
                    amount: U256::from(1),
                    memo: B256::repeat_byte(0x6d),
                }
                .abi_encode(),
            ),
            Bytes::from(
                ITIP20::transferFromCall {
                    from: Address::repeat_byte(0x33),
                    to: Address::repeat_byte(0x22),
                    amount: U256::from(1),
                }
                .abi_encode(),
            ),
        ] {
            let tx = aa_pool_tx(sender, 0, |tx| {
                tx.calls[0].input = input;
            });

            let err = preflight_tip20_transfer(&tx, 10).expect_err("unsupported call must reject");
            assert_eq!(err, FastPathFallbackReason::NotTransfer);
        }
    }

    #[test]
    fn preflight_rejects_unsupported_nonce_and_auth_shapes() {
        let sender = Address::repeat_byte(0x11);

        let tx = aa_pool_tx(sender, 0, |tx| {
            tx.nonce_key = U256::ZERO;
        });
        let err = preflight_tip20_transfer(&tx, 10).expect_err("protocol nonce must reject");
        assert_eq!(err, FastPathFallbackReason::Not2dNonce);

        let tx = aa_pool_tx(sender, 1, |tx| {
            tx.nonce_key = TEMPO_EXPIRING_NONCE_KEY;
            tx.valid_before = Some(nz(20));
        });
        let err =
            preflight_tip20_transfer(&tx, 10).expect_err("nonzero expiring nonce must reject");
        assert_eq!(err, FastPathFallbackReason::ExpiringNonce);

        let tx = aa_pool_tx(sender, 0, |tx| {
            tx.fee_payer_signature = Some(Signature::test_signature());
        });
        let err = preflight_tip20_transfer(&tx, 10).expect_err("sponsored tx must reject");
        assert_eq!(err, FastPathFallbackReason::SponsoredFeePayer);

        let tx = aa_pool_tx(sender, 0, |tx| {
            tx.key_authorization = Some(signed_key_authorization());
        });
        let err = preflight_tip20_transfer(&tx, 10).expect_err("key auth tx must reject");
        assert_eq!(err, FastPathFallbackReason::KeyAuthorization);

        let tx = aa_pool_tx(sender, 0, |tx| {
            tx.tempo_authorization_list.push(tempo_authorization());
        });
        let err = preflight_tip20_transfer(&tx, 10).expect_err("auth list tx must reject");
        assert_eq!(err, FastPathFallbackReason::AuthorizationList);

        let tx = aa_pool_tx(sender, 0, |tx| {
            tx.access_list = AccessList(vec![AccessListItem {
                address: Address::repeat_byte(0x44),
                storage_keys: vec![B256::repeat_byte(0x55)],
            }]);
        });
        let err = preflight_tip20_transfer(&tx, 10).expect_err("access list tx must reject");
        assert_eq!(err, FastPathFallbackReason::AccessList);
    }

    #[test]
    fn preflight_rejects_fee_token_and_validity_mismatches() {
        let sender = Address::repeat_byte(0x11);

        let tx = aa_pool_tx_with_resolved_fee_token(sender, 0, None, |_| {});
        let err = preflight_tip20_transfer(&tx, 10).expect_err("missing resolved token rejects");
        assert_eq!(err, FastPathFallbackReason::MissingResolvedFeeToken);

        let tx =
            aa_pool_tx_with_resolved_fee_token(sender, 0, Some(Address::repeat_byte(0x44)), |_| {});
        let err = preflight_tip20_transfer(&tx, 10).expect_err("resolved token mismatch rejects");
        assert_eq!(err, FastPathFallbackReason::FeeTokenMismatch);

        let tx = aa_pool_tx(sender, 0, |tx| {
            tx.fee_token = Some(Address::repeat_byte(0x44));
        });
        let err = preflight_tip20_transfer(&tx, 10).expect_err("explicit token mismatch rejects");
        assert_eq!(err, FastPathFallbackReason::FeeTokenMismatch);

        let tx = aa_pool_tx(sender, 0, |tx| {
            tx.valid_before = Some(nz(10));
        });
        let err = preflight_tip20_transfer(&tx, 10).expect_err("expired valid_before rejects");
        assert_eq!(err, FastPathFallbackReason::InvalidValidityWindow);

        let tx = aa_pool_tx(sender, 0, |tx| {
            tx.valid_after = Some(nz(11));
        });
        let err = preflight_tip20_transfer(&tx, 10).expect_err("future valid_after rejects");
        assert_eq!(err, FastPathFallbackReason::InvalidValidityWindow);

        let tx = aa_pool_tx(sender, 0, |tx| {
            tx.nonce_key = TEMPO_EXPIRING_NONCE_KEY;
        });
        let err =
            preflight_tip20_transfer(&tx, 10).expect_err("missing expiring valid_before rejects");
        assert_eq!(err, FastPathFallbackReason::ExpiringNonce);

        let tx = aa_pool_tx(sender, 0, |tx| {
            tx.nonce_key = TEMPO_EXPIRING_NONCE_KEY;
            tx.valid_before = Some(nz(41));
        });
        let err =
            preflight_tip20_transfer(&tx, 10).expect_err("too-far expiring valid_before rejects");
        assert_eq!(err, FastPathFallbackReason::ExpiringNonce);
    }
}

/// Runs a parallel static preflight over a fixed chunk of pool transactions.
///
/// This deliberately accepts only the v1 shape that can later be converted to
/// storage-slot action deltas: one sender-paid AA transaction, one 2D or valid
/// expiring nonce, one direct `ITIP20.transfer` call, and the same token for
/// transfer and fees.
pub(crate) fn preflight_tip20_transfer_batch(
    txs: &[Arc<ValidPoolTransaction<TempoPooledTransaction>>],
    block_timestamp: u64,
) -> Result<Tip20TransferBatch, FastPathFallbackReason> {
    if txs.is_empty() {
        return Err(FastPathFallbackReason::EmptyBatch);
    }

    let results = txs
        .par_iter()
        .map(|tx| preflight_tip20_transfer(tx, block_timestamp))
        .collect::<Vec<_>>();

    let actions = results
        .into_iter()
        .collect::<Result<Vec<_>, FastPathFallbackReason>>()?;

    Ok(Tip20TransferBatch { actions })
}

fn preflight_tip20_transfer(
    pool_tx: &Arc<ValidPoolTransaction<TempoPooledTransaction>>,
    block_timestamp: u64,
) -> Result<Tip20TransferActionSet, FastPathFallbackReason> {
    if !pool_tx.origin.is_external() {
        return Err(FastPathFallbackReason::NotPublicPool);
    }

    let recovered = pool_tx.transaction.inner();
    let TempoTxEnvelope::AA(aa_tx) = recovered.inner() else {
        return Err(FastPathFallbackReason::NotAa);
    };
    let tx = aa_tx.tx();

    let is_expiring_nonce = tx.nonce_key == TEMPO_EXPIRING_NONCE_KEY;
    if tx.nonce_key.is_zero() {
        return Err(FastPathFallbackReason::Not2dNonce);
    }
    if pool_tx.transaction.is_expiring_nonce() != is_expiring_nonce {
        return Err(FastPathFallbackReason::ExpiringNonce);
    }
    let (expiring_nonce_hash, expiring_valid_before) = if is_expiring_nonce {
        if tx.nonce != 0 {
            return Err(FastPathFallbackReason::ExpiringNonce);
        }
        let valid_before = tx
            .valid_before
            .ok_or(FastPathFallbackReason::ExpiringNonce)?
            .get();
        let max_valid_before = block_timestamp.saturating_add(EXPIRING_NONCE_MAX_EXPIRY_SECS);
        if valid_before <= block_timestamp || valid_before > max_valid_before {
            return Err(FastPathFallbackReason::ExpiringNonce);
        }
        (
            Some(
                pool_tx
                    .transaction
                    .expiring_nonce_hash()
                    .ok_or(FastPathFallbackReason::ExpiringNonce)?,
            ),
            Some(valid_before),
        )
    } else {
        (None, tx.valid_before.map(|valid_before| valid_before.get()))
    };
    if tx.fee_payer_signature.is_some()
        || pool_tx.transaction.fee_payer().ok() != Some(pool_tx.sender())
    {
        return Err(FastPathFallbackReason::SponsoredFeePayer);
    }
    if tx.key_authorization.is_some() {
        return Err(FastPathFallbackReason::KeyAuthorization);
    }
    if !tx.tempo_authorization_list.is_empty() {
        return Err(FastPathFallbackReason::AuthorizationList);
    }
    if !tx.access_list.is_empty() {
        return Err(FastPathFallbackReason::AccessList);
    }
    if !matches!(
        aa_tx.signature(),
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(_))
    ) {
        return Err(FastPathFallbackReason::NonPrimitiveSignature);
    }
    if tx
        .valid_before
        .is_some_and(|valid_before| valid_before.get() <= block_timestamp)
        || tx
            .valid_after
            .is_some_and(|valid_after| valid_after.get() > block_timestamp)
    {
        return Err(FastPathFallbackReason::InvalidValidityWindow);
    }

    let [call] = tx.calls.as_slice() else {
        return Err(FastPathFallbackReason::MultiCall);
    };
    let Some(&token) = call.to.to() else {
        return Err(FastPathFallbackReason::CreateCall);
    };
    if !call.value.is_zero() || !recovered.value().is_zero() {
        return Err(FastPathFallbackReason::CallValue);
    }

    let transfer = ITIP20::transferCall::abi_decode(call.input.as_ref())
        .map_err(|_| FastPathFallbackReason::NotTransfer)?;

    let fee_token = pool_tx
        .transaction
        .resolved_fee_token()
        .ok_or(FastPathFallbackReason::MissingResolvedFeeToken)?;
    if fee_token != token || tx.fee_token.is_some_and(|raw| raw != token) {
        return Err(FastPathFallbackReason::FeeTokenMismatch);
    }

    Ok(Tip20TransferActionSet {
        pool_tx: Arc::clone(pool_tx),
        sender: pool_tx.sender(),
        token,
        recipient: transfer.to,
        amount: transfer.amount,
        nonce_key: tx.nonce_key,
        nonce: tx.nonce,
        expiring_nonce_hash,
        valid_before: expiring_valid_before,
        block_timestamp,
        max_fee: pool_tx.transaction.fee_token_cost(),
    })
}
