use crate::{TempoBlockExecutor, TempoTxResult};
use alloy_evm::{
    Evm, RecoveredTx,
    block::{BlockExecutionError, BlockExecutor},
};
use alloy_primitives::{Address, B256, IntoLogData, Log, TxKind, U256};
use alloy_sol_types::SolInterface;
use rayon::prelude::*;
use reth_evm::block::StateDB;
use reth_primitives_traits::Recovered;
use reth_revm::{
    Inspector,
    context::{Block as _, Cfg as _, CfgEnv, Transaction as _, result::ResultGas},
    context_interface::{
        cfg::{GasId, GasParams, gas},
        context::SStoreResult,
    },
    interpreter::InitialAndFloorGas,
    state::{Account, AccountInfo, EvmState, EvmStorageSlot, TransactionId},
};
use std::collections::{HashMap, HashSet};
use tempo_chainspec::{
    constants::gas::tempo_t6_discounted_payment_effective_gas_price, hardfork::TempoHardfork,
};
use tempo_contracts::precompiles::{ITIP20, NonceEvent, TIP20Event};
use tempo_precompiles::{
    NONCE_PRECOMPILE_ADDRESS, TIP_FEE_MANAGER_ADDRESS, TIP403_REGISTRY_ADDRESS, input_cost,
    storage::StorageKey as _,
    tip_fee_manager::TipFeeManager,
    tip20::{U128_MAX, decode_tip20_balance, tip20_slots},
    tip403_registry::{ALLOW_ALL_POLICY_ID, tip403_registry_slots},
};
use tempo_primitives::{
    TempoAddressExt, TempoTxEnvelope,
    transaction::{TEMPO_EXPIRING_NONCE_KEY, calc_gas_balance_spending},
};
use tempo_revm::{
    TempoTxEnv, calculate_aa_batch_intrinsic_gas, evm::TempoContext, gas_params::SSTORE_SET_COST,
};

/// One payload-builder candidate for the BlockSTM TIP-20 transfer path.
#[derive(Debug)]
pub struct Tip20TransferBlockstmTx<'tx> {
    /// Cached transaction environment used by the normal block executor.
    pub tx_env: TempoTxEnv,
    /// Recovered transaction, retained for receipt construction and transaction validation.
    pub recovered: &'tx Recovered<TempoTxEnvelope>,
    /// Fee token resolved by pool validation.
    pub fee_token: Address,
}

/// Summary emitted after a BlockSTM TIP-20 transfer batch completes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tip20TransferBlockstmBatchStats {
    /// Number of transactions in the batch.
    pub transaction_count: usize,
    /// Number of decoded direct transfer actions.
    pub action_count: usize,
    /// Number of distinct storage keys read by the custom action plans.
    pub read_set_count: usize,
    /// Number of distinct storage keys written by the custom action plans.
    pub write_set_count: usize,
    /// Number of speculative conflict retries.
    pub retry_count: usize,
}

/// Reason the BlockSTM TIP-20 transfer path cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tip20TransferBlockstmFallback {
    EmptyBatch,
    FeeTokenMismatch,
    ExpiringNonce,
    SubblockTransaction,
    ValueTransfer,
    AccessList,
    Eip7702Authorization,
    TempoAuthorization,
    KeyAuthorization,
    KeychainSignature,
    InvalidFeePayer,
    InvalidFeeCharge,
    InvalidNonce,
    AccountHasCode,
    GasLimit,
    GasOverflow,
    InsufficientBalance,
    BalanceOverflow,
    StmValidation,
    EmptyCalls,
    ContractCreation,
    NonTip20Target,
    TransferFrom,
    UnsupportedSelector,
    InvalidCalldata,
    InvalidRecipient,
    VirtualRecipient,
    TokenPaused,
    TransferPolicy,
    ReceivePolicy,
    RewardActive,
}

impl Tip20TransferBlockstmFallback {
    /// Returns the stable metric label for this fallback reason.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmptyBatch => "empty_batch",
            Self::FeeTokenMismatch => "fee_token_mismatch",
            Self::ExpiringNonce => "expiring_nonce",
            Self::SubblockTransaction => "subblock_transaction",
            Self::ValueTransfer => "value_transfer",
            Self::AccessList => "access_list",
            Self::Eip7702Authorization => "eip7702_authorization",
            Self::TempoAuthorization => "tempo_authorization",
            Self::KeyAuthorization => "key_authorization",
            Self::KeychainSignature => "keychain_signature",
            Self::InvalidFeePayer => "invalid_fee_payer",
            Self::InvalidFeeCharge => "invalid_fee_charge",
            Self::InvalidNonce => "invalid_nonce",
            Self::AccountHasCode => "account_has_code",
            Self::GasLimit => "gas_limit",
            Self::GasOverflow => "gas_overflow",
            Self::InsufficientBalance => "insufficient_balance",
            Self::BalanceOverflow => "balance_overflow",
            Self::StmValidation => "stm_validation",
            Self::EmptyCalls => "empty_calls",
            Self::ContractCreation => "contract_creation",
            Self::NonTip20Target => "non_tip20_target",
            Self::TransferFrom => "transfer_from",
            Self::UnsupportedSelector => "unsupported_selector",
            Self::InvalidCalldata => "invalid_calldata",
            Self::InvalidRecipient => "invalid_recipient",
            Self::VirtualRecipient => "virtual_recipient",
            Self::TokenPaused => "token_paused",
            Self::TransferPolicy => "transfer_policy",
            Self::ReceivePolicy => "receive_policy",
            Self::RewardActive => "reward_active",
        }
    }
}

/// Error returned by the BlockSTM TIP-20 transfer batch API.
#[derive(Debug)]
pub enum Tip20TransferBlockstmBatchError {
    /// The batch is not eligible for BlockSTM execution; no transaction was executed.
    Fallback(Tip20TransferBlockstmFallback),
    /// Synthetic validation/execution rejected a transaction. Previous transactions in the batch
    /// were already committed through the normal block executor commit path.
    Execution {
        /// Index of the failed transaction in the attempted batch.
        transaction_index: usize,
        /// Execution error returned by synthetic result construction or block validation.
        error: BlockExecutionError,
    },
    /// The batch preflight failed while reading state; no transaction was executed.
    Database(BlockExecutionError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct StorageKey {
    address: Address,
    slot: U256,
}

#[derive(Debug, Clone)]
struct Tip20BlockstmExecution {
    txs: Vec<Tip20BlockstmTxExecution>,
    retry_count: usize,
}

#[derive(Debug, Clone, Default)]
struct Tip20BlockstmBaseState {
    storage: HashMap<StorageKey, U256>,
    accounts: HashMap<Address, AccountInfo>,
}

#[derive(Debug, Clone)]
struct Tip20BlockstmTxExecution {
    reads: HashMap<StorageKey, VersionedValue>,
    writes: HashMap<StorageKey, U256>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VersionedValue {
    version: Option<usize>,
    value: U256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Tip20TransferBlockstmPlan {
    nonce: Tip20BlockstmNonceAction,
    fee_payer: Address,
    max_fee: U256,
    actions: Vec<Tip20BlockstmAction>,
}

impl Tip20TransferBlockstmPlan {
    fn read_set(&self) -> HashSet<StorageKey> {
        core::iter::once(self.nonce.read_key())
            .chain(self.actions.iter().flat_map(Tip20BlockstmAction::read_set))
            .collect()
    }

    fn write_set(&self) -> HashSet<StorageKey> {
        core::iter::once(self.nonce.write_key())
            .chain(self.actions.iter().flat_map(Tip20BlockstmAction::write_set))
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tip20BlockstmNonceAction {
    Protocol {
        caller: Address,
        nonce: u64,
    },
    TwoDimensional {
        caller: Address,
        nonce_key: U256,
        nonce: u64,
    },
}

impl Tip20BlockstmNonceAction {
    fn caller(self) -> Address {
        match self {
            Self::Protocol { caller, .. } | Self::TwoDimensional { caller, .. } => caller,
        }
    }

    fn read_key(self) -> StorageKey {
        match self {
            Self::Protocol { caller, .. } => protocol_nonce_key(caller),
            Self::TwoDimensional {
                caller, nonce_key, ..
            } => two_dimensional_nonce_key(caller, nonce_key),
        }
    }

    fn write_key(self) -> StorageKey {
        self.read_key()
    }

    fn log(self) -> Option<Log> {
        match self {
            Self::Protocol { .. } => None,
            Self::TwoDimensional {
                caller,
                nonce_key,
                nonce,
            } => Some(Log {
                address: NONCE_PRECOMPILE_ADDRESS,
                data: NonceEvent::nonce_incremented(caller, nonce_key, nonce.saturating_add(1))
                    .into_log_data(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tip20BlockstmAction {
    FeeReserve {
        token: Address,
        fee_payer: Address,
        amount: U256,
    },
    Transfer(Tip20TransferAction),
    FeeSettle {
        token: Address,
        fee_payer: Address,
        beneficiary: Address,
        max_amount: U256,
    },
}

impl Tip20BlockstmAction {
    fn read_set(&self) -> Vec<StorageKey> {
        match self {
            Self::FeeReserve {
                token, fee_payer, ..
            } => token_state_read_set(*token)
                .into_iter()
                .chain(reward_inactive_read_set(*token, *fee_payer))
                .chain(reward_inactive_read_set(*token, TIP_FEE_MANAGER_ADDRESS))
                .collect(),
            Self::Transfer(action) => token_state_read_set(action.token)
                .into_iter()
                .chain(reward_inactive_read_set(action.token, action.from))
                .chain(reward_inactive_read_set(action.token, action.to))
                .chain([receive_policy_key(action.to)])
                .collect(),
            Self::FeeSettle {
                token,
                fee_payer,
                beneficiary,
                ..
            } => reward_inactive_read_set(*token, *fee_payer)
                .into_iter()
                .chain(reward_inactive_read_set(*token, TIP_FEE_MANAGER_ADDRESS))
                .chain([collected_fees_key(*beneficiary, *token)])
                .collect(),
        }
    }

    fn write_set(&self) -> Vec<StorageKey> {
        match self {
            Self::FeeReserve {
                token, fee_payer, ..
            }
            | Self::FeeSettle {
                token, fee_payer, ..
            } => vec![
                balance_key(*token, *fee_payer),
                balance_key(*token, TIP_FEE_MANAGER_ADDRESS),
            ],
            Self::Transfer(action) => action.write_set().into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Tip20TransferAction {
    token: Address,
    from: Address,
    to: Address,
    amount: U256,
    memo: Option<B256>,
    calldata_len: usize,
}

impl Tip20TransferAction {
    fn calldata_len(&self) -> usize {
        self.calldata_len
    }

    fn write_set(&self) -> [StorageKey; 2] {
        [
            balance_key(self.token, self.from),
            balance_key(self.token, self.to),
        ]
    }
}

impl<'a, DB, I> TempoBlockExecutor<'a, DB, I>
where
    DB: StateDB,
    I: Inspector<TempoContext<DB>>,
{
    /// Executes a strict direct TIP-20 transfer batch through the BlockSTM entry point.
    ///
    /// This first decodes direct transfer actions in parallel and derives per-action storage keys.
    /// The commit step intentionally goes through the canonical block executor, preserving Tempo's
    /// existing fee accounting, receipt construction, logs, BAL indexing, and section accounting.
    pub fn execute_tip20_transfer_blockstm_batch<'tx>(
        &mut self,
        txs: Vec<Tip20TransferBlockstmTx<'tx>>,
        validator_token: Address,
        mut on_result: impl FnMut(usize, &TempoTxResult),
    ) -> Result<Tip20TransferBlockstmBatchStats, Tip20TransferBlockstmBatchError> {
        if txs.is_empty() {
            return Err(Tip20TransferBlockstmBatchError::Fallback(
                Tip20TransferBlockstmFallback::EmptyBatch,
            ));
        }

        let block = self.inner.evm.block();
        let beneficiary = block.beneficiary;
        let basefee = block.basefee as u128;
        let blob_gasprice = block.blob_gasprice().unwrap_or_default();

        let decoded = txs
            .par_iter()
            .map(|tx| {
                build_tip20_transfer_plan(tx, validator_token, beneficiary, basefee, blob_gasprice)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(Tip20TransferBlockstmBatchError::Fallback)?;
        self.validate_tip20_transfer_state(&decoded)?;

        let base_state = self.read_plan_base_state(&decoded)?;
        let execution = execute_tip20_transfer_plans_blockstm(
            &decoded,
            &base_state.storage,
            self.inner.evm.cfg.spec.is_t6(),
        )
        .map_err(Tip20TransferBlockstmBatchError::Fallback)?;

        let action_count = decoded
            .iter()
            .flat_map(|plan| &plan.actions)
            .filter(|action| matches!(action, Tip20BlockstmAction::Transfer(_)))
            .count();
        let read_set_count = execution.txs.iter().map(|tx| tx.reads.len()).sum();
        let write_set_count = execution.txs.iter().map(|tx| tx.writes.len()).sum();

        for (index, ((tx, tx_execution), plan)) in txs
            .into_iter()
            .zip(&execution.txs)
            .zip(&decoded)
            .enumerate()
        {
            let mut tx_execution = tx_execution.clone();
            let gas = synthetic_tip20_result_gas(
                &tx.tx_env,
                plan,
                &tx_execution,
                &base_state,
                &self.inner.evm.cfg,
            )
            .map_err(Tip20TransferBlockstmBatchError::Fallback)?;
            let tx_gas_used = gas.tx_gas_used();
            let actual_fee = synthetic_actual_fee(
                &tx.tx_env,
                tx_gas_used,
                basefee,
                self.inner.evm.cfg.spec.is_t6(),
            );
            settle_actual_fee(
                plan,
                &mut tx_execution,
                actual_fee,
                self.inner.evm.cfg.spec.is_t6(),
            )
            .map_err(Tip20TransferBlockstmBatchError::Fallback)?;
            let block_gas_used = if self.inner.evm.cfg.enable_amsterdam_eip8037 {
                gas.block_regular_gas_used()
            } else {
                tx_gas_used
            };
            let next_section = self
                .validate_tx(tx.recovered.tx(), block_gas_used)
                .map_err(|error| Tip20TransferBlockstmBatchError::Execution {
                    transaction_index: index,
                    error: error.into(),
                })?;
            let result = TempoTxResult::new_blockstm_tip20_success(
                tx.recovered.tx(),
                execution_state(&tx_execution, &base_state),
                synthetic_tip20_logs(plan, actual_fee),
                gas,
                next_section,
                self.is_payment(tx.recovered.tx()),
                block_gas_used,
                actual_fee,
            );
            on_result(index, &result);
            self.commit_transaction(result);
        }

        Ok(Tip20TransferBlockstmBatchStats {
            transaction_count: decoded.len(),
            action_count,
            read_set_count,
            write_set_count,
            retry_count: execution.retry_count,
        })
    }

    fn validate_tip20_transfer_state(
        &mut self,
        plans: &[Tip20TransferBlockstmPlan],
    ) -> Result<(), Tip20TransferBlockstmBatchError> {
        let mut token_accounts = HashMap::<Address, HashSet<Address>>::new();

        for plan in plans {
            for action in &plan.actions {
                match action {
                    Tip20BlockstmAction::FeeReserve {
                        token, fee_payer, ..
                    }
                    | Tip20BlockstmAction::FeeSettle {
                        token, fee_payer, ..
                    } => {
                        token_accounts
                            .entry(*token)
                            .or_default()
                            .extend([*fee_payer, TIP_FEE_MANAGER_ADDRESS]);
                    }
                    Tip20BlockstmAction::Transfer(action) => {
                        validate_direct_recipient(action.to)?;
                        self.validate_receive_policy(action.to)?;

                        token_accounts
                            .entry(action.token)
                            .or_default()
                            .extend([action.from, action.to]);
                    }
                }
            }
        }

        for (token, accounts) in token_accounts {
            self.validate_token_global_state(token)?;
            for account in accounts {
                self.validate_reward_inactive(token, account)?;
            }
        }

        Ok(())
    }

    fn validate_token_global_state(
        &mut self,
        token: Address,
    ) -> Result<(), Tip20TransferBlockstmBatchError> {
        if self.read_storage(token, tip20_slots::PAUSED)? != U256::ZERO {
            return Err(Tip20TransferBlockstmBatchError::Fallback(
                Tip20TransferBlockstmFallback::TokenPaused,
            ));
        }

        let transfer_policy = self.read_storage(token, tip20_slots::TRANSFER_POLICY_ID)?;
        if transfer_policy_id(transfer_policy) != U256::from(ALLOW_ALL_POLICY_ID) {
            return Err(Tip20TransferBlockstmBatchError::Fallback(
                Tip20TransferBlockstmFallback::TransferPolicy,
            ));
        }

        if self.read_storage(token, tip20_slots::GLOBAL_REWARD_PER_TOKEN)? != U256::ZERO
            || self.read_storage(token, tip20_slots::OPTED_IN_SUPPLY)? != U256::ZERO
        {
            return Err(Tip20TransferBlockstmBatchError::Fallback(
                Tip20TransferBlockstmFallback::RewardActive,
            ));
        }

        Ok(())
    }

    fn validate_receive_policy(
        &mut self,
        account: Address,
    ) -> Result<(), Tip20TransferBlockstmBatchError> {
        let receive_policy_config = self.read_storage(
            TIP403_REGISTRY_ADDRESS,
            account.mapping_slot(tip403_registry_slots::RECEIVE_POLICIES),
        )?;
        if receive_policy_config != U256::ZERO {
            return Err(Tip20TransferBlockstmBatchError::Fallback(
                Tip20TransferBlockstmFallback::ReceivePolicy,
            ));
        }

        Ok(())
    }

    fn validate_reward_inactive(
        &mut self,
        token: Address,
        account: Address,
    ) -> Result<(), Tip20TransferBlockstmBatchError> {
        let balance = self.read_storage(token, balance_slot(account))?;
        decode_balance_state(balance).map_err(Tip20TransferBlockstmBatchError::Fallback)?;

        let reward_info_base = account.mapping_slot(tip20_slots::USER_REWARD_INFO);
        for offset in 0..USER_REWARD_INFO_SLOTS {
            if self.read_storage(token, reward_info_base + U256::from(offset))? != U256::ZERO {
                return Err(Tip20TransferBlockstmBatchError::Fallback(
                    Tip20TransferBlockstmFallback::RewardActive,
                ));
            }
        }

        Ok(())
    }

    fn read_storage(
        &mut self,
        address: Address,
        slot: U256,
    ) -> Result<U256, Tip20TransferBlockstmBatchError> {
        self.inner
            .evm
            .db_mut()
            .storage(address, slot)
            .map_err(BlockExecutionError::other)
            .map_err(Tip20TransferBlockstmBatchError::Database)
    }

    fn read_plan_base_state(
        &mut self,
        plans: &[Tip20TransferBlockstmPlan],
    ) -> Result<Tip20BlockstmBaseState, Tip20TransferBlockstmBatchError> {
        let mut keys = HashSet::new();
        let mut caller_accounts = HashSet::new();
        for plan in plans {
            keys.extend(plan.read_set());
            keys.extend(plan.write_set());
            caller_accounts.insert(plan.nonce.caller());
        }
        let mut accounts = keys.iter().map(|key| key.address).collect::<HashSet<_>>();
        accounts.extend(caller_accounts.iter().copied());

        let mut storage = HashMap::with_capacity(keys.len());
        for key in keys {
            let value = if is_protocol_nonce_key(key) {
                let info = self.read_account_info(key.address)?;
                U256::from(info.nonce)
            } else {
                self.read_storage(key.address, key.slot)?
            };
            storage.insert(key, value);
        }

        let mut account_infos = HashMap::with_capacity(accounts.len());
        for account in accounts {
            let info = self.read_account_info(account)?;
            account_infos.insert(account, info);
        }
        for caller in caller_accounts {
            let Some(info) = account_infos.get(&caller) else {
                return Err(Tip20TransferBlockstmBatchError::Fallback(
                    Tip20TransferBlockstmFallback::StmValidation,
                ));
            };
            if !info.is_empty_code_hash() {
                return Err(Tip20TransferBlockstmBatchError::Fallback(
                    Tip20TransferBlockstmFallback::AccountHasCode,
                ));
            }
        }

        Ok(Tip20BlockstmBaseState {
            storage,
            accounts: account_infos,
        })
    }

    fn read_account_info(
        &mut self,
        address: Address,
    ) -> Result<AccountInfo, Tip20TransferBlockstmBatchError> {
        self.inner
            .evm
            .db_mut()
            .basic(address)
            .map_err(BlockExecutionError::other)
            .map_err(Tip20TransferBlockstmBatchError::Database)
            .map(|account| account.unwrap_or_default())
    }
}

const USER_REWARD_INFO_SLOTS: u64 = 3;
const U64_MASK: U256 = U256::from_limbs([u64::MAX, 0, 0, 0]);
const REWARD_FLAG_SHIFT_BITS: usize = 128;
const REWARD_FLAG_OPTED_OUT: u8 = 1;
const REWARD_FLAG_OPTED_IN: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tip20BalanceState {
    amount: U256,
    reward_flag: u8,
}

impl Tip20BalanceState {
    fn inactive_write_flag(self) -> u8 {
        if self.reward_flag == 0 {
            REWARD_FLAG_OPTED_OUT
        } else {
            self.reward_flag
        }
    }
}

fn validate_direct_recipient(to: Address) -> Result<(), Tip20TransferBlockstmBatchError> {
    if to.is_zero() || to.is_tip20() {
        return Err(Tip20TransferBlockstmBatchError::Fallback(
            Tip20TransferBlockstmFallback::InvalidRecipient,
        ));
    }
    if to.is_virtual() {
        return Err(Tip20TransferBlockstmBatchError::Fallback(
            Tip20TransferBlockstmFallback::VirtualRecipient,
        ));
    }

    Ok(())
}

fn transfer_policy_id(raw: U256) -> U256 {
    (raw >> (tip20_slots::TRANSFER_POLICY_ID_OFFSET * 8)) & U64_MASK
}

fn decode_balance_state(raw: U256) -> Result<Tip20BalanceState, Tip20TransferBlockstmFallback> {
    let amount = decode_tip20_balance(raw);
    let flag_word = raw >> REWARD_FLAG_SHIFT_BITS;
    if flag_word > U256::from(u8::MAX) {
        return Err(Tip20TransferBlockstmFallback::RewardActive);
    }

    let reward_flag = flag_word.to::<u8>();
    if reward_flag >= REWARD_FLAG_OPTED_IN {
        return Err(Tip20TransferBlockstmFallback::RewardActive);
    }

    Ok(Tip20BalanceState {
        amount,
        reward_flag,
    })
}

fn encode_balance(amount: U256, reward_flag: u8, is_t6: bool) -> U256 {
    if is_t6 {
        amount | (U256::from(reward_flag) << REWARD_FLAG_SHIFT_BITS)
    } else {
        amount
    }
}

fn build_tip20_transfer_plan(
    tx: &Tip20TransferBlockstmTx<'_>,
    validator_token: Address,
    beneficiary: Address,
    basefee: u128,
    blob_gasprice: u128,
) -> Result<Tip20TransferBlockstmPlan, Tip20TransferBlockstmFallback> {
    let transfers = decode_tip20_transfer_actions(tx, validator_token)?;
    let nonce = decode_nonce_action(&tx.tx_env)?;
    let fee_payer = tx
        .tx_env
        .fee_payer()
        .map_err(|_| Tip20TransferBlockstmFallback::InvalidFeePayer)?;
    let max_fee = tx
        .tx_env
        .effective_balance_spending(basefee, blob_gasprice)
        .and_then(|spending| {
            spending
                .checked_sub(tx.tx_env.value())
                .ok_or(reth_revm::context::result::InvalidTransaction::OverflowPaymentInTransaction)
        })
        .map_err(|_| Tip20TransferBlockstmFallback::InvalidFeeCharge)?;

    let mut actions = Vec::with_capacity(transfers.len() + usize::from(!max_fee.is_zero()) * 2);
    if !max_fee.is_zero() {
        actions.push(Tip20BlockstmAction::FeeReserve {
            token: tx.fee_token,
            fee_payer,
            amount: max_fee,
        });
    }
    actions.extend(transfers.into_iter().map(Tip20BlockstmAction::Transfer));
    if !max_fee.is_zero() {
        actions.push(Tip20BlockstmAction::FeeSettle {
            token: tx.fee_token,
            fee_payer,
            beneficiary,
            max_amount: max_fee,
        });
    }

    Ok(Tip20TransferBlockstmPlan {
        nonce,
        fee_payer,
        max_fee,
        actions,
    })
}

fn execute_tip20_transfer_plans_blockstm(
    plans: &[Tip20TransferBlockstmPlan],
    base_storage: &HashMap<StorageKey, U256>,
    is_t6: bool,
) -> Result<Tip20BlockstmExecution, Tip20TransferBlockstmFallback> {
    let mut versions = HashMap::<StorageKey, Vec<(usize, U256)>>::new();
    let mut executions = vec![None; plans.len()];
    let mut pending = (0..plans.len()).collect::<Vec<_>>();
    let mut retry_count = 0;

    while !pending.is_empty() {
        let version_snapshot = versions.clone();
        let attempts = pending
            .par_iter()
            .map(|&index| {
                (
                    index,
                    execute_tip20_transfer_plan(
                        index,
                        &plans[index],
                        base_storage,
                        &version_snapshot,
                        is_t6,
                    ),
                )
            })
            .collect::<Vec<_>>();

        let mut next_pending = Vec::new();
        let mut committed = 0;
        for (index, execution) in attempts {
            let execution = match execution {
                Ok(execution) => execution,
                Err(Tip20TransferBlockstmFallback::InvalidNonce) => {
                    retry_count += 1;
                    next_pending.push(index);
                    continue;
                }
                Err(err) => return Err(err),
            };
            if validate_tip20_execution_reads(index, &execution, base_storage, &versions) {
                for (key, value) in &execution.writes {
                    versions.entry(*key).or_default().push((index, *value));
                }
                executions[index] = Some(execution);
                committed += 1;
            } else {
                retry_count += 1;
                next_pending.push(index);
            }
        }

        if committed == 0 {
            return Err(Tip20TransferBlockstmFallback::StmValidation);
        }
        pending = next_pending;
    }

    let txs = executions
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(Tip20TransferBlockstmFallback::StmValidation)?;

    Ok(Tip20BlockstmExecution { txs, retry_count })
}

fn execute_tip20_transfer_plan(
    tx_index: usize,
    plan: &Tip20TransferBlockstmPlan,
    base_storage: &HashMap<StorageKey, U256>,
    versions: &HashMap<StorageKey, Vec<(usize, U256)>>,
    is_t6: bool,
) -> Result<Tip20BlockstmTxExecution, Tip20TransferBlockstmFallback> {
    let mut execution = Tip20BlockstmTxExecution {
        reads: HashMap::new(),
        writes: HashMap::new(),
    };

    for key in plan.read_set() {
        let value = read_versioned(base_storage, versions, tx_index, key);
        execution.reads.insert(key, value);
    }

    apply_nonce_action(plan.nonce, &mut execution, base_storage, versions, tx_index)?;

    for action in &plan.actions {
        match action {
            Tip20BlockstmAction::FeeReserve {
                token,
                fee_payer,
                amount,
            } => transfer_balance(
                *token,
                *fee_payer,
                TIP_FEE_MANAGER_ADDRESS,
                *amount,
                is_t6,
                &mut execution,
                base_storage,
                versions,
                tx_index,
            )?,
            Tip20BlockstmAction::Transfer(action) => transfer_balance(
                action.token,
                action.from,
                action.to,
                action.amount,
                is_t6,
                &mut execution,
                base_storage,
                versions,
                tx_index,
            )?,
            Tip20BlockstmAction::FeeSettle {
                token,
                beneficiary,
                max_amount,
                ..
            } => {
                let key = collected_fees_key(*beneficiary, *token);
                let current = read_for_write(&mut execution, base_storage, versions, tx_index, key);
                let new_value = current
                    .checked_add(*max_amount)
                    .ok_or(Tip20TransferBlockstmFallback::BalanceOverflow)?;
                execution.writes.insert(key, new_value);
            }
        }
    }

    Ok(execution)
}

fn apply_nonce_action(
    action: Tip20BlockstmNonceAction,
    execution: &mut Tip20BlockstmTxExecution,
    base_storage: &HashMap<StorageKey, U256>,
    versions: &HashMap<StorageKey, Vec<(usize, U256)>>,
    tx_index: usize,
) -> Result<(), Tip20TransferBlockstmFallback> {
    let key = action.write_key();
    let current = read_for_write(execution, base_storage, versions, tx_index, key);
    let expected = match action {
        Tip20BlockstmNonceAction::Protocol { nonce, .. }
        | Tip20BlockstmNonceAction::TwoDimensional { nonce, .. } => nonce,
    };
    if current != U256::from(expected) {
        return Err(Tip20TransferBlockstmFallback::InvalidNonce);
    }
    let next = expected
        .checked_add(1)
        .ok_or(Tip20TransferBlockstmFallback::InvalidNonce)?;
    execution.writes.insert(key, U256::from(next));

    Ok(())
}

fn settle_actual_fee(
    plan: &Tip20TransferBlockstmPlan,
    execution: &mut Tip20BlockstmTxExecution,
    actual_fee: U256,
    is_t6: bool,
) -> Result<(), Tip20TransferBlockstmFallback> {
    let Some((token, fee_payer, beneficiary, max_amount)) =
        plan.actions.iter().find_map(|action| match action {
            Tip20BlockstmAction::FeeSettle {
                token,
                fee_payer,
                beneficiary,
                max_amount,
            } => Some((*token, *fee_payer, *beneficiary, *max_amount)),
            _ => None,
        })
    else {
        return if actual_fee.is_zero() {
            Ok(())
        } else {
            Err(Tip20TransferBlockstmFallback::InvalidFeeCharge)
        };
    };

    if actual_fee > max_amount {
        return Err(Tip20TransferBlockstmFallback::InvalidFeeCharge);
    }

    let refund = max_amount - actual_fee;
    if !refund.is_zero() {
        let fee_payer_key = balance_key(token, fee_payer);
        let fee_manager_key = balance_key(token, TIP_FEE_MANAGER_ADDRESS);
        let fee_payer_balance = decode_balance_state(
            *execution
                .writes
                .get(&fee_payer_key)
                .ok_or(Tip20TransferBlockstmFallback::StmValidation)?,
        )?;
        let fee_manager_balance = decode_balance_state(
            *execution
                .writes
                .get(&fee_manager_key)
                .ok_or(Tip20TransferBlockstmFallback::StmValidation)?,
        )?;

        let refunded_fee_payer = fee_payer_balance
            .amount
            .checked_add(refund)
            .ok_or(Tip20TransferBlockstmFallback::BalanceOverflow)?;
        let refunded_fee_manager = fee_manager_balance
            .amount
            .checked_sub(refund)
            .ok_or(Tip20TransferBlockstmFallback::InsufficientBalance)?;
        execution.writes.insert(
            fee_payer_key,
            encode_balance(
                refunded_fee_payer,
                fee_payer_balance.inactive_write_flag(),
                is_t6,
            ),
        );
        execution.writes.insert(
            fee_manager_key,
            encode_balance(
                refunded_fee_manager,
                fee_manager_balance.inactive_write_flag(),
                is_t6,
            ),
        );
    }

    let collected_key = collected_fees_key(beneficiary, token);
    let original_collected = execution
        .reads
        .get(&collected_key)
        .map(|read| read.value)
        .unwrap_or_default();
    let new_collected = original_collected
        .checked_add(actual_fee)
        .ok_or(Tip20TransferBlockstmFallback::BalanceOverflow)?;
    execution.writes.insert(collected_key, new_collected);

    Ok(())
}

fn execution_state(
    execution: &Tip20BlockstmTxExecution,
    base_state: &Tip20BlockstmBaseState,
) -> EvmState {
    let mut state = EvmState::default();

    for (key, value) in &execution.writes {
        if is_protocol_nonce_key(*key) {
            let account = state.entry(key.address).or_insert_with(|| {
                let mut account = Account::from(
                    base_state
                        .accounts
                        .get(&key.address)
                        .cloned()
                        .unwrap_or_default(),
                );
                account.mark_touch();
                account
            });
            account.info.nonce = value.to::<u64>();
            account.mark_touch();
            continue;
        }

        let account = state.entry(key.address).or_insert_with(|| {
            let mut account = Account::from(
                base_state
                    .accounts
                    .get(&key.address)
                    .cloned()
                    .unwrap_or_default(),
            );
            account.mark_touch();
            account
        });
        let original = execution
            .reads
            .get(key)
            .map(|read| read.value)
            .unwrap_or_default();
        account.storage.insert(
            key.slot,
            EvmStorageSlot::new_changed(original, *value, TransactionId::ZERO),
        );
    }

    state
}

fn validate_tip20_execution_reads(
    tx_index: usize,
    execution: &Tip20BlockstmTxExecution,
    base_storage: &HashMap<StorageKey, U256>,
    versions: &HashMap<StorageKey, Vec<(usize, U256)>>,
) -> bool {
    execution.reads.iter().all(|(key, observed)| {
        read_versioned(base_storage, versions, tx_index, *key).version == observed.version
    })
}

fn transfer_balance(
    token: Address,
    from: Address,
    to: Address,
    amount: U256,
    is_t6: bool,
    execution: &mut Tip20BlockstmTxExecution,
    base_storage: &HashMap<StorageKey, U256>,
    versions: &HashMap<StorageKey, Vec<(usize, U256)>>,
    tx_index: usize,
) -> Result<(), Tip20TransferBlockstmFallback> {
    if amount.is_zero() {
        return Ok(());
    }

    let from_key = balance_key(token, from);
    let to_key = balance_key(token, to);
    let from_balance =
        read_balance_for_write(execution, base_storage, versions, tx_index, from_key)?;
    let to_balance = read_balance_for_write(execution, base_storage, versions, tx_index, to_key)?;

    if from_balance.amount < amount {
        return Err(Tip20TransferBlockstmFallback::InsufficientBalance);
    }
    let new_from = from_balance.amount - amount;
    let new_to = to_balance
        .amount
        .checked_add(amount)
        .ok_or(Tip20TransferBlockstmFallback::BalanceOverflow)?;
    if new_to > U128_MAX {
        return Err(Tip20TransferBlockstmFallback::BalanceOverflow);
    }

    execution.writes.insert(
        from_key,
        encode_balance(new_from, from_balance.inactive_write_flag(), is_t6),
    );
    execution.writes.insert(
        to_key,
        encode_balance(new_to, to_balance.inactive_write_flag(), is_t6),
    );

    Ok(())
}

fn read_balance_for_write(
    execution: &mut Tip20BlockstmTxExecution,
    base_storage: &HashMap<StorageKey, U256>,
    versions: &HashMap<StorageKey, Vec<(usize, U256)>>,
    tx_index: usize,
    key: StorageKey,
) -> Result<Tip20BalanceState, Tip20TransferBlockstmFallback> {
    let raw = read_for_write(execution, base_storage, versions, tx_index, key);
    decode_balance_state(raw)
}

fn read_for_write(
    execution: &mut Tip20BlockstmTxExecution,
    base_storage: &HashMap<StorageKey, U256>,
    versions: &HashMap<StorageKey, Vec<(usize, U256)>>,
    tx_index: usize,
    key: StorageKey,
) -> U256 {
    if let Some(value) = execution.writes.get(&key) {
        return *value;
    }

    let value = read_versioned(base_storage, versions, tx_index, key);
    execution.reads.entry(key).or_insert(value);
    value.value
}

fn read_versioned(
    base_storage: &HashMap<StorageKey, U256>,
    versions: &HashMap<StorageKey, Vec<(usize, U256)>>,
    tx_index: usize,
    key: StorageKey,
) -> VersionedValue {
    versions
        .get(&key)
        .and_then(|values| {
            values
                .iter()
                .rev()
                .find(|(version, _)| *version < tx_index)
                .copied()
        })
        .map(|(version, value)| VersionedValue {
            version: Some(version),
            value,
        })
        .unwrap_or_else(|| VersionedValue {
            version: None,
            value: *base_storage.get(&key).unwrap_or(&U256::ZERO),
        })
}

fn synthetic_tip20_result_gas(
    tx: &TempoTxEnv,
    plan: &Tip20TransferBlockstmPlan,
    execution: &Tip20BlockstmTxExecution,
    base_state: &Tip20BlockstmBaseState,
    cfg: &CfgEnv<TempoHardfork>,
) -> Result<ResultGas, Tip20TransferBlockstmFallback> {
    let initial = synthetic_initial_gas(tx, cfg)?;
    let mut meter = SyntheticTip20GasMeter::default();
    let mut original_values = HashMap::<StorageKey, U256>::new();
    let mut present_values = HashMap::<StorageKey, U256>::new();

    for action in plan.actions.iter().filter_map(|action| match action {
        Tip20BlockstmAction::Transfer(action) => Some(action),
        _ => None,
    }) {
        meter.add_regular(input_cost(action.calldata_len()))?;
        for key in Tip20BlockstmAction::Transfer(action.clone()).read_set() {
            meter.sload(key, cfg.gas_params())?;
            original_values
                .entry(key)
                .or_insert_with(|| tx_storage_value(execution, base_state, key));
            present_values
                .entry(key)
                .or_insert_with(|| tx_storage_value(execution, base_state, key));
        }

        if !action.amount.is_zero() {
            let from_key = balance_key(action.token, action.from);
            let to_key = balance_key(action.token, action.to);
            let from_balance = decode_balance_state(
                *present_values
                    .entry(from_key)
                    .or_insert_with(|| tx_storage_value(execution, base_state, from_key)),
            )?;
            let to_balance = decode_balance_state(
                *present_values
                    .entry(to_key)
                    .or_insert_with(|| tx_storage_value(execution, base_state, to_key)),
            )?;
            let new_from = from_balance
                .amount
                .checked_sub(action.amount)
                .ok_or(Tip20TransferBlockstmFallback::InsufficientBalance)?;
            let new_to = to_balance
                .amount
                .checked_add(action.amount)
                .ok_or(Tip20TransferBlockstmFallback::BalanceOverflow)?;
            let new_from_raw = encode_balance(
                new_from,
                from_balance.inactive_write_flag(),
                cfg.spec.is_t6(),
            );
            let new_to_raw =
                encode_balance(new_to, to_balance.inactive_write_flag(), cfg.spec.is_t6());

            meter.sstore(
                from_key,
                *original_values
                    .entry(from_key)
                    .or_insert_with(|| tx_storage_value(execution, base_state, from_key)),
                present_values[&from_key],
                new_from_raw,
                cfg.gas_params(),
            )?;
            present_values.insert(from_key, new_from_raw);
            meter.sstore(
                to_key,
                *original_values
                    .entry(to_key)
                    .or_insert_with(|| tx_storage_value(execution, base_state, to_key)),
                present_values[&to_key],
                new_to_raw,
                cfg.gas_params(),
            )?;
            present_values.insert(to_key, new_to_raw);
        }

        meter.log(
            &tip20_transfer_log(action.token, action.from, action.to, action.amount),
            cfg.gas_params(),
        )?;
        if let Some(memo) = action.memo {
            meter.log(
                &tip20_transfer_with_memo_log(
                    action.token,
                    action.from,
                    action.to,
                    action.amount,
                    memo,
                ),
                cfg.gas_params(),
            )?;
        }
    }

    let regular_gas = initial
        .initial_regular_gas()
        .checked_add(meter.regular_gas)
        .ok_or(Tip20TransferBlockstmFallback::GasOverflow)?;
    let state_gas = initial
        .initial_state_gas_final()
        .checked_add(meter.state_gas)
        .ok_or(Tip20TransferBlockstmFallback::GasOverflow)?;
    let total_spent = regular_gas
        .checked_add(state_gas)
        .ok_or(Tip20TransferBlockstmFallback::GasOverflow)?;
    if tx.gas_limit() < total_spent {
        return Err(Tip20TransferBlockstmFallback::GasLimit);
    }

    Ok(ResultGas::new_with_state_gas(
        total_spent,
        meter.refund.max(0) as u64,
        initial.floor_gas(),
        state_gas,
    ))
}

fn synthetic_initial_gas(
    tx: &TempoTxEnv,
    cfg: &CfgEnv<TempoHardfork>,
) -> Result<InitialAndFloorGas, Tip20TransferBlockstmFallback> {
    let gas_params = cfg.gas_params();
    let spec = cfg.spec();
    let gas_limit = tx.gas_limit();

    let mut gas = if let Some(aa_env) = tx.tempo_tx_env.as_ref() {
        let mut batch_gas =
            calculate_aa_batch_intrinsic_gas(aa_env, gas_params, tx.access_list(), *spec)
                .map_err(|_| Tip20TransferBlockstmFallback::GasLimit)?;

        let mut nonce_2d_gas = 0;
        if spec.is_t1() {
            if aa_env.nonce_key == TEMPO_EXPIRING_NONCE_KEY {
                return Err(Tip20TransferBlockstmFallback::ExpiringNonce);
            } else if tx.nonce() == 0 {
                batch_gas.initial_regular_gas += gas_params.get(GasId::new_account_cost());
                batch_gas.initial_state_gas += gas_params.new_account_state_gas();
            } else if !aa_env.nonce_key.is_zero() {
                batch_gas.initial_regular_gas += spec.gas_existing_nonce_key();
            }
        } else if !aa_env.nonce_key.is_zero() {
            nonce_2d_gas = if tx.nonce() == 0 {
                spec.gas_new_nonce_key()
            } else {
                spec.gas_existing_nonce_key()
            };
        }

        if spec.is_t0() {
            batch_gas.initial_regular_gas += nonce_2d_gas;
        }
        if gas_limit < batch_gas.initial_total_gas() {
            return Err(Tip20TransferBlockstmFallback::GasLimit);
        }
        if !spec.is_t0() {
            batch_gas.initial_regular_gas += nonce_2d_gas;
        }

        batch_gas
    } else {
        let mut initial = gas_params.initial_tx_gas(tx.input(), false, 0, 0, 0);
        if spec.is_t1() && tx.nonce() == 0 {
            initial.initial_regular_gas += gas_params.get(GasId::new_account_cost());
            initial.initial_state_gas += gas_params.new_account_state_gas();
        }
        if gas_limit < initial.initial_total_gas() {
            return Err(Tip20TransferBlockstmFallback::GasLimit);
        }
        initial
    };

    if cfg.is_eip7623_disabled() {
        gas.floor_gas = 0;
    }
    if gas_limit < gas.floor_gas() {
        return Err(Tip20TransferBlockstmFallback::GasLimit);
    }
    if cfg.is_amsterdam_eip8037_enabled()
        && gas.initial_regular_gas().max(gas.floor_gas()) > cfg.tx_gas_limit_cap()
    {
        return Err(Tip20TransferBlockstmFallback::GasLimit);
    }

    Ok(gas)
}

#[derive(Debug, Default)]
struct SyntheticTip20GasMeter {
    regular_gas: u64,
    state_gas: u64,
    refund: i64,
    warm_storage: HashSet<StorageKey>,
}

impl SyntheticTip20GasMeter {
    fn add_regular(&mut self, amount: u64) -> Result<(), Tip20TransferBlockstmFallback> {
        self.regular_gas = self
            .regular_gas
            .checked_add(amount)
            .ok_or(Tip20TransferBlockstmFallback::GasOverflow)?;
        Ok(())
    }

    fn add_state(&mut self, amount: u64) -> Result<(), Tip20TransferBlockstmFallback> {
        self.state_gas = self
            .state_gas
            .checked_add(amount)
            .ok_or(Tip20TransferBlockstmFallback::GasOverflow)?;
        Ok(())
    }

    fn sload(
        &mut self,
        key: StorageKey,
        gas_params: &GasParams,
    ) -> Result<(), Tip20TransferBlockstmFallback> {
        self.add_regular(gas_params.warm_storage_read_cost())?;
        if self.warm_storage.insert(key) {
            self.add_regular(gas_params.cold_storage_additional_cost())?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn sstore(
        &mut self,
        key: StorageKey,
        original_value: U256,
        present_value: U256,
        new_value: U256,
        gas_params: &GasParams,
    ) -> Result<(), Tip20TransferBlockstmFallback> {
        let is_cold = self.warm_storage.insert(key);
        let values = SStoreResult {
            original_value,
            present_value,
            new_value,
        };

        self.add_regular(gas_params.sstore_static_gas())?;
        self.add_regular(gas_params.sstore_dynamic_gas(true, &values, is_cold))?;
        self.add_state(gas_params.sstore_state_gas(&values))?;
        self.refund = self
            .refund
            .saturating_add(gas_params.sstore_refund(true, &values));

        Ok(())
    }

    fn log(
        &mut self,
        log: &Log,
        gas_params: &GasParams,
    ) -> Result<(), Tip20TransferBlockstmFallback> {
        self.add_regular(
            gas::LOG + gas_params.log_cost(log.topics().len() as u8, log.data.data.len() as u64),
        )
    }
}

fn tx_storage_value(
    execution: &Tip20BlockstmTxExecution,
    base_state: &Tip20BlockstmBaseState,
    key: StorageKey,
) -> U256 {
    execution
        .reads
        .get(&key)
        .map(|read| read.value)
        .or_else(|| base_state.storage.get(&key).copied())
        .unwrap_or_default()
}

fn synthetic_actual_fee(tx: &TempoTxEnv, tx_gas_used: u64, basefee: u128, is_t6: bool) -> U256 {
    let mut effective_gas_price = tx.effective_gas_price(basefee);
    if is_t6 && tx.is_discounted_payment() && tx_gas_used <= SSTORE_SET_COST {
        effective_gas_price = tempo_t6_discounted_payment_effective_gas_price(effective_gas_price);
    }
    calc_gas_balance_spending(tx_gas_used, effective_gas_price)
}

fn synthetic_tip20_logs(plan: &Tip20TransferBlockstmPlan, actual_fee: U256) -> Vec<Log> {
    let mut logs = Vec::new();
    if let Some(log) = plan.nonce.log() {
        logs.push(log);
    }

    for action in &plan.actions {
        let Tip20BlockstmAction::Transfer(action) = action else {
            continue;
        };
        logs.push(tip20_transfer_log(
            action.token,
            action.from,
            action.to,
            action.amount,
        ));
        if let Some(memo) = action.memo {
            logs.push(tip20_transfer_with_memo_log(
                action.token,
                action.from,
                action.to,
                action.amount,
                memo,
            ));
        }
    }

    if let Some((token, fee_payer, max_amount)) = plan.actions.iter().find_map(|action| {
        if let Tip20BlockstmAction::FeeSettle {
            token,
            fee_payer,
            max_amount,
            ..
        } = action
        {
            Some((*token, *fee_payer, *max_amount))
        } else {
            None
        }
    }) && (!actual_fee.is_zero() || max_amount > actual_fee)
    {
        logs.push(tip20_transfer_log(
            token,
            fee_payer,
            TIP_FEE_MANAGER_ADDRESS,
            actual_fee,
        ));
    }

    logs
}

fn tip20_transfer_log(token: Address, from: Address, to: Address, amount: U256) -> Log {
    Log {
        address: token,
        data: TIP20Event::transfer(from, to, amount).into_log_data(),
    }
}

fn tip20_transfer_with_memo_log(
    token: Address,
    from: Address,
    to: Address,
    amount: U256,
    memo: B256,
) -> Log {
    Log {
        address: token,
        data: TIP20Event::transfer_with_memo(from, to, amount, memo).into_log_data(),
    }
}

fn decode_tip20_transfer_actions(
    tx: &Tip20TransferBlockstmTx<'_>,
    validator_token: Address,
) -> Result<Vec<Tip20TransferAction>, Tip20TransferBlockstmFallback> {
    if tx.fee_token != validator_token {
        return Err(Tip20TransferBlockstmFallback::FeeTokenMismatch);
    }
    if tx.recovered.tx().is_expiring_nonce() {
        return Err(Tip20TransferBlockstmFallback::ExpiringNonce);
    }
    if tx.recovered.tx().subblock_proposer().is_some() {
        return Err(Tip20TransferBlockstmFallback::SubblockTransaction);
    }
    if !tx.tx_env.value().is_zero() {
        return Err(Tip20TransferBlockstmFallback::ValueTransfer);
    }
    if tx
        .tx_env
        .access_list()
        .is_some_and(|mut access_list| access_list.next().is_some())
    {
        return Err(Tip20TransferBlockstmFallback::AccessList);
    }
    if tx.tx_env.authorization_list_len() != 0 {
        return Err(Tip20TransferBlockstmFallback::Eip7702Authorization);
    }

    if let Some(aa_env) = tx.tx_env.tempo_tx_env.as_ref() {
        if !aa_env.tempo_authorization_list.is_empty() {
            return Err(Tip20TransferBlockstmFallback::TempoAuthorization);
        }
        if aa_env.key_authorization.is_some() {
            return Err(Tip20TransferBlockstmFallback::KeyAuthorization);
        }
    }
    if tx
        .recovered
        .tx()
        .as_aa()
        .is_some_and(|aa| aa.signature().as_keychain().is_some())
    {
        return Err(Tip20TransferBlockstmFallback::KeychainSignature);
    }

    let mut actions = Vec::new();
    for (kind, input) in tx.tx_env.calls() {
        actions.push(decode_tip20_transfer_call(
            tx.tx_env.caller(),
            *kind,
            input,
        )?);
    }

    if actions.is_empty() {
        return Err(Tip20TransferBlockstmFallback::EmptyCalls);
    }

    Ok(actions)
}

fn decode_nonce_action(
    tx: &TempoTxEnv,
) -> Result<Tip20BlockstmNonceAction, Tip20TransferBlockstmFallback> {
    let caller = tx.caller();
    let nonce = tx.nonce();

    let Some(aa) = tx.tempo_tx_env.as_ref() else {
        return Ok(Tip20BlockstmNonceAction::Protocol { caller, nonce });
    };

    if aa.nonce_key == TEMPO_EXPIRING_NONCE_KEY {
        return Err(Tip20TransferBlockstmFallback::ExpiringNonce);
    }

    if aa.nonce_key.is_zero() {
        Ok(Tip20BlockstmNonceAction::Protocol { caller, nonce })
    } else {
        Ok(Tip20BlockstmNonceAction::TwoDimensional {
            caller,
            nonce_key: aa.nonce_key,
            nonce,
        })
    }
}

fn decode_tip20_transfer_call(
    from: Address,
    kind: TxKind,
    input: &[u8],
) -> Result<Tip20TransferAction, Tip20TransferBlockstmFallback> {
    let Some(token) = kind.to().copied() else {
        return Err(Tip20TransferBlockstmFallback::ContractCreation);
    };
    if !token.is_tip20() {
        return Err(Tip20TransferBlockstmFallback::NonTip20Target);
    }

    let call = ITIP20::ITIP20Calls::abi_decode(input)
        .map_err(|_| Tip20TransferBlockstmFallback::InvalidCalldata)?;
    match call {
        ITIP20::ITIP20Calls::transfer(call) => Ok(Tip20TransferAction {
            token,
            from,
            to: call.to,
            amount: call.amount,
            memo: None,
            calldata_len: input.len(),
        }),
        ITIP20::ITIP20Calls::transferWithMemo(call) => Ok(Tip20TransferAction {
            token,
            from,
            to: call.to,
            amount: call.amount,
            memo: Some(call.memo),
            calldata_len: input.len(),
        }),
        ITIP20::ITIP20Calls::transferFrom(_) | ITIP20::ITIP20Calls::transferFromWithMemo(_) => {
            Err(Tip20TransferBlockstmFallback::TransferFrom)
        }
        _ => Err(Tip20TransferBlockstmFallback::UnsupportedSelector),
    }
}

#[cfg(test)]
fn count_write_conflicts(plans: &[Tip20TransferBlockstmPlan]) -> usize {
    let mut seen = HashSet::new();
    let mut conflicts = 0;
    for plan in plans {
        for key in plan.write_set() {
            if !seen.insert(key) {
                conflicts += 1;
            }
        }
    }
    conflicts
}

const PROTOCOL_NONCE_SLOT: U256 = U256::MAX;
const NONCE_MANAGER_NONCES_SLOT: U256 = U256::ZERO;

fn protocol_nonce_key(caller: Address) -> StorageKey {
    StorageKey {
        address: caller,
        slot: PROTOCOL_NONCE_SLOT,
    }
}

fn is_protocol_nonce_key(key: StorageKey) -> bool {
    key.slot == PROTOCOL_NONCE_SLOT
}

fn two_dimensional_nonce_key(caller: Address, nonce_key: U256) -> StorageKey {
    StorageKey {
        address: NONCE_PRECOMPILE_ADDRESS,
        slot: nonce_key.mapping_slot(caller.mapping_slot(NONCE_MANAGER_NONCES_SLOT)),
    }
}

fn balance_key(token: Address, account: Address) -> StorageKey {
    StorageKey {
        address: token,
        slot: balance_slot(account),
    }
}

fn balance_slot(account: Address) -> U256 {
    account.mapping_slot(tip20_slots::BALANCES)
}

fn collected_fees_key(beneficiary: Address, token: Address) -> StorageKey {
    StorageKey {
        address: TIP_FEE_MANAGER_ADDRESS,
        slot: TipFeeManager::new().collected_fees[beneficiary][token].slot(),
    }
}

fn receive_policy_key(account: Address) -> StorageKey {
    StorageKey {
        address: TIP403_REGISTRY_ADDRESS,
        slot: account.mapping_slot(tip403_registry_slots::RECEIVE_POLICIES),
    }
}

fn token_state_read_set(token: Address) -> [StorageKey; 4] {
    [
        StorageKey {
            address: token,
            slot: tip20_slots::PAUSED,
        },
        StorageKey {
            address: token,
            slot: tip20_slots::TRANSFER_POLICY_ID,
        },
        StorageKey {
            address: token,
            slot: tip20_slots::GLOBAL_REWARD_PER_TOKEN,
        },
        StorageKey {
            address: token,
            slot: tip20_slots::OPTED_IN_SUPPLY,
        },
    ]
}

fn reward_inactive_read_set(token: Address, account: Address) -> [StorageKey; 4] {
    let reward_info_base = account.mapping_slot(tip20_slots::USER_REWARD_INFO);
    [
        balance_key(token, account),
        StorageKey {
            address: token,
            slot: reward_info_base,
        },
        StorageKey {
            address: token,
            slot: reward_info_base + U256::ONE,
        },
        StorageKey {
            address: token,
            slot: reward_info_base + U256::from(2),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TestExecutorBuilder, test_chainspec};
    use alloy_consensus::{Signed, TxLegacy};
    use alloy_eips::eip2930::{AccessList, AccessListItem};
    use alloy_evm::FromRecoveredTx;
    use alloy_primitives::{Signature, address};
    use alloy_sol_types::SolCall;
    use reth_revm::{
        State,
        state::{AccountInfo, Bytecode},
    };
    use revm::database::states::plain_account::PlainStorage;
    use tempo_primitives::{
        MasterId, TempoSignature, TempoTransaction, UserTag,
        subblock::TEMPO_SUBBLOCK_NONCE_KEY_PREFIX,
        transaction::{Call, TEMPO_EXPIRING_NONCE_KEY},
    };

    const TOKEN: Address = address!("20c0000000000000000000000000000000000001");
    const SENDER: Address = address!("1000000000000000000000000000000000000001");

    fn blockstm_tx(input: Vec<u8>) -> (Recovered<TempoTxEnvelope>, TempoTxEnv) {
        blockstm_tx_to(TOKEN, input)
    }

    fn blockstm_tx_to(to: Address, input: Vec<u8>) -> (Recovered<TempoTxEnvelope>, TempoTxEnv) {
        blockstm_tx_with_fee_to(to, input, 0, 0)
    }

    fn blockstm_tx_with_fee(
        input: Vec<u8>,
        gas_limit: u64,
        gas_price: u128,
    ) -> (Recovered<TempoTxEnvelope>, TempoTxEnv) {
        blockstm_tx_with_fee_to(TOKEN, input, gas_limit, gas_price)
    }

    fn blockstm_tx_with_fee_to(
        to: Address,
        input: Vec<u8>,
        gas_limit: u64,
        gas_price: u128,
    ) -> (Recovered<TempoTxEnvelope>, TempoTxEnv) {
        let tx = TempoTxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy {
                gas_limit,
                gas_price,
                to: TxKind::Call(to),
                input: input.into(),
                ..Default::default()
            },
            Signature::test_signature(),
        ));
        let recovered = Recovered::new_unchecked(tx, SENDER);
        let tx_env = TempoTxEnv::from_recovered_tx(recovered.inner(), SENDER);
        (recovered, tx_env)
    }

    fn aa_blockstm_tx(
        calls: Vec<Call>,
        nonce_key: U256,
    ) -> (Recovered<TempoTxEnvelope>, TempoTxEnv) {
        aa_blockstm_tx_with_gas(calls, nonce_key, 100_000)
    }

    fn aa_blockstm_tx_with_gas(
        calls: Vec<Call>,
        nonce_key: U256,
        gas_limit: u64,
    ) -> (Recovered<TempoTxEnvelope>, TempoTxEnv) {
        let tx = TempoTransaction {
            chain_id: 1,
            calls,
            gas_limit,
            nonce_key,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            ..Default::default()
        };
        let signed =
            TempoTxEnvelope::AA(tx.into_signed(TempoSignature::from(Signature::test_signature())));
        let recovered = Recovered::new_unchecked(signed, SENDER);
        let tx_env = TempoTxEnv::from_recovered_tx(recovered.inner(), SENDER);
        (recovered, tx_env)
    }

    fn transfer_call(to: Address, amount: U256) -> Call {
        Call {
            to: TxKind::Call(TOKEN),
            value: U256::ZERO,
            input: ITIP20::transferCall { to, amount }.abi_encode().into(),
        }
    }

    fn transfer_with_memo_call(to: Address, amount: U256, memo: B256) -> Call {
        Call {
            to: TxKind::Call(TOKEN),
            value: U256::ZERO,
            input: ITIP20::transferWithMemoCall { to, amount, memo }
                .abi_encode()
                .into(),
        }
    }

    fn policy_word(policy_id: u64) -> U256 {
        U256::from(policy_id) << (tip20_slots::TRANSFER_POLICY_ID_OFFSET * 8)
    }

    fn precompile_marker_info() -> AccountInfo {
        AccountInfo::default().with_code(Bytecode::new_legacy([0xef].into()))
    }

    fn assert_fallback(
        err: Tip20TransferBlockstmBatchError,
        expected: Tip20TransferBlockstmFallback,
    ) {
        match err {
            Tip20TransferBlockstmBatchError::Fallback(actual) => assert_eq!(actual, expected),
            other => panic!("expected fallback {expected:?}, got {other:?}"),
        }
    }

    #[test]
    fn direct_transfer_is_eligible() {
        let (recovered, tx_env) = blockstm_tx(
            ITIP20::transferCall {
                to: Address::random(),
                amount: U256::from(1),
            }
            .abi_encode(),
        );

        let tx = Tip20TransferBlockstmTx {
            tx_env,
            recovered: &recovered,
            fee_token: TOKEN,
        };
        let actions = decode_tip20_transfer_actions(&tx, TOKEN).unwrap();
        assert_eq!(actions.len(), 1);
    }

    #[test]
    fn aa_batch_with_only_direct_transfers_is_eligible() {
        let recipient_a = address!("10000000000000000000000000000000000000a1");
        let recipient_b = address!("10000000000000000000000000000000000000b1");
        let (recovered, tx_env) = aa_blockstm_tx(
            vec![
                transfer_call(recipient_a, U256::from(1)),
                transfer_with_memo_call(recipient_b, U256::from(2), B256::repeat_byte(0x42)),
            ],
            U256::from(7),
        );

        let tx = Tip20TransferBlockstmTx {
            tx_env,
            recovered: &recovered,
            fee_token: TOKEN,
        };
        let actions = decode_tip20_transfer_actions(&tx, TOKEN).unwrap();
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0].to, recipient_a);
        assert_eq!(actions[1].to, recipient_b);
        assert_eq!(actions[1].memo, Some(B256::repeat_byte(0x42)));
    }

    #[test]
    fn transfer_from_falls_back() {
        let (recovered, tx_env) = blockstm_tx(
            ITIP20::transferFromCall {
                from: Address::random(),
                to: Address::random(),
                amount: U256::from(1),
            }
            .abi_encode(),
        );

        let tx = Tip20TransferBlockstmTx {
            tx_env,
            recovered: &recovered,
            fee_token: TOKEN,
        };
        assert_eq!(
            decode_tip20_transfer_actions(&tx, TOKEN),
            Err(Tip20TransferBlockstmFallback::TransferFrom)
        );
    }

    #[test]
    fn non_tip20_target_falls_back() {
        let non_tip20 = address!("1000000000000000000000000000000000000042");
        let (recovered, tx_env) = blockstm_tx_to(
            non_tip20,
            ITIP20::transferCall {
                to: Address::random(),
                amount: U256::from(1),
            }
            .abi_encode(),
        );

        let tx = Tip20TransferBlockstmTx {
            tx_env,
            recovered: &recovered,
            fee_token: TOKEN,
        };
        assert_eq!(
            decode_tip20_transfer_actions(&tx, TOKEN),
            Err(Tip20TransferBlockstmFallback::NonTip20Target)
        );
    }

    #[test]
    fn access_list_falls_back() {
        let (recovered, mut tx_env) = blockstm_tx(
            ITIP20::transferCall {
                to: Address::random(),
                amount: U256::from(1),
            }
            .abi_encode(),
        );
        tx_env.inner.access_list = AccessList(vec![AccessListItem {
            address: SENDER,
            storage_keys: vec![B256::ZERO],
        }]);

        let tx = Tip20TransferBlockstmTx {
            tx_env,
            recovered: &recovered,
            fee_token: TOKEN,
        };
        assert_eq!(
            decode_tip20_transfer_actions(&tx, TOKEN),
            Err(Tip20TransferBlockstmFallback::AccessList)
        );
    }

    #[test]
    fn expiring_nonce_falls_back() {
        let (recovered, tx_env) = aa_blockstm_tx(
            vec![transfer_call(Address::random(), U256::from(1))],
            TEMPO_EXPIRING_NONCE_KEY,
        );

        let tx = Tip20TransferBlockstmTx {
            tx_env,
            recovered: &recovered,
            fee_token: TOKEN,
        };
        assert_eq!(
            decode_tip20_transfer_actions(&tx, TOKEN),
            Err(Tip20TransferBlockstmFallback::ExpiringNonce)
        );
    }

    #[test]
    fn subblock_transaction_falls_back() {
        let mut nonce_bytes = [0u8; 32];
        nonce_bytes[0] = TEMPO_SUBBLOCK_NONCE_KEY_PREFIX;
        let (recovered, tx_env) = aa_blockstm_tx(
            vec![transfer_call(Address::random(), U256::from(1))],
            U256::from_be_bytes(nonce_bytes),
        );

        let tx = Tip20TransferBlockstmTx {
            tx_env,
            recovered: &recovered,
            fee_token: TOKEN,
        };
        assert_eq!(
            decode_tip20_transfer_actions(&tx, TOKEN),
            Err(Tip20TransferBlockstmFallback::SubblockTransaction)
        );
    }

    #[test]
    fn fee_token_mismatch_falls_back() {
        let (recovered, tx_env) = blockstm_tx(
            ITIP20::transferCall {
                to: Address::random(),
                amount: U256::from(1),
            }
            .abi_encode(),
        );

        let tx = Tip20TransferBlockstmTx {
            tx_env,
            recovered: &recovered,
            fee_token: TOKEN,
        };
        assert_eq!(
            decode_tip20_transfer_actions(&tx, Address::random()),
            Err(Tip20TransferBlockstmFallback::FeeTokenMismatch)
        );
    }

    #[test]
    fn unsupported_direct_recipient_falls_back() {
        assert!(matches!(
            validate_direct_recipient(Address::ZERO),
            Err(Tip20TransferBlockstmBatchError::Fallback(
                Tip20TransferBlockstmFallback::InvalidRecipient
            ))
        ));
        assert!(matches!(
            validate_direct_recipient(TOKEN),
            Err(Tip20TransferBlockstmBatchError::Fallback(
                Tip20TransferBlockstmFallback::InvalidRecipient
            ))
        ));

        let virtual_recipient = Address::new_virtual(
            MasterId::from([1, 2, 3, 4]),
            UserTag::from([5, 6, 7, 8, 9, 10]),
        );
        assert!(matches!(
            validate_direct_recipient(virtual_recipient),
            Err(Tip20TransferBlockstmBatchError::Fallback(
                Tip20TransferBlockstmFallback::VirtualRecipient
            ))
        ));
    }

    #[test]
    fn transfer_policy_id_extracts_packed_allow_all() {
        let raw = U256::from(ALLOW_ALL_POLICY_ID) << (tip20_slots::TRANSFER_POLICY_ID_OFFSET * 8);
        assert_eq!(transfer_policy_id(raw), U256::from(ALLOW_ALL_POLICY_ID));
    }

    #[test]
    fn transfer_plan_includes_same_token_fee_actions_and_storage_sets() {
        let recipient = address!("10000000000000000000000000000000000000cc");
        let beneficiary = address!("10000000000000000000000000000000000000dd");
        let (recovered, tx_env) = blockstm_tx_with_fee(
            ITIP20::transferCall {
                to: recipient,
                amount: U256::from(7),
            }
            .abi_encode(),
            21_000,
            2_000_000_000_000,
        );

        let tx = Tip20TransferBlockstmTx {
            tx_env,
            recovered: &recovered,
            fee_token: TOKEN,
        };
        let plan = build_tip20_transfer_plan(&tx, TOKEN, beneficiary, 1, 0).unwrap();

        assert_eq!(plan.fee_payer, SENDER);
        assert_eq!(plan.max_fee, U256::from(42_000));
        assert_eq!(plan.actions.len(), 3);
        assert!(matches!(
            &plan.actions[0],
            Tip20BlockstmAction::FeeReserve {
                token: TOKEN,
                fee_payer: SENDER,
                amount
            } if *amount == U256::from(42_000)
        ));
        assert!(matches!(
            &plan.actions[1],
            Tip20BlockstmAction::Transfer(Tip20TransferAction {
                token: TOKEN,
                from: SENDER,
                to,
                amount,
                memo: None,
                ..
            }) if *to == recipient && *amount == U256::from(7)
        ));
        assert!(matches!(
            &plan.actions[2],
            Tip20BlockstmAction::FeeSettle {
                token: TOKEN,
                fee_payer: SENDER,
                beneficiary: actual_beneficiary,
                max_amount
            } if *actual_beneficiary == beneficiary && *max_amount == U256::from(42_000)
        ));

        let read_set = plan.read_set();
        assert!(read_set.contains(&receive_policy_key(recipient)));
        assert!(read_set.contains(&collected_fees_key(beneficiary, TOKEN)));
        assert!(read_set.contains(&StorageKey {
            address: TOKEN,
            slot: tip20_slots::TRANSFER_POLICY_ID,
        }));

        let write_set = plan.write_set();
        assert!(write_set.contains(&balance_key(TOKEN, SENDER)));
        assert!(write_set.contains(&balance_key(TOKEN, recipient)));
        assert!(write_set.contains(&balance_key(TOKEN, TIP_FEE_MANAGER_ADDRESS)));
    }

    #[test]
    fn write_conflicts_are_counted_across_transactions() {
        let recipient = address!("10000000000000000000000000000000000000ce");
        let beneficiary = address!("10000000000000000000000000000000000000df");
        let (recovered, tx_env) = blockstm_tx_with_fee(
            ITIP20::transferCall {
                to: recipient,
                amount: U256::from(1),
            }
            .abi_encode(),
            21_000,
            1_000_000_000_000,
        );
        let tx = Tip20TransferBlockstmTx {
            tx_env,
            recovered: &recovered,
            fee_token: TOKEN,
        };
        let plan = build_tip20_transfer_plan(&tx, TOKEN, beneficiary, 1, 0).unwrap();

        assert_eq!(count_write_conflicts(&[plan.clone()]), 0);
        assert!(count_write_conflicts(&[plan.clone(), plan]) > 0);
    }

    #[test]
    fn speculative_execution_applies_transfers_and_same_token_fee_overlays() {
        let recipient = address!("10000000000000000000000000000000000000c1");
        let beneficiary = address!("10000000000000000000000000000000000000d1");
        let (recovered, tx_env) = blockstm_tx_with_fee(
            ITIP20::transferCall {
                to: recipient,
                amount: U256::from(7),
            }
            .abi_encode(),
            21_000,
            1_000_000_000_000,
        );
        let tx = Tip20TransferBlockstmTx {
            tx_env,
            recovered: &recovered,
            fee_token: TOKEN,
        };
        let plan = build_tip20_transfer_plan(&tx, TOKEN, beneficiary, 1, 0).unwrap();
        let base_storage = HashMap::from([
            (
                balance_key(TOKEN, SENDER),
                encode_balance(U256::from(100_000), REWARD_FLAG_OPTED_OUT, true),
            ),
            (
                balance_key(TOKEN, recipient),
                encode_balance(U256::from(5), REWARD_FLAG_OPTED_OUT, true),
            ),
            (collected_fees_key(beneficiary, TOKEN), U256::from(3)),
        ]);

        let execution =
            execute_tip20_transfer_plans_blockstm(&[plan], &base_storage, true).unwrap();
        assert_eq!(execution.retry_count, 0);
        let writes = &execution.txs[0].writes;
        assert_eq!(
            writes[&balance_key(TOKEN, SENDER)],
            encode_balance(U256::from(78_993), REWARD_FLAG_OPTED_OUT, true)
        );
        assert_eq!(
            writes[&balance_key(TOKEN, recipient)],
            encode_balance(U256::from(12), REWARD_FLAG_OPTED_OUT, true)
        );
        assert_eq!(
            writes[&balance_key(TOKEN, TIP_FEE_MANAGER_ADDRESS)],
            encode_balance(U256::from(21_000), REWARD_FLAG_OPTED_OUT, true)
        );
        assert_eq!(
            writes[&collected_fees_key(beneficiary, TOKEN)],
            U256::from(21_003)
        );
    }

    #[test]
    fn fee_settlement_rewrites_overlay_to_actual_validator_fee() {
        let recipient = address!("10000000000000000000000000000000000000c2");
        let beneficiary = address!("10000000000000000000000000000000000000d3");
        let (recovered, tx_env) = blockstm_tx_with_fee(
            ITIP20::transferCall {
                to: recipient,
                amount: U256::from(7),
            }
            .abi_encode(),
            21_000,
            1_000_000_000_000,
        );
        let tx = Tip20TransferBlockstmTx {
            tx_env,
            recovered: &recovered,
            fee_token: TOKEN,
        };
        let plan = build_tip20_transfer_plan(&tx, TOKEN, beneficiary, 1, 0).unwrap();
        let base_storage = HashMap::from([
            (
                balance_key(TOKEN, SENDER),
                encode_balance(U256::from(100_000), REWARD_FLAG_OPTED_OUT, true),
            ),
            (
                balance_key(TOKEN, recipient),
                encode_balance(U256::from(5), REWARD_FLAG_OPTED_OUT, true),
            ),
            (collected_fees_key(beneficiary, TOKEN), U256::from(3)),
        ]);
        let mut execution =
            execute_tip20_transfer_plans_blockstm(&[plan.clone()], &base_storage, true)
                .unwrap()
                .txs
                .remove(0);

        settle_actual_fee(&plan, &mut execution, U256::from(1_000), true).unwrap();
        assert_eq!(
            execution.writes[&balance_key(TOKEN, SENDER)],
            encode_balance(U256::from(98_993), REWARD_FLAG_OPTED_OUT, true)
        );
        assert_eq!(
            execution.writes[&balance_key(TOKEN, TIP_FEE_MANAGER_ADDRESS)],
            encode_balance(U256::from(1_000), REWARD_FLAG_OPTED_OUT, true)
        );
        assert_eq!(
            execution.writes[&collected_fees_key(beneficiary, TOKEN)],
            U256::from(1_003)
        );
    }

    #[test]
    fn speculative_execution_retries_conflicting_transfers() {
        let recipient_a = address!("10000000000000000000000000000000000000a1");
        let recipient_b = address!("10000000000000000000000000000000000000b1");
        let beneficiary = address!("10000000000000000000000000000000000000d2");

        let make_plan = |to, amount, nonce_key| {
            let (recovered, tx_env) =
                aa_blockstm_tx(vec![transfer_call(to, amount)], U256::from(nonce_key));
            let tx = Tip20TransferBlockstmTx {
                tx_env,
                recovered: &recovered,
                fee_token: TOKEN,
            };
            build_tip20_transfer_plan(&tx, TOKEN, beneficiary, 1, 0).unwrap()
        };
        let plan_a = make_plan(recipient_a, U256::from(10), 1);
        let plan_b = make_plan(recipient_b, U256::from(20), 2);
        let base_storage = HashMap::from([(
            balance_key(TOKEN, SENDER),
            encode_balance(U256::from(100), REWARD_FLAG_OPTED_OUT, true),
        )]);

        let execution =
            execute_tip20_transfer_plans_blockstm(&[plan_a, plan_b], &base_storage, true).unwrap();
        assert_eq!(execution.retry_count, 1);
        assert_eq!(
            execution.txs[1].writes[&balance_key(TOKEN, SENDER)],
            encode_balance(U256::from(68), REWARD_FLAG_OPTED_OUT, true)
        );
        assert_eq!(
            execution.txs[1].writes[&balance_key(TOKEN, recipient_b)],
            encode_balance(U256::from(20), REWARD_FLAG_OPTED_OUT, true)
        );
    }

    #[test]
    fn speculative_execution_retries_protocol_nonce_successor() {
        let recipient_a = address!("10000000000000000000000000000000000000a2");
        let recipient_b = address!("10000000000000000000000000000000000000b2");
        let beneficiary = address!("10000000000000000000000000000000000000d4");

        let make_plan = |to, amount, nonce| {
            let (recovered, mut tx_env) =
                blockstm_tx(ITIP20::transferCall { to, amount }.abi_encode());
            tx_env.inner.nonce = nonce;
            let tx = Tip20TransferBlockstmTx {
                tx_env,
                recovered: &recovered,
                fee_token: TOKEN,
            };
            build_tip20_transfer_plan(&tx, TOKEN, beneficiary, 1, 0).unwrap()
        };
        let plan_a = make_plan(recipient_a, U256::from(10), 0);
        let plan_b = make_plan(recipient_b, U256::from(20), 1);
        let base_storage = HashMap::from([(
            balance_key(TOKEN, SENDER),
            encode_balance(U256::from(100), REWARD_FLAG_OPTED_OUT, true),
        )]);

        let execution =
            execute_tip20_transfer_plans_blockstm(&[plan_a, plan_b], &base_storage, true).unwrap();
        assert_eq!(execution.retry_count, 1);
        assert_eq!(
            execution.txs[1].writes[&protocol_nonce_key(SENDER)],
            U256::from(2)
        );
        assert_eq!(
            execution.txs[1].writes[&balance_key(TOKEN, SENDER)],
            encode_balance(U256::from(70), REWARD_FLAG_OPTED_OUT, true)
        );
    }

    #[test]
    fn non_expiring_2d_nonce_writes_nonce_slot_and_emits_first_log() {
        let recipient = address!("10000000000000000000000000000000000000a3");
        let beneficiary = address!("10000000000000000000000000000000000000d5");
        let nonce_key = U256::from(7);
        let (recovered, tx_env) =
            aa_blockstm_tx(vec![transfer_call(recipient, U256::from(5))], nonce_key);
        let tx = Tip20TransferBlockstmTx {
            tx_env,
            recovered: &recovered,
            fee_token: TOKEN,
        };
        let plan = build_tip20_transfer_plan(&tx, TOKEN, beneficiary, 1, 0).unwrap();
        let base_storage = HashMap::from([(
            balance_key(TOKEN, SENDER),
            encode_balance(U256::from(100), REWARD_FLAG_OPTED_OUT, true),
        )]);

        let execution =
            execute_tip20_transfer_plans_blockstm(&[plan.clone()], &base_storage, true).unwrap();
        let nonce_storage_key = two_dimensional_nonce_key(SENDER, nonce_key);
        assert_eq!(execution.txs[0].writes[&nonce_storage_key], U256::ONE);

        let logs = synthetic_tip20_logs(&plan, U256::ZERO);
        assert_eq!(logs[0].address, NONCE_PRECOMPILE_ADDRESS);
    }

    #[test]
    fn non_expiring_2d_nonce_batch_completes_synthetic_success_path() {
        let beneficiary = address!("10000000000000000000000000000000000000d6");
        let batch_len = 64usize;
        let mut txs = Vec::with_capacity(batch_len);
        let mut plans = Vec::with_capacity(batch_len);

        for i in 0..batch_len {
            let recipient = Address::from_word(B256::with_last_byte(0x80 + i as u8));
            let nonce_key = U256::from(u64::MAX - i as u64);
            let (recovered, tx_env) = aa_blockstm_tx_with_gas(
                vec![transfer_call(recipient, U256::from(1))],
                nonce_key,
                300_000,
            );
            let tx = Tip20TransferBlockstmTx {
                tx_env: tx_env.clone(),
                recovered: &recovered,
                fee_token: TOKEN,
            };
            plans.push(build_tip20_transfer_plan(&tx, TOKEN, beneficiary, 1, 0).unwrap());
            txs.push((recovered, tx_env));
        }

        let base_storage = HashMap::from([(
            balance_key(TOKEN, SENDER),
            encode_balance(U256::from(100_000_000), REWARD_FLAG_OPTED_OUT, true),
        )]);
        let base_state = Tip20BlockstmBaseState {
            storage: base_storage.clone(),
            accounts: HashMap::new(),
        };

        let execution =
            execute_tip20_transfer_plans_blockstm(&plans, &base_storage, true).unwrap();
        assert!(execution.retry_count > 0);
        assert_eq!(execution.txs.len(), batch_len);

        let mut settled = execution.txs;
        let mut cfg = CfgEnv::<TempoHardfork>::default();
        cfg.spec = TempoHardfork::T6;
        for (index, execution) in settled.iter_mut().enumerate() {
            let plan = &plans[index];
            let tx_env = &txs[index].1;
            let gas = synthetic_tip20_result_gas(tx_env, plan, execution, &base_state, &cfg)
                .unwrap();
            let actual_fee = synthetic_actual_fee(tx_env, gas.tx_gas_used(), 1, true);
            settle_actual_fee(plan, execution, actual_fee, true).unwrap();

            let nonce_key = match plan.nonce {
                Tip20BlockstmNonceAction::TwoDimensional { nonce_key, .. } => nonce_key,
                Tip20BlockstmNonceAction::Protocol { .. } => panic!("expected 2D nonce action"),
            };
            assert_eq!(
                execution.writes[&two_dimensional_nonce_key(SENDER, nonce_key)],
                U256::ONE
            );
        }
    }

    #[test]
    fn public_blockstm_batch_commits_non_expiring_2d_nonces() {
        let chainspec = test_chainspec();
        let batch_len = 16usize;
        let mut db = State::builder().with_bundle_update().build();
        db.insert_account_with_storage(
            TOKEN,
            precompile_marker_info(),
            PlainStorage::from_iter([
                (
                    tip20_slots::TRANSFER_POLICY_ID,
                    policy_word(ALLOW_ALL_POLICY_ID),
                ),
                (
                    balance_key(TOKEN, SENDER).slot,
                    encode_balance(U256::from(100_000_000), REWARD_FLAG_OPTED_OUT, true),
                ),
            ]),
        );
        db.insert_account(NONCE_PRECOMPILE_ADDRESS, precompile_marker_info());
        db.insert_account(TIP_FEE_MANAGER_ADDRESS, precompile_marker_info());
        let mut executor = TestExecutorBuilder::default()
            .with_general_gas_limit(1_000_000_000)
            .build(db, &chainspec);

        let mut txs = Vec::with_capacity(batch_len);
        let mut nonce_keys = Vec::with_capacity(batch_len);
        for i in 0..batch_len {
            let recipient = Address::from_word(B256::with_last_byte(0xa0 + i as u8));
            let nonce_key = U256::from(u64::MAX - i as u64);
            let (recovered, tx_env) = aa_blockstm_tx_with_gas(
                vec![transfer_call(recipient, U256::from(1))],
                nonce_key,
                300_000,
            );
            nonce_keys.push(nonce_key);
            txs.push((recovered, tx_env));
        }

        let batch = txs
            .iter()
            .map(|(recovered, tx_env)| Tip20TransferBlockstmTx {
                tx_env: tx_env.clone(),
                recovered,
                fee_token: TOKEN,
            })
            .collect();
        let mut result_count = 0;
        let stats = executor
            .execute_tip20_transfer_blockstm_batch(batch, TOKEN, |_, result| {
                assert!(result.block_gas_used() > 0);
                assert!(result.validator_fee() > U256::ZERO);
                result_count += 1;
            })
            .unwrap();

        assert_eq!(stats.transaction_count, batch_len);
        assert_eq!(stats.action_count, batch_len);
        assert_eq!(result_count, batch_len);
        assert_eq!(executor.receipts().len(), batch_len);
        for nonce_key in nonce_keys {
            let key = two_dimensional_nonce_key(SENDER, nonce_key);
            assert_eq!(executor.read_storage(key.address, key.slot).unwrap(), U256::ONE);
        }
    }

    #[test]
    fn inactive_packed_reward_flags_are_supported() {
        assert_eq!(
            decode_balance_state(encode_balance(U256::from(10), REWARD_FLAG_OPTED_OUT, true))
                .unwrap(),
            Tip20BalanceState {
                amount: U256::from(10),
                reward_flag: REWARD_FLAG_OPTED_OUT,
            }
        );
        assert_eq!(
            decode_balance_state(encode_balance(U256::from(10), REWARD_FLAG_OPTED_IN, true)),
            Err(Tip20TransferBlockstmFallback::RewardActive)
        );
    }

    #[test]
    fn token_state_fallbacks_are_conservative() {
        let chainspec = test_chainspec();

        let cases = [
            (
                PlainStorage::from_iter([
                    (tip20_slots::PAUSED, U256::ONE),
                    (
                        tip20_slots::TRANSFER_POLICY_ID,
                        policy_word(ALLOW_ALL_POLICY_ID),
                    ),
                ]),
                Tip20TransferBlockstmFallback::TokenPaused,
            ),
            (
                PlainStorage::from_iter([(tip20_slots::TRANSFER_POLICY_ID, U256::ZERO)]),
                Tip20TransferBlockstmFallback::TransferPolicy,
            ),
            (
                PlainStorage::from_iter([
                    (
                        tip20_slots::TRANSFER_POLICY_ID,
                        policy_word(ALLOW_ALL_POLICY_ID),
                    ),
                    (tip20_slots::GLOBAL_REWARD_PER_TOKEN, U256::ONE),
                ]),
                Tip20TransferBlockstmFallback::RewardActive,
            ),
        ];

        for (storage, expected) in cases {
            let mut db = State::builder().with_bundle_update().build();
            db.insert_account_with_storage(TOKEN, AccountInfo::default(), storage);
            let mut executor = TestExecutorBuilder::default().build(db, &chainspec);

            let err = executor.validate_token_global_state(TOKEN).unwrap_err();
            assert_fallback(err, expected);
        }
    }

    #[test]
    fn allow_all_reward_inactive_token_state_is_supported() {
        let chainspec = test_chainspec();
        let mut db = State::builder().with_bundle_update().build();
        db.insert_account_with_storage(
            TOKEN,
            AccountInfo::default(),
            PlainStorage::from_iter([(
                tip20_slots::TRANSFER_POLICY_ID,
                policy_word(ALLOW_ALL_POLICY_ID),
            )]),
        );
        let mut executor = TestExecutorBuilder::default().build(db, &chainspec);

        executor.validate_token_global_state(TOKEN).unwrap();
    }

    #[test]
    fn reward_metadata_falls_back() {
        let chainspec = test_chainspec();
        let account = address!("10000000000000000000000000000000000000aa");
        let mut db = State::builder().with_bundle_update().build();
        db.insert_account_with_storage(
            TOKEN,
            AccountInfo::default(),
            PlainStorage::from_iter([(
                account.mapping_slot(tip20_slots::USER_REWARD_INFO),
                U256::ONE,
            )]),
        );
        let mut executor = TestExecutorBuilder::default().build(db, &chainspec);

        let err = executor
            .validate_reward_inactive(TOKEN, account)
            .unwrap_err();
        assert_fallback(err, Tip20TransferBlockstmFallback::RewardActive);
    }

    #[test]
    fn receive_policy_falls_back() {
        let chainspec = test_chainspec();
        let account = address!("10000000000000000000000000000000000000bb");
        let mut db = State::builder().with_bundle_update().build();
        db.insert_account_with_storage(
            TIP403_REGISTRY_ADDRESS,
            AccountInfo::default(),
            PlainStorage::from_iter([(
                account.mapping_slot(tip403_registry_slots::RECEIVE_POLICIES),
                U256::ONE,
            )]),
        );
        let mut executor = TestExecutorBuilder::default().build(db, &chainspec);

        let err = executor.validate_receive_policy(account).unwrap_err();
        assert_fallback(err, Tip20TransferBlockstmFallback::ReceivePolicy);
    }
}
