use crate::{TempoBlockExecutor, TempoTxResult};
use alloy_evm::{
    Evm, RecoveredTx,
    block::{BlockExecutionError, BlockExecutor},
};
use alloy_primitives::{Address, B256, IntoLogData, Log, TxKind, U256};
use alloy_sol_types::SolInterface;
use reth_evm::{Database, block::StateDB};
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
use tempo_contracts::precompiles::{ITIP20, TIP20Event};
use tempo_precompiles::{
    NONCE_PRECOMPILE_ADDRESS, TIP_FEE_MANAGER_ADDRESS, TIP403_REGISTRY_ADDRESS, input_cost,
    nonce::{EXPIRING_NONCE_MAX_EXPIRY_SECS, EXPIRING_NONCE_SET_CAPACITY},
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
    handler::EXPIRING_NONCE_GAS,
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

/// Reason the BlockSTM TIP-20 transfer path cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tip20TransferBlockstmFallback {
    FeeTokenMismatch,
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
    MissingExpiringNonceValidBefore,
    ExpiringNonceReplay,
    ExpiringNonceSetFull,
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
            Self::FeeTokenMismatch => "fee_token_mismatch",
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
            Self::MissingExpiringNonceValidBefore => "missing_expiring_nonce_valid_before",
            Self::ExpiringNonceReplay => "expiring_nonce_replay",
            Self::ExpiringNonceSetFull => "expiring_nonce_set_full",
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

/// Error returned by the BlockSTM TIP-20 transfer execution API.
#[derive(Debug)]
pub enum Tip20TransferBlockstmExecutionError {
    /// The transaction is not eligible for BlockSTM execution; no state was committed.
    Fallback(Tip20TransferBlockstmFallback),
    /// Synthetic validation/execution rejected a transaction.
    Execution {
        /// Index of the failed transaction in the streaming sequence.
        transaction_index: usize,
        /// Execution error returned by synthetic result construction or block validation.
        error: BlockExecutionError,
    },
    /// Preflight failed while reading state; no state was committed.
    Database(BlockExecutionError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct StorageKey {
    address: Address,
    slot: U256,
}

#[derive(Debug, Clone, Default)]
struct Tip20BlockstmBaseState {
    storage: HashMap<StorageKey, U256>,
    accounts: HashMap<Address, AccountInfo>,
}

#[derive(Debug, Clone)]
struct Tip20BlockstmTxExecution {
    storage: HashMap<StorageKey, Tip20BlockstmTxStorage>,
}

#[derive(Debug, Clone, Copy)]
struct Tip20BlockstmTxStorage {
    original: U256,
    written: Option<U256>,
}

impl Tip20BlockstmTxExecution {
    fn written_storage(&self) -> impl Iterator<Item = (StorageKey, U256, U256)> + '_ {
        self.storage
            .iter()
            .filter_map(|(key, value)| value.written.map(|written| (*key, value.original, written)))
    }

    #[cfg(test)]
    fn written_value(&self, key: StorageKey) -> Option<U256> {
        self.storage.get(&key).and_then(|value| value.written)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tip20TransferBlockstmPlan {
    nonce: Tip20ExpiringNonceAction,
    fee_reserve: Tip20FeeReserveAction,
    transfer: Tip20TransferAction,
    fee_settle: Tip20FeeSettleAction,
}

impl Tip20TransferBlockstmPlan {
    fn new(
        nonce: Tip20ExpiringNonceAction,
        fee_reserve: Tip20FeeReserveAction,
        transfer: Tip20TransferAction,
        fee_settle: Tip20FeeSettleAction,
    ) -> Self {
        Self {
            nonce,
            fee_reserve,
            transfer,
            fee_settle,
        }
    }

    fn read_set(&self) -> impl Iterator<Item = StorageKey> + '_ {
        self.nonce
            .read_set()
            .chain(self.fee_reserve.read_set())
            .chain(self.transfer.read_set())
            .chain(self.fee_settle.read_set())
    }

    fn write_set(&self) -> impl Iterator<Item = StorageKey> + '_ {
        self.nonce
            .write_set()
            .chain(self.fee_reserve.write_set())
            .chain(self.transfer.write_set())
            .chain(self.fee_settle.write_set())
    }

    fn base_storage_keys(&self) -> impl Iterator<Item = StorageKey> + '_ {
        self.read_set().chain(self.write_set())
    }

    fn base_accounts(&self) -> impl Iterator<Item = Address> + '_ {
        self.base_storage_keys()
            .map(|key| key.address)
            .chain([self.nonce.caller])
    }
}

pub fn prewarm_tip20_transfer_blockstm_plan<DB: Database>(
    db: &mut DB,
    plan: &Tip20TransferBlockstmPlan,
) -> Result<(), DB::Error> {
    let nonce_ring_ptr_key = expiring_nonce_ring_ptr_key();

    for key in plan.base_storage_keys() {
        if key == nonce_ring_ptr_key {
            continue;
        }
        let _ = db.storage(key.address, key.slot)?;
    }

    for account in plan.base_accounts() {
        let _ = db.basic(account)?;
    }

    Ok(())
}

fn read_expiring_nonce_base_storage<E>(
    plan: &Tip20TransferBlockstmPlan,
    block_timestamp: u64,
    mut read_storage: impl FnMut(StorageKey) -> Result<U256, E>,
    mut ring_index: impl FnMut(U256, Option<usize>) -> Result<u32, E>,
) -> Result<(), E> {
    let Tip20ExpiringNonceAction {
        replay_hash,
        valid_before: _,
        expiring_nonce_idx,
        ..
    } = plan.nonce;

    let seen_key = expiring_nonce_seen_key(replay_hash);
    let seen_expiry = read_storage(seen_key)?;
    if seen_expiry != U256::ZERO && seen_expiry > U256::from(block_timestamp) {
        return Ok(());
    }

    let ptr_key = expiring_nonce_ring_ptr_key();
    let idx = ring_index(read_storage(ptr_key)?, expiring_nonce_idx)?;
    let ring_key = expiring_nonce_ring_key(idx);
    let old_hash_word = read_storage(ring_key)?;

    if old_hash_word != U256::ZERO {
        let old_seen_key = expiring_nonce_seen_key(expiring_nonce_hash_from_word(old_hash_word));
        let _ = read_storage(old_seen_key)?;
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tip20ExpiringNonceAction {
    caller: Address,
    replay_hash: B256,
    valid_before: u64,
    expiring_nonce_idx: Option<usize>,
}

impl Tip20ExpiringNonceAction {
    fn read_set(&self) -> impl Iterator<Item = StorageKey> {
        [
            expiring_nonce_ring_ptr_key(),
            expiring_nonce_seen_key(self.replay_hash),
        ]
        .into_iter()
    }

    fn write_set(&self) -> impl Iterator<Item = StorageKey> {
        self.read_set()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Tip20FeeReserveAction {
    token: Address,
    fee_payer: Address,
    amount: U256,
}

impl Tip20FeeReserveAction {
    fn read_set(&self) -> impl Iterator<Item = StorageKey> {
        token_state_read_set(self.token)
            .into_iter()
            .chain(reward_inactive_read_set(self.token, self.fee_payer))
            .chain(reward_inactive_read_set(
                self.token,
                TIP_FEE_MANAGER_ADDRESS,
            ))
    }

    fn write_set(&self) -> impl Iterator<Item = StorageKey> {
        [
            balance_key(self.token, self.fee_payer),
            balance_key(self.token, TIP_FEE_MANAGER_ADDRESS),
        ]
        .into_iter()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Tip20FeeSettleAction {
    token: Address,
    fee_payer: Address,
    beneficiary: Address,
    max_amount: U256,
}

impl Tip20FeeSettleAction {
    fn read_set(&self) -> impl Iterator<Item = StorageKey> {
        reward_inactive_read_set(self.token, self.fee_payer)
            .into_iter()
            .chain(reward_inactive_read_set(
                self.token,
                TIP_FEE_MANAGER_ADDRESS,
            ))
            .chain([collected_fees_key(self.beneficiary, self.token)])
    }

    fn write_set(&self) -> impl Iterator<Item = StorageKey> {
        [
            balance_key(self.token, self.fee_payer),
            balance_key(self.token, TIP_FEE_MANAGER_ADDRESS),
            collected_fees_key(self.beneficiary, self.token),
        ]
        .into_iter()
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
    fn read_set(&self) -> impl Iterator<Item = StorageKey> {
        token_state_read_set(self.token)
            .into_iter()
            .chain(reward_inactive_read_set(self.token, self.from))
            .chain(reward_inactive_read_set(self.token, self.to))
            .chain([receive_policy_key(self.to)])
    }

    fn write_set(&self) -> impl Iterator<Item = StorageKey> {
        [
            balance_key(self.token, self.from),
            balance_key(self.token, self.to),
        ]
        .into_iter()
    }
}

impl<'a, DB, I> TempoBlockExecutor<'a, DB, I>
where
    DB: StateDB,
    I: Inspector<TempoContext<DB>>,
{
    /// Executes one pre-built BlockSTM TIP-20 transfer plan.
    ///
    /// `should_commit` observes the synthetic result before state mutation. Returning `false`
    /// leaves executor state unchanged, allowing the payload builder to stop at the exact block
    /// gas boundary instead of reserving the pooled transaction gas limit up front.
    pub fn execute_tip20_transfer_blockstm_planned_tx<'tx>(
        &mut self,
        tx: Tip20TransferBlockstmTx<'tx>,
        plan: Tip20TransferBlockstmPlan,
        transaction_index: usize,
        should_commit: impl FnOnce(&TempoTxResult) -> bool,
    ) -> Result<bool, Tip20TransferBlockstmExecutionError> {
        let block = self.inner.evm.block();
        let block_timestamp = block.timestamp().saturating_to::<u64>();
        let basefee = block.basefee as u128;

        self.validate_tip20_transfer_state(&plan)?;

        let base_state = self.read_plan_base_state(&plan, block_timestamp)?;
        let cfg = self.inner.evm.cfg.clone();
        let is_t6 = cfg.spec.is_t6();
        let mut tx_execution =
            execute_tip20_transfer_plan_with_deltas(&plan, &base_state, is_t6, block_timestamp)
                .map_err(Tip20TransferBlockstmExecutionError::Fallback)?;
        let gas = synthetic_tip20_result_gas(&tx.tx_env, &plan, &tx_execution, &base_state, &cfg)
            .map_err(Tip20TransferBlockstmExecutionError::Fallback)?;
        let actual_fee = synthetic_actual_fee(&tx.tx_env, &gas, basefee, is_t6);
        settle_actual_fee_with_deltas(&plan, &mut tx_execution, &base_state, actual_fee, is_t6)
            .map_err(Tip20TransferBlockstmExecutionError::Fallback)?;
        let tx_gas_used = gas.tx_gas_used();
        let block_gas_used = if cfg.enable_amsterdam_eip8037 {
            gas.block_regular_gas_used()
        } else {
            tx_gas_used
        };
        let next_section = self
            .validate_tx(tx.recovered.tx(), block_gas_used)
            .map_err(|error| Tip20TransferBlockstmExecutionError::Execution {
                transaction_index,
                error: error.into(),
            })?;
        let result = TempoTxResult::new_blockstm_tip20_success(
            tx.recovered.tx(),
            execution_state(&tx_execution, &base_state),
            synthetic_tip20_logs(&plan, actual_fee),
            gas,
            next_section,
            self.is_payment(tx.recovered.tx()),
            block_gas_used,
            actual_fee,
        );
        if !should_commit(&result) {
            return Ok(false);
        }
        self.commit_transaction(result);

        Ok(true)
    }

    fn validate_tip20_transfer_state(
        &mut self,
        plan: &Tip20TransferBlockstmPlan,
    ) -> Result<(), Tip20TransferBlockstmExecutionError> {
        validate_direct_recipient(plan.transfer.to)?;
        self.validate_receive_policy(plan.transfer.to)?;

        self.validate_token_global_state(plan.fee_reserve.token)?;
        self.validate_reward_inactive(plan.fee_reserve.token, plan.fee_reserve.fee_payer)?;
        self.validate_reward_inactive(plan.fee_reserve.token, TIP_FEE_MANAGER_ADDRESS)?;

        if plan.transfer.token != plan.fee_reserve.token {
            self.validate_token_global_state(plan.transfer.token)?;
        }
        self.validate_reward_inactive(plan.transfer.token, plan.transfer.from)?;
        self.validate_reward_inactive(plan.transfer.token, plan.transfer.to)?;

        Ok(())
    }

    fn validate_token_global_state(
        &mut self,
        token: Address,
    ) -> Result<(), Tip20TransferBlockstmExecutionError> {
        if self.read_storage(token, tip20_slots::PAUSED)? != U256::ZERO {
            return Err(Tip20TransferBlockstmExecutionError::Fallback(
                Tip20TransferBlockstmFallback::TokenPaused,
            ));
        }

        let transfer_policy = self.read_storage(token, tip20_slots::TRANSFER_POLICY_ID)?;
        if transfer_policy_id(transfer_policy) != U256::from(ALLOW_ALL_POLICY_ID) {
            return Err(Tip20TransferBlockstmExecutionError::Fallback(
                Tip20TransferBlockstmFallback::TransferPolicy,
            ));
        }

        if self.read_storage(token, tip20_slots::GLOBAL_REWARD_PER_TOKEN)? != U256::ZERO
            || self.read_storage(token, tip20_slots::OPTED_IN_SUPPLY)? != U256::ZERO
        {
            return Err(Tip20TransferBlockstmExecutionError::Fallback(
                Tip20TransferBlockstmFallback::RewardActive,
            ));
        }

        Ok(())
    }

    fn validate_receive_policy(
        &mut self,
        account: Address,
    ) -> Result<(), Tip20TransferBlockstmExecutionError> {
        let receive_policy_config = self.read_storage(
            TIP403_REGISTRY_ADDRESS,
            account.mapping_slot(tip403_registry_slots::RECEIVE_POLICIES),
        )?;
        if receive_policy_config != U256::ZERO {
            return Err(Tip20TransferBlockstmExecutionError::Fallback(
                Tip20TransferBlockstmFallback::ReceivePolicy,
            ));
        }

        Ok(())
    }

    fn validate_reward_inactive(
        &mut self,
        token: Address,
        account: Address,
    ) -> Result<(), Tip20TransferBlockstmExecutionError> {
        let balance = self.read_storage(token, balance_slot(account))?;
        decode_balance_state(balance).map_err(Tip20TransferBlockstmExecutionError::Fallback)?;

        let reward_info_base = account.mapping_slot(tip20_slots::USER_REWARD_INFO);
        for offset in 0..USER_REWARD_INFO_SLOTS {
            if self.read_storage(token, reward_info_base + U256::from(offset))? != U256::ZERO {
                return Err(Tip20TransferBlockstmExecutionError::Fallback(
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
    ) -> Result<U256, Tip20TransferBlockstmExecutionError> {
        self.inner
            .evm
            .db_mut()
            .storage(address, slot)
            .map_err(BlockExecutionError::other)
            .map_err(Tip20TransferBlockstmExecutionError::Database)
    }

    fn read_plan_base_state(
        &mut self,
        plan: &Tip20TransferBlockstmPlan,
        block_timestamp: u64,
    ) -> Result<Tip20BlockstmBaseState, Tip20TransferBlockstmExecutionError> {
        let mut storage = HashMap::new();
        for key in plan.base_storage_keys() {
            let _ = self.read_base_storage(&mut storage, key)?;
        }
        read_expiring_nonce_base_storage(
            plan,
            block_timestamp,
            |key| self.read_base_storage(&mut storage, key),
            |ptr_word, expiring_nonce_idx| {
                let ptr = expiring_nonce_ring_ptr_from_word(ptr_word)
                    .map_err(Tip20TransferBlockstmExecutionError::Fallback)?;
                expiring_nonce_ring_index(ptr, expiring_nonce_idx)
                    .map_err(Tip20TransferBlockstmExecutionError::Fallback)
            },
        )?;

        let mut account_infos = HashMap::new();
        for account in plan.base_accounts() {
            if account_infos.contains_key(&account) {
                continue;
            }
            let info = self.read_account_info(account)?;
            account_infos.insert(account, info);
        }
        let Some(info) = account_infos.get(&plan.nonce.caller) else {
            return Err(Tip20TransferBlockstmExecutionError::Fallback(
                Tip20TransferBlockstmFallback::StmValidation,
            ));
        };
        if !info.is_empty_code_hash() {
            return Err(Tip20TransferBlockstmExecutionError::Fallback(
                Tip20TransferBlockstmFallback::AccountHasCode,
            ));
        }

        Ok(Tip20BlockstmBaseState {
            storage,
            accounts: account_infos,
        })
    }

    fn read_base_storage(
        &mut self,
        storage: &mut HashMap<StorageKey, U256>,
        key: StorageKey,
    ) -> Result<U256, Tip20TransferBlockstmExecutionError> {
        if let Some(value) = storage.get(&key) {
            return Ok(*value);
        }

        let value = self.read_storage(key.address, key.slot)?;
        storage.insert(key, value);
        Ok(value)
    }

    fn read_account_info(
        &mut self,
        address: Address,
    ) -> Result<AccountInfo, Tip20TransferBlockstmExecutionError> {
        self.inner
            .evm
            .db_mut()
            .basic(address)
            .map_err(BlockExecutionError::other)
            .map_err(Tip20TransferBlockstmExecutionError::Database)
            .map(|account| account.unwrap_or_default())
    }
}

const USER_REWARD_INFO_SLOTS: u64 = 3;
const U64_MASK: U256 = U256::from_limbs([u64::MAX, 0, 0, 0]);
const REWARD_FLAG_SHIFT_BITS: usize = 128;
const REWARD_FLAG_UNINITIALIZED: u8 = 0;
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

fn validate_direct_recipient(to: Address) -> Result<(), Tip20TransferBlockstmExecutionError> {
    if to.is_zero() || to.is_tip20() {
        return Err(Tip20TransferBlockstmExecutionError::Fallback(
            Tip20TransferBlockstmFallback::InvalidRecipient,
        ));
    }
    if to.is_virtual() {
        return Err(Tip20TransferBlockstmExecutionError::Fallback(
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

pub fn build_tip20_transfer_blockstm_plan(
    tx: &Tip20TransferBlockstmTx<'_>,
    validator_token: Address,
    beneficiary: Address,
    basefee: u128,
    blob_gasprice: u128,
    spec: TempoHardfork,
) -> Result<Tip20TransferBlockstmPlan, Tip20TransferBlockstmFallback> {
    let transfer = decode_tip20_transfer_action(tx, validator_token)?;
    let nonce = decode_expiring_nonce_action(&tx.tx_env, spec)?;
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

    Ok(Tip20TransferBlockstmPlan::new(
        nonce,
        Tip20FeeReserveAction {
            token: tx.fee_token,
            fee_payer,
            amount: max_fee,
        },
        transfer,
        Tip20FeeSettleAction {
            token: tx.fee_token,
            fee_payer,
            beneficiary,
            max_amount: max_fee,
        },
    ))
}

fn execute_tip20_transfer_plan_with_deltas(
    plan: &Tip20TransferBlockstmPlan,
    base_state: &Tip20BlockstmBaseState,
    is_t6: bool,
    block_timestamp: u64,
) -> Result<Tip20BlockstmTxExecution, Tip20TransferBlockstmFallback> {
    let mut execution = Tip20BlockstmTxExecution {
        storage: HashMap::new(),
    };

    apply_expiring_nonce_action(
        plan.nonce.replay_hash,
        plan.nonce.valid_before,
        plan.nonce.expiring_nonce_idx,
        &mut execution,
        base_state,
        block_timestamp,
    )?;
    reserve_fee_balance(
        plan.fee_reserve.token,
        plan.fee_reserve.fee_payer,
        plan.fee_reserve.amount,
        is_t6,
        &mut execution,
        base_state,
    )?;
    transfer_balance(
        plan.transfer.token,
        plan.transfer.from,
        plan.transfer.to,
        plan.transfer.amount,
        is_t6,
        &mut execution,
        base_state,
    )?;

    Ok(execution)
}

fn apply_expiring_nonce_action(
    replay_hash: B256,
    valid_before: u64,
    expiring_nonce_idx: Option<usize>,
    execution: &mut Tip20BlockstmTxExecution,
    base_state: &Tip20BlockstmBaseState,
    block_timestamp: u64,
) -> Result<(), Tip20TransferBlockstmFallback> {
    if valid_before <= block_timestamp
        || valid_before > block_timestamp.saturating_add(EXPIRING_NONCE_MAX_EXPIRY_SECS)
    {
        return Err(Tip20TransferBlockstmFallback::InvalidNonce);
    }

    let seen_key = expiring_nonce_seen_key(replay_hash);
    let seen_expiry = read_for_write(execution, base_state, seen_key);
    if seen_expiry != U256::ZERO && seen_expiry > U256::from(block_timestamp) {
        return Err(Tip20TransferBlockstmFallback::ExpiringNonceReplay);
    }

    let ptr_key = expiring_nonce_ring_ptr_key();
    let ptr = expiring_nonce_ring_ptr_from_word(read_for_write(execution, base_state, ptr_key))?;
    let idx = expiring_nonce_ring_index(ptr, expiring_nonce_idx)?;
    let ring_key = expiring_nonce_ring_key(idx);
    let old_hash_word = read_for_write(execution, base_state, ring_key);

    if old_hash_word != U256::ZERO {
        let old_seen_key = expiring_nonce_seen_key(expiring_nonce_hash_from_word(old_hash_word));
        let old_expiry = read_for_write(execution, base_state, old_seen_key);
        if old_expiry != U256::ZERO && old_expiry > U256::from(block_timestamp) {
            return Err(Tip20TransferBlockstmFallback::ExpiringNonceSetFull);
        }
        write_value(execution, base_state, old_seen_key, U256::ZERO);
    }

    write_value(
        execution,
        base_state,
        ring_key,
        expiring_nonce_hash_to_word(replay_hash),
    );
    write_value(execution, base_state, seen_key, U256::from(valid_before));

    let next_ptr = expiring_nonce_next_ring_ptr(idx);
    write_value(execution, base_state, ptr_key, U256::from(next_ptr));
    if expiring_nonce_idx.is_some() {
        write_value(execution, base_state, ptr_key, U256::from(ptr));
    }

    Ok(())
}

fn settle_actual_fee_with_deltas(
    plan: &Tip20TransferBlockstmPlan,
    execution: &mut Tip20BlockstmTxExecution,
    base_state: &Tip20BlockstmBaseState,
    actual_fee: U256,
    is_t6: bool,
) -> Result<(), Tip20TransferBlockstmFallback> {
    let Tip20FeeSettleAction {
        token,
        fee_payer,
        beneficiary,
        max_amount,
    } = plan.fee_settle;

    if actual_fee > max_amount {
        return Err(Tip20TransferBlockstmFallback::InvalidFeeCharge);
    }

    let refund = max_amount - actual_fee;
    if !refund.is_zero() {
        refund_fee_balance(token, fee_payer, refund, is_t6, execution, base_state)?;
    }

    let collected_key = collected_fees_key(beneficiary, token);
    let collected = read_for_write(execution, base_state, collected_key);
    let new_collected = collected
        .checked_add(actual_fee)
        .ok_or(Tip20TransferBlockstmFallback::BalanceOverflow)?;
    write_value(execution, base_state, collected_key, new_collected);

    Ok(())
}

fn execution_state(
    execution: &Tip20BlockstmTxExecution,
    base_state: &Tip20BlockstmBaseState,
) -> EvmState {
    let mut state = EvmState::default();

    for (key, original, written) in execution.written_storage() {
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
        account.storage.insert(
            key.slot,
            EvmStorageSlot::new_changed(original, written, TransactionId::ZERO),
        );
    }

    state
}

#[derive(Debug, Clone, Copy)]
enum BalanceWriteFlag {
    Preserve,
    Inactive,
}

impl BalanceWriteFlag {
    fn resolve(self, balance: Tip20BalanceState) -> u8 {
        match self {
            Self::Preserve => balance.reward_flag,
            Self::Inactive => balance.inactive_write_flag(),
        }
    }
}

fn reserve_fee_balance(
    token: Address,
    fee_payer: Address,
    amount: U256,
    is_t6: bool,
    execution: &mut Tip20BlockstmTxExecution,
    base_state: &Tip20BlockstmBaseState,
) -> Result<(), Tip20TransferBlockstmFallback> {
    transfer_balance_with_flags(
        token,
        fee_payer,
        TIP_FEE_MANAGER_ADDRESS,
        amount,
        is_t6,
        BalanceWriteFlag::Inactive,
        BalanceWriteFlag::Preserve,
        execution,
        base_state,
    )
}

fn refund_fee_balance(
    token: Address,
    fee_payer: Address,
    amount: U256,
    is_t6: bool,
    execution: &mut Tip20BlockstmTxExecution,
    base_state: &Tip20BlockstmBaseState,
) -> Result<(), Tip20TransferBlockstmFallback> {
    transfer_balance_with_flags(
        token,
        TIP_FEE_MANAGER_ADDRESS,
        fee_payer,
        amount,
        is_t6,
        BalanceWriteFlag::Preserve,
        BalanceWriteFlag::Inactive,
        execution,
        base_state,
    )
}

fn transfer_balance(
    token: Address,
    from: Address,
    to: Address,
    amount: U256,
    is_t6: bool,
    execution: &mut Tip20BlockstmTxExecution,
    base_state: &Tip20BlockstmBaseState,
) -> Result<(), Tip20TransferBlockstmFallback> {
    transfer_balance_with_flags(
        token,
        from,
        to,
        amount,
        is_t6,
        BalanceWriteFlag::Inactive,
        BalanceWriteFlag::Inactive,
        execution,
        base_state,
    )
}

#[allow(clippy::too_many_arguments)]
fn transfer_balance_with_flags(
    token: Address,
    from: Address,
    to: Address,
    amount: U256,
    is_t6: bool,
    from_write_flag: BalanceWriteFlag,
    to_write_flag: BalanceWriteFlag,
    execution: &mut Tip20BlockstmTxExecution,
    base_state: &Tip20BlockstmBaseState,
) -> Result<(), Tip20TransferBlockstmFallback> {
    if amount.is_zero() {
        return Ok(());
    }

    let from_key = balance_key(token, from);
    let to_key = balance_key(token, to);
    let from_balance = read_balance_for_write(execution, base_state, from_key)?;

    if from_balance.amount < amount {
        return Err(Tip20TransferBlockstmFallback::InsufficientBalance);
    }
    let new_from = from_balance.amount - amount;
    write_value(
        execution,
        base_state,
        from_key,
        encode_balance(new_from, from_write_flag.resolve(from_balance), is_t6),
    );

    let to_balance = read_balance_for_write(execution, base_state, to_key)?;
    let new_to = to_balance
        .amount
        .checked_add(amount)
        .ok_or(Tip20TransferBlockstmFallback::BalanceOverflow)?;
    if new_to > U128_MAX {
        return Err(Tip20TransferBlockstmFallback::BalanceOverflow);
    }

    write_value(
        execution,
        base_state,
        to_key,
        encode_balance(new_to, to_write_flag.resolve(to_balance), is_t6),
    );

    Ok(())
}

fn read_balance_for_write(
    execution: &mut Tip20BlockstmTxExecution,
    base_state: &Tip20BlockstmBaseState,
    key: StorageKey,
) -> Result<Tip20BalanceState, Tip20TransferBlockstmFallback> {
    let raw = read_for_write(execution, base_state, key);
    decode_balance_state(raw)
}

fn read_for_write(
    execution: &mut Tip20BlockstmTxExecution,
    base_state: &Tip20BlockstmBaseState,
    key: StorageKey,
) -> U256 {
    if let Some(value) = execution.storage.get(&key) {
        return value.written.unwrap_or(value.original);
    }

    let original = base_storage_value(base_state, key);
    execution.storage.insert(
        key,
        Tip20BlockstmTxStorage {
            original,
            written: None,
        },
    );
    original
}

fn write_value(
    execution: &mut Tip20BlockstmTxExecution,
    base_state: &Tip20BlockstmBaseState,
    key: StorageKey,
    value: U256,
) {
    execution
        .storage
        .entry(key)
        .and_modify(|storage| storage.written = Some(value))
        .or_insert_with(|| Tip20BlockstmTxStorage {
            original: base_storage_value(base_state, key),
            written: Some(value),
        });
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

    seed_fee_reserve_gas_state(
        plan,
        execution,
        base_state,
        cfg,
        &mut meter,
        &mut original_values,
        &mut present_values,
    )?;

    meter_tip20_transfer_action_gas(
        &plan.transfer,
        execution,
        base_state,
        cfg,
        &mut meter,
        &mut original_values,
        &mut present_values,
    )?;

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

fn seed_fee_reserve_gas_state(
    plan: &Tip20TransferBlockstmPlan,
    execution: &Tip20BlockstmTxExecution,
    base_state: &Tip20BlockstmBaseState,
    cfg: &CfgEnv<TempoHardfork>,
    meter: &mut SyntheticTip20GasMeter,
    original_values: &mut HashMap<StorageKey, U256>,
    present_values: &mut HashMap<StorageKey, U256>,
) -> Result<(), Tip20TransferBlockstmFallback> {
    let Tip20FeeReserveAction {
        token,
        fee_payer,
        amount,
    } = plan.fee_reserve;

    // Fee reserve gas is excluded from receipts, but its storage accesses still warm the
    // transaction access set before the user TIP-20 calls execute.
    meter.warm_storage(paused_key(token));
    meter.warm_storage(transfer_policy_key(token));
    let payer_key = balance_key(token, fee_payer);
    let manager_key = balance_key(token, TIP_FEE_MANAGER_ADDRESS);
    meter.warm_storage(payer_key);
    meter.warm_storage(manager_key);

    if !amount.is_zero() {
        let payer_raw = synthetic_present_value(
            present_values,
            original_values,
            execution,
            base_state,
            payer_key,
        );
        let manager_raw = synthetic_present_value(
            present_values,
            original_values,
            execution,
            base_state,
            manager_key,
        );
        let payer_balance = decode_balance_state(payer_raw)?;
        let manager_balance = decode_balance_state(manager_raw)?;
        let new_payer = payer_balance
            .amount
            .checked_sub(amount)
            .ok_or(Tip20TransferBlockstmFallback::InsufficientBalance)?;
        let new_manager = manager_balance
            .amount
            .checked_add(amount)
            .ok_or(Tip20TransferBlockstmFallback::BalanceOverflow)?;

        present_values.insert(
            payer_key,
            encode_balance(
                new_payer,
                payer_balance.inactive_write_flag(),
                cfg.spec.is_t6(),
            ),
        );
        present_values.insert(
            manager_key,
            encode_balance(new_manager, manager_balance.reward_flag, cfg.spec.is_t6()),
        );
    }

    Ok(())
}

fn meter_tip20_transfer_action_gas(
    action: &Tip20TransferAction,
    execution: &Tip20BlockstmTxExecution,
    base_state: &Tip20BlockstmBaseState,
    cfg: &CfgEnv<TempoHardfork>,
    meter: &mut SyntheticTip20GasMeter,
    original_values: &mut HashMap<StorageKey, U256>,
    present_values: &mut HashMap<StorageKey, U256>,
) -> Result<(), Tip20TransferBlockstmFallback> {
    let gas_params = cfg.gas_params();

    meter.add_regular(input_cost(action.calldata_len))?;
    meter.warm_account_info(gas_params)?;
    meter.sload(paused_key(action.token), gas_params)?;
    meter.sload(transfer_policy_key(action.token), gas_params)?;
    meter.tload(gas_params)?;
    meter.sload(receive_policy_key(action.to), gas_params)?;

    let from_key = balance_key(action.token, action.from);
    let to_key = balance_key(action.token, action.to);

    meter.sload(from_key, gas_params)?;
    let from_balance = decode_balance_state(synthetic_present_value(
        present_values,
        original_values,
        execution,
        base_state,
        from_key,
    ))?;
    if from_balance.amount < action.amount {
        return Err(Tip20TransferBlockstmFallback::InsufficientBalance);
    }

    let from_flag = meter_tip20_t6_reward_update(
        action.token,
        action.from,
        execution,
        base_state,
        cfg,
        meter,
        original_values,
        present_values,
    )?;
    let to_flag = meter_tip20_t6_reward_update(
        action.token,
        action.to,
        execution,
        base_state,
        cfg,
        meter,
        original_values,
        present_values,
    )?;
    if from_flag != REWARD_FLAG_OPTED_OUT || to_flag != REWARD_FLAG_OPTED_OUT {
        return Err(Tip20TransferBlockstmFallback::RewardActive);
    }

    if !action.amount.is_zero() {
        let from_present_raw = synthetic_present_value(
            present_values,
            original_values,
            execution,
            base_state,
            from_key,
        );
        let from_present = decode_balance_state(from_present_raw)?;
        let new_from = from_present
            .amount
            .checked_sub(action.amount)
            .ok_or(Tip20TransferBlockstmFallback::InsufficientBalance)?;
        let new_from_raw = encode_balance(new_from, from_flag, cfg.spec.is_t6());
        meter.sstore(
            from_key,
            synthetic_original_value(original_values, execution, base_state, from_key),
            from_present_raw,
            new_from_raw,
            gas_params,
        )?;
        present_values.insert(from_key, new_from_raw);

        meter.sload(to_key, gas_params)?;
        let to_present_raw = synthetic_present_value(
            present_values,
            original_values,
            execution,
            base_state,
            to_key,
        );
        let to_present = decode_balance_state(to_present_raw)?;
        let new_to = to_present
            .amount
            .checked_add(action.amount)
            .ok_or(Tip20TransferBlockstmFallback::BalanceOverflow)?;
        let new_to_raw = encode_balance(new_to, to_flag, cfg.spec.is_t6());
        meter.sstore(
            to_key,
            synthetic_original_value(original_values, execution, base_state, to_key),
            to_present_raw,
            new_to_raw,
            gas_params,
        )?;
        present_values.insert(to_key, new_to_raw);
    }

    meter.log(
        &tip20_transfer_log(action.token, action.from, action.to, action.amount),
        gas_params,
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
            gas_params,
        )?;
    }

    Ok(())
}

fn meter_tip20_t6_reward_update(
    token: Address,
    holder: Address,
    execution: &Tip20BlockstmTxExecution,
    base_state: &Tip20BlockstmBaseState,
    cfg: &CfgEnv<TempoHardfork>,
    meter: &mut SyntheticTip20GasMeter,
    original_values: &mut HashMap<StorageKey, U256>,
    present_values: &mut HashMap<StorageKey, U256>,
) -> Result<u8, Tip20TransferBlockstmFallback> {
    if !cfg.spec.is_t6() {
        return Err(Tip20TransferBlockstmFallback::RewardActive);
    }

    let balance_key = balance_key(token, holder);
    meter.sload(balance_key, cfg.gas_params())?;
    let balance = decode_balance_state(synthetic_present_value(
        present_values,
        original_values,
        execution,
        base_state,
        balance_key,
    ))?;

    match balance.reward_flag {
        REWARD_FLAG_OPTED_OUT => Ok(REWARD_FLAG_OPTED_OUT),
        REWARD_FLAG_UNINITIALIZED => {
            let reward_recipient_key = StorageKey {
                address: token,
                slot: holder.mapping_slot(tip20_slots::USER_REWARD_INFO),
            };
            meter.sload(reward_recipient_key, cfg.gas_params())?;
            let reward_recipient = synthetic_present_value(
                present_values,
                original_values,
                execution,
                base_state,
                reward_recipient_key,
            );
            if reward_recipient != U256::ZERO {
                return Err(Tip20TransferBlockstmFallback::RewardActive);
            }
            Ok(REWARD_FLAG_OPTED_OUT)
        }
        _ => Err(Tip20TransferBlockstmFallback::RewardActive),
    }
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

        if spec.is_t1() {
            if aa_env.nonce_key == TEMPO_EXPIRING_NONCE_KEY {
                batch_gas.initial_regular_gas += EXPIRING_NONCE_GAS;
            } else if tx.nonce() == 0 {
                batch_gas.initial_regular_gas += gas_params.get(GasId::new_account_cost());
                batch_gas.initial_state_gas += gas_params.new_account_state_gas();
            }
        }
        if gas_limit < batch_gas.initial_total_gas() {
            return Err(Tip20TransferBlockstmFallback::GasLimit);
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
    fn warm_storage(&mut self, key: StorageKey) {
        self.warm_storage.insert(key);
    }

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

    fn warm_account_info(
        &mut self,
        gas_params: &GasParams,
    ) -> Result<(), Tip20TransferBlockstmFallback> {
        self.add_regular(gas_params.warm_storage_read_cost())
    }

    fn tload(&mut self, gas_params: &GasParams) -> Result<(), Tip20TransferBlockstmFallback> {
        self.add_regular(gas_params.warm_storage_read_cost())
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

fn synthetic_original_value(
    original_values: &mut HashMap<StorageKey, U256>,
    execution: &Tip20BlockstmTxExecution,
    base_state: &Tip20BlockstmBaseState,
    key: StorageKey,
) -> U256 {
    *original_values
        .entry(key)
        .or_insert_with(|| tx_storage_value(execution, base_state, key))
}

fn synthetic_present_value(
    present_values: &mut HashMap<StorageKey, U256>,
    original_values: &mut HashMap<StorageKey, U256>,
    execution: &Tip20BlockstmTxExecution,
    base_state: &Tip20BlockstmBaseState,
    key: StorageKey,
) -> U256 {
    if let Some(value) = present_values.get(&key) {
        return *value;
    }

    let value = synthetic_original_value(original_values, execution, base_state, key);
    present_values.insert(key, value);
    value
}

fn tx_storage_value(
    execution: &Tip20BlockstmTxExecution,
    base_state: &Tip20BlockstmBaseState,
    key: StorageKey,
) -> U256 {
    execution
        .storage
        .get(&key)
        .map(|value| value.original)
        .unwrap_or_else(|| base_storage_value(base_state, key))
}

fn base_storage_value(base_state: &Tip20BlockstmBaseState, key: StorageKey) -> U256 {
    base_state.storage.get(&key).copied().unwrap_or_default()
}

fn synthetic_actual_fee(tx: &TempoTxEnv, gas: &ResultGas, basefee: u128, is_t6: bool) -> U256 {
    let fee_gas_used = gas.spent_sub_refunded();
    let mut effective_gas_price = tx.effective_gas_price(basefee);
    if is_t6 && tx.is_discounted_payment() && fee_gas_used <= SSTORE_SET_COST {
        effective_gas_price = tempo_t6_discounted_payment_effective_gas_price(effective_gas_price);
    }
    calc_gas_balance_spending(fee_gas_used, effective_gas_price)
}

fn synthetic_tip20_logs(plan: &Tip20TransferBlockstmPlan, actual_fee: U256) -> Vec<Log> {
    let mut logs = Vec::new();

    let action = &plan.transfer;
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

    let Tip20FeeSettleAction {
        token,
        fee_payer,
        max_amount,
        ..
    } = plan.fee_settle;
    if !actual_fee.is_zero() || max_amount > actual_fee {
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

fn decode_tip20_transfer_action(
    tx: &Tip20TransferBlockstmTx<'_>,
    validator_token: Address,
) -> Result<Tip20TransferAction, Tip20TransferBlockstmFallback> {
    if tx.fee_token != validator_token {
        return Err(Tip20TransferBlockstmFallback::FeeTokenMismatch);
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

    let mut calls = tx.tx_env.calls();
    let Some((kind, input)) = calls.next() else {
        return Err(Tip20TransferBlockstmFallback::EmptyCalls);
    };
    let action = decode_tip20_transfer_call(tx.tx_env.caller(), *kind, input)?;
    if calls.next().is_some() {
        return Err(Tip20TransferBlockstmFallback::UnsupportedSelector);
    }

    Ok(action)
}

fn decode_expiring_nonce_action(
    tx: &TempoTxEnv,
    spec: TempoHardfork,
) -> Result<Tip20ExpiringNonceAction, Tip20TransferBlockstmFallback> {
    let caller = tx.caller();
    let nonce = tx.nonce();

    let Some(aa) = tx.tempo_tx_env.as_ref() else {
        return Err(Tip20TransferBlockstmFallback::InvalidNonce);
    };

    if aa.nonce_key == TEMPO_EXPIRING_NONCE_KEY && spec.is_t1() {
        if nonce != 0 {
            return Err(Tip20TransferBlockstmFallback::InvalidNonce);
        }

        Ok(Tip20ExpiringNonceAction {
            caller,
            replay_hash: if spec.is_t1b() {
                tx.unique_tx_identifier().unwrap_or(aa.tx_hash)
            } else {
                aa.tx_hash
            },
            valid_before: aa
                .valid_before
                .ok_or(Tip20TransferBlockstmFallback::MissingExpiringNonceValidBefore)?,
            expiring_nonce_idx: aa.expiring_nonce_idx,
        })
    } else {
        Err(Tip20TransferBlockstmFallback::InvalidNonce)
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

const NONCE_MANAGER_EXPIRING_NONCE_SEEN_SLOT: U256 = U256::from_limbs([1, 0, 0, 0]);
const NONCE_MANAGER_EXPIRING_NONCE_RING_SLOT: U256 = U256::from_limbs([2, 0, 0, 0]);
const NONCE_MANAGER_EXPIRING_NONCE_RING_PTR_SLOT: U256 = U256::from_limbs([3, 0, 0, 0]);

fn expiring_nonce_seen_key(hash: B256) -> StorageKey {
    StorageKey {
        address: NONCE_PRECOMPILE_ADDRESS,
        slot: hash.mapping_slot(NONCE_MANAGER_EXPIRING_NONCE_SEEN_SLOT),
    }
}

fn expiring_nonce_ring_key(index: u32) -> StorageKey {
    StorageKey {
        address: NONCE_PRECOMPILE_ADDRESS,
        slot: index.mapping_slot(NONCE_MANAGER_EXPIRING_NONCE_RING_SLOT),
    }
}

fn expiring_nonce_ring_ptr_key() -> StorageKey {
    StorageKey {
        address: NONCE_PRECOMPILE_ADDRESS,
        slot: NONCE_MANAGER_EXPIRING_NONCE_RING_PTR_SLOT,
    }
}

fn expiring_nonce_ring_ptr_from_word(word: U256) -> Result<u32, Tip20TransferBlockstmFallback> {
    if word > U256::from(u32::MAX) {
        return Err(Tip20TransferBlockstmFallback::StmValidation);
    }
    Ok(word.to::<u32>())
}

fn expiring_nonce_ring_index(
    ptr: u32,
    expiring_nonce_idx: Option<usize>,
) -> Result<u32, Tip20TransferBlockstmFallback> {
    let Some(offset) = expiring_nonce_idx else {
        return Ok(ptr);
    };

    let offset = u32::try_from(offset).map_err(|_| Tip20TransferBlockstmFallback::InvalidNonce)?;
    Ok(((u64::from(ptr) + u64::from(offset)) % u64::from(EXPIRING_NONCE_SET_CAPACITY)) as u32)
}

fn expiring_nonce_next_ring_ptr(index: u32) -> u32 {
    if index >= EXPIRING_NONCE_SET_CAPACITY - 1 {
        0
    } else {
        index + 1
    }
}

fn expiring_nonce_hash_to_word(hash: B256) -> U256 {
    U256::from_be_slice(hash.as_slice())
}

fn expiring_nonce_hash_from_word(word: U256) -> B256 {
    B256::from(word.to_be_bytes::<32>())
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

fn paused_key(token: Address) -> StorageKey {
    StorageKey {
        address: token,
        slot: tip20_slots::PAUSED,
    }
}

fn transfer_policy_key(token: Address) -> StorageKey {
    StorageKey {
        address: token,
        slot: tip20_slots::TRANSFER_POLICY_ID,
    }
}

fn token_state_read_set(token: Address) -> [StorageKey; 4] {
    [
        paused_key(token),
        transfer_policy_key(token),
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
    use alloy_primitives::{Signature, address, keccak256};
    use alloy_signer::SignerSync;
    use alloy_signer_local::{MnemonicBuilder, PrivateKeySigner};
    use alloy_sol_types::SolCall;
    use reth_primitives_traits::Account as RethAccount;
    use reth_revm::{
        State,
        db::states::bundle_state::BundleRetention,
        state::{AccountInfo, Bytecode},
    };
    use reth_trie::{HashedPostState, KeccakKeyHasher};
    use revm::database::{CacheDB, EmptyDB, states::plain_account::PlainStorage};
    use std::{
        collections::BTreeSet,
        fmt::Write as _,
        sync::{Arc, Mutex},
    };
    use tempo_precompiles::{
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::TIP20Setup,
    };
    use tempo_primitives::{
        AASigned, MasterId, TempoSignature, TempoTransaction, TempoTxEnvelope, UserTag,
        transaction::{Call, PrimitiveSignature, TEMPO_EXPIRING_NONCE_KEY},
    };
    use tempo_revm::gas_params::tempo_gas_params;

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

    fn expiring_blockstm_tx_with_gas(
        calls: Vec<Call>,
        valid_before: u64,
        gas_limit: u64,
    ) -> (Recovered<TempoTxEnvelope>, TempoTxEnv) {
        let tx = TempoTransaction {
            chain_id: 1,
            calls,
            gas_limit,
            nonce_key: TEMPO_EXPIRING_NONCE_KEY,
            nonce: 0,
            valid_before: core::num::NonZeroU64::new(valid_before),
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

    fn signed_expiring_tip20_transfer(
        signer: &PrivateKeySigner,
        recipient: Address,
        amount: U256,
        valid_before: u64,
        gas_limit: u64,
        gas_price: u128,
    ) -> (Recovered<TempoTxEnvelope>, TempoTxEnv) {
        let tx = TempoTransaction {
            chain_id: 1,
            fee_token: Some(tempo_precompiles::PATH_USD_ADDRESS),
            calls: vec![transfer_call_to_token(
                tempo_precompiles::PATH_USD_ADDRESS,
                recipient,
                amount,
            )],
            gas_limit,
            nonce_key: TEMPO_EXPIRING_NONCE_KEY,
            nonce: 0,
            valid_before: core::num::NonZeroU64::new(valid_before),
            max_fee_per_gas: gas_price,
            max_priority_fee_per_gas: gas_price,
            ..Default::default()
        };
        let signature = signer
            .sign_hash_sync(&tx.signature_hash())
            .expect("test transaction must sign");
        let signed = TempoTxEnvelope::AA(AASigned::new_unhashed(
            tx,
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature)),
        ));
        let recovered = Recovered::new_unchecked(signed, signer.address());
        let tx_env = TempoTxEnv::from_recovered_tx(recovered.inner(), signer.address());
        (recovered, tx_env)
    }

    fn txgen_signers(account_count: usize) -> Vec<PrivateKeySigner> {
        (0..account_count)
            .map(|idx| {
                MnemonicBuilder::from_phrase(
                    "test test test test test test test test test test test junk",
                )
                .index(idx as u32)
                .expect("valid test account index")
                .build()
                .expect("valid test mnemonic")
            })
            .collect()
    }

    fn transfer_call(to: Address, amount: U256) -> Call {
        transfer_call_to_token(TOKEN, to, amount)
    }

    fn transfer_call_to_token(token: Address, to: Address, amount: U256) -> Call {
        Call {
            to: TxKind::Call(token),
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

    fn path_usd_state_with_balances_and_reward_flag(
        balances: impl IntoIterator<Item = (Address, U256)>,
        reward_flag: u8,
    ) -> State<EmptyDB> {
        let balances = balances.into_iter().collect::<Vec<_>>();
        let mut provider = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut provider, || {
            let mut setup = TIP20Setup::path_usd(SENDER)
                .with_issuer(SENDER)
                .clear_events();
            for (account, balance) in &balances {
                setup = setup.with_mint(*account, *balance);
            }
            setup.apply().expect("pathUSD setup must succeed");
        });

        let balance_slots = balances
            .into_iter()
            .map(|(account, balance)| {
                (
                    balance_slot(account),
                    encode_balance(balance, reward_flag, true),
                )
            })
            .collect::<HashMap<_, _>>();
        let mut db = State::builder().with_bundle_update().build();
        let mut storage_by_account: HashMap<Address, PlainStorage> = HashMap::new();
        for (address, slot, mut value) in provider.into_storage() {
            if address == tempo_precompiles::PATH_USD_ADDRESS
                && let Some(balance) = balance_slots.get(&slot)
            {
                value = *balance;
            }
            storage_by_account
                .entry(address)
                .or_default()
                .insert(slot, value);
        }
        let inserted_accounts = storage_by_account.keys().copied().collect::<HashSet<_>>();
        for (address, storage) in storage_by_account {
            db.insert_account_with_storage(address, precompile_marker_info(), storage);
        }
        for address in [
            tempo_precompiles::PATH_USD_ADDRESS,
            NONCE_PRECOMPILE_ADDRESS,
            TIP_FEE_MANAGER_ADDRESS,
        ] {
            if !inserted_accounts.contains(&address) {
                db.insert_account(address, precompile_marker_info());
            }
        }
        db
    }

    fn path_usd_parent_db_with_balances_and_reward_flag(
        balances: impl IntoIterator<Item = (Address, U256)>,
        reward_flag: u8,
    ) -> CacheDB<EmptyDB> {
        let state = path_usd_state_with_balances_and_reward_flag(balances, reward_flag);
        let mut db = CacheDB::new(EmptyDB::default());
        for (address, account) in state.cache.trie_account() {
            db.insert_account_info(address, account.info.clone());
            for (slot, value) in &account.storage {
                db.insert_account_storage(address, *slot, *value)
                    .expect("cache DB storage insert must succeed");
            }
        }
        db
    }

    fn assert_fallback(
        err: Tip20TransferBlockstmExecutionError,
        expected: Tip20TransferBlockstmFallback,
    ) {
        match err {
            Tip20TransferBlockstmExecutionError::Fallback(actual) => assert_eq!(actual, expected),
            other => panic!("expected fallback {expected:?}, got {other:?}"),
        }
    }

    fn t6_test_cfg() -> CfgEnv<TempoHardfork> {
        let mut cfg = CfgEnv::<TempoHardfork>::default();
        cfg.spec = TempoHardfork::T6;
        cfg.gas_params = tempo_gas_params(TempoHardfork::T6);
        cfg
    }

    fn test_base_state(storage: HashMap<StorageKey, U256>) -> Tip20BlockstmBaseState {
        Tip20BlockstmBaseState {
            storage,
            accounts: HashMap::new(),
        }
    }

    fn db_to_trie_state(
        db: &State<EmptyDB>,
    ) -> HashMap<Address, (RethAccount, HashMap<B256, U256>)> {
        db.cache
            .trie_account()
            .into_iter()
            .map(|(address, account)| {
                (
                    address,
                    (
                        RethAccount::from(&account.info),
                        account
                            .storage
                            .iter()
                            .filter(|(_, value)| !value.is_zero())
                            .map(|(slot, value)| (B256::from(*slot), *value))
                            .collect(),
                    ),
                )
            })
            .collect()
    }

    fn apply_evm_state_updates_to_trie_state(
        trie_state: &mut HashMap<Address, (RethAccount, HashMap<B256, U256>)>,
        updates: &[EvmState],
    ) {
        for update in updates {
            for (address, account) in update {
                if !account.is_touched() {
                    continue;
                }

                if account.is_selfdestructed() {
                    trie_state.remove(address);
                    continue;
                }

                let info_changed = account.info != account.original_info();
                let changed_storage = account
                    .storage
                    .iter()
                    .filter(|(_, value)| value.is_changed())
                    .map(|(slot, value)| (B256::from(*slot), value.present_value))
                    .collect::<Vec<_>>();
                if !info_changed && changed_storage.is_empty() {
                    continue;
                }

                let entry = trie_state.entry(*address).or_default();
                if info_changed {
                    entry.0 = RethAccount::from(&account.info);
                }
                for (slot, value) in changed_storage {
                    if value.is_zero() {
                        entry.1.remove(&slot);
                    } else {
                        entry.1.insert(slot, value);
                    }
                }
            }
        }
    }

    fn evm_state_to_hashed_post_state(update: EvmState) -> HashedPostState {
        let mut hashed_state = HashedPostState::with_capacity(update.len());

        for (address, account) in update {
            if !account.is_touched() {
                continue;
            }

            let hashed_address = keccak256(address);
            let destroyed = account.is_selfdestructed();
            if account.info != account.original_info() {
                let info = if destroyed {
                    None
                } else {
                    Some(account.info.into())
                };
                hashed_state.accounts.insert(hashed_address, info);
            }

            let mut changed_storage = account
                .storage
                .into_iter()
                .filter(|(_, value)| value.is_changed())
                .map(|(slot, value)| (keccak256(B256::from(slot)), value.present_value))
                .peekable();
            if destroyed {
                hashed_state
                    .storages
                    .insert(hashed_address, reth_trie::HashedStorage::new(true));
            } else if changed_storage.peek().is_some() {
                hashed_state.storages.insert(
                    hashed_address,
                    reth_trie::HashedStorage::from_iter(false, changed_storage),
                );
            }
        }

        hashed_state
    }

    fn describe_trie_state_diff(
        normal: &HashMap<Address, (RethAccount, HashMap<B256, U256>)>,
        blockstm: &HashMap<Address, (RethAccount, HashMap<B256, U256>)>,
    ) -> String {
        let mut out = String::new();
        let mut addresses = BTreeSet::new();
        addresses.extend(normal.keys().copied());
        addresses.extend(blockstm.keys().copied());

        let mut diffs = 0usize;
        for address in addresses {
            let normal_account = normal.get(&address);
            let blockstm_account = blockstm.get(&address);
            match (normal_account, blockstm_account) {
                (Some((normal_info, normal_storage)), Some((blockstm_info, blockstm_storage))) => {
                    if normal_info != blockstm_info {
                        let _ = writeln!(
                            out,
                            "account {address}: normal={normal_info:?} blockstm={blockstm_info:?}"
                        );
                        diffs += 1;
                    }

                    let mut slots = BTreeSet::new();
                    slots.extend(normal_storage.keys().copied());
                    slots.extend(blockstm_storage.keys().copied());
                    for slot in slots {
                        let normal_value = normal_storage.get(&slot).copied().unwrap_or_default();
                        let blockstm_value =
                            blockstm_storage.get(&slot).copied().unwrap_or_default();
                        if normal_value != blockstm_value {
                            let _ = writeln!(
                                out,
                                "storage {address} {slot}: normal={normal_value:#x} blockstm={blockstm_value:#x}"
                            );
                            diffs += 1;
                        }
                        if diffs >= 12 {
                            return out;
                        }
                    }
                }
                (Some(_), None) => {
                    let _ = writeln!(out, "account {address}: present in normal only");
                    diffs += 1;
                }
                (None, Some(_)) => {
                    let _ = writeln!(out, "account {address}: present in blockstm only");
                    diffs += 1;
                }
                (None, None) => {}
            }

            if diffs >= 12 {
                return out;
            }
        }

        out
    }

    fn describe_hashed_post_state_diff(
        left_label: &str,
        left: &HashedPostState,
        right_label: &str,
        right: &HashedPostState,
    ) -> String {
        let mut out = String::new();
        let mut addresses = BTreeSet::new();
        addresses.extend(left.accounts.keys().copied());
        addresses.extend(right.accounts.keys().copied());
        addresses.extend(left.storages.keys().copied());
        addresses.extend(right.storages.keys().copied());

        let mut diffs = 0usize;
        for address in addresses {
            let left_account = left.accounts.get(&address);
            let right_account = right.accounts.get(&address);
            if left_account != right_account {
                let _ = writeln!(
                    out,
                    "account {address}: {left_label}={left_account:?} {right_label}={right_account:?}"
                );
                diffs += 1;
            }

            let left_storage = left.storages.get(&address);
            let right_storage = right.storages.get(&address);
            match (left_storage, right_storage) {
                (Some(left_storage), Some(right_storage)) => {
                    if left_storage.wiped != right_storage.wiped {
                        let _ = writeln!(
                            out,
                            "storage {address}: {left_label}.wiped={} {right_label}.wiped={}",
                            left_storage.wiped, right_storage.wiped
                        );
                        diffs += 1;
                    }

                    let mut slots = BTreeSet::new();
                    slots.extend(left_storage.storage.keys().copied());
                    slots.extend(right_storage.storage.keys().copied());
                    for slot in slots {
                        let left_value = left_storage.storage.get(&slot).copied();
                        let right_value = right_storage.storage.get(&slot).copied();
                        if left_value != right_value {
                            let _ = writeln!(
                                out,
                                "storage {address} {slot}: {left_label}={left_value:?} {right_label}={right_value:?}"
                            );
                            diffs += 1;
                        }
                        if diffs >= 12 {
                            return out;
                        }
                    }
                }
                (Some(_), None) => {
                    let _ = writeln!(out, "storage {address}: present in {left_label} only");
                    diffs += 1;
                }
                (None, Some(_)) => {
                    let _ = writeln!(out, "storage {address}: present in {right_label} only");
                    diffs += 1;
                }
                (None, None) => {}
            }

            if diffs >= 12 {
                return out;
            }
        }

        out
    }

    #[derive(Debug)]
    struct TestTip20BlockstmExecution {
        txs: Vec<Tip20BlockstmTxExecution>,
        actual_fees: Vec<U256>,
    }

    fn execute_test_blockstm(
        txs: &[Tip20TransferBlockstmTx<'_>],
        plans: &[Tip20TransferBlockstmPlan],
        base_storage: HashMap<StorageKey, U256>,
    ) -> TestTip20BlockstmExecution {
        let mut base_state = test_base_state(base_storage);
        let cfg = t6_test_cfg();
        let mut executions = Vec::with_capacity(plans.len());
        let mut actual_fees = Vec::with_capacity(plans.len());

        for (tx, plan) in txs.iter().zip(plans) {
            let mut execution =
                execute_tip20_transfer_plan_with_deltas(plan, &base_state, true, 1).unwrap();
            let gas = synthetic_tip20_result_gas(&tx.tx_env, plan, &execution, &base_state, &cfg)
                .unwrap();
            let actual_fee = synthetic_actual_fee(&tx.tx_env, &gas, 1, true);
            settle_actual_fee_with_deltas(plan, &mut execution, &base_state, actual_fee, true)
                .unwrap();

            for (key, _, written) in execution.written_storage() {
                base_state.storage.insert(key, written);
            }

            executions.push(execution);
            actual_fees.push(actual_fee);
        }

        TestTip20BlockstmExecution {
            txs: executions,
            actual_fees,
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
        let action = decode_tip20_transfer_action(&tx, TOKEN).unwrap();
        assert_eq!(action.token, TOKEN);
    }

    #[test]
    fn aa_batch_with_multiple_direct_transfers_falls_back() {
        let recipient_a = address!("10000000000000000000000000000000000000a1");
        let recipient_b = address!("10000000000000000000000000000000000000b1");
        let (recovered, tx_env) = expiring_blockstm_tx_with_gas(
            vec![
                transfer_call(recipient_a, U256::from(1)),
                transfer_with_memo_call(recipient_b, U256::from(2), B256::repeat_byte(0x42)),
            ],
            20,
            100_000,
        );

        let tx = Tip20TransferBlockstmTx {
            tx_env,
            recovered: &recovered,
            fee_token: TOKEN,
        };
        assert_eq!(
            decode_tip20_transfer_action(&tx, TOKEN),
            Err(Tip20TransferBlockstmFallback::UnsupportedSelector)
        );
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
            decode_tip20_transfer_action(&tx, TOKEN),
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
            decode_tip20_transfer_action(&tx, TOKEN),
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
            decode_tip20_transfer_action(&tx, TOKEN),
            Err(Tip20TransferBlockstmFallback::AccessList)
        );
    }

    #[test]
    fn expiring_nonce_writes_seen_ring_and_pointer() {
        let recipient = address!("10000000000000000000000000000000000000e1");
        let beneficiary = address!("10000000000000000000000000000000000000e2");
        let valid_before = 30;
        let (recovered, tx_env) = expiring_blockstm_tx_with_gas(
            vec![transfer_call(recipient, U256::from(1))],
            valid_before,
            350_000,
        );

        let tx = Tip20TransferBlockstmTx {
            tx_env,
            recovered: &recovered,
            fee_token: TOKEN,
        };
        let plan =
            build_tip20_transfer_blockstm_plan(&tx, TOKEN, beneficiary, 1, 0, TempoHardfork::T6)
                .unwrap();
        let Tip20ExpiringNonceAction {
            replay_hash,
            valid_before: planned_valid_before,
            ..
        } = plan.nonce;
        assert_eq!(planned_valid_before, valid_before);

        let execution = execute_test_blockstm(
            &[tx],
            &[plan],
            HashMap::from([(
                balance_key(TOKEN, SENDER),
                encode_balance(U256::from(1_000_000), REWARD_FLAG_OPTED_OUT, true),
            )]),
        );

        assert_eq!(
            execution.txs[0]
                .written_value(expiring_nonce_seen_key(replay_hash))
                .unwrap(),
            U256::from(valid_before)
        );
        assert_eq!(
            execution.txs[0]
                .written_value(expiring_nonce_ring_key(0))
                .unwrap(),
            expiring_nonce_hash_to_word(replay_hash)
        );
        assert_eq!(
            execution.txs[0]
                .written_value(expiring_nonce_ring_ptr_key())
                .unwrap(),
            U256::from(1)
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
            decode_tip20_transfer_action(&tx, Address::random()),
            Err(Tip20TransferBlockstmFallback::FeeTokenMismatch)
        );
    }

    #[test]
    fn unsupported_direct_recipient_falls_back() {
        assert!(matches!(
            validate_direct_recipient(Address::ZERO),
            Err(Tip20TransferBlockstmExecutionError::Fallback(
                Tip20TransferBlockstmFallback::InvalidRecipient
            ))
        ));
        assert!(matches!(
            validate_direct_recipient(TOKEN),
            Err(Tip20TransferBlockstmExecutionError::Fallback(
                Tip20TransferBlockstmFallback::InvalidRecipient
            ))
        ));

        let virtual_recipient = Address::new_virtual(
            MasterId::from([1, 2, 3, 4]),
            UserTag::from([5, 6, 7, 8, 9, 10]),
        );
        assert!(matches!(
            validate_direct_recipient(virtual_recipient),
            Err(Tip20TransferBlockstmExecutionError::Fallback(
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
        let (recovered, tx_env) = expiring_blockstm_tx_with_gas(
            vec![transfer_call(recipient, U256::from(7))],
            30,
            42_000,
        );

        let tx = Tip20TransferBlockstmTx {
            tx_env,
            recovered: &recovered,
            fee_token: TOKEN,
        };
        let plan =
            build_tip20_transfer_blockstm_plan(&tx, TOKEN, beneficiary, 1, 0, TempoHardfork::T6)
                .unwrap();

        assert_eq!(plan.fee_reserve.token, TOKEN);
        assert_eq!(plan.fee_reserve.fee_payer, SENDER);
        assert_eq!(plan.fee_reserve.amount, plan.fee_settle.max_amount);
        assert_eq!(plan.transfer.token, TOKEN);
        assert_eq!(plan.transfer.from, SENDER);
        assert_eq!(plan.transfer.to, recipient);
        assert_eq!(plan.transfer.amount, U256::from(7));
        assert_eq!(plan.transfer.memo, None);
        assert_eq!(plan.fee_settle.token, TOKEN);
        assert_eq!(plan.fee_settle.fee_payer, SENDER);
        assert_eq!(plan.fee_settle.beneficiary, beneficiary);

        assert!(
            plan.read_set()
                .any(|key| key == receive_policy_key(recipient))
        );
        assert!(
            plan.read_set()
                .any(|key| key == collected_fees_key(beneficiary, TOKEN))
        );
        assert!(plan.read_set().any(|key| key
            == StorageKey {
                address: TOKEN,
                slot: tip20_slots::TRANSFER_POLICY_ID,
            }));

        assert!(
            plan.write_set()
                .any(|key| key == balance_key(TOKEN, SENDER))
        );
        assert!(
            plan.write_set()
                .any(|key| key == balance_key(TOKEN, recipient))
        );
        assert!(
            plan.write_set()
                .any(|key| key == balance_key(TOKEN, TIP_FEE_MANAGER_ADDRESS))
        );
        assert!(
            plan.write_set()
                .any(|key| key == collected_fees_key(beneficiary, TOKEN))
        );
    }

    #[test]
    fn synthetic_actual_fee_uses_post_refund_gas_before_floor() {
        let (_, tx_env) = blockstm_tx_with_fee(Vec::new(), 1_000, 1_000_000_000_000);
        let gas = ResultGas::new_with_state_gas(90, 0, 100, 20);

        assert_eq!(gas.tx_gas_used(), 100);
        assert_eq!(gas.spent_sub_refunded(), 90);

        let actual_fee = synthetic_actual_fee(&tx_env, &gas, 0, false);

        assert_eq!(
            actual_fee,
            calc_gas_balance_spending(gas.spent_sub_refunded(), 1_000_000_000_000)
        );
        assert_ne!(
            actual_fee,
            calc_gas_balance_spending(gas.tx_gas_used(), 1_000_000_000_000)
        );
    }

    #[test]
    fn speculative_execution_applies_transfers_and_same_token_fee_overlays() {
        let recipient = address!("10000000000000000000000000000000000000c1");
        let beneficiary = address!("10000000000000000000000000000000000000d1");
        let transfer_amount = U256::from(7);
        let (recovered, tx_env) = expiring_blockstm_tx_with_gas(
            vec![transfer_call(recipient, transfer_amount)],
            30,
            350_000,
        );
        let tx = Tip20TransferBlockstmTx {
            tx_env,
            recovered: &recovered,
            fee_token: TOKEN,
        };
        let plan =
            build_tip20_transfer_blockstm_plan(&tx, TOKEN, beneficiary, 1, 0, TempoHardfork::T6)
                .unwrap();
        let sender_balance = U256::from(1_000_000);
        let recipient_balance = U256::from(5);
        let collected_fees = U256::from(3);
        let base_storage = HashMap::from([
            (
                balance_key(TOKEN, SENDER),
                encode_balance(sender_balance, REWARD_FLAG_OPTED_OUT, true),
            ),
            (
                balance_key(TOKEN, recipient),
                encode_balance(recipient_balance, REWARD_FLAG_OPTED_OUT, true),
            ),
            (collected_fees_key(beneficiary, TOKEN), collected_fees),
        ]);

        let execution = execute_test_blockstm(&[tx], &[plan], base_storage);
        let actual_fee = execution.actual_fees[0];
        assert_eq!(
            execution.txs[0]
                .written_value(balance_key(TOKEN, SENDER))
                .unwrap(),
            encode_balance(
                sender_balance - transfer_amount - actual_fee,
                REWARD_FLAG_OPTED_OUT,
                true
            )
        );
        assert_eq!(
            execution.txs[0]
                .written_value(balance_key(TOKEN, recipient))
                .unwrap(),
            encode_balance(
                recipient_balance + transfer_amount,
                REWARD_FLAG_OPTED_OUT,
                true
            )
        );
        assert_eq!(
            execution.txs[0]
                .written_value(balance_key(TOKEN, TIP_FEE_MANAGER_ADDRESS))
                .unwrap(),
            encode_balance(actual_fee, REWARD_FLAG_UNINITIALIZED, true)
        );
        assert_eq!(
            execution.txs[0]
                .written_value(collected_fees_key(beneficiary, TOKEN))
                .unwrap(),
            collected_fees + actual_fee
        );
    }

    #[test]
    fn speculative_execution_self_transfer_has_no_net_transfer_delta() {
        let beneficiary = address!("10000000000000000000000000000000000000d2");
        let transfer_amount = U256::from(7);
        let (recovered, tx_env) = expiring_blockstm_tx_with_gas(
            vec![transfer_call(SENDER, transfer_amount)],
            30,
            350_000,
        );
        let tx = Tip20TransferBlockstmTx {
            tx_env,
            recovered: &recovered,
            fee_token: TOKEN,
        };
        let plan =
            build_tip20_transfer_blockstm_plan(&tx, TOKEN, beneficiary, 1, 0, TempoHardfork::T6)
                .unwrap();
        let sender_balance = U256::from(1_000_000);
        let base_storage = HashMap::from([(
            balance_key(TOKEN, SENDER),
            encode_balance(sender_balance, REWARD_FLAG_OPTED_OUT, true),
        )]);

        let execution = execute_test_blockstm(&[tx], &[plan], base_storage);
        let actual_fee = execution.actual_fees[0];

        assert_eq!(
            execution.txs[0]
                .written_value(balance_key(TOKEN, SENDER))
                .unwrap(),
            encode_balance(sender_balance - actual_fee, REWARD_FLAG_OPTED_OUT, true)
        );
        assert_eq!(
            execution.txs[0]
                .written_value(balance_key(TOKEN, TIP_FEE_MANAGER_ADDRESS))
                .unwrap(),
            encode_balance(actual_fee, REWARD_FLAG_UNINITIALIZED, true)
        );
    }

    #[test]
    fn delta_execution_refunds_max_fee_to_actual_validator_fee() {
        let recipient = address!("10000000000000000000000000000000000000c2");
        let beneficiary = address!("10000000000000000000000000000000000000d3");
        let transfer_amount = U256::from(7);
        let (recovered, tx_env) = expiring_blockstm_tx_with_gas(
            vec![transfer_call(recipient, transfer_amount)],
            30,
            350_000,
        );
        let tx = Tip20TransferBlockstmTx {
            tx_env,
            recovered: &recovered,
            fee_token: TOKEN,
        };
        let plan =
            build_tip20_transfer_blockstm_plan(&tx, TOKEN, beneficiary, 1, 0, TempoHardfork::T6)
                .unwrap();
        let sender_balance = U256::from(1_000_000);
        let recipient_balance = U256::from(5);
        let collected_fees = U256::from(3);
        let base_storage = HashMap::from([
            (
                balance_key(TOKEN, SENDER),
                encode_balance(sender_balance, REWARD_FLAG_OPTED_OUT, true),
            ),
            (
                balance_key(TOKEN, recipient),
                encode_balance(recipient_balance, REWARD_FLAG_OPTED_OUT, true),
            ),
            (collected_fees_key(beneficiary, TOKEN), collected_fees),
        ]);

        let execution = execute_test_blockstm(&[tx], &[plan], base_storage);
        let actual_fee = execution.actual_fees[0];
        assert!(actual_fee < U256::from(700_000));
        assert_eq!(
            execution.txs[0]
                .written_value(balance_key(TOKEN, SENDER))
                .unwrap(),
            encode_balance(
                sender_balance - transfer_amount - actual_fee,
                REWARD_FLAG_OPTED_OUT,
                true
            )
        );
        assert_eq!(
            execution.txs[0]
                .written_value(balance_key(TOKEN, TIP_FEE_MANAGER_ADDRESS))
                .unwrap(),
            encode_balance(actual_fee, REWARD_FLAG_UNINITIALIZED, true)
        );
        assert_eq!(
            execution.txs[0]
                .written_value(collected_fees_key(beneficiary, TOKEN))
                .unwrap(),
            collected_fees + actual_fee
        );
    }

    #[test]
    fn delta_execution_handles_conflicting_transfers() {
        let recipient_a = address!("10000000000000000000000000000000000000a1");
        let recipient_b = address!("10000000000000000000000000000000000000b1");
        let beneficiary = address!("10000000000000000000000000000000000000d2");

        let (recovered_a, tx_env_a) = expiring_blockstm_tx_with_gas(
            vec![transfer_call(recipient_a, U256::from(10))],
            30,
            350_000,
        );
        let tx_a = Tip20TransferBlockstmTx {
            tx_env: tx_env_a,
            recovered: &recovered_a,
            fee_token: TOKEN,
        };
        let plan_a =
            build_tip20_transfer_blockstm_plan(&tx_a, TOKEN, beneficiary, 1, 0, TempoHardfork::T6)
                .unwrap();
        let (recovered_b, tx_env_b) = expiring_blockstm_tx_with_gas(
            vec![transfer_call(recipient_b, U256::from(20))],
            30,
            350_000,
        );
        let tx_b = Tip20TransferBlockstmTx {
            tx_env: tx_env_b,
            recovered: &recovered_b,
            fee_token: TOKEN,
        };
        let plan_b =
            build_tip20_transfer_blockstm_plan(&tx_b, TOKEN, beneficiary, 1, 0, TempoHardfork::T6)
                .unwrap();
        let sender_balance = U256::from(1_000_000);
        let base_storage = HashMap::from([
            (
                balance_key(TOKEN, SENDER),
                encode_balance(sender_balance, REWARD_FLAG_OPTED_OUT, true),
            ),
            (
                balance_key(TOKEN, recipient_a),
                encode_balance(U256::from(100), REWARD_FLAG_OPTED_OUT, true),
            ),
            (
                balance_key(TOKEN, recipient_b),
                encode_balance(U256::from(100), REWARD_FLAG_OPTED_OUT, true),
            ),
        ]);

        let execution = execute_test_blockstm(&[tx_a, tx_b], &[plan_a, plan_b], base_storage);
        let total_fee = execution.actual_fees[0] + execution.actual_fees[1];
        assert_eq!(
            execution.txs[1]
                .written_value(balance_key(TOKEN, SENDER))
                .unwrap(),
            encode_balance(
                sender_balance - U256::from(30) - total_fee,
                REWARD_FLAG_OPTED_OUT,
                true
            )
        );
        assert_eq!(
            execution.txs[1]
                .written_value(balance_key(TOKEN, recipient_b))
                .unwrap(),
            encode_balance(U256::from(120), REWARD_FLAG_OPTED_OUT, true)
        );
        assert_eq!(
            execution.txs[1]
                .written_value(balance_key(TOKEN, TIP_FEE_MANAGER_ADDRESS))
                .unwrap(),
            encode_balance(total_fee, REWARD_FLAG_UNINITIALIZED, true)
        );
    }

    #[test]
    fn blockstm_txgen_expiring_nonce_state_matches_payload_reexecution() {
        let chainspec = test_chainspec();
        let token = tempo_precompiles::PATH_USD_ADDRESS;
        let account_count = 10usize;
        let tx_count = 50usize;
        let block_timestamp = 1_700_000_000u64;
        let valid_before = block_timestamp + 10;
        let participant_balance = U256::from(1_000_000_000_000_000_000u128);
        let signers = txgen_signers(account_count);
        let participants = signers
            .iter()
            .map(PrivateKeySigner::address)
            .collect::<Vec<_>>();

        let mut txs = Vec::with_capacity(tx_count);
        for idx in 0..tx_count {
            let signer = &signers[idx % signers.len()];
            let recipient = participants[(idx.wrapping_mul(17) + 1) % participants.len()];
            txs.push(signed_expiring_tip20_transfer(
                signer,
                recipient,
                U256::from(idx as u64 + 1),
                valid_before,
                300_000,
                100_000_000_000,
            ));
        }

        let build_db = || {
            path_usd_state_with_balances_and_reward_flag(
                participants
                    .iter()
                    .copied()
                    .map(|participant| (participant, participant_balance)),
                REWARD_FLAG_OPTED_OUT,
            )
        };
        let build_hooked_executor = |mut db: State<EmptyDB>| {
            let updates = Arc::new(Mutex::new(Vec::<EvmState>::new()));
            let captured = updates.clone();
            db.set_state_hook(Some(Box::new(move |state: &EvmState| {
                captured.lock().unwrap().push(state.clone());
            })));
            let mut executor = TestExecutorBuilder::default()
                .with_general_gas_limit(10_000_000_000)
                .with_parent_beacon_block_root(B256::ZERO)
                .with_spec(TempoHardfork::T6)
                .build(db, &chainspec);
            executor.evm_mut().ctx_mut().block.timestamp = U256::from(block_timestamp);
            executor.evm_mut().ctx_mut().block.basefee = 1;
            executor
                .apply_pre_execution_changes()
                .expect("pre-execution changes");
            executor.evm_mut().db_mut().bump_bal_index();
            (executor, updates)
        };

        let prestate_db = build_db();
        let prestate = db_to_trie_state(&prestate_db);

        let (mut blockstm_executor, blockstm_updates) = build_hooked_executor(build_db());
        let beneficiary = blockstm_executor.evm().block().beneficiary;
        for (idx, (recovered, tx_env)) in txs.iter().enumerate() {
            let tx = Tip20TransferBlockstmTx {
                tx_env: tx_env.clone(),
                recovered,
                fee_token: token,
            };
            let plan = build_tip20_transfer_blockstm_plan(
                &tx,
                token,
                beneficiary,
                1,
                0,
                TempoHardfork::T6,
            )
            .unwrap();
            assert!(
                blockstm_executor
                    .execute_tip20_transfer_blockstm_planned_tx(tx, plan, idx, |_| true)
                    .unwrap()
            );
            blockstm_executor.evm_mut().db_mut().bump_bal_index();
        }
        assert_eq!(blockstm_executor.receipts().len(), tx_count);

        let blockstm_updates = blockstm_updates.lock().unwrap().clone();
        let mut blockstm_poststate = prestate.clone();
        apply_evm_state_updates_to_trie_state(&mut blockstm_poststate, &blockstm_updates);

        let (mut validation_executor, validation_updates) = build_hooked_executor(build_db());
        for (expiring_nonce_idx, (recovered, tx_env)) in txs.iter().enumerate() {
            let mut indexed_tx_env = tx_env.clone();
            indexed_tx_env
                .tempo_tx_env
                .as_mut()
                .expect("tempo tx env")
                .expiring_nonce_idx = Some(expiring_nonce_idx);

            validation_executor
                .execute_transaction((indexed_tx_env, recovered))
                .expect("payload re-execution transaction");
            validation_executor.evm_mut().db_mut().bump_bal_index();
        }

        let validation_updates = validation_updates.lock().unwrap().clone();
        let mut validation_poststate = prestate.clone();
        apply_evm_state_updates_to_trie_state(&mut validation_poststate, &validation_updates);
        assert_eq!(
            blockstm_poststate,
            validation_poststate,
            "STM post-state differs from payload re-execution post-state:\n{}",
            describe_trie_state_diff(&validation_poststate, &blockstm_poststate)
        );
    }

    #[test]
    fn blockstm_state_changes_match_payload_reexecution() {
        let chainspec = test_chainspec();
        let token = tempo_precompiles::PATH_USD_ADDRESS;
        let account_count = 10usize;
        let tx_count = 4_433usize;
        let block_timestamp = 1_700_000_000u64;
        let valid_before = block_timestamp + 10;
        let participant_balance = U256::from(1_000_000_000_000_000_000u128);
        let signers = txgen_signers(account_count);
        let participants = signers
            .iter()
            .map(PrivateKeySigner::address)
            .collect::<Vec<_>>();

        let mut txs = Vec::with_capacity(tx_count);
        for idx in 0..tx_count {
            let signer = &signers[idx % signers.len()];
            let recipient = participants[(idx.wrapping_mul(17) + 1) % participants.len()];
            txs.push(signed_expiring_tip20_transfer(
                signer,
                recipient,
                U256::from(idx as u64 + 1),
                valid_before,
                300_000,
                100_000_000_000,
            ));
        }

        let build_db = || {
            let parent_db = path_usd_parent_db_with_balances_and_reward_flag(
                participants
                    .iter()
                    .copied()
                    .map(|participant| (participant, participant_balance)),
                REWARD_FLAG_OPTED_OUT,
            );
            State::builder()
                .with_database(parent_db)
                .with_bundle_update()
                .build()
        };
        let build_hooked_executor = |mut db: State<CacheDB<EmptyDB>>| {
            let updates = Arc::new(Mutex::new(Vec::<EvmState>::new()));
            let captured = updates.clone();
            db.set_state_hook(Some(Box::new(move |state: &EvmState| {
                captured.lock().unwrap().push(state.clone());
            })));
            let mut executor = TestExecutorBuilder::default()
                .with_general_gas_limit(10_000_000_000)
                .with_parent_beacon_block_root(B256::ZERO)
                .with_spec(TempoHardfork::T6)
                .build(db, &chainspec);
            executor.evm_mut().ctx_mut().block.gas_limit = 10_000_000_000;
            executor.evm_mut().ctx_mut().block.timestamp = U256::from(block_timestamp);
            executor.evm_mut().ctx_mut().block.basefee = 1;
            executor
                .apply_pre_execution_changes()
                .expect("pre-execution changes");
            executor.evm_mut().db_mut().bump_bal_index();
            (executor, updates)
        };

        let (mut blockstm_executor, blockstm_updates) = build_hooked_executor(build_db());
        let beneficiary = blockstm_executor.evm().block().beneficiary;
        for (idx, (recovered, tx_env)) in txs.iter().enumerate() {
            let tx = Tip20TransferBlockstmTx {
                tx_env: tx_env.clone(),
                recovered,
                fee_token: token,
            };
            let plan = build_tip20_transfer_blockstm_plan(
                &tx,
                token,
                beneficiary,
                1,
                0,
                TempoHardfork::T6,
            )
            .unwrap();
            assert!(
                blockstm_executor
                    .execute_tip20_transfer_blockstm_planned_tx(tx, plan, idx, |_| true)
                    .unwrap()
            );
            blockstm_executor.evm_mut().db_mut().bump_bal_index();
        }
        assert_eq!(blockstm_executor.receipts().len(), tx_count);

        let mut blockstm_hashed_state = HashedPostState::default();
        for update in blockstm_updates.lock().unwrap().clone() {
            blockstm_hashed_state.extend(evm_state_to_hashed_post_state(update));
        }

        let (mut validation_executor, validation_updates) = build_hooked_executor(build_db());
        for (expiring_nonce_idx, (recovered, tx_env)) in txs.iter().enumerate() {
            let mut indexed_tx_env = tx_env.clone();
            indexed_tx_env
                .tempo_tx_env
                .as_mut()
                .expect("tempo tx env")
                .expiring_nonce_idx = Some(expiring_nonce_idx);

            validation_executor
                .execute_transaction((indexed_tx_env, recovered))
                .expect("payload re-execution transaction");
            validation_executor.evm_mut().db_mut().bump_bal_index();
        }
        assert_eq!(validation_executor.receipts().len(), tx_count);

        let mut validation_hashed_state = HashedPostState::default();
        for update in validation_updates.lock().unwrap().clone() {
            validation_hashed_state.extend(evm_state_to_hashed_post_state(update));
        }

        if blockstm_hashed_state != validation_hashed_state {
            panic!(
                "STM state-hook hashed post-state differs from payload re-execution state-hook hashed post-state:\n{}",
                describe_hashed_post_state_diff(
                    "blockstm",
                    &blockstm_hashed_state,
                    "validation",
                    &validation_hashed_state,
                )
            );
        }

        let (mut blockstm_evm, _result) = blockstm_executor.finish().expect("finish STM block");
        blockstm_evm
            .db_mut()
            .merge_transitions(BundleRetention::Reverts);
        let blockstm_bundle_hashed_state = HashedPostState::from_bundle_state::<KeccakKeyHasher>(
            &blockstm_evm.db().bundle_state.state,
        );

        let (mut validation_evm, _result) = validation_executor
            .finish()
            .expect("finish payload re-execution block");
        validation_evm
            .db_mut()
            .merge_transitions(BundleRetention::Reverts);
        let validation_bundle_hashed_state = HashedPostState::from_bundle_state::<KeccakKeyHasher>(
            &validation_evm.db().bundle_state.state,
        );

        if blockstm_bundle_hashed_state != validation_bundle_hashed_state {
            panic!(
                "STM bundle hashed post-state differs from payload re-execution bundle hashed post-state:\n{}",
                describe_hashed_post_state_diff(
                    "blockstm",
                    &blockstm_bundle_hashed_state,
                    "validation",
                    &validation_bundle_hashed_state,
                )
            );
        }
    }

    #[test]
    fn planned_tx_can_be_rejected_before_commit() {
        let chainspec = test_chainspec();
        let signer = txgen_signers(1).pop().unwrap();
        let recipient = address!("10000000000000000000000000000000000000c1");
        let sender_balance = U256::from(1_000_000_000);
        let db = path_usd_state_with_balances_and_reward_flag(
            [(signer.address(), sender_balance), (recipient, U256::ZERO)],
            REWARD_FLAG_OPTED_OUT,
        );
        let mut executor = TestExecutorBuilder::default()
            .with_general_gas_limit(10_000_000_000)
            .with_parent_beacon_block_root(B256::ZERO)
            .with_spec(TempoHardfork::T6)
            .build(db, &chainspec);
        executor.evm_mut().ctx_mut().block.timestamp = U256::from(1);
        executor.evm_mut().ctx_mut().block.basefee = 1;
        executor
            .apply_pre_execution_changes()
            .expect("pre-execution changes");
        executor.evm_mut().db_mut().bump_bal_index();

        let (recovered, tx_env) =
            signed_expiring_tip20_transfer(&signer, recipient, U256::from(1), 30, 350_000, 1);
        let tx = Tip20TransferBlockstmTx {
            tx_env,
            recovered: &recovered,
            fee_token: tempo_precompiles::PATH_USD_ADDRESS,
        };
        let beneficiary = executor.evm().block().beneficiary;
        let plan = build_tip20_transfer_blockstm_plan(
            &tx,
            tempo_precompiles::PATH_USD_ADDRESS,
            beneficiary,
            1,
            0,
            TempoHardfork::T6,
        )
        .unwrap();

        let committed = executor
            .execute_tip20_transfer_blockstm_planned_tx(tx, plan, 0, |result| {
                assert!(result.block_gas_used() > 0);
                false
            })
            .unwrap();

        assert!(!committed);
        assert!(executor.receipts().is_empty());
        assert_eq!(
            executor
                .read_storage(
                    tempo_precompiles::PATH_USD_ADDRESS,
                    balance_slot(signer.address())
                )
                .unwrap(),
            encode_balance(sender_balance, REWARD_FLAG_OPTED_OUT, true)
        );
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
