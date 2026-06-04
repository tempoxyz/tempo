use std::collections::hash_map::Entry;

use crate::{TempoBlockExecutor, TempoTxResult};
use alloy_evm::{
    Evm, RecoveredTx,
    block::{BlockExecutionError, BlockExecutor},
};
use alloy_primitives::{Address, TxKind, U256, map::HashMap};
use alloy_sol_types::SolInterface;
use reth_evm::block::StateDB;
use reth_primitives_traits::Recovered;
use reth_revm::{
    Inspector,
    context::{Transaction as _, result::ExecutionResult},
    state::{Account, AccountInfo, EvmState, EvmStorageSlot, TransactionId},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::ITIP20;
use tempo_precompiles::{
    storage::evm::EvmAction,
    tip20::{RewardFlag, UserState},
};
use tempo_primitives::{TempoAddressExt, TempoTxEnvelope, transaction::TEMPO_EXPIRING_NONCE_KEY};
use tempo_revm::{TempoHaltReason, TempoTxEnv, evm::TempoContext};

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

/// Precomputed TIP-20 transfer result plus semantic precompile storage actions.
#[derive(Debug)]
pub struct Tip20TransferActionReplay {
    pub result: ExecutionResult<TempoHaltReason>,
    pub actions: Vec<EvmAction>,
    pub validator_fee: U256,
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
    InvalidNonce,
    MissingExpiringNonceValidBefore,
    InsufficientBalance,
    BalanceOverflow,
    EmptyCalls,
    ContractCreation,
    NonTip20Target,
    TransferFrom,
    UnsupportedSelector,
    InvalidCalldata,
    InvalidRecipient,
    VirtualRecipient,
    RewardActive,
    ActionExecutionFailed,
    MissingActions,
    ActionConflict,
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
            Self::InvalidNonce => "invalid_nonce",
            Self::MissingExpiringNonceValidBefore => "missing_expiring_nonce_valid_before",
            Self::InsufficientBalance => "insufficient_balance",
            Self::BalanceOverflow => "balance_overflow",
            Self::EmptyCalls => "empty_calls",
            Self::ContractCreation => "contract_creation",
            Self::NonTip20Target => "non_tip20_target",
            Self::TransferFrom => "transfer_from",
            Self::UnsupportedSelector => "unsupported_selector",
            Self::InvalidCalldata => "invalid_calldata",
            Self::InvalidRecipient => "invalid_recipient",
            Self::VirtualRecipient => "virtual_recipient",
            Self::RewardActive => "reward_active",
            Self::ActionExecutionFailed => "action_execution_failed",
            Self::MissingActions => "missing_actions",
            Self::ActionConflict => "action_conflict",
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

#[derive(Debug, Default)]
pub struct Tip20ActionReplayState {
    writes: HashMap<StorageKey, WriteKind>,
}

impl Tip20ActionReplayState {
    fn has_write(&self, key: StorageKey) -> bool {
        self.writes.contains_key(&key)
    }

    fn has_store(&self, key: StorageKey) -> bool {
        self.writes
            .get(&key)
            .is_some_and(|kind| *kind == WriteKind::Store)
    }

    fn commit(&mut self, writes: impl IntoIterator<Item = (StorageKey, WriteKind)>) {
        for (key, kind) in writes {
            merge_write_kind(&mut self.writes, key, kind);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteKind {
    Store,
    Delta,
}

struct AppliedActionReplay {
    state: EvmState,
    writes: Vec<(StorageKey, WriteKind)>,
}

impl<'a, DB, I> TempoBlockExecutor<'a, DB, I>
where
    DB: StateDB,
    I: Inspector<TempoContext<DB>>,
{
    /// Commits one precomputed TIP-20 transfer by replaying recorded precompile storage actions.
    ///
    /// `should_commit` observes the result before state mutation. Returning `false` leaves
    /// executor state unchanged, allowing the payload builder to stop at the exact block gas
    /// boundary.
    pub fn execute_tip20_transfer_action_replay_tx<'tx>(
        &mut self,
        tx: Tip20TransferBlockstmTx<'tx>,
        replay: Tip20TransferActionReplay,
        replay_state: &mut Tip20ActionReplayState,
        transaction_index: usize,
        should_commit: impl FnOnce(&TempoTxResult) -> bool,
    ) -> Result<bool, Tip20TransferBlockstmExecutionError> {
        if !replay.result.is_success() {
            return Err(Tip20TransferBlockstmExecutionError::Fallback(
                Tip20TransferBlockstmFallback::ActionExecutionFailed,
            ));
        }

        let cfg = self.inner.evm.cfg_env().clone();
        let gas = replay.result.gas();
        let block_gas_used = if cfg.enable_amsterdam_eip8037 {
            gas.block_regular_gas_used()
        } else {
            gas.tx_gas_used()
        };
        let next_section = self
            .validate_tx(tx.recovered.tx(), block_gas_used)
            .map_err(|error| Tip20TransferBlockstmExecutionError::Execution {
                transaction_index,
                error: error.into(),
            })?;
        let applied = action_replay_state(
            self.inner.evm.db_mut(),
            &replay.actions,
            replay_state,
            cfg.spec,
        )?;
        let result = TempoTxResult::new_precomputed(
            tx.recovered.tx(),
            replay.result,
            applied.state,
            next_section,
            self.is_payment(tx.recovered.tx()),
            block_gas_used,
            replay.validator_fee,
        );
        if !should_commit(&result) {
            return Ok(false);
        }

        self.commit_transaction(result);
        replay_state.commit(applied.writes);
        Ok(true)
    }
}

pub fn validate_tip20_transfer_blockstm_tx(
    tx: &Tip20TransferBlockstmTx<'_>,
    validator_token: Address,
    spec: TempoHardfork,
) -> Result<(), Tip20TransferBlockstmFallback> {
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

    let Some(aa_env) = tx.tx_env.tempo_tx_env.as_ref() else {
        return Err(Tip20TransferBlockstmFallback::InvalidNonce);
    };
    if !aa_env.tempo_authorization_list.is_empty() {
        return Err(Tip20TransferBlockstmFallback::TempoAuthorization);
    }
    if aa_env.key_authorization.is_some() {
        return Err(Tip20TransferBlockstmFallback::KeyAuthorization);
    }
    if aa_env.nonce_key != TEMPO_EXPIRING_NONCE_KEY || !spec.is_t1() || tx.tx_env.nonce() != 0 {
        return Err(Tip20TransferBlockstmFallback::InvalidNonce);
    }
    if aa_env.valid_before.is_none() {
        return Err(Tip20TransferBlockstmFallback::MissingExpiringNonceValidBefore);
    }
    if tx
        .recovered
        .tx()
        .as_aa()
        .is_some_and(|aa| aa.signature().as_keychain().is_some())
    {
        return Err(Tip20TransferBlockstmFallback::KeychainSignature);
    }
    tx.tx_env
        .fee_payer()
        .map_err(|_| Tip20TransferBlockstmFallback::InvalidFeePayer)?;

    let mut calls = tx.tx_env.calls();
    let Some((kind, input)) = calls.next() else {
        return Err(Tip20TransferBlockstmFallback::EmptyCalls);
    };
    validate_tip20_transfer_call(*kind, input)?;
    if calls.next().is_some() {
        return Err(Tip20TransferBlockstmFallback::UnsupportedSelector);
    }

    Ok(())
}

fn validate_tip20_transfer_call(
    kind: TxKind,
    input: &[u8],
) -> Result<(), Tip20TransferBlockstmFallback> {
    let TxKind::Call(token) = kind else {
        return Err(Tip20TransferBlockstmFallback::ContractCreation);
    };
    if !token.is_tip20() {
        return Err(Tip20TransferBlockstmFallback::NonTip20Target);
    }

    match ITIP20::ITIP20Calls::abi_decode(input)
        .map_err(|_| Tip20TransferBlockstmFallback::InvalidCalldata)?
    {
        ITIP20::ITIP20Calls::transfer(call) => validate_direct_recipient(call.to),
        ITIP20::ITIP20Calls::transferWithMemo(call) => validate_direct_recipient(call.to),
        ITIP20::ITIP20Calls::transferFrom(_) | ITIP20::ITIP20Calls::transferFromWithMemo(_) => {
            Err(Tip20TransferBlockstmFallback::TransferFrom)
        }
        _ => Err(Tip20TransferBlockstmFallback::UnsupportedSelector),
    }
}

fn validate_direct_recipient(to: Address) -> Result<(), Tip20TransferBlockstmFallback> {
    if to.is_zero() || to.is_tip20() {
        return Err(Tip20TransferBlockstmFallback::InvalidRecipient);
    }
    if to.is_virtual() {
        return Err(Tip20TransferBlockstmFallback::VirtualRecipient);
    }

    Ok(())
}

fn action_replay_state<DB: StateDB>(
    db: &mut DB,
    actions: &[EvmAction],
    replay_state: &Tip20ActionReplayState,
    spec: TempoHardfork,
) -> Result<AppliedActionReplay, Tip20TransferBlockstmExecutionError> {
    if actions.is_empty() {
        return Err(Tip20TransferBlockstmExecutionError::Fallback(
            Tip20TransferBlockstmFallback::MissingActions,
        ));
    }

    let mut originals = HashMap::<StorageKey, U256>::default();
    let mut writes = HashMap::<StorageKey, U256>::default();
    let mut write_kinds = HashMap::<StorageKey, WriteKind>::default();

    for action in actions {
        match *action {
            EvmAction::Sload(address, slot) => {
                let key = StorageKey { address, slot };
                if replay_state.has_store(key) {
                    return Err(action_conflict());
                }
                let _ = action_current_value(db, &writes, &mut originals, key)?;
            }
            EvmAction::Sstore(address, slot, value) => {
                let key = StorageKey { address, slot };
                if replay_state.has_write(key) {
                    return Err(action_conflict());
                }
                action_write_value(
                    db,
                    &mut writes,
                    &mut originals,
                    &mut write_kinds,
                    key,
                    value,
                    WriteKind::Store,
                )?;
            }
            EvmAction::Sinc(address, slot, delta) => {
                let key = StorageKey { address, slot };
                if replay_state.has_store(key) {
                    return Err(action_conflict());
                }
                let value = action_current_value(db, &writes, &mut originals, key)?
                    .checked_add(delta)
                    .ok_or_else(balance_overflow)?;
                action_write_value(
                    db,
                    &mut writes,
                    &mut originals,
                    &mut write_kinds,
                    key,
                    value,
                    WriteKind::Delta,
                )?;
            }
            EvmAction::Tip20BalanceSinc(address, slot, delta, flag) => {
                let key = StorageKey { address, slot };
                if replay_state.has_store(key) {
                    return Err(action_conflict());
                }
                let value = action_tip20_balance_value(
                    action_current_value(db, &writes, &mut originals, key)?,
                    spec,
                    delta,
                    flag,
                    true,
                )?;
                action_write_value(
                    db,
                    &mut writes,
                    &mut originals,
                    &mut write_kinds,
                    key,
                    value,
                    WriteKind::Delta,
                )?;
            }
            EvmAction::Tip20BalanceSdec(address, slot, delta, flag) => {
                let key = StorageKey { address, slot };
                if replay_state.has_store(key) {
                    return Err(action_conflict());
                }
                let value = action_tip20_balance_value(
                    action_current_value(db, &writes, &mut originals, key)?,
                    spec,
                    delta,
                    flag,
                    false,
                )?;
                action_write_value(
                    db,
                    &mut writes,
                    &mut originals,
                    &mut write_kinds,
                    key,
                    value,
                    WriteKind::Delta,
                )?;
            }
        }
    }

    let mut state = EvmState::default();
    for (key, value) in writes {
        if let Entry::Vacant(e) = state.entry(key.address) {
            let mut account = Account::from(action_account_info(db, key.address)?);
            account.mark_touch();
            e.insert(account);
        }
        let account = state
            .get_mut(&key.address)
            .expect("action replay account inserted");
        let original = originals.get(&key).copied().unwrap_or_default();
        account.storage.insert(
            key.slot,
            EvmStorageSlot::new_changed(original, value, TransactionId::ZERO),
        );
    }

    Ok(AppliedActionReplay {
        state,
        writes: write_kinds.into_iter().collect(),
    })
}

fn action_current_value<DB: StateDB>(
    db: &mut DB,
    writes: &HashMap<StorageKey, U256>,
    originals: &mut HashMap<StorageKey, U256>,
    key: StorageKey,
) -> Result<U256, Tip20TransferBlockstmExecutionError> {
    if let Some(value) = writes.get(&key) {
        return Ok(*value);
    }
    if let Some(value) = originals.get(&key) {
        return Ok(*value);
    }

    let value = db
        .storage(key.address, key.slot)
        .map_err(BlockExecutionError::other)
        .map_err(Tip20TransferBlockstmExecutionError::Database)?;
    originals.insert(key, value);
    Ok(value)
}

fn action_write_value<DB: StateDB>(
    db: &mut DB,
    writes: &mut HashMap<StorageKey, U256>,
    originals: &mut HashMap<StorageKey, U256>,
    write_kinds: &mut HashMap<StorageKey, WriteKind>,
    key: StorageKey,
    value: U256,
    kind: WriteKind,
) -> Result<(), Tip20TransferBlockstmExecutionError> {
    if !originals.contains_key(&key) {
        let _ = action_current_value(db, writes, originals, key)?;
    }
    writes.insert(key, value);
    merge_write_kind(write_kinds, key, kind);
    Ok(())
}

fn action_tip20_balance_value(
    current: U256,
    spec: TempoHardfork,
    delta: U256,
    flag: RewardFlag,
    increment: bool,
) -> Result<U256, Tip20TransferBlockstmExecutionError> {
    let state = UserState::decode_storage_word(current, spec).map_err(|_| {
        Tip20TransferBlockstmExecutionError::Fallback(Tip20TransferBlockstmFallback::RewardActive)
    })?;
    let state = if increment {
        state
            .incremented(delta, flag)
            .map_err(|_| balance_overflow())?
    } else {
        state
            .decremented(delta, flag)
            .map_err(|_| insufficient_balance())?
    };
    state.encode_storage_word(spec).map_err(|_| {
        Tip20TransferBlockstmExecutionError::Fallback(Tip20TransferBlockstmFallback::RewardActive)
    })
}

fn merge_write_kind(writes: &mut HashMap<StorageKey, WriteKind>, key: StorageKey, kind: WriteKind) {
    writes
        .entry(key)
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
) -> Result<AccountInfo, Tip20TransferBlockstmExecutionError> {
    db.basic(address)
        .map_err(BlockExecutionError::other)
        .map_err(Tip20TransferBlockstmExecutionError::Database)
        .map(|account| account.unwrap_or_default())
}

fn action_conflict() -> Tip20TransferBlockstmExecutionError {
    Tip20TransferBlockstmExecutionError::Fallback(Tip20TransferBlockstmFallback::ActionConflict)
}

fn balance_overflow() -> Tip20TransferBlockstmExecutionError {
    Tip20TransferBlockstmExecutionError::Fallback(Tip20TransferBlockstmFallback::BalanceOverflow)
}

fn insufficient_balance() -> Tip20TransferBlockstmExecutionError {
    Tip20TransferBlockstmExecutionError::Fallback(
        Tip20TransferBlockstmFallback::InsufficientBalance,
    )
}
