//! Conservative reuse of transaction call bodies across changed fee state.
//!
//! Validation, pre-execution and settlement still run in order. A body is reusable
//! only if its database reads and all journal values it could observe are unchanged.
//! Unobserved pre-execution storage is carried forward from the fresh journal. This
//! does not make fee operations commute or bypass their overflow/liquidity checks.

use alloy_evm::Database;
use alloy_primitives::{
    Address, B256, U256,
    map::{HashMap, HashSet},
};
use revm::{
    context::{JournalEntry, JournalInner},
    context_interface::cfg::gas::GasTracker,
    handler::FrameResult,
    state::{AccountInfo, Bytecode},
};
use tempo_precompiles::storage::access::StorageAccesses;
pub use tempo_precompiles::storage::access::{
    is_recording as is_recording_body, record_database_time,
};

/// A database value observed during speculative execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReadKey {
    /// Account existence, balance, nonce and code metadata.
    Account(Address),
    /// Persistent storage.
    Storage(Address, U256),
    /// Bytecode loaded by hash.
    Code(B256),
    /// A historical block hash.
    BlockHash(u64),
}

/// The exact value corresponding to a [`ReadKey`].
#[derive(Clone, Debug, Eq)]
pub enum ReadValue {
    /// Account metadata, including absence.
    Account(Option<AccountInfo>),
    /// A storage word.
    Storage(U256),
    /// Contract code.
    Code(Bytecode),
    /// A historical block hash.
    BlockHash(B256),
}

impl PartialEq for ReadValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Account(Some(left)), Self::Account(Some(right))) => {
                account_info_matches(left, right)
            }
            (Self::Account(None), Self::Account(None)) => true,
            (Self::Storage(left), Self::Storage(right)) => left == right,
            (Self::Code(left), Self::Code(right)) => bytecode_matches(left, right),
            (Self::BlockHash(left), Self::BlockHash(right)) => left == right,
            _ => false,
        }
    }
}

/// Compare both code bytes and their execution kind. Bytecode's ordinary
/// equality omits the distinction between legacy code and EIP-7702 delegation.
pub fn bytecode_matches(left: &Bytecode, right: &Bytecode) -> bool {
    // bytecode() borrows a field of the immutable shared BytecodeInner. Identity
    // of that field proves that the complete representation is shared too.
    std::ptr::eq(left.bytecode(), right.bytecode())
        || (left.kind() == right.kind() && left == right)
}

/// Compare balance, nonce, code hash and the supplied inline code representation.
/// Different inline-code availability conservatively requires ordinary execution.
/// Even absent versus empty code changes returned metadata/state hooks and can
/// affect later code loading after public database mutations.
pub fn account_info_matches(left: &AccountInfo, right: &AccountInfo) -> bool {
    left == right
        && match (&left.code, &right.code) {
            (Some(left), Some(right)) => bytecode_matches(left, right),
            (None, None) => true,
            _ => false,
        }
}

/// Read from the current committed prefix without modifying its journal.
pub fn read<DB: Database>(db: &mut DB, key: ReadKey) -> Result<ReadValue, DB::Error> {
    match key {
        ReadKey::Account(address) => db.basic(address).map(ReadValue::Account),
        ReadKey::Storage(address, slot) => db.storage(address, slot).map(ReadValue::Storage),
        ReadKey::Code(hash) => db.code_by_hash(hash).map(ReadValue::Code),
        ReadKey::BlockHash(number) => db.block_hash(number).map(ReadValue::BlockHash),
    }
}

/// A native AA nonce read and an upper bound for useful speculation at the current
/// prefix. A larger stored uint64 suggests leaving the candidate to the ordinary
/// executor. This is only a scheduling hint: state and configuration may change,
/// and validation must still run in order for candidates omitted from speculation.
pub fn nonce_hint(
    tx: &crate::TempoTxEnv,
    spec: tempo_chainspec::hardfork::TempoHardfork,
    timestamp: u64,
) -> Option<(ReadKey, u64)> {
    use tempo_precompiles::{NONCE_PRECOMPILE_ADDRESS, nonce::slots, storage::StorageKey};
    use tempo_primitives::transaction::TEMPO_EXPIRING_NONCE_KEY;

    let aa = tx.tempo_tx_env.as_ref()?;
    if aa.nonce_key.is_zero() {
        return None;
    }
    let (slot, bound) = if aa.nonce_key == TEMPO_EXPIRING_NONCE_KEY && spec.is_t1() {
        let hash = if spec.is_t1b() {
            tx.unique_tx_identifier()?
        } else {
            aa.tx_hash
        };
        (hash.mapping_slot(slots::EXPIRING_NONCE_SEEN), timestamp)
    } else {
        (
            aa.nonce_key
                .mapping_slot(tx.inner.caller.mapping_slot(slots::NONCES)),
            tx.inner.nonce,
        )
    };
    Some((ReadKey::Storage(NONCE_PRECOMPILE_ADDRESS, slot), bound))
}

/// A per-window plan for fee storage, the expiring nonce pointer and the first
/// native TIP-20 transfer. Repeated payers, tokens and holders need their mapping
/// slots constructed only once. This caches keys, never values across windows.
///
/// Preferences, virtual recipients and reward delegates still use conditional
/// database reads. Only actual execution reads become validation dependencies.
#[derive(Debug, Default)]
pub struct PrefetchPlan {
    initialized: bool,
    nonce_account: bool,
    nonce_ring: bool,
    payers: HashSet<Address>,
    beneficiaries: HashSet<Address>,
    tokens: HashMap<Address, TokenHints>,
    collectors: HashSet<(Address, Address)>,
    holders: HashMap<(Address, Address), bool>,
}

#[derive(Debug, Default)]
struct TokenHints {
    account: bool,
    transfer: bool,
    fee: bool,
    rewards: bool,
}

impl PrefetchPlan {
    /// Visits newly needed keys. The scheduler separately prefetches [`nonce_hint`].
    pub fn visit(
        &mut self,
        tx: &crate::TempoTxEnv,
        beneficiary: Address,
        spec: tempo_chainspec::hardfork::TempoHardfork,
        mut emit: impl FnMut(ReadKey),
    ) {
        use alloy_sol_types::SolCall;
        use tempo_precompiles::{
            NONCE_PRECOMPILE_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
            nonce::slots as nonce_slots,
            storage::StorageKey,
            tip_fee_manager::slots as fee_slots,
            tip20::{ITIP20, slots as token_slots},
        };
        use tempo_primitives::{TempoAddressExt, transaction::TEMPO_EXPIRING_NONCE_KEY};

        if !self.initialized {
            emit(ReadKey::Account(TIP_FEE_MANAGER_ADDRESS));
            self.initialized = true;
        }
        let payer = tx.fee_payer().unwrap_or(tx.inner.caller);
        // Explicit fee tokens bypass the saved payer preference. Do not mark the
        // payer as fetched here: a later candidate may omit its explicit token.
        if tx.fee_token.is_none() && self.payers.insert(payer) {
            emit(ReadKey::Storage(
                TIP_FEE_MANAGER_ADDRESS,
                payer.mapping_slot(fee_slots::USER_TOKENS),
            ));
        }
        if let Some(aa) = &tx.tempo_tx_env
            && !aa.nonce_key.is_zero()
        {
            if !self.nonce_account {
                emit(ReadKey::Account(NONCE_PRECOMPILE_ADDRESS));
                self.nonce_account = true;
            }
            if aa.nonce_key == TEMPO_EXPIRING_NONCE_KEY && spec.is_t1() && !self.nonce_ring {
                emit(ReadKey::Storage(
                    NONCE_PRECOMPILE_ADDRESS,
                    nonce_slots::EXPIRING_NONCE_RING_PTR,
                ));
                self.nonce_ring = true;
            }
        }
        let pays_fees = tx.inner.gas_price != 0;
        if pays_fees && self.beneficiaries.insert(beneficiary) {
            emit(ReadKey::Storage(
                TIP_FEE_MANAGER_ADDRESS,
                beneficiary.mapping_slot(fee_slots::VALIDATOR_TOKENS),
            ));
        }
        let call = tx.calls().next();
        let called_token = call
            .as_ref()
            .and_then(|(kind, _)| kind.to().copied())
            .filter(|token| token.is_tip20());
        let recipient = called_token.and_then(|_| {
            ITIP20::transferCall::abi_decode(call.as_ref()?.1)
                .ok()
                .map(|call| call.to)
        });
        let tokens = [
            Some(tempo_contracts::precompiles::DEFAULT_FEE_TOKEN),
            tx.fee_token,
            called_token,
        ];
        for (index, token) in tokens.iter().enumerate() {
            let Some(token) = *token else { continue };
            if tokens[..index].contains(&Some(token)) {
                continue;
            }
            let recipient = recipient.filter(|_| called_token == Some(token));
            let flags = self.tokens.entry(token).or_default();
            if !flags.account {
                emit(ReadKey::Account(token));
                flags.account = true;
            }
            if (pays_fees || recipient.is_some()) && !flags.transfer {
                for slot in [token_slots::PAUSED, token_slots::TRANSFER_POLICY_ID] {
                    emit(ReadKey::Storage(token, slot));
                }
                flags.transfer = true;
            }
            // T8 disables automatic reward settlement on transfers and fees.
            // Avoid fetching three unused reward-info slots for every holder.
            let rewards = !spec.is_t8();
            if rewards && (pays_fees || recipient.is_some()) && !flags.rewards {
                emit(ReadKey::Storage(
                    token,
                    token_slots::GLOBAL_REWARD_PER_TOKEN,
                ));
                flags.rewards = true;
            }
            if pays_fees && !flags.fee {
                emit(ReadKey::Storage(
                    token,
                    TIP_FEE_MANAGER_ADDRESS.mapping_slot(token_slots::BALANCES),
                ));
                emit(ReadKey::Storage(token, token_slots::CURRENCY));
                flags.fee = true;
            }
            if pays_fees && self.collectors.insert((token, beneficiary)) {
                emit(ReadKey::Storage(
                    TIP_FEE_MANAGER_ADDRESS,
                    token.mapping_slot(beneficiary.mapping_slot(fee_slots::COLLECTED_FEES)),
                ));
            }
            self.holder(
                token,
                payer,
                rewards
                    && (pays_fees
                        || recipient.is_some_and(|to| payer == tx.inner.caller || payer == to)),
                &mut emit,
            );
            if let Some(recipient) = recipient {
                if tx.inner.caller != payer {
                    self.holder(token, tx.inner.caller, rewards, &mut emit);
                }
                if recipient != payer && recipient != tx.inner.caller {
                    self.holder(token, recipient, rewards, &mut emit);
                }
            }
        }
    }

    fn holder(
        &mut self,
        token: Address,
        holder: Address,
        rewards: bool,
        emit: &mut impl FnMut(ReadKey),
    ) {
        use std::collections::hash_map::Entry;
        use tempo_precompiles::{
            storage::{StorableType, StorageKey},
            tip20::{rewards::UserRewardInfo, slots},
        };
        let new_rewards = match self.holders.entry((token, holder)) {
            Entry::Vacant(entry) => {
                emit(ReadKey::Storage(
                    token,
                    holder.mapping_slot(slots::BALANCES),
                ));
                entry.insert(rewards);
                rewards
            }
            Entry::Occupied(mut entry) => {
                let new_rewards = rewards && !*entry.get();
                *entry.get_mut() |= rewards;
                new_rewards
            }
        };
        if new_rewards {
            let base = holder.mapping_slot(slots::USER_REWARD_INFO);
            for offset in 0..UserRewardInfo::SLOTS {
                emit(ReadKey::Storage(
                    token,
                    base.wrapping_add(U256::from(offset)),
                ));
            }
        }
    }
}

// Original per-transaction planner, retained as an independent coverage oracle.
#[cfg(test)]
fn reference_prefetch_keys(
    tx: &crate::TempoTxEnv,
    beneficiary: Address,
    spec: tempo_chainspec::hardfork::TempoHardfork,
) -> Vec<ReadKey> {
    use alloy_sol_types::SolCall;
    use tempo_precompiles::{
        NONCE_PRECOMPILE_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
        nonce::slots as nonce_slots,
        storage::{StorableType, StorageKey},
        tip_fee_manager::slots as fee_slots,
        tip20::{ITIP20, rewards::UserRewardInfo, slots as token_slots},
    };
    use tempo_primitives::{TempoAddressExt, transaction::TEMPO_EXPIRING_NONCE_KEY};

    let payer = tx.fee_payer().unwrap_or(tx.inner.caller);
    let mut keys = vec![ReadKey::Account(TIP_FEE_MANAGER_ADDRESS)];
    if tx.fee_token.is_none() {
        keys.push(ReadKey::Storage(
            TIP_FEE_MANAGER_ADDRESS,
            payer.mapping_slot(fee_slots::USER_TOKENS),
        ));
    }
    if let Some(aa) = &tx.tempo_tx_env
        && !aa.nonce_key.is_zero()
    {
        keys.push(ReadKey::Account(NONCE_PRECOMPILE_ADDRESS));
        if aa.nonce_key == TEMPO_EXPIRING_NONCE_KEY && spec.is_t1() {
            keys.push(ReadKey::Storage(
                NONCE_PRECOMPILE_ADDRESS,
                nonce_slots::EXPIRING_NONCE_RING_PTR,
            ));
        }
    }
    let pays_fees = tx.inner.gas_price != 0;
    if pays_fees {
        keys.push(ReadKey::Storage(
            TIP_FEE_MANAGER_ADDRESS,
            beneficiary.mapping_slot(fee_slots::VALIDATOR_TOKENS),
        ));
    }
    let call = tx.calls().next();
    let called_token = call
        .as_ref()
        .and_then(|(kind, _)| kind.to().copied())
        .filter(|token| token.is_tip20());
    let recipient = called_token.and_then(|_| {
        ITIP20::transferCall::abi_decode(call.as_ref()?.1)
            .ok()
            .map(|call| call.to)
    });
    let mut tokens = vec![tempo_contracts::precompiles::DEFAULT_FEE_TOKEN];
    tokens.extend(tx.fee_token);
    tokens.extend(called_token);
    tokens.sort_unstable();
    tokens.dedup();
    for token in tokens {
        keys.extend([
            ReadKey::Account(token),
            ReadKey::Storage(token, payer.mapping_slot(token_slots::BALANCES)),
        ]);
        let recipient = recipient.filter(|_| called_token == Some(token));
        if !pays_fees && recipient.is_none() {
            continue;
        }
        keys.extend([
            ReadKey::Storage(token, token_slots::PAUSED),
            ReadKey::Storage(token, token_slots::TRANSFER_POLICY_ID),
        ]);
        if !spec.is_t8() {
            keys.push(ReadKey::Storage(
                token,
                token_slots::GLOBAL_REWARD_PER_TOKEN,
            ));
        }
        if pays_fees {
            keys.extend([
                ReadKey::Storage(
                    token,
                    TIP_FEE_MANAGER_ADDRESS.mapping_slot(token_slots::BALANCES),
                ),
                ReadKey::Storage(token, token_slots::CURRENCY),
                ReadKey::Storage(
                    TIP_FEE_MANAGER_ADDRESS,
                    token.mapping_slot(beneficiary.mapping_slot(fee_slots::COLLECTED_FEES)),
                ),
            ]);
        }
        let mut holders = Vec::with_capacity(3);
        if pays_fees {
            holders.push(payer);
        }
        if let Some(recipient) = recipient {
            holders.extend([tx.inner.caller, recipient]);
        }
        holders.sort_unstable();
        holders.dedup();
        for holder in holders {
            keys.push(ReadKey::Storage(
                token,
                holder.mapping_slot(token_slots::BALANCES),
            ));
            if !spec.is_t8() {
                let rewards = holder.mapping_slot(token_slots::USER_REWARD_INFO);
                keys.extend((0..UserRewardInfo::SLOTS).map(|offset| {
                    ReadKey::Storage(token, rewards.wrapping_add(U256::from(offset)))
                }));
            }
        }
    }
    keys
}

/// The call-body boundary recorded on a worker. Inspectors and custom instruction
/// tables must not use this cache, since their callbacks cannot be replayed.
#[derive(Debug)]
pub struct BodyCache {
    before: JournalInner<JournalEntry>,
    after: JournalInner<JournalEntry>,
    gas: GasTracker,
    after_gas: GasTracker,
    accesses: StorageAccesses,
    result: FrameResult,
    reads: Option<Vec<(ReadKey, ReadValue)>>,
    before_error_context: Option<String>,
    after_error_context: Option<String>,
}

impl BodyCache {
    pub(crate) fn capture(
        before: JournalInner<JournalEntry>,
        after: JournalInner<JournalEntry>,
        (gas, after_gas): (GasTracker, GasTracker),
        accesses: StorageAccesses,
        result: FrameResult,
        before_error_context: Option<String>,
        after_error_context: Option<String>,
    ) -> Option<Self> {
        if accesses.unsupported
            || before.depth != after.depth
            || !after.journal.starts_with(&before.journal)
            || !after.logs.starts_with(&before.logs)
            || before
                .state
                .keys()
                .any(|address| !after.state.contains_key(address))
            || after
                .state
                .values()
                .any(|account| account.is_created() || account.is_selfdestructed())
        {
            return None;
        }
        Some(Self {
            before,
            after,
            gas,
            after_gas,
            accesses,
            result,
            reads: None,
            before_error_context,
            after_error_context,
        })
    }

    /// Attach database reads collected inside the same call-body scope.
    pub fn set_database_reads(&mut self, reads: Vec<(ReadKey, ReadValue)>) {
        self.reads = Some(reads);
    }

    pub(crate) fn try_apply<DB: Database>(
        self,
        context: &mut crate::evm::TempoContext<DB>,
        gas: &mut GasTracker,
    ) -> Option<FrameResult> {
        let journal = &mut context.journaled_state;
        let fresh = &journal.inner;
        if self.gas != *gas
            || self.before_error_context != context.local.precompile_error_message
            || self.before.cfg != fresh.cfg
            || self.before.transaction_id != fresh.transaction_id
            || self.before.depth != fresh.depth
            || self.before.warm_addresses != fresh.warm_addresses
            || self.before.transient_storage != fresh.transient_storage
            || self.before.selfdestructed_addresses != fresh.selfdestructed_addresses
            || self.before.state.len() != fresh.state.len()
        {
            return None;
        }

        // Account metadata can be read without hitting the database (BALANCE,
        // CALL, EXTCODE*, native precompiles, etc.). Compare it conservatively for
        // every preloaded account; only storage gets per-slot relaxation.
        for (address, old) in &self.before.state {
            let new = fresh.state.get(address)?;
            if !account_info_matches(&old.info, &new.info)
                || !account_info_matches(&old.original_info(), &new.original_info())
                || old.status != new.status
                || old.transaction_id != new.transaction_id
            {
                return None;
            }
        }
        for (address, key) in &self.accesses.slots {
            let old = self
                .before
                .state
                .get(address)
                .and_then(|a| a.storage.get(key));
            let new = fresh.state.get(address).and_then(|a| a.storage.get(key));
            // Exact comparison includes original values and cold/warm status:
            // both affect gas, even if the present values happen to match.
            if old != new {
                return None;
            }
        }
        for (key, expected) in self.reads.as_ref()? {
            if read(&mut journal.database, *key).ok().as_ref() != Some(expected) {
                return None;
            }
        }

        // All checks precede mutations. Keep the fresh fee/nonces journal prefix
        // so post-execution and error unwinding see its exact writes and logs.
        let JournalInner {
            state,
            transient_storage,
            logs,
            depth,
            journal: entries,
            transaction_id,
            cfg,
            warm_addresses,
            selfdestructed_addresses,
        } = self.after;
        let fresh = &mut journal.inner;
        fresh
            .journal
            .extend(entries.into_iter().skip(self.before.journal.len()));
        fresh
            .logs
            .extend(logs.into_iter().skip(self.before.logs.len()));
        for (address, mut account) in state {
            if let Some(old) = self.before.state.get(&address) {
                let current = fresh
                    .state
                    .get_mut(&address)
                    .expect("validated prefix account");
                // Keep the freshly executed fee/nonce slots in place. Only slots
                // observed by the body need their recorded final value/warmness.
                let mut storage = std::mem::take(&mut current.storage);
                if !self.accesses.slots.is_empty() {
                    for key in old.storage.keys() {
                        if self.accesses.slots.contains(&(address, *key))
                            && !account.storage.contains_key(key)
                        {
                            storage.remove(key);
                        }
                    }
                    for (key, slot) in account.storage {
                        if self.accesses.slots.contains(&(address, key)) {
                            storage.insert(key, slot);
                        }
                    }
                }
                account.storage = storage;
                *current = account;
            } else {
                fresh.state.insert(address, account);
            }
        }
        fresh.transient_storage = transient_storage;
        fresh.depth = depth;
        fresh.transaction_id = transaction_id;
        fresh.cfg = cfg;
        fresh.warm_addresses = warm_addresses;
        fresh.selfdestructed_addresses = selfdestructed_addresses;
        context.local.precompile_error_message = self.after_error_context;
        *gas = self.after_gas;
        Some(self.result)
    }
}

#[derive(Debug, Default)]
pub(crate) struct BodyReplay {
    pub recording: bool,
    pub minimum_duration: std::time::Duration,
    pub captured: Option<BodyCache>,
    pub candidate: Option<BodyCache>,
    pub reused: bool,
}

#[cfg(test)]
mod prefetch_tests {
    use super::*;
    use alloy_evm::FromRecoveredTx;
    use alloy_primitives::{Bytes, TxKind, address};
    use alloy_sol_types::SolCall;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_precompiles::{PATH_USD_ADDRESS, tip20::ITIP20};
    use tempo_primitives::{TempoSignature, TempoTransaction, transaction::Call};

    #[test]
    fn grouped_hints_preserve_each_prefix_of_the_original_plan() {
        let tokens = [
            PATH_USD_ADDRESS,
            address!("20c0000000000000000000000000000000000001"),
        ];
        let txs = (0..96)
            .map(|i| {
                let sender = Address::repeat_byte((i % 4 + 1) as u8);
                let recipient = Address::repeat_byte((i % 5 + 1) as u8);
                let signed = TempoTransaction {
                    chain_id: 1,
                    gas_limit: 1_000_000,
                    max_fee_per_gas: (i % 3 == 1).into(),
                    nonce_key: [U256::ZERO, U256::from(13), U256::MAX][i % 3],
                    calls: vec![Call {
                        to: if i % 7 == 0 {
                            TxKind::Create
                        } else {
                            tokens[i % 2].into()
                        },
                        value: U256::ZERO,
                        input: if i % 5 == 0 {
                            Bytes::from_static(&[1, 2, 3])
                        } else {
                            ITIP20::transferCall {
                                to: recipient,
                                amount: U256::from(17),
                            }
                            .abi_encode()
                            .into()
                        },
                    }],
                    ..Default::default()
                }
                .into_signed(TempoSignature::default());
                let mut tx = crate::TempoTxEnv::from_recovered_tx(&signed, sender);
                tx.fee_token = (i % 4 != 0).then_some(tokens[(i / 2) % 2]);
                tx.fee_payer = Some(Some(Address::repeat_byte((i / 3 % 5 + 1) as u8)));
                if i % 11 == 0 {
                    tx.tempo_tx_env = None;
                }
                tx
            })
            .collect::<Vec<_>>();
        for reverse in [false, true] {
            let mut plan = PrefetchPlan::default();
            let mut expected = HashSet::<ReadKey>::default();
            let mut actual = HashSet::<ReadKey>::default();
            let mut reference_count = 0;
            let mut planned_count = 0;
            for step in 0..txs.len() * 2 {
                let index = if reverse {
                    txs.len() - 1 - step % txs.len()
                } else {
                    step % txs.len()
                };
                let tx = &txs[index];
                let beneficiary = Address::repeat_byte((step % 3 + 10) as u8);
                let spec = [
                    TempoHardfork::T0,
                    TempoHardfork::T1,
                    TempoHardfork::T1B,
                    TempoHardfork::T4,
                    TempoHardfork::T7,
                    TempoHardfork::T8,
                    TempoHardfork::T13,
                    TempoHardfork::T14,
                ][step % 8];
                let original = reference_prefetch_keys(tx, beneficiary, spec);
                reference_count += original.len();
                expected.extend(original);
                plan.visit(tx, beneficiary, spec, |key| {
                    actual.insert(key);
                    planned_count += 1;
                });
                assert_eq!(actual, expected, "step={step} reverse={reverse}");
            }
            assert!(
                planned_count * 4 < reference_count,
                "{planned_count} vs {reference_count}"
            );
        }
    }
}
