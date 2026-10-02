//! Conservative reuse of transaction call bodies across changed fee state.
//!
//! Validation, pre-execution and settlement still run in order. A body is reusable
//! only if its database reads and all journal values it could observe are unchanged.
//! Unobserved pre-execution storage is carried forward from the fresh journal. This
//! does not make fee operations commute or bypass their overflow/liquidity checks.

use alloy_evm::Database;
use alloy_primitives::{Address, B256, U256};
use revm::{
    context::{JournalEntry, JournalInner},
    context_interface::cfg::gas::InitialAndFloorGas,
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
            aa.expiring_nonce_hash?
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

/// Bounded hints for fee storage, the expiring nonce pointer and the first native
/// TIP-20 transfer. The scheduler separately prefetches [`nonce_hint`].
/// These do not resolve token preferences, virtual recipients or reward delegates:
/// conditional accesses still use the database, and only actual reads become dependencies.
pub fn prefetch_keys(
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
    let mut keys = vec![
        ReadKey::Account(TIP_FEE_MANAGER_ADDRESS),
        ReadKey::Storage(
            TIP_FEE_MANAGER_ADDRESS,
            payer.mapping_slot(fee_slots::USER_TOKENS),
        ),
    ];
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
            ReadKey::Storage(token, token_slots::GLOBAL_REWARD_PER_TOKEN),
        ]);
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
            let rewards = holder.mapping_slot(token_slots::USER_REWARD_INFO);
            keys.extend(
                (0..UserRewardInfo::SLOTS).map(|offset| {
                    ReadKey::Storage(token, rewards.wrapping_add(U256::from(offset)))
                }),
            );
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
    gas: InitialAndFloorGas,
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
        gas: InitialAndFloorGas,
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
        gas: &InitialAndFloorGas,
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
            if old.info != new.info
                || old.original_info != new.original_info
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
