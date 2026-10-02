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
        mut self,
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
        let mut entries = fresh.journal.clone();
        entries.extend(self.after.journal.drain(self.before.journal.len()..));
        self.after.journal = entries;
        let mut logs = fresh.logs.clone();
        logs.extend(self.after.logs.drain(self.before.logs.len()..));
        self.after.logs = logs;

        for (address, old) in &self.before.state {
            let new = &fresh.state[address];
            let after = self.after.state.get_mut(address)?;
            // Replace all unobserved prefix slots, including those loaded only
            // by one of the two pre-executions (e.g. an expiring-nonce ring index).
            for key in old.storage.keys() {
                if !self.accesses.slots.contains(&(*address, *key)) {
                    after.storage.remove(key);
                }
            }
            for (key, slot) in &new.storage {
                if !self.accesses.slots.contains(&(*address, *key)) {
                    after.storage.insert(*key, slot.clone());
                }
            }
        }
        journal.inner = self.after;
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
