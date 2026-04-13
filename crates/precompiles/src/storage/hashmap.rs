use alloy::primitives::{Address, LogData, U256};
use revm::{
    context::journaled_state::JournalCheckpoint,
    state::{AccountInfo, Bytecode},
};
use std::collections::HashMap;
use tempo_chainspec::hardfork::TempoHardfork;

use crate::{error::TempoPrecompileError, storage::PrecompileStorageProvider};

/// In-memory [`PrecompileStorageProvider`] for unit tests.
///
/// Stores all state in `HashMap`s, avoiding the need for a real EVM context.
pub struct HashMapStorageProvider {
    internals: HashMap<(Address, U256), U256>,
    transient: HashMap<(Address, U256), U256>,
    accounts: HashMap<Address, AccountInfo>,
    chain_id: u64,
    timestamp: U256,
    beneficiary: Address,
    block_number: u64,
    spec: TempoHardfork,
    is_static: bool,
    counter_sload: u64,
    snapshots: Vec<Snapshot>,

    /// Emitted events keyed by contract address.
    pub events: HashMap<Address, Vec<LogData>>,
}

/// Snapshot of mutable state for checkpoint/revert support.
///
/// PERF: naive cloning strategy due to its limited usage.
struct Snapshot {
    internals: HashMap<(Address, U256), U256>,
    events: HashMap<Address, Vec<LogData>>,
}

impl HashMapStorageProvider {
    /// Creates a new provider with the given chain ID and default hardfork.
    pub fn new(chain_id: u64) -> Self {
        Self::new_with_spec(chain_id, TempoHardfork::default())
    }

    /// Creates a new provider with the given chain ID and hardfork spec.
    pub fn new_with_spec(chain_id: u64, spec: TempoHardfork) -> Self {
        Self {
            internals: HashMap::new(),
            transient: HashMap::new(),
            accounts: HashMap::new(),
            events: HashMap::new(),
            snapshots: Vec::new(),
            chain_id,
            #[expect(clippy::disallowed_methods)]
            timestamp: U256::from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            ),
            beneficiary: Address::ZERO,
            block_number: 0,
            spec,
            is_static: false,
            counter_sload: 0,
        }
    }

    /// Returns self with the hardfork spec overridden (builder pattern).
    pub fn with_spec(mut self, spec: TempoHardfork) -> Self {
        self.spec = spec;
        self
    }
}

impl PrecompileStorageProvider for HashMapStorageProvider {
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
        let account = self.accounts.entry(address).or_default();
        account.code_hash = code.hash_slow();
        account.code = Some(code);
        Ok(())
    }

    fn with_account_info(
        &mut self,
        address: Address,
        f: &mut dyn FnMut(&AccountInfo),
    ) -> Result<(), TempoPrecompileError> {
        let account = self.accounts.entry(address).or_default();
        f(&*account);
        Ok(())
    }

    fn sstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
    ) -> Result<(), TempoPrecompileError> {
        self.internals.insert((address, key), value);
        Ok(())
    }

    fn tstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
    ) -> Result<(), TempoPrecompileError> {
        self.transient.insert((address, key), value);
        Ok(())
    }

    fn emit_event(&mut self, address: Address, event: LogData) -> Result<(), TempoPrecompileError> {
        self.events.entry(address).or_default().push(event);
        Ok(())
    }

    fn sload(&mut self, address: Address, key: U256) -> Result<U256, TempoPrecompileError> {
        self.counter_sload += 1;
        Ok(self
            .internals
            .get(&(address, key))
            .copied()
            .unwrap_or(U256::ZERO))
    }

    fn tload(&mut self, address: Address, key: U256) -> Result<U256, TempoPrecompileError> {
        Ok(self
            .transient
            .get(&(address, key))
            .copied()
            .unwrap_or(U256::ZERO))
    }

    fn deduct_gas(&mut self, _gas: u64) -> Result<(), TempoPrecompileError> {
        Ok(())
    }

    fn refund_gas(&mut self, _gas: i64) {
        // No-op
    }

    fn gas_used(&self) -> u64 {
        0
    }

    fn gas_refunded(&self) -> i64 {
        0
    }

    fn spec(&self) -> TempoHardfork {
        self.spec
    }

    fn is_static(&self) -> bool {
        self.is_static
    }

    fn checkpoint(&mut self) -> JournalCheckpoint {
        let idx = self.snapshots.len();
        self.snapshots.push(Snapshot {
            internals: self.internals.clone(),
            events: self.events.clone(),
        });
        JournalCheckpoint {
            log_i: 0,
            journal_i: idx,
            selfdestructed_i: 0,
        }
    }

    fn checkpoint_commit(&mut self, checkpoint: JournalCheckpoint) {
        assert_eq!(
            checkpoint.journal_i,
            self.snapshots.len() - 1,
            "out-of-order checkpoint commit (expected top of stack)"
        );
        self.snapshots.pop();
    }

    fn checkpoint_revert(&mut self, checkpoint: JournalCheckpoint) {
        assert_eq!(
            checkpoint.journal_i,
            self.snapshots.len() - 1,
            "out-of-order checkpoint revert (expected top of stack)"
        );
        if let Some(snapshot) = self.snapshots.drain(checkpoint.journal_i..).next() {
            self.internals = snapshot.internals;
            self.events = snapshot.events;
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl HashMapStorageProvider {
    /// Returns the account info for the given address, if it exists.
    pub fn get_account_info(&self, address: Address) -> Option<&AccountInfo> {
        self.accounts.get(&address)
    }

    /// Returns all emitted events for the given address.
    pub fn get_events(&self, address: Address) -> &Vec<LogData> {
        static EMPTY: Vec<LogData> = Vec::new();
        self.events.get(&address).unwrap_or(&EMPTY)
    }

    /// Sets the nonce for the given address.
    pub fn set_nonce(&mut self, address: Address, nonce: u64) {
        let account = self.accounts.entry(address).or_default();
        account.nonce = nonce;
    }

    /// Overrides the block timestamp.
    pub fn set_timestamp(&mut self, timestamp: U256) {
        self.timestamp = timestamp;
    }

    /// Overrides the block beneficiary (coinbase).
    pub fn set_beneficiary(&mut self, beneficiary: Address) {
        self.beneficiary = beneficiary;
    }

    /// Overrides the block number.
    pub fn set_block_number(&mut self, block_number: u64) {
        self.block_number = block_number;
    }

    /// Overrides the active hardfork spec.
    pub fn set_spec(&mut self, spec: TempoHardfork) {
        self.spec = spec;
    }

    /// Clears all transient storage (simulates a new block).
    pub fn clear_transient(&mut self) {
        self.transient.clear();
    }

    /// Clears all emitted events for the given address.
    pub fn clear_events(&mut self, address: Address) {
        let _ = self
            .events
            .entry(address)
            .and_modify(|v| v.clear())
            .or_default();
    }

    pub fn counter_sload(&self) -> u64 {
        self.counter_sload
    }

    /// Returns all storage entries as `(address, slot, value)`.
    pub fn into_storage(self) -> impl Iterator<Item = (Address, U256, U256)> {
        self.internals
            .into_iter()
            .map(|((addr, slot), value)| (addr, slot, value))
    }
}
