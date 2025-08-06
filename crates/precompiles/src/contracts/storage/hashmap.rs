use std::collections::HashMap;

use alloy::primitives::{Address, LogData, U256};

use crate::contracts::storage::StorageProvider;

pub struct HashMapStorageProvider {
    internals: HashMap<(Address, U256), U256>,
    pub events: HashMap<Address, Vec<LogData>>,
    chain_id: u64,
}

impl HashMapStorageProvider {
    pub fn new(chain_id: u64) -> Self {
        Self {
            internals: HashMap::new(),
            events: HashMap::new(),
            chain_id,
        }
    }
}

impl StorageProvider for HashMapStorageProvider {
    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn set_code(&mut self, _address: Address, _code: Vec<u8>) {
        // noop
    }

    fn sstore(&mut self, address: Address, key: U256, value: U256) {
        self.internals.insert((address, key), value);
    }

    fn emit_event(&mut self, address: Address, event: LogData) {
        self.events.entry(address).or_default().push(event);
    }

    fn sload(&mut self, address: Address, key: U256) -> U256 {
        self.internals
            .get(&(address, key))
            .copied()
            .unwrap_or(U256::ZERO)
    }
}
