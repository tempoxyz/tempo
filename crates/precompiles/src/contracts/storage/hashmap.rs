use std::collections::HashMap;

use alloy::primitives::{LogData, U256};

use crate::contracts::storage::StorageProvider;

pub struct HashMapStorageProvider {
    pub internals: HashMap<(u64, U256), U256>,
    pub events: HashMap<u64, Vec<LogData>>,
}

impl Default for HashMapStorageProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl HashMapStorageProvider {
    pub fn new() -> Self {
        Self {
            internals: HashMap::new(),
            events: HashMap::new(),
        }
    }
}

impl StorageProvider for HashMapStorageProvider {
    fn set_code(&mut self, _token_id: u64, _code: Vec<u8>) {
        // noop
    }

    fn sstore(&mut self, token_id: u64, key: U256, value: U256) {
        self.internals.insert((token_id, key), value);
    }

    fn emit_event(&mut self, _token_id: u64, event: LogData) {
        self.events.entry(_token_id).or_default().push(event);
    }

    fn sload(&mut self, token_id: u64, key: U256) -> U256 {
        self.internals
            .get(&(token_id, key))
            .copied()
            .unwrap_or(U256::ZERO)
    }
}
