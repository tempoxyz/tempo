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
    type Error = ();

    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn set_code(&mut self, _address: Address, _code: Vec<u8>) -> Result<(), Self::Error> {
        // noop
        Ok(())
    }

    fn sstore(&mut self, address: Address, key: U256, value: U256) -> Result<(), Self::Error> {
        self.internals.insert((address, key), value);
        Ok(())
    }

    fn emit_event(&mut self, address: Address, event: LogData) -> Result<(), Self::Error> {
        self.events.entry(address).or_default().push(event);
        Ok(())
    }

    fn sload(&mut self, address: Address, key: U256) -> Result<U256, Self::Error> {
        Ok(self
            .internals
            .get(&(address, key))
            .copied()
            .unwrap_or(U256::ZERO))
    }
}
