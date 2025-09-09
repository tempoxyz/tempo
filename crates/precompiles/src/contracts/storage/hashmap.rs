use std::collections::HashMap;

use alloy::primitives::{Address, LogData, U256};
use reth_evm::revm::state::Bytecode;

use crate::contracts::storage::StorageProvider;

pub struct HashMapStorageProvider {
    internals: HashMap<(Address, U256), U256>,
    code: HashMap<Address, Bytecode>,
    nonces: HashMap<Address, u64>,
    pub events: HashMap<Address, Vec<LogData>>,
    chain_id: u64,
}

impl HashMapStorageProvider {
    pub fn new(chain_id: u64) -> Self {
        Self {
            internals: HashMap::new(),
            code: HashMap::new(),
            nonces: HashMap::new(),
            events: HashMap::new(),
            chain_id,
        }
    }

    pub fn set_nonce(&mut self, address: Address, nonce: u64) {
        self.nonces.insert(address, nonce);
    }
}

impl StorageProvider for HashMapStorageProvider {
    type Error = ();

    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn set_code(&mut self, address: Address, code: Bytecode) -> Result<(), Self::Error> {
        self.code.insert(address, code);
        Ok(())
    }

    fn get_code(&mut self, address: Address) -> Result<Option<Bytecode>, Self::Error> {
        Ok(self.code.get(&address).cloned())
    }

    fn sstore(&mut self, address: Address, key: U256, value: U256) -> Result<(), Self::Error> {
        self.internals.insert((address, key), value);
        Ok(())
    }

    fn emit_event(&mut self, address: Address, event: LogData) -> Result<(), Self::Error> {
        self.events.entry(address).or_default().push(event);
        Ok(())
    }

    fn get_nonce(&mut self, address: Address) -> Result<u64, Self::Error> {
        Ok(self.nonces.get(&address).copied().unwrap_or(0))
    }

    fn sload(&mut self, address: Address, key: U256) -> Result<U256, Self::Error> {
        Ok(self
            .internals
            .get(&(address, key))
            .copied()
            .unwrap_or(U256::ZERO))
    }
}
