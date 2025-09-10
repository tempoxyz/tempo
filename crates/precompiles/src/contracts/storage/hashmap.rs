use std::collections::HashMap;

use alloy::primitives::{Address, LogData, U256};
use reth_evm::revm::state::{AccountInfo, Bytecode};

use crate::contracts::storage::StorageProvider;

pub struct HashMapStorageProvider {
    internals: HashMap<(Address, U256), U256>,
    accounts: HashMap<Address, AccountInfo>,
    pub events: HashMap<Address, Vec<LogData>>,
    chain_id: u64,
}

impl HashMapStorageProvider {
    pub fn new(chain_id: u64) -> Self {
        Self {
            internals: HashMap::new(),
            accounts: HashMap::new(),
            events: HashMap::new(),
            chain_id,
        }
    }
    pub fn set_nonce(&mut self, address: Address, nonce: u64) {
        let account = self.accounts.entry(address).or_default();
        account.nonce = nonce;
    }
}

impl StorageProvider for HashMapStorageProvider {
    type Error = ();

    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn set_code(&mut self, address: Address, code: Bytecode) -> Result<(), Self::Error> {
        let account = self.accounts.entry(address).or_default();
        account.code = Some(code);
        Ok(())
    }

    fn get_account_info(&mut self, address: Address) -> Result<AccountInfo, Self::Error> {
        Ok(self.accounts.get(&address).cloned().unwrap_or_default())
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
