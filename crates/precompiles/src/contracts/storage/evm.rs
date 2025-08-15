use alloy::primitives::{Address, Log, LogData, U256};
use alloy_evm::EvmInternals;
use reth::revm::state::Bytecode;

use crate::contracts::storage::StorageProvider;

pub struct EvmStorageProvider<'a> {
    internals: EvmInternals<'a>,
    chain_id: u64,
}

impl<'a> EvmStorageProvider<'a> {
    pub fn new(internals: EvmInternals<'a>, chain_id: u64) -> Self {
        Self {
            internals,
            chain_id,
        }
    }

    pub fn ensure_loaded_account(&mut self, account: Address) {
        self.internals
            .load_account(account)
            .expect("TODO: handle err");
        self.internals.touch_account(account);
    }
}

impl<'a> StorageProvider for EvmStorageProvider<'a> {
    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn set_code(&mut self, address: Address, code: Vec<u8>) {
        self.ensure_loaded_account(address);
        self.internals
            .set_code(address, Bytecode::new_raw(code.into()));
    }

    fn sstore(&mut self, address: Address, key: U256, value: U256) {
        self.ensure_loaded_account(address);
        self.internals
            .sstore(address, key, value)
            .expect("Could not store value");
    }

    fn emit_event(&mut self, address: Address, event: LogData) {
        self.internals.log(Log {
            address,
            data: event,
        });
    }

    fn sload(&mut self, address: Address, key: U256) -> U256 {
        self.ensure_loaded_account(address);
        self.internals
            .sload(address, key)
            .map_or(U256::ZERO, |value| value.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_evm::{
        EthEvmFactory, EvmEnv, EvmFactory, EvmInternals,
        revm::context::{ContextTr, Host},
    };
    use reth::revm::db::{CacheDB, EmptyDB};

    #[test]
    fn test_sstore_sload() {
        let db = CacheDB::new(EmptyDB::new());
        let mut evm = EthEvmFactory::default().create_evm(db, EvmEnv::default());
        let block = evm.block.clone();
        let evm_internals = EvmInternals::new(evm.journal_mut(), &block);
        let mut provider = EvmStorageProvider::new(evm_internals, 1);

        let addr = Address::random();
        let key = U256::random();
        let value = U256::random();

        provider.sstore(addr, key, value);
        let sload_val = provider.sload(addr, key);

        assert_eq!(sload_val, value);
    }

    #[test]
    fn test_set_code() {
        let db = CacheDB::new(EmptyDB::new());
        let mut evm = EthEvmFactory::default().create_evm(db, EvmEnv::default());
        let block = evm.block.clone();
        let evm_internals = EvmInternals::new(evm.journal_mut(), &block);
        let mut provider = EvmStorageProvider::new(evm_internals, 1);

        let addr = Address::random();
        let code = vec![0xff];
        provider.set_code(addr, code.clone());
        drop(provider);

        let account_code = evm.load_account_code(addr);
        assert!(account_code.is_some());
    }

    #[test]
    fn test_emit_event() {}
}
