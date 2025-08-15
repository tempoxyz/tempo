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
}

impl<'a> StorageProvider for EvmStorageProvider<'a> {
    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn set_code(&mut self, address: Address, code: Vec<u8>) {
        self.internals
            .set_code(address, Bytecode::new_raw(code.into()));
    }

    fn sstore(&mut self, address: Address, key: U256, value: U256) {
        self.internals.sstore(address, key, value).unwrap();
    }

    fn emit_event(&mut self, address: Address, event: LogData) {
        self.internals.log(Log {
            address,
            data: event,
        });
    }

    fn sload(&mut self, address: Address, key: U256) -> U256 {
        self.internals
            .sload(address, key)
            .map_or(U256::ZERO, |value| value.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{B256, LogData, address};
    use alloy_evm::{
        EthEvm, EthEvmFactory, EvmEnv, EvmFactory, EvmInternals, precompiles::PrecompilesMap,
        revm::context::ContextTr,
    };
    use reth::revm::db::{CacheDB, EmptyDB};

    #[test]
    fn test_sstore() {
        let db = CacheDB::new(EmptyDB::new());
        let evm = EthEvmFactory::default().create_evm(db, EvmEnv::default());
        let journal = evm.journal_mut();
        let block_env = evm.block;

        let evm_internals = EvmInternals::new(journal, block_env);
        // let mut provider = EvmStorageProvider::new(evm_internals, 1);
    }

    #[test]
    fn test_sload() {}

    #[test]
    fn test_set_code() {}

    #[test]
    fn test_emit_event() {}
}
