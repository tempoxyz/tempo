use alloy::primitives::{Address, Log, LogData, U256};
use reth::revm::state::Bytecode;
use reth_evm::EvmInternals;

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
    use reth::revm::{
        Context, MainContext,
        context::{ContextTr, Evm},
        db::{CacheDB, EmptyDB, InMemoryDB},
        inspector::NoOpInspector,
    };
    use reth_evm::{EthEvm, EthEvmFactory, EvmEnv, EvmFactory, precompiles::PrecompilesMap};

    fn create_evm() -> EthEvm<CacheDB<EmptyDB>, NoOpInspector, PrecompilesMap> {
        let db = CacheDB::new(EmptyDB::new());
        let evm = EthEvmFactory::default().create_evm(db, EvmEnv::default());
        evm
    }

    #[test]
    fn test_sstore() {
        let mut evm = create_evm();
        // let evm_internals = EvmInternals::new(evm.journal(), evm.block);
        // let mut provider = EvmStorageProvider::new(evm_internals, 1);
    }

    #[test]
    fn test_sload() {}

    #[test]
    fn test_set_code() {}

    #[test]
    fn test_emit_event() {}
}
