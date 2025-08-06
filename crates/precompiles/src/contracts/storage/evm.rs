use alloy::primitives::{Address, Log, LogData, U256};
use reth::revm::state::Bytecode;
use reth_evm::EvmInternals;

use crate::contracts::storage::StorageProvider;

pub struct EvmStorageProvider<'a> {
    pub internals: EvmInternals<'a>,
}

impl<'a> EvmStorageProvider<'a> {
    pub fn new(internals: EvmInternals<'a>) -> Self {
        Self { internals }
    }
}

impl<'a> StorageProvider for EvmStorageProvider<'a> {
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
