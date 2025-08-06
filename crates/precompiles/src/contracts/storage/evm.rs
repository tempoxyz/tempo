use alloy::primitives::{Log, LogData, U256};
use reth::revm::state::Bytecode;
use reth_evm::EvmInternals;

use crate::contracts::{storage::StorageProvider, utils::token_id_to_address};

pub struct EvmStorageProvider<'a> {
    pub internals: EvmInternals<'a>,
}

impl<'a> EvmStorageProvider<'a> {
    pub fn new(internals: EvmInternals<'a>) -> Self {
        Self { internals }
    }
}

impl<'a> StorageProvider for EvmStorageProvider<'a> {
    fn set_code(&mut self, token_id: u64, code: Vec<u8>) {
        self.internals.set_code(
            token_id_to_address(token_id),
            Bytecode::new_raw(code.into()),
        );
    }

    fn sstore(&mut self, token_id: u64, key: U256, value: U256) {
        self.internals
            .sstore(token_id_to_address(token_id), key, value)
            .unwrap();
    }

    fn emit_event(&mut self, token_id: u64, event: LogData) {
        self.internals.log(Log {
            address: token_id_to_address(token_id),
            data: event,
        });
    }

    fn sload(&mut self, token_id: u64, key: U256) -> U256 {
        self.internals
            .sload(token_id_to_address(token_id), key)
            .map_or(U256::ZERO, |value| value.data)
    }
}
