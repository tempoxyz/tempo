pub mod evm;
pub mod hashmap;
pub mod slots;

use alloy::primitives::{LogData, U256};

pub trait StorageProvider {
    fn set_code(&mut self, token_id: u64, code: Vec<u8>);
    fn sstore(&mut self, token_id: u64, key: U256, value: U256);
    fn sload(&mut self, token_id: u64, key: U256) -> U256;
    fn emit_event(&mut self, token_id: u64, event: LogData);
}
