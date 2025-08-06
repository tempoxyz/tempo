pub mod evm;
pub mod hashmap;
pub mod slots;

use alloy::primitives::{Address, LogData, U256};

pub trait StorageProvider {
    fn chain_id(&self) -> u64;
    fn set_code(&mut self, address: Address, code: Vec<u8>);
    fn sstore(&mut self, address: Address, key: U256, value: U256);
    fn sload(&mut self, address: Address, key: U256) -> U256;
    fn emit_event(&mut self, address: Address, event: LogData);
}
