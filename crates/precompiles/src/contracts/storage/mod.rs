pub mod evm;
pub mod hashmap;
pub mod slots;

use std::fmt::Debug;

use alloy::primitives::{Address, LogData, U256};
use reth_evm::revm::state::{AccountInfo, Bytecode};

pub trait StorageProvider {
    type Error: Debug;

    fn chain_id(&self) -> u64;
    fn set_code(&mut self, address: Address, code: Bytecode) -> Result<(), Self::Error>;
    fn get_account_info(&mut self, address: Address) -> Result<AccountInfo, Self::Error>;
    fn sstore(&mut self, address: Address, key: U256, value: U256) -> Result<(), Self::Error>;
    fn sload(&mut self, address: Address, key: U256) -> Result<U256, Self::Error>;
    fn emit_event(&mut self, address: Address, event: LogData) -> Result<(), Self::Error>;
}
