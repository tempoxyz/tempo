pub mod evm;
pub mod hashmap;
pub mod slots;

use alloy::primitives::{Address, LogData, U256};
use revm::state::{AccountInfo, Bytecode};

use crate::error::TempoPrecompileError;

pub trait PrecompileStorageProvider {
    type Error: Into<TempoPrecompileError>;

    fn chain_id(&self) -> u64;
    fn timestamp(&self) -> U256;
    fn set_code(&mut self, address: Address, code: Bytecode) -> Result<(), Self::Error>;
    fn get_account_info(&mut self, address: Address) -> Result<AccountInfo, Self::Error>;
    fn sstore(&mut self, address: Address, key: U256, value: U256) -> Result<(), Self::Error>;
    fn sload(&mut self, address: Address, key: U256) -> Result<U256, Self::Error>;
    fn emit_event(&mut self, address: Address, event: LogData) -> Result<(), Self::Error>;
}

pub trait StorageOps {
    fn sstore(&mut self, slot: U256, value: U256) -> Result<(), TempoPrecompileError>;
    fn sload(&mut self, slot: U256) -> Result<U256, TempoPrecompileError>;
}
