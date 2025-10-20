pub mod evm;
pub mod hashmap;
pub mod slots;

use std::fmt::Debug;

use alloy::primitives::{Address, LogData, U256};
use revm::{
    precompile::PrecompileError,
    state::{AccountInfo, Bytecode},
};

pub trait PrecompileStorageProvider {
    fn chain_id(&self) -> u64;
    fn timestamp(&self) -> U256;
    fn set_code(&mut self, address: Address, code: Bytecode) -> Result<(), PrecompileError>;
    fn get_account_info(&mut self, address: Address) -> Result<AccountInfo, PrecompileError>;
    fn sstore(&mut self, address: Address, key: U256, value: U256) -> Result<(), PrecompileError>;
    fn sload(&mut self, address: Address, key: U256) -> Result<U256, PrecompileError>;
    fn emit_event(&mut self, address: Address, event: LogData) -> Result<(), PrecompileError>;
}

pub trait StorageOps {
    // TODO: error handling
    fn sstore(&mut self, slot: U256, value: U256);
    fn sload(&mut self, slot: U256) -> U256;
}
