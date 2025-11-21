// pub mod evm;
pub mod hashmap;

pub mod thread_local;
pub use thread_local::StorageGuard;

mod types;
pub use types::*;

pub mod packing;
pub use packing::FieldLocation;
pub use types::mapping as slots;

use alloy::primitives::{Address, LogData, U256};
use revm::state::{AccountInfo, Bytecode};
use tempo_chainspec::hardfork::TempoHardfork;

use crate::error::Result;

/// Low-level storage provider for interacting with the EVM.
pub trait PrecompileStorageProvider {
    /// Enters this storage provider's context, enabling thread-local access.
    ///
    /// Only one `StorageGuard` can exist at a time, in the same thread.
    /// If multiple storage providers are instantiated in parallel threads, they CANNOT point to the same storage addresses.
    fn enter(&mut self) -> Result<StorageGuard<'_>>
    where
        Self: Sized,
    {
        StorageGuard::new(self)
    }

    fn chain_id(&self) -> u64;
    fn timestamp(&self) -> U256;
    fn beneficiary(&self) -> Address;
    fn set_code(&mut self, address: Address, code: Bytecode) -> Result<()>;
    fn get_account_info(&mut self, address: Address) -> Result<&'_ AccountInfo>;
    fn sload(&mut self, address: Address, key: U256) -> Result<U256>;
    fn tload(&mut self, address: Address, key: U256) -> Result<U256>;
    fn sstore(&mut self, address: Address, key: U256, value: U256) -> Result<()>;
    fn tstore(&mut self, address: Address, key: U256, value: U256) -> Result<()>;
    fn emit_event(&mut self, address: Address, event: LogData) -> Result<()>;

    /// Deducts gas from the remaining gas and return an error if the gas is insufficient.
    fn deduct_gas(&mut self, gas: u64) -> Result<()>;

    /// Returns the gas used so far.
    fn gas_used(&self) -> u64;

    /// Currently active hardfork.
    fn spec(&self) -> TempoHardfork;
}

/// Storage operations for a given (contract) address.
pub trait StorageOps {
    /// Performs an SSTORE operation at the provided slot, with the given value.
    fn sstore(&mut self, slot: U256, value: U256) -> Result<()>;
    /// Performs an SLOAD operation at the provided slot.
    fn sload(&self, slot: U256) -> Result<U256>;
}

/// Trait providing access to a contract's address.
///
/// Automatically implemented by the `#[contract]` macro.
pub trait ContractStorage {
    /// Contract address.
    fn address(&self) -> Address;
}
