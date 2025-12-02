// pub mod evm;
pub mod hashmap;

pub mod thread_local;
pub use thread_local::StorageContext;

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
///
/// # Implementations
///
/// - `EvmPrecompileStorageProvider` - Production EVM storage
/// - `HashMapStorageProvider` - Test storage
///
/// # Sync with `[StorageContext]`
///
/// `StorageContext` mirrors these methods with split mutability for read (staticcall) vs write (call).
/// When adding new methods here, remember to add corresponding methods to `StorageContext`.
pub trait PrecompileStorageProvider {
    /// Returns the chain ID.
    fn chain_id(&self) -> u64;

    /// Returns the current block timestamp.
    fn timestamp(&self) -> U256;

    /// Returns the current block beneficiary (coinbase).
    fn beneficiary(&self) -> Address;

    /// Sets the bytecode at the given address.
    fn set_code(&mut self, address: Address, code: Bytecode) -> Result<()>;

    /// Returns the account info for the given address.
    fn get_account_info(&mut self, address: Address) -> Result<&'_ AccountInfo>;

    /// Performs an SLOAD operation (persistent storage read).
    fn sload(&mut self, address: Address, key: U256) -> Result<U256>;

    /// Performs a TLOAD operation (transient storage read).
    fn tload(&mut self, address: Address, key: U256) -> Result<U256>;

    /// Performs an SSTORE operation (persistent storage write).
    fn sstore(&mut self, address: Address, key: U256, value: U256) -> Result<()>;

    /// Performs a TSTORE operation (transient storage write).
    fn tstore(&mut self, address: Address, key: U256, value: U256) -> Result<()>;

    /// Emits an event from the given contract address.
    fn emit_event(&mut self, address: Address, event: LogData) -> Result<()>;

    /// Deducts gas from the remaining gas and returns an error if insufficient.
    fn deduct_gas(&mut self, gas: u64) -> Result<()>;

    /// Returns the gas used so far.
    fn gas_used(&self) -> u64;

    /// Returns the currently active hardfork.
    fn spec(&self) -> TempoHardfork;

    // Test-only methods, only implemented by test providers like `HashMapStorageProvider`.
    #[cfg(any(test, feature = "test-utils"))]
    fn get_events(&self, _address: Address) -> &Vec<LogData> {
        unimplemented!("get_events only available for test storage providers")
    }
    #[cfg(any(test, feature = "test-utils"))]
    fn set_nonce(&mut self, _address: Address, _nonce: u64) {
        unimplemented!("set_nonce only available for test storage providers")
    }
    #[cfg(any(test, feature = "test-utils"))]
    fn set_timestamp(&mut self, _timestamp: U256) {
        unimplemented!("set_timestamp only available for test storage providers")
    }
    #[cfg(any(test, feature = "test-utils"))]
    fn set_beneficiary(&mut self, _beneficiary: Address) {
        unimplemented!("set_beneficiary only available for test storage providers")
    }
    #[cfg(any(test, feature = "test-utils"))]
    fn set_spec(&mut self, _spec: TempoHardfork) {
        unimplemented!("set_spec only available for test storage providers")
    }
    #[cfg(any(test, feature = "test-utils"))]
    fn clear_transient(&mut self) {
        unimplemented!("clear_transient only available for test storage providers")
    }
}

/// Storage operations for a given (contract) address.
///
/// Abstracts over persistent storage (SLOAD/SSTORE) and transient storage (TLOAD/TSTORE).
/// Implementors must route to the appropriate opcode.
pub trait StorageOps {
    /// Stores a value at the provided slot.
    fn store(&mut self, slot: U256, value: U256) -> Result<()>;
    /// Loads a value from the provided slot.
    fn load(&self, slot: U256) -> Result<U256>;
}

/// Trait providing access to a contract's address.
///
/// Automatically implemented by the `#[contract]` macro.
pub trait ContractStorage {
    /// Contract address.
    fn address(&self) -> Address;

    /// Contract storage accessor.
    fn storage(&mut self) -> &mut StorageContext;
}
