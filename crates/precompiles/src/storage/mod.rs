pub mod evm;
pub mod hashmap;

mod types;
use tempo_chainspec::hardfork::TempoHardfork;
pub use types::*;

pub mod packing;
pub use packing::FieldLocation;
pub use types::mapping as slots;

// Re-export extension traits for convenience
pub use types::vec::VecSlotExt;

use alloy::primitives::{Address, LogData, U256};
use revm::state::{AccountInfo, Bytecode};

use crate::error::TempoPrecompileError;

/// Low-level storage provider for interacting with the EVM.
pub trait PrecompileStorageProvider {
    fn chain_id(&self) -> u64;
    fn timestamp(&self) -> U256;
    fn beneficiary(&self) -> Address;
    fn set_code(&mut self, address: Address, code: Bytecode) -> Result<(), TempoPrecompileError>;
    fn get_account_info(
        &mut self,
        address: Address,
    ) -> Result<&'_ AccountInfo, TempoPrecompileError>;
    fn sload(&mut self, address: Address, key: U256) -> Result<U256, TempoPrecompileError>;
    fn tload(&mut self, address: Address, key: U256) -> Result<U256, TempoPrecompileError>;
    fn sstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
    ) -> Result<(), TempoPrecompileError>;
    fn tstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
    ) -> Result<(), TempoPrecompileError>;
    fn emit_event(&mut self, address: Address, event: LogData) -> Result<(), TempoPrecompileError>;

    /// Deducts gas from the remaining gas and return an error if the gas is insufficient.
    fn deduct_gas(&mut self, gas: u64) -> Result<(), TempoPrecompileError>;

    /// Add refund to the refund gas counter.
    fn refund_gas(&mut self, gas: i64);

    /// Returns the gas used so far.
    fn gas_used(&self) -> u64;

    /// Returns the gas refunded so far.
    fn gas_refunded(&self) -> i64;

    /// Currently active hardfork.
    fn spec(&self) -> TempoHardfork;
}

/// Storage operations for a given (contract) address.
pub trait StorageOps {
    /// Performs an SSTORE operation at the provided slot, with the given value.
    fn sstore(&mut self, slot: U256, value: U256) -> Result<(), TempoPrecompileError>;
    /// Performs an SLOAD operation at the provided slot.
    fn sload(&mut self, slot: U256) -> Result<U256, TempoPrecompileError>;
}

/// Trait providing access to a contract's address and storage provider.
///
/// Abstracts the common pattern of contracts needing both an address and a mutable reference
/// to a storage provider. It is automatically implemented by the `#[contract]` macro.
pub trait ContractStorage {
    type Storage: PrecompileStorageProvider;

    /// Contract address.
    fn address(&self) -> Address;
    /// Storage provider.
    fn storage(&mut self) -> &mut Self::Storage;
}

/// Blanket implementation of `StorageOps` for all type that implement `ContractStorage`.
/// Allows contracts to use `StorageOps` while delegating to `PrecompileStorageProvider`.
impl<T> StorageOps for T
where
    T: ContractStorage,
{
    /// Performs an SSTORE operation at the provided slot, with the given value.
    fn sstore(&mut self, slot: U256, value: U256) -> Result<(), TempoPrecompileError> {
        let address = self.address();
        self.storage().sstore(address, slot, value)
    }

    /// Performs an SLOAD operation at the provided slot.
    fn sload(&mut self, slot: U256) -> Result<U256, TempoPrecompileError> {
        let address = self.address();
        self.storage().sload(address, slot)
    }
}
