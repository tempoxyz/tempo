use alloy::primitives::{Address, LogData, U256};
use alloy_evm::{Database, EvmInternals};
use revm::{
    context::{Block, CfgEnv, JournalTr},
    state::{AccountInfo, Bytecode},
};
use scoped_tls::scoped_thread_local;
use std::{
    cell::{Cell, RefCell},
    fmt::Debug,
};
use tempo_chainspec::hardfork::TempoHardfork;

use crate::{
    Precompile,
    error::{Result, TempoPrecompileError},
    storage::{PrecompileStorageProvider, evm::EvmPrecompileStorageProvider},
};

scoped_thread_local!(static STORAGE: RefCell<&mut dyn PrecompileStorageProvider>);

// Thread-local for tx.origin - set by the handler before transaction execution
thread_local!(static TX_ORIGIN: Cell<Address> = const { Cell::new(Address::ZERO) });

/// Sets the transaction origin (tx.origin) for the current thread.
///
/// This should be called by the transaction handler before executing a transaction.
/// Precompiles can then access it via `StorageCtx::tx_origin()`.
pub fn set_tx_origin(origin: Address) {
    TX_ORIGIN.set(origin);
}

/// Gets the transaction origin (tx.origin) for the current thread.
///
/// Returns `Address::ZERO` if not set.
pub fn get_tx_origin() -> Address {
    TX_ORIGIN.get()
}

/// Thread-local storage accessor that implements `PrecompileStorageProvider` without the trait bound.
///
/// This is the only type that exposes access to the thread-local `STORAGE` static.
///
/// # Important
///
/// Since it provides access to the current thread-local storage context, it MUST be used within
/// a `StorageCtx::enter` closure.
///
/// # Sync with `PrecompileStorageProvider`
///
/// This type mirrors `PrecompileStorageProvider` methods but with split mutability:
/// - Read operations (staticcall) take `&self`
/// - Write operations take `&mut self`
#[derive(Debug, Default, Clone, Copy)]
pub struct StorageCtx;

impl StorageCtx {
    /// Enter storage context. All storage operations must happen within the closure.
    ///
    /// # IMPORTANT
    ///
    /// The caller must ensure that:
    /// 1. Only one `enter` call is active at a time, in the same thread.
    /// 2. If multiple storage providers are instantiated in parallel threads,
    ///    they CANNOT point to the same storage addresses.
    pub fn enter<S, R>(storage: &mut S, f: impl FnOnce() -> R) -> R
    where
        S: PrecompileStorageProvider,
    {
        // SAFETY: `scoped_tls` ensures the pointer is only accessible within the closure scope.
        let storage: &mut dyn PrecompileStorageProvider = storage;
        let storage_static: &mut (dyn PrecompileStorageProvider + 'static) =
            unsafe { std::mem::transmute(storage) };
        let cell = RefCell::new(storage_static);
        STORAGE.set(&cell, f)
    }

    /// Execute an infallible function with access to the current thread-local storage provider.
    ///
    /// # Panics
    /// Panics if no storage context is set.
    fn with_storage<F, R>(f: F) -> R
    where
        F: FnOnce(&mut dyn PrecompileStorageProvider) -> R,
    {
        assert!(
            STORAGE.is_set(),
            "No storage context. 'StorageCtx::enter' must be called first"
        );
        STORAGE.with(|cell| {
            // SAFETY: `scoped_tls` ensures the pointer is only accessible within the closure scope.
            // Holding the guard prevents re-entrant borrows.
            let mut guard = cell.borrow_mut();
            f(&mut **guard)
        })
    }

    /// Execute a (fallible) function with access to the current thread-local storage provider.
    fn try_with_storage<F, R>(f: F) -> Result<R>
    where
        F: FnOnce(&mut dyn PrecompileStorageProvider) -> Result<R>,
    {
        if !STORAGE.is_set() {
            return Err(TempoPrecompileError::Fatal(
                "No storage context. 'StorageCtx::enter' must be called first".to_string(),
            ));
        }
        STORAGE.with(|cell| {
            // SAFETY: `scoped_tls` ensures the pointer is only accessible within the closure scope.
            // Holding the guard prevents re-entrant borrows.
            let mut guard = cell.borrow_mut();
            f(&mut **guard)
        })
    }

    // `PrecompileStorageProvider` methods (with modified mutability for read-only methods)

    /// Executes a closure with access to the account info, returning the closure's result.
    ///
    /// This is an ergonomic wrapper that flattens the Result, avoiding double `?`.
    pub fn with_account_info<T>(
        &self,
        address: Address,
        mut f: impl FnMut(&AccountInfo) -> Result<T>,
    ) -> Result<T> {
        let mut result: Option<Result<T>> = None;
        Self::try_with_storage(|s| {
            s.with_account_info(address, &mut |info| {
                result = Some(f(info));
            })
        })?;
        result.unwrap()
    }

    pub fn chain_id(&self) -> u64 {
        Self::with_storage(|s| s.chain_id())
    }

    pub fn timestamp(&self) -> U256 {
        Self::with_storage(|s| s.timestamp())
    }

    pub fn beneficiary(&self) -> Address {
        Self::with_storage(|s| s.beneficiary())
    }

    pub fn set_code(&mut self, address: Address, code: Bytecode) -> Result<()> {
        Self::try_with_storage(|s| s.set_code(address, code))
    }

    pub fn sload(&self, address: Address, key: U256) -> Result<U256> {
        Self::try_with_storage(|s| s.sload(address, key))
    }

    pub fn tload(&self, address: Address, key: U256) -> Result<U256> {
        Self::try_with_storage(|s| s.tload(address, key))
    }

    pub fn sstore(&mut self, address: Address, key: U256, value: U256) -> Result<()> {
        Self::try_with_storage(|s| s.sstore(address, key, value))
    }

    pub fn tstore(&mut self, address: Address, key: U256, value: U256) -> Result<()> {
        Self::try_with_storage(|s| s.tstore(address, key, value))
    }

    pub fn emit_event(&mut self, address: Address, event: LogData) -> Result<()> {
        Self::try_with_storage(|s| s.emit_event(address, event))
    }

    pub fn deduct_gas(&mut self, gas: u64) -> Result<()> {
        Self::try_with_storage(|s| s.deduct_gas(gas))
    }

    pub fn refund_gas(&mut self, gas: i64) {
        Self::with_storage(|s| s.refund_gas(gas))
    }

    pub fn gas_used(&self) -> u64 {
        Self::with_storage(|s| s.gas_used())
    }

    pub fn gas_refunded(&self) -> i64 {
        Self::with_storage(|s| s.gas_refunded())
    }

    pub fn spec(&self) -> TempoHardfork {
        Self::with_storage(|s| s.spec())
    }

    pub fn is_static(&self) -> bool {
        Self::with_storage(|s| s.is_static())
    }

    /// Returns the transaction origin (tx.origin) for the current transaction.
    ///
    /// This is set by the handler before transaction execution and can be used
    /// by precompiles to determine the original signer of the transaction.
    pub fn tx_origin(&self) -> Address {
        Self::with_storage(|s| s.tx_origin())
    }
}

impl<'evm> StorageCtx {
    /// Generic entry point for EVM-like environments.
    /// Sets up the storage provider and executes a closure within that context.
    pub fn enter_evm<J, R>(
        journal: &'evm mut J,
        block_env: &'evm dyn Block,
        cfg: &CfgEnv<TempoHardfork>,
        f: impl FnOnce() -> R,
    ) -> R
    where
        J: JournalTr<Database: Database> + Debug,
    {
        let internals = EvmInternals::new(journal, block_env);
        let mut provider = EvmPrecompileStorageProvider::new_max_gas(internals, cfg);

        // The core logic of setting up thread-local storage is here.
        Self::enter(&mut provider, f)
    }

    /// Entry point for a "canonical" precompile (with unique known address).
    pub fn enter_precompile<J, P, R>(
        journal: &'evm mut J,
        block_env: &'evm dyn Block,
        cfg: &CfgEnv<TempoHardfork>,
        f: impl FnOnce(P) -> R,
    ) -> R
    where
        J: JournalTr<Database: Database> + Debug,
        P: Precompile + Default,
    {
        // Delegate all the setup logic to `enter_evm`.
        // We just need to provide a closure that `enter_evm` expects.
        Self::enter_evm(journal, block_env, cfg, || f(P::default()))
    }
}

#[cfg(any(test, feature = "test-utils"))]
use crate::storage::hashmap::HashMapStorageProvider;

#[cfg(any(test, feature = "test-utils"))]
impl StorageCtx {
    /// Returns a mutable reference to the underlying `HashMapStorageProvider`.
    ///
    /// NOTE: takes a non-mutable reference because it's internal. The mutability
    /// of the storage operation is determined by the public function.
    #[allow(clippy::mut_from_ref)]
    fn as_hashmap(&self) -> &mut HashMapStorageProvider {
        Self::with_storage(|s| {
            // SAFETY: Test code always uses HashMapStorageProvider.
            // Reference valid for duration of StorageCtx::enter closure.
            unsafe {
                extend_lifetime_mut(
                    &mut *(s as *mut dyn PrecompileStorageProvider as *mut HashMapStorageProvider),
                )
            }
        })
    }

    /// NOTE: assumes storage tests always use the `HashMapStorageProvider`
    pub fn get_account_info(&self, address: Address) -> Option<&AccountInfo> {
        self.as_hashmap().get_account_info(address)
    }

    /// NOTE: assumes storage tests always use the `HashMapStorageProvider`
    pub fn get_events(&self, address: Address) -> &Vec<LogData> {
        self.as_hashmap().get_events(address)
    }

    /// NOTE: assumes storage tests always use the `HashMapStorageProvider`
    pub fn set_nonce(&mut self, address: Address, nonce: u64) {
        self.as_hashmap().set_nonce(address, nonce)
    }

    /// NOTE: assumes storage tests always use the `HashMapStorageProvider`
    pub fn set_timestamp(&mut self, timestamp: U256) {
        self.as_hashmap().set_timestamp(timestamp)
    }

    /// NOTE: assumes storage tests always use the `HashMapStorageProvider`
    pub fn set_beneficiary(&mut self, beneficiary: Address) {
        self.as_hashmap().set_beneficiary(beneficiary)
    }

    /// NOTE: assumes storage tests always use the `HashMapStorageProvider`
    pub fn set_spec(&mut self, spec: TempoHardfork) {
        self.as_hashmap().set_spec(spec)
    }

    /// NOTE: assumes storage tests always use the `HashMapStorageProvider`
    pub fn clear_transient(&mut self) {
        self.as_hashmap().clear_transient()
    }

    /// Checks if a contract at the given address has bytecode deployed.
    pub fn has_bytecode(&self, address: Address) -> bool {
        if let Some(account_info) = self.get_account_info(address) {
            !account_info.is_empty_code_hash()
        } else {
            false
        }
    }
}

/// Extends the lifetime of a mutable reference: `&'a mut T -> &'b mut T`
///
/// SAFETY: the caller must ensure the reference remains valid for the extended lifetime.
#[cfg(any(test, feature = "test-utils"))]
unsafe fn extend_lifetime_mut<'b, T: ?Sized>(r: &mut T) -> &'b mut T {
    unsafe { &mut *(r as *mut T) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "already borrowed")]
    fn test_reentrant_with_storage_panics() {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            // first borrow
            StorageCtx::with_storage(|_| {
                // re-entrant call should panic
                StorageCtx::with_storage(|_| ())
            })
        });
    }
}
