use alloy::primitives::{Address, LogData, U256};
use revm::state::{AccountInfo, Bytecode};
use scoped_tls::scoped_thread_local;
use std::cell::Cell;
use tempo_chainspec::hardfork::TempoHardfork;

use crate::{
    error::{Result, TempoPrecompileError},
    storage::PrecompileStorageProvider,
};

scoped_thread_local!(static STORAGE: Cell<*mut dyn PrecompileStorageProvider>);

/// Reborrows a raw pointer as a mutable reference.
///
/// # Safety
/// Caller must ensure:
/// - `ptr` points to valid, initialized memory
/// - No other references (mutable or shared) exist to the pointee
/// - The returned reference does not outlive the pointee
#[inline]
unsafe fn reborrow_mut<'a>(ptr: *mut dyn PrecompileStorageProvider) -> &'a mut dyn PrecompileStorageProvider {
    // SAFETY: Caller guarantees ptr is valid and not aliased.
    unsafe { &mut *ptr }
}

/// Thread-local storage accessor that implements `PrecompileStorageProvider` without the trait bound.
///
/// # Important
///
/// Since it provides access to the current thread-local storage context, it MUST be used within
/// a `StorageAccessor::enter` closure.
///
/// # Sync with `PrecompileStorageProvider`
///
/// This type mirrors `PrecompileStorageProvider` methods but with split mutability:
/// - Read operations (staticcall) take `&self`
/// - Write operations take `&mut self`
#[derive(Debug, Default, Clone, Copy)]
pub struct StorageAccessor;

impl StorageAccessor {
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
        let ptr: *mut dyn PrecompileStorageProvider = storage;
        // SAFETY: scoped_tls ensures ptr only accessible within closure scope.
        // The closure cannot return references to the storage, and the storage
        // outlives the closure execution.
        let ptr_static: *mut (dyn PrecompileStorageProvider + 'static) =
            unsafe { std::mem::transmute(ptr) };
        let cell = Cell::new(ptr_static);
        STORAGE.set(&cell, f)
    }

    /// Execute a function with access to the current thread-local storage provider.
    fn with_storage<F, R>(f: F) -> Result<R>
    where
        F: FnOnce(&mut dyn PrecompileStorageProvider) -> Result<R>,
    {
        if !STORAGE.is_set() {
            return Err(TempoPrecompileError::Fatal(
                "No storage context. 'StorageAccessor::enter' must be called first".to_string(),
            ));
        }
        STORAGE.with(|cell| {
            // SAFETY: Single-threaded access, scoped_tls prevents aliasing,
            // returned reference doesn't escape closure.
            f(unsafe { reborrow_mut(cell.get()) })
        })
    }

    // `PrecompileStorageProvider` methods (with modified mutability for read-only methods)

    pub fn chain_id(&self) -> u64 {
        // NOTE: safe to unwrap as `chain_id()` is infallible.
        Self::with_storage(|s| Ok(s.chain_id())).unwrap()
    }

    pub fn timestamp(&self) -> U256 {
        // NOTE: safe to unwrap as `timestamp()` is infallible.
        Self::with_storage(|s| Ok(s.timestamp())).unwrap()
    }

    pub fn beneficiary(&self) -> Address {
        // NOTE: safe to unwrap as `beneficiary()` is infallible.
        Self::with_storage(|s| Ok(s.beneficiary())).unwrap()
    }

    pub fn set_code(&mut self, address: Address, code: Bytecode) -> Result<()> {
        Self::with_storage(|s| s.set_code(address, code))
    }

    pub fn get_account_info(&self, address: Address) -> Result<&'_ AccountInfo> {
        // SAFETY: The returned reference is valid for the duration of the
        // `StorageAccessor::enter` closure. Since `StorageAccessor` can only be used
        // while inside enter(), the reference remains valid.
        Self::with_storage(|s| {
            let info = s.get_account_info(address)?;
            // Extend the lifetime to match &'_ self
            // This is safe because the underlying storage outlives the accessor
            let info: &'_ AccountInfo = unsafe { &*(info as *const AccountInfo) };
            Ok(info)
        })
    }

    pub fn sload(&self, address: Address, key: U256) -> Result<U256> {
        Self::with_storage(|s| s.sload(address, key))
    }

    pub fn tload(&self, address: Address, key: U256) -> Result<U256> {
        Self::with_storage(|s| s.tload(address, key))
    }

    pub fn sstore(&mut self, address: Address, key: U256, value: U256) -> Result<()> {
        Self::with_storage(|s| s.sstore(address, key, value))
    }

    pub fn tstore(&mut self, address: Address, key: U256, value: U256) -> Result<()> {
        Self::with_storage(|s| s.tstore(address, key, value))
    }

    pub fn emit_event(&mut self, address: Address, event: LogData) -> Result<()> {
        Self::with_storage(|s| s.emit_event(address, event))
    }

    pub fn deduct_gas(&mut self, gas: u64) -> Result<()> {
        Self::with_storage(|s| s.deduct_gas(gas))
    }

    pub fn gas_used(&self) -> u64 {
        // NOTE: safe to unwrap as `gas_used()` is infallible.
        Self::with_storage(|s| Ok(s.gas_used())).unwrap()
    }

    pub fn spec(&self) -> TempoHardfork {
        // NOTE: safe to unwrap as `spec()` is infallible.
        Self::with_storage(|s| Ok(s.spec())).unwrap()
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn get_events(&self, address: Address) -> &Vec<LogData> {
        // SAFETY: The returned reference is valid for the duration of the
        // `StorageAccessor::enter` closure. Since `StorageAccessor` can only be used
        // while inside enter(), the reference remains valid.
        Self::with_storage(|s| {
            let events = s.get_events(address);
            let events: &'_ Vec<LogData> = unsafe { &*(events as *const Vec<LogData>) };
            Ok(events)
        })
        .unwrap()
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_nonce(&mut self, address: Address, nonce: u64) {
        Self::with_storage(|s| {
            s.set_nonce(address, nonce);
            Ok(())
        })
        .unwrap()
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_timestamp(&mut self, timestamp: U256) {
        Self::with_storage(|s| {
            s.set_timestamp(timestamp);
            Ok(())
        })
        .unwrap()
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_beneficiary(&mut self, beneficiary: Address) {
        Self::with_storage(|s| {
            s.set_beneficiary(beneficiary);
            Ok(())
        })
        .unwrap()
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_spec(&mut self, spec: TempoHardfork) {
        Self::with_storage(|s| {
            s.set_spec(spec);
            Ok(())
        })
        .unwrap()
    }
}
