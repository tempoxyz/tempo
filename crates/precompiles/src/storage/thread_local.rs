//! Thread-local storage infrastructure for precompiles
//!
//! This module provides a thread-local storage system that eliminates the need for explicit
//! storage parameter passing in precompile operations. It uses two guard types:
//!
//! - `StorageGuard`: Transaction-scoped, ensures storage provider is available for the duration
//! - `AddressGuard`: Contract-scoped, tracks which contract address is currently active
//!
//! # Safety
//!
//! The `StorageGuard::new()` function is unsafe because it stores a raw pointer to the storage
//! provider. The caller must ensure that:
//! 1. The storage provider outlives the guard
//! 2. Only one `StorageGuard` exists per thread at a time
//! 3. The storage provider is not moved while the guard is active

use crate::{error::TempoPrecompileError, storage::PrecompileStorageProvider};
use alloy::primitives::Address;
use std::{
    cell::{Cell, RefCell},
    marker::PhantomData,
};

/// Maximum depth for nested contract calls
const MAX_CALL_DEPTH: usize = 64;

thread_local! {
    /// Thread-local storage for the current storage provider pointer
    pub(crate) static STORAGE: Cell<Option<*mut dyn PrecompileStorageProvider>> = const { Cell::new(None) };

    /// Thread-local stack of contract addresses for nested calls
    static ADDRESS_STACK: RefCell<Vec<Address>> = const { RefCell::new(Vec::new()) };
}

/// Transaction-scoped guard that provides thread-local storage access
///
/// This guard must be created once per transaction and ensures that the storage
/// provider is available for the duration of the transaction. When dropped, it
/// cleans up the thread-local state.
pub struct StorageGuard {
    _lifetime: PhantomData<&'static mut dyn PrecompileStorageProvider>,
}

impl StorageGuard {
    /// Create a new storage guard
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// 1. The storage provider outlives this guard
    /// 2. Only one `StorageGuard` exists per thread at a time
    /// 3. The storage provider is not moved while the guard is active
    ///
    /// # Panics
    ///
    /// Panics if a `StorageGuard` already exists on the current thread
    pub unsafe fn new<S: PrecompileStorageProvider>(storage: &mut S) -> Self {
        if STORAGE.with(|s| s.get()).is_some() {
            panic!(
                "StorageGuard already exists - double initialization detected. \
                 Only one StorageGuard can exist per thread at a time."
            );
        }

        // Convert to trait object pointer with explicit lifetime
        // SAFETY: The caller ensures storage outlives this guard
        let ptr: *mut dyn PrecompileStorageProvider = storage;
        let ptr_static: *mut dyn PrecompileStorageProvider = unsafe { std::mem::transmute(ptr) };
        STORAGE.with(|s| s.set(Some(ptr_static)));

        Self {
            _lifetime: PhantomData,
        }
    }
}

impl Drop for StorageGuard {
    fn drop(&mut self) {
        // Clean up thread-local state
        STORAGE.with(|s| s.set(None));
        ADDRESS_STACK.with(|s| s.borrow_mut().clear());
    }
}

/// Contract-scoped guard that tracks the current contract address
///
/// This guard is safe to use and is cleaned up when dropped. When multiple contracts
/// are called in sequence (cross-contract calls), the address stack tracks which
/// contract is currently active.
pub struct AddressGuard {
    _marker: PhantomData<*const ()>,
}

impl AddressGuard {
    /// Create a new address guard for the given contract address.
    ///
    /// Errors if the maximum call depth is exceeded.
    pub fn new(address: Address) -> Result<Self, TempoPrecompileError> {
        ADDRESS_STACK.with(|stack| {
            let mut stack = stack.borrow_mut();
            if stack.len() >= MAX_CALL_DEPTH {
                return Err(TempoPrecompileError::CallDepthExceeded);
            }
            stack.push(address);
            Ok(Self {
                _marker: PhantomData,
            })
        })
    }

    /// Get the current contract address without consuming the guard
    pub fn current_address() -> Result<Address, TempoPrecompileError> {
        ADDRESS_STACK.with(|s| {
            s.borrow()
                .last()
                .copied()
                .ok_or(TempoPrecompileError::NoAddressContext)
        })
    }
}

impl Drop for AddressGuard {
    fn drop(&mut self) {
        ADDRESS_STACK.with(|s| {
            s.borrow_mut().pop();
        });
    }
}

/// Execute a function with access to the current storage context
///
/// This helper function provides safe access to both the storage provider and
/// the current contract address. It handles all the thread-local access internally.
///
/// # Errors
///
/// Returns an error if:
/// - No `StorageGuard` is active (no storage context)
/// - No `AddressGuard` is active (no address context)
/// - The provided function returns an error
pub fn with_storage_context<F, R>(f: F) -> Result<R, TempoPrecompileError>
where
    F: FnOnce(&mut dyn PrecompileStorageProvider, Address) -> Result<R, TempoPrecompileError>,
{
    // Get storage pointer from thread-local
    let storage_ptr = STORAGE
        .with(|s| s.get())
        .ok_or(TempoPrecompileError::NoStorageContext)?;

    // Get current address from thread-local stack
    let address = ADDRESS_STACK.with(|s| {
        s.borrow()
            .last()
            .copied()
            .ok_or(TempoPrecompileError::NoAddressContext)
    })?;

    // SAFETY: `StorageGuard` ensures the storage pointer is valid for the lifetime of the tx.
    let storage = unsafe { &mut *storage_ptr };

    f(storage, address)
}

// Context types for compile-time enforcement of call mutability
//
// These zero-sized types track whether a cross-contract call context allows
// state modifications, enforcing EVM-like static call restrictions at compile time.

/// Marker type for read-only (static) call context
pub struct ReadOnly;
/// Marker type for read-write (mutable) call context
pub struct ReadWrite;

// Marker traits to determine call context
pub trait CallCtx {}
pub trait StaticCtx: CallCtx {}
pub trait MutableCtx: StaticCtx {}

impl CallCtx for ReadOnly {}
impl CallCtx for ReadWrite {}
impl StaticCtx for ReadOnly {}
impl StaticCtx for ReadWrite {}
impl MutableCtx for ReadWrite {}

/// Trait to infer call context from method receiver type
///
/// This enables automatic inference: `&self` → `ReadOnly`, `&mut self` → `ReadWrite`
pub trait MethodCtx {
    type Allowed: CallCtx;
}

impl<T> MethodCtx for &T {
    type Allowed = ReadOnly;
}

impl<T> MethodCtx for &mut T {
    type Allowed = ReadWrite;
}

/// Builder for cross-contract calls with compile-time context enforcement
///
/// Generic over the contract type `T` and call context `Ctx`, leveraging
/// the type system to only allow mutable operations in mutable contexts.
pub struct CallBuilder<T, CTX: CallCtx> {
    address: Address,
    _ctx: PhantomData<(T, CTX)>,
}

impl<T, CTX: CallCtx> CallBuilder<T, CTX> {
    pub fn new(address: Address) -> Self {
        Self {
            address,
            _ctx: PhantomData,
        }
    }
}

/// Read-only context: closure receives immutable reference
impl<T: ContractCall> CallBuilder<T, ReadOnly> {
    pub fn staticcall<F, R>(self, f: F) -> Result<R, TempoPrecompileError>
    where
        F: FnOnce(&T) -> Result<R, TempoPrecompileError>,
    {
        let _guard = AddressGuard::new(self.address)?;
        let instance = T::_new();
        f(&instance)
    }
}

/// Read-write context: closure receives mutable reference
impl<T: ContractCall> CallBuilder<T, ReadWrite> {
    pub fn call<F, R>(self, f: F) -> Result<R, TempoPrecompileError>
    where
        F: FnOnce(&mut T) -> Result<R, TempoPrecompileError>,
    {
        let _guard = AddressGuard::new(self.address)?;
        let mut instance = T::_new();
        f(&mut instance)
    }
}

/// Trait for contracts that support the builder-based cross-contract call pattern
///
/// This is typically implemented by the macro-generated code for each contract.
pub trait ContractCall: Sized {
    /// Create a new instance of the contract (macro-generated)
    fn _new() -> Self;

    /// Create a call builder with context inferred from method receiver
    fn new<M>(_ctx: M, address: Address) -> CallBuilder<Self, M::Allowed>
    where
        M: MethodCtx,
    {
        CallBuilder::new(address)
    }
}

/// Helper functions for accessing storage provider methods without explicit parameters
///
/// These functions use the thread-local storage context to provide ergonomic access
/// to common storage provider operations.
pub mod context {
    use super::*;
    use crate::storage::LogData;
    use alloy::primitives::U256;
    use tempo_chainspec::hardfork::TempoHardfork;

    /// Emit an event from the current contract address
    pub fn emit_event(event: LogData) -> Result<(), TempoPrecompileError> {
        with_storage_context(|storage, address| storage.emit_event(address, event))
    }

    /// Get the current block timestamp
    pub fn timestamp() -> Result<U256, TempoPrecompileError> {
        with_storage_context(|storage, _| Ok(storage.timestamp()))
    }

    /// Get the current hardfork specification
    pub fn spec() -> Result<TempoHardfork, TempoPrecompileError> {
        with_storage_context(|storage, _| Ok(storage.spec()))
    }

    /// Get the chain ID
    pub fn chain_id() -> Result<u64, TempoPrecompileError> {
        with_storage_context(|storage, _| Ok(storage.chain_id()))
    }

    /// Get the current block beneficiary (coinbase)
    pub fn beneficiary() -> Result<Address, TempoPrecompileError> {
        with_storage_context(|storage, _| Ok(storage.beneficiary()))
    }

    /// Deduct gas from the current transaction
    pub fn deduct_gas(amount: u64) -> Result<(), TempoPrecompileError> {
        with_storage_context(|storage, _| storage.deduct_gas(amount))
    }

    /// Get the total gas used so far
    pub fn gas_used() -> Result<u64, TempoPrecompileError> {
        with_storage_context(|storage, _| Ok(storage.gas_used()))
    }

    /// Get the current contract address
    pub fn current_address() -> Result<Address, TempoPrecompileError> {
        AddressGuard::current_address()
    }

    /// Get the current call depth
    pub fn call_depth() -> usize {
        ADDRESS_STACK.with(|s| s.borrow().len())
    }
}
