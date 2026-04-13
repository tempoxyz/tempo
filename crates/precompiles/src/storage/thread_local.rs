use alloy::primitives::{Address, B256, LogData, U256};
use alloy_evm::{Database, EvmInternals};
use revm::{
    context::{
        Block, CfgEnv, ContextTr, JournalTr, Transaction, journaled_state::JournalCheckpoint,
    },
    state::{AccountInfo, Bytecode},
};
use scoped_tls::scoped_thread_local;
use std::{cell::RefCell, fmt::Debug};
use tempo_chainspec::hardfork::TempoHardfork;

use crate::{
    Precompile,
    error::{Result, TempoPrecompileError},
    storage::{PrecompileStorageProvider, evm::EvmPrecompileStorageProvider},
};

scoped_thread_local!(static STORAGE: RefCell<&mut dyn PrecompileStorageProvider>);

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

    /// Returns the chain ID.
    pub fn chain_id(&self) -> u64 {
        Self::with_storage(|s| s.chain_id())
    }

    /// Returns the current block timestamp.
    pub fn timestamp(&self) -> U256 {
        Self::with_storage(|s| s.timestamp())
    }

    /// Returns the current block beneficiary (coinbase).
    pub fn beneficiary(&self) -> Address {
        Self::with_storage(|s| s.beneficiary())
    }

    /// Returns the current block number.
    pub fn block_number(&self) -> u64 {
        Self::with_storage(|s| s.block_number())
    }

    /// Sets the bytecode at the given address.
    pub fn set_code(&mut self, address: Address, code: Bytecode) -> Result<()> {
        Self::try_with_storage(|s| s.set_code(address, code))
    }

    /// Performs an SLOAD operation (persistent storage read).
    pub fn sload(&self, address: Address, key: U256) -> Result<U256> {
        Self::try_with_storage(|s| s.sload(address, key))
    }

    /// Performs a TLOAD operation (transient storage read).
    pub fn tload(&self, address: Address, key: U256) -> Result<U256> {
        Self::try_with_storage(|s| s.tload(address, key))
    }

    /// Performs an SSTORE operation (persistent storage write).
    pub fn sstore(&mut self, address: Address, key: U256, value: U256) -> Result<()> {
        Self::try_with_storage(|s| s.sstore(address, key, value))
    }

    /// Performs a TSTORE operation (transient storage write).
    pub fn tstore(&mut self, address: Address, key: U256, value: U256) -> Result<()> {
        Self::try_with_storage(|s| s.tstore(address, key, value))
    }

    /// Emits an event from the given contract address.
    pub fn emit_event(&mut self, address: Address, event: LogData) -> Result<()> {
        Self::try_with_storage(|s| s.emit_event(address, event))
    }

    /// Adds refund to the gas refund counter.
    pub fn refund_gas(&mut self, gas: i64) {
        Self::with_storage(|s| s.refund_gas(gas))
    }

    /// Returns the gas used so far.
    pub fn gas_used(&self) -> u64 {
        Self::with_storage(|s| s.gas_used())
    }

    /// Returns the gas refunded so far.
    pub fn gas_refunded(&self) -> i64 {
        Self::with_storage(|s| s.gas_refunded())
    }

    /// Returns the currently active hardfork.
    pub fn spec(&self) -> TempoHardfork {
        Self::with_storage(|s| s.spec())
    }

    /// Returns whether the current call context is static.
    pub fn is_static(&self) -> bool {
        Self::with_storage(|s| s.is_static())
    }

    /// Creates a journal checkpoint and returns a RAII guard.
    ///
    /// All state mutations after this call will be atomically
    /// reverted if the guard is dropped without calling
    /// [`CheckpointGuard::commit`].
    ///
    /// # Panics
    ///
    /// Panics if no storage context is set.
    pub fn checkpoint(&mut self) -> CheckpointGuard {
        // spec: only available +T1C. Prior to that checkpoints are a no-op.
        let checkpoint = Self::with_storage(|s| {
            if s.spec().is_t1c() {
                Some(s.checkpoint())
            } else {
                None
            }
        });

        CheckpointGuard { checkpoint }
    }

    /// Deducts gas from the remaining gas and returns an error if insufficient.
    pub fn deduct_gas(&mut self, gas: u64) -> Result<()> {
        Self::try_with_storage(|s| s.deduct_gas(gas))
    }

    /// Computes keccak256 and charges the appropriate gas.
    ///
    /// Prefer this over naked `keccak256` to ensure gas is accounted for.
    pub fn keccak256(&self, data: &[u8]) -> Result<B256> {
        Self::try_with_storage(|s| s.keccak256(data))
    }

    /// Recovers the signer address from an ECDSA signature and charges ecrecover gas.
    /// As per [TIP-1004], it only accepts `v` values of `27` or `28` (no `0`/`1` normalization).
    ///
    /// Returns `Ok(None)` on invalid signatures; callers map to domain-specific errors.
    ///
    /// [TIP-1004]: <https://github.com/tempoxyz/tempo/blob/main/tips/tip-1004.md#signature-validation>
    pub fn recover_signer(&self, digest: B256, v: u8, r: B256, s: B256) -> Result<Option<Address>> {
        Self::try_with_storage(|storage| storage.recover_signer(digest, v, r, s))
    }
}

/// RAII guard for atomic state mutation batching.
///
/// On drop, automatically reverts all state changes made since the checkpoint
/// unless [`commit`](CheckpointGuard::commit) was called.
///
/// # SPEC
/// Only active +T1C, previously it is a no-op (no checkpoint is created).
///
/// # Examples
///
/// ```ignore
/// let guard = self.storage.checkpoint();
/// self.sstore(addr, key, value)?;  // reverted on drop (T1C+)
/// self.emit_event(...)?;
/// guard.commit();  // finalizes all mutations
/// ```
pub struct CheckpointGuard {
    checkpoint: Option<JournalCheckpoint>,
}

impl CheckpointGuard {
    /// Commits all state changes since the checkpoint.
    pub fn commit(mut self) {
        if let Some(cp) = self.checkpoint.take() {
            StorageCtx::with_storage(|s| s.checkpoint_commit(cp));
        }
    }
}

impl Drop for CheckpointGuard {
    fn drop(&mut self) {
        if let Some(cp) = self.checkpoint.take() {
            StorageCtx::with_storage(|s| s.checkpoint_revert(cp));
        }
    }
}

impl<'evm> StorageCtx {
    /// Generic entry point for EVM-like environments.
    /// Sets up the storage provider and executes a closure within that context.
    pub fn enter_evm<J, R>(
        journal: &'evm mut J,
        block_env: &'evm dyn Block,
        cfg: &CfgEnv<TempoHardfork>,
        tx_env: &'evm impl Transaction,
        f: impl FnOnce() -> R,
    ) -> R
    where
        J: JournalTr<Database: Database> + Debug,
    {
        let internals = EvmInternals::new(journal, block_env, cfg, tx_env);
        let mut provider = EvmPrecompileStorageProvider::new_max_gas(internals, cfg);

        // The core logic of setting up thread-local storage is here.
        Self::enter(&mut provider, f)
    }

    /// Like [`enter_evm`](Self::enter_evm), but takes a `&mut impl ContextTr`
    /// directly instead of requiring the caller to destructure the context.
    pub fn enter_ctx<C, R>(ctx: &mut C, f: impl FnOnce() -> R) -> R
    where
        C: ContextTr<Cfg = CfgEnv<TempoHardfork>, Journal: Debug, Db: Database>,
    {
        let (tx, block, cfg, journal) = ctx.tx_block_cfg_journal_mut();
        Self::enter_evm(journal, block, cfg, tx, f)
    }

    /// Entry point for a "canonical" precompile (with unique known address).
    pub fn enter_precompile<J, P, R>(
        journal: &'evm mut J,
        block_env: &'evm dyn Block,
        cfg: &CfgEnv<TempoHardfork>,
        tx_env: &'evm impl Transaction,
        f: impl FnOnce(P) -> R,
    ) -> R
    where
        J: JournalTr<Database: Database> + Debug,
        P: Precompile + Default,
    {
        // Delegate all the setup logic to `enter_evm`.
        // We just need to provide a closure that `enter_evm` expects.
        Self::enter_evm(journal, block_env, cfg, tx_env, || f(P::default()))
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
    pub fn set_block_number(&mut self, block_number: u64) {
        self.as_hashmap().set_block_number(block_number)
    }

    /// NOTE: assumes storage tests always use the `HashMapStorageProvider`
    pub fn set_spec(&mut self, spec: TempoHardfork) {
        self.as_hashmap().set_spec(spec)
    }

    /// NOTE: assumes storage tests always use the `HashMapStorageProvider`
    pub fn clear_transient(&mut self) {
        self.as_hashmap().clear_transient()
    }

    /// NOTE: assumes storage tests always use the `HashMapStorageProvider`
    ///
    /// USAGE: `TIP20Setup` clears events of the configured contract when
    /// `apply()` is called only if `clear_events()` was explicitly set.
    pub fn clear_events(&mut self, address: Address) {
        self.as_hashmap().clear_events(address);
    }

    /// NOTE: assumes storage tests always use the `HashMapStorageProvider`
    pub fn counter_sload(&self) -> u64 {
        self.as_hashmap().counter_sload()
    }

    /// Checks if a contract at the given address has bytecode deployed.
    pub fn has_bytecode(&self, address: Address) -> Result<bool> {
        self.with_account_info(address, |info| Ok(!info.is_empty_code_hash()))
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
    use alloy::primitives::U256;
    use tempo_chainspec::hardfork::TempoHardfork;

    fn t1c_storage() -> HashMapStorageProvider {
        HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1C)
    }

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

    #[test]
    fn test_checkpoint_commit_and_revert() {
        let mut storage = t1c_storage();
        let addr = Address::ZERO;
        let key = U256::from(1);

        StorageCtx::enter(&mut storage, || {
            let mut ctx = StorageCtx;

            // commit persists state
            ctx.sstore(addr, key, U256::from(42)).unwrap();
            let guard = ctx.checkpoint();
            ctx.sstore(addr, key, U256::from(99)).unwrap();
            guard.commit();
            assert_eq!(ctx.sload(addr, key).unwrap(), U256::from(99));

            // drop reverts state
            {
                let _guard = ctx.checkpoint();
                ctx.sstore(addr, key, U256::from(1)).unwrap();
            }
            assert_eq!(ctx.sload(addr, key).unwrap(), U256::from(99));
        });
    }

    #[test]
    fn test_nested_checkpoints_lifo() {
        let mut storage = t1c_storage();
        let addr = Address::ZERO;
        let key = U256::from(1);

        StorageCtx::enter(&mut storage, || {
            let mut ctx = StorageCtx;
            ctx.sstore(addr, key, U256::from(10)).unwrap();

            // both committed in LIFO order
            let outer = ctx.checkpoint();
            ctx.sstore(addr, key, U256::from(20)).unwrap();
            let inner = ctx.checkpoint();
            ctx.sstore(addr, key, U256::from(30)).unwrap();
            inner.commit();
            outer.commit();
            assert_eq!(ctx.sload(addr, key).unwrap(), U256::from(30));

            // inner reverts, outer commits
            let outer = ctx.checkpoint();
            ctx.sstore(addr, key, U256::from(40)).unwrap();
            {
                let _inner = ctx.checkpoint();
                ctx.sstore(addr, key, U256::from(50)).unwrap();
            }
            outer.commit();
            assert_eq!(ctx.sload(addr, key).unwrap(), U256::from(40));
        });
    }

    #[test]
    #[should_panic(expected = "out-of-order")]
    fn test_nested_checkpoints_out_of_order_commit_panics() {
        let mut storage = t1c_storage();

        StorageCtx::enter(&mut storage, || {
            let mut ctx = StorageCtx;

            let outer = ctx.checkpoint();
            let _inner = ctx.checkpoint();

            // Wrong order: committing outer while inner is still active
            outer.commit();
        });
    }

    #[test]
    fn test_checkpoint_noop_pre_t1c() {
        let mut storage = HashMapStorageProvider::new(1); // default = T0
        let addr = Address::ZERO;
        let key = U256::from(1);

        StorageCtx::enter(&mut storage, || {
            let mut ctx = StorageCtx;

            ctx.sstore(addr, key, U256::from(42)).unwrap();
            {
                let _guard = ctx.checkpoint(); // no-op pre-T1C
                ctx.sstore(addr, key, U256::from(99)).unwrap();
                // drop does nothing — no checkpoint was created
            }
            // state is NOT reverted because checkpoints are disabled pre-T1C
            assert_eq!(ctx.sload(addr, key).unwrap(), U256::from(99));
        });
    }
}
