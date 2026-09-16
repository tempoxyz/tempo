use alloy::{
    primitives::{Address, B256, Bytes, LogData, U256},
    sol_types::SolInterface,
};
use alloy_evm::{Database, EvmInternals};
use revm::{
    context::{CfgEnv, ContextTr, JournalTr, Transaction, journaled_state::JournalCheckpoint},
    precompile::{PrecompileHalt, PrecompileOutput, PrecompileResult},
    state::{AccountInfo, Bytecode},
};
use scoped_tls::scoped_thread_local;
use std::{cell::RefCell, fmt::Debug, marker::PhantomData};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_primitives::TempoBlockEnv;

use crate::{
    Precompile,
    error::{IntoPrecompileResult, Result, TempoPrecompileError},
    storage::{PrecompileStorageProvider, StorageActions, evm::EvmPrecompileStorageProvider},
};

scoped_thread_local!(static STORAGE: RefCell<&mut dyn PrecompileStorageProvider>);

/// Read-only access to the active storage frame.
#[derive(Debug, Clone, Copy)]
pub struct ReadOnly;

/// Permission to mutate state, issued only at a checked execution boundary.
#[derive(Debug)]
pub struct Writable(PhantomData<std::rc::Rc<()>>);

/// Access to the active thread-local storage frame, parameterized by permission.
///
/// The default context permits reads and gas metering. State mutation requires
/// borrowing a `StorageCtx<Writable>` supplied by a mutation dispatch callback or
/// a non-static system execution entry point. Slots and generated handlers pass
/// this capability through every write; creating or cloning a handler grants no
/// permission. Backend checks still enforce the current frame's static flag.
/// All operations must run inside [`StorageCtx::enter`].
///
/// Read-only contexts have no mutation methods:
/// ```compile_fail,E0599
/// use tempo_precompiles::storage::StorageCtx;
/// use alloy::primitives::{Address, U256};
/// StorageCtx.sstore(Address::ZERO, U256::ZERO, U256::ONE);
/// ```
/// They cannot authorize a handler write:
/// ```compile_fail,E0308
/// use tempo_precompiles::storage::{Handler, Slot, StorageCtx};
/// use alloy::primitives::{Address, U256};
/// Slot::<U256>::new(U256::ZERO, Address::ZERO).write(&mut StorageCtx, U256::ONE);
/// ```
/// Mutating contracts also require the capability:
/// ```compile_fail,E0061
/// use tempo_precompiles::tip20::TIP20Token;
/// fn pause(token: &mut TIP20Token) {
///     let _ = token.pause(Default::default(), Default::default());
/// }
/// ```
/// Writable contexts cannot be freely constructed:
/// ```compile_fail,E0599
/// use tempo_precompiles::storage::{StorageCtx, Writable};
/// let write = StorageCtx::<Writable>::default();
/// ```
/// The permission belongs to its thread:
/// ```compile_fail,E0277
/// use tempo_precompiles::storage::{StorageCtx, Writable};
/// fn require_send<T: Send>() {}
/// require_send::<StorageCtx<Writable>>();
/// ```
#[derive(Debug)]
pub struct StorageCtx<Access = ReadOnly> {
    access: PhantomData<Access>,
}

/// Read access never grants permission to mutate the current frame.
#[allow(non_upper_case_globals)]
pub const StorageCtx: StorageCtx<ReadOnly> = StorageCtx {
    access: PhantomData,
};

impl Default for StorageCtx<ReadOnly> {
    fn default() -> Self {
        StorageCtx
    }
}

impl Clone for StorageCtx<ReadOnly> {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for StorageCtx<ReadOnly> {}

impl std::ops::Deref for StorageCtx<Writable> {
    type Target = StorageCtx<ReadOnly>;

    fn deref(&self) -> &Self::Target {
        &StorageCtx
    }
}

impl StorageCtx<ReadOnly> {
    /// The caller must preserve the fork-specific ABI rejection at dispatch.
    pub(crate) fn writable() -> Result<StorageCtx<Writable>> {
        if StorageCtx.is_static() {
            return Err(TempoPrecompileError::StaticCallNotAllowed);
        }
        Ok(StorageCtx {
            access: PhantomData,
        })
    }

    /// Obtain a write capability for test fixtures in a non-static frame.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn test_writable() -> StorageCtx<Writable> {
        Self::writable().expect("test fixture requires a non-static storage context")
    }
}

impl StorageCtx {
    /// Enter an owned provider with a borrowed write capability.
    /// Static providers are rejected before invoking the callback.
    pub fn enter_writable<S: PrecompileStorageProvider, R>(
        storage: &mut S,
        f: impl FnOnce(&mut StorageCtx<Writable>) -> R,
    ) -> Result<R> {
        if storage.is_static() {
            return Err(TempoPrecompileError::StaticCallNotAllowed);
        }
        Ok(Self::enter(storage, || {
            f(&mut StorageCtx {
                access: PhantomData,
            })
        }))
    }

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

    /// Returns `EXTCODEHASH(address)` and the account's runtime bytecode.
    pub fn account_code(&self, address: Address) -> Result<(B256, Bytecode)> {
        Self::try_with_storage(|s| s.account_code(address))
    }

    /// Returns the chain ID.
    pub fn chain_id(&self) -> u64 {
        Self::with_storage(|s| s.chain_id())
    }

    /// Returns the current block timestamp.
    pub fn timestamp(&self) -> U256 {
        self.with_block_env(|block_env| block_env.timestamp)
    }

    /// Returns the current block beneficiary (coinbase).
    pub fn beneficiary(&self) -> Address {
        self.with_block_env(|block_env| block_env.beneficiary)
    }

    /// Returns the current block number.
    pub fn block_number(&self) -> u64 {
        self.with_block_env(|block_env| block_env.number.saturating_to::<u64>())
    }

    /// Executes a closure with access to the current Tempo block environment.
    pub fn with_block_env<R>(&self, f: impl FnOnce(&TempoBlockEnv) -> R) -> R {
        Self::with_storage(|s| f(s.block_env()))
    }

    /// Returns the epoch containing `height`.
    pub fn epoch(&self, height: u64) -> u64 {
        self.with_block_env(|block_env| block_env.epoch(height))
    }

    /// Performs an SLOAD operation (persistent storage read).
    pub fn sload(&self, address: Address, key: U256) -> Result<U256> {
        Self::try_with_storage(|s| s.sload(address, key))
    }

    /// Performs a TLOAD operation (transient storage read).
    pub fn tload(&self, address: Address, key: U256) -> Result<U256> {
        Self::try_with_storage(|s| s.tload(address, key))
    }

    /// Adds refund to the gas refund counter.
    pub fn refund_gas(&self, gas: i64) {
        Self::with_storage(|s| s.refund_gas(gas))
    }

    /// Returns the gas limit for this precompile call.
    pub fn gas_limit(&self) -> u64 {
        Self::with_storage(|s| s.gas_limit())
    }

    /// Returns the gas used so far.
    pub fn gas_used(&self) -> u64 {
        Self::with_storage(|s| s.gas_used())
    }

    /// Returns the state-creating gas used so far (cold SSTORE zero->non-zero, code deposit).
    pub fn state_gas_used(&self) -> u64 {
        Self::with_storage(|s| s.state_gas_used())
    }

    /// Returns the state gas that was drawn from regular gas because the reservoir was empty
    /// (EIP-8037's `state_gas_from_gas_left`).
    pub fn state_gas_spilled(&self) -> u64 {
        Self::with_storage(|s| s.state_gas_spilled())
    }

    /// Returns the gas refunded so far.
    pub fn gas_refunded(&self) -> i64 {
        Self::with_storage(|s| s.gas_refunded())
    }

    /// Returns the reservoir gas.
    pub fn reservoir(&self) -> u64 {
        Self::with_storage(|s| s.reservoir())
    }

    /// Returns the currently active hardfork.
    pub fn spec(&self) -> TempoHardfork {
        Self::with_storage(|s| s.spec())
    }

    /// Returns the shared storage-actions recorder for the current storage context.
    pub fn actions(&self) -> StorageActions {
        Self::with_storage(|s| s.storage_actions())
    }

    /// Mirrors `CfgEnv::enable_amsterdam_eip8037`. Used by precompiles to gate the TIP-1016
    /// regular/state gas split independently of the active hardfork.
    pub fn amsterdam_eip8037_enabled(&self) -> bool {
        Self::with_storage(|s| s.amsterdam_eip8037_enabled())
    }

    /// Returns whether the current call context is static.
    pub fn is_static(&self) -> bool {
        Self::with_storage(|s| s.is_static())
    }

    /// Enables or disables TIP-1060 storage-credit accounting for subsequent storage writes.
    pub fn set_tip1060_storage_credits(&self, enabled: bool) {
        Self::with_storage(|s| s.set_tip1060_storage_credits(enabled))
    }

    /// Enables or disables minting new TIP-1060 storage credits for subsequent storage clears.
    pub fn set_tip1060_storage_credit_minting(&self, enabled: bool) {
        Self::with_storage(|s| s.set_tip1060_storage_credit_minting(enabled))
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
    pub fn checkpoint(&self) -> CheckpointGuard {
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
    pub fn deduct_gas(&self, gas: u64) -> Result<()> {
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

    /// Returns a [`PrecompileOutput`] with [`revm::precompile::PrecompileStatus::Success`] and the current gas values.
    pub fn success_output(&self, output: Bytes) -> PrecompileOutput {
        PrecompileOutput::new(self.gas_used(), output, self.reservoir())
    }

    /// Returns an ABI-encoded success output.
    pub fn abi_success(&self, output: impl SolInterface) -> PrecompileOutput {
        self.success_output(output.abi_encode().into())
    }

    /// Returns a [`PrecompileOutput`] with [`revm::precompile::PrecompileStatus::Revert`] and the current gas values.
    pub fn revert_output(&self, output: Bytes) -> PrecompileOutput {
        PrecompileOutput::revert(self.gas_used(), output, self.reservoir())
    }

    /// Reverts with an ABI-encoded error.
    pub fn abi_revert(&self, error: impl SolInterface) -> PrecompileOutput {
        self.revert_output(error.abi_encode().into())
    }

    /// Returns a [`PrecompileOutput`] with [`revm::precompile::PrecompileStatus::Halt`] and the current gas values.
    pub fn halt_output(&self, halt: PrecompileHalt) -> PrecompileOutput {
        PrecompileOutput::halt(halt, self.reservoir())
    }

    /// Returns a [`PrecompileResult`] constructed from the given error.
    pub fn error_result(&self, error: impl IntoPrecompileResult) -> PrecompileResult {
        error.into_precompile_result(self.gas_used(), self.reservoir())
    }
}

impl StorageCtx<Writable> {
    /// Copy deployed runtime bytecode to another account.
    pub fn copy_runtime(&mut self, source: Address, destination: Address) -> Result<Option<B256>> {
        StorageCtx::try_with_storage(|s| s.copy_runtime(source, destination))
    }
    /// Set bytecode at an account.
    pub fn set_code(&mut self, address: Address, code: Bytecode) -> Result<()> {
        StorageCtx::try_with_storage(|s| s.set_code(address, code))
    }
    /// Write a persistent storage slot.
    pub fn sstore(&mut self, address: Address, key: U256, value: U256) -> Result<()> {
        StorageCtx::try_with_storage(|s| s.sstore(address, key, value))
    }
    /// Increment a persistent storage slot without observing the new value.
    pub fn sinc(&mut self, address: Address, key: U256, delta: U256) -> Result<()> {
        StorageCtx::try_with_storage(|s| s.sinc(address, key, delta))
    }
    /// Decrement a persistent storage slot without observing the new value.
    pub fn sdec(&mut self, address: Address, key: U256, delta: U256) -> Result<()> {
        StorageCtx::try_with_storage(|s| s.sdec(address, key, delta))
    }
    /// Write a transient storage slot.
    pub fn tstore(&mut self, address: Address, key: U256, value: U256) -> Result<()> {
        StorageCtx::try_with_storage(|s| s.tstore(address, key, value))
    }
    /// Emit an event from the given contract address.
    pub fn emit_event(&mut self, address: Address, event: LogData) -> Result<()> {
        StorageCtx::try_with_storage(|s| s.emit_event(address, event))
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
        block_env: &'evm TempoBlockEnv,
        cfg: &CfgEnv<TempoHardfork>,
        tx_env: &'evm (impl Transaction + 'static),
        actions: StorageActions,
        f: impl FnOnce(&mut StorageCtx<Writable>) -> R,
    ) -> R
    where
        J: JournalTr<Database: Database> + Debug,
    {
        let internals = EvmInternals::new(journal, block_env, cfg, tx_env);
        let mut provider =
            EvmPrecompileStorageProvider::new_max_gas(internals, cfg).with_actions(actions);

        // The core logic of setting up thread-local storage is here.
        Self::enter_writable(&mut provider, f).expect("system storage provider is non-static")
    }

    /// Enters storage with TIP-1060 storage-credit accounting disabled.
    ///
    /// Use when provider gas is not charged, or is charged externally, and the writes must not
    /// mint, consume, or settle storage credits. If those writes create persistent storage, the
    /// external charge must include `STORAGE_CREDIT_VALUE` unless exempt.
    pub fn enter_evm_without_tip1060_accounting<J, R>(
        journal: &'evm mut J,
        block_env: &'evm TempoBlockEnv,
        cfg: &CfgEnv<TempoHardfork>,
        tx_env: &'evm (impl Transaction + 'static),
        actions: StorageActions,
        f: impl FnOnce(&mut StorageCtx<Writable>) -> R,
    ) -> R
    where
        J: JournalTr<Database: Database> + Debug,
    {
        let internals = EvmInternals::new(journal, block_env, cfg, tx_env);
        let mut provider =
            EvmPrecompileStorageProvider::new_max_gas(internals, cfg).with_actions(actions);
        provider.set_tip1060_storage_credits(false);

        Self::enter_writable(&mut provider, f).expect("system storage provider is non-static")
    }

    /// Like [`enter_evm`](Self::enter_evm), but takes a `&mut impl ContextTr`
    /// directly instead of requiring the caller to destructure the context.
    pub fn enter_ctx<C, R>(
        ctx: &mut C,
        actions: StorageActions,
        f: impl FnOnce(&mut StorageCtx<Writable>) -> R,
    ) -> R
    where
        C: ContextTr<
                Block = TempoBlockEnv,
                Cfg = CfgEnv<TempoHardfork>,
                Journal: Debug,
                Db: Database,
            >,
        C::Tx: 'static,
    {
        let (tx, block, cfg, journal) = ctx.tx_block_cfg_journal_mut();
        Self::enter_evm(journal, block, cfg, tx, actions, f)
    }

    /// Like [`enter_ctx`](Self::enter_ctx), but meters storage access under `gas_limit`
    /// and returns both the closure result and gas consumed.
    pub fn enter_ctx_with_gas_limit<C, R>(
        ctx: &mut C,
        gas_limit: u64,
        reservoir: u64,
        actions: StorageActions,
        f: impl FnOnce(&mut StorageCtx<Writable>) -> R,
    ) -> (R, u64)
    where
        C: ContextTr<
                Block = TempoBlockEnv,
                Cfg = CfgEnv<TempoHardfork>,
                Journal: Debug,
                Db: Database,
            >,
        C::Tx: 'static,
    {
        let (tx, block, cfg, journal) = ctx.tx_block_cfg_journal_mut();
        let internals = EvmInternals::new(journal, block, cfg, tx);
        let mut provider =
            EvmPrecompileStorageProvider::new_with_gas_limit(internals, cfg, gas_limit, reservoir)
                .with_actions(actions);
        let result =
            Self::enter_writable(&mut provider, f).expect("system storage provider is non-static");
        let gas_used = provider.gas_used();
        (result, gas_used)
    }

    /// Entry point for a "canonical" precompile (with unique known address).
    pub fn enter_precompile<J, P, R>(
        journal: &'evm mut J,
        block_env: &'evm TempoBlockEnv,
        cfg: &CfgEnv<TempoHardfork>,
        tx_env: &'evm (impl Transaction + 'static),
        actions: StorageActions,
        f: impl FnOnce(&mut StorageCtx<Writable>, P) -> R,
    ) -> R
    where
        J: JournalTr<Database: Database> + Debug,
        P: Precompile + Default,
    {
        // Delegate all the setup logic to `enter_evm`.
        // We just need to provide a closure that `enter_evm` expects.
        Self::enter_evm(journal, block_env, cfg, tx_env, actions, |write| {
            f(write, P::default())
        })
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

    /// NOTE: assumes storage tests always use the `HashMapStorageProvider`
    pub fn counter_sstore(&self) -> u64 {
        self.as_hashmap().counter_sstore()
    }

    /// NOTE: assumes storage tests always use the `HashMapStorageProvider`
    pub fn reset_counters(&mut self) {
        self.as_hashmap().reset_counters()
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
            StorageCtx::test_writable()
                .sstore(addr, key, U256::from(42))
                .unwrap();
            let guard = ctx.checkpoint();
            StorageCtx::test_writable()
                .sstore(addr, key, U256::from(99))
                .unwrap();
            guard.commit();
            assert_eq!(ctx.sload(addr, key).unwrap(), U256::from(99));

            // drop reverts state
            {
                let _guard = ctx.checkpoint();
                StorageCtx::test_writable()
                    .sstore(addr, key, U256::from(1))
                    .unwrap();
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
            StorageCtx::test_writable()
                .sstore(addr, key, U256::from(10))
                .unwrap();

            // both committed in LIFO order
            let outer = ctx.checkpoint();
            StorageCtx::test_writable()
                .sstore(addr, key, U256::from(20))
                .unwrap();
            let inner = ctx.checkpoint();
            StorageCtx::test_writable()
                .sstore(addr, key, U256::from(30))
                .unwrap();
            inner.commit();
            outer.commit();
            assert_eq!(ctx.sload(addr, key).unwrap(), U256::from(30));

            // inner reverts, outer commits
            let outer = ctx.checkpoint();
            StorageCtx::test_writable()
                .sstore(addr, key, U256::from(40))
                .unwrap();
            {
                let _inner = ctx.checkpoint();
                StorageCtx::test_writable()
                    .sstore(addr, key, U256::from(50))
                    .unwrap();
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

            StorageCtx::test_writable()
                .sstore(addr, key, U256::from(42))
                .unwrap();
            {
                let _guard = ctx.checkpoint(); // no-op pre-T1C
                StorageCtx::test_writable()
                    .sstore(addr, key, U256::from(99))
                    .unwrap();
                // drop does nothing — no checkpoint was created
            }
            // state is NOT reverted because checkpoints are disabled pre-T1C
            assert_eq!(ctx.sload(addr, key).unwrap(), U256::from(99));
        });
    }
}
