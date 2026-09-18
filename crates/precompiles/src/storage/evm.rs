use crate::{
    error::TempoPrecompileError,
    storage::{PrecompileStorageProvider, StorageActions, actions::StorageAction},
    storage_credits::{NonCreditableSlots, sstore_storage_credits},
};
use alloy::primitives::{Address, B256, Log, LogData, U256};
use alloy_evm::EvmInternals;
use bitflags::bitflags;
use revm::{
    context::{CfgEnv, journaled_state::JournalCheckpoint},
    context_interface::cfg::{GasParams, gas},
    interpreter::{SStoreResult, StateLoad, gas::GasTracker},
    state::{AccountInfo, Bytecode},
};
use std::{cell::RefCell, rc::Rc};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_primitives::TempoBlockEnv;

/// Production [`PrecompileStorageProvider`] backed by the live EVM journal.
///
/// Wraps `EvmInternals` and tracks gas consumption for storage operations.
pub struct EvmPrecompileStorageProvider<'a> {
    internals: EvmInternals<'a>,
    gas_tracker: GasTracker,
    spec: TempoHardfork,

    is_static: bool,
    gas_params: GasParams,
    tip1060_storage_credits_enabled: bool,
    tip1060_storage_credit_minting_enabled: bool,
    non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
    /// Debug-only LIFO checkpoint validator. See [`Self::assert_lifo`].
    #[cfg(debug_assertions)]
    checkpoint_stack: Vec<(usize, usize)>,
    /// Recorded storage actions.
    actions: StorageActions,
}

impl<'a> EvmPrecompileStorageProvider<'a> {
    /// Creates a new storage provider with the given gas limit, hardfork, and static flag.
    pub fn new(
        internals: EvmInternals<'a>,
        gas_limit: u64,
        reservoir: u64,
        spec: TempoHardfork,
        is_static: bool,
        gas_params: GasParams,
    ) -> Self {
        Self {
            internals,
            gas_tracker: GasTracker::new(gas_limit, gas_limit, reservoir),
            spec,

            is_static,
            gas_params,
            tip1060_storage_credits_enabled: true,
            tip1060_storage_credit_minting_enabled: true,
            non_creditable_slots: Rc::new(RefCell::new(NonCreditableSlots::empty())),
            #[cfg(debug_assertions)]
            checkpoint_stack: Vec::new(),
            actions: StorageActions::disabled(),
        }
    }

    /// Creates a new storage provider with maximum gas limit and non-static context.
    pub fn new_max_gas(internals: EvmInternals<'a>, cfg: &CfgEnv<TempoHardfork>) -> Self {
        Self::new(
            internals,
            u64::MAX,
            0,
            cfg.spec,
            false,
            cfg.gas_params.clone(),
        )
    }

    /// Creates a new storage provider with the given gas limit, deriving spec from `cfg`.
    pub fn new_with_gas_limit(
        internals: EvmInternals<'a>,
        cfg: &CfgEnv<TempoHardfork>,
        gas_limit: u64,
        reservoir: u64,
    ) -> Self {
        Self::new(
            internals,
            gas_limit,
            reservoir,
            cfg.spec,
            false,
            cfg.gas_params.clone(),
        )
    }

    /// Sets the storage actions for this provider.
    pub fn with_actions(mut self, actions: StorageActions) -> Self {
        self.actions = actions;
        self
    }

    /// Sets the transaction-local non-creditable clear-slot context for this provider.
    pub fn with_non_creditable_slots(mut self, slots: Rc<RefCell<NonCreditableSlots>>) -> Self {
        self.non_creditable_slots = slots;
        self
    }

    /// Replaces the recorded storage actions with an empty buffer, returning the previous actions.
    pub fn take_actions(&self) -> Option<Vec<StorageAction>> {
        self.actions.take()
    }

    /// Replaces the recorded storage actions with the given ones, returning the previous actions.
    pub fn replace_actions(&self, actions: Vec<StorageAction>) -> Option<Vec<StorageAction>> {
        self.actions.replace(actions)
    }

    #[inline]
    fn deduct_state_gas(&mut self, gas: u64) -> Result<(), TempoPrecompileError> {
        if !self.gas_tracker.record_state_cost(gas) {
            return Err(TempoPrecompileError::OutOfGas);
        }
        Ok(())
    }

    /// Performs a raw journaled SLOAD without metering gas or recording a storage action.
    #[inline]
    fn sload_journal(
        &mut self,
        address: Address,
        key: U256,
        skip_cold_load: bool,
    ) -> Result<StateLoad<U256>, TempoPrecompileError> {
        let mut account = self.internals.load_account_mut(address)?;
        let val = account.sload(key, skip_cold_load)?;
        Ok(StateLoad::new(val.present_value, val.is_cold))
    }

    /// Performs a raw journaled SSTORE without metering gas or recording a storage action.
    #[inline]
    fn sstore_journal(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
        skip_cold_load: bool,
    ) -> Result<StateLoad<SStoreResult>, TempoPrecompileError> {
        Ok(self
            .internals
            .load_account_mut(address)?
            .sstore(key, value, skip_cold_load)?)
    }

    /// Performs a metered precompile SLOAD, optionally recording the storage action.
    #[inline]
    fn sload_inner(
        &mut self,
        address: Address,
        key: U256,
        record: bool,
    ) -> Result<U256, TempoPrecompileError> {
        let additional_cost = self.gas_params.cold_storage_additional_cost();

        // T4+: pre-charge static gas to avoid cheap useless work.
        let skip_cold_load = {
            self.deduct_gas(self.gas_params.warm_storage_read_cost())?;
            self.gas_tracker.remaining() < additional_cost
        };

        let result = self.sload_journal(address, key, skip_cold_load)?;
        if record {
            self.actions
                .record(StorageAction::Sload(address, key, result.data));
        }

        // dynamic gas
        if result.is_cold {
            self.deduct_gas(additional_cost)?;
        }

        Ok(result.data)
    }

    /// Performs a metered precompile SSTORE and records `action` before storage-credit bookkeeping.
    #[inline]
    fn sstore_inner(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
        action: impl FnOnce(&SStoreResult) -> StorageAction,
    ) -> Result<(), TempoPrecompileError> {
        // T4+: pre-charge static gas before loading storage to avoid cheap useless work.
        let skip_cold_load = {
            self.deduct_gas(self.gas_params.sstore_static_gas())?;
            self.gas_tracker.remaining() < self.gas_params.cold_storage_additional_cost()
        };

        let result = self.sstore_journal(address, key, value, skip_cold_load)?;
        self.actions.record(action(&result.data));

        // TIP-1060 (T7+): run the storage credits policy so precompile-driven storage
        // writes honor the same accounting as the opcode-level SSTORE hook.
        if self.tip1060_storage_credits_enabled {
            sstore_storage_credits(self, address, Some(key), &result)?
        }

        // dynamic gas
        self.deduct_gas(
            self.gas_params
                .sstore_dynamic_gas(true, &result.data, result.is_cold),
        )?;

        // Track state gas (cold SSTORE zero->non-zero only)
        self.deduct_state_gas(self.gas_params.sstore_state_gas(&result.data))?;

        // refund gas.
        self.refund_gas(self.gas_params.sstore_refund(true, &result.data));

        Ok(())
    }

    #[inline]
    fn with_loaded_account<R>(
        &mut self,
        address: Address,
        f: impl FnOnce(bool, &AccountInfo) -> R,
    ) -> Result<R, TempoPrecompileError> {
        let additional_cost = self.gas_params.cold_account_additional_cost();

        // T4+: pre-charge static gas to avoid cheap useless work.
        let insufficient_gas_for_cold_load = {
            self.deduct_gas(self.gas_params.warm_storage_read_cost())?;
            self.gas_tracker.remaining() < additional_cost
        };

        let mut account = self
            .internals
            .load_account_mut_skip_cold_load(address, insufficient_gas_for_cold_load)?;

        // Dynamic gas.
        if account.is_cold {
            deduct_gas(&mut self.gas_tracker, additional_cost)?;
        }

        let exists = !account.data.account().is_loaded_as_not_existing();
        account.load_code()?;

        Ok(f(exists, &account.data.account().info))
    }
}

impl crate::storage_credits::StorageCreditsBackend for EvmPrecompileStorageProvider<'_> {
    type Error = TempoPrecompileError;

    #[inline]
    fn gas_tracker(&mut self) -> &mut GasTracker {
        &mut self.gas_tracker
    }

    #[inline]
    fn gas_params(&self) -> &GasParams {
        &self.gas_params
    }

    #[inline]
    fn sload(
        &mut self,
        address: Address,
        key: U256,
        skip_cold_load: bool,
    ) -> Result<StateLoad<U256>, Self::Error> {
        let val = self.sload_journal(address, key, skip_cold_load)?;
        self.actions
            .record_always(StorageAction::Sload(address, key, val.data));
        Ok(val)
    }

    #[inline]
    fn sstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
        skip_cold_load: bool,
    ) -> Result<SstoreTransitionFlags, Self::Error> {
        let val = self.sstore_journal(address, key, value, skip_cold_load)?;
        self.actions.record_always(StorageAction::Sstore(
            address,
            key,
            val.data.present_value,
            value,
        ));
        Ok(val.into())
    }

    #[inline]
    fn tload(&mut self, address: Address, key: U256) -> U256 {
        self.internals.tload(address, key)
    }

    #[inline]
    fn tstore(&mut self, address: Address, key: U256, value: U256) {
        self.internals.tstore(address, key, value);
    }

    #[inline]
    fn is_non_creditable_slot(&mut self, owner: Address, key: U256) -> bool {
        self.non_creditable_slots
            .borrow()
            .is_non_creditable_slot(owner, key)
    }

    #[inline]
    fn tip1060_storage_credit_minting_enabled(&self) -> bool {
        self.tip1060_storage_credit_minting_enabled
    }
}

impl<'a> PrecompileStorageProvider for EvmPrecompileStorageProvider<'a> {
    fn chain_id(&self) -> u64 {
        self.internals.chain_id()
    }

    fn block_env(&self) -> &TempoBlockEnv {
        self.internals
            .block_env_downcast_ref::<TempoBlockEnv>()
            .expect("EvmPrecompileStorageProvider requires TempoBlockEnv")
    }

    #[inline]
    fn set_code(&mut self, address: Address, code: Bytecode) -> Result<(), TempoPrecompileError> {
        let code_len = code.len();
        self.deduct_gas(self.gas_params.code_deposit_cost(code_len))?;

        // Track state gas for code deposit
        self.deduct_state_gas(self.gas_params.code_deposit_state_gas(code_len))?;

        self.internals
            .load_account_mut(address)?
            .set_code_and_hash_slow(code);

        Ok(())
    }

    #[inline]
    fn with_account_info(
        &mut self,
        address: Address,
        f: &mut dyn FnMut(&AccountInfo),
    ) -> Result<(), TempoPrecompileError> {
        self.with_loaded_account(address, |_, info| f(info))
    }

    #[inline]
    fn account_code(&mut self, address: Address) -> Result<(B256, Bytecode), TempoPrecompileError> {
        self.with_loaded_account(address, |exists, info| {
            let code_hash = if exists { info.code_hash } else { B256::ZERO };
            let code = info.code.clone().unwrap_or_default();
            (code_hash, code)
        })
    }

    #[inline]
    fn sstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
    ) -> Result<(), TempoPrecompileError> {
        self.sstore_inner(address, key, value, |result| {
            StorageAction::Sstore(address, key, result.present_value, value)
        })
    }

    #[inline]
    fn sinc(
        &mut self,
        address: Address,
        key: U256,
        delta: U256,
    ) -> Result<(), TempoPrecompileError> {
        let current = self.sload_inner(address, key, false)?;
        let value = current
            .checked_add(delta)
            .ok_or_else(TempoPrecompileError::under_overflow)?;

        // If the value goes from zero to non-zero, do not record it as `Sinc`,
        // because it requires special TIP-1060 gas credits accounting.
        let sstore_action = if current == U256::ZERO && value != U256::ZERO {
            self.actions
                .record(StorageAction::Sload(address, key, current));
            StorageAction::Sstore(address, key, current, value)
        } else {
            StorageAction::Sinc(address, key, current, delta)
        };

        self.sstore_inner(address, key, value, |_| sstore_action)
    }

    #[inline]
    fn sdec(
        &mut self,
        address: Address,
        key: U256,
        delta: U256,
    ) -> Result<(), TempoPrecompileError> {
        let current = self.sload_inner(address, key, false)?;
        let value = current
            .checked_sub(delta)
            .ok_or_else(|| TempoPrecompileError::storage_delta_underflow(current))?;

        // If the value goes from non-zero to zero, do not record it as `Sdec`,
        // because it requires special TIP-1060 gas credits accounting.
        let sstore_action = if current != U256::ZERO && value == U256::ZERO {
            self.actions
                .record(StorageAction::Sload(address, key, current));
            StorageAction::Sstore(address, key, current, value)
        } else {
            StorageAction::Sdec(address, key, current, delta)
        };

        self.sstore_inner(address, key, value, |_| sstore_action)
    }

    #[inline]
    fn tstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
    ) -> Result<(), TempoPrecompileError> {
        self.deduct_gas(self.gas_params.warm_storage_read_cost())?;
        self.internals.tstore(address, key, value);
        Ok(())
    }

    #[inline]
    fn emit_event(&mut self, address: Address, event: LogData) -> Result<(), TempoPrecompileError> {
        self.deduct_gas(
            gas::LOG
                + self
                    .gas_params
                    .log_cost(event.topics().len() as u8, event.data.len() as u64),
        )?;

        self.internals.log(Log {
            address,
            data: event,
        });

        Ok(())
    }

    #[inline]
    fn sload(&mut self, address: Address, key: U256) -> Result<U256, TempoPrecompileError> {
        self.sload_inner(address, key, true)
    }

    #[inline]
    fn tload(&mut self, address: Address, key: U256) -> Result<U256, TempoPrecompileError> {
        self.deduct_gas(self.gas_params.warm_storage_read_cost())?;

        Ok(self.internals.tload(address, key))
    }

    #[inline]
    fn deduct_gas(&mut self, gas: u64) -> Result<(), TempoPrecompileError> {
        deduct_gas(&mut self.gas_tracker, gas)
    }

    #[inline]
    fn refund_gas(&mut self, gas: i64) {
        self.gas_tracker.record_refund(gas);
    }

    #[inline]
    fn gas_limit(&self) -> u64 {
        self.gas_tracker.limit()
    }

    #[inline]
    fn gas_used(&self) -> u64 {
        self.gas_tracker.limit() - self.gas_tracker.remaining()
    }

    #[inline]
    fn state_gas_used(&self) -> u64 {
        // SAFETY: we never decrement the state gas spent counter
        self.gas_tracker.state_gas_spent() as u64
    }

    #[inline]
    fn state_gas_spilled(&self) -> u64 {
        self.gas_tracker.state_gas_spilled()
    }

    #[inline]
    fn gas_refunded(&self) -> i64 {
        self.gas_tracker.refunded()
    }

    #[inline]
    fn reservoir(&self) -> u64 {
        self.gas_tracker.reservoir()
    }

    #[inline]
    fn spec(&self) -> TempoHardfork {
        self.spec
    }

    #[inline]
    fn storage_actions(&self) -> StorageActions {
        self.actions.clone()
    }

    #[inline]
    fn is_static(&self) -> bool {
        self.is_static
    }

    #[inline]
    fn checkpoint(&mut self) -> JournalCheckpoint {
        let cp = self.internals.checkpoint();
        #[cfg(debug_assertions)]
        self.track_checkpoint(&cp);
        cp
    }

    #[inline]
    fn checkpoint_commit(&mut self, _checkpoint: JournalCheckpoint) {
        #[cfg(debug_assertions)]
        self.assert_lifo(&_checkpoint, "commit");
        self.internals.checkpoint_commit()
    }

    #[inline]
    fn checkpoint_revert(&mut self, checkpoint: JournalCheckpoint) {
        #[cfg(debug_assertions)]
        self.assert_lifo(&checkpoint, "revert");
        self.internals.checkpoint_revert(checkpoint)
    }

    #[inline]
    fn set_tip1060_storage_credits(&mut self, enabled: bool) {
        self.tip1060_storage_credits_enabled = enabled;
    }

    #[inline]
    fn set_tip1060_storage_credit_minting(&mut self, enabled: bool) {
        self.tip1060_storage_credit_minting_enabled = enabled;
    }
}

/// LIFO checkpoint validation (debug builds only).
///
/// Since `EvmInternals` doesn't expose revm's journal depth, we mirror it by
/// recording each checkpoint's (`journal_i`, `log_i`) on creation and asserting
/// that commits/reverts always resolve the most recent checkpoint first.
#[cfg(debug_assertions)]
impl EvmPrecompileStorageProvider<'_> {
    /// Records a newly created checkpoint for later LIFO validation.
    fn track_checkpoint(&mut self, cp: &JournalCheckpoint) {
        self.checkpoint_stack.push((cp.journal_i, cp.log_i));
    }

    /// Panics if `cp` is not the most recently created checkpoint.
    fn assert_lifo(&mut self, cp: &JournalCheckpoint, op: &str) {
        let top = self
            .checkpoint_stack
            .pop()
            .unwrap_or_else(|| panic!("checkpoint_{op}: no active checkpoint"));

        assert_eq!(
            (cp.journal_i, cp.log_i),
            top,
            "out-of-order checkpoint {op} (expected top of stack)"
        );
    }
}

bitflags! {
    /// SSTORE transition flags that drive gas/refund accounting.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SstoreTransitionFlags: u8 {
        /// The slot's transaction-start value is zero.
        const ORIGINAL_ZERO = 1 << 0;
        /// The slot's pre-SSTORE value is zero.
        const PRESENT_ZERO = 1 << 1;
        /// The slot's post-SSTORE value is zero.
        const NEW_ZERO = 1 << 2;
        /// The slot's transaction-start value equals its pre-SSTORE value.
        const ORIGINAL_EQ_PRESENT = 1 << 3;
        /// The slot's transaction-start value equals its post-SSTORE value.
        const ORIGINAL_EQ_NEW = 1 << 4;
        /// The slot's pre-SSTORE current value equals its post-SSTORE value.
        const PRESENT_EQ_NEW = 1 << 5;
    }
}

impl SstoreTransitionFlags {
    /// Computes the SSTORE transition flags from the values that drive gas/refund accounting.
    pub fn from_values(original: U256, present: U256, new: U256) -> Self {
        let mut flags = Self::empty();

        if original.is_zero() {
            flags |= Self::ORIGINAL_ZERO;
        }
        if present.is_zero() {
            flags |= Self::PRESENT_ZERO;
        }
        if new.is_zero() {
            flags |= Self::NEW_ZERO;
        }
        if original == present {
            flags |= Self::ORIGINAL_EQ_PRESENT;
        }
        if original == new {
            flags |= Self::ORIGINAL_EQ_NEW;
        }
        if present == new {
            flags |= Self::PRESENT_EQ_NEW;
        }

        flags
    }

    /// Returns whether the write changes slot occupancy.
    pub fn crosses_zero_boundary(&self) -> bool {
        self.contains(Self::PRESENT_ZERO) != self.contains(Self::NEW_ZERO)
    }

    /// Returns whether the write creates an occupied slot.
    pub fn is_zero_to_nonzero(&self) -> bool {
        self.contains(Self::PRESENT_ZERO) && !self.contains(Self::NEW_ZERO)
    }

    /// Returns whether the write clears an occupied slot.
    pub fn is_nonzero_to_zero(&self) -> bool {
        !self.contains(Self::PRESENT_ZERO) && self.contains(Self::NEW_ZERO)
    }

    /// Returns whether the write changes the present value.
    pub fn changes_present(&self) -> bool {
        !self.contains(Self::PRESENT_EQ_NEW)
    }

    /// Returns whether this slot is still clean before the write.
    ///
    /// In EVM SSTORE terminology, "clean" means the transaction has not changed
    /// the slot yet, so the transaction-start value (`original`) still equals
    /// the current pre-write value (`present`).
    pub fn is_original_eq_present(&self) -> bool {
        self.contains(Self::ORIGINAL_EQ_PRESENT)
    }

    /// Returns whether the warm clean-update SSTORE cost applies.
    ///
    /// This is the `present != new && original == present` case: the write
    /// changes a slot for the first time in the transaction. Dirty writes
    /// (`original != present`) use different SSTORE accounting and do not pay
    /// this clean-update charge again.
    pub fn charges_clean_update(&self) -> bool {
        self.changes_present() && self.is_original_eq_present()
    }
}

impl From<&StateLoad<SStoreResult>> for SstoreTransitionFlags {
    fn from(result: &StateLoad<SStoreResult>) -> Self {
        Self::from_values(
            result.data.original_value,
            result.data.present_value,
            result.data.new_value,
        )
    }
}

impl From<StateLoad<SStoreResult>> for SstoreTransitionFlags {
    fn from(result: StateLoad<SStoreResult>) -> Self {
        Self::from(&result)
    }
}

/// Deducts gas from the remaining gas and returns an error if insufficient.
#[inline]
pub fn deduct_gas(
    gas_tracker: &mut GasTracker,
    additional_cost: u64,
) -> Result<(), TempoPrecompileError> {
    if !gas_tracker.record_regular_cost(additional_cost) {
        return Err(TempoPrecompileError::OutOfGas);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{B256, b256, bytes, keccak256};
    use alloy_evm::{EvmEnv, EvmFactory, EvmInternals, revm::context::Host};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use revm::{
        database::{CacheDB, EmptyDB},
        interpreter::StateLoad,
    };
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_evm::{TempoEvmFactory, evm::TempoEvm};
    use tempo_revm::gas_params::tempo_gas_params;

    struct TestEvm(TempoEvm<CacheDB<EmptyDB>>);

    impl TestEvm {
        fn new(spec: TempoHardfork) -> Self {
            let db = CacheDB::new(EmptyDB::new());
            let mut cfg = revm::context::CfgEnv::<TempoHardfork>::default();
            cfg.spec = spec;
            cfg.gas_params = tempo_gas_params(spec);

            Self(TempoEvmFactory::default().create_evm(
                db,
                EvmEnv {
                    cfg_env: cfg,
                    ..Default::default()
                },
            ))
        }

        fn provider_with_gas_limit(
            &mut self,
            gas_limit: u64,
            reservoir: u64,
        ) -> EvmPrecompileStorageProvider<'_> {
            let ctx = self.0.ctx_mut();
            let spec = ctx.cfg.spec;

            let gas_params = ctx.cfg.gas_params.clone();
            let evm_internals =
                EvmInternals::new(&mut ctx.journaled_state, &ctx.block, &ctx.cfg, &ctx.tx);

            EvmPrecompileStorageProvider::new(
                evm_internals,
                gas_limit,
                reservoir,
                spec,
                false,
                gas_params,
            )
        }

        fn provider_max_gas(&mut self) -> EvmPrecompileStorageProvider<'_> {
            let ctx = self.0.ctx_mut();
            let evm_internals =
                EvmInternals::new(&mut ctx.journaled_state, &ctx.block, &ctx.cfg, &ctx.tx);
            EvmPrecompileStorageProvider::new_max_gas(evm_internals, &ctx.cfg)
        }
    }

    impl Default for TestEvm {
        fn default() -> Self {
            Self::new(TempoHardfork::default())
        }
    }

    impl std::ops::Deref for TestEvm {
        type Target = TempoEvm<CacheDB<EmptyDB>>;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl std::ops::DerefMut for TestEvm {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    #[test]
    fn test_sstore_sload_actions_recording() -> eyre::Result<()> {
        let mut evm = TestEvm::default();
        let addr = Address::random();

        let mut provider = evm
            .provider_max_gas()
            .with_actions(StorageActions::enabled());

        let (k1, v1) = (U256::from(1), U256::from(10));
        let (k2, v2) = (U256::from(2), U256::from(20));
        let v1_new = U256::from(11);

        provider.sstore(addr, k1, v1)?;
        provider.sstore(addr, k2, v2)?;
        let _ = provider.sload(addr, k1)?;
        provider.sstore(addr, k1, v1_new)?;
        let _ = provider.sload(addr, k2)?;
        provider.sinc(addr, k1, U256::from(4))?;
        provider.sdec(addr, k2, U256::from(5))?;

        assert_eq!(
            provider.take_actions(),
            Some(vec![
                StorageAction::Sstore(addr, k1, U256::ZERO, v1),
                StorageAction::Sload(
                    crate::STORAGE_CREDITS_ADDRESS,
                    U256::from_be_slice(addr.as_slice()),
                    U256::ZERO
                ),
                StorageAction::Sstore(addr, k2, U256::ZERO, v2),
                StorageAction::Sload(
                    crate::STORAGE_CREDITS_ADDRESS,
                    U256::from_be_slice(addr.as_slice()),
                    U256::ZERO
                ),
                StorageAction::Sload(addr, k1, v1),
                StorageAction::Sstore(addr, k1, v1, v1_new),
                StorageAction::Sload(addr, k2, v2),
                StorageAction::Sinc(addr, k1, v1_new, U256::from(4)),
                StorageAction::Sdec(addr, k2, v2, U256::from(5)),
            ])
        );

        Ok(())
    }

    #[test]
    fn test_sstore_sload_actions_recording_disabled_by_default() -> eyre::Result<()> {
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();
        let addr = Address::random();
        provider.sstore(addr, U256::from(1), U256::from(100))?;
        let _ = provider.sload(addr, U256::from(1))?;

        assert_eq!(provider.take_actions(), None);

        Ok(())
    }

    #[test]
    fn test_sstore_sload() -> eyre::Result<()> {
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();

        let addr = Address::random();
        let key = U256::random();
        let value = U256::random();

        provider.sstore(addr, key, value)?;
        let sload_val = provider.sload(addr, key)?;
        assert_eq!(sload_val, value);
        Ok(())
    }

    #[test]
    fn test_set_code() -> eyre::Result<()> {
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();

        let addr = Address::random();
        let code = Bytecode::new_raw(vec![0xff].into());

        provider.set_code(addr, code.clone())?;
        std::mem::drop(provider);

        let Some(StateLoad { data, is_cold: _ }) = evm.load_account_code(addr) else {
            panic!("Failed to load account code")
        };

        assert_eq!(data, *code.original_bytes());
        Ok(())
    }

    #[test]
    fn test_get_account_info() -> eyre::Result<()> {
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();

        // Get account info for a new account
        provider.with_account_info(Address::random(), &mut |info| {
            // Should be an empty account
            assert!(info.balance.is_zero());
            assert_eq!(info.nonce, 0);
            // Note: load_account_code may return empty bytecode as Some(empty) for new accounts
            if let Some(ref code) = info.code {
                assert!(code.is_empty(), "New account should have empty code");
            }
        })?;

        Ok(())
    }

    #[test]
    fn test_emit_event() -> eyre::Result<()> {
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();

        let topic = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let data = bytes!(
            "00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001"
        );

        let log_data = LogData::new_unchecked(vec![topic], data);

        // Should not error even though events can't be emitted from handlers
        provider.emit_event(Address::random(), log_data)?;

        Ok(())
    }

    #[test]
    fn test_multiple_storage_operations() -> eyre::Result<()> {
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();
        let address = Address::random();

        // Store multiple values
        for i in 0..10 {
            let key = U256::from(i);
            let value = U256::from(i * 100);
            provider.sstore(address, key, value)?;
        }

        // Verify all values
        for i in 0..10 {
            let key = U256::from(i);
            let expected_value = U256::from(i * 100);
            let loaded_value = provider.sload(address, key)?;
            assert_eq!(loaded_value, expected_value);
        }

        Ok(())
    }

    #[test]
    fn test_overwrite_storage() -> eyre::Result<()> {
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();
        let address = Address::random();
        let key = U256::from(99);

        // Store initial value
        let initial_value = U256::from(111);
        provider.sstore(address, key, initial_value)?;
        assert_eq!(provider.sload(address, key)?, initial_value);

        // Overwrite with new value
        let new_value = U256::from(999);
        provider.sstore(address, key, new_value)?;
        assert_eq!(provider.sload(address, key)?, new_value);

        Ok(())
    }

    #[test]
    fn test_different_addresses() -> eyre::Result<()> {
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();
        let (address1, address2) = (Address::random(), Address::random());
        let key = U256::from(42);

        // Store different values at the same key for different addresses
        let value1 = U256::from(100);
        let value2 = U256::from(200);

        provider.sstore(address1, key, value1)?;
        provider.sstore(address2, key, value2)?;

        // Verify values are independent
        assert_eq!(provider.sload(address1, key)?, value1);
        assert_eq!(provider.sload(address2, key)?, value2);

        Ok(())
    }

    #[test]
    fn test_multiple_transient_storage_operations() -> eyre::Result<()> {
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();
        let address = Address::random();

        // Store multiple values
        for i in 0..10 {
            let key = U256::from(i);
            let value = U256::from(i * 100);
            provider.tstore(address, key, value)?;
        }

        // Verify all values
        for i in 0..10 {
            let key = U256::from(i);
            let expected_value = U256::from(i * 100);
            let loaded_value = provider.tload(address, key)?;
            assert_eq!(loaded_value, expected_value);
        }

        Ok(())
    }

    #[test]
    fn test_overwrite_transient_storage() -> eyre::Result<()> {
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();
        let address = Address::random();
        let key = U256::from(99);

        // Store initial value
        let initial_value = U256::from(111);
        provider.tstore(address, key, initial_value)?;
        assert_eq!(provider.tload(address, key)?, initial_value);

        // Overwrite with new value
        let new_value = U256::from(999);
        provider.tstore(address, key, new_value)?;
        assert_eq!(provider.tload(address, key)?, new_value);

        Ok(())
    }

    #[test]
    fn test_transient_storage_different_addresses() -> eyre::Result<()> {
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();
        let (address1, address2) = (Address::random(), Address::random());
        let key = U256::ONE;

        // Store different values at the same key for different addresses
        let value1 = U256::from(100);
        let value2 = U256::from(200);

        provider.tstore(address1, key, value1)?;
        provider.tstore(address2, key, value2)?;

        // Verify values are independent
        assert_eq!(provider.tload(address1, key)?, value1);
        assert_eq!(provider.tload(address2, key)?, value2);

        Ok(())
    }

    #[test]
    fn test_transient_storage_isolation_from_persistent() -> eyre::Result<()> {
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();
        let address = Address::random();
        let key = U256::from(123);
        let persistent_value = U256::from(456);
        let transient_value = U256::from(789);

        // Store in persistent storage
        provider.sstore(address, key, persistent_value)?;

        // Store in transient storage with same key
        provider.tstore(address, key, transient_value)?;

        // Verify they are independent
        assert_eq!(provider.sload(address, key)?, persistent_value);
        assert_eq!(provider.tload(address, key)?, transient_value);

        Ok(())
    }

    #[test]
    fn test_keccak256_gas() -> eyre::Result<()> {
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();

        // 1 word: KECCAK256(30) + KECCAK256WORD(6) * ceil(11/32) = 36
        assert_eq!(
            provider.keccak256(b"hello world")?,
            keccak256(b"hello world")
        );
        assert_eq!(provider.gas_used(), 36);
        // 2 words: 30 + 6*2 = 42, cumulative = 78
        provider.keccak256(&[0u8; 64])?;
        assert_eq!(provider.gas_used(), 78);
        std::mem::drop(provider);

        // OOG: 30 gas is not enough (needs 36 for 1 word)
        let mut provider = evm.provider_with_gas_limit(30, 0);
        assert!(matches!(
            provider.keccak256(b"hello"),
            Err(TempoPrecompileError::OutOfGas)
        ));

        Ok(())
    }

    #[test]
    fn test_recover_signer_gas() -> eyre::Result<()> {
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();

        let signer = PrivateKeySigner::random();
        let digest = keccak256(b"test message");
        let sig = signer.sign_hash_sync(&digest).unwrap();
        let v = u8::from(sig.v()) + 27;
        let r: B256 = sig.r().into();
        let s: B256 = sig.s().into();

        // Invalid v → None, gas still charged
        assert!(
            provider
                .recover_signer(B256::ZERO, 0, B256::ZERO, B256::ZERO)?
                .is_none()
        );
        assert_eq!(provider.gas_used(), crate::ECRECOVER_GAS);

        // Valid signature → correct recovery
        assert_eq!(
            provider.recover_signer(digest, v, r, s)?,
            Some(signer.address())
        );
        assert_eq!(provider.gas_used(), crate::ECRECOVER_GAS * 2);
        std::mem::drop(provider);

        // OOG: 100 gas is not enough (needs 3000)
        let mut provider = evm.provider_with_gas_limit(100, 0);
        assert!(matches!(
            provider.recover_signer(digest, v, r, s),
            Err(TempoPrecompileError::OutOfGas)
        ));

        Ok(())
    }

    #[test]
    fn test_sstore_t4_fork_sufficient_gas() -> eyre::Result<()> {
        // T4 fork sstore/sload with abundant gas: round-trip the value.
        let mut evm = TestEvm::new(TempoHardfork::T4);
        let mut provider = evm.provider_max_gas();

        let address = Address::random();
        let key = U256::from(42);
        let value = U256::from(999);

        provider.sstore(address, key, value)?;
        assert_eq!(provider.sload(address, key)?, value);
        Ok(())
    }

    #[test]
    fn test_sload_t4_fork_sufficient_gas() -> eyre::Result<()> {
        // T4 fork sload with abundant gas: cold then warm reads return the stored value.
        let mut evm = TestEvm::new(TempoHardfork::T4);
        let mut provider = evm.provider_max_gas();

        let address = Address::random();
        let key = U256::from(100);
        let value = U256::from(12345);

        provider.sstore(address, key, value)?;
        assert_eq!(provider.sload(address, key)?, value);
        // second access should hit the warm path
        assert_eq!(provider.sload(address, key)?, value);
        Ok(())
    }

    #[test]
    fn test_with_account_info_t4_fork() -> eyre::Result<()> {
        // T4 fork with_account_info on a fresh account: zero balance/nonce.
        let mut evm = TestEvm::new(TempoHardfork::T4);
        let mut provider = evm.provider_max_gas();

        let mut account_nonce = u64::MAX;
        provider.with_account_info(Address::random(), &mut |info| {
            account_nonce = info.nonce;
            assert!(info.balance.is_zero());
        })?;

        assert_eq!(account_nonce, 0);
        Ok(())
    }

    #[test]
    fn test_sstore_sload_cold_storage_t4() -> eyre::Result<()> {
        // T4 fork cold/warm handling across multiple addresses.
        let mut evm = TestEvm::new(TempoHardfork::T4);
        let mut provider = evm.provider_max_gas();

        let addr1 = Address::random();
        let addr2 = Address::random();
        let key1 = U256::from(1);
        let key2 = U256::from(2);

        // Cold writes
        provider.sstore(addr1, key1, U256::from(100))?;
        provider.sstore(addr2, key2, U256::from(200))?;

        // Warm overwrites
        provider.sstore(addr1, key1, U256::from(110))?;
        provider.sstore(addr2, key2, U256::from(210))?;

        assert_eq!(provider.sload(addr1, key1)?, U256::from(110));
        assert_eq!(provider.sload(addr2, key2)?, U256::from(210));
        Ok(())
    }

    #[test]
    fn test_sload_insufficient_gas_for_cold_load_t4() -> eyre::Result<()> {
        // T4 fork sload succeeds even when remaining gas can't cover the cold-load cost.
        let mut evm = TestEvm::new(TempoHardfork::T4);
        let address = Address::random();
        let key = U256::from(100);
        let value = U256::from(555);

        // Seed storage with abundant gas first.
        {
            let mut provider = evm.provider_max_gas();
            provider.sstore(address, key, value)?;
        }

        let gas_params = evm.ctx().cfg.gas_params.clone();
        let warm_read_gas = gas_params.warm_storage_read_cost();
        let dynamic_gas = 2_100u64;
        let gas_limit = warm_read_gas + dynamic_gas;

        let mut provider = evm.provider_with_gas_limit(gas_limit, 0);
        let initial_gas = provider.gas_used();

        assert_eq!(provider.sload(address, key)?, value);
        assert!(
            provider.gas_used() > initial_gas,
            "sload should consume gas"
        );
        Ok(())
    }

    #[test]
    fn test_with_account_info_insufficient_gas_for_cold_load_t4() -> eyre::Result<()> {
        // T4 fork with_account_info under a tight gas budget.
        let mut evm = TestEvm::new(TempoHardfork::T4);
        let gas_params = evm.ctx().cfg.gas_params.clone();

        let static_gas = gas_params.sstore_static_gas();
        let gas_limit = static_gas + 10_000u64;

        let mut provider = evm.provider_with_gas_limit(gas_limit, 0);
        let initial_gas = provider.gas_used();

        let mut retrieved_nonce = u64::MAX;
        provider.with_account_info(Address::random(), &mut |info| {
            retrieved_nonce = info.nonce;
        })?;

        assert_eq!(retrieved_nonce, 0);
        assert!(
            provider.gas_used() > initial_gas,
            "with_account_info should consume gas"
        );
        Ok(())
    }
}
