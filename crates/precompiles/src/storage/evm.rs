use crate::{
    configurable_account::CONFIGURABLE_ACCOUNT_CODE,
    error::TempoPrecompileError,
    storage::{
        CallOutcome, ConfigCommitmentWriteGas, GasCheckpoint, PrecompileStorageProvider,
        StorageActions, StorageCheckpoint, account_config_commitment, actions::StorageAction,
    },
    storage_credits::{NonCreditableSlots, StorageCreditsBackend, sstore_storage_credits},
};
use alloy::primitives::{Address, B256, Bytes, Log, LogData, U256};
use bitflags::bitflags;
use evm2::{
    Evm, EvmFeatures, EvmTypes, ExecutionError, HostError, Version,
    bytecode::Bytecode,
    evm::{AccountExtension, AccountInfo, SLoad, SStore},
    interpreter::{GasTracker, Host, InstrStop, MessageExt, MessageKind, gas},
    version::{GasId, GasParams},
};
use std::{
    cell::{Cell, RefCell},
    ops::{Deref, DerefMut},
    rc::Rc,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_primitives::{
    TempoBlockEnv, TempoBlockExt, TempoEvmKind, account::encode_config_commitment,
};

/// Limit on the nested calls ([`PrecompileStorageProvider::call`]) running at once, each of which
/// recurses on the native stack. Only a hardfork may change it once a precompile makes them.
pub const MAX_NESTED_CALLS: u16 = 8;

/// Production [`PrecompileStorageProvider`] backed by EVM2's live transaction state.
///
/// Wraps [`evm2::evm::State`] and tracks gas consumption for storage operations.
pub struct EvmPrecompileStorageProvider<'evm, 'gas, 'db, T: EvmTypes> {
    evm: &'evm mut Evm<'db, T>,
    version: Version,
    gas_tracker: GasTrackerStorage<'gas>,
    spec: TempoHardfork,
    is_static: bool,
    tip1060_storage_credits_enabled: bool,
    tip1060_storage_credit_minting_enabled: bool,
    non_creditable_slots: Option<Rc<RefCell<NonCreditableSlots>>>,
    /// Recorded storage actions.
    actions: StorageActions,
    /// Charge every SLOAD as cold, so gas does not reveal which slots were already warm.
    cold_pricing: bool,
    /// The precompile call frame that nested calls start from, if the provider serves one.
    frame: Option<Frame>,
    /// Checkpoints taken and not yet committed or reverted, during which nested calls are refused.
    open_checkpoints: u32,
}

impl<'evm, 'gas, 'db, T> EvmPrecompileStorageProvider<'evm, 'gas, 'db, T>
where
    T: EvmTypes<BlockEnvExt = TempoBlockExt>,
    T::EvmExt: EvmStorageExt,
{
    /// Creates a storage provider over EVM2's live state and gas tracker.
    pub fn new(
        evm: &'evm mut Evm<'db, T>,
        gas_tracker: &'gas mut GasTracker,
        spec: TempoHardfork,
        is_static: bool,
    ) -> Self {
        Self::with_gas_tracker(
            evm,
            GasTrackerStorage::Borrowed(gas_tracker),
            spec,
            is_static,
        )
    }

    /// Creates a non-static storage provider with the maximum gas limit.
    pub fn new_max_gas(evm: &'evm mut Evm<'db, T>, spec: TempoHardfork) -> Self {
        Self::with_gas_tracker(
            evm,
            GasTrackerStorage::Owned(GasTracker::new(u64::MAX)),
            spec,
            false,
        )
    }

    fn with_gas_tracker(
        evm: &'evm mut Evm<'db, T>,
        gas_tracker: GasTrackerStorage<'gas>,
        spec: TempoHardfork,
        is_static: bool,
    ) -> Self {
        Self {
            version: *evm.version(),
            evm,
            gas_tracker,
            spec,
            is_static,
            tip1060_storage_credits_enabled: spec.is_t7(),
            tip1060_storage_credit_minting_enabled: true,
            non_creditable_slots: None,
            actions: StorageActions::disabled(),
            cold_pricing: false,
            frame: None,
            open_checkpoints: 0,
        }
    }

    /// Sets the precompile call frame, without which [`PrecompileStorageProvider::call`] fails.
    pub(crate) fn with_frame(mut self, frame: Frame) -> Self {
        self.frame = Some(frame);
        self
    }

    /// Sets the storage actions for this provider.
    pub fn with_actions(mut self, actions: StorageActions) -> Self {
        self.actions = actions;
        self
    }

    /// Overrides the gas parameter table used by this storage provider.
    pub fn with_gas_params(mut self, gas_params: GasParams) -> Self {
        self.version.gas_params = gas_params;
        self
    }

    /// Sets the transaction-local non-creditable clear-slot context for this provider.
    pub fn with_non_creditable_slots(mut self, slots: Rc<RefCell<NonCreditableSlots>>) -> Self {
        self.non_creditable_slots = Some(slots);
        self
    }

    /// Counts a checkpoint as closed by a commit or revert.
    fn close_checkpoint(&mut self) {
        self.open_checkpoints = self
            .open_checkpoints
            .checked_sub(1)
            .expect("every checkpoint commit or revert closes a checkpoint taken earlier");
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
    fn ensure_not_static(&self) -> Result<(), TempoPrecompileError> {
        match self.is_static {
            false => Ok(()),
            true => Err(TempoPrecompileError::StaticCallNotAllowed),
        }
    }

    #[inline]
    fn deduct_state_gas(&mut self, gas: u64) -> Result<(), TempoPrecompileError> {
        self.gas_tracker.deduct_state_gas(gas)
    }

    /// Performs a raw journaled SLOAD without metering gas or recording a storage action.
    #[inline]
    fn sload_journal(
        &mut self,
        address: Address,
        key: U256,
        skip_cold_load: bool,
    ) -> Result<SLoad, TempoPrecompileError> {
        let mut account = self
            .evm
            .state_mut()
            .account_with_skip(&address, skip_cold_load && self.spec.is_t15())?;
        account.warm();
        let storage = account.storage();
        let (slot, is_cold) = if self.version.feature(EvmFeatures::EIP2929) {
            storage.into_slot_with_skip_and_warm(key, skip_cold_load)?
        } else {
            (storage.into_slot_with_skip(key, skip_cold_load)?, false)
        };
        Ok(SLoad {
            value: slot.current(),
            is_cold,
            _non_exhaustive: (),
        })
    }

    /// Performs a raw journaled SSTORE without metering gas or recording a storage action.
    #[inline]
    fn sstore_journal(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
        skip_cold_load: bool,
    ) -> Result<SStore, TempoPrecompileError> {
        self.ensure_not_static()?;
        let mut account = self
            .evm
            .state_mut()
            .account_with_skip(&address, skip_cold_load && self.spec.is_t15())?;
        account.warm();
        let storage = account.storage();
        let (mut slot, is_cold) = if self.version.feature(EvmFeatures::EIP2929) {
            storage.into_slot_with_skip_and_warm(key, skip_cold_load)?
        } else {
            (storage.into_slot_with_skip(key, skip_cold_load)?, false)
        };
        let (original_value, present_value) = slot.write(value);
        Ok(SStore {
            original_value,
            present_value,
            new_value: value,
            is_cold,
            _non_exhaustive: (),
        })
    }

    /// Performs a metered precompile SLOAD, optionally recording the storage action.
    #[inline]
    fn sload_inner(
        &mut self,
        address: Address,
        key: U256,
        record: bool,
    ) -> Result<U256, TempoPrecompileError> {
        let additional_cost = self
            .version
            .gas_params
            .get(GasId::ColdStorageAdditionalCost);

        // T4+: pre-charge static gas to avoid cheap useless work.
        let skip_cold_load = if self.spec.is_t4() {
            self.deduct_gas(self.version.gas_params.get(GasId::WarmStorageReadCost))?;
            self.gas_tracker.remaining() < additional_cost
        } else {
            false
        };

        let result = self.sload_journal(address, key, skip_cold_load)?;
        if record {
            self.actions
                .record(StorageAction::Sload(address, key, result.value));
        }

        if !self.spec.is_t4() {
            self.deduct_gas(self.version.gas_params.get(GasId::WarmStorageReadCost))?;
        }

        // dynamic gas
        if result.is_cold || self.cold_pricing {
            self.deduct_gas(additional_cost)?;
        }

        Ok(result.value)
    }

    /// Performs a metered precompile SSTORE and records `action` before storage-credit bookkeeping.
    #[inline]
    fn sstore_inner(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
        action: impl FnOnce(&SStore) -> StorageAction,
    ) -> Result<(), TempoPrecompileError> {
        // T12+: EIP-2200 sentry. SSTORE fails if the frame only has the call stipend remaining.
        if self.spec.is_t12()
            && self.gas_tracker.remaining() <= self.gas_params().get(GasId::CallStipend)
        {
            return Err(TempoPrecompileError::OutOfGas);
        }

        // T4+: pre-charge static gas before loading storage to avoid cheap useless work.
        let skip_cold_load = if self.spec.is_t4() {
            self.deduct_gas(self.version.gas_params.get(GasId::SstoreStatic))?;
            self.gas_tracker.remaining()
                < self
                    .version
                    .gas_params
                    .get(GasId::ColdStorageAdditionalCost)
        } else {
            false
        };

        let result = self.sstore_journal(address, key, value, skip_cold_load)?;
        self.actions.record(action(&result));

        if !self.spec.is_t4() {
            self.deduct_gas(self.version.gas_params.get(GasId::SstoreStatic))?;
        }

        let dynamic_gas = self.version.gas_params.sstore_dynamic_gas(true, &result);
        let state_gas = self.state_gas_enabled();
        if state_gas {
            // Charge execution gas before the storage-credit hook charges state gas.
            self.deduct_gas(dynamic_gas)?;
        }

        // TIP-1060 (T7+): run the storage credits policy so precompile-driven storage
        // writes honor the same accounting as the opcode-level SSTORE hook.
        // Its settlement replaces EIP-8037's immediate slot-restoration refill.
        if self.tip1060_storage_credits_enabled {
            sstore_storage_credits(self, address, Some(key), &result)?
        }

        if !state_gas {
            self.deduct_gas(dynamic_gas)?;
        }

        // Native precompile storage did not surface SSTORE refunds before TIP-1016.
        if self.spec.is_t4() {
            self.refund_gas(self.version.gas_params.sstore_refund(true, &result));
        }

        Ok(())
    }

    #[inline]
    fn with_loaded_account<R>(
        &mut self,
        address: Address,
        f: impl FnOnce(&AccountInfo, Bytecode) -> R,
    ) -> Result<R, TempoPrecompileError> {
        let additional_cost = self.version.gas_params.cold_account_additional_cost();

        // T4+: pre-charge static gas to avoid cheap useless work.
        let warm_storage_read_cost = self.version.gas_params.get(GasId::WarmStorageReadCost);
        let insufficient_gas_for_cold_load = if self.spec.is_t4() {
            self.deduct_gas(warm_storage_read_cost)?;
            self.gas_tracker.remaining() < additional_cost
        } else {
            false
        };

        let mut account = self
            .evm
            .state_mut()
            .account_with_skip(&address, insufficient_gas_for_cold_load)?;
        let is_cold = self.version.feature(EvmFeatures::EIP2929) && account.warm();

        if !self.spec.is_t4() {
            self.gas_tracker.deduct_gas(warm_storage_read_cost)?;
        }

        if is_cold {
            self.gas_tracker.deduct_gas(additional_cost)?;
        }

        let code = account.load_code()?;

        let default = AccountInfo::default();
        Ok(f(account.get().unwrap_or(&default), code))
    }
}

impl<T> StorageCreditsBackend for EvmPrecompileStorageProvider<'_, '_, '_, T>
where
    T: EvmTypes<BlockEnvExt = TempoBlockExt>,
    T::EvmExt: EvmStorageExt,
{
    type Error = TempoPrecompileError;

    #[inline]
    fn gas_params(&self) -> &GasParams {
        &self.version.gas_params
    }

    #[inline]
    fn state_gas_enabled(&self) -> bool {
        self.version.feature(EvmFeatures::EIP8037)
    }

    #[inline]
    fn gas_tracker(&mut self) -> &mut GasTracker {
        &mut self.gas_tracker
    }

    #[inline]
    fn sload(
        &mut self,
        address: Address,
        key: U256,
        skip_cold_load: bool,
    ) -> Result<SLoad, Self::Error> {
        let value = self.sload_journal(address, key, skip_cold_load)?;
        self.actions
            .record_always(StorageAction::Sload(address, key, value.value));
        Ok(value)
    }

    #[inline]
    fn sstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
        skip_cold_load: bool,
    ) -> Result<SstoreTransitionFlags, Self::Error> {
        let result = self.sstore_journal(address, key, value, skip_cold_load)?;
        self.actions.record_always(StorageAction::Sstore(
            address,
            key,
            result.present_value,
            value,
        ));
        Ok(result.into())
    }

    #[inline]
    fn tload(&mut self, address: Address, key: U256) -> U256 {
        self.evm.state_mut().tload(&address, &key)
    }

    #[inline]
    fn tstore(&mut self, address: Address, key: U256, value: U256) -> Result<(), Self::Error> {
        self.ensure_not_static()?;
        self.evm.state_mut().tstore(&address, &key, &value);
        Ok(())
    }

    #[inline]
    fn is_non_creditable_slot(&mut self, owner: Address, key: U256) -> bool {
        self.non_creditable_slots
            .as_ref()
            .is_some_and(|slots| slots.borrow().is_non_creditable_slot(owner, key))
    }

    #[inline]
    fn tip1060_storage_credit_minting_enabled(&self) -> bool {
        self.tip1060_storage_credit_minting_enabled
    }
}

impl<T> PrecompileStorageProvider for EvmPrecompileStorageProvider<'_, '_, '_, T>
where
    T: EvmTypes<BlockEnvExt = TempoBlockExt>,
    T::EvmExt: EvmStorageExt,
{
    fn chain_id(&self) -> u64 {
        self.version.chain_id
    }

    fn block_env(&self) -> &TempoBlockEnv {
        self.evm.block()
    }

    #[inline]
    fn set_code(&mut self, address: Address, code: Bytes) -> Result<(), TempoPrecompileError> {
        self.ensure_not_static()?;
        let code = Bytecode::new_raw(code);
        let code_len = code.len();
        let mut execution_gas = self
            .version
            .gas_params
            .get(GasId::CodeDepositCost)
            .saturating_mul(code_len as u64);
        let state_gas = self.state_gas_enabled();
        if state_gas {
            execution_gas =
                execution_gas.saturating_add(self.version.gas_params.keccak256_word_cost(code_len));
        }
        self.deduct_gas(execution_gas)?;

        let was_empty = {
            let mut account = self.evm.state_mut().account(&address)?;
            account.warm();
            let was_empty = account.get().is_none_or(AccountInfo::is_empty);
            account.set_code_slow(code);
            was_empty
        };

        if state_gas {
            // Finish charging execution work before drawing on the state reservoir.
            if was_empty {
                self.deduct_gas(self.version.gas_params.get(GasId::Create))?;
                self.deduct_state_gas(self.version.gas_params.create_state_gas())?;
            }
            self.deduct_state_gas(self.version.gas_params.code_deposit_state_gas(code_len))?;
        }

        Ok(())
    }

    #[inline]
    fn with_account_info(
        &mut self,
        address: Address,
        f: &mut dyn FnMut(&AccountInfo),
    ) -> Result<(), TempoPrecompileError> {
        self.with_loaded_account(address, |info, _| f(info))
    }

    fn with_warm_caller_info(
        &mut self,
        address: Address,
        f: &mut dyn FnMut(&AccountInfo),
    ) -> Result<(), TempoPrecompileError> {
        // The provider has no transaction origin; the caller check is the call site's.
        let account = self
            .evm
            .state_mut()
            .account_with_skip(&address, true)
            .map_err(|error| {
                TempoPrecompileError::Fatal(format!(
                    "caller account must already be warm: {error:?}"
                ))
            })?;
        let default = AccountInfo::default();
        f(account.get().unwrap_or(&default));
        Ok(())
    }

    #[inline]
    fn sstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
    ) -> Result<(), TempoPrecompileError> {
        self.ensure_not_static()?;

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
        self.ensure_not_static()?;

        let current = self.sload_inner(address, key, false)?;
        let value = current
            .checked_add(delta)
            .ok_or_else(TempoPrecompileError::under_overflow)?;

        // If the value goes from zero to non-zero, do not record it as `Sinc`,
        // because it requires special TIP-1060 gas credits accounting.
        let sstore_action = if current.is_zero() && !value.is_zero() {
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
        self.ensure_not_static()?;

        let current = self.sload_inner(address, key, false)?;
        let value = current
            .checked_sub(delta)
            .ok_or_else(|| TempoPrecompileError::storage_delta_underflow(current))?;

        // If the value goes from non-zero to zero, do not record it as `Sdec`,
        // because it requires special TIP-1060 gas credits accounting.
        let sstore_action = if !current.is_zero() && value.is_zero() {
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
        self.ensure_not_static()?;

        self.deduct_gas(self.version.gas_params.get(GasId::WarmStorageReadCost))?;
        self.evm.state_mut().tstore(&address, &key, &value);
        Ok(())
    }

    #[inline]
    fn emit_event(&mut self, address: Address, event: LogData) -> Result<(), TempoPrecompileError> {
        self.ensure_not_static()?;

        self.deduct_gas(
            u64::from(gas::LOG).saturating_add(
                self.version
                    .gas_params
                    .log_cost(event.topics().len() as u8, event.data.len()),
            ),
        )?;

        self.evm.log(Log {
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
        self.deduct_gas(self.version.gas_params.get(GasId::WarmStorageReadCost))?;
        Ok(self.evm.state_mut().tload(&address, &key))
    }

    #[inline]
    fn deduct_gas(&mut self, gas: u64) -> Result<(), TempoPrecompileError> {
        self.gas_tracker.deduct_gas(gas)
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
        self.gas_tracker.spent()
    }

    #[inline]
    fn state_gas_used(&self) -> i64 {
        self.gas_tracker.state_gas_spent()
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
    fn amsterdam_eip8037_enabled(&self) -> bool {
        self.version.feature(EvmFeatures::EIP8037)
    }

    #[inline]
    fn is_static(&self) -> bool {
        self.is_static
    }

    fn set_cold_pricing(&mut self, enabled: bool) -> bool {
        core::mem::replace(&mut self.cold_pricing, enabled)
    }

    fn call_frame_address(&self) -> Option<Address> {
        self.frame.as_ref().map(|frame| frame.address)
    }

    fn call(
        &mut self,
        target: Address,
        input: Bytes,
        gas_limit: u64,
        is_static: bool,
    ) -> Result<CallOutcome, TempoPrecompileError> {
        // A refusal fails the precompile call: as a failed callee, it would let whoever nests the
        // calls pick the path the precompile takes. Inside a checkpoint, a revert would roll back a
        // successful callee's state but not the gas and refund it merged, so calls are refused
        // there: like the EVM, only a whole frame reverts after a call.
        let frame = match &self.frame {
            Some(frame)
                if self.open_checkpoints == 0 && frame.nested_calls.get() < MAX_NESTED_CALLS =>
            {
                frame.clone()
            }
            _ => return Err(TempoPrecompileError::NestedCallUnavailable),
        };
        // The callee's storage accesses are not recorded as storage actions.
        self.actions.mark_unreplayable();

        let mut message = MessageExt {
            kind: if is_static {
                MessageKind::StaticCall
            } else {
                MessageKind::Call
            },
            // The EVM runs no frame past its call depth limit, so this cannot overflow.
            depth: frame.depth + 1,
            gas_limit,
            destination: target,
            call_target: target,
            caller: frame.address,
            input: input.into(),
            caller_is_static: self.is_static,
            ..Default::default()
        };
        frame.nested_calls.set(frame.nested_calls.get() + 1);
        let running = RunningNestedCall(frame.nested_calls);
        // Charges and forwards gas as `CALL` does, and rolls back a failed callee.
        let result = self.evm.execute_call(&mut self.gas_tracker, &mut message);
        drop(running);
        let result = result.map_err(|error| match error {
            HostError::Halt(stop) if stop.is_fatal() => {
                TempoPrecompileError::Fatal(format!("nested call stopped fatally: {stop:?}"))
            }
            HostError::Halt(stop) if stop.is_out_of_gas() => TempoPrecompileError::OutOfGas,
            HostError::Halt(
                InstrStop::StateChangeDuringStaticCall | InstrStop::CallNotAllowedInsideStatic,
            ) => TempoPrecompileError::StaticCallNotAllowed,
            HostError::Halt(stop) => TempoPrecompileError::NestedCallHalted(stop),
            HostError::Execution(ExecutionError::Database(error)) => {
                TempoPrecompileError::Database(error)
            }
            HostError::Execution(ExecutionError::Fatal(error)) => {
                TempoPrecompileError::Fatal(error.to_string())
            }
        })?;
        if !result.is_success() {
            return Ok(CallOutcome::Failure(result.output));
        }
        Ok(CallOutcome::Success(result.output))
    }

    #[inline]
    fn checkpoint(&mut self) -> StorageCheckpoint {
        self.open_checkpoints += 1;
        StorageCheckpoint {
            state: self.evm.state_mut().checkpoint(),
            gas: self
                .version
                .feature(EvmFeatures::EIP8037)
                .then_some(GasCheckpoint {
                    state_gas_spent: self.gas_tracker.state_gas_spent(),
                    refunded: self.gas_tracker.refunded(),
                }),
        }
    }

    #[inline]
    fn checkpoint_commit(&mut self, _checkpoint: StorageCheckpoint) {
        self.close_checkpoint();
    }

    #[inline]
    fn checkpoint_revert(&mut self, checkpoint: StorageCheckpoint) {
        self.close_checkpoint();
        if let Some(gas) = checkpoint.gas {
            // TIP-1060 only refills state gas at transaction settlement, so
            // state spending within a native checkpoint is nonnegative.
            let state = u64::try_from(self.gas_tracker.state_gas_spent() - gas.state_gas_spent)
                .expect("native checkpoint cannot settle storage credits");
            self.gas_tracker.refill_reservoir(state);
            self.gas_tracker.set_refunded(gas.refunded);
        }
        self.evm
            .state_mut()
            .rollback(checkpoint.state, self.version.features);
    }

    #[inline]
    fn set_tip1060_storage_credits(&mut self, enabled: bool) {
        self.tip1060_storage_credits_enabled = enabled && self.spec.is_t7();
    }

    #[inline]
    fn set_tip1060_storage_credit_minting(&mut self, enabled: bool) {
        self.tip1060_storage_credit_minting_enabled = enabled;
    }

    #[inline]
    fn kind(&self) -> TempoEvmKind {
        self.evm.ext().kind()
    }

    #[inline]
    fn config_commitment(&mut self, address: Address) -> Result<B256, TempoPrecompileError> {
        let spec = self.spec;
        self.with_loaded_account(address, |info, _| account_config_commitment(info, spec))?
    }

    fn set_config_commitment(
        &mut self,
        address: Address,
        commitment: B256,
        gas: ConfigCommitmentWriteGas,
    ) -> Result<(), TempoPrecompileError> {
        // Reject before any read or gas charge, so a rejected write is never charged.
        if !self.spec.is_t14() || self.is_static || commitment.is_zero() {
            return Err(TempoPrecompileError::InvalidConfigCommitmentWrite);
        }
        self.deduct_gas(gas.static_cost())?;
        // The authorization read already charged account access (or was intrinsic).
        let spec = self.spec;
        let (previous, creates_account) = {
            let account = self.evm.state_mut().account(&address)?;
            match account.get() {
                Some(info) => (account_config_commitment(info, spec)?, info.is_empty()),
                None => (B256::ZERO, true),
            }
        };
        self.deduct_gas(gas.dynamic_cost(previous, &self.version.gas_params)?)?;
        self.deduct_state_gas(gas.state_cost(previous, &self.version.gas_params))?;
        // The write makes an empty account permanent; an intrinsic write was priced with the
        // transaction, creation included.
        if creates_account && gas == ConfigCommitmentWriteGas::Precompile {
            self.deduct_gas(self.version.gas_params.get(GasId::NewAccountCost))?;
            self.deduct_state_gas(self.version.gas_params.new_account_state_gas())?;
        }
        let mut account = self.evm.state_mut().account(&address)?;
        if previous.is_zero() {
            // Registration and migration pay for the commitment write, including this marker.
            account.set_code_slow(Bytecode::new_raw(CONFIGURABLE_ACCOUNT_CODE));
        }
        account.set_extension(AccountExtension::from(encode_config_commitment(commitment)));
        self.actions.record_always(StorageAction::ConfigCommitment(
            address, previous, commitment,
        ));
        Ok(())
    }
}

/// Extension state required by an EVM-backed precompile storage context.
pub trait EvmStorageExt {
    /// Returns the storage action recorder.
    fn storage_actions(&self) -> StorageActions;

    /// Returns the transaction-local non-creditable slots.
    fn non_creditable_slots(&self) -> Rc<RefCell<NonCreditableSlots>>;

    /// Returns the kind of the EVM, whose rules every storage context over it follows.
    fn kind(&self) -> TempoEvmKind;
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

impl From<&SStore> for SstoreTransitionFlags {
    fn from(result: &SStore) -> Self {
        Self::from_values(
            result.original_value,
            result.present_value,
            result.new_value,
        )
    }
}

impl From<SStore> for SstoreTransitionFlags {
    fn from(result: SStore) -> Self {
        Self::from(&result)
    }
}

/// The precompile call frame an [`EvmPrecompileStorageProvider`] serves.
#[derive(Debug, Clone)]
pub(crate) struct Frame {
    /// The precompile's address, which its callees see as their caller.
    pub(crate) address: Address,
    /// The precompile's call depth.
    pub(crate) depth: u16,
    /// Count of the running nested calls, shared by the frames of a precompile provider.
    pub(crate) nested_calls: Rc<Cell<u16>>,
}

/// Counts a nested call as running until dropped, also when the callee unwinds.
struct RunningNestedCall(Rc<Cell<u16>>);

impl Drop for RunningNestedCall {
    fn drop(&mut self) {
        self.0.set(self.0.get() - 1);
    }
}

enum GasTrackerStorage<'a> {
    Borrowed(&'a mut GasTracker),
    Owned(GasTracker),
}

impl GasTrackerStorage<'_> {
    #[inline]
    fn deduct_gas(&mut self, gas: u64) -> Result<(), TempoPrecompileError> {
        if self.remaining() < gas {
            Err(TempoPrecompileError::OutOfGas)
        } else {
            self.spend(gas).map_err(|_| TempoPrecompileError::OutOfGas)
        }
    }

    #[inline]
    fn deduct_state_gas(&mut self, gas: u64) -> Result<(), TempoPrecompileError> {
        let spill = gas.saturating_sub(self.reservoir());
        if self.remaining() < spill {
            Err(TempoPrecompileError::OutOfGas)
        } else {
            self.spend_state(gas)
                .map_err(|_| TempoPrecompileError::OutOfGas)
        }
    }
}

impl Deref for GasTrackerStorage<'_> {
    type Target = GasTracker;

    #[inline]
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(gas_tracker) => gas_tracker,
            Self::Owned(gas_tracker) => gas_tracker,
        }
    }
}

impl DerefMut for GasTrackerStorage<'_> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Borrowed(gas_tracker) => gas_tracker,
            Self::Owned(gas_tracker) => gas_tracker,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EvmPrecompileStorageProvider, EvmStorageExt, Frame, GasTrackerStorage, MAX_NESTED_CALLS,
    };
    use crate::{
        STORAGE_CREDITS_ADDRESS,
        error::TempoPrecompileError,
        storage::{CallOutcome, PrecompileStorageProvider, StorageActions, actions::StorageAction},
        storage_credits::{NonCreditableSlots, StorageCredits},
    };
    use alloy::primitives::{
        Address, B256, Bytes, KECCAK256_EMPTY, Log, LogData, U256, bytes, keccak256,
    };
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use evm2::{
        BaseEvmConfigSelector, Evm, EvmTypesHost, ExecutionConfig, SpecId, Version,
        bytecode::Bytecode,
        evm::{
            AccountInfo, InMemoryDB,
            precompile::{NoPrecompiles, PrecompileOutput},
        },
        interpreter::{GasTracker, Host, InstrStop, Message, MessageKind},
        precompiles::{
            Precompile, PrecompileError, PrecompileId, PrecompileMap, PrecompileResult, Precompiles,
        },
        registry::TxRegistry,
        utils::b256_to_word,
        version::{GasId, GasParams},
    };
    use std::{
        borrow::Cow,
        cell::{Cell, RefCell},
        rc::Rc,
    };
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_primitives::{TempoBlockEnv, TempoBlockExt, TempoEvmKind};

    /// The precompile whose call frame the nested-call tests run in.
    const CALLING_PRECOMPILE: Address = Address::repeat_byte(0x7e);
    /// The contract the nested-call tests call.
    const CALLEE: Address = Address::repeat_byte(0xc0);

    struct TestTypes;

    /// Unit-test EVMs without extension state record no storage actions and execute Tempo L1.
    impl EvmStorageExt for () {
        fn storage_actions(&self) -> StorageActions {
            StorageActions::disabled()
        }

        fn non_creditable_slots(&self) -> Rc<RefCell<NonCreditableSlots>> {
            Rc::new(RefCell::new(NonCreditableSlots::empty()))
        }

        fn kind(&self) -> TempoEvmKind {
            TempoEvmKind::L1
        }
    }

    impl EvmTypesHost for TestTypes {
        type ConfigSelector = BaseEvmConfigSelector;
        type SpecId = SpecId;
        type Tx = ();
        type EvmExt = ();
        type MessageExt = ();
        type MessageResultExt = ();
        type TxEnvExt = ();
        type TxResultExt = ();
        type BlockEnvExt = TempoBlockExt;
        type Host<'a> = Evm<'a, Self>;
    }

    struct TestEvm {
        evm: Evm<'static, TestTypes>,
        gas_tracker: GasTracker,
        version: Version,
        spec: TempoHardfork,
    }

    impl TestEvm {
        fn new(spec: TempoHardfork) -> Self {
            Self::with_database(spec, InMemoryDB::default())
        }

        fn with_storage(spec: TempoHardfork, address: Address, key: U256, value: U256) -> Self {
            let mut database = InMemoryDB::default();
            database.insert_account_info(&address, Default::default());
            database.insert_account_storage(&address, &key, &value);
            Self::with_database(spec, database)
        }

        fn with_database(spec: TempoHardfork, database: InMemoryDB) -> Self {
            let version = tempo_chainspec::gas_params::version(SpecId::OSAKA, spec, false);
            Self {
                evm: Evm::new_with_execution_config(
                    ExecutionConfig::for_spec_and_version(SpecId::OSAKA, version),
                    SpecId::OSAKA,
                    TempoBlockEnv::default(),
                    TxRegistry::new(),
                    database,
                    NoPrecompiles::default(),
                ),
                gas_tracker: GasTracker::new(u64::MAX),
                version,
                spec,
            }
        }

        fn provider_with_gas_limit(
            &mut self,
            gas_limit: u64,
            reservoir: u64,
        ) -> EvmPrecompileStorageProvider<'_, '_, 'static, TestTypes> {
            self.gas_tracker =
                GasTracker::new_with_execution_gas_and_reservoir(gas_limit, reservoir);
            EvmPrecompileStorageProvider::with_gas_tracker(
                &mut self.evm,
                GasTrackerStorage::Borrowed(&mut self.gas_tracker),
                self.spec,
                false,
            )
        }

        fn provider_with_reservoir(
            &mut self,
            reservoir: u64,
        ) -> EvmPrecompileStorageProvider<'_, '_, 'static, TestTypes> {
            self.provider_with_gas_limit(u64::MAX, reservoir)
        }

        fn provider_max_gas(&mut self) -> EvmPrecompileStorageProvider<'_, '_, 'static, TestTypes> {
            EvmPrecompileStorageProvider::with_gas_tracker(
                &mut self.evm,
                GasTrackerStorage::Owned(GasTracker::new(u64::MAX)),
                self.spec,
                false,
            )
        }

        fn static_provider(&mut self) -> EvmPrecompileStorageProvider<'_, '_, 'static, TestTypes> {
            EvmPrecompileStorageProvider::with_gas_tracker(
                &mut self.evm,
                GasTrackerStorage::Owned(GasTracker::new(u64::MAX)),
                self.spec,
                true,
            )
        }

        fn gas_params(&self) -> GasParams {
            self.version.gas_params
        }

        fn load_account_code(&mut self, address: Address) -> eyre::Result<Bytes> {
            let mut account = self
                .evm
                .state_mut()
                .account(&address)
                .map_err(|code| eyre::eyre!("failed to load account: {code:?}"))?;
            Ok(account
                .load_code()
                .map_err(|code| eyre::eyre!("failed to load account code: {code:?}"))?
                .original_bytes())
        }
    }

    impl Default for TestEvm {
        fn default() -> Self {
            Self::new(TempoHardfork::default())
        }
    }

    #[test]
    fn test_static_provider_mutation_guards() {
        use crate::storage_credits::StorageCreditsBackend;

        let mut evm = TestEvm::default();
        let mut provider = evm.static_provider();

        let (address, key, value) = (Address::ZERO, U256::ZERO, U256::ZERO);
        let results = [
            provider.set_code(address, Bytes::new()),
            PrecompileStorageProvider::sstore(&mut provider, address, key, value),
            PrecompileStorageProvider::tstore(&mut provider, address, key, value),
            StorageCreditsBackend::sstore(&mut provider, address, key, value, false).map(|_| ()),
            StorageCreditsBackend::tstore(&mut provider, address, key, value),
            provider.sinc(address, key, value),
            provider.sdec(address, key, value),
            provider.emit_event(address, LogData::new_unchecked(vec![], bytes!())),
        ];

        assert!(
            results
                .into_iter()
                .all(|result| { result == Err(TempoPrecompileError::StaticCallNotAllowed) })
        );
    }

    #[test]
    fn test_sstore_sload_actions_recording() -> eyre::Result<()> {
        let mut evm = TestEvm::default();
        let addr = Address::random();

        let mut provider = evm
            .provider_max_gas()
            .with_actions(StorageActions::enabled());

        let (k1, v1) = (U256::ONE, U256::from(10));
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
                StorageAction::Sstore(addr, k2, U256::ZERO, v2),
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
        provider.sstore(addr, U256::ONE, U256::from(100))?;
        let _ = provider.sload(addr, U256::ONE)?;

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
        let code = Bytes::from(vec![0xff]);

        provider.set_code(addr, code.clone())?;
        std::mem::drop(provider);

        let data = evm.load_account_code(addr)?;

        assert_eq!(data, code);
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
            assert_eq!(info.code_hash, KECCAK256_EMPTY);
        })?;

        Ok(())
    }

    #[test]
    fn test_failed_account_info_charge_preserves_remaining_gas_before_t4() -> eyre::Result<()> {
        let mut evm = TestEvm::new(TempoHardfork::T1);
        let address = Address::random();
        evm.evm.state_mut().prewarm(&address);

        let warm_storage_read_cost = evm.gas_params().get(GasId::WarmStorageReadCost);
        let mut provider =
            evm.provider_with_gas_limit(warm_storage_read_cost.saturating_sub(10), 0);

        assert_eq!(
            provider.with_account_info(address, &mut |_| {}),
            Err(TempoPrecompileError::OutOfGas)
        );
        assert_eq!(provider.gas_used(), 0);

        Ok(())
    }

    #[test]
    fn test_emit_event() -> eyre::Result<()> {
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_max_gas();

        let topic = B256::with_last_byte(1);
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
    fn test_sstore_reentrancy_sentry_blocks_dirty_write() -> eyre::Result<()> {
        for spec in [TempoHardfork::T11, TempoHardfork::T12] {
            let mut evm = TestEvm::new(spec);
            let gas_params = evm.version.gas_params;
            let address = Address::random();
            let key = U256::from(42);

            evm.provider_max_gas().sstore(address, key, U256::ONE)?;

            let result = evm
                .provider_with_gas_limit(gas_params.get(GasId::CallStipend), 0)
                .sstore(address, key, U256::from(2));

            let expected = if spec.is_t12() {
                assert_eq!(result, Err(TempoPrecompileError::OutOfGas));
                U256::ONE
            } else {
                result.expect("pre-T12 SSTORE at stipend should preserve historical behavior");
                U256::from(2)
            };

            assert_eq!(
                evm.provider_max_gas().sload(address, key)?,
                expected,
                "failed SSTORE must not mutate storage"
            );
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
    fn test_failed_gas_charges_preserve_remaining_gas() -> eyre::Result<()> {
        let mut evm = TestEvm::default();
        let mut provider = evm.provider_with_gas_limit(100, 0);

        assert_eq!(
            provider.deduct_gas(101),
            Err(TempoPrecompileError::OutOfGas)
        );
        assert_eq!(provider.gas_used(), 0);

        provider.deduct_gas(100)?;
        assert_eq!(provider.gas_used(), 100);
        std::mem::drop(provider);

        let mut provider = evm.provider_with_gas_limit(100, 50);
        assert_eq!(
            provider.deduct_state_gas(151),
            Err(TempoPrecompileError::OutOfGas)
        );
        assert_eq!(provider.gas_used(), 0);
        assert_eq!(provider.state_gas_used(), 0);
        assert_eq!(provider.reservoir(), 50);

        provider.deduct_state_gas(150)?;
        assert_eq!(provider.gas_used(), 100);
        assert_eq!(provider.state_gas_used(), 150);
        assert_eq!(provider.reservoir(), 0);
        std::mem::drop(provider);

        let mut provider = evm.provider_with_gas_limit(100, 0);
        assert_eq!(
            crate::storage_credits::StorageCreditsBackend::charge_gas(&mut provider, 101),
            Err(TempoPrecompileError::OutOfGas)
        );
        assert_eq!(provider.gas_used(), 0);

        crate::storage_credits::StorageCreditsBackend::charge_gas(&mut provider, 100)?;
        assert_eq!(provider.gas_used(), 100);

        Ok(())
    }

    #[test]
    fn test_storage_creation_oog_consumes_execution_gas_and_settles_state_gas() -> eyre::Result<()>
    {
        let mut evm = TestEvm::new(TempoHardfork::T15);
        let mut provider = evm.provider_with_gas_limit(100, 50);
        provider.deduct_state_gas(75)?;
        provider.refund_gas(5_000);

        assert_eq!(
            crate::storage_credits::StorageCreditsBackend::charge_storage_creation(&mut provider),
            Err(TempoPrecompileError::OutOfGas)
        );
        assert_eq!(provider.gas_tracker.remaining(), 0);
        assert_eq!(provider.state_gas_used(), 75);
        assert_eq!(provider.state_gas_spilled(), 25);
        assert_eq!(provider.reservoir(), 0);

        provider
            .gas_tracker
            .settle_gas(evm2::interpreter::InstrStop::OutOfGas);
        assert_eq!(provider.gas_tracker.remaining(), 0);
        assert_eq!(provider.state_gas_used(), 0);
        assert_eq!(provider.state_gas_spilled(), 0);
        assert_eq!(provider.reservoir(), 50);
        assert_eq!(provider.gas_refunded(), 0);
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
    fn test_state_gas_used_only_counts_state_creating_ops() -> eyre::Result<()> {
        let mut evm = TestEvm::new(TempoHardfork::T15);
        let gas_params = evm.gas_params();
        let mut provider = evm.provider_with_reservoir(0);

        let (address, code_address, slot) = (Address::random(), Address::random(), U256::ONE);

        // SLOADs should not add state gas
        provider.sload(address, slot)?;
        assert_eq!(
            provider.state_gas_used(),
            0,
            "SLOAD should not add state gas"
        );
        assert!(provider.gas_used() > 0, "SLOAD should consume regular gas");

        // SSTORE zero->non-zero should add state gas
        let gas_before = provider.gas_used();
        provider.sstore(address, slot, U256::ONE)?;
        let state_gas_after_set = provider.state_gas_used();
        assert_eq!(
            state_gas_after_set, 245_000,
            "SSTORE zero->non-zero should add 245k state gas"
        );
        assert!(
            provider.gas_used() > gas_before,
            "SSTORE should consume gas"
        );

        // SSTORE non-zero->non-zero should NOT add more state gas
        provider.sstore(address, slot, U256::from(2))?;
        assert_eq!(
            provider.state_gas_used(),
            state_gas_after_set,
            "SSTORE non-zero->non-zero should not add state gas"
        );

        // Code deposit should add state gas (2,300 per byte)
        let state_gas_before_code = provider.state_gas_used();
        provider.set_code(code_address, Bytes::from(vec![0xef]))?;
        assert_eq!(
            provider.state_gas_used(),
            state_gas_before_code
                + (gas_params.create_state_gas() + gas_params.code_deposit_state_gas(1)) as i64,
            "set_code(new account, 1 byte) should add CREATE state gas plus 2,300 code deposit state gas"
        );

        Ok(())
    }

    /// Tests that state gas (EIP-8037) is deducted from the reservoir first and
    /// spills into regular gas once the reservoir is exhausted.
    #[test]
    fn test_state_gas_spills_from_reservoir_to_regular_gas() -> eyre::Result<()> {
        let mut evm = TestEvm::new(TempoHardfork::T15);

        // Reservoir = 500k: enough for 2 full SSTOREs (2 × 245k = 490k)
        // but the 3rd SSTORE (245k) must spill 235k into regular gas.
        let gas_limit = 1_000_000u64;
        let reservoir = 500_000u64;
        let state_gas_per_sstore = 245_000u64;
        let mut provider = evm.provider_with_gas_limit(gas_limit, reservoir);
        let address = Address::random();

        // --- First SSTORE (zero→non-zero): fully covered by reservoir ---
        provider.sstore(address, U256::ONE, U256::from(42))?;

        let regular_gas_per_sstore = provider.gas_used() - 2_000; // Subsequent credit-slot loads are warm.
        assert_eq!(
            provider.state_gas_used(),
            state_gas_per_sstore as i64,
            "first SSTORE should consume 245k state gas"
        );
        assert_eq!(
            provider.reservoir(),
            reservoir - state_gas_per_sstore,
            "reservoir should decrease by state gas cost"
        );

        // --- Second SSTORE: still fits in remaining reservoir (255k left, need 245k) ---
        provider.sstore(address, U256::from(2), U256::from(43))?;

        assert_eq!(
            provider.state_gas_used(),
            2 * state_gas_per_sstore as i64,
            "two SSTOREs should consume 490k state gas"
        );
        assert_eq!(
            provider.reservoir(),
            reservoir - 2 * state_gas_per_sstore,
            "reservoir should have 10k left after 2 SSTOREs"
        );
        let remaining_reservoir = provider.reservoir(); // 10k
        let regular_gas_before_spill = provider.gas_used();

        // --- Third SSTORE: reservoir insufficient, 235k spills to regular gas ---
        provider.sstore(address, U256::from(3), U256::from(44))?;

        assert_eq!(
            provider.state_gas_used(),
            3 * state_gas_per_sstore as i64,
            "three SSTOREs should consume 735k state gas total"
        );
        assert_eq!(
            provider.reservoir(),
            0,
            "reservoir should be fully exhausted"
        );

        // Regular gas increase = normal sstore cost + spill from reservoir
        let spill = state_gas_per_sstore - remaining_reservoir; // 245k - 10k = 235k
        let expected_regular_after = regular_gas_before_spill + regular_gas_per_sstore + spill;
        assert_eq!(
            provider.gas_used(),
            expected_regular_after,
            "regular gas should include spill of {spill} from exhausted reservoir"
        );

        Ok(())
    }

    #[test]
    fn test_sstore_credit_price_changes_dimension_at_tip1016() -> eyre::Result<()> {
        for (spec, expected_execution, expected_state) in [
            (TempoHardfork::T7, 254_300, 0),
            (TempoHardfork::T13, 254_300, 0),
            (TempoHardfork::T14, 254_300, 0),
            (TempoHardfork::T15, 9_300, 245_000),
        ] {
            let mut evm = TestEvm::new(spec);
            let mut provider = evm.provider_with_reservoir(245_000);
            provider.sstore(Address::repeat_byte(0x22), U256::ZERO, U256::ONE)?;
            assert_eq!(provider.gas_used(), expected_execution, "{spec:?}");
            assert_eq!(provider.state_gas_used(), expected_state as i64, "{spec:?}");
            assert_eq!(provider.reservoir(), 245_000 - expected_state, "{spec:?}");
        }
        Ok(())
    }

    #[test]
    fn test_t15_cold_sstore_matches_tip1016_spec() -> eyre::Result<()> {
        let mut evm = TestEvm::new(TempoHardfork::T15);
        let mut provider = evm.provider_with_reservoir(490_000);

        let (address, cold_slot, warm_slot) = (Address::random(), U256::ONE, U256::from(2));

        provider.sstore(address, cold_slot, U256::ONE)?;
        assert_eq!(
            provider.gas_used(),
            9_300,
            "TIP-1016 cold SSTORE should consume 9,300 regular gas (100 static + 5,000 write + 2,100 Berlin cold-slot access + 2,100 cold credits-slot load)"
        );
        assert_eq!(
            provider.state_gas_used(),
            245_000,
            "TIP-1016 cold SSTORE should consume the 245,000 creditable portion as state gas"
        );

        provider.sload(address, warm_slot)?;
        let gas_before_warm_sstore = provider.gas_used();
        let state_gas_before_warm_sstore = provider.state_gas_used();

        provider.sstore(address, warm_slot, U256::ONE)?;
        assert_eq!(
            provider.gas_used() - gas_before_warm_sstore,
            5_200,
            "TIP-1016 warm zero-to-non-zero SSTORE should consume 5,200 regular gas (100 static + 5,000 write + 100 warm credits-slot load) after the slot is warmed by SLOAD"
        );
        assert_eq!(
            provider.state_gas_used() - state_gas_before_warm_sstore,
            245_000,
            "TIP-1016 warm zero-to-non-zero SSTORE should still consume 245,000 state gas"
        );

        Ok(())
    }

    #[test]
    fn test_t15_set_code_new_account_matches_tip1016_success_path() -> eyre::Result<()> {
        let mut evm = TestEvm::new(TempoHardfork::T15);
        let gas_params = evm.gas_params();

        let code = Bytes::from(vec![0xef]);
        let expected_state_gas =
            gas_params.create_state_gas() + gas_params.code_deposit_state_gas(code.len());
        let expected_regular_gas = gas_params.get(GasId::Create)
            + gas_params.get(GasId::CodeDepositCost) * code.len() as u64
            + gas_params.keccak256_word_cost(code.len());
        let mut provider = evm.provider_with_reservoir(expected_state_gas);

        provider.set_code(Address::random(), code)?;
        assert_eq!(
            provider.gas_used(),
            expected_regular_gas,
            "TIP-1016 CREATE success path should charge CREATE + code deposit"
        );
        assert_eq!(
            provider.state_gas_used(),
            expected_state_gas as i64,
            "set_code on a new account should charge CREATE state gas plus code deposit state gas"
        );

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
        let key1 = U256::ONE;
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
    fn test_sstore_with_limited_execution_gas_t15() -> eyre::Result<()> {
        // T15 SSTORE uses the reservoir for state gas and a limited execution budget.
        let mut evm = TestEvm::new(TempoHardfork::T15);
        let gas_params = evm.gas_params();

        let static_gas = gas_params.get(GasId::SstoreStatic);
        let dynamic_gas = 25_000u64;
        let gas_limit = static_gas + dynamic_gas;

        // Generous reservoir so T15 state-gas (zero->non-zero) doesn't spill into regular gas.
        let mut provider = evm.provider_with_gas_limit(gas_limit, u64::MAX);

        let initial_gas = provider.gas_used();
        let address = Address::random();
        let key = U256::from(42);
        let value = U256::from(999);

        provider.sstore(address, key, value)?;
        let gas_after_sstore = provider.gas_used();
        assert!(gas_after_sstore > initial_gas, "sstore should consume gas");

        assert_eq!(provider.sload(address, key)?, value);
        assert!(
            provider.gas_used() > gas_after_sstore,
            "sload should consume additional gas"
        );
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

        let gas_params = evm.gas_params();
        let warm_read_gas = gas_params.get(GasId::WarmStorageReadCost);
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
        let gas_params = evm.gas_params();

        let static_gas = gas_params.get(GasId::SstoreStatic);
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

    #[test]
    fn test_multiple_sstore_with_limited_execution_gas_t15() -> eyre::Result<()> {
        // T15 multiple SSTOREs under a constrained execution gas budget.
        let mut evm = TestEvm::new(TempoHardfork::T15);
        let gas_params = evm.gas_params();

        let static_gas = gas_params.get(GasId::SstoreStatic);
        let dynamic_gas = 20_000u64;
        let gas_per_sstore = static_gas + dynamic_gas;
        let gas_limit = gas_per_sstore * 3;

        let mut provider = evm.provider_with_gas_limit(gas_limit, u64::MAX);
        let address = Address::random();
        let mut prev_gas = provider.gas_used();

        for i in 0..3 {
            provider.sstore(address, U256::from(i), U256::from(i * 1000))?;
            let current_gas = provider.gas_used();
            assert!(
                current_gas > prev_gas,
                "each sstore should increase gas usage"
            );
            prev_gas = current_gas;
        }

        for i in 0..3 {
            assert_eq!(
                provider.sload(address, U256::from(i))?,
                U256::from(i * 1000)
            );
        }
        Ok(())
    }

    #[test]
    fn test_checkpoints_commit_and_revert_storage() -> eyre::Result<()> {
        let mut evm = TestEvm::new(TempoHardfork::T4);
        let mut provider = evm.provider_max_gas();
        let address = Address::repeat_byte(0x22);
        let key = U256::from(1);

        provider.sstore(address, key, U256::from(1))?;
        let checkpoint = provider.checkpoint();
        provider.sstore(address, key, U256::from(2))?;
        provider.checkpoint_revert(checkpoint);
        assert_eq!(provider.sload(address, key)?, U256::from(1));

        let checkpoint = provider.checkpoint();
        provider.sstore(address, key, U256::from(3))?;
        provider.checkpoint_commit(checkpoint);
        assert_eq!(provider.sload(address, key)?, U256::from(3));
        Ok(())
    }

    #[test]
    fn test_native_checkpoints_match_frame_gas_settlement() -> eyre::Result<()> {
        fn write(
            storage: &mut EvmPrecompileStorageProvider<'_, '_, '_, TestTypes>,
            address: Address,
            slot: u64,
            execution_gas: u64,
            state_gas: u64,
            refund: i64,
        ) {
            storage.deduct_gas(execution_gas).unwrap();
            storage.deduct_state_gas(state_gas).unwrap();
            storage.refund_gas(refund);
            // Journal changes independently of gas pricing to isolate checkpoint accounting.
            crate::storage_credits::StorageCreditsBackend::sstore(
                storage,
                address,
                U256::from(slot),
                U256::ONE,
                false,
            )
            .unwrap();
            crate::storage_credits::StorageCreditsBackend::tstore(
                storage,
                address,
                U256::from(slot),
                U256::ONE,
            )
            .unwrap();
            storage.evm.log(Log {
                address,
                data: LogData::default(),
            });
        }

        fn run(
            evm: &mut Evm<'_, TestTypes>,
            message: &Message<TestTypes>,
            gas: &mut GasTracker,
        ) -> PrecompileResult {
            let address = message.destination;
            let input = evm.message_input(message);
            let commit = input[0] != 0;
            let ending = input[1];
            let refund = if input[2] == 0 { 400 } else { -1_400 };
            let mut storage =
                EvmPrecompileStorageProvider::new(evm, gas, TempoHardfork::T15, false);
            write(&mut storage, address, 0, 11, 150, 1_000);
            let outer = storage.checkpoint();
            write(&mut storage, address, 1, 17, 200, refund);
            let inner = storage.checkpoint();
            write(&mut storage, address, 2, 7, 100, 300);
            storage.checkpoint_commit(inner);

            if ending == 2 {
                // OOG zeroes execution gas, then checkpoint rollback can return spilled
                // gas. The enclosing frame must still burn it when the halt propagates.
                let error = crate::storage_credits::StorageCreditsBackend::charge_storage_creation(
                    &mut storage,
                )
                .unwrap_err();
                storage.checkpoint_revert(outer);
                return error.into_precompile_result();
            }
            if commit {
                storage.checkpoint_commit(outer);
            } else {
                storage.checkpoint_revert(outer);
            }
            if ending == 1 {
                Err(PrecompileError::Revert(Bytes::new()))
            } else {
                Ok(PrecompileOutput::new(Bytes::new()))
            }
        }

        let address = Address::repeat_byte(0x66);
        for reservoir in [0, 100, 200, 1_000] {
            for commit in [false, true] {
                for refund in [400, -1_400] {
                    for (ending, stop) in [
                        (0, InstrStop::Return),
                        (1, InstrStop::Revert),
                        (2, InstrStop::PrecompileOOG),
                    ] {
                        let mut evm = TestEvm::new(TempoHardfork::T15);
                        let mut map = PrecompileMap::new();
                        map.insert(Precompile::new(
                            address,
                            PrecompileId::custom("checkpoint"),
                            run,
                        ));
                        evm.evm.set_precompiles(Precompiles::new(Cow::Owned(map)));
                        let mut message = Message::<TestTypes> {
                            kind: MessageKind::Call,
                            destination: address,
                            call_target: address,
                            code_address: address,
                            gas_limit: 10_000,
                            reservoir,
                            input: Bytes::from(vec![
                                u8::from(commit),
                                ending,
                                u8::from(refund < 0),
                            ])
                            .into(),
                            ..Default::default()
                        };
                        let result = Host::execute_message(&mut evm.evm, &mut message)?;

                        // Equivalent parent/child accounting using evm2's frame-return helpers.
                        let mut expected =
                            GasTracker::new_with_execution_gas_and_reservoir(10_000, reservoir);
                        expected.spend(11).unwrap();
                        expected.spend_state(150).unwrap();
                        expected.record_refund(1_000);
                        let mut child = GasTracker::new_with_execution_gas_and_reservoir(
                            expected.remaining(),
                            expected.reservoir(),
                        );
                        child.spend(24).unwrap();
                        child.spend_state(300).unwrap();
                        child.record_refund(refund + 300);
                        let child_stop = if commit {
                            InstrStop::Return
                        } else {
                            InstrStop::Revert
                        };
                        child.settle_gas(child_stop);
                        expected.spend_all();
                        expected.merge_child_gas(child, child_stop);
                        expected.settle_gas(stop);
                        assert_eq!(result.stop, stop);
                        assert_eq!(
                            result.gas, expected,
                            "reservoir={reservoir}, commit={commit}, refund={refund}, stop={stop:?}"
                        );

                        let success = stop.is_success();
                        for slot in 0..3 {
                            let value = U256::from(u64::from(success && (slot == 0 || commit)));
                            assert_eq!(
                                evm.evm
                                    .state_mut()
                                    .storage(&address)?
                                    .into_slot(U256::from(slot))?
                                    .current(),
                                value
                            );
                            assert_eq!(
                                evm.evm.state_mut().tload(&address, &U256::from(slot)),
                                value
                            );
                        }
                        assert_eq!(
                            evm.evm.logs().len(),
                            if !success {
                                0
                            } else if commit {
                                3
                            } else {
                                1
                            }
                        );
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn test_t15_nested_checkpoint_restores_refunds_and_preserves_committed_gas() -> eyre::Result<()>
    {
        let mut evm = TestEvm::new(TempoHardfork::T15);
        let mut provider = evm.provider_with_reservoir(1_000_000);
        let address = Address::repeat_byte(0x22);

        provider.sstore(address, U256::ZERO, U256::ONE)?;
        provider.sstore(address, U256::ZERO, U256::ZERO)?;
        assert_eq!(provider.gas_refunded(), 5_000);

        let outer = provider.checkpoint();
        provider.sstore(address, U256::ONE, U256::ONE)?;
        let inner = provider.checkpoint();
        provider.sstore(address, U256::ONE, U256::ZERO)?;
        assert_eq!(provider.gas_refunded(), 10_000);

        provider.checkpoint_revert(inner);
        assert_eq!(provider.gas_refunded(), 5_000);
        assert_eq!(provider.sload(address, U256::ONE)?, U256::ONE);
        provider.checkpoint_commit(outer);
        assert_eq!(provider.state_gas_used(), 490_000);
        assert_eq!(provider.reservoir(), 510_000);

        let committed = provider.checkpoint();
        provider.sstore(address, U256::ONE, U256::ZERO)?;
        provider.checkpoint_commit(committed);
        assert_eq!(provider.gas_refunded(), 10_000);
        assert_eq!(provider.state_gas_used(), 490_000);
        assert_eq!(provider.reservoir(), 510_000);
        Ok(())
    }

    #[test]
    fn test_clearing_storage_mints_a_tip1060_credit() -> eyre::Result<()> {
        let owner = Address::repeat_byte(0x33);
        let key = U256::from(1);
        let mut evm = TestEvm::with_storage(TempoHardfork::T7, owner, key, U256::ONE);
        let mut provider = evm.provider_max_gas();

        assert_eq!(provider.sload(owner, key)?, U256::ONE);
        provider.sstore(owner, key, U256::ZERO)?;
        assert_eq!(
            provider.sload(STORAGE_CREDITS_ADDRESS, StorageCredits::slot(owner))?,
            U256::ONE
        );
        Ok(())
    }

    #[test]
    fn test_tip1060_accounting_can_be_disabled() -> eyre::Result<()> {
        let owner = Address::repeat_byte(0x44);
        let key = U256::from(1);
        let mut evm = TestEvm::with_storage(TempoHardfork::T7, owner, key, U256::ONE);
        let mut provider = evm.provider_max_gas();
        provider.set_tip1060_storage_credits(false);

        provider.sstore(owner, key, U256::ZERO)?;
        assert_eq!(
            provider.sload(STORAGE_CREDITS_ADDRESS, StorageCredits::slot(owner))?,
            U256::ZERO
        );
        Ok(())
    }

    #[test]
    fn test_t15_sstore_restore_refund_matches_tip1016_spec() -> eyre::Result<()> {
        let mut evm = TestEvm::new(TempoHardfork::T15);
        let reservoir = 245_000;
        let mut provider = evm.provider_with_reservoir(reservoir);

        let (address, slot) = (Address::random(), U256::ONE);
        provider.sstore(address, slot, U256::ONE)?;
        provider.sstore(address, slot, U256::ZERO)?;

        // 0→x→0 restoration under the storage-credit hook: only the 5,000
        // write portion goes through the execution refund counter. The 245k
        // creditable portion is NOT returned — the x→0 clear mints a storage
        // credit for the contract instead of refilling the reservoir.
        assert_eq!(
            provider.gas_refunded(),
            5_000,
            "refund counter must carry only the regular portion of the restoration"
        );
        assert_eq!(
            provider.state_gas_used(),
            245_000,
            "the creditable portion stays consumed; the clear mints a credit instead"
        );
        assert_eq!(
            provider.reservoir(),
            0,
            "no reservoir refill under the storage-credit hook"
        );
        assert_eq!(
            provider.sload(
                crate::STORAGE_CREDITS_ADDRESS,
                crate::storage_credits::StorageCredits::slot(address)
            )?,
            U256::ONE,
            "the x→0 clear must mint exactly one storage credit for the contract"
        );

        Ok(())
    }

    #[test]
    fn test_t15_set_code_charges_hash_cost_per_word_of_code_bytes() -> eyre::Result<()> {
        let mut evm = TestEvm::new(TempoHardfork::T15);
        let gas_params = evm.gas_params();

        let code_len = 45usize; // 2 words, e.g. the zone portal proxy runtime
        let code = Bytes::from(vec![0x00; code_len]);
        let expected_hash_cost = 6 * code_len.div_ceil(32) as u64;
        let expected_regular_gas = u64::from(gas_params[GasId::Create])
            + (u64::from(gas_params[GasId::CodeDepositCost]) * code_len as u64)
            + expected_hash_cost;
        let expected_state_gas =
            gas_params.create_state_gas() + gas_params.code_deposit_state_gas(code_len);
        let mut provider = evm.provider_with_reservoir(expected_state_gas);

        provider.set_code(Address::random(), code)?;
        assert_eq!(
            provider.gas_used(),
            expected_regular_gas,
            "set_code should charge HASH_COST over code bytes, not words"
        );

        Ok(())
    }

    #[test]
    fn test_t15_set_code_oog_rolls_back_installed_code() -> eyre::Result<()> {
        for fail_execution_charge in [true, false] {
            let mut evm = TestEvm::new(TempoHardfork::T15);
            let gas_params = evm.gas_params();
            let code = Bytes::from(vec![0xef]);
            let execution_gas = u64::from(gas_params[GasId::CodeDepositCost])
                + gas_params.keccak256_word_cost(code.len())
                + u64::from(gas_params[GasId::Create]);
            let (gas_limit, reservoir) = if fail_execution_charge {
                (execution_gas - 1, gas_params.create_state_gas())
            } else {
                // CREATE spills 25 gas, leaving no gas for code-deposit state charges.
                (execution_gas + 25, gas_params.create_state_gas() - 25)
            };
            let address = Address::repeat_byte(0x55);
            let mut provider = evm.provider_with_gas_limit(gas_limit, reservoir);
            let checkpoint = provider.checkpoint();

            assert_eq!(
                provider.set_code(address, code),
                Err(TempoPrecompileError::OutOfGas)
            );
            provider.checkpoint_revert(checkpoint);
            assert_eq!(provider.state_gas_used(), 0);
            assert_eq!(provider.state_gas_spilled(), 0);
            assert_eq!(provider.reservoir(), reservoir);
            std::mem::drop(provider);
            assert!(evm.load_account_code(address)?.is_empty());
        }
        Ok(())
    }

    #[test]
    fn test_t15_set_code_pre_touched_destination_skips_create() -> eyre::Result<()> {
        let mut evm = TestEvm::new(TempoHardfork::T15);
        let gas_params = evm.gas_params();

        let address = Address::random();
        evm.evm.overlay_db_mut().insert_account_info(
            &address,
            evm2::evm::AccountInfo {
                balance: U256::ONE,
                nonce: 1,
                ..Default::default()
            },
        );

        let code = Bytes::from(vec![0xef]);
        let expected_state_gas = gas_params.code_deposit_state_gas(code.len());
        let expected_regular_gas = (u64::from(gas_params[GasId::CodeDepositCost])
            * code.len() as u64)
            + gas_params.keccak256_word_cost(code.len());
        // Reservoir also covers the second deployment below so no state gas
        // spills into regular gas and skews the assertions.
        let mut provider =
            evm.provider_with_reservoir(expected_state_gas + gas_params.code_deposit_state_gas(2));

        provider.set_code(address, code)?;
        assert_eq!(
            provider.gas_used(),
            expected_regular_gas,
            "a pre-touched destination is not empty, so only code deposit + hash cost are charged"
        );
        assert_eq!(
            provider.state_gas_used(),
            expected_state_gas as i64,
            "a pre-touched destination should pay only code deposit state gas"
        );

        // Re-deploying over existing code is not a fresh deployment either,
        // but it still pays the deposit and hash costs.
        let code = Bytes::from(vec![0xef, 0xef]);
        provider.set_code(address, code.clone())?;
        assert_eq!(
            provider.gas_used(),
            expected_regular_gas
                + (u64::from(gas_params[GasId::CodeDepositCost]) * code.len() as u64)
                + gas_params.keccak256_word_cost(code.len()),
            "set_code over existing code must not charge CREATE"
        );

        Ok(())
    }

    /// The frame of [`CALLING_PRECOMPILE`] as a top-level call, with no nested call running.
    fn frame() -> Frame {
        Frame {
            address: CALLING_PRECOMPILE,
            depth: 0,
            nested_calls: Rc::default(),
        }
    }

    fn evm_with_callee(code: Bytes) -> TestEvm {
        let mut database = InMemoryDB::default();
        database.insert_account_info(
            &CALLEE,
            AccountInfo::default().with_code(Bytecode::new_raw(code)),
        );
        TestEvm::with_database(TempoHardfork::default(), database)
    }

    #[test]
    fn test_call_frame_address_reports_the_running_precompile() {
        let mut evm = evm_with_callee(Bytes::new());
        let provider = evm.provider_with_gas_limit(1_000_000, 0);
        assert_eq!(provider.call_frame_address(), None);
        let provider = provider.with_frame(frame());
        assert_eq!(provider.call_frame_address(), Some(CALLING_PRECOMPILE));
    }

    #[test]
    fn test_call_reports_callee_outcome_and_rolls_back_failed_callee() -> eyre::Result<()> {
        let caller = CALLING_PRECOMPILE.into_word();
        // sstore(0, caller); mstore(0, caller); then return(0, 32) | revert(0, 32)
        for (ending, succeeds) in [(0xf3, true), (0xfd, false)] {
            let code = [bytes!("335f55335f5260205f").as_ref(), &[ending]].concat();
            let mut evm = evm_with_callee(code.into());
            let mut provider = evm
                .provider_with_gas_limit(10_000_000, 0)
                .with_frame(frame());

            // The callee sees the precompile as its caller, and keeps its write if it returns.
            let outcome = provider.call(CALLEE, Bytes::new(), u64::MAX, false)?;
            let stored = provider.sload(CALLEE, U256::ZERO)?;
            if succeeds {
                assert_eq!(outcome, CallOutcome::Success(caller.into()));
                assert_eq!(stored, b256_to_word(caller));
            } else {
                assert_eq!(outcome, CallOutcome::Failure(caller.into()));
                assert_eq!(stored, U256::ZERO);
            }
            // Either way the callee returns the gas it did not use.
            assert!(provider.gas_used() < 5_000_000);
        }
        Ok(())
    }

    #[test]
    fn test_call_forwards_capped_gas_that_halting_callee_burns() -> eyre::Result<()> {
        // invalid
        let mut evm = evm_with_callee(bytes!("fe"));
        let gas_params = evm.gas_params();
        let warm_cost = gas_params.get(GasId::WarmStorageReadCost);
        let cold_cost = gas_params.cold_account_additional_cost();
        let gas_limit = 1_000_000;
        let mut provider = evm
            .provider_with_gas_limit(gas_limit, 0)
            .with_frame(frame());

        // Uncapped, the callee gets all but one 64th of what is left after the cold access.
        let outcome = provider.call(CALLEE, Bytes::new(), u64::MAX, false)?;
        assert_eq!(outcome, CallOutcome::Failure(Bytes::new()));
        let kept = (gas_limit - warm_cost - cold_cost) / 64;
        assert_eq!(provider.gas_used(), gas_limit - kept);

        // Capped, it gets `gas_limit`, on top of the now warm access.
        let outcome = provider.call(CALLEE, Bytes::new(), 1_000, false)?;
        assert_eq!(outcome, CallOutcome::Failure(Bytes::new()));
        assert_eq!(provider.gas_used(), gas_limit - kept + warm_cost + 1_000);
        Ok(())
    }

    #[test]
    fn test_call_fails_precompile_when_refused_or_out_of_gas() {
        let mut evm = evm_with_callee(bytes!("00"));
        let gas_params = evm.gas_params();
        let access_cost =
            gas_params.get(GasId::WarmStorageReadCost) + gas_params.cold_account_additional_cost();

        // Without a frame, or with the limit of nested calls running, nothing is charged.
        let limited = Frame {
            nested_calls: Rc::new(Cell::new(MAX_NESTED_CALLS)),
            ..frame()
        };
        for refusing in [None, Some(limited)] {
            let mut provider = evm.provider_with_gas_limit(1_000_000, 0);
            provider.frame = refusing;
            assert_eq!(
                provider.call(CALLEE, Bytes::new(), u64::MAX, false),
                Err(TempoPrecompileError::NestedCallUnavailable)
            );
            assert_eq!(provider.gas_used(), 0);
        }

        // The frame's own charge is an error too, not a callee failure the precompile could ignore.
        let mut provider = evm
            .provider_with_gas_limit(access_cost - 1, 0)
            .with_frame(frame());
        assert_eq!(
            provider.call(CALLEE, Bytes::new(), u64::MAX, false),
            Err(TempoPrecompileError::OutOfGas)
        );
    }

    #[test]
    fn test_call_keeps_static_context() -> eyre::Result<()> {
        // sstore(0, 1); stop
        let mut evm = evm_with_callee(bytes!("60015f5500"));

        // A static frame makes every callee static, whatever the call kind.
        let mut provider = evm.static_provider().with_frame(frame());
        let outcome = provider.call(CALLEE, Bytes::new(), 1_000_000, false)?;
        assert_eq!(outcome, CallOutcome::Failure(Bytes::new()));

        let mut provider = evm
            .provider_with_gas_limit(10_000_000, 0)
            .with_frame(frame());
        let outcome = provider.call(CALLEE, Bytes::new(), 1_000_000, true)?;
        assert_eq!(outcome, CallOutcome::Failure(Bytes::new()));

        let outcome = provider.call(CALLEE, Bytes::new(), 1_000_000, false)?;
        assert_eq!(outcome, CallOutcome::Success(Bytes::new()));
        assert_eq!(provider.sload(CALLEE, U256::ZERO)?, U256::ONE);
        Ok(())
    }

    #[test]
    fn test_call_runs_eip7702_delegate_in_target_context() -> eyre::Result<()> {
        let delegator = Address::repeat_byte(0xde);
        // sstore(0, caller); stop
        let mut database = InMemoryDB::default();
        database.insert_account_info(
            &CALLEE,
            AccountInfo::default().with_code(Bytecode::new_raw(bytes!("335f5500"))),
        );
        database.insert_account_info(
            &delegator,
            AccountInfo::default().with_code(Bytecode::new_eip7702(CALLEE)),
        );
        let mut evm = TestEvm::with_database(TempoHardfork::default(), database);
        let gas_params = evm.gas_params();
        let access_cost =
            gas_params.get(GasId::WarmStorageReadCost) + gas_params.cold_account_additional_cost();
        let mut provider = evm
            .provider_with_gas_limit(10_000_000, 0)
            .with_frame(frame());

        // Without gas the delegate's code halts, after both account accesses were charged.
        let outcome = provider.call(delegator, Bytes::new(), 0, false)?;
        assert_eq!(outcome, CallOutcome::Failure(Bytes::new()));
        assert_eq!(provider.gas_used(), 2 * access_cost);

        let outcome = provider.call(delegator, Bytes::new(), u64::MAX, false)?;
        assert_eq!(outcome, CallOutcome::Success(Bytes::new()));
        let caller = b256_to_word(CALLING_PRECOMPILE.into_word());
        assert_eq!(provider.sload(delegator, U256::ZERO)?, caller);
        assert_eq!(provider.sload(CALLEE, U256::ZERO)?, U256::ZERO);
        Ok(())
    }

    #[test]
    fn test_call_refused_inside_checkpoint() -> eyre::Result<()> {
        let mut evm = evm_with_callee(bytes!("00"));
        let mut provider = evm
            .provider_with_gas_limit(1_000_000, 0)
            .with_frame(frame());

        // Refused while any checkpoint is open, before anything is charged.
        let outer = provider.checkpoint();
        let inner = provider.checkpoint();
        assert_eq!(
            provider.call(CALLEE, Bytes::new(), u64::MAX, false),
            Err(TempoPrecompileError::NestedCallUnavailable)
        );
        provider.checkpoint_commit(inner);
        assert_eq!(
            provider.call(CALLEE, Bytes::new(), u64::MAX, false),
            Err(TempoPrecompileError::NestedCallUnavailable)
        );
        assert_eq!(provider.gas_used(), 0);

        // Allowed again once every checkpoint is committed or reverted.
        provider.checkpoint_revert(outer);
        let outcome = provider.call(CALLEE, Bytes::new(), u64::MAX, false)?;
        assert_eq!(outcome, CallOutcome::Success(Bytes::new()));
        Ok(())
    }

    #[test]
    fn test_call_marks_storage_actions_unreplayable() -> eyre::Result<()> {
        let actions = StorageActions::enabled();
        let mut evm = evm_with_callee(bytes!("00"));
        let mut provider = evm
            .provider_with_gas_limit(1_000_000, 0)
            .with_actions(actions.clone())
            .with_frame(frame());

        // The callee's storage accesses are not recorded.
        provider.sload(CALLING_PRECOMPILE, U256::ZERO)?;
        let outcome = provider.call(CALLEE, Bytes::new(), u64::MAX, false)?;
        assert_eq!(outcome, CallOutcome::Success(Bytes::new()));
        assert_eq!(actions.take_replay(), None);
        Ok(())
    }
}
