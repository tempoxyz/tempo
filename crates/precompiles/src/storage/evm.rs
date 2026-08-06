use crate::{
    error::{Result as TempoResult, TempoPrecompileError},
    storage::{PrecompileStorageProvider, StorageActions, actions::StorageAction},
    storage_credits::{NonCreditableSlots, StorageCreditsBackend, sstore_storage_credits},
};
use alloy::primitives::{Address, B256, Bytes, Log, LogData, U256};
use evm2::{
    Evm, EvmFeatures, EvmTypes, Version,
    bytecode::Bytecode,
    env::TxEnv,
    evm::{SLoad, SStore},
    interpreter::{GasTracker, Host, Message, MessageExt, MessageKind, gas},
    precompiles::{PrecompileError, PrecompileHalt, PrecompileResult},
    version::GasId,
};
use std::{
    cell::RefCell,
    ops::{Deref, DerefMut},
    rc::Rc,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_primitives::{TempoBlockEnv, TempoBlockExt};

/// Extension state required by an EVM-backed precompile storage context.
pub trait EvmStorageExt {
    /// Returns the storage action recorder.
    fn storage_actions(&self) -> StorageActions;

    /// Returns the transaction-local non-creditable slots.
    fn non_creditable_slots(&self) -> Rc<RefCell<NonCreditableSlots>>;
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

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(gas_tracker) => gas_tracker,
            Self::Owned(gas_tracker) => gas_tracker,
        }
    }
}

impl DerefMut for GasTrackerStorage<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Borrowed(gas_tracker) => gas_tracker,
            Self::Owned(gas_tracker) => gas_tracker,
        }
    }
}

/// EVM-backed precompile storage and execution context.
///
/// Active precompile frames carry transaction/message context for nested calls. Ambient storage
/// contexts omit that frame context and retain the regular storage-only behavior.
pub struct EvmPrecompileExecution<'evm, 'db, T: EvmTypes> {
    evm: &'evm mut Evm<'db, T>,
    gas: GasTrackerStorage<'evm>,
    tx_env: Option<TxEnv<T>>,
    message: Option<Message<T>>,
    version: Version,
    block: TempoBlockEnv,
    spec: TempoHardfork,
    is_static: bool,
    actions: StorageActions,
    non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
    tip1060_storage_credits_enabled: bool,
    tip1060_storage_credit_minting_enabled: bool,
}

impl<'evm, 'db, T> EvmPrecompileExecution<'evm, 'db, T>
where
    T: EvmTypes<BlockEnvExt = TempoBlockExt>,
{
    /// Creates an execution context for an active precompile frame.
    pub fn new(
        evm: &'evm mut Evm<'db, T>,
        gas: &'evm mut GasTracker,
        tx_env: TxEnv<T>,
        message: &Message<T>,
        spec: TempoHardfork,
        actions: StorageActions,
        non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
    ) -> Self {
        let is_static = message.caller_is_static || message.kind == MessageKind::StaticCall;
        Self::with_gas_tracker(
            evm,
            GasTrackerStorage::Borrowed(gas),
            Some(tx_env),
            Some(message.clone()),
            spec,
            is_static,
            actions,
            non_creditable_slots,
        )
    }

    /// Creates a storage-only context over a live EVM and borrowed gas tracker.
    pub fn new_storage(
        evm: &'evm mut Evm<'db, T>,
        gas: &'evm mut GasTracker,
        spec: TempoHardfork,
        is_static: bool,
        actions: StorageActions,
        non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
    ) -> Self {
        Self::with_gas_tracker(
            evm,
            GasTrackerStorage::Borrowed(gas),
            None,
            None,
            spec,
            is_static,
            actions,
            non_creditable_slots,
        )
    }

    /// Creates a storage-only context with an independent maximum-gas tracker.
    pub fn new_max_gas(evm: &'evm mut Evm<'db, T>, spec: TempoHardfork) -> Self {
        Self::with_gas_tracker(
            evm,
            GasTrackerStorage::Owned(GasTracker::new(u64::MAX)),
            None,
            None,
            spec,
            false,
            StorageActions::disabled(),
            Rc::new(RefCell::new(NonCreditableSlots::empty())),
        )
    }

    fn with_gas_tracker(
        evm: &'evm mut Evm<'db, T>,
        gas: GasTrackerStorage<'evm>,
        tx_env: Option<TxEnv<T>>,
        message: Option<Message<T>>,
        spec: TempoHardfork,
        is_static: bool,
        actions: StorageActions,
        non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
    ) -> Self {
        let version = *evm.version();
        let block = *evm.block();
        Self {
            evm,
            gas,
            tx_env,
            message,
            version,
            block,
            spec,
            is_static,
            actions,
            non_creditable_slots,
            tip1060_storage_credits_enabled: spec.is_t7(),
            tip1060_storage_credit_minting_enabled: true,
        }
    }

    /// Sets the storage actions for this context.
    pub fn with_actions(mut self, actions: StorageActions) -> Self {
        self.actions = actions;
        self
    }

    /// Overrides the gas parameter table used by this context.
    pub fn with_gas_params(mut self, gas_params: evm2::version::GasParams) -> Self {
        self.version.gas_params = gas_params;
        self
    }

    /// Sets the transaction-local non-creditable clear-slot context.
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
    fn deduct_gas(&mut self, gas: u64) -> Result<(), TempoPrecompileError> {
        self.gas.deduct_gas(gas)
    }

    #[inline]
    fn deduct_state_gas(&mut self, gas: u64) -> Result<(), TempoPrecompileError> {
        self.gas.deduct_state_gas(gas)
    }

    /// Performs a raw journaled SLOAD without metering gas or recording a storage action.
    #[inline]
    fn sload_journal(
        &mut self,
        address: Address,
        key: U256,
        skip_cold_load: bool,
    ) -> Result<SLoad, TempoPrecompileError> {
        let eip2929 = self.version.feature(EvmFeatures::EIP2929);
        let state = self.evm.state_mut();
        state.account(&address, false)?.warm();
        let mut slot = state.storage(&address).into_slot(key, skip_cold_load)?;
        let is_cold = eip2929 && slot.warm();
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
        let eip2929 = self.version.feature(EvmFeatures::EIP2929);
        let state = self.evm.state_mut();
        state.account(&address, false)?.warm();
        let mut slot = state.storage(&address).into_slot(key, skip_cold_load)?;
        let is_cold = eip2929 && slot.warm();
        let (original_value, present_value) = slot.write(value);
        Ok(SStore {
            original_value,
            present_value,
            new_value: value,
            is_cold,
            _non_exhaustive: (),
        })
    }

    #[inline]
    fn sload_inner(
        &mut self,
        address: Address,
        key: U256,
        record: bool,
    ) -> Result<U256, TempoPrecompileError> {
        let additional_cost = u64::from(
            self.version
                .gas_params
                .get(GasId::ColdStorageAdditionalCost),
        );

        // T4+: pre-charge static gas to avoid cheap useless work.
        let skip_cold_load = if self.spec.is_t4() {
            self.deduct_gas(u64::from(
                self.version.gas_params.get(GasId::WarmStorageReadCost),
            ))?;
            self.gas.remaining() < additional_cost
        } else {
            false
        };

        let result = self.sload_journal(address, key, skip_cold_load)?;
        if record {
            self.actions
                .record(StorageAction::Sload(address, key, result.value));
        }

        if !self.spec.is_t4() {
            self.deduct_gas(u64::from(
                self.version.gas_params.get(GasId::WarmStorageReadCost),
            ))?;
        }

        if result.is_cold {
            self.deduct_gas(additional_cost)?;
        }

        Ok(result.value)
    }

    #[inline]
    fn sstore_inner(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
        action: impl FnOnce(&SStore) -> StorageAction,
    ) -> Result<(), TempoPrecompileError> {
        // T4+: pre-charge static gas before loading storage to avoid cheap useless work.
        let skip_cold_load = if self.spec.is_t4() {
            self.deduct_gas(u64::from(self.version.gas_params.get(GasId::SstoreStatic)))?;
            self.gas.remaining()
                < u64::from(
                    self.version
                        .gas_params
                        .get(GasId::ColdStorageAdditionalCost),
                )
        } else {
            false
        };

        let result = self.sstore_journal(address, key, value, skip_cold_load)?;
        self.actions.record(action(&result));

        if !self.spec.is_t4() {
            self.deduct_gas(u64::from(self.version.gas_params.get(GasId::SstoreStatic)))?;
        }

        // TIP-1060 (T7+): run the storage credits policy so precompile-driven storage
        // writes honor the same accounting as the opcode-level SSTORE hook.
        if self.tip1060_storage_credits_enabled {
            sstore_storage_credits(self, address, Some(key), &result)?
        }

        self.deduct_gas(self.version.gas_params.sstore_dynamic_gas(true, &result))?;
        self.deduct_state_gas(self.version.gas_params.sstore_state_gas(&result))?;

        // Native precompile storage did not surface SSTORE refunds before TIP-1016.
        if self.spec.is_t4() {
            self.refund_gas(self.version.gas_params.sstore_refund(true, &result));
        }

        Ok(())
    }
}

impl<T> StorageCreditsBackend for EvmPrecompileExecution<'_, '_, T>
where
    T: EvmTypes<BlockEnvExt = TempoBlockExt>,
{
    type Error = TempoPrecompileError;

    #[inline]
    fn gas_params(&self) -> &evm2::version::GasParams {
        &self.version.gas_params
    }

    #[inline]
    fn gas_tracker(&mut self) -> &mut GasTracker {
        &mut *self.gas
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
    ) -> Result<SStore, Self::Error> {
        let result = self.sstore_journal(address, key, value, skip_cold_load)?;
        self.actions.record_always(StorageAction::Sstore(
            address,
            key,
            result.present_value,
            value,
        ));
        Ok(result)
    }

    #[inline]
    fn tload(&mut self, address: Address, key: U256) -> U256 {
        self.evm.state_mut().tload(&address, &key)
    }

    #[inline]
    fn tstore(&mut self, address: Address, key: U256, value: U256) {
        self.evm.state_mut().tstore(&address, &key, &value);
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

impl<T> PrecompileStorageProvider for EvmPrecompileExecution<'_, '_, T>
where
    T: EvmTypes<BlockEnvExt = TempoBlockExt>,
{
    fn chain_id(&self) -> u64 {
        self.version.chain_id
    }

    fn block_env(&self) -> &TempoBlockEnv {
        &self.block
    }

    fn set_code(&mut self, address: Address, code: Bytes) -> TempoResult<()> {
        let code = Bytecode::new_raw(code);
        let code_len = code.len();
        self.deduct_gas(
            u64::from(self.version.gas_params.get(GasId::CodeDepositCost))
                .saturating_mul(code_len as u64),
        )?;
        self.deduct_state_gas(self.version.gas_params.code_deposit_state_gas(code_len))?;

        let was_empty = {
            let mut account = self.evm.state_mut().account(&address, false)?;
            let was_empty = account.get().is_none_or(evm2::evm::AccountInfo::is_empty);
            account.set_code_slow(code);
            was_empty
        };

        // TIP-1016: charge TIP20 deployments as CREATE.
        if self.version.feature(EvmFeatures::EIP8037) && was_empty {
            self.deduct_gas(u64::from(self.version.gas_params.get(GasId::Create)))?;
            self.deduct_state_gas(self.version.gas_params.create_state_gas())?;
            self.deduct_gas(
                self.version
                    .gas_params
                    .keccak256_word_cost(code_len.div_ceil(32)),
            )?;
        }

        Ok(())
    }

    fn with_account_info(
        &mut self,
        address: Address,
        f: &mut dyn FnMut(&evm2::evm::AccountInfo),
    ) -> TempoResult<()> {
        let additional_cost = self.version.gas_params.cold_account_additional_cost();
        let warm_storage_read_cost =
            u64::from(self.version.gas_params.get(GasId::WarmStorageReadCost));
        let is_t4 = self.spec.is_t4();
        let insufficient_gas_for_cold_load = if is_t4 {
            self.deduct_gas(warm_storage_read_cost)?;
            self.gas.remaining() < additional_cost
        } else {
            false
        };

        let info = {
            let mut account = self
                .evm
                .state_mut()
                .account(&address, insufficient_gas_for_cold_load)?;
            let is_cold = self.version.feature(EvmFeatures::EIP2929) && account.warm();

            if !is_t4 {
                if self.gas.remaining() < warm_storage_read_cost {
                    return Err(TempoPrecompileError::OutOfGas);
                }
                self.gas
                    .spend(warm_storage_read_cost)
                    .map_err(|_| TempoPrecompileError::OutOfGas)?;
            }

            if is_cold {
                if self.gas.remaining() < additional_cost {
                    return Err(TempoPrecompileError::OutOfGas);
                }
                self.gas
                    .spend(additional_cost)
                    .map_err(|_| TempoPrecompileError::OutOfGas)?;
            }

            account.load_code()?;
            let info = account.get().cloned().unwrap_or_default();
            info
        };

        f(&info);
        Ok(())
    }

    fn account_code(&mut self, address: Address) -> TempoResult<(B256, Bytecode)> {
        let mut result = None;
        self.with_account_info(address, &mut |info| {
            result = Some((
                info.code_hash,
                info.code.clone().unwrap_or_else(Bytecode::default),
            ));
        })?;
        Ok(result.expect("account info callback is always invoked"))
    }

    fn sload(&mut self, address: Address, key: U256) -> TempoResult<U256> {
        self.sload_inner(address, key, true)
    }

    fn tload(&mut self, address: Address, key: U256) -> TempoResult<U256> {
        self.deduct_gas(u64::from(
            self.version.gas_params.get(GasId::WarmStorageReadCost),
        ))?;
        Ok(self.evm.state_mut().tload(&address, &key))
    }

    fn sstore(&mut self, address: Address, key: U256, value: U256) -> TempoResult<()> {
        self.sstore_inner(address, key, value, |result| {
            StorageAction::Sstore(address, key, result.present_value, value)
        })
    }

    fn sinc(&mut self, address: Address, key: U256, delta: U256) -> TempoResult<()> {
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

    fn sdec(&mut self, address: Address, key: U256, delta: U256) -> TempoResult<()> {
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

    fn tstore(&mut self, address: Address, key: U256, value: U256) -> TempoResult<()> {
        self.deduct_gas(u64::from(
            self.version.gas_params.get(GasId::WarmStorageReadCost),
        ))?;
        self.evm.state_mut().tstore(&address, &key, &value);
        Ok(())
    }

    fn emit_event(&mut self, address: Address, event: LogData) -> TempoResult<()> {
        self.deduct_gas(
            u64::from(gas::LOG).saturating_add(
                self.version
                    .gas_params
                    .log_cost(event.topics().len() as u8, event.data.len()),
            ),
        )?;
        self.evm.state_mut().log(Log {
            address,
            data: event,
        });
        Ok(())
    }

    fn deduct_gas(&mut self, gas: u64) -> TempoResult<()> {
        Self::deduct_gas(self, gas)
    }

    fn refund_gas(&mut self, gas: i64) {
        self.gas.record_refund(gas);
    }

    fn gas_limit(&self) -> u64 {
        self.gas.limit()
    }

    fn gas_used(&self) -> u64 {
        self.gas.spent()
    }

    fn state_gas_used(&self) -> u64 {
        self.gas.state_gas_spent() as u64
    }

    fn gas_refunded(&self) -> i64 {
        self.gas.refunded()
    }

    fn reservoir(&self) -> u64 {
        self.gas.reservoir()
    }

    fn spec(&self) -> TempoHardfork {
        self.spec
    }

    fn storage_actions(&self) -> StorageActions {
        self.actions.clone()
    }

    fn amsterdam_eip8037_enabled(&self) -> bool {
        self.version.feature(EvmFeatures::EIP8037)
    }

    fn is_static(&self) -> bool {
        self.is_static
    }

    fn checkpoint(&mut self) -> evm2::evm::StateCheckpoint {
        self.evm.state_mut().checkpoint()
    }

    fn call(&mut self, target: Address, input: Bytes, gas_limit: u64) -> PrecompileResult {
        self.execute_nested_call(MessageKind::Call, target, input, gas_limit)
    }

    fn static_call(&mut self, target: Address, input: Bytes, gas_limit: u64) -> PrecompileResult {
        self.execute_nested_call(MessageKind::StaticCall, target, input, gas_limit)
    }

    fn checkpoint_commit(&mut self, checkpoint: evm2::evm::StateCheckpoint) {
        let _ = checkpoint;
    }

    fn checkpoint_revert(&mut self, checkpoint: evm2::evm::StateCheckpoint) {
        self.evm
            .state_mut()
            .rollback(checkpoint, self.version.features);
    }

    fn set_tip1060_storage_credits(&mut self, enabled: bool) {
        self.tip1060_storage_credits_enabled = enabled && self.spec.is_t7();
    }

    fn set_tip1060_storage_credit_minting(&mut self, enabled: bool) {
        self.tip1060_storage_credit_minting_enabled = enabled;
    }
}

impl<T> EvmPrecompileExecution<'_, '_, T>
where
    T: EvmTypes<BlockEnvExt = TempoBlockExt>,
{
    fn execute_nested_call(
        &mut self,
        kind: MessageKind,
        target: Address,
        input: Bytes,
        gas_limit: u64,
    ) -> PrecompileResult {
        let Some(message) = self.message.as_ref() else {
            return Err(PrecompileHalt::Other(
                "nested precompile calls require a live EVM context".into(),
            )
            .into());
        };
        let Some(tx_env) = self.tx_env.as_ref() else {
            return Err(PrecompileHalt::Other(
                "nested precompile calls require a live EVM context".into(),
            )
            .into());
        };
        let caller = message.code_address;
        let depth = message.depth.saturating_add(1);
        let caller_is_static = message.caller_is_static || message.kind == MessageKind::StaticCall;
        let call_base_gas = if self.version.feature(EvmFeatures::EIP2929) {
            100
        } else if self.version.feature(EvmFeatures::EIP150) {
            700
        } else {
            40
        };
        self.gas.spend(call_base_gas)?;

        let cold_account_cost = self.version.gas_params.cold_account_additional_cost();
        let skip_cold_load = self.gas.remaining() < cold_account_cost;
        let loaded = Host::load_account(&mut *self.evm, &target, true, skip_cold_load)?;
        if loaded.is_cold {
            self.gas.spend(cold_account_cost)?;
        }

        let mut code = loaded.code;
        let mut code_address = target;
        let mut disable_precompiles = false;
        if self.version.feature(EvmFeatures::EIP7702)
            && let Some(delegated_address) = code.eip7702_address()
        {
            self.gas.spend(
                self.version
                    .gas_params
                    .get(GasId::WarmStorageReadCost)
                    .into(),
            )?;
            let skip_cold_load = self.gas.remaining() < cold_account_cost;
            let delegated =
                Host::load_account(&mut *self.evm, &delegated_address, true, skip_cold_load)?;
            if delegated.is_cold {
                self.gas.spend(cold_account_cost)?;
            }
            code = delegated.code;
            code_address = delegated_address;
            disable_precompiles = true;
        }

        let child_gas_limit = if self.version.features.contains(EvmFeatures::EIP150) {
            self.version
                .gas_params
                .call_stipend_reduction(self.gas.remaining())
                .min(gas_limit)
        } else {
            gas_limit
        };
        self.gas.spend(child_gas_limit)?;

        let mut child = MessageExt {
            kind,
            depth,
            gas_limit: child_gas_limit,
            reservoir: self.gas.reservoir(),
            destination: target,
            caller,
            input,
            value: alloy::primitives::U256::ZERO,
            code_address,
            disable_precompiles,
            caller_is_static,
            ..MessageExt::default()
        };

        let result = Host::execute_message(&mut *self.evm, tx_env, code, &mut child);
        if result.stop.is_fatal() {
            return Err(result.stop.into());
        }
        self.gas.merge_child_gas(result.gas, result.stop);

        match result.stop {
            stop if stop.is_success() => {
                Ok(evm2::evm::precompile::PrecompileOutput::new(result.output))
            }
            stop if stop.is_revert() => Err(PrecompileError::Revert(result.output)),
            stop if stop.is_fatal() => Err(stop.into()),
            stop => Err(
                PrecompileHalt::Other(format!("nested call halted with {stop:?}").into()).into(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EvmPrecompileExecution;
    use crate::{
        STORAGE_CREDITS_ADDRESS, TempoPrecompiles,
        error::TempoPrecompileError,
        storage::{PrecompileStorageProvider, StorageActions, actions::StorageAction},
        storage_credits::StorageCredits,
    };
    use alloy::primitives::{Address, B256, Bytes, LogData, U256, b256, bytes, keccak256};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use evm2::{
        BaseEvmConfigSelector, Evm, EvmTypesHost, ExecutionConfig, SpecId, Version,
        evm::InMemoryDB,
        interpreter::GasTracker,
        registry::TxRegistry,
        version::{GasId, GasParams},
    };
    use std::{cell::RefCell, rc::Rc};
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_primitives::{TempoBlockEnv, TempoBlockExt};

    struct TestTypes;

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
            Self::with_amsterdam(spec, false)
        }

        fn new_with_tip1016(spec: TempoHardfork) -> Self {
            Self::with_amsterdam(spec, true)
        }

        fn with_amsterdam(spec: TempoHardfork, amsterdam_eip8037_enabled: bool) -> Self {
            Self::with_database(spec, amsterdam_eip8037_enabled, InMemoryDB::default())
        }

        fn with_storage(spec: TempoHardfork, address: Address, key: U256, value: U256) -> Self {
            let mut database = InMemoryDB::default();
            database.insert_account_storage(&address, &key, &value);
            Self::with_database(spec, false, database)
        }

        fn with_database(
            spec: TempoHardfork,
            amsterdam_eip8037_enabled: bool,
            database: InMemoryDB,
        ) -> Self {
            let version = tempo_chainspec::gas_params::version(
                SpecId::OSAKA,
                spec,
                amsterdam_eip8037_enabled,
            );
            Self {
                evm: Evm::new_with_execution_config(
                    ExecutionConfig::for_spec_and_version(SpecId::OSAKA, version),
                    SpecId::OSAKA,
                    TempoBlockEnv::default(),
                    TxRegistry::new(),
                    database,
                    TempoPrecompiles::new(
                        spec,
                        StorageActions::disabled(),
                        Rc::new(RefCell::new(
                            crate::storage_credits::NonCreditableSlots::empty(),
                        )),
                    ),
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
        ) -> EvmPrecompileExecution<'_, 'static, TestTypes> {
            self.gas_tracker = GasTracker::new_with_regular_gas_and_reservoir(gas_limit, reservoir);
            EvmPrecompileExecution::new_storage(
                &mut self.evm,
                &mut self.gas_tracker,
                self.spec,
                false,
                StorageActions::disabled(),
                Rc::new(RefCell::new(
                    crate::storage_credits::NonCreditableSlots::empty(),
                )),
            )
        }

        fn provider_with_reservoir(
            &mut self,
            reservoir: u64,
        ) -> EvmPrecompileExecution<'_, 'static, TestTypes> {
            self.provider_with_gas_limit(u64::MAX, reservoir)
        }

        fn provider_max_gas(&mut self) -> EvmPrecompileExecution<'_, 'static, TestTypes> {
            EvmPrecompileExecution::new_max_gas(&mut self.evm, self.spec)
        }

        fn gas_params(&self) -> GasParams {
            self.version.gas_params
        }

        fn load_account_code(&mut self, address: Address) -> eyre::Result<Bytes> {
            let mut account = self
                .evm
                .state_mut()
                .account(&address, false)
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
            assert_eq!(info.code_hash, alloy::primitives::KECCAK256_EMPTY);
        })?;

        Ok(())
    }

    #[test]
    fn test_failed_account_info_charge_preserves_remaining_gas_before_t4() -> eyre::Result<()> {
        let mut evm = TestEvm::new(TempoHardfork::T1);
        let address = Address::random();
        evm.evm.state_mut().prewarm(&address);

        let warm_storage_read_cost = u64::from(evm.gas_params().get(GasId::WarmStorageReadCost));
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
        let mut evm = TestEvm::new_with_tip1016(TempoHardfork::T4);
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
        provider.sstore(address, slot, U256::from(1))?;
        let state_gas_after_set = provider.state_gas_used();
        assert_eq!(
            state_gas_after_set, 230_000,
            "SSTORE zero->non-zero should add 230k state gas"
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
                + gas_params.create_state_gas()
                + gas_params.code_deposit_state_gas(1),
            "set_code(new account, 1 byte) should add CREATE state gas plus 2,300 code deposit state gas"
        );

        Ok(())
    }

    /// Tests that state gas (EIP-8037) is deducted from the reservoir first and
    /// spills into regular gas once the reservoir is exhausted.
    #[test]
    fn test_state_gas_spills_from_reservoir_to_regular_gas() -> eyre::Result<()> {
        let mut evm = TestEvm::new_with_tip1016(TempoHardfork::T4);

        // Reservoir = 500k: enough for 2 full SSTOREs (2 × 230k = 460k)
        // but the 3rd SSTORE (230k) must spill 190k into regular gas.
        let gas_limit = 1_000_000u64;
        let reservoir = 500_000u64;
        let state_gas_per_sstore = 230_000u64;
        let mut provider = evm.provider_with_gas_limit(gas_limit, reservoir);
        let address = Address::random();

        // --- First SSTORE (zero→non-zero): fully covered by reservoir ---
        provider.sstore(address, U256::from(1), U256::from(42))?;

        let regular_gas_per_sstore = provider.gas_used(); // static + dynamic (regular)
        assert_eq!(
            provider.state_gas_used(),
            state_gas_per_sstore,
            "first SSTORE should consume 230k state gas"
        );
        assert_eq!(
            provider.reservoir(),
            reservoir - state_gas_per_sstore,
            "reservoir should decrease by state gas cost"
        );

        // --- Second SSTORE: still fits in remaining reservoir (270k left, need 230k) ---
        provider.sstore(address, U256::from(2), U256::from(43))?;

        assert_eq!(
            provider.state_gas_used(),
            2 * state_gas_per_sstore,
            "two SSTOREs should consume 460k state gas"
        );
        assert_eq!(
            provider.reservoir(),
            reservoir - 2 * state_gas_per_sstore,
            "reservoir should have 40k left after 2 SSTOREs"
        );
        let remaining_reservoir = provider.reservoir(); // 40k
        let regular_gas_before_spill = provider.gas_used();

        // --- Third SSTORE: reservoir insufficient, 190k spills to regular gas ---
        provider.sstore(address, U256::from(3), U256::from(44))?;

        assert_eq!(
            provider.state_gas_used(),
            3 * state_gas_per_sstore,
            "three SSTOREs should consume 690k state gas total"
        );
        assert_eq!(
            provider.reservoir(),
            0,
            "reservoir should be fully exhausted"
        );

        // Regular gas increase = normal sstore cost + spill from reservoir
        let spill = state_gas_per_sstore - remaining_reservoir; // 230k - 40k = 190k
        let expected_regular_after = regular_gas_before_spill + regular_gas_per_sstore + spill;
        assert_eq!(
            provider.gas_used(),
            expected_regular_after,
            "regular gas should include spill of {spill} from exhausted reservoir"
        );

        Ok(())
    }

    #[test]
    fn test_t4_cold_sstore_matches_tip1016_spec() -> eyre::Result<()> {
        let mut evm = TestEvm::new_with_tip1016(TempoHardfork::T4);
        let mut provider = evm.provider_with_reservoir(460_000);

        let (address, cold_slot, warm_slot) = (Address::random(), U256::ONE, U256::from(2));

        provider.sstore(address, cold_slot, U256::ONE)?;
        assert_eq!(
            provider.gas_used(),
            22_200,
            "TIP-1016 cold SSTORE should consume 22,200 regular gas including the retained Berlin cold-slot access charge"
        );
        assert_eq!(
            provider.state_gas_used(),
            230_000,
            "TIP-1016 cold SSTORE should consume 230,000 state gas"
        );

        provider.sload(address, warm_slot)?;
        let gas_before_warm_sstore = provider.gas_used();
        let state_gas_before_warm_sstore = provider.state_gas_used();

        provider.sstore(address, warm_slot, U256::ONE)?;
        assert_eq!(
            provider.gas_used() - gas_before_warm_sstore,
            20_100,
            "TIP-1016 warm zero-to-non-zero SSTORE should consume 20,100 regular gas after the slot is warmed by SLOAD"
        );
        assert_eq!(
            provider.state_gas_used() - state_gas_before_warm_sstore,
            230_000,
            "TIP-1016 warm zero-to-non-zero SSTORE should still consume 230,000 state gas"
        );

        Ok(())
    }

    #[test]
    fn test_t4_set_code_new_account_matches_tip1016_success_path() -> eyre::Result<()> {
        let mut evm = TestEvm::new_with_tip1016(TempoHardfork::T4);
        let gas_params = evm.gas_params();

        let code = Bytes::from(vec![0xef]);
        let expected_state_gas =
            gas_params.create_state_gas() + gas_params.code_deposit_state_gas(code.len());
        let expected_regular_gas = u64::from(gas_params.get(GasId::Create))
            + u64::from(gas_params.get(GasId::CodeDepositCost)) * code.len() as u64
            + gas_params.keccak256_word_cost(code.len().div_ceil(32));
        let mut provider = evm.provider_with_reservoir(expected_state_gas);

        provider.set_code(Address::random(), code)?;
        assert_eq!(
            provider.gas_used(),
            expected_regular_gas,
            "TIP-1016 CREATE success path should charge CREATE + code deposit"
        );
        assert_eq!(
            provider.state_gas_used(),
            expected_state_gas,
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
    fn test_sstore_insufficient_gas_for_cold_load_t4() -> eyre::Result<()> {
        // T4 fork sstore with a tight gas budget: cold-load cost is skipped when the
        // pre-charged static gas leaves the remaining gas below the cold additional cost.
        let mut evm = TestEvm::new_with_tip1016(TempoHardfork::T4);
        let gas_params = evm.gas_params();

        let static_gas = u64::from(gas_params.get(GasId::SstoreStatic));
        let dynamic_gas = 25_000u64;
        let gas_limit = static_gas + dynamic_gas;

        // Generous reservoir so T4 state-gas (zero->non-zero) doesn't spill into regular gas.
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
        let warm_read_gas = u64::from(gas_params.get(GasId::WarmStorageReadCost));
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

        let static_gas = u64::from(gas_params.get(GasId::SstoreStatic));
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
    fn test_multiple_sstore_insufficient_gas_scenarios_t4() -> eyre::Result<()> {
        // T4 fork multiple sstores under a constrained gas budget.
        let mut evm = TestEvm::new_with_tip1016(TempoHardfork::T4);
        let gas_params = evm.gas_params();

        let static_gas = u64::from(gas_params.get(GasId::SstoreStatic));
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
    fn test_clearing_storage_mints_a_tip1060_credit() -> eyre::Result<()> {
        let owner = Address::repeat_byte(0x33);
        let key = U256::from(1);
        let mut evm = TestEvm::with_storage(TempoHardfork::T7, owner, key, U256::ONE);
        let mut provider = evm.provider_max_gas();

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
    #[ignore = "TIP-1016 mismatch: 0->X->0 refund math does not net to GAS_WARM_ACCESS (100 gas) yet"]
    fn test_t4_sstore_restore_refund_matches_tip1016_spec() -> eyre::Result<()> {
        let mut evm = TestEvm::new(TempoHardfork::T4);
        let mut provider = evm.provider_with_reservoir(230_000);

        let (address, slot) = (Address::random(), U256::ONE);
        provider.sstore(address, slot, U256::ONE)?;
        provider.sstore(address, slot, U256::ZERO)?;
        assert_eq!(provider.gas_refunded(), 247_800);
        let net_gas_after_refund =
            provider.gas_used() + provider.state_gas_used() - provider.gas_refunded() as u64;
        assert_eq!(
            net_gas_after_refund, 100,
            "TIP-1016 says 0->X->0 should net to GAS_WARM_ACCESS (100)"
        );

        Ok(())
    }
}
