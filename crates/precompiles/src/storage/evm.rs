use crate::{
    error::TempoPrecompileError,
    storage::{PrecompileStorageProvider, StorageActions, actions::StorageAction},
    storage_credits::{NonCreditableSlots, StorageCreditsBackend, sstore_storage_credits},
};
use alloy::primitives::{Address, Bytes, Log, LogData, U256};
use evm2::{
    Evm, EvmFeatures, EvmTypes, Version,
    bytecode::Bytecode,
    evm::{SLoad, SStore, State},
    interpreter::{GasTracker, gas},
    version::GasId,
};
use std::{
    cell::RefCell,
    ops::{Deref, DerefMut},
    rc::Rc,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_primitives::{TempoBlockEnv, TempoBlockExt};

/// Production [`PrecompileStorageProvider`] backed by EVM2's live transaction state.
///
/// Wraps [`State`] and tracks gas consumption for storage operations.
pub struct EvmPrecompileStorageProvider<'state, 'gas, 'db> {
    state: &'state mut State<'db>,
    version: Version,
    block: TempoBlockEnv,
    gas_tracker: GasTrackerStorage<'gas>,
    spec: TempoHardfork,
    is_static: bool,
    tip1060_storage_credits_enabled: bool,
    tip1060_storage_credit_minting_enabled: bool,
    non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
    /// Recorded storage actions.
    actions: StorageActions,
}

impl<'state, 'gas, 'db> EvmPrecompileStorageProvider<'state, 'gas, 'db> {
    /// Creates a storage provider over EVM2's live state and gas tracker.
    pub fn new<T>(
        evm: &'state mut Evm<'db, T>,
        gas_tracker: &'gas mut GasTracker,
        spec: TempoHardfork,
        is_static: bool,
    ) -> Self
    where
        T: EvmTypes<BlockEnvExt = TempoBlockExt>,
    {
        let version = *evm.version();
        let block = *evm.block();
        Self::with_gas_tracker(
            evm.state_mut(),
            version,
            block,
            GasTrackerStorage::Borrowed(gas_tracker),
            spec,
            is_static,
        )
    }

    /// Creates a non-static storage provider with the maximum gas limit.
    pub fn new_max_gas<T>(evm: &'state mut Evm<'db, T>, spec: TempoHardfork) -> Self
    where
        T: EvmTypes<BlockEnvExt = TempoBlockExt>,
    {
        let version = *evm.version();
        let block = *evm.block();
        Self::with_gas_tracker(
            evm.state_mut(),
            version,
            block,
            GasTrackerStorage::Owned(GasTracker::new(u64::MAX)),
            spec,
            false,
        )
    }

    fn with_gas_tracker(
        state: &'state mut State<'db>,
        version: Version,
        block: TempoBlockEnv,
        gas_tracker: GasTrackerStorage<'gas>,
        spec: TempoHardfork,
        is_static: bool,
    ) -> Self {
        Self {
            state,
            version,
            block,
            gas_tracker,
            spec,
            is_static,
            tip1060_storage_credits_enabled: spec.is_t7(),
            tip1060_storage_credit_minting_enabled: true,
            non_creditable_slots: Rc::new(RefCell::new(NonCreditableSlots::empty())),
            actions: StorageActions::disabled(),
        }
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
        self.gas_tracker
            .spend_state(gas)
            .map_err(|_| TempoPrecompileError::OutOfGas)
    }

    /// Performs a raw journaled SLOAD without metering gas or recording a storage action.
    #[inline]
    fn sload_journal(
        &mut self,
        address: Address,
        key: U256,
        skip_cold_load: bool,
    ) -> Result<SLoad, TempoPrecompileError> {
        let mut slot = self
            .state
            .storage(&address)
            .into_slot(key, skip_cold_load)?;
        let is_cold = self.version.feature(EvmFeatures::EIP2929) && slot.warm();
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
        let mut slot = self
            .state
            .storage(&address)
            .into_slot(key, skip_cold_load)?;
        let is_cold = self.version.feature(EvmFeatures::EIP2929) && slot.warm();
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
            self.deduct_gas(u64::from(
                self.version.gas_params.get(GasId::WarmStorageReadCost),
            ))?;
        }

        // dynamic gas
        if result.is_cold {
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
        // T4+: pre-charge static gas before loading storage to avoid cheap useless work.
        let skip_cold_load = if self.spec.is_t4() {
            self.deduct_gas(u64::from(self.version.gas_params.get(GasId::SstoreStatic)))?;
            self.gas_tracker.remaining()
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

        // dynamic gas
        self.deduct_gas(self.version.gas_params.sstore_dynamic_gas(true, &result))?;

        // Track state gas (cold SSTORE zero->non-zero only)
        self.deduct_state_gas(self.version.gas_params.sstore_state_gas(&result))?;

        // refund gas.
        self.refund_gas(self.version.gas_params.sstore_refund(true, &result));

        Ok(())
    }
}

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

impl StorageCreditsBackend for EvmPrecompileStorageProvider<'_, '_, '_> {
    type Error = TempoPrecompileError;

    #[inline]
    fn gas_params(&self) -> &evm2::version::GasParams {
        &self.version.gas_params
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
        self.state.tload(&address, &key)
    }

    #[inline]
    fn tstore(&mut self, address: Address, key: U256, value: U256) {
        self.state.tstore(&address, &key, &value);
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

impl PrecompileStorageProvider for EvmPrecompileStorageProvider<'_, '_, '_> {
    fn chain_id(&self) -> u64 {
        self.version.chain_id
    }

    fn block_env(&self) -> &TempoBlockEnv {
        &self.block
    }

    #[inline]
    fn set_code(&mut self, address: Address, code: Bytes) -> Result<(), TempoPrecompileError> {
        let code = Bytecode::new_raw(code);
        let code_len = code.len();
        self.deduct_gas(
            u64::from(self.version.gas_params.get(GasId::CodeDepositCost))
                .saturating_mul(code_len as u64),
        )?;

        // Track state gas for code deposit
        self.deduct_state_gas(self.version.gas_params.code_deposit_state_gas(code_len))?;

        let was_empty = {
            let mut account = self.state.account(&address, false)?;
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

    #[inline]
    fn with_account_info(
        &mut self,
        address: Address,
        f: &mut dyn FnMut(&evm2::evm::AccountInfo),
    ) -> Result<(), TempoPrecompileError> {
        let additional_cost = self.version.gas_params.cold_account_additional_cost();

        // T4+: pre-charge static gas to avoid cheap useless work.
        let warm_storage_read_cost =
            u64::from(self.version.gas_params.get(GasId::WarmStorageReadCost));
        let insufficient_gas_for_cold_load = if self.spec.is_t4() {
            self.deduct_gas(warm_storage_read_cost)?;
            self.gas_tracker.remaining() < additional_cost
        } else {
            false
        };

        let mut account = self
            .state
            .account(&address, insufficient_gas_for_cold_load)?;
        let is_cold = self.version.feature(EvmFeatures::EIP2929) && account.warm();

        if !self.spec.is_t4() {
            self.gas_tracker
                .spend(warm_storage_read_cost)
                .map_err(|_| TempoPrecompileError::OutOfGas)?;
        }

        if is_cold {
            self.gas_tracker
                .spend(additional_cost)
                .map_err(|_| TempoPrecompileError::OutOfGas)?;
        }

        account.load_code()?;

        let info = account.get().cloned().unwrap_or_default();
        f(&info);
        Ok(())
    }

    #[inline]
    fn account_code(
        &mut self,
        address: Address,
    ) -> Result<(alloy_primitives::B256, Bytecode), TempoPrecompileError> {
        let mut result = None;
        self.with_account_info(address, &mut |info| {
            result = Some((
                info.code_hash,
                info.code.clone().unwrap_or_else(Bytecode::default),
            ));
        })?;
        Ok(result.expect("account info callback is always invoked"))
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
        self.deduct_gas(u64::from(
            self.version.gas_params.get(GasId::WarmStorageReadCost),
        ))?;
        self.state.tstore(&address, &key, &value);
        Ok(())
    }

    #[inline]
    fn emit_event(&mut self, address: Address, event: LogData) -> Result<(), TempoPrecompileError> {
        self.deduct_gas(
            u64::from(gas::LOG).saturating_add(
                self.version
                    .gas_params
                    .log_cost(event.topics().len() as u8, event.data.len()),
            ),
        )?;

        self.state.log(Log {
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
        self.deduct_gas(u64::from(
            self.version.gas_params.get(GasId::WarmStorageReadCost),
        ))?;
        Ok(self.state.tload(&address, &key))
    }

    #[inline]
    fn deduct_gas(&mut self, gas: u64) -> Result<(), TempoPrecompileError> {
        self.gas_tracker
            .spend(gas)
            .map_err(|_| TempoPrecompileError::OutOfGas)
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
    fn state_gas_used(&self) -> u64 {
        // SAFETY: we never decrement the state gas spent counter
        self.gas_tracker.state_gas_spent() as u64
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

    #[inline]
    fn checkpoint(&mut self) -> evm2::evm::StateCheckpoint {
        self.state.checkpoint()
    }

    #[inline]
    fn checkpoint_commit(&mut self, _checkpoint: evm2::evm::StateCheckpoint) {}

    #[inline]
    fn checkpoint_revert(&mut self, checkpoint: evm2::evm::StateCheckpoint) {
        self.state.rollback(checkpoint, self.version.features);
    }

    #[inline]
    fn set_tip1060_storage_credits(&mut self, enabled: bool) {
        self.tip1060_storage_credits_enabled = enabled && self.spec.is_t7();
    }

    #[inline]
    fn set_tip1060_storage_credit_minting(&mut self, enabled: bool) {
        self.tip1060_storage_credit_minting_enabled = enabled;
    }
}

#[cfg(test)]
mod tests {
    use super::{EvmPrecompileStorageProvider, GasTrackerStorage};
    use crate::{
        STORAGE_CREDITS_ADDRESS,
        error::TempoPrecompileError,
        storage::{PrecompileStorageProvider, StorageActions, actions::StorageAction},
        storage_credits::StorageCredits,
    };
    use alloy::primitives::{Address, B256, Bytes, LogData, U256, b256, bytes, keccak256};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use evm2::{
        SpecId, Version,
        evm::{InMemoryDB, State},
        interpreter::GasTracker,
        version::{GasId, GasParams},
    };
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_primitives::TempoBlockEnv;

    struct TestEvm {
        state: State<'static>,
        gas_tracker: GasTracker,
        version: Version,
        block_env: TempoBlockEnv,
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
                state: State::new(database),
                gas_tracker: GasTracker::new(u64::MAX),
                version,
                block_env: TempoBlockEnv::default(),
                spec,
            }
        }

        fn provider_with_gas_limit(
            &mut self,
            gas_limit: u64,
            reservoir: u64,
        ) -> EvmPrecompileStorageProvider<'_, '_, 'static> {
            self.gas_tracker = GasTracker::new_with_regular_gas_and_reservoir(gas_limit, reservoir);
            EvmPrecompileStorageProvider::with_gas_tracker(
                &mut self.state,
                self.version,
                self.block_env,
                GasTrackerStorage::Borrowed(&mut self.gas_tracker),
                self.spec,
                false,
            )
        }

        fn provider_with_reservoir(
            &mut self,
            reservoir: u64,
        ) -> EvmPrecompileStorageProvider<'_, '_, 'static> {
            self.provider_with_gas_limit(u64::MAX, reservoir)
        }

        fn provider_max_gas(&mut self) -> EvmPrecompileStorageProvider<'_, '_, 'static> {
            EvmPrecompileStorageProvider::with_gas_tracker(
                &mut self.state,
                self.version,
                self.block_env,
                GasTrackerStorage::Owned(GasTracker::new(u64::MAX)),
                self.spec,
                false,
            )
        }

        fn gas_params(&self) -> GasParams {
            self.version.gas_params
        }

        fn load_account_code(&mut self, address: Address) -> eyre::Result<Bytes> {
            let mut account = self
                .state
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
