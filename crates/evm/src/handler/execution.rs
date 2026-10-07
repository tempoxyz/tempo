//! Transaction services shared by interpreter and direct payment execution.
use crate::{
    FeeTokenResolver, ProtocolFeeContext, TempoBlockEnv, TempoEvmExt, TempoEvmTypes,
    TempoFeeManager, TempoStateAccess, TempoTxEnv,
};
use alloy_eips::eip2930::AccessList;
use alloy_primitives::{Address, TxKind, U256};
use evm2::{
    Evm, EvmFeatures, TxResult, Version, evm::State, handler::GasSettlement,
    interpreter::GasTracker, registry::HandlerResult, version::GasParams,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{
    error::Result as TempoResult,
    storage::{PrecompileStorageProvider, StorageCtx, evm::EvmPrecompileStorageProvider},
    tip_fee_manager::TipFeeManager,
};

pub(super) trait TempoExecutionHost<'db>: TempoStateAccess<((),)> + Sized {
    fn state(&self) -> &State<'db>;
    fn state_mut(&mut self) -> &mut State<'db>;
    fn version(&self) -> &Version;
    fn block(&self) -> &TempoBlockEnv;
    fn config_spec_id(&self) -> TempoHardfork;
    fn ext(&self) -> &TempoEvmExt;
    fn ext_mut(&mut self) -> &mut TempoEvmExt;

    fn feature(&self, feature: EvmFeatures) -> bool {
        self.version().feature(feature)
    }

    fn enter_storage_with_gas_params<R>(
        &mut self,
        credits: bool,
        gas_limit: u64,
        reservoir: u64,
        gas_params: GasParams,
        f: impl FnOnce() -> R,
    ) -> (R, GasTracker) {
        let mut gas = GasTracker::new_with_execution_gas_and_reservoir(gas_limit, reservoir);
        let version = *self.version();
        let block = *self.block();
        let spec = self.config_spec_id();
        let actions = self.ext().actions.clone();
        let slots = self.ext().non_creditable_slots.clone();
        let mut storage = EvmPrecompileStorageProvider::<TempoEvmTypes>::from_state(
            self.state_mut(),
            &mut gas,
            version,
            block,
            spec,
            false,
        )
        .with_actions(actions)
        .with_non_creditable_slots(slots)
        .with_gas_params(gas_params);
        storage.set_tip1060_storage_credits(credits);
        let result = StorageCtx::enter(&mut storage, f);
        (result, gas)
    }

    fn enter_protocol_storage<R>(&mut self, f: impl FnOnce() -> R) -> R {
        self.enter_storage_with_gas_params(false, u64::MAX, 0, self.version().gas_params, f)
            .0
    }

    fn enter_metered_storage<R>(
        &mut self,
        gas: u64,
        reservoir: u64,
        f: impl FnOnce() -> R,
    ) -> (R, GasTracker) {
        self.enter_storage_with_gas_params(true, gas, reservoir, self.version().gas_params, f)
    }

    fn warm_base_accounts(&mut self, caller: Address, to: TxKind) {
        self.state_mut().prewarm(&caller);
        if self.feature(EvmFeatures::EIP3651) {
            let beneficiary = self.block().beneficiary;
            self.state_mut().prewarm(&beneficiary);
        }
        if let TxKind::Call(to) = to {
            self.state_mut().prewarm(&to);
        }
        // Native payment calls do not access Ethereum builtin accounts. The EVM
        // implementation below retains its full precompile prewarm list.
    }

    fn warm_access_list(&mut self, list: &AccessList) {
        for item in list.iter() {
            self.state_mut().prewarm_storage(
                &item.address,
                item.storage_keys
                    .iter()
                    .map(|key| U256::from_be_bytes(key.0)),
            );
        }
    }

    fn get_fee_token(
        &mut self,
        tx: &TempoTxEnv,
        payer: Address,
        spec: TempoHardfork,
    ) -> TempoResult<Address> {
        let actions = self.ext().actions.clone();
        TempoFeeManager::new().resolve_fee_token(self, tx, payer, spec, actions)
    }

    fn validate_fee_token(&mut self, token: Address, spec: TempoHardfork) -> HandlerResult<()> {
        let actions = self.ext().actions.clone();
        self.ensure_tip20_usd(spec, token, actions)
    }

    fn get_validator_token(&mut self, beneficiary: Address) -> TempoResult<Address> {
        let actions = self.ext().actions.clone();
        self.with_read_only_storage_ctx(self.config_spec_id(), actions, || {
            TipFeeManager::new().get_validator_token(beneficiary)
        })
    }

    fn collect_fee_pre_tx(
        &mut self,
        payer: Address,
        token: Address,
        max: U256,
        beneficiary: Address,
        skip: bool,
    ) -> TempoResult<Address> {
        self.enter_protocol_storage(|| {
            TipFeeManager::new().collect_fee_pre_tx(payer, token, max, beneficiary, skip)
        })
    }

    fn collect_fee_post_tx(
        &mut self,
        payer: Address,
        spending: U256,
        refund: U256,
        token: Address,
        beneficiary: Address,
    ) -> TempoResult<U256> {
        self.enter_protocol_storage(|| {
            TipFeeManager::new().collect_fee_post_tx(payer, spending, refund, token, beneficiary)
        })
    }

    fn finalize_gas(
        &mut self,
        gas: GasSettlement<TempoEvmTypes>,
    ) -> HandlerResult<TxResult<TempoEvmTypes>> {
        let result = gas.result;
        Ok(TxResult::<TempoEvmTypes> {
            status: result.is_success(),
            total_gas_spent: gas
                .gas_limit
                .saturating_sub(result.gas.remaining())
                .saturating_sub(result.gas.reservoir()),
            state_gas_spent: (result
                .gas
                .state_gas_spent()
                .saturating_add_unsigned(gas.initial_state_gas)
                .max(0) as u64)
                .saturating_sub(gas.state_refund),
            refunded: result.final_refund(
                gas.gas_limit,
                u64::from(
                    self.version()
                        .gas_params
                        .get(evm2::version::GasId::MaxRefundQuotient),
                ),
            ),
            floor_gas: gas.floor_gas,
            stop: result.stop,
            output: result.output,
            created_address: result.created_address,
            ..Default::default()
        })
    }
}

impl<'db> TempoExecutionHost<'db> for Evm<'db, TempoEvmTypes> {
    fn state(&self) -> &State<'db> {
        Evm::state(self)
    }
    fn state_mut(&mut self) -> &mut State<'db> {
        Evm::state_mut(self)
    }
    fn version(&self) -> &Version {
        Evm::version(self)
    }
    fn block(&self) -> &TempoBlockEnv {
        Evm::block(self)
    }
    fn config_spec_id(&self) -> TempoHardfork {
        Evm::config_spec_id(self)
    }
    fn ext(&self) -> &TempoEvmExt {
        Evm::ext(self)
    }
    fn ext_mut(&mut self) -> &mut TempoEvmExt {
        Evm::ext_mut(self)
    }
    fn enter_storage_with_gas_params<R>(
        &mut self,
        credits: bool,
        gas_limit: u64,
        reservoir: u64,
        params: GasParams,
        f: impl FnOnce() -> R,
    ) -> (R, GasTracker) {
        let mut gas = GasTracker::new_with_execution_gas_and_reservoir(gas_limit, reservoir);
        let actions = self.ext().actions.clone();
        let slots = self.ext().non_creditable_slots.clone();
        let spec = self.config_spec_id();
        let mut storage = EvmPrecompileStorageProvider::new(self, &mut gas, spec, false)
            .with_actions(actions)
            .with_non_creditable_slots(slots)
            .with_gas_params(params);
        storage.set_tip1060_storage_credits(credits);
        let result = StorageCtx::enter(&mut storage, f);
        (result, gas)
    }
    fn warm_base_accounts(&mut self, caller: Address, to: TxKind) {
        evm2::ethereum::warm_base_accounts(self, caller, to);
    }
    fn get_fee_token(
        &mut self,
        tx: &TempoTxEnv,
        payer: Address,
        spec: TempoHardfork,
    ) -> TempoResult<Address> {
        self.ext()
            .fee_manager
            .clone()
            .get_fee_token(self, tx, payer, spec)
    }
    fn validate_fee_token(&mut self, token: Address, spec: TempoHardfork) -> HandlerResult<()> {
        self.ext()
            .fee_manager
            .clone()
            .validate_fee_token(self, token, spec)
    }
    fn get_validator_token(&mut self, beneficiary: Address) -> TempoResult<Address> {
        self.ext()
            .fee_manager
            .clone()
            .get_validator_token(self, beneficiary)
    }
    fn collect_fee_pre_tx(
        &mut self,
        payer: Address,
        token: Address,
        max: U256,
        beneficiary: Address,
        skip: bool,
    ) -> TempoResult<Address> {
        self.ext().fee_manager.clone().collect_fee_pre_tx(
            ProtocolFeeContext { host: self },
            payer,
            token,
            max,
            beneficiary,
            skip,
        )
    }
    fn collect_fee_post_tx(
        &mut self,
        payer: Address,
        spending: U256,
        refund: U256,
        token: Address,
        beneficiary: Address,
    ) -> TempoResult<U256> {
        self.ext().fee_manager.clone().collect_fee_post_tx(
            ProtocolFeeContext { host: self },
            payer,
            spending,
            refund,
            token,
            beneficiary,
        )
    }
    fn finalize_gas(
        &mut self,
        gas: GasSettlement<TempoEvmTypes>,
    ) -> HandlerResult<TxResult<TempoEvmTypes>> {
        evm2::ethereum::finalize_gas(self, gas)
    }
}
