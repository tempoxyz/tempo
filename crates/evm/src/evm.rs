use crate::{
    ProtocolFeeManager, TempoEvmExt, TempoEvmTypes, TempoFeeManager, TempoPoolValidationError,
    TempoPoolValidationEvm, TempoPoolValidationResult, TempoTxEnv, ValidationContext,
};
use alloy_consensus::transaction::Recovered;
use evm2::{AnyError, registry::HandlerError};
use std::sync::Arc;

/// Tempo's EVM is EVM2 with the Tempo type family.
pub type TempoEvm<'a> = evm2::Evm<'a, TempoEvmTypes>;

/// Configuration copied into each Tempo EVM instance.
#[derive(Clone, Debug)]
pub struct TempoEvmFactory {
    fee_manager: Arc<dyn ProtocolFeeManager>,
}

impl Default for TempoEvmFactory {
    fn default() -> Self {
        Self {
            fee_manager: Arc::new(TempoFeeManager::new()),
        }
    }
}

impl TempoEvmFactory {
    /// Uses a custom protocol fee implementation for subsequently created EVMs.
    pub fn with_fee_manager(mut self, fee_manager: impl ProtocolFeeManager + 'static) -> Self {
        self.fee_manager = Arc::new(fee_manager);
        self
    }

    pub(crate) fn evm_ext(&self, mut ext: TempoEvmExt) -> TempoEvmExt {
        ext.fee_manager = self.fee_manager.clone();
        ext
    }
}

impl reth_evm_ethereum::EvmFactory for TempoEvmFactory {
    type Types = TempoEvmTypes;
    type SpecId = tempo_chainspec::hardfork::TempoHardfork;

    fn spec_id(&self, spec: evm2::SpecId) -> Self::SpecId {
        spec.into()
    }

    fn execution_config(
        &self,
        spec: Self::SpecId,
        version: evm2::Version,
    ) -> evm2::ExecutionConfig<Self::Types> {
        evm2::ExecutionConfig::for_spec_and_version(spec, version)
    }

    fn tx_registry(
        &self,
        spec: Self::SpecId,
    ) -> evm2::registry::TxRegistry<Self::Types, evm2::TxResult<Self::Types>> {
        crate::tempo_tx_registry(spec.into())
    }

    fn configure_evm(&self, evm: &mut TempoEvm<'_>) {
        let spec = evm.config_spec_id();
        let mut ext = core::mem::take(evm.ext_mut());
        ext.fee_manager = self.fee_manager.clone();
        let precompiles = tempo_precompiles::TempoPrecompiles::new(
            spec,
            ext.actions.clone(),
            ext.non_creditable_slots.clone(),
        );
        *evm.ext_mut() = ext;
        evm.set_precompiles(precompiles);
    }
}

impl TempoPoolValidationEvm for TempoEvm<'_> {
    fn configure_for_pool(&mut self) {
        self.ext_mut().skip_valid_after_check = true;
        self.ext_mut().skip_liquidity_check = true;
    }

    fn validate_pool_transaction(
        &mut self,
        tx: TempoTxEnv,
    ) -> (TempoPoolValidationResult, TempoTxEnv) {
        let signer = tx.evm_tx().signer();
        let tx = Recovered::new_unchecked(tx, signer);
        let result = crate::handler::validate_transaction(self, &tx)
            .map(|()| ValidationContext {
                fee_token: self
                    .ext()
                    .resolved_fee_token
                    .expect("successful Tempo handler resolves a fee token"),
                key_expiry: self.ext().key_expiry,
            })
            .map_err(|err| match err {
                HandlerError::Fatal(error) => TempoPoolValidationError::Fatal(error),
                HandlerError::Database(error) if error.is_fatal() => {
                    TempoPoolValidationError::Fatal(AnyError::new(error))
                }
                err => TempoPoolValidationError::Invalid(err),
            });
        self.state_mut().clear_transaction_state();
        self.ext_mut().resolved_fee_token = None;
        self.ext_mut().key_expiry = None;
        self.ext().non_creditable_slots.borrow_mut().clear();
        (result, tx.into_inner())
    }
}

#[cfg(test)]
mod tests;
