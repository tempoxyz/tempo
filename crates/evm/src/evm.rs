use crate::{ProtocolFeeManager, TempoEvmExt, TempoEvmTypes, TempoFeeManager};
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

#[cfg(test)]
mod tests;
