//! ABI dispatch for the [`FeatureRegistry`] precompile.

use super::*;
use crate::{
    Precompile, charge_input_cost, dispatch_call, error::TempoPrecompileError, storage::StorageCtx,
    view,
};
use alloy::{
    primitives::Address,
    sol_types::{SolCall, SolInterface},
};
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::IFeatureRegistry::{self, IFeatureRegistryCalls};

fn unsupported<T: SolCall>() -> PrecompileResult {
    StorageCtx.error_result(TempoPrecompileError::UnknownFunctionSelector(T::SELECTOR))
}

impl Precompile for FeatureRegistry {
    fn call(&mut self, calldata: &[u8], _msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch_call(
            calldata,
            &[],
            IFeatureRegistryCalls::abi_decode,
            |call| match call {
                IFeatureRegistryCalls::featuresTip(call) => view(call, |_| self.features_tip()),
                IFeatureRegistryCalls::owner(_) => unsupported::<IFeatureRegistry::ownerCall>(),
                IFeatureRegistryCalls::activationQuorum(_) => {
                    unsupported::<IFeatureRegistry::activationQuorumCall>()
                }
                IFeatureRegistryCalls::scheduledFeaturesTip(_) => {
                    unsupported::<IFeatureRegistry::scheduledFeaturesTipCall>()
                }
                IFeatureRegistryCalls::setSupportedFeaturesTip(_) => {
                    unsupported::<IFeatureRegistry::setSupportedFeaturesTipCall>()
                }
                IFeatureRegistryCalls::scheduleFeaturesTip(_) => {
                    unsupported::<IFeatureRegistry::scheduleFeaturesTipCall>()
                }
                IFeatureRegistryCalls::cancelScheduledFeaturesTip(_) => {
                    unsupported::<IFeatureRegistry::cancelScheduledFeaturesTipCall>()
                }
                IFeatureRegistryCalls::validatorSupportedFeaturesTip(_) => {
                    unsupported::<IFeatureRegistry::validatorSupportedFeaturesTipCall>()
                }
                IFeatureRegistryCalls::featuresTipSupport(_) => {
                    unsupported::<IFeatureRegistry::featuresTipSupportCall>()
                }
                IFeatureRegistryCalls::hasFeaturesTipQuorum(_) => {
                    unsupported::<IFeatureRegistry::hasFeaturesTipQuorumCall>()
                }
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};
    use alloy::sol_types::{SolCall, SolError, SolValue};
    use tempo_chainspec::features::HIGHEST_ACTIVE_PROTOCOL_FEATURE_ID_SLOT;
    use tempo_contracts::precompiles::UnknownFunctionSelector;

    #[test]
    fn features_tip_defaults_to_zero() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let registry = FeatureRegistry::new();
            assert_eq!(registry.features_tip()?, 0);
            Ok(())
        })
    }

    #[test]
    fn features_tip_reads_cursor_slot() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            assert_eq!(
                registry.features_tip.slot(),
                HIGHEST_ACTIVE_PROTOCOL_FEATURE_ID_SLOT
            );

            registry.features_tip.write(7)?;
            assert_eq!(registry.features_tip()?, 7);

            Ok(())
        })
    }

    #[test]
    fn features_tip_dispatch_returns_encoded_cursor() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            registry.features_tip.write(11)?;

            let call = IFeatureRegistry::featuresTipCall {};
            let result = registry.call(&call.abi_encode(), Address::ZERO)?;
            assert!(!result.is_revert());
            assert_eq!(u64::abi_decode(&result.bytes)?, 11);

            Ok(())
        })
    }

    #[test]
    fn unimplemented_selectors_remain_unknown() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            let call = IFeatureRegistry::hasFeaturesTipQuorumCall { featuresTip: 1 };
            let result = registry.call(&call.abi_encode(), Address::ZERO)?;
            assert!(result.is_revert());
            let decoded = UnknownFunctionSelector::abi_decode(&result.bytes)?;
            assert_eq!(
                decoded.selector.0,
                IFeatureRegistry::hasFeaturesTipQuorumCall::SELECTOR
            );

            Ok(())
        })
    }
}
