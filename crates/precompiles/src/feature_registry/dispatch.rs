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
                IFeatureRegistryCalls::activationQuorum(call) => {
                    view(call, |_| self.activation_quorum())
                }
                IFeatureRegistryCalls::scheduledFeaturesTip(call) => {
                    view(call, |_| self.scheduled_features_tip())
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
    use alloy::{
        primitives::U256,
        sol_types::{SolCall, SolError, SolValue},
    };
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
    fn activation_quorum_returns_fixed_threshold() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let registry = FeatureRegistry::new();
            let quorum = registry.activation_quorum()?;
            assert_eq!(quorum.numerator, U256::from(4));
            assert_eq!(quorum.denominator, U256::from(5));
            Ok(())
        })
    }

    #[test]
    fn scheduled_features_tip_defaults_to_zero() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let registry = FeatureRegistry::new();
            let scheduled = registry.scheduled_features_tip()?;
            assert_eq!(scheduled.featuresTip, 0);
            assert_eq!(scheduled.activationEpoch, 0);
            Ok(())
        })
    }

    #[test]
    fn scheduled_features_tip_reads_schedule_fields() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            registry.scheduled_features_tip.write(13)?;
            registry.scheduled_activation_epoch.write(21)?;

            let scheduled = registry.scheduled_features_tip()?;
            assert_eq!(scheduled.featuresTip, 13);
            assert_eq!(scheduled.activationEpoch, 21);

            Ok(())
        })
    }

    #[test]
    fn scheduled_features_tip_preserves_active_features_tip() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            registry.features_tip.write(7)?;
            registry.scheduled_features_tip.write(13)?;
            registry.scheduled_activation_epoch.write(21)?;

            assert_eq!(registry.features_tip()?, 7);
            let scheduled = registry.scheduled_features_tip()?;
            assert_eq!(scheduled.featuresTip, 13);
            assert_eq!(scheduled.activationEpoch, 21);

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
    fn activation_quorum_dispatch_returns_encoded_threshold() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();

            let call = IFeatureRegistry::activationQuorumCall {};
            let result = registry.call(&call.abi_encode(), Address::ZERO)?;
            assert!(!result.is_revert());
            let decoded =
                IFeatureRegistry::activationQuorumCall::abi_decode_returns(&result.bytes)?;
            assert_eq!(decoded.numerator, U256::from(4));
            assert_eq!(decoded.denominator, U256::from(5));

            Ok(())
        })
    }

    #[test]
    fn scheduled_features_tip_dispatch_returns_encoded_schedule() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = FeatureRegistry::new();
            registry.scheduled_features_tip.write(34)?;
            registry.scheduled_activation_epoch.write(55)?;

            let call = IFeatureRegistry::scheduledFeaturesTipCall {};
            let result = registry.call(&call.abi_encode(), Address::ZERO)?;
            assert!(!result.is_revert());
            let decoded =
                IFeatureRegistry::scheduledFeaturesTipCall::abi_decode_returns(&result.bytes)?;
            assert_eq!(decoded.featuresTip, 34);
            assert_eq!(decoded.activationEpoch, 55);

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
