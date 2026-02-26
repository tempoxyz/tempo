use super::*;
use crate::{Precompile, dispatch_call, input_cost, mutate_void, view};
use alloy::{primitives::Address, sol_types::SolInterface};
use revm::precompile::{PrecompileError, PrecompileResult};
use tempo_contracts::precompiles::IFeatureRegistry::IFeatureRegistryCalls;

impl Precompile for FeatureRegistry {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        self.storage
            .deduct_gas(input_cost(calldata.len()))
            .map_err(|_| PrecompileError::OutOfGas)?;

        dispatch_call(
            calldata,
            IFeatureRegistryCalls::abi_decode,
            |call| match call {
                IFeatureRegistryCalls::owner(call) => view(call, |_| self.owner()),
                IFeatureRegistryCalls::featureWord(call) => {
                    view(call, |c| self.feature_word(c.index))
                }
                IFeatureRegistryCalls::isActive(call) => {
                    view(call, |c| self.is_active(c.featureId))
                }
                IFeatureRegistryCalls::scheduledActivation(call) => {
                    view(call, |c| self.scheduled_activation(c.featureId))
                }
                IFeatureRegistryCalls::activate(call) => {
                    mutate_void(call, msg_sender, |s, c| self.activate(s, c.featureId))
                }
                IFeatureRegistryCalls::deactivate(call) => {
                    mutate_void(call, msg_sender, |s, c| self.deactivate(s, c.featureId))
                }
                IFeatureRegistryCalls::scheduleActivation(call) => {
                    mutate_void(call, msg_sender, |s, c| {
                        self.schedule_activation(s, c.featureId, c.activateAt)
                    })
                }
                IFeatureRegistryCalls::cancelScheduledActivation(call) => {
                    mutate_void(call, msg_sender, |s, c| {
                        self.cancel_scheduled_activation(s, c.featureId)
                    })
                }
                IFeatureRegistryCalls::transferOwnership(call) => {
                    mutate_void(call, msg_sender, |s, c| {
                        self.transfer_ownership(s, c.newOwner)
                    })
                }
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        expect_precompile_revert,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
    };
    use alloy::sol_types::{SolCall, SolValue};
    use tempo_contracts::precompiles::{
        FeatureRegistryError, IFeatureRegistry, IFeatureRegistry::IFeatureRegistryCalls,
    };

    #[test]
    fn test_dispatch_owner() -> eyre::Result<()> {
        let admin = Address::random();
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut reg = FeatureRegistry::new();
            reg.initialize(admin)?;

            let calldata = IFeatureRegistry::ownerCall {}.abi_encode();
            let result = reg.call(&calldata, admin)?;

            assert!(!result.reverted);
            let decoded = Address::abi_decode(&result.bytes)?;
            assert_eq!(decoded, admin);

            Ok(())
        })
    }

    #[test]
    fn test_dispatch_activate_and_is_active() -> eyre::Result<()> {
        let admin = Address::random();
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut reg = FeatureRegistry::new();
            reg.initialize(admin)?;

            // Activate feature 5
            let calldata = IFeatureRegistry::activateCall { featureId: 5 }.abi_encode();
            let result = reg.call(&calldata, admin)?;
            assert!(!result.reverted);

            // Check isActive
            let calldata = IFeatureRegistry::isActiveCall { featureId: 5 }.abi_encode();
            let result = reg.call(&calldata, admin)?;
            assert!(!result.reverted);
            let active = bool::abi_decode(&result.bytes)?;
            assert!(active);

            Ok(())
        })
    }

    #[test]
    fn test_dispatch_unauthorized() -> eyre::Result<()> {
        let admin = Address::random();
        let non_owner = Address::random();
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut reg = FeatureRegistry::new();
            reg.initialize(admin)?;

            let calldata = IFeatureRegistry::activateCall { featureId: 0 }.abi_encode();
            let result = reg.call(&calldata, non_owner);
            expect_precompile_revert(&result, FeatureRegistryError::unauthorized());

            Ok(())
        })
    }

    #[test]
    fn test_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut reg = FeatureRegistry::new();

            let unsupported = check_selector_coverage(
                &mut reg,
                IFeatureRegistryCalls::SELECTORS,
                "IFeatureRegistry",
                IFeatureRegistryCalls::name_by_selector,
            );

            assert_full_coverage([unsupported]);

            Ok(())
        })
    }
}
