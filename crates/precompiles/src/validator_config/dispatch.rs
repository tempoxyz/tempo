use super::ValidatorConfig;
use crate::{
    Precompile, dispatch_call, error::TempoPrecompileError, input_cost, mutate_void, view,
};
use alloy::{primitives::Address, sol_types::SolInterface};
use revm::precompile::{PrecompileError, PrecompileResult};
use tempo_contracts::precompiles::IValidatorConfig::IValidatorConfigCalls;

impl Precompile for ValidatorConfig {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        self.storage
            .deduct_gas(input_cost(calldata.len()))
            .map_err(|_| PrecompileError::OutOfGas)?;

        dispatch_call(
            calldata,
            IValidatorConfigCalls::abi_decode,
            |call| match call {
                // View functions
                IValidatorConfigCalls::owner(call) => view(call, |_| self.owner()),
                IValidatorConfigCalls::getValidators(call) => view(call, |_| self.get_validators()),
                IValidatorConfigCalls::getNextFullDkgCeremony(call) => {
                    view(call, |_| self.get_next_full_dkg_ceremony())
                }
                IValidatorConfigCalls::validatorsArray(call) => view(call, |c| {
                    let index =
                        u64::try_from(c.index).map_err(|_| TempoPrecompileError::array_oob())?;
                    self.validators_array(index)
                }),
                IValidatorConfigCalls::validators(call) => {
                    view(call, |c| self.validators(c.validator))
                }
                IValidatorConfigCalls::validatorCount(call) => {
                    view(call, |_| self.validator_count())
                }

                // Mutate functions
                IValidatorConfigCalls::addValidator(call) => {
                    mutate_void(call, msg_sender, |s, c| self.add_validator(s, c))
                }
                IValidatorConfigCalls::updateValidator(call) => {
                    mutate_void(call, msg_sender, |s, c| self.update_validator(s, c))
                }
                IValidatorConfigCalls::changeValidatorStatus(call) => {
                    mutate_void(call, msg_sender, |s, c| self.change_validator_status(s, c))
                }
                IValidatorConfigCalls::changeOwner(call) => {
                    mutate_void(call, msg_sender, |s, c| self.change_owner(s, c))
                }
                IValidatorConfigCalls::setNextFullDkgCeremony(call) => {
                    mutate_void(call, msg_sender, |s, c| {
                        self.set_next_full_dkg_ceremony(s, c)
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
    use alloy::{
        primitives::{Address, FixedBytes},
        sol_types::{SolCall, SolValue},
    };
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{
        IValidatorConfig, IValidatorConfig::IValidatorConfigCalls, ValidatorConfigError,
    };

    #[test]
    fn test_function_selector_dispatch() -> eyre::Result<()> {
        let sender = Address::random();
        let owner = Address::random();

        // T1: invalid selector returns reverted output
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut validator_config = ValidatorConfig::new();
            validator_config.initialize(owner)?;

            let result = validator_config.call(&[0x12, 0x34, 0x56, 0x78], sender)?;
            assert!(result.reverted);

            // T1: insufficient calldata also returns reverted output
            let result = validator_config.call(&[0x12, 0x34], sender)?;
            assert!(result.reverted);

            Ok(())
        })?;

        // Pre-T1 (T0): insufficient calldata returns error
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T0);
        StorageCtx::enter(&mut storage, || {
            let mut validator_config = ValidatorConfig::new();
            validator_config.initialize(owner)?;

            let result = validator_config.call(&[0x12, 0x34], sender);
            assert!(matches!(result, Err(PrecompileError::Other(_))));

            Ok(())
        })
    }

    #[test]
    fn test_owner_view_dispatch() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();
        let owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut validator_config = ValidatorConfig::new();

            // Initialize with owner
            validator_config.initialize(owner)?;

            // Call owner() via dispatch
            let owner_call = IValidatorConfig::ownerCall {};
            let calldata = owner_call.abi_encode();

            let result = validator_config.call(&calldata, sender)?;
            // HashMapStorageProvider does not do gas accounting, so we expect 0 here.
            assert_eq!(result.gas_used, 0);

            // Verify we get the correct owner
            let decoded = Address::abi_decode(&result.bytes)?;
            assert_eq!(decoded, owner);

            Ok(())
        })
    }

    #[test]
    fn test_add_validator_dispatch() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator_addr = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut validator_config = ValidatorConfig::new();

            // Initialize with owner
            validator_config.initialize(owner)?;

            // Add validator via dispatch
            let public_key = FixedBytes::<32>::from([0x42; 32]);
            let add_call = IValidatorConfig::addValidatorCall {
                newValidatorAddress: validator_addr,
                publicKey: public_key,
                active: true,
                inboundAddress: "192.168.1.1:8000".to_string(),
                outboundAddress: "192.168.1.1:9000".to_string(),
            };
            let calldata = add_call.abi_encode();

            let result = validator_config.call(&calldata, owner)?;

            // HashMapStorageProvider does not have gas accounting, so we expect 0
            assert_eq!(result.gas_used, 0);

            // Verify validator was added by calling getValidators
            let validators = validator_config.get_validators()?;
            assert_eq!(validators.len(), 1);
            assert_eq!(validators[0].validatorAddress, validator_addr);
            assert_eq!(validators[0].publicKey, public_key);
            assert_eq!(validators[0].inboundAddress, "192.168.1.1:8000");
            assert_eq!(validators[0].outboundAddress, "192.168.1.1:9000");
            assert!(validators[0].active);

            Ok(())
        })
    }

    #[test]
    fn test_unauthorized_add_validator_dispatch() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let non_owner = Address::random();
        let validator_addr = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut validator_config = ValidatorConfig::new();

            // Initialize with owner
            validator_config.initialize(owner)?;

            // Try to add validator as non-owner
            let public_key = FixedBytes::<32>::from([0x42; 32]);
            let add_call = IValidatorConfig::addValidatorCall {
                newValidatorAddress: validator_addr,
                publicKey: public_key,
                active: true,
                inboundAddress: "192.168.1.1:8000".to_string(),
                outboundAddress: "192.168.1.1:9000".to_string(),
            };
            let calldata = add_call.abi_encode();

            let result = validator_config.call(&calldata, non_owner);
            expect_precompile_revert(&result, ValidatorConfigError::unauthorized());

            Ok(())
        })
    }

    #[test]
    fn test_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut validator_config = ValidatorConfig::new();

            let unsupported = check_selector_coverage(
                &mut validator_config,
                IValidatorConfigCalls::SELECTORS,
                "IValidatorConfig",
                IValidatorConfigCalls::name_by_selector,
            );

            assert_full_coverage([unsupported]);

            Ok(())
        })
    }
}
