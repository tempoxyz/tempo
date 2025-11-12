use super::{IValidatorConfig, ValidatorConfig};
use crate::{Precompile, input_cost, mutate_void, storage::PrecompileStorageProvider, view};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};

impl<'a, S: PrecompileStorageProvider> Precompile for ValidatorConfig<'a, S> {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        self.storage
            .deduct_gas(input_cost(calldata.len()))
            .map_err(|_| PrecompileError::OutOfGas)?;

        let selector: [u8; 4] = calldata
            .get(..4)
            .ok_or_else(|| {
                PrecompileError::Other("Invalid input: missing function selector".to_string())
            })?
            .try_into()
            .map_err(|_| PrecompileError::Other("Invalid function selector length".to_string()))?;

        let result = match selector {
            // View functions
            IValidatorConfig::ownerCall::SELECTOR => {
                view::<IValidatorConfig::ownerCall>(calldata, |_call| self.owner())
            }
            IValidatorConfig::getValidatorsCall::SELECTOR => {
                view::<IValidatorConfig::getValidatorsCall>(calldata, |call| {
                    self.get_validators(call)
                })
            }

            // Mutate functions
            IValidatorConfig::addValidatorCall::SELECTOR => {
                mutate_void::<IValidatorConfig::addValidatorCall>(
                    calldata,
                    msg_sender,
                    |s, call| self.add_validator(s, call),
                )
            }
            IValidatorConfig::updateValidatorCall::SELECTOR => {
                mutate_void::<IValidatorConfig::updateValidatorCall>(
                    calldata,
                    msg_sender,
                    |s, call| self.update_validator(s, call),
                )
            }
            IValidatorConfig::changeValidatorStatusCall::SELECTOR => {
                mutate_void::<IValidatorConfig::changeValidatorStatusCall>(
                    calldata,
                    msg_sender,
                    |s, call| self.change_validator_status(s, call),
                )
            }
            IValidatorConfig::changeOwnerCall::SELECTOR => {
                mutate_void::<IValidatorConfig::changeOwnerCall>(calldata, msg_sender, |s, call| {
                    self.change_owner(s, call)
                })
            }

            _ => Err(PrecompileError::Other(
                "Unknown function selector".to_string(),
            )),
        };

        result.map(|mut res| {
            res.gas_used = self.storage.gas_used();
            res
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        expect_precompile_revert,
        storage::hashmap::HashMapStorageProvider,
        test_util::{assert_full_coverage, check_selector_coverage},
    };
    use alloy::{
        primitives::{Bytes, FixedBytes},
        sol_types::SolValue,
    };
    use tempo_contracts::precompiles::{
        IValidatorConfig::IValidatorConfigCalls, ValidatorConfigError,
    };

    #[test]
    fn test_function_selector_dispatch() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut validator_config = ValidatorConfig::new(&mut storage);
        let sender = Address::from([1u8; 20]);

        // Initialize with owner
        let owner = Address::from([0u8; 20]);
        validator_config.initialize(owner).unwrap();

        // Test invalid selector
        let result = validator_config.call(&Bytes::from([0x12, 0x34, 0x56, 0x78]), sender);
        assert!(matches!(result, Err(PrecompileError::Other(_))));

        // Test insufficient calldata
        let result = validator_config.call(&Bytes::from([0x12, 0x34]), sender);
        assert!(matches!(result, Err(PrecompileError::Other(_))));
    }

    #[test]
    fn test_owner_view_dispatch() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut validator_config = ValidatorConfig::new(&mut storage);
        let sender = Address::from([1u8; 20]);

        // Initialize with owner
        let owner = Address::from([0u8; 20]);
        validator_config.initialize(owner).unwrap();

        // Call owner() via dispatch
        let owner_call = IValidatorConfig::ownerCall {};
        let calldata = owner_call.abi_encode();

        let result = validator_config
            .call(&Bytes::from(calldata), sender)
            .unwrap();
        // HashMapStorageProvider does not do gas accounting, so we expect 0 here.
        assert_eq!(result.gas_used, 0);

        // Verify we get the correct owner
        let decoded = Address::abi_decode(&result.bytes).unwrap();
        assert_eq!(decoded, owner);
    }

    #[test]
    fn test_add_validator_dispatch() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut validator_config = ValidatorConfig::new(&mut storage);

        // Initialize with owner
        let owner = Address::from([0u8; 20]);
        validator_config.initialize(owner).unwrap();

        // Add validator via dispatch
        let validator_addr = Address::from([1u8; 20]);
        let public_key = FixedBytes::<32>::from([0x42; 32]);
        let add_call = IValidatorConfig::addValidatorCall {
            newValidatorAddress: validator_addr,
            publicKey: public_key,
            active: true,
            inboundAddress: "192.168.1.1:8000".to_string(),
            outboundAddress: "192.168.1.1:9000".to_string(),
        };
        let calldata = add_call.abi_encode();

        let result = validator_config
            .call(&Bytes::from(calldata), owner)
            .unwrap();

        // HashMapStorageProvider does not have gas accounting, so we expect 0
        assert_eq!(result.gas_used, 0);

        // Verify validator was added by calling getValidators
        let get_call = IValidatorConfig::getValidatorsCall {};
        let validators = validator_config.get_validators(get_call).unwrap();
        assert_eq!(validators.len(), 1);
        assert_eq!(validators[0].validatorAddress, validator_addr);
        assert_eq!(validators[0].publicKey, public_key);
        assert_eq!(validators[0].inboundAddress, "192.168.1.1:8000");
        assert_eq!(validators[0].outboundAddress, "192.168.1.1:9000");
        assert!(validators[0].active);
    }

    #[test]
    fn test_unauthorized_add_validator_dispatch() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut validator_config = ValidatorConfig::new(&mut storage);

        // Initialize with owner
        let owner = Address::from([0u8; 20]);
        validator_config.initialize(owner).unwrap();

        // Try to add validator as non-owner
        let non_owner = Address::from([1u8; 20]);
        let validator_addr = Address::from([2u8; 20]);
        let public_key = FixedBytes::<32>::from([0x42; 32]);
        let add_call = IValidatorConfig::addValidatorCall {
            newValidatorAddress: validator_addr,
            publicKey: public_key,
            active: true,
            inboundAddress: "192.168.1.1:8000".to_string(),
            outboundAddress: "192.168.1.1:9000".to_string(),
        };
        let calldata = add_call.abi_encode();

        let result = validator_config.call(&Bytes::from(calldata), non_owner);
        expect_precompile_revert(&result, ValidatorConfigError::unauthorized());
    }

    #[test]
    fn validator_config_test_selector_coverage() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut validator_config = ValidatorConfig::new(&mut storage);

        let unsupported = check_selector_coverage(
            &mut validator_config,
            IValidatorConfigCalls::SELECTORS,
            "IValidatorConfig",
            IValidatorConfigCalls::name_by_selector,
        );

        assert_full_coverage([unsupported]);
    }
}
