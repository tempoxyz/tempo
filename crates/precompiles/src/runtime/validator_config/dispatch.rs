#[cfg(test)]
mod tests {
    use crate::{
        Precompile, expect_precompile_revert,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
        validator_config::{
            IValidatorConfig, Interface as _, ValidatorConfig, ValidatorConfigError,
        },
    };
    use alloy::{
        primitives::{Address, FixedBytes},
        sol_types::{SolCall, SolValue},
    };
    use revm::precompile::PrecompileError;
    use tempo_chainspec::hardfork::TempoHardfork;

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
                new_validator_address: validator_addr,
                public_key,
                active: true,
                inbound_address: "192.168.1.1:8000".to_string(),
                outbound_address: "192.168.1.1:9000".to_string(),
            };
            let calldata = add_call.abi_encode();

            let result = validator_config.call(&calldata, owner)?;

            // HashMapStorageProvider does not have gas accounting, so we expect 0
            assert_eq!(result.gas_used, 0);

            // Verify validator was added by calling getValidators
            let validators = validator_config.get_validators()?;
            assert_eq!(validators.len(), 1);
            assert_eq!(validators[0].validator_address, validator_addr);
            assert_eq!(validators[0].public_key, public_key);
            assert_eq!(validators[0].inbound_address, "192.168.1.1:8000");
            assert_eq!(validators[0].outbound_address, "192.168.1.1:9000");
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
                new_validator_address: validator_addr,
                public_key,
                active: true,
                inbound_address: "192.168.1.1:8000".to_string(),
                outbound_address: "192.168.1.1:9000".to_string(),
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
                IValidatorConfig::Calls::SELECTORS,
                "IValidatorConfig",
                IValidatorConfig::Calls::name_by_selector,
            );

            assert_full_coverage([unsupported]);

            Ok(())
        })
    }

    #[test]
    fn test_change_validator_status_by_index_t1_gating() -> eyre::Result<()> {
        use crate::dispatch::UnknownFunctionSelector;
        use alloy::sol_types::SolError;

        let owner = Address::random();
        let validator = Address::random();
        let public_key = FixedBytes::<32>::from([0x42; 32]);

        // T0: changeValidatorStatusByIndex returns UnknownFunctionSelector
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T0);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut validator_config = ValidatorConfig::new();
            validator_config.initialize(owner)?;

            // Add a validator first
            validator_config.add_validator(
                owner,
                validator,
                public_key,
                true,
                "192.168.1.1:8000".to_string(),
                "192.168.1.1:9000".to_string(),
            )?;

            // Try to call changeValidatorStatusByIndex in T0 - should return UnknownFunctionSelector
            let call = IValidatorConfig::changeValidatorStatusByIndexCall {
                index: 0,
                active: false,
            };
            let calldata = call.abi_encode();
            let result = validator_config.call(&calldata, owner)?;

            assert!(result.reverted);
            let decoded = UnknownFunctionSelector::abi_decode(&result.bytes)?;
            assert_eq!(
                decoded.selector.0,
                IValidatorConfig::changeValidatorStatusByIndexCall::SELECTOR
            );

            Ok(())
        })?;

        // T1: changeValidatorStatusByIndex works
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut validator_config = ValidatorConfig::new();
            validator_config.initialize(owner)?;

            // Add a validator first
            validator_config.add_validator(
                owner,
                validator,
                public_key,
                true,
                "192.168.1.1:8000".to_string(),
                "192.168.1.1:9000".to_string(),
            )?;

            // changeValidatorStatusByIndex should work in T1
            let call = IValidatorConfig::changeValidatorStatusByIndexCall {
                index: 0,
                active: false,
            };
            let calldata = call.abi_encode();
            let result = validator_config.call(&calldata, owner)?;

            assert!(
                !result.reverted,
                "changeValidatorStatusByIndex should succeed in T1"
            );

            // Verify the status was changed
            let validators = validator_config.get_validators()?;
            assert!(!validators[0].active, "Validator should be inactive");

            Ok(())
        })
    }
}
