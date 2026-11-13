//! ABI dispatch for the [`ValidatorConfig`] (V1) precompile.

use super::ValidatorConfig;
use crate::{Precompile, charge_input_cost, dispatch, error::TempoPrecompileError, mutate, view};
use alloy::primitives::Address;
use evm2::precompiles::PrecompileResult;
use tempo_contracts::precompiles::IValidatorConfig;

impl Precompile for ValidatorConfig {
    // From T15 every selector reverts with UnknownFunctionSelector: consensus reads only
    // ValidatorConfigV2, so V1 dispatch is kept only to replay historical blocks.
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }
        dispatch!(
            calldata,
            |call| match call {
                IValidatorConfig::IValidatorConfigCalls {
                    // View functions
                    #[schedule(until = T15)]
                    owner(call) => view(call, |_| self.owner()),
                    #[schedule(until = T15)]
                    getValidators(call) => view(call, |_| self.get_validators()),
                    #[schedule(until = T15)]
                    getNextFullDkgCeremony(call) => view(call, |_| self.get_next_full_dkg_ceremony()),
                    #[schedule(until = T15)]
                    validatorsArray(call) => view(call, |c| {
                        let index = u64::try_from(c.index)
                            .map_err(|_| TempoPrecompileError::array_oob())?;
                        self.validators_array(index)
                    }),
                    #[schedule(until = T15)]
                    validators(call) => view(call, |c| self.validators(c.validator)),
                    #[schedule(until = T15)]
                    validatorCount(call) => view(call, |_| self.validator_count()),

                    // Mutate functions
                    #[schedule(until = T15)]
                    addValidator(call) => mutate(call, msg_sender, |sender, c| self.add_validator(sender, c)),
                    #[schedule(until = T15)]
                    updateValidator(call) => mutate(call, msg_sender, |sender, c| self.update_validator(sender, c)),
                    #[schedule(until = T15)]
                    changeValidatorStatus(call) => mutate(call, msg_sender, |sender, c| self.change_validator_status(sender, c)),
                    #[schedule(since = T1, until = T15)]
                    changeValidatorStatusByIndex(call) => mutate(call, msg_sender, |sender, c| {
                        self.change_validator_status_by_index(sender, c)
                    }),
                    #[schedule(until = T15)]
                    changeOwner(call) => mutate(call, msg_sender, |sender, c| self.change_owner(sender, c)),
                    #[schedule(until = T15)]
                    setNextFullDkgCeremony(call) => mutate(call, msg_sender, |sender, c| {
                        self.set_next_full_dkg_ceremony(sender, c)
                    })
                }
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        expect_precompile_revert,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage, revert_bytes},
    };
    use alloy::{
        primitives::{Address, FixedBytes},
        sol_types::{SolCall, SolError, SolValue},
    };
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{
        IValidatorConfig::{self, IValidatorConfigCalls},
        UnknownFunctionSelector, ValidatorConfigError,
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

            let result = validator_config.call(&[0x12, 0x34, 0x56, 0x78], sender);
            assert!(matches!(result, Err(evm2::PrecompileError::Revert(_))));

            // T1: insufficient calldata also returns reverted output
            let result = validator_config.call(&[0x12, 0x34], sender);
            assert!(matches!(result, Err(evm2::PrecompileError::Revert(_))));

            Ok(())
        })?;

        // Pre-T1 (T0): insufficient calldata returns halted output
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T0);
        StorageCtx::enter(&mut storage, || {
            let mut validator_config = ValidatorConfig::new();
            validator_config.initialize(owner)?;

            let result = validator_config.call(&[0x12, 0x34], sender);
            assert!(matches!(result, Err(evm2::PrecompileError::Halt(_))));

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
            let decoded = Address::abi_decode(result.bytes())?;
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
            let public_key = FixedBytes::<32>::repeat_byte(0x42);
            let add_call = IValidatorConfig::addValidatorCall {
                newValidatorAddress: validator_addr,
                publicKey: public_key,
                active: true,
                inboundAddress: "192.168.1.1:8000".to_string(),
                outboundAddress: "192.168.1.1:9000".to_string(),
            };
            let calldata = add_call.abi_encode();

            validator_config.call(&calldata, owner)?;

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
            let public_key = FixedBytes::<32>::repeat_byte(0x42);
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
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1);
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

    #[test]
    fn test_change_validator_status_by_index_t1_gating() -> eyre::Result<()> {
        let owner = Address::random();
        let validator = Address::random();
        let public_key = FixedBytes::<32>::repeat_byte(0x42);

        // T0: changeValidatorStatusByIndex returns UnknownFunctionSelector
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T0);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut validator_config = ValidatorConfig::new();
            validator_config.initialize(owner)?;

            // Add a validator first
            validator_config.add_validator(
                owner,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator,
                    publicKey: public_key,
                    active: true,
                    inboundAddress: "192.168.1.1:8000".to_string(),
                    outboundAddress: "192.168.1.1:9000".to_string(),
                },
            )?;

            // Try to call changeValidatorStatusByIndex in T0 - should return UnknownFunctionSelector
            let call = IValidatorConfig::changeValidatorStatusByIndexCall {
                index: 0,
                active: false,
            };
            let calldata = call.abi_encode();
            let result = validator_config.call(&calldata, owner);

            let decoded = UnknownFunctionSelector::abi_decode(revert_bytes(&result))?;
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
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator,
                    publicKey: public_key,
                    active: true,
                    inboundAddress: "192.168.1.1:8000".to_string(),
                    outboundAddress: "192.168.1.1:9000".to_string(),
                },
            )?;

            // changeValidatorStatusByIndex should work in T1
            let call = IValidatorConfig::changeValidatorStatusByIndexCall {
                index: 0,
                active: false,
            };
            let calldata = call.abi_encode();
            validator_config.call(&calldata, owner)?;

            // Verify the status was changed
            let validators = validator_config.get_validators()?;
            assert!(!validators[0].active, "Validator should be inactive");

            Ok(())
        })
    }

    #[test]
    fn test_t15_disables_all_selectors() -> eyre::Result<()> {
        let owner = Address::random();

        // T14: V1 still dispatches
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut validator_config = ValidatorConfig::new();
            validator_config.initialize(owner)?;

            let result =
                validator_config.call(&IValidatorConfig::ownerCall {}.abi_encode(), owner)?;
            assert_eq!(Address::abi_decode(result.bytes())?, owner);

            Ok(())
        })?;

        // T15: every selector reverts with UnknownFunctionSelector, even for the owner
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut validator_config = ValidatorConfig::new();
            validator_config.initialize(owner)?;

            for selector in IValidatorConfigCalls::SELECTORS {
                let result = validator_config.call(selector, owner);
                let decoded = UnknownFunctionSelector::abi_decode(revert_bytes(&result))?;
                assert_eq!(
                    decoded.selector.0,
                    *selector,
                    "{}",
                    IValidatorConfigCalls::name_by_selector(*selector).unwrap_or_default()
                );
            }

            Ok(())
        })
    }
}
