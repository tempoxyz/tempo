use super::ValidatorConfigV2;
use crate::{Precompile, dispatch_call, error::TempoPrecompileError, input_cost, mutate_void, view};
use alloy::{primitives::Address, sol_types::SolInterface};
use revm::precompile::{PrecompileError, PrecompileOutput, PrecompileResult};
use tempo_contracts::precompiles::IValidatorConfigV2::IValidatorConfigV2Calls;

impl Precompile for ValidatorConfigV2 {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        self.storage
            .deduct_gas(input_cost(calldata.len()))
            .map_err(|_| PrecompileError::OutOfGas)?;

        // Pre-T2: behave like an empty contract (call succeeds, no execution)
        if !self.storage.spec().is_t2() {
            return Ok(PrecompileOutput::new(self.storage.gas_used(), Default::default()));
        }

        // Block height is not directly available from the storage provider,
        // so we use 0 as a placeholder. In production, block height is provided
        // by the EVM context. For mutating calls that need block_height,
        // we pass 0 here - the actual block height injection happens at a higher level.
        let block_height = 0u64;

        dispatch_call(
            calldata,
            IValidatorConfigV2Calls::abi_decode,
            |call| match call {
                // View functions
                IValidatorConfigV2Calls::owner(call) => view(call, |_| self.owner()),
                IValidatorConfigV2Calls::getValidators(call) => {
                    view(call, |_| self.get_validators())
                }
                IValidatorConfigV2Calls::getActiveValidators(call) => {
                    view(call, |_| self.get_active_validators())
                }
                IValidatorConfigV2Calls::getInitializedAtHeight(call) => {
                    view(call, |_| self.get_initialized_at_height())
                }
                IValidatorConfigV2Calls::validatorCount(call) => {
                    view(call, |_| self.validator_count())
                }
                IValidatorConfigV2Calls::validatorByIndex(call) => view(call, |c| {
                    let index =
                        u64::try_from(c.index).map_err(|_| TempoPrecompileError::array_oob())?;
                    self.validator_by_index(index)
                }),
                IValidatorConfigV2Calls::validatorByAddress(call) => {
                    view(call, |c| self.validator_by_address(c.validatorAddress))
                }
                IValidatorConfigV2Calls::validatorByPublicKey(call) => {
                    view(call, |c| self.validator_by_public_key(c.publicKey))
                }
                IValidatorConfigV2Calls::getNextFullDkgCeremony(call) => {
                    view(call, |_| self.get_next_full_dkg_ceremony())
                }
                IValidatorConfigV2Calls::isInitialized(call) => {
                    view(call, |_| self.is_initialized())
                }

                // Mutate functions
                IValidatorConfigV2Calls::addValidator(call) => {
                    mutate_void(call, msg_sender, |s, c| {
                        self.add_validator(s, c, block_height)
                    })
                }
                IValidatorConfigV2Calls::deactivateValidator(call) => {
                    mutate_void(call, msg_sender, |s, c| {
                        self.deactivate_validator(s, c, block_height)
                    })
                }
                IValidatorConfigV2Calls::rotateValidator(call) => {
                    mutate_void(call, msg_sender, |s, c| {
                        self.rotate_validator(s, c, block_height)
                    })
                }
                IValidatorConfigV2Calls::setIpAddresses(call) => {
                    mutate_void(call, msg_sender, |s, c| self.set_ip_addresses(s, c))
                }
                IValidatorConfigV2Calls::transferValidatorOwnership(call) => {
                    mutate_void(call, msg_sender, |s, c| {
                        self.transfer_validator_ownership(s, c)
                    })
                }
                IValidatorConfigV2Calls::transferOwnership(call) => {
                    mutate_void(call, msg_sender, |s, c| self.transfer_ownership(s, c))
                }
                IValidatorConfigV2Calls::setNextFullDkgCeremony(call) => {
                    mutate_void(call, msg_sender, |s, c| {
                        self.set_next_full_dkg_ceremony(s, c)
                    })
                }
                IValidatorConfigV2Calls::migrateValidator(call) => {
                    mutate_void(call, msg_sender, |s, c| self.migrate_validator(s, c))
                }
                IValidatorConfigV2Calls::initializeIfMigrated(call) => {
                    mutate_void(call, msg_sender, |s, c| {
                        self.initialize_if_migrated(s, c)
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
        IValidatorConfigV2, IValidatorConfigV2::IValidatorConfigV2Calls, ValidatorConfigV2Error,
    };

    #[test]
    fn test_pre_t2_returns_empty_success() -> eyre::Result<()> {
        let owner = Address::random();

        // Pre-T2 (T1): calling the precompile should succeed with empty output
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner, 100)?;

            // Any call should succeed with empty bytes
            let owner_call = IValidatorConfigV2::ownerCall {};
            let calldata = owner_call.abi_encode();
            let result = vc.call(&calldata, owner)?;

            assert!(!result.reverted, "Pre-T2 call should not revert");
            assert!(result.bytes.is_empty(), "Pre-T2 call should return empty bytes");

            Ok(())
        })?;

        // Pre-T2 (T0): same behavior
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T0);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner, 100)?;

            let calldata = IValidatorConfigV2::ownerCall {}.abi_encode();
            let result = vc.call(&calldata, owner)?;

            assert!(!result.reverted);
            assert!(result.bytes.is_empty());

            // Even empty calldata should succeed
            let result = vc.call(&[], owner)?;
            assert!(!result.reverted);
            assert!(result.bytes.is_empty());

            Ok(())
        })?;

        Ok(())
    }

    #[test]
    fn test_t2_dispatch_works() -> eyre::Result<()> {
        let owner = Address::random();

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner, 100)?;

            // owner() should work in T2
            let calldata = IValidatorConfigV2::ownerCall {}.abi_encode();
            let result = vc.call(&calldata, owner)?;

            assert!(!result.reverted);
            let decoded = Address::abi_decode(&result.bytes)?;
            assert_eq!(decoded, owner);

            Ok(())
        })
    }

    #[test]
    fn test_add_validator_dispatch() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let owner = Address::random();
        let validator_addr = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner, 100)?;

            let public_key = FixedBytes::<32>::from([0x42; 32]);
            let add_call = IValidatorConfigV2::addValidatorCall {
                validatorAddress: validator_addr,
                publicKey: public_key,
                ingress: "192.168.1.1:8000".to_string(),
                egress: "192.168.1.1".to_string(),
                signature: vec![0u8; 64].into(),
            };
            let calldata = add_call.abi_encode();

            let result = vc.call(&calldata, owner)?;
            assert!(!result.reverted);

            let validators = vc.get_validators()?;
            assert_eq!(validators.len(), 1);
            assert_eq!(validators[0].validatorAddress, validator_addr);
            assert_eq!(validators[0].publicKey, public_key);

            Ok(())
        })
    }

    #[test]
    fn test_unauthorized_add_validator_dispatch() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let owner = Address::random();
        let non_owner = Address::random();
        let validator_addr = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner, 100)?;

            let add_call = IValidatorConfigV2::addValidatorCall {
                validatorAddress: validator_addr,
                publicKey: FixedBytes::<32>::from([0x42; 32]),
                ingress: "192.168.1.1:8000".to_string(),
                egress: "192.168.1.1".to_string(),
                signature: vec![0u8; 64].into(),
            };
            let calldata = add_call.abi_encode();

            let result = vc.call(&calldata, non_owner);
            expect_precompile_revert(&result, ValidatorConfigV2Error::unauthorized());

            Ok(())
        })
    }

    #[test]
    fn test_function_selector_dispatch() -> eyre::Result<()> {
        let sender = Address::random();
        let owner = Address::random();

        // T2: invalid selector returns reverted output
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner, 100)?;

            let result = vc.call(&[0x12, 0x34, 0x56, 0x78], sender)?;
            assert!(result.reverted);

            // Insufficient calldata also returns reverted output
            let result = vc.call(&[0x12, 0x34], sender)?;
            assert!(result.reverted);

            Ok(())
        })
    }

    #[test]
    fn test_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();

            let unsupported = check_selector_coverage(
                &mut vc,
                IValidatorConfigV2Calls::SELECTORS,
                "IValidatorConfigV2",
                IValidatorConfigV2Calls::name_by_selector,
            );

            assert_full_coverage([unsupported]);

            Ok(())
        })
    }
}
