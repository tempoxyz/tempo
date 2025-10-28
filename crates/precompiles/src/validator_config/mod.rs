pub mod dispatch;

use std::{fmt::Display, str::FromStr};

pub use tempo_contracts::precompiles::{IValidatorConfig, ValidatorConfigError};

use crate::{error::TempoPrecompileError, storage::PrecompileStorageProvider};
use alloy::primitives::{Address, Bytes, FixedBytes, U256};
use revm::{interpreter::instructions::utility::IntoAddress, state::Bytecode};
use tracing::trace;

/// Storage slots for ValidatorConfig precompile
pub mod slots {
    use crate::storage::slots::mapping_slot;
    use alloy::primitives::{Address, U256, uint};

    // Simple values
    pub const OWNER: U256 = uint!(0_U256);
    pub const VALIDATOR_COUNT: U256 = uint!(1_U256);

    // Mappings
    /// Maps index -> validator address (for iteration)
    pub const VALIDATORS_ARRAY: U256 = uint!(2_U256);

    /// Maps validator address -> Validator struct (base slot)
    pub const VALIDATORS: U256 = uint!(3_U256);

    // Validator struct field offsets (relative to validator base slot)
    /// Communication key field offset (bytes32)
    pub const VALIDATOR_KEY_OFFSET: U256 = uint!(0_U256);
    /// Packed: active (bool, lowest byte) + index (u64, next 8 bytes)
    pub const VALIDATOR_ACTIVE_INDEX_OFFSET: U256 = uint!(1_U256);
    /// Inbound address field offset (string)
    pub const VALIDATOR_INBOUND_ADDRESS_OFFSET: U256 = uint!(2_U256);
    /// Outbound address field offset (string)
    pub const VALIDATOR_OUTBOUND_ADDRESS_OFFSET: U256 = uint!(3_U256);

    pub fn validator_at_index_slot(index: u64) -> U256 {
        mapping_slot(index.to_be_bytes(), VALIDATORS_ARRAY)
    }

    pub fn validator_base_slot(validator: &Address) -> U256 {
        mapping_slot(validator, VALIDATORS)
    }

    /// Pack active (bool) and index (u64) into a single U256
    /// Layout: [... zeros ...][index: 8 bytes][active: 1 byte]
    pub fn pack_active_index(active: bool, index: u64) -> U256 {
        let mut bytes = [0u8; 32];
        // Put active in lowest byte
        bytes[31] = if active { 1 } else { 0 };
        // Put index in next 8 bytes (bytes 23-30)
        bytes[23..31].copy_from_slice(&index.to_be_bytes());
        U256::from_be_bytes(bytes)
    }

    /// Unpack active (bool) and index (u64) from a U256
    pub fn unpack_active_index(value: U256) -> (bool, u64) {
        let bytes = value.to_be_bytes::<32>();
        let active = bytes[31] != 0;
        let index = u64::from_be_bytes(bytes[23..31].try_into().unwrap());
        (active, index)
    }
}

/// Validator Config precompile for managing consensus validators
pub struct ValidatorConfig<'a, S: PrecompileStorageProvider> {
    storage: &'a mut S,
    precompile_address: Address,
}

impl<'a, S: PrecompileStorageProvider> ValidatorConfig<'a, S> {
    pub fn new(precompile_address: Address, storage: &'a mut S) -> Self {
        Self {
            storage,
            precompile_address,
        }
    }

    /// Initialize the precompile with an owner
    pub fn initialize(&mut self, owner: Address) -> Result<(), TempoPrecompileError> {
        trace!(address=%self.precompile_address, %owner, "Initializing validator config precompile");

        // must ensure the account is not empty, by setting some code
        self.storage.set_code(
            self.precompile_address,
            Bytecode::new_legacy(Bytes::from_static(&[0xef])),
        )?;

        self.storage.sstore(
            self.precompile_address,
            slots::OWNER,
            owner.into_word().into(),
        )?;

        Ok(())
    }

    /// Internal helper to get owner
    pub fn owner(&mut self) -> Result<Address, TempoPrecompileError> {
        Ok(self
            .storage
            .sload(self.precompile_address, slots::OWNER)?
            .into_address())
    }

    /// Check if caller is the owner
    pub fn check_owner(&mut self, caller: &Address) -> Result<(), TempoPrecompileError> {
        if self.owner()? != *caller {
            return Err(ValidatorConfigError::unauthorized())?;
        }
        Ok(())
    }

    /// Change the owner (owner only)
    pub fn change_owner(
        &mut self,
        sender: &Address,
        call: IValidatorConfig::changeOwnerCall,
    ) -> Result<(), TempoPrecompileError> {
        self.check_owner(sender)?;
        self.storage.sstore(
            self.precompile_address,
            slots::OWNER,
            call.newOwner.into_word().into(),
        )?;
        Ok(())
    }

    /// Get the current validator count
    fn validator_count(&mut self) -> Result<u64, TempoPrecompileError> {
        Ok(self
            .storage
            .sload(self.precompile_address, slots::VALIDATOR_COUNT)?
            .to::<u64>())
    }

    /// Check if a validator exists by checking if their key is non-zero
    /// Since ed25519 keys cannot be zero, this is a reliable existence check
    fn validator_exists(&mut self, validator: &Address) -> Result<bool, TempoPrecompileError> {
        let slot = slots::validator_base_slot(validator);
        let key = self
            .storage
            .sload(self.precompile_address, slot + slots::VALIDATOR_KEY_OFFSET)?;

        Ok(!key.is_zero())
    }

    /// Get all validators (view function)
    pub fn get_validators(
        &mut self,
        _call: IValidatorConfig::getValidatorsCall,
    ) -> Result<Vec<IValidatorConfig::Validator>, TempoPrecompileError> {
        let count = self.validator_count()?;
        let mut validators = Vec::new();

        for i in 0..count {
            let validator_address = self
                .storage
                .sload(self.precompile_address, slots::validator_at_index_slot(i))?
                .into_address();

            let slot = slots::validator_base_slot(&validator_address);

            let key = FixedBytes::<32>::from(
                self.storage
                    .sload(self.precompile_address, slot + slots::VALIDATOR_KEY_OFFSET)?,
            );

            let active_and_idx = self.storage.sload(
                self.precompile_address,
                slot + slots::VALIDATOR_ACTIVE_INDEX_OFFSET,
            )?;

            let (active, index) = slots::unpack_active_index(active_and_idx);

            let inbound_address =
                self.read_string(slot + slots::VALIDATOR_INBOUND_ADDRESS_OFFSET)?;

            let outbound_address =
                self.read_string(slot + slots::VALIDATOR_OUTBOUND_ADDRESS_OFFSET)?;

            validators.push(IValidatorConfig::Validator {
                key,
                active,
                index,
                validatorAddress: validator_address,
                inboundAddress: inbound_address,
                outboundAddress: outbound_address,
            });
        }

        Ok(validators)
    }

    /// Add a new validator (owner only)
    pub fn add_validator(
        &mut self,
        sender: &Address,
        call: IValidatorConfig::addValidatorCall,
    ) -> Result<(), TempoPrecompileError> {
        // Only owner can create validators
        self.check_owner(sender)?;

        // Check if validator already exists
        if self.validator_exists(&call.newValidatorAddress)? {
            return Err(ValidatorConfigError::validator_already_exists())?;
        }

        let count = self.validator_count()?;

        // Get mapping slot to store validator at
        let slot = slots::validator_base_slot(&call.newValidatorAddress);

        // Store key
        self.storage.sstore(
            self.precompile_address,
            slot + slots::VALIDATOR_KEY_OFFSET,
            U256::from_be_bytes(call.key.0),
        )?;

        // Store active + index packed
        self.storage.sstore(
            self.precompile_address,
            slot + slots::VALIDATOR_ACTIVE_INDEX_OFFSET,
            slots::pack_active_index(call.active, count),
        )?;

        // Store inboundAddress
        let inbound = call.inboundAddress.parse::<HostWithPort>().map_err(|err| {
            ValidatorConfigError::not_host_port("inboundAddress".to_string(), format!("{err:?}"))
        })?;
        self.write_string(
            slot + slots::VALIDATOR_INBOUND_ADDRESS_OFFSET,
            inbound.to_string(),
        )?;

        // Store outboundAddress
        let outbound = call
            .outboundAddress
            .parse::<HostWithPort>()
            .map_err(|err| {
                ValidatorConfigError::not_host_port(
                    "outboundAddress".to_string(),
                    format!("{err:?}"),
                )
            })?;
        self.write_string(
            slot + slots::VALIDATOR_OUTBOUND_ADDRESS_OFFSET,
            outbound.to_string(),
        )?;

        // Set validator in validators array
        let validator_array_slot = slots::validator_at_index_slot(count);
        self.storage.sstore(
            self.precompile_address,
            validator_array_slot,
            call.newValidatorAddress.into_word().into(),
        )?;

        // Increment count
        self.storage.sstore(
            self.precompile_address,
            slots::VALIDATOR_COUNT,
            U256::from(count + 1),
        )?;

        Ok(())
    }

    /// Update validator information (and optionally rotate to new address)
    pub fn update_validator(
        &mut self,
        sender: &Address,
        call: IValidatorConfig::updateValidatorCall,
    ) -> Result<(), TempoPrecompileError> {
        // Validator can update their own info
        if !self.validator_exists(sender)? {
            return Err(ValidatorConfigError::validator_not_found())?;
        }

        let new_slot = slots::validator_base_slot(&call.newValidatorAddress);
        let mut active: bool = false;
        let mut index: u64 = 0;

        // Check if rotating to a new address
        // If so, we only need to delete storage at the old slot, since we would update the values at the new slot after
        if call.newValidatorAddress != *sender {
            if self.validator_exists(&call.newValidatorAddress)? {
                return Err(ValidatorConfigError::validator_already_exists())?;
            }

            // Get old validator's slot
            let old_slot = slots::validator_base_slot(sender);

            // Clear old validator's key
            self.storage.sstore(
                self.precompile_address,
                old_slot + slots::VALIDATOR_KEY_OFFSET,
                U256::ZERO,
            )?;

            // Unpack active and index
            (active, index) = slots::unpack_active_index(self.storage.sload(
                self.precompile_address,
                old_slot + slots::VALIDATOR_ACTIVE_INDEX_OFFSET,
            )?);

            // Clear old validator's active/index
            self.storage.sstore(
                self.precompile_address,
                old_slot + slots::VALIDATOR_ACTIVE_INDEX_OFFSET,
                U256::ZERO,
            )?;

            // Clear old validator's inboundAddress
            self.storage.sstore(
                self.precompile_address,
                old_slot + slots::VALIDATOR_INBOUND_ADDRESS_OFFSET,
                U256::ZERO,
            )?;

            // Clear old validator's outboundAddress
            self.storage.sstore(
                self.precompile_address,
                old_slot + slots::VALIDATOR_OUTBOUND_ADDRESS_OFFSET,
                U256::ZERO,
            )?;

            // Update the validators array to point to new address
            let array_slot = slots::validator_at_index_slot(index);
            self.storage.sstore(
                self.precompile_address,
                array_slot,
                call.newValidatorAddress.into_word().into(),
            )?;
        }

        let key = self.storage.sload(
            self.precompile_address,
            new_slot + slots::VALIDATOR_KEY_OFFSET,
        )?;

        if key != U256::from_be_bytes(call.key.0) {
            self.storage.sstore(
                self.precompile_address,
                new_slot + slots::VALIDATOR_KEY_OFFSET,
                U256::from_be_bytes(call.key.0),
            )?;
        }

        if active || index != 0 {
            self.storage.sstore(
                self.precompile_address,
                new_slot + slots::VALIDATOR_ACTIVE_INDEX_OFFSET,
                slots::pack_active_index(active, index),
            )?;
        }

        if self.read_string(new_slot + slots::VALIDATOR_INBOUND_ADDRESS_OFFSET)?
            != call.inboundAddress
        {
            self.write_string(
                new_slot + slots::VALIDATOR_INBOUND_ADDRESS_OFFSET,
                call.inboundAddress,
            )?;
        }

        if self.read_string(new_slot + slots::VALIDATOR_OUTBOUND_ADDRESS_OFFSET)?
            != call.outboundAddress
        {
            self.write_string(
                new_slot + slots::VALIDATOR_OUTBOUND_ADDRESS_OFFSET,
                call.outboundAddress,
            )?;
        }
        Ok(())
    }

    /// Change validator active status (owner only)
    pub fn change_validator_status(
        &mut self,
        sender: &Address,
        call: IValidatorConfig::changeValidatorStatusCall,
    ) -> Result<(), TempoPrecompileError> {
        self.check_owner(sender)?;

        if !self.validator_exists(&call.validator)? {
            return Err(ValidatorConfigError::validator_not_found())?;
        }

        // Read current packed value to get the index
        let slot = slots::validator_base_slot(&call.validator);
        let current_value = self.storage.sload(
            self.precompile_address,
            slot + slots::VALIDATOR_ACTIVE_INDEX_OFFSET,
        )?;
        let (_, index) = slots::unpack_active_index(current_value);

        // Write new packed value with updated active status
        let new_packed_value = slots::pack_active_index(call.active, index);
        self.storage.sstore(
            self.precompile_address,
            slot + slots::VALIDATOR_ACTIVE_INDEX_OFFSET,
            new_packed_value,
        )?;

        Ok(())
    }

    // Helper methods for string storage
    fn read_string(&mut self, slot: U256) -> Result<String, TempoPrecompileError> {
        let value = self.storage.sload(self.precompile_address, slot)?;
        let bytes = value.to_be_bytes::<32>();
        let len = bytes[31] as usize / 2;
        if len > 31 {
            return Err(ValidatorConfigError::unauthorized())?;
        }
        Ok(String::from_utf8_lossy(&bytes[..len]).to_string())
    }

    fn write_string(&mut self, slot: U256, value: String) -> Result<(), TempoPrecompileError> {
        let bytes = value.as_bytes();
        if bytes.len() > 31 {
            return Err(ValidatorConfigError::unauthorized())?;
        }
        let mut storage_bytes = [0u8; 32];
        storage_bytes[..bytes.len()].copy_from_slice(bytes);
        storage_bytes[31] = (bytes.len() * 2) as u8;

        self.storage.sstore(
            self.precompile_address,
            slot,
            U256::from_be_bytes(storage_bytes),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::hashmap::HashMapStorageProvider;
    use alloy::primitives::Address;

    const PRECOMPILE_ADDRESS: Address = Address::new([0x01; 20]);

    #[test]
    fn test_owner_initialization_and_change() {
        let mut storage = HashMapStorageProvider::new(1);
        let owner1 = Address::from([0x11; 20]);
        let owner2 = Address::from([0x22; 20]);

        let mut validator_config = ValidatorConfig::new(PRECOMPILE_ADDRESS, &mut storage);

        // Initialize with owner1
        validator_config.initialize(owner1).unwrap();

        // Check that owner is owner1
        let current_owner = validator_config.owner().unwrap();
        assert_eq!(
            current_owner, owner1,
            "Owner should be owner1 after initialization"
        );

        // Change owner to owner2
        validator_config
            .change_owner(
                &owner1,
                IValidatorConfig::changeOwnerCall { newOwner: owner2 },
            )
            .expect("Should change owner");

        // Check that owner is now owner2
        let current_owner = validator_config.owner().unwrap();
        assert_eq!(current_owner, owner2, "Owner should be owner2 after change");
    }

    #[test]
    fn test_owner_only_functions() {
        let mut storage = HashMapStorageProvider::new(1);
        let owner1 = Address::from([0x11; 20]);
        let owner2 = Address::from([0x22; 20]);
        let validator1 = Address::from([0x33; 20]);

        let mut validator_config = ValidatorConfig::new(PRECOMPILE_ADDRESS, &mut storage);

        // Initialize with owner1
        validator_config.initialize(owner1).unwrap();

        // Owner1 adds a validator - should succeed
        let key = FixedBytes::<32>::from([0x44; 32]);
        let result = validator_config.add_validator(
            &owner1,
            IValidatorConfig::addValidatorCall {
                newValidatorAddress: validator1,
                key,
                inboundAddress: "192.168.1.1".to_string(),
                active: true,
                outboundAddress: "192.168.1.1".to_string(),
            },
        );
        assert!(result.is_ok(), "Owner should be able to add validator");

        // Verify validator was added
        let validators = validator_config
            .get_validators(IValidatorConfig::getValidatorsCall {})
            .expect("Should get validators");
        assert_eq!(validators.len(), 1, "Should have 1 validator");
        assert_eq!(validators[0].validatorAddress, validator1);
        assert_eq!(validators[0].key, key);
        assert!(validators[0].active, "New validator should be active");

        // Owner1 changes validator status - should succeed
        let result = validator_config.change_validator_status(
            &owner1,
            IValidatorConfig::changeValidatorStatusCall {
                validator: validator1,
                active: false,
            },
        );
        assert!(
            result.is_ok(),
            "Owner should be able to change validator status"
        );

        // Verify status was changed
        let validators = validator_config
            .get_validators(IValidatorConfig::getValidatorsCall {})
            .expect("Should get validators");
        assert!(!validators[0].active, "Validator should be inactive");

        // Owner2 (non-owner) tries to add validator - should fail
        let validator2 = Address::from([0x55; 20]);
        let result = validator_config.add_validator(
            &owner2,
            IValidatorConfig::addValidatorCall {
                newValidatorAddress: validator2,
                key: FixedBytes::<32>::from([0x66; 32]),
                inboundAddress: "192.168.1.2".to_string(),
                active: true,
                outboundAddress: "192.168.1.2".to_string(),
            },
        );
        assert!(
            result.is_err(),
            "Non-owner should not be able to add validator"
        );
        assert_eq!(
            result.unwrap_err(),
            ValidatorConfigError::unauthorized().into(),
            "Should return Unauthorized error"
        );

        // Owner2 (non-owner) tries to change validator status - should fail
        let result = validator_config.change_validator_status(
            &owner2,
            IValidatorConfig::changeValidatorStatusCall {
                validator: validator1,
                active: true,
            },
        );
        assert!(
            result.is_err(),
            "Non-owner should not be able to change validator status"
        );
        assert_eq!(
            result.unwrap_err(),
            ValidatorConfigError::unauthorized().into(),
            "Should return Unauthorized error"
        );
    }

    #[test]
    fn test_validator_lifecycle() {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::from([0x01; 20]);

        let mut validator_config = ValidatorConfig::new(PRECOMPILE_ADDRESS, &mut storage);
        validator_config.initialize(owner).unwrap();

        // Add first validator
        let validator1 = Address::from([0x11; 20]);
        let key1 = FixedBytes::<32>::from([0x21; 32]);
        validator_config
            .add_validator(
                &owner,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator1,
                    key: key1,
                    inboundAddress: "192.168.1.1".to_string(),
                    active: true,
                    outboundAddress: "192.168.1.1".to_string(),
                },
            )
            .expect("Should add validator1");

        // Try adding duplicate validator - should fail
        let result = validator_config.add_validator(
            &owner,
            IValidatorConfig::addValidatorCall {
                newValidatorAddress: validator1,
                key: FixedBytes::<32>::from([0x22; 32]),
                inboundAddress: "192.168.1.2".to_string(),
                active: true,
                outboundAddress: "192.168.1.2".to_string(),
            },
        );
        assert!(result.is_err(), "Should not allow duplicate validator");
        assert_eq!(
            result.unwrap_err(),
            ValidatorConfigError::validator_already_exists().into(),
            "Should return ValidatorAlreadyExists error"
        );

        // Add 4 more unique validators
        let validator2 = Address::from([0x12; 20]);
        let key2 = FixedBytes::<32>::from([0x22; 32]);
        validator_config
            .add_validator(
                &owner,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator2,
                    key: key2,
                    inboundAddress: "192.168.1.2".to_string(),
                    active: true,
                    outboundAddress: "192.168.1.2".to_string(),
                },
            )
            .expect("Should add validator2");

        let validator3 = Address::from([0x13; 20]);
        let key3 = FixedBytes::<32>::from([0x23; 32]);
        validator_config
            .add_validator(
                &owner,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator3,
                    key: key3,
                    inboundAddress: "192.168.1.3".to_string(),
                    active: false,
                    outboundAddress: "192.168.1.3".to_string(),
                },
            )
            .expect("Should add validator3");

        let validator4 = Address::from([0x14; 20]);
        let key4 = FixedBytes::<32>::from([0x24; 32]);
        validator_config
            .add_validator(
                &owner,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator4,
                    key: key4,
                    inboundAddress: "192.168.1.4".to_string(),
                    active: true,
                    outboundAddress: "192.168.1.4".to_string(),
                },
            )
            .expect("Should add validator4");

        let validator5 = Address::from([0x15; 20]);
        let key5 = FixedBytes::<32>::from([0x25; 32]);
        validator_config
            .add_validator(
                &owner,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator5,
                    key: key5,
                    inboundAddress: "192.168.1.5".to_string(),
                    active: true,
                    outboundAddress: "192.168.1.5".to_string(),
                },
            )
            .expect("Should add validator5");

        // Get all validators
        let mut validators = validator_config
            .get_validators(IValidatorConfig::getValidatorsCall {})
            .expect("Should get validators");

        // Verify count
        assert_eq!(validators.len(), 5, "Should have 5 validators");

        // Sort by validator address for consistent checking
        validators.sort_by_key(|v| v.validatorAddress);

        // Verify each validator
        assert_eq!(validators[0].validatorAddress, validator1);
        assert_eq!(validators[0].key, key1);
        assert_eq!(validators[0].inboundAddress, "192.168.1.1");
        assert!(validators[0].active);

        assert_eq!(validators[1].validatorAddress, validator2);
        assert_eq!(validators[1].key, key2);
        assert_eq!(validators[1].inboundAddress, "192.168.1.2");
        assert!(validators[1].active);

        assert_eq!(validators[2].validatorAddress, validator3);
        assert_eq!(validators[2].key, key3);
        assert_eq!(validators[2].inboundAddress, "192.168.1.3");
        assert!(!validators[2].active);

        assert_eq!(validators[3].validatorAddress, validator4);
        assert_eq!(validators[3].key, key4);
        assert_eq!(validators[3].inboundAddress, "192.168.1.4");
        assert!(validators[3].active);

        assert_eq!(validators[4].validatorAddress, validator5);
        assert_eq!(validators[4].key, key5);
        assert_eq!(validators[4].inboundAddress, "192.168.1.5");
        assert!(validators[4].active);

        // Validator1 updates IP and key (keeps same address)
        let key1_new = FixedBytes::<32>::from([0x31; 32]);
        validator_config
            .update_validator(
                &validator1,
                IValidatorConfig::updateValidatorCall {
                    newValidatorAddress: validator1,
                    key: key1_new,
                    inboundAddress: "10.0.0.1".to_string(),
                    outboundAddress: "10.0.0.1".to_string(),
                },
            )
            .expect("Should update validator1");

        // Validator2 rotates to new address, keeps IP and key
        let validator2_new = Address::from([0x22; 20]);
        validator_config
            .update_validator(
                &validator2,
                IValidatorConfig::updateValidatorCall {
                    newValidatorAddress: validator2_new,
                    key: key2,
                    inboundAddress: "192.168.1.2".to_string(),
                    outboundAddress: "192.168.1.2".to_string(),
                },
            )
            .expect("Should rotate validator2 address");

        // Validator3 rotates to new address and updates IP, keeps key
        let validator3_new = Address::from([0x23; 20]);
        validator_config
            .update_validator(
                &validator3,
                IValidatorConfig::updateValidatorCall {
                    newValidatorAddress: validator3_new,
                    key: key3,
                    inboundAddress: "10.0.0.3".to_string(),
                    outboundAddress: "10.0.0.3".to_string(),
                },
            )
            .expect("Should rotate validator3 address and update IP");

        // Get all validators again
        let mut validators = validator_config
            .get_validators(IValidatorConfig::getValidatorsCall {})
            .expect("Should get validators");

        // Should still have 5 validators
        assert_eq!(validators.len(), 5, "Should still have 5 validators");

        // Sort by validator address
        validators.sort_by_key(|v| v.validatorAddress);

        // Verify validator1 - updated IP and key
        assert_eq!(validators[0].validatorAddress, validator1);
        assert_eq!(validators[0].key, key1_new, "Key should be updated");
        assert_eq!(
            validators[0].inboundAddress, "10.0.0.1",
            "IP should be updated"
        );
        assert!(validators[0].active);

        // Verify validator4 - unchanged
        assert_eq!(validators[1].validatorAddress, validator4);
        assert_eq!(validators[1].key, key4);
        assert_eq!(validators[1].inboundAddress, "192.168.1.4");
        assert!(validators[1].active);

        // Verify validator5 - unchanged
        assert_eq!(validators[2].validatorAddress, validator5);
        assert_eq!(validators[2].key, key5);
        assert_eq!(validators[2].inboundAddress, "192.168.1.5");
        assert!(validators[2].active);

        // Verify validator2_new - rotated address, kept IP and key
        assert_eq!(validators[3].validatorAddress, validator2_new);
        assert_eq!(validators[3].key, key2, "Key should be same");
        assert_eq!(
            validators[3].inboundAddress, "192.168.1.2",
            "IP should be same"
        );
        assert!(validators[3].active);

        // Verify validator3_new - rotated address and updated IP, kept key
        assert_eq!(validators[4].validatorAddress, validator3_new);
        assert_eq!(validators[4].key, key3, "Key should be same");
        assert_eq!(
            validators[4].inboundAddress, "10.0.0.3",
            "IP should be updated"
        );
        assert!(!validators[4].active);
    }

    #[test]
    fn test_owner_cannot_update_validator() {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::from([0x01; 20]);
        let validator = Address::from([0x11; 20]);

        let mut validator_config = ValidatorConfig::new(PRECOMPILE_ADDRESS, &mut storage);
        validator_config.initialize(owner).unwrap();

        // Owner adds a validator
        let key = FixedBytes::<32>::from([0x21; 32]);
        validator_config
            .add_validator(
                &owner,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator,
                    key,
                    inboundAddress: "192.168.1.1".to_string(),
                    active: true,
                    outboundAddress: "192.168.1.1".to_string(),
                },
            )
            .expect("Should add validator");

        // Owner tries to update validator - should fail
        let result = validator_config.update_validator(
            &owner,
            IValidatorConfig::updateValidatorCall {
                newValidatorAddress: validator,
                key: FixedBytes::<32>::from([0x22; 32]),
                inboundAddress: "10.0.0.1".to_string(),
                outboundAddress: "10.0.0.1".to_string(),
            },
        );

        assert!(
            result.is_err(),
            "Owner should not be able to update validator"
        );
        assert_eq!(
            result.unwrap_err(),
            ValidatorConfigError::validator_not_found().into(),
            "Should return ValidatorNotFound error"
        );
    }
}

#[derive(Debug, thiserror::Error)]
enum HostWithPortParseError {
    #[error("failed to parse input as URL")]
    Url(#[from] url::ParseError),
    #[error("input did not contain host")]
    NoHost,
    #[error("input did not contain port")]
    NoPort,
    #[error("input did not match <host>:<port>; only inputs of that form are accepted")]
    NotHostPort,
}

/// A string guaranteed to be `<host>:<port>`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HostWithPort {
    host: String,
    port: u16,
}

impl Display for HostWithPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.host)?;
        f.write_str(":")?;
        self.port.fmt(f)
    }
}

// FIXME(janis): This might be overkill. Maybe a simple regex here is better.
impl FromStr for HostWithPort {
    type Err = HostWithPortParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = s.trim().parse::<url::Url>()?;

        let host = url.host_str().ok_or(Self::Err::NoHost)?;
        let port = url.port().ok_or(Self::Err::NoPort)?;

        let this = Self {
            host: host.to_string(),
            port,
        };
        if this.to_string() != url.to_string() {
            return Err(Self::Err::NotHostPort);
        }
        Ok(this)
    }
}
