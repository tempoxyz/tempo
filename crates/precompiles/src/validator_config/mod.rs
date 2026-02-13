pub mod abi;
pub mod dispatch;

pub use abi::{IValidatorConfig, IValidatorConfig::prelude::*};

#[cfg(feature = "precompile")]
pub use abi::IValidatorConfig::Interface;

use crate::{
    VALIDATOR_CONFIG_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping},
};
use alloy::primitives::{Address, B256, U256};
use tempo_precompiles_macros::contract;
use tracing::trace;

/// Validator Config precompile for managing consensus validators
#[contract(addr = VALIDATOR_CONFIG_ADDRESS, abi = IValidatorConfig, dispatch)]
pub struct ValidatorConfig {
    owner: Address,
    validators_array: Vec<Address>,
    validators: Mapping<Address, Validator>,
    /// The epoch at which a fresh DKG ceremony will be triggered
    next_dkg_ceremony: u64,
}

impl ValidatorConfig {
    /// Initialize the precompile with an owner
    pub fn initialize(&mut self, owner: Address) -> Result<()> {
        trace!(address=%self.address, %owner, "Initializing validator config precompile");

        // must ensure the account is not empty, by setting some code
        self.__initialize()?;
        self.owner.write(owner)
    }

    /// Check if caller is the owner
    pub fn check_owner(&self, caller: Address) -> Result<()> {
        if self.owner()? != caller {
            return Err(ValidatorConfigError::unauthorized())?;
        }

        Ok(())
    }

    /// Check if a validator exists by checking if their publicKey is non-zero
    /// Since ed25519 keys cannot be zero, this is a reliable existence check
    fn validator_exists(&self, validator: Address) -> Result<bool> {
        let validator = self.validators[validator].read()?;
        Ok(!validator.public_key.is_zero())
    }
}

impl IValidatorConfig::Interface for ValidatorConfig {
    /// Change owner (owner only)
    fn change_owner(&mut self, msg_sender: Address, new_owner: Address) -> Result<()> {
        self.check_owner(msg_sender)?;
        self.owner.write(new_owner)
    }

    fn get_validators(&self) -> Result<Vec<Validator>> {
        let count = self.validators_array.len()?;
        let mut validators = Vec::with_capacity(count);

        for i in 0..count {
            // Read validator address from the array at index i
            let validator_address = self.validators_array[i].read()?;
            let mut val = self.validators[validator_address].read()?;
            val.validator_address = validator_address;
            validators.push(val);
        }

        Ok(validators)
    }

    fn validators_array(&self, index: U256) -> Result<Address> {
        let index = u64::try_from(index).map_err(|_| TempoPrecompileError::array_oob())?;
        match self.validators_array.at(index as usize)? {
            Some(elem) => elem.read(),
            None => Err(TempoPrecompileError::array_oob()),
        }
    }

    fn validator_count(&self) -> Result<u64> {
        self.validators_array.len().map(|c| c as u64)
    }

    /// Add a new validator (owner only)
    fn add_validator(
        &mut self,
        msg_sender: Address,
        new_validator_address: Address,
        public_key: B256,
        active: bool,
        inbound_address: String,
        outbound_address: String,
    ) -> Result<()> {
        // Reject zero public key - zero is used as sentinel value for non-existence
        if public_key.is_zero() {
            return Err(ValidatorConfigError::invalid_public_key())?;
        }

        // Only owner can create validators
        self.check_owner(msg_sender)?;

        // Check if validator already exists
        if self.validator_exists(new_validator_address)? {
            return Err(ValidatorConfigError::validator_already_exists())?;
        }

        // Validate addresses
        ensure_address_is_ip_port(&inbound_address).map_err(|err| {
            ValidatorConfigError::not_host_port(
                "inboundAddress".to_string(),
                inbound_address.clone(),
                format!("{err:?}"),
            )
        })?;

        ensure_address_is_ip_port(&outbound_address).map_err(|err| {
            ValidatorConfigError::not_ip_port(
                "outboundAddress".to_string(),
                outbound_address.clone(),
                format!("{err:?}"),
            )
        })?;

        // Store the new validator in the validators mapping
        let count = self.validator_count()?;
        let validator = Validator {
            public_key,
            active,
            index: count,
            validator_address: new_validator_address,
            inbound_address,
            outbound_address,
        };
        self.validators[new_validator_address].write(validator)?;

        // Add the validator public key to the validators array
        self.validators_array.push(new_validator_address)
    }

    /// Update validator information (and optionally rotate to new address)
    ///
    /// # Security Note
    ///
    /// The field `validator_address` must never be set to a user-controllable address.
    ///
    /// This function allows validators to update their own public key mid-epoch, which could
    /// cause a chain halt at the next epoch boundary if exploited (the DKG manager panics when
    /// the original key stored in the boundary header cannot be mapped to the modified registry).
    /// By setting validator addresses to non-user-controllable addresses in the genesis config,
    /// only the contract owner (admin) can effectively call this function.
    fn update_validator(
        &mut self,
        msg_sender: Address,
        new_validator_address: Address,
        public_key: B256,
        inbound_address: String,
        outbound_address: String,
    ) -> Result<()> {
        // Reject zero public key - zero is used as sentinel value for non-existence
        if public_key.is_zero() {
            return Err(ValidatorConfigError::invalid_public_key())?;
        }

        // Validator can update their own info
        if !self.validator_exists(msg_sender)? {
            return Err(ValidatorConfigError::validator_not_found())?;
        }

        // Load the current validator info
        let old_validator = self.validators[msg_sender].read()?;

        // Check if rotating to a new address
        if new_validator_address != msg_sender {
            if self.validator_exists(new_validator_address)? {
                return Err(ValidatorConfigError::validator_already_exists())?;
            }

            // Update the validators array to point at the new validator address
            self.validators_array[old_validator.index as usize].write(new_validator_address)?;

            // Clear the old validator
            self.validators[msg_sender].delete()?;
        }

        ensure_address_is_ip_port(&inbound_address).map_err(|err| {
            ValidatorConfigError::not_host_port(
                "inboundAddress".to_string(),
                inbound_address.clone(),
                format!("{err:?}"),
            )
        })?;

        ensure_address_is_ip_port(&outbound_address).map_err(|err| {
            ValidatorConfigError::not_ip_port(
                "outboundAddress".to_string(),
                outbound_address.clone(),
                format!("{err:?}"),
            )
        })?;

        let updated_validator = Validator {
            public_key,
            active: old_validator.active,
            index: old_validator.index,
            validator_address: new_validator_address,
            inbound_address,
            outbound_address,
        };

        self.validators[new_validator_address].write(updated_validator)
    }

    /// Change validator active status (owner only) - by address
    /// Deprecated: Use change_validator_status_by_index to prevent front-running attacks
    fn change_validator_status(
        &mut self,
        msg_sender: Address,
        validator: Address,
        active: bool,
    ) -> Result<()> {
        self.check_owner(msg_sender)?;

        if !self.validator_exists(validator)? {
            return Err(ValidatorConfigError::validator_not_found())?;
        }

        let mut val = self.validators[validator].read()?;
        val.active = active;
        self.validators[validator].write(val)
    }

    /// Change validator active status by index (owner only) - T1+
    /// Added in T1 to prevent front-running attacks where a validator changes its address
    fn change_validator_status_by_index(
        &mut self,
        msg_sender: Address,
        index: u64,
        active: bool,
    ) -> Result<()> {
        self.check_owner(msg_sender)?;

        // Look up validator address by index
        let validator_address = match self.validators_array.at(index as usize)? {
            Some(elem) => elem.read()?,
            None => return Err(ValidatorConfigError::validator_not_found())?,
        };

        let mut validator = self.validators[validator_address].read()?;
        validator.active = active;
        self.validators[validator_address].write(validator)
    }

    /// Set the epoch at which a fresh DKG ceremony will be triggered (owner only).
    ///
    /// Epoch N runs the ceremony, and epoch N+1 uses the new DKG polynomial.
    fn set_next_full_dkg_ceremony(&mut self, msg_sender: Address, epoch: u64) -> Result<()> {
        self.check_owner(msg_sender)?;
        self.next_dkg_ceremony.write(epoch)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("input was not of the form `<ip>:<port>`")]
pub struct IpWithPortParseError {
    #[from]
    source: std::net::AddrParseError,
}

pub fn ensure_address_is_ip_port(input: &str) -> core::result::Result<(), IpWithPortParseError> {
    // Only accept IP addresses (v4 or v6) with port
    input.parse::<std::net::SocketAddr>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};
    use alloy::primitives::Address;
    use alloy_primitives::FixedBytes;

    #[test]
    fn test_owner_initialization_and_change() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner1 = Address::random();
        let owner2 = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut validator_config = ValidatorConfig::new();

            // Initialize with owner1
            validator_config.initialize(owner1)?;

            // Check that owner is owner1
            let current_owner = validator_config.owner()?;
            assert_eq!(
                current_owner, owner1,
                "Owner should be owner1 after initialization"
            );

            // Change owner to owner2
            validator_config.change_owner(owner1, owner2)?;

            // Check that owner is now owner2
            let current_owner = validator_config.owner()?;
            assert_eq!(current_owner, owner2, "Owner should be owner2 after change");

            Ok(())
        })
    }

    #[test]
    fn test_owner_only_functions() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner1 = Address::random();
        let owner2 = Address::random();
        let validator1 = Address::random();
        let validator2 = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut validator_config = ValidatorConfig::new();

            // Initialize with owner1
            validator_config.initialize(owner1)?;

            // Owner1 adds a validator - should succeed
            let public_key = FixedBytes::<32>::from([0x44; 32]);
            validator_config.add_validator(
                owner1,
                validator1,
                public_key,
                true,
                "192.168.1.1:8000".to_string(),
                "192.168.1.1:9000".to_string(),
            )?;

            // Verify validator was added
            let validators = validator_config.get_validators()?;
            assert_eq!(validators.len(), 1, "Should have 1 validator");
            assert_eq!(validators[0].validator_address, validator1);
            assert_eq!(validators[0].public_key, public_key);
            assert!(validators[0].active, "New validator should be active");

            // Owner1 changes validator status - should succeed
            validator_config.change_validator_status(owner1, validator1, false)?;

            // Verify status was changed
            let validators = validator_config.get_validators()?;
            assert!(!validators[0].active, "Validator should be inactive");

            // Owner2 (non-owner) tries to add validator - should fail
            let res = validator_config.add_validator(
                owner2,
                validator2,
                FixedBytes::<32>::from([0x66; 32]),
                true,
                "192.168.1.2:8000".to_string(),
                "192.168.1.2:9000".to_string(),
            );
            assert_eq!(res, Err(ValidatorConfigError::unauthorized().into()));

            // Owner2 (non-owner) tries to change validator status - should fail
            let res = validator_config.change_validator_status(owner2, validator1, true);
            assert_eq!(res, Err(ValidatorConfigError::unauthorized().into()));

            Ok(())
        })
    }

    #[test]
    fn test_validator_lifecycle() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let owner = Address::from([0x01; 20]);

            let mut validator_config = ValidatorConfig::new();
            validator_config.initialize(owner)?;

            let validator1 = Address::from([0x11; 20]);
            let public_key1 = FixedBytes::<32>::from([0x21; 32]);
            let inbound1 = "192.168.1.1:8000".to_string();
            let outbound1 = "192.168.1.1:9000".to_string();
            validator_config.add_validator(
                owner,
                validator1,
                public_key1,
                true,
                inbound1.clone(),
                outbound1,
            )?;

            // Try adding duplicate validator - should fail
            let result = validator_config.add_validator(
                owner,
                validator1,
                FixedBytes::<32>::from([0x22; 32]),
                true,
                "192.168.1.1:8000".to_string(),
                "192.168.1.1:9000".to_string(),
            );
            assert_eq!(
                result,
                Err(ValidatorConfigError::validator_already_exists().into()),
                "Should return ValidatorAlreadyExists error"
            );

            // Add 4 more unique validators
            let validator2 = Address::from([0x12; 20]);
            let public_key2 = FixedBytes::<32>::from([0x22; 32]);
            validator_config.add_validator(
                owner,
                validator2,
                public_key2,
                true,
                "192.168.1.2:8000".to_string(),
                "192.168.1.2:9000".to_string(),
            )?;

            let validator3 = Address::from([0x13; 20]);
            let public_key3 = FixedBytes::<32>::from([0x23; 32]);
            validator_config.add_validator(
                owner,
                validator3,
                public_key3,
                false,
                "192.168.1.3:8000".to_string(),
                "192.168.1.3:9000".to_string(),
            )?;

            let validator4 = Address::from([0x14; 20]);
            let public_key4 = FixedBytes::<32>::from([0x24; 32]);
            validator_config.add_validator(
                owner,
                validator4,
                public_key4,
                true,
                "192.168.1.4:8000".to_string(),
                "192.168.1.4:9000".to_string(),
            )?;

            let validator5 = Address::from([0x15; 20]);
            let public_key5 = FixedBytes::<32>::from([0x25; 32]);
            validator_config.add_validator(
                owner,
                validator5,
                public_key5,
                true,
                "192.168.1.5:8000".to_string(),
                "192.168.1.5:9000".to_string(),
            )?;

            // Get all validators
            let mut validators = validator_config.get_validators()?;

            // Verify count
            assert_eq!(validators.len(), 5, "Should have 5 validators");

            // Sort by validator address for consistent checking
            validators.sort_by_key(|v| v.validator_address);

            // Verify each validator
            assert_eq!(validators[0].validator_address, validator1);
            assert_eq!(validators[0].public_key, public_key1);
            assert_eq!(validators[0].inbound_address, inbound1);
            assert!(validators[0].active);

            assert_eq!(validators[1].validator_address, validator2);
            assert_eq!(validators[1].public_key, public_key2);
            assert_eq!(validators[1].inbound_address, "192.168.1.2:8000");
            assert!(validators[1].active);

            assert_eq!(validators[2].validator_address, validator3);
            assert_eq!(validators[2].public_key, public_key3);
            assert_eq!(validators[2].inbound_address, "192.168.1.3:8000");
            assert!(!validators[2].active);

            assert_eq!(validators[3].validator_address, validator4);
            assert_eq!(validators[3].public_key, public_key4);
            assert_eq!(validators[3].inbound_address, "192.168.1.4:8000");
            assert!(validators[3].active);

            assert_eq!(validators[4].validator_address, validator5);
            assert_eq!(validators[4].public_key, public_key5);
            assert_eq!(validators[4].inbound_address, "192.168.1.5:8000");
            assert!(validators[4].active);

            // Validator1 updates from long to short address (tests update_string slot clearing)
            let public_key1_new = FixedBytes::<32>::from([0x31; 32]);
            let short_inbound1 = "10.0.0.1:8000".to_string();
            let short_outbound1 = "10.0.0.1:9000".to_string();
            validator_config.update_validator(
                validator1,
                validator1,
                public_key1_new,
                short_inbound1.clone(),
                short_outbound1,
            )?;

            // Validator2 rotates to new address, keeps IP and publicKey
            let validator2_new = Address::from([0x22; 20]);
            validator_config.update_validator(
                validator2,
                validator2_new,
                public_key2,
                "192.168.1.2:8000".to_string(),
                "192.168.1.2:9000".to_string(),
            )?;

            // Validator3 rotates to new address with long host (tests delete_string on old slot)
            let validator3_new = Address::from([0x23; 20]);
            let long_inbound3 = "192.169.1.3:8000".to_string();
            let long_outbound3 = "192.168.1.3:9000".to_string();
            validator_config.update_validator(
                validator3,
                validator3_new,
                public_key3,
                long_inbound3.clone(),
                long_outbound3,
            )?;

            // Get all validators again
            let mut validators = validator_config.get_validators()?;

            // Should still have 5 validators
            assert_eq!(validators.len(), 5, "Should still have 5 validators");

            // Sort by validator address
            validators.sort_by_key(|v| v.validator_address);

            // Verify validator1 - updated from long to short address
            assert_eq!(validators[0].validator_address, validator1);
            assert_eq!(
                validators[0].public_key, public_key1_new,
                "PublicKey should be updated"
            );
            assert_eq!(
                validators[0].inbound_address, short_inbound1,
                "Address should be updated to short"
            );
            assert!(validators[0].active);

            // Verify validator4 - unchanged
            assert_eq!(validators[1].validator_address, validator4);
            assert_eq!(validators[1].public_key, public_key4);
            assert_eq!(validators[1].inbound_address, "192.168.1.4:8000");
            assert!(validators[1].active);

            // Verify validator5 - unchanged
            assert_eq!(validators[2].validator_address, validator5);
            assert_eq!(validators[2].public_key, public_key5);
            assert_eq!(validators[2].inbound_address, "192.168.1.5:8000");
            assert!(validators[2].active);

            // Verify validator2_new - rotated address, kept IP and publicKey
            assert_eq!(validators[3].validator_address, validator2_new);
            assert_eq!(
                validators[3].public_key, public_key2,
                "PublicKey should be same"
            );
            assert_eq!(
                validators[3].inbound_address, "192.168.1.2:8000",
                "IP should be same"
            );
            assert!(validators[3].active);

            // Verify validator3_new - rotated address with long host, kept publicKey
            assert_eq!(validators[4].validator_address, validator3_new);
            assert_eq!(
                validators[4].public_key, public_key3,
                "PublicKey should be same"
            );
            assert_eq!(
                validators[4].inbound_address, long_inbound3,
                "Address should be updated to long"
            );
            assert!(!validators[4].active);

            Ok(())
        })
    }

    #[test]
    fn test_owner_cannot_update_validator() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut validator_config = ValidatorConfig::new();
            validator_config.initialize(owner)?;

            // Owner adds a validator
            let public_key = FixedBytes::<32>::from([0x21; 32]);
            validator_config.add_validator(
                owner,
                validator,
                public_key,
                true,
                "192.168.1.1:8000".to_string(),
                "192.168.1.1:9000".to_string(),
            )?;

            // Owner tries to update validator - should fail
            let result = validator_config.update_validator(
                owner,
                validator,
                FixedBytes::<32>::from([0x22; 32]),
                "10.0.0.1:8000".to_string(),
                "10.0.0.1:9000".to_string(),
            );

            assert_eq!(
                result,
                Err(ValidatorConfigError::validator_not_found().into()),
                "Should return ValidatorNotFound error"
            );

            Ok(())
        })
    }

    #[test]
    fn test_validator_rotation_clears_all_slots() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator1 = Address::random();
        let validator2 = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut validator_config = ValidatorConfig::new();
            validator_config.initialize(owner)?;

            // Add validator with long inbound address that uses multiple slots
            let long_inbound = "192.168.1.1:8000".to_string();
            let long_outbound = "192.168.1.1:9000".to_string();
            let public_key = FixedBytes::<32>::from([0x21; 32]);

            validator_config.add_validator(
                owner,
                validator1,
                public_key,
                true,
                long_inbound,
                long_outbound,
            )?;

            // Rotate to new address with shorter addresses
            validator_config.update_validator(
                validator1,
                validator2,
                public_key,
                "10.0.0.1:8000".to_string(),
                "10.0.0.1:9000".to_string(),
            )?;

            // Verify old slots are cleared by checking storage directly
            let validator = validator_config.validators[validator1].read()?;

            // Assert all validator fields are cleared/zeroed
            assert_eq!(
                validator.public_key,
                B256::ZERO,
                "Old validator public key should be cleared"
            );
            assert_eq!(
                validator.validator_address,
                Address::ZERO,
                "Old validator address should be cleared"
            );
            assert_eq!(validator.index, 0, "Old validator index should be cleared");
            assert!(!validator.active, "Old validator should be inactive");
            assert_eq!(
                validator.inbound_address,
                String::default(),
                "Old validator inbound address should be cleared"
            );
            assert_eq!(
                validator.outbound_address,
                String::default(),
                "Old validator outbound address should be cleared"
            );

            Ok(())
        })
    }

    #[test]
    fn test_next_dkg_ceremony() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let non_owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut validator_config = ValidatorConfig::new();
            validator_config.initialize(owner)?;

            // Default value is 0
            assert_eq!(validator_config.get_next_full_dkg_ceremony()?, 0);

            // Owner can set the value
            validator_config.set_next_full_dkg_ceremony(owner, 42)?;
            assert_eq!(validator_config.get_next_full_dkg_ceremony()?, 42);

            // Non-owner cannot set the value
            let result = validator_config.set_next_full_dkg_ceremony(non_owner, 100);
            assert_eq!(result, Err(ValidatorConfigError::unauthorized().into()));

            // Value unchanged after failed attempt
            assert_eq!(validator_config.get_next_full_dkg_ceremony()?, 42);

            Ok(())
        })
    }

    #[test]
    fn test_ipv4_with_port_is_host_port() {
        ensure_address_is_ip_port("127.0.0.1:8000").unwrap();
    }

    #[test]
    fn test_ipv6_with_port_is_host_port() {
        ensure_address_is_ip_port("[::1]:8000").unwrap();
    }

    #[test]
    fn test_add_validator_rejects_zero_public_key() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut validator_config = ValidatorConfig::new();
            validator_config.initialize(owner)?;

            let zero_public_key = FixedBytes::<32>::ZERO;
            let result = validator_config.add_validator(
                owner,
                validator,
                zero_public_key,
                true,
                "192.168.1.1:8000".to_string(),
                "192.168.1.1:9000".to_string(),
            );

            assert_eq!(
                result,
                Err(ValidatorConfigError::invalid_public_key().into()),
                "Should reject zero public key"
            );

            // Verify no validator was added
            let validators = validator_config.get_validators()?;
            assert_eq!(validators.len(), 0, "Should have no validators");

            Ok(())
        })
    }

    #[test]
    fn test_update_validator_rejects_zero_public_key() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut validator_config = ValidatorConfig::new();
            validator_config.initialize(owner)?;

            let original_public_key = FixedBytes::<32>::from([0x44; 32]);
            validator_config.add_validator(
                owner,
                validator,
                original_public_key,
                true,
                "192.168.1.1:8000".to_string(),
                "192.168.1.1:9000".to_string(),
            )?;

            let zero_public_key = FixedBytes::<32>::ZERO;
            let result = validator_config.update_validator(
                validator,
                validator,
                zero_public_key,
                "192.168.1.1:8000".to_string(),
                "192.168.1.1:9000".to_string(),
            );

            assert_eq!(
                result,
                Err(ValidatorConfigError::invalid_public_key().into()),
                "Should reject zero public key in update"
            );

            // Verify original public key is preserved
            let validators = validator_config.get_validators()?;
            assert_eq!(validators.len(), 1, "Should still have 1 validator");
            assert_eq!(
                validators[0].public_key, original_public_key,
                "Original public key should be preserved"
            );

            Ok(())
        })
    }

    #[test]
    fn test_validators_array_returns_correct_address() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator1 = Address::random();
        let validator2 = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut validator_config = ValidatorConfig::new();
            validator_config.initialize(owner)?;

            let public_key1 = FixedBytes::<32>::from([0x11; 32]);
            let public_key2 = FixedBytes::<32>::from([0x22; 32]);

            // Add validators
            validator_config.add_validator(
                owner,
                validator1,
                public_key1,
                true,
                "192.168.1.1:8000".to_string(),
                "192.168.1.1:9000".to_string(),
            )?;

            validator_config.add_validator(
                owner,
                validator2,
                public_key2,
                true,
                "192.168.1.2:8000".to_string(),
                "192.168.1.2:9000".to_string(),
            )?;

            // validators_array should return the actual addresses, not default
            assert_eq!(validator_config.validators_array(U256::ZERO)?, validator1);
            assert_eq!(validator_config.validators_array(U256::ONE)?, validator2);

            // Verify they're not default
            assert_ne!(
                validator_config.validators_array(U256::ZERO)?,
                Address::ZERO
            );
            assert_ne!(validator_config.validators_array(U256::ONE)?, Address::ZERO);

            Ok(())
        })
    }

    #[test]
    fn test_next_dkg_ceremony_returns_correct_value() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut validator_config = ValidatorConfig::new();
            validator_config.initialize(owner)?;

            // Default should be 0
            assert_eq!(validator_config.get_next_full_dkg_ceremony()?, 0);

            // Set to a specific value
            validator_config.set_next_full_dkg_ceremony(owner, 100)?;

            // Should return the set value, not 0 or 1
            let result = validator_config.get_next_full_dkg_ceremony()?;
            assert_eq!(result, 100);
            assert_ne!(result, 0);
            assert_ne!(result, 1);

            Ok(())
        })
    }

    #[test]
    fn test_ensure_address_is_ip_port_rejects_invalid() {
        // Test invalid formats are rejected (not silently returning Ok)
        let invalid_cases = [
            "not-an-ip:8000",    // hostname, not IP
            "192.168.1.1",       // missing port
            "8000",              // just port
            "",                  // empty
            "192.168.1.1:abc",   // non-numeric port
            "192.168.1.1:99999", // port out of range
        ];

        for invalid in invalid_cases {
            let result = ensure_address_is_ip_port(invalid);
            assert!(result.is_err(), "Expected error for '{invalid}', got Ok");
        }

        // Valid IP:port should succeed
        assert!(ensure_address_is_ip_port("192.168.1.1:8000").is_ok());
        assert!(ensure_address_is_ip_port("[::1]:8000").is_ok());
    }
}
