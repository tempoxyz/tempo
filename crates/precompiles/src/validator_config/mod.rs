pub mod dispatch;

use tempo_contracts::precompiles::VALIDATOR_CONFIG_ADDRESS;
pub use tempo_contracts::precompiles::{IValidatorConfig, ValidatorConfigError};
use tempo_precompiles_macros::{Storable, contract};

/// Minimum number of active validators required to maintain network security.
/// This prevents collapsing the validator set to a 1-of-1 configuration.
pub const MIN_VALIDATORS: u64 = 3;

use crate::{
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping},
};
use alloy::primitives::{Address, B256, keccak256};
use tracing::trace;

/// Validator information
#[derive(Debug, Storable)]
struct Validator {
    public_key: B256,
    active: bool,
    index: u64,
    validator_address: Address,
    /// Address where other validators can connect to this validator.
    /// Format: `<hostname|ip>:<port>`
    inbound_address: String,
    /// IP address for firewall whitelisting by other validators.
    /// Format: `<ip>:<port>` - must be an IP address, not a hostname.
    outbound_address: String,
}

/// Validator Config precompile for managing consensus validators
#[contract(addr = VALIDATOR_CONFIG_ADDRESS)]
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

    /// Internal helper to get owner
    pub fn owner(&self) -> Result<Address> {
        self.owner.read()
    }

    /// Check if caller is the owner
    pub fn check_owner(&self, caller: Address) -> Result<()> {
        if self.owner()? != caller {
            return Err(ValidatorConfigError::unauthorized())?;
        }

        Ok(())
    }

    /// Change the owner (owner only)
    pub fn change_owner(
        &mut self,
        sender: Address,
        call: IValidatorConfig::changeOwnerCall,
    ) -> Result<()> {
        self.check_owner(sender)?;
        self.owner.write(call.newOwner)
    }

    /// Get the current validator count
    pub fn validator_count(&self) -> Result<u64> {
        self.validators_array.len().map(|c| c as u64)
    }

    /// Get validator address at a specific index in the validators array
    pub fn validators_array(&self, index: u64) -> Result<Address> {
        match self.validators_array.at(index as usize)? {
            Some(elem) => elem.read(),
            None => Err(TempoPrecompileError::array_oob()),
        }
    }

    /// Get validator information by address
    pub fn validators(&self, validator: Address) -> Result<IValidatorConfig::Validator> {
        let validator_info = self.validators[validator].read()?;
        Ok(IValidatorConfig::Validator {
            publicKey: validator_info.public_key,
            active: validator_info.active,
            index: validator_info.index,
            validatorAddress: validator_info.validator_address,
            inboundAddress: validator_info.inbound_address,
            outboundAddress: validator_info.outbound_address,
        })
    }

    /// Check if a validator exists by checking if their publicKey is non-zero
    /// Since ed25519 keys cannot be zero, this is a reliable existence check
    fn validator_exists(&self, validator: Address) -> Result<bool> {
        let validator = self.validators[validator].read()?;
        Ok(!validator.public_key.is_zero())
    }

    /// Count the number of active validators
    fn active_validator_count(&self) -> Result<u64> {
        let count = self.validators_array.len()?;
        let mut active_count = 0u64;
        for i in 0..count {
            let validator_address = self.validators_array[i].read()?;
            let validator = self.validators[validator_address].read()?;
            if validator.active {
                active_count += 1;
            }
        }
        Ok(active_count)
    }

    /// Get all validators (view function)
    pub fn get_validators(&self) -> Result<Vec<IValidatorConfig::Validator>> {
        let count = self.validators_array.len()?;
        let mut validators = Vec::with_capacity(count);

        for i in 0..count {
            // Read validator address from the array at index i
            let validator_address = self.validators_array[i].read()?;

            let Validator {
                public_key,
                active,
                index,
                validator_address: _,
                inbound_address,
                outbound_address,
            } = self.validators[validator_address].read()?;

            validators.push(IValidatorConfig::Validator {
                publicKey: public_key,
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
        sender: Address,
        call: IValidatorConfig::addValidatorCall,
    ) -> Result<()> {
        // Reject zero public key - zero is used as sentinel value for non-existence
        if call.publicKey.is_zero() {
            return Err(ValidatorConfigError::invalid_public_key())?;
        }

        // Only owner can create validators
        self.check_owner(sender)?;

        // Check if validator already exists
        if self.validator_exists(call.newValidatorAddress)? {
            return Err(ValidatorConfigError::validator_already_exists())?;
        }

        // Validate addresses
        ensure_address_is_ip_port(&call.inboundAddress).map_err(|err| {
            ValidatorConfigError::not_host_port(
                "inboundAddress".to_string(),
                call.inboundAddress.clone(),
                format!("{err:?}"),
            )
        })?;

        ensure_address_is_ip_port(&call.outboundAddress).map_err(|err| {
            ValidatorConfigError::not_ip_port(
                "outboundAddress".to_string(),
                call.outboundAddress.clone(),
                format!("{err:?}"),
            )
        })?;

        // Store the new validator in the validators mapping
        let count = self.validator_count()?;
        let validator = Validator {
            public_key: call.publicKey,
            active: call.active,
            index: count,
            validator_address: call.newValidatorAddress,
            inbound_address: call.inboundAddress,
            outbound_address: call.outboundAddress,
        };
        self.validators[call.newValidatorAddress].write(validator)?;

        // Add the validator public key to the validators array
        self.validators_array.push(call.newValidatorAddress)
    }

    /// Update validator information (and optionally rotate to new address)
    pub fn update_validator(
        &mut self,
        sender: Address,
        call: IValidatorConfig::updateValidatorCall,
    ) -> Result<()> {
        // Reject zero public key - zero is used as sentinel value for non-existence
        if call.publicKey.is_zero() {
            return Err(ValidatorConfigError::invalid_public_key())?;
        }

        // Validator can update their own info
        if !self.validator_exists(sender)? {
            return Err(ValidatorConfigError::validator_not_found())?;
        }

        // Load the current validator info
        let old_validator = self.validators[sender].read()?;

        // Check if rotating to a new address
        if call.newValidatorAddress != sender {
            if self.validator_exists(call.newValidatorAddress)? {
                return Err(ValidatorConfigError::validator_already_exists())?;
            }

            // Update the validators array to point at the new validator address
            self.validators_array[old_validator.index as usize].write(call.newValidatorAddress)?;

            // Clear the old validator
            self.validators[sender].delete()?;
        }

        ensure_address_is_ip_port(&call.inboundAddress).map_err(|err| {
            ValidatorConfigError::not_host_port(
                "inboundAddress".to_string(),
                call.inboundAddress.clone(),
                format!("{err:?}"),
            )
        })?;

        ensure_address_is_ip_port(&call.outboundAddress).map_err(|err| {
            ValidatorConfigError::not_ip_port(
                "outboundAddress".to_string(),
                call.outboundAddress.clone(),
                format!("{err:?}"),
            )
        })?;

        let updated_validator = Validator {
            public_key: call.publicKey,
            active: old_validator.active,
            index: old_validator.index,
            validator_address: call.newValidatorAddress,
            inbound_address: call.inboundAddress,
            outbound_address: call.outboundAddress,
        };

        self.validators[call.newValidatorAddress].write(updated_validator)
    }

    /// Change validator active status (owner only)
    pub fn change_validator_status(
        &mut self,
        sender: Address,
        call: IValidatorConfig::changeValidatorStatusCall,
    ) -> Result<()> {
        self.check_owner(sender)?;

        if !self.validator_exists(call.validator)? {
            return Err(ValidatorConfigError::validator_not_found())?;
        }

        let mut validator = self.validators[call.validator].read()?;

        // If deactivating a currently active validator, check minimum validator count
        if validator.active && !call.active {
            let active_count = self.active_validator_count()?;
            // After deactivation, we'd have active_count - 1 active validators
            if active_count <= MIN_VALIDATORS {
                return Err(ValidatorConfigError::below_minimum_validators(
                    active_count - 1,
                    MIN_VALIDATORS,
                ))?;
            }
        }

        validator.active = call.active;
        self.validators[call.validator].write(validator)
    }

    /// Get the epoch at which a fresh DKG ceremony will be triggered.
    ///
    /// The fresh DKG ceremony runs in epoch N, and epoch N+1 uses the new DKG polynomial.
    pub fn get_next_full_dkg_ceremony(&self) -> Result<u64> {
        self.next_dkg_ceremony.read()
    }

    /// Get the epoch at which a fresh DKG ceremony will be triggered (public getter)
    pub fn next_dkg_ceremony(&self) -> Result<u64> {
        self.next_dkg_ceremony.read()
    }

    /// Set the epoch at which a fresh DKG ceremony will be triggered (owner only).
    ///
    /// Epoch N runs the ceremony, and epoch N+1 uses the new DKG polynomial.
    pub fn set_next_full_dkg_ceremony(
        &mut self,
        sender: Address,
        call: IValidatorConfig::setNextFullDkgCeremonyCall,
    ) -> Result<()> {
        self.check_owner(sender)?;
        self.next_dkg_ceremony.write(call.epoch)
    }

    /// Compute a hash of the current active validator set.
    ///
    /// This is used in deposit attestation digests to bind signatures to a specific
    /// validator set, preventing threshold manipulation during validator set transitions.
    ///
    /// The hash is computed as:
    /// `keccak256(sorted_active_validator_addresses)`
    ///
    /// Addresses are sorted to ensure deterministic ordering regardless of the order
    /// validators were added.
    pub fn compute_validator_set_hash(&self) -> Result<B256> {
        let validators = self.get_validators()?;
        let mut active_addresses: Vec<Address> = validators
            .iter()
            .filter(|v| v.active)
            .map(|v| v.validatorAddress)
            .collect();

        // Sort for deterministic ordering
        active_addresses.sort();

        // Compute hash of concatenated addresses
        let mut buf = Vec::with_capacity(active_addresses.len() * 20);
        for addr in &active_addresses {
            buf.extend_from_slice(addr.as_slice());
        }

        Ok(keccak256(&buf))
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
    use alloy::primitives::{Address, address};
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
            validator_config.change_owner(
                owner1,
                IValidatorConfig::changeOwnerCall { newOwner: owner2 },
            )?;

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

            // Owner1 adds validators - need MIN_VALIDATORS+1 to test deactivation
            let public_key = FixedBytes::<32>::from([0x44; 32]);
            validator_config.add_validator(
                owner1,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator1,
                    publicKey: public_key,
                    inboundAddress: "192.168.1.1:8000".to_string(),
                    active: true,
                    outboundAddress: "192.168.1.1:9000".to_string(),
                },
            )?;

            // Add more validators to meet MIN_VALIDATORS requirement
            for i in 0..MIN_VALIDATORS {
                validator_config.add_validator(
                    owner1,
                    IValidatorConfig::addValidatorCall {
                        newValidatorAddress: Address::from_word(FixedBytes::<32>::from(
                            [i as u8 + 0x10; 32],
                        )),
                        publicKey: FixedBytes::<32>::from([i as u8 + 0x50; 32]),
                        inboundAddress: format!("192.168.1.{}:8000", i + 10),
                        active: true,
                        outboundAddress: format!("192.168.1.{}:9000", i + 10),
                    },
                )?;
            }

            // Verify validators were added
            let validators = validator_config.get_validators()?;
            assert_eq!(
                validators.len(),
                MIN_VALIDATORS as usize + 1,
                "Should have MIN_VALIDATORS+1 validators"
            );
            assert_eq!(validators[0].validatorAddress, validator1);
            assert_eq!(validators[0].publicKey, public_key);
            assert!(validators[0].active, "New validator should be active");

            // Owner1 changes validator status - should succeed (still above MIN_VALIDATORS)
            validator_config.change_validator_status(
                owner1,
                IValidatorConfig::changeValidatorStatusCall {
                    validator: validator1,
                    active: false,
                },
            )?;

            // Verify status was changed
            let validators = validator_config.get_validators()?;
            assert!(!validators[0].active, "Validator should be inactive");

            // Owner2 (non-owner) tries to add validator - should fail
            let res = validator_config.add_validator(
                owner2,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator2,
                    publicKey: FixedBytes::<32>::from([0x66; 32]),
                    inboundAddress: "192.168.1.2:8000".to_string(),
                    active: true,
                    outboundAddress: "192.168.1.2:9000".to_string(),
                },
            );
            assert_eq!(res, Err(ValidatorConfigError::unauthorized().into()));

            // Owner2 (non-owner) tries to change validator status - should fail
            let res = validator_config.change_validator_status(
                owner2,
                IValidatorConfig::changeValidatorStatusCall {
                    validator: validator1,
                    active: true,
                },
            );
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
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator1,
                    publicKey: public_key1,
                    inboundAddress: inbound1.clone(),
                    active: true,
                    outboundAddress: outbound1,
                },
            )?;

            // Try adding duplicate validator - should fail
            let result = validator_config.add_validator(
                owner,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator1,
                    publicKey: FixedBytes::<32>::from([0x22; 32]),
                    inboundAddress: "192.168.1.1:8000".to_string(),
                    active: true,
                    outboundAddress: "192.168.1.1:9000".to_string(),
                },
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
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator2,
                    publicKey: public_key2,
                    inboundAddress: "192.168.1.2:8000".to_string(),
                    active: true,
                    outboundAddress: "192.168.1.2:9000".to_string(),
                },
            )?;

            let validator3 = Address::from([0x13; 20]);
            let public_key3 = FixedBytes::<32>::from([0x23; 32]);
            validator_config.add_validator(
                owner,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator3,
                    publicKey: public_key3,
                    inboundAddress: "192.168.1.3:8000".to_string(),
                    active: false,
                    outboundAddress: "192.168.1.3:9000".to_string(),
                },
            )?;

            let validator4 = Address::from([0x14; 20]);
            let public_key4 = FixedBytes::<32>::from([0x24; 32]);
            validator_config.add_validator(
                owner,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator4,
                    publicKey: public_key4,
                    inboundAddress: "192.168.1.4:8000".to_string(),
                    active: true,
                    outboundAddress: "192.168.1.4:9000".to_string(),
                },
            )?;

            let validator5 = Address::from([0x15; 20]);
            let public_key5 = FixedBytes::<32>::from([0x25; 32]);
            validator_config.add_validator(
                owner,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator5,
                    publicKey: public_key5,
                    inboundAddress: "192.168.1.5:8000".to_string(),
                    active: true,
                    outboundAddress: "192.168.1.5:9000".to_string(),
                },
            )?;

            // Get all validators
            let mut validators = validator_config.get_validators()?;

            // Verify count
            assert_eq!(validators.len(), 5, "Should have 5 validators");

            // Sort by validator address for consistent checking
            validators.sort_by_key(|v| v.validatorAddress);

            // Verify each validator
            assert_eq!(validators[0].validatorAddress, validator1);
            assert_eq!(validators[0].publicKey, public_key1);
            assert_eq!(validators[0].inboundAddress, inbound1);
            assert!(validators[0].active);

            assert_eq!(validators[1].validatorAddress, validator2);
            assert_eq!(validators[1].publicKey, public_key2);
            assert_eq!(validators[1].inboundAddress, "192.168.1.2:8000");
            assert!(validators[1].active);

            assert_eq!(validators[2].validatorAddress, validator3);
            assert_eq!(validators[2].publicKey, public_key3);
            assert_eq!(validators[2].inboundAddress, "192.168.1.3:8000");
            assert!(!validators[2].active);

            assert_eq!(validators[3].validatorAddress, validator4);
            assert_eq!(validators[3].publicKey, public_key4);
            assert_eq!(validators[3].inboundAddress, "192.168.1.4:8000");
            assert!(validators[3].active);

            assert_eq!(validators[4].validatorAddress, validator5);
            assert_eq!(validators[4].publicKey, public_key5);
            assert_eq!(validators[4].inboundAddress, "192.168.1.5:8000");
            assert!(validators[4].active);

            // Validator1 updates from long to short address (tests update_string slot clearing)
            let public_key1_new = FixedBytes::<32>::from([0x31; 32]);
            let short_inbound1 = "10.0.0.1:8000".to_string();
            let short_outbound1 = "10.0.0.1:9000".to_string();
            validator_config.update_validator(
                validator1,
                IValidatorConfig::updateValidatorCall {
                    newValidatorAddress: validator1,
                    publicKey: public_key1_new,
                    inboundAddress: short_inbound1.clone(),
                    outboundAddress: short_outbound1,
                },
            )?;

            // Validator2 rotates to new address, keeps IP and publicKey
            let validator2_new = Address::from([0x22; 20]);
            validator_config.update_validator(
                validator2,
                IValidatorConfig::updateValidatorCall {
                    newValidatorAddress: validator2_new,
                    publicKey: public_key2,
                    inboundAddress: "192.168.1.2:8000".to_string(),
                    outboundAddress: "192.168.1.2:9000".to_string(),
                },
            )?;

            // Validator3 rotates to new address with long host (tests delete_string on old slot)
            let validator3_new = Address::from([0x23; 20]);
            let long_inbound3 = "192.169.1.3:8000".to_string();
            let long_outbound3 = "192.168.1.3:9000".to_string();
            validator_config.update_validator(
                validator3,
                IValidatorConfig::updateValidatorCall {
                    newValidatorAddress: validator3_new,
                    publicKey: public_key3,
                    inboundAddress: long_inbound3.clone(),
                    outboundAddress: long_outbound3,
                },
            )?;

            // Get all validators again
            let mut validators = validator_config.get_validators()?;

            // Should still have 5 validators
            assert_eq!(validators.len(), 5, "Should still have 5 validators");

            // Sort by validator address
            validators.sort_by_key(|v| v.validatorAddress);

            // Verify validator1 - updated from long to short address
            assert_eq!(validators[0].validatorAddress, validator1);
            assert_eq!(
                validators[0].publicKey, public_key1_new,
                "PublicKey should be updated"
            );
            assert_eq!(
                validators[0].inboundAddress, short_inbound1,
                "Address should be updated to short"
            );
            assert!(validators[0].active);

            // Verify validator4 - unchanged
            assert_eq!(validators[1].validatorAddress, validator4);
            assert_eq!(validators[1].publicKey, public_key4);
            assert_eq!(validators[1].inboundAddress, "192.168.1.4:8000");
            assert!(validators[1].active);

            // Verify validator5 - unchanged
            assert_eq!(validators[2].validatorAddress, validator5);
            assert_eq!(validators[2].publicKey, public_key5);
            assert_eq!(validators[2].inboundAddress, "192.168.1.5:8000");
            assert!(validators[2].active);

            // Verify validator2_new - rotated address, kept IP and publicKey
            assert_eq!(validators[3].validatorAddress, validator2_new);
            assert_eq!(
                validators[3].publicKey, public_key2,
                "PublicKey should be same"
            );
            assert_eq!(
                validators[3].inboundAddress, "192.168.1.2:8000",
                "IP should be same"
            );
            assert!(validators[3].active);

            // Verify validator3_new - rotated address with long host, kept publicKey
            assert_eq!(validators[4].validatorAddress, validator3_new);
            assert_eq!(
                validators[4].publicKey, public_key3,
                "PublicKey should be same"
            );
            assert_eq!(
                validators[4].inboundAddress, long_inbound3,
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
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator,
                    publicKey: public_key,
                    inboundAddress: "192.168.1.1:8000".to_string(),
                    active: true,
                    outboundAddress: "192.168.1.1:9000".to_string(),
                },
            )?;

            // Owner tries to update validator - should fail
            let result = validator_config.update_validator(
                owner,
                IValidatorConfig::updateValidatorCall {
                    newValidatorAddress: validator,
                    publicKey: FixedBytes::<32>::from([0x22; 32]),
                    inboundAddress: "10.0.0.1:8000".to_string(),
                    outboundAddress: "10.0.0.1:9000".to_string(),
                },
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
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator1,
                    publicKey: public_key,
                    inboundAddress: long_inbound,
                    active: true,
                    outboundAddress: long_outbound,
                },
            )?;

            // Rotate to new address with shorter addresses
            validator_config.update_validator(
                validator1,
                IValidatorConfig::updateValidatorCall {
                    newValidatorAddress: validator2,
                    publicKey: public_key,
                    inboundAddress: "10.0.0.1:8000".to_string(),
                    outboundAddress: "10.0.0.1:9000".to_string(),
                },
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
            validator_config.set_next_full_dkg_ceremony(
                owner,
                IValidatorConfig::setNextFullDkgCeremonyCall { epoch: 42 },
            )?;
            assert_eq!(validator_config.get_next_full_dkg_ceremony()?, 42);

            // Non-owner cannot set the value
            let result = validator_config.set_next_full_dkg_ceremony(
                non_owner,
                IValidatorConfig::setNextFullDkgCeremonyCall { epoch: 100 },
            );
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
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator,
                    publicKey: zero_public_key,
                    inboundAddress: "192.168.1.1:8000".to_string(),
                    active: true,
                    outboundAddress: "192.168.1.1:9000".to_string(),
                },
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
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator,
                    publicKey: original_public_key,
                    inboundAddress: "192.168.1.1:8000".to_string(),
                    active: true,
                    outboundAddress: "192.168.1.1:9000".to_string(),
                },
            )?;

            let zero_public_key = FixedBytes::<32>::ZERO;
            let result = validator_config.update_validator(
                validator,
                IValidatorConfig::updateValidatorCall {
                    newValidatorAddress: validator,
                    publicKey: zero_public_key,
                    inboundAddress: "192.168.1.1:8000".to_string(),
                    outboundAddress: "192.168.1.1:9000".to_string(),
                },
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
                validators[0].publicKey, original_public_key,
                "Original public key should be preserved"
            );

            Ok(())
        })
    }

    #[test]
    fn test_cannot_deactivate_below_minimum_validators() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut validator_config = ValidatorConfig::new();
            validator_config.initialize(owner)?;

            // Add exactly MIN_VALIDATORS active validators
            let mut validators = Vec::new();
            for i in 0..super::MIN_VALIDATORS {
                let validator = Address::random();
                validators.push(validator);
                validator_config.add_validator(
                    owner,
                    IValidatorConfig::addValidatorCall {
                        newValidatorAddress: validator,
                        publicKey: FixedBytes::<32>::from([i as u8 + 1; 32]),
                        inboundAddress: format!("192.168.1.{}:8000", i + 1),
                        active: true,
                        outboundAddress: format!("192.168.1.{}:9000", i + 1),
                    },
                )?;
            }

            // Verify we have MIN_VALIDATORS active
            let all_validators = validator_config.get_validators()?;
            assert_eq!(all_validators.len() as u64, super::MIN_VALIDATORS);

            // Try to deactivate one validator - should fail
            let result = validator_config.change_validator_status(
                owner,
                IValidatorConfig::changeValidatorStatusCall {
                    validator: validators[0],
                    active: false,
                },
            );

            assert_eq!(
                result,
                Err(ValidatorConfigError::below_minimum_validators(
                    super::MIN_VALIDATORS - 1,
                    super::MIN_VALIDATORS
                )
                .into()),
                "Should reject deactivating below minimum validators"
            );

            // Verify validator is still active
            let validator_info = validator_config.validators(validators[0])?;
            assert!(validator_info.active, "Validator should still be active");

            Ok(())
        })
    }

    #[test]
    fn test_can_deactivate_with_more_than_minimum_validators() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut validator_config = ValidatorConfig::new();
            validator_config.initialize(owner)?;

            // Add MIN_VALIDATORS + 1 active validators
            let mut validators = Vec::new();
            for i in 0..=super::MIN_VALIDATORS {
                let validator = Address::random();
                validators.push(validator);
                validator_config.add_validator(
                    owner,
                    IValidatorConfig::addValidatorCall {
                        newValidatorAddress: validator,
                        publicKey: FixedBytes::<32>::from([i as u8 + 1; 32]),
                        inboundAddress: format!("192.168.1.{}:8000", i + 1),
                        active: true,
                        outboundAddress: format!("192.168.1.{}:9000", i + 1),
                    },
                )?;
            }

            // Verify we have MIN_VALIDATORS + 1 active
            let all_validators = validator_config.get_validators()?;
            assert_eq!(all_validators.len() as u64, super::MIN_VALIDATORS + 1);

            // Deactivate one validator - should succeed
            validator_config.change_validator_status(
                owner,
                IValidatorConfig::changeValidatorStatusCall {
                    validator: validators[0],
                    active: false,
                },
            )?;

            // Verify validator is now inactive
            let validator_info = validator_config.validators(validators[0])?;
            assert!(!validator_info.active, "Validator should be inactive");

            // Now try to deactivate another - should fail (at minimum)
            let result = validator_config.change_validator_status(
                owner,
                IValidatorConfig::changeValidatorStatusCall {
                    validator: validators[1],
                    active: false,
                },
            );

            assert_eq!(
                result,
                Err(ValidatorConfigError::below_minimum_validators(
                    super::MIN_VALIDATORS - 1,
                    super::MIN_VALIDATORS
                )
                .into()),
                "Should reject deactivating below minimum validators"
            );

            Ok(())
        })
    }

    #[test]
    fn test_compute_validator_set_hash() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut validator_config = ValidatorConfig::new();
            validator_config.initialize(owner)?;

            // Add validators in non-sorted order (need 4 to be able to deactivate one and stay above MIN_VALIDATORS=3)
            let validator_a = address!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            let validator_c = address!("cccccccccccccccccccccccccccccccccccccccc");
            let validator_b = address!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
            let validator_d = address!("dddddddddddddddddddddddddddddddddddddddd");

            validator_config.add_validator(
                owner,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator_c,
                    publicKey: FixedBytes::<32>::from([0x03; 32]),
                    inboundAddress: "192.168.1.3:8000".to_string(),
                    active: true,
                    outboundAddress: "192.168.1.3:9000".to_string(),
                },
            )?;
            validator_config.add_validator(
                owner,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator_a,
                    publicKey: FixedBytes::<32>::from([0x01; 32]),
                    inboundAddress: "192.168.1.1:8000".to_string(),
                    active: true,
                    outboundAddress: "192.168.1.1:9000".to_string(),
                },
            )?;
            validator_config.add_validator(
                owner,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator_b,
                    publicKey: FixedBytes::<32>::from([0x02; 32]),
                    inboundAddress: "192.168.1.2:8000".to_string(),
                    active: true,
                    outboundAddress: "192.168.1.2:9000".to_string(),
                },
            )?;
            validator_config.add_validator(
                owner,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator_d,
                    publicKey: FixedBytes::<32>::from([0x04; 32]),
                    inboundAddress: "192.168.1.4:8000".to_string(),
                    active: true,
                    outboundAddress: "192.168.1.4:9000".to_string(),
                },
            )?;

            // Compute hash
            let hash = validator_config.compute_validator_set_hash()?;

            // Compute expected hash manually (sorted: a, b, c, d)
            let mut buf = Vec::with_capacity(80);
            buf.extend_from_slice(validator_a.as_slice());
            buf.extend_from_slice(validator_b.as_slice());
            buf.extend_from_slice(validator_c.as_slice());
            buf.extend_from_slice(validator_d.as_slice());
            let expected = keccak256(&buf);

            assert_eq!(
                hash, expected,
                "Validator set hash should match sorted order"
            );

            // Deactivate one validator and verify hash changes
            validator_config.change_validator_status(
                owner,
                IValidatorConfig::changeValidatorStatusCall {
                    validator: validator_b,
                    active: false,
                },
            )?;

            let hash_after = validator_config.compute_validator_set_hash()?;
            assert_ne!(
                hash, hash_after,
                "Hash should change when validator is deactivated"
            );

            // Verify the new hash only includes active validators (a, c, d)
            let mut buf = Vec::with_capacity(60);
            buf.extend_from_slice(validator_a.as_slice());
            buf.extend_from_slice(validator_c.as_slice());
            buf.extend_from_slice(validator_d.as_slice());
            let expected_after = keccak256(&buf);
            assert_eq!(
                hash_after, expected_after,
                "Hash should only include active validators"
            );

            Ok(())
        })
    }
}
