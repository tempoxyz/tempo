pub mod dispatch;

use tempo_contracts::precompiles::VALIDATOR_CONFIG_ADDRESS;
pub use tempo_contracts::precompiles::{IValidatorConfig, ValidatorConfigError};
use tempo_precompiles_macros::{Storable, contract};

use crate::{
    error::TempoPrecompileError,
    storage::{Mapping, PrecompileStorageProvider, Slot, VecSlotExt},
};
use alloy::primitives::{Address, B256, Bytes};
use revm::state::Bytecode;
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

/// Helper type to easily interact with the `validators_array`
type ValidatorsArray = Slot<Vec<Address>>;

/// Validator Config precompile for managing consensus validators
#[contract]
pub struct ValidatorConfig {
    owner: Address,
    validator_count: u64,
    validators_array: Vec<Address>,
    validators: Mapping<Address, Validator>,
}

impl<'a, S: PrecompileStorageProvider> ValidatorConfig<'a, S> {
    pub fn new(storage: &'a mut S) -> Self {
        Self::_new(VALIDATOR_CONFIG_ADDRESS, storage)
    }

    /// Initialize the precompile with an owner
    pub fn initialize(&mut self, owner: Address) -> Result<(), TempoPrecompileError> {
        trace!(address=%self.address, %owner, "Initializing validator config precompile");

        // must ensure the account is not empty, by setting some code
        self.storage.set_code(
            self.address,
            Bytecode::new_legacy(Bytes::from_static(&[0xef])),
        )?;

        self.sstore_owner(owner)?;

        Ok(())
    }

    /// Internal helper to get owner
    pub fn owner(&mut self) -> Result<Address, TempoPrecompileError> {
        self.sload_owner()
    }

    /// Check if caller is the owner
    pub fn check_owner(&mut self, caller: Address) -> Result<(), TempoPrecompileError> {
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
    ) -> Result<(), TempoPrecompileError> {
        self.check_owner(sender)?;
        self.sstore_owner(call.newOwner)
    }

    /// Get the current validator count
    fn validator_count(&mut self) -> Result<u64, TempoPrecompileError> {
        self.sload_validator_count()
    }

    /// Check if a validator exists by checking if their publicKey is non-zero
    /// Since ed25519 keys cannot be zero, this is a reliable existence check
    fn validator_exists(&mut self, validator: Address) -> Result<bool, TempoPrecompileError> {
        let validator = self.sload_validators(validator)?;
        Ok(!validator.public_key.is_zero())
    }

    /// Get all validators (view function)
    pub fn get_validators(
        &mut self,
        _call: IValidatorConfig::getValidatorsCall,
    ) -> Result<Vec<IValidatorConfig::Validator>, TempoPrecompileError> {
        let count = self.validator_count()?;
        let mut validators = Vec::new();

        let validators_array = ValidatorsArray::new(slots::VALIDATORS_ARRAY);
        for i in 0..count {
            // Read validator address from the array at index i
            let validator_address = validators_array.read_at(self, i as usize)?;

            let Validator {
                public_key,
                active,
                index,
                validator_address: _,
                inbound_address,
                outbound_address,
            } = self.sload_validators(validator_address)?;

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
    ) -> Result<(), TempoPrecompileError> {
        // Only owner can create validators
        self.check_owner(sender)?;

        // Check if validator already exists
        if self.validator_exists(call.newValidatorAddress)? {
            return Err(ValidatorConfigError::validator_already_exists())?;
        }

        // Validate addresses
        ensure_is_host_port(&call.inboundAddress).map_err(|err| {
            ValidatorConfigError::not_host_port(
                "inboundAddress".to_string(),
                call.inboundAddress.clone(),
                format!("{err:?}"),
            )
        })?;

        ensure_is_ip_port(&call.outboundAddress).map_err(|err| {
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
        self.sstore_validators(call.newValidatorAddress, validator)?;

        // Add the validator public key to the validators array
        ValidatorsArray::new(slots::VALIDATORS_ARRAY).push(self, call.newValidatorAddress)?;

        // Increment the validator count
        self.sstore_validator_count(
            count
                .checked_add(1)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        Ok(())
    }

    /// Update validator information (and optionally rotate to new address)
    pub fn update_validator(
        &mut self,
        sender: Address,
        call: IValidatorConfig::updateValidatorCall,
    ) -> Result<(), TempoPrecompileError> {
        // Validator can update their own info
        if !self.validator_exists(sender)? {
            return Err(ValidatorConfigError::validator_not_found())?;
        }

        // Load the current validator info
        let old_validator = self.sload_validators(sender)?;

        // Check if rotating to a new address
        if call.newValidatorAddress != sender {
            if self.validator_exists(call.newValidatorAddress)? {
                return Err(ValidatorConfigError::validator_already_exists())?;
            }

            // Update the validators array to point at the new validator address
            ValidatorsArray::new(slots::VALIDATORS_ARRAY).write_at(
                self,
                old_validator.index as usize,
                call.newValidatorAddress,
            )?;

            // Clear the old validator
            self.clear_validators(sender)?;
        }

        ensure_is_host_port(&call.inboundAddress).map_err(|err| {
            ValidatorConfigError::not_host_port(
                "inboundAddress".to_string(),
                call.inboundAddress.clone(),
                format!("{err:?}"),
            )
        })?;

        ensure_is_ip_port(&call.outboundAddress).map_err(|err| {
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

        self.sstore_validators(call.newValidatorAddress, updated_validator)?;

        Ok(())
    }

    /// Change validator active status (owner only)
    pub fn change_validator_status(
        &mut self,
        sender: Address,
        call: IValidatorConfig::changeValidatorStatusCall,
    ) -> Result<(), TempoPrecompileError> {
        self.check_owner(sender)?;

        if !self.validator_exists(call.validator)? {
            return Err(ValidatorConfigError::validator_not_found())?;
        }

        let mut validator = self.sload_validators(call.validator)?;
        validator.active = call.active;
        self.sstore_validators(call.validator, validator)?;

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
enum HostWithPortParseError {
    #[error("failed to parse host segment of input")]
    HostNotFqdn(#[from] fqdn::Error),
    #[error("failed to parse port segment of input")]
    BadPort(#[from] std::num::ParseIntError),
    #[error("input has no colon and cannot be of the form <host>:<port>")]
    NoColon,
}

#[derive(Debug, thiserror::Error)]
enum IpWithPortParseError {
    #[error("input must be an IP address with port")]
    NotIpPort(#[from] std::net::AddrParseError),
}

fn ensure_is_host_port(input: &str) -> Result<(), HostWithPortParseError> {
    // First, attempt to parse it as a socket addr; this covers the ipv4, ipv6 cases.
    if input.parse::<std::net::SocketAddr>().is_ok() {
        Ok(())
    } else {
        // If that fails, try to parse the parts individually
        let (maybe_host, maybe_port) = input
            .rsplit_once(':')
            .ok_or(HostWithPortParseError::NoColon)?;
        maybe_host.parse::<fqdn::FQDN>()?;
        maybe_port.parse::<u16>()?;
        Ok(())
    }
}

fn ensure_is_ip_port(input: &str) -> Result<(), IpWithPortParseError> {
    // Only accept IP addresses (v4 or v6) with port
    input.parse::<std::net::SocketAddr>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::hashmap::HashMapStorageProvider;
    use alloy::primitives::Address;
    use alloy_primitives::FixedBytes;

    #[test]
    fn test_owner_initialization_and_change() {
        let mut storage = HashMapStorageProvider::new(1);
        let owner1 = Address::from([0x11; 20]);
        let owner2 = Address::from([0x22; 20]);

        let mut validator_config = ValidatorConfig::new(&mut storage);

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
                owner1,
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

        let mut validator_config = ValidatorConfig::new(&mut storage);

        // Initialize with owner1
        validator_config.initialize(owner1).unwrap();

        // Owner1 adds a validator - should succeed
        let public_key = FixedBytes::<32>::from([0x44; 32]);
        let result = validator_config.add_validator(
            owner1,
            IValidatorConfig::addValidatorCall {
                newValidatorAddress: validator1,
                publicKey: public_key,
                inboundAddress: "192.168.1.1:8000".to_string(),
                active: true,
                outboundAddress: "192.168.1.1:9000".to_string(),
            },
        );
        assert!(result.is_ok(), "Owner should be able to add validator");

        // Verify validator was added
        let validators = validator_config
            .get_validators(IValidatorConfig::getValidatorsCall {})
            .expect("Should get validators");
        assert_eq!(validators.len(), 1, "Should have 1 validator");
        assert_eq!(validators[0].validatorAddress, validator1);
        assert_eq!(validators[0].publicKey, public_key);
        assert!(validators[0].active, "New validator should be active");

        // Owner1 changes validator status - should succeed
        let result = validator_config.change_validator_status(
            owner1,
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
            owner2,
            IValidatorConfig::addValidatorCall {
                newValidatorAddress: validator2,
                publicKey: FixedBytes::<32>::from([0x66; 32]),
                inboundAddress: "192.168.1.2:8000".to_string(),
                active: true,
                outboundAddress: "192.168.1.2:9000".to_string(),
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
            owner2,
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

        let mut validator_config = ValidatorConfig::new(&mut storage);
        validator_config.initialize(owner).unwrap();

        // Add first validator with long inbound address (100+ bytes)
        let validator1 = Address::from([0x11; 20]);
        let public_key1 = FixedBytes::<32>::from([0x21; 32]);
        let long_host1 = "a.".repeat(100);
        let long_inbound1 = format!("{long_host1}:8000");
        let long_outbound1 = "192.168.1.1:9000".to_string();
        validator_config
            .add_validator(
                owner,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator1,
                    publicKey: public_key1,
                    inboundAddress: long_inbound1.clone(),
                    active: true,
                    outboundAddress: long_outbound1,
                },
            )
            .expect("should add validator1");

        // Try adding duplicate validator - should fail
        let result = validator_config.add_validator(
            owner,
            IValidatorConfig::addValidatorCall {
                newValidatorAddress: validator1,
                publicKey: FixedBytes::<32>::from([0x22; 32]),
                inboundAddress: "192.168.1.2:8000".to_string(),
                active: true,
                outboundAddress: "192.168.1.2:9000".to_string(),
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
        let public_key2 = FixedBytes::<32>::from([0x22; 32]);
        validator_config
            .add_validator(
                owner,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator2,
                    publicKey: public_key2,
                    inboundAddress: "192.168.1.2:8000".to_string(),
                    active: true,
                    outboundAddress: "192.168.1.2:9000".to_string(),
                },
            )
            .expect("Should add validator2");

        let validator3 = Address::from([0x13; 20]);
        let public_key3 = FixedBytes::<32>::from([0x23; 32]);
        validator_config
            .add_validator(
                owner,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator3,
                    publicKey: public_key3,
                    inboundAddress: "192.168.1.3:8000".to_string(),
                    active: false,
                    outboundAddress: "192.168.1.3:9000".to_string(),
                },
            )
            .expect("Should add validator3");

        let validator4 = Address::from([0x14; 20]);
        let public_key4 = FixedBytes::<32>::from([0x24; 32]);
        validator_config
            .add_validator(
                owner,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator4,
                    publicKey: public_key4,
                    inboundAddress: "192.168.1.4:8000".to_string(),
                    active: true,
                    outboundAddress: "192.168.1.4:9000".to_string(),
                },
            )
            .expect("Should add validator4");

        let validator5 = Address::from([0x15; 20]);
        let public_key5 = FixedBytes::<32>::from([0x25; 32]);
        validator_config
            .add_validator(
                owner,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator5,
                    publicKey: public_key5,
                    inboundAddress: "192.168.1.5:8000".to_string(),
                    active: true,
                    outboundAddress: "192.168.1.5:9000".to_string(),
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
        assert_eq!(validators[0].publicKey, public_key1);
        assert_eq!(validators[0].inboundAddress, long_inbound1);
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
        validator_config
            .update_validator(
                validator1,
                IValidatorConfig::updateValidatorCall {
                    newValidatorAddress: validator1,
                    publicKey: public_key1_new,
                    inboundAddress: short_inbound1.clone(),
                    outboundAddress: short_outbound1,
                },
            )
            .expect("Should update validator1");

        // Validator2 rotates to new address, keeps IP and publicKey
        let validator2_new = Address::from([0x22; 20]);
        validator_config
            .update_validator(
                validator2,
                IValidatorConfig::updateValidatorCall {
                    newValidatorAddress: validator2_new,
                    publicKey: public_key2,
                    inboundAddress: "192.168.1.2:8000".to_string(),
                    outboundAddress: "192.168.1.2:9000".to_string(),
                },
            )
            .expect("Should rotate validator2 address");

        // Validator3 rotates to new address with long host (tests delete_string on old slot)
        let validator3_new = Address::from([0x23; 20]);
        let long_host3 = "b.".repeat(125);
        let long_inbound3 = format!("{long_host3}:8000");
        let long_outbound3 = "192.168.1.3:9000".to_string();
        validator_config
            .update_validator(
                validator3,
                IValidatorConfig::updateValidatorCall {
                    newValidatorAddress: validator3_new,
                    publicKey: public_key3,
                    inboundAddress: long_inbound3.clone(),
                    outboundAddress: long_outbound3,
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
    }

    #[test]
    fn test_owner_cannot_update_validator() {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::from([0x01; 20]);
        let validator = Address::from([0x11; 20]);

        let mut validator_config = ValidatorConfig::new(&mut storage);
        validator_config.initialize(owner).unwrap();

        // Owner adds a validator
        let public_key = FixedBytes::<32>::from([0x21; 32]);
        validator_config
            .add_validator(
                owner,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator,
                    publicKey: public_key,
                    inboundAddress: "192.168.1.1:8000".to_string(),
                    active: true,
                    outboundAddress: "192.168.1.1:9000".to_string(),
                },
            )
            .expect("Should add validator");

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

    #[test]
    fn test_max_length_dns_hostname() {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::from([0x01; 20]);
        let validator = Address::from([0x11; 20]);

        let mut validator_config = ValidatorConfig::new(&mut storage);
        validator_config.initialize(owner).unwrap();

        // Create a 253-character hostname (max valid DNS length) for inbound
        // Using valid DNS characters: a-z, 0-9, hyphens, dots
        let aaa = "a".repeat(63);
        let bbb = "b".repeat(63);
        let ccc = "c".repeat(63);
        let ddd = "d".repeat(61);
        let inbound_address = format!("{aaa}.{bbb}.{ccc}.{ddd}:8000");
        // Outbound must be IP address
        let outbound_address = "192.168.1.1:9000".to_string();

        // Add validator with max-length hostname - should succeed
        let public_key = FixedBytes::<32>::from([0x21; 32]);
        validator_config
            .add_validator(
                owner,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator,
                    publicKey: public_key,
                    inboundAddress: inbound_address.clone(),
                    active: true,
                    outboundAddress: outbound_address.clone(),
                },
            )
            .expect("should accept a 253 character hostname");

        // Read back and verify
        let validators = validator_config
            .get_validators(IValidatorConfig::getValidatorsCall {})
            .expect("Should get validators");
        assert_eq!(validators.len(), 1, "Should have 1 validator");
        assert_eq!(validators[0].inboundAddress, inbound_address);
        assert_eq!(validators[0].outboundAddress, outbound_address);
    }

    #[test]
    fn test_too_long_dns_hostname() {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::from([0x01; 20]);
        let validator = Address::from([0x11; 20]);

        let mut validator_config = ValidatorConfig::new(&mut storage);
        validator_config.initialize(owner).unwrap();

        // Create a 254-character hostname (exceeds max DNS length)
        let too_long_host = "a".repeat(254);
        let inbound_address = format!("{too_long_host}:8000");
        let outbound_address = format!("{too_long_host}:9000");

        // Try to add validator with too-long hostname - should fail
        let public_key = FixedBytes::<32>::from([0x21; 32]);
        let result = validator_config.add_validator(
            owner,
            IValidatorConfig::addValidatorCall {
                newValidatorAddress: validator,
                publicKey: public_key,
                inboundAddress: inbound_address,
                active: true,
                outboundAddress: outbound_address,
            },
        );
        assert!(
            result.is_err(),
            "Should reject 254-character hostname (exceeds DNS limit)"
        );
    }

    #[test]
    fn test_validator_rotation_clears_all_slots() {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::from([0x01; 20]);
        let validator1 = Address::from([0x11; 20]);
        let validator2 = Address::from([0x22; 20]);

        let mut validator_config = ValidatorConfig::new(&mut storage);
        validator_config.initialize(owner).unwrap();

        // Add validator with long inbound address that uses multiple slots
        let long_host = "a.".repeat(100);
        let long_inbound = format!("{long_host}:8000");
        let long_outbound = "192.168.1.1:9000".to_string();
        let public_key = FixedBytes::<32>::from([0x21; 32]);

        validator_config
            .add_validator(
                owner,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator1,
                    publicKey: public_key,
                    inboundAddress: long_inbound,
                    active: true,
                    outboundAddress: long_outbound,
                },
            )
            .expect("Should add validator with long addresses");

        // Rotate to new address with shorter addresses
        validator_config
            .update_validator(
                validator1,
                IValidatorConfig::updateValidatorCall {
                    newValidatorAddress: validator2,
                    publicKey: public_key,
                    inboundAddress: "10.0.0.1:8000".to_string(),
                    outboundAddress: "10.0.0.1:9000".to_string(),
                },
            )
            .expect("Should rotate validator");

        // Verify old slots are cleared by checking storage directly
        let validator = validator_config
            .sload_validators(validator1)
            .expect("Could not load validator");

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
    }

    #[test]
    fn test_update_string_various_lengths() {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::from([0x01; 20]);
        let validator = Address::from([0x11; 20]);

        let mut validator_config = ValidatorConfig::new(&mut storage);
        validator_config.initialize(owner).unwrap();

        // Start with a long address
        let long_host = "a.".repeat(100);
        let initial_inbound = format!("{long_host}:8000");
        let public_key = FixedBytes::<32>::from([0x21; 32]);

        validator_config
            .add_validator(
                owner,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: validator,
                    publicKey: public_key,
                    inboundAddress: initial_inbound.clone(),
                    active: true,
                    outboundAddress: "10.0.0.1:9000".to_string(),
                },
            )
            .expect("Should add validator");

        // Update to same value - should still work
        validator_config
            .update_validator(
                validator,
                IValidatorConfig::updateValidatorCall {
                    newValidatorAddress: validator,
                    publicKey: public_key,
                    inboundAddress: initial_inbound.clone(),
                    outboundAddress: "10.0.0.1:9000".to_string(),
                },
            )
            .expect("Should update with same address");

        let validators = validator_config
            .get_validators(IValidatorConfig::getValidatorsCall {})
            .unwrap();
        assert_eq!(validators[0].inboundAddress, initial_inbound);

        // Update to shorter address - should clear extra slots
        let short_inbound = "192.168.1.1:8000".to_string();
        validator_config
            .update_validator(
                validator,
                IValidatorConfig::updateValidatorCall {
                    newValidatorAddress: validator,
                    publicKey: public_key,
                    inboundAddress: short_inbound.clone(),
                    outboundAddress: "10.0.0.1:9000".to_string(),
                },
            )
            .expect("Should update to shorter address");

        let validators = validator_config
            .get_validators(IValidatorConfig::getValidatorsCall {})
            .unwrap();
        assert_eq!(validators[0].inboundAddress, short_inbound);

        // Verify the validator's address was updated successfully
        let validators = validator_config
            .get_validators(IValidatorConfig::getValidatorsCall {})
            .unwrap();
        assert_eq!(validators.len(), 1, "Should still have 1 validator");
        assert_eq!(
            validators[0].inboundAddress, short_inbound,
            "Address should be updated to short version"
        );
        assert_eq!(
            validators[0].publicKey, public_key,
            "Public key should remain unchanged"
        );

        // Update to medium-length address
        let medium_host = "b.".repeat(50);
        let medium_inbound = format!("{medium_host}:8000");
        validator_config
            .update_validator(
                validator,
                IValidatorConfig::updateValidatorCall {
                    newValidatorAddress: validator,
                    publicKey: public_key,
                    inboundAddress: medium_inbound.clone(),
                    outboundAddress: "10.0.0.1:9000".to_string(),
                },
            )
            .expect("Should update to medium-length address");

        let validators = validator_config
            .get_validators(IValidatorConfig::getValidatorsCall {})
            .unwrap();
        assert_eq!(validators[0].inboundAddress, medium_inbound);
    }

    #[test]
    fn ipv4_with_port_is_host_port() {
        ensure_is_host_port("127.0.0.1:8000").unwrap();
    }

    #[test]
    fn ipv6_with_port_is_host_port() {
        ensure_is_host_port("[::1]:8000").unwrap();
    }

    #[test]
    fn hostname_with_port_is_host_port() {
        ensure_is_host_port("localhost:8000").unwrap();
    }

    #[test]
    fn k8s_style_with_port_is_host_port() {
        ensure_is_host_port("service.namespace:8000").unwrap();
    }
}
