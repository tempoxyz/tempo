pub mod dispatch;

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

    // Validator struct field offsets
    /// Communication key field offset (bytes32)
    pub const VALIDATOR_KEY_OFFSET: U256 = uint!(0_U256);
    /// Packed: active (bool, lowest byte) + index (u64, next 8 bytes)
    pub const VALIDATOR_ACTIVE_INDEX_OFFSET: U256 = uint!(1_U256);
    /// Inbound address field offset (string, uses 9 slots: 2-10)
    pub const VALIDATOR_INBOUND_ADDRESS_OFFSET: U256 = uint!(2_U256);
    /// Outbound address field offset (string, uses 9 slots: 11-19)
    pub const VALIDATOR_OUTBOUND_ADDRESS_OFFSET: U256 = uint!(11_U256);

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

    /// Check if a validator exists by checking if their publicKey is non-zero
    /// Since ed25519 keys cannot be zero, this is a reliable existence check
    fn validator_exists(&mut self, validator: &Address) -> Result<bool, TempoPrecompileError> {
        let slot = slots::validator_base_slot(validator);
        let public_key = self
            .storage
            .sload(self.precompile_address, slot + slots::VALIDATOR_KEY_OFFSET)?;

        Ok(!public_key.is_zero())
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

            let public_key = FixedBytes::<32>::from(
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

        // Store publicKey
        self.storage.sstore(
            self.precompile_address,
            slot + slots::VALIDATOR_KEY_OFFSET,
            U256::from_be_bytes(call.publicKey.0),
        )?;

        // Store active + index packed
        self.storage.sstore(
            self.precompile_address,
            slot + slots::VALIDATOR_ACTIVE_INDEX_OFFSET,
            slots::pack_active_index(call.active, count),
        )?;

        // Store inboundAddress
        ensure_is_host_port(&call.inboundAddress).map_err(|err| {
            ValidatorConfigError::not_host_port(
                "inboundAddress".to_string(),
                call.inboundAddress.clone(),
                format!("{err:?}"),
            )
        })?;
        self.write_string(
            slot + slots::VALIDATOR_INBOUND_ADDRESS_OFFSET,
            call.inboundAddress,
        )?;

        // Store outboundAddress (must be IP:port for firewall whitelisting)
        ensure_is_ip_port(&call.outboundAddress).map_err(|err| {
            ValidatorConfigError::not_ip_port(
                "outboundAddress".to_string(),
                call.outboundAddress.clone(),
                format!("{err:?}"),
            )
        })?;
        self.write_string(
            slot + slots::VALIDATOR_OUTBOUND_ADDRESS_OFFSET,
            call.outboundAddress,
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

            // Clear old validator's publicKey
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
            self.delete_string(old_slot + slots::VALIDATOR_INBOUND_ADDRESS_OFFSET)?;

            // Clear old validator's outboundAddress
            self.delete_string(old_slot + slots::VALIDATOR_OUTBOUND_ADDRESS_OFFSET)?;

            // Update the validators array to point to new address
            let array_slot = slots::validator_at_index_slot(index);
            self.storage.sstore(
                self.precompile_address,
                array_slot,
                call.newValidatorAddress.into_word().into(),
            )?;
        }

        let public_key = self.storage.sload(
            self.precompile_address,
            new_slot + slots::VALIDATOR_KEY_OFFSET,
        )?;

        if public_key != U256::from_be_bytes(call.publicKey.0) {
            self.storage.sstore(
                self.precompile_address,
                new_slot + slots::VALIDATOR_KEY_OFFSET,
                U256::from_be_bytes(call.publicKey.0),
            )?;
        }

        if active || index != 0 {
            self.storage.sstore(
                self.precompile_address,
                new_slot + slots::VALIDATOR_ACTIVE_INDEX_OFFSET,
                slots::pack_active_index(active, index),
            )?;
        }

        ensure_is_host_port(&call.inboundAddress).map_err(|err| {
            ValidatorConfigError::not_host_port(
                "inboundAddress".to_string(),
                call.inboundAddress.clone(),
                format!("{err:?}"),
            )
        })?;
        self.update_string(
            new_slot + slots::VALIDATOR_INBOUND_ADDRESS_OFFSET,
            call.inboundAddress,
        )?;

        ensure_is_ip_port(&call.outboundAddress).map_err(|err| {
            ValidatorConfigError::not_ip_port(
                "outboundAddress".to_string(),
                call.outboundAddress.clone(),
                format!("{err:?}"),
            )
        })?;
        self.update_string(
            new_slot + slots::VALIDATOR_OUTBOUND_ADDRESS_OFFSET,
            call.outboundAddress,
        )?;
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
        let first_value = self.storage.sload(self.precompile_address, slot)?;
        let first_bytes = first_value.to_be_bytes::<32>();
        let len = u16::from_be_bytes([first_bytes[0], first_bytes[1]]) as usize;

        if len == 0 {
            return Ok(String::new());
        }

        let mut all_bytes = Vec::with_capacity(len);
        let first_chunk_len = len.min(30);
        all_bytes.extend_from_slice(&first_bytes[2..2 + first_chunk_len]);

        let mut remaining = len - first_chunk_len;
        let mut slot_offset = 1;
        while remaining > 0 {
            let slot_value = self
                .storage
                .sload(self.precompile_address, slot + U256::from(slot_offset))?;
            let slot_bytes = slot_value.to_be_bytes::<32>();
            let to_read = remaining.min(32);
            all_bytes.extend_from_slice(&slot_bytes[..to_read]);
            remaining -= to_read;
            slot_offset += 1;
        }

        Ok(String::from_utf8_lossy(&all_bytes).to_string())
    }

    fn write_string(&mut self, slot: U256, value: String) -> Result<(), TempoPrecompileError> {
        let bytes = value.as_bytes();
        let len = bytes.len();

        let mut first_slot = [0u8; 32];
        let len_bytes = (len as u16).to_be_bytes();
        first_slot[0] = len_bytes[0];
        first_slot[1] = len_bytes[1];
        let first_chunk_len = len.min(30);
        first_slot[2..2 + first_chunk_len].copy_from_slice(&bytes[..first_chunk_len]);
        self.storage.sstore(
            self.precompile_address,
            slot,
            U256::from_be_bytes(first_slot),
        )?;

        if len > 30 {
            for (i, chunk) in bytes[30..].chunks(32).enumerate() {
                let mut slot_bytes = [0u8; 32];
                slot_bytes[..chunk.len()].copy_from_slice(chunk);
                self.storage.sstore(
                    self.precompile_address,
                    slot + U256::from(i + 1),
                    U256::from_be_bytes(slot_bytes),
                )?;
            }
        }

        Ok(())
    }

    fn update_string(&mut self, slot: U256, value: String) -> Result<(), TempoPrecompileError> {
        let bytes = value.as_bytes();
        let new_len = bytes.len();

        // Read old length
        let old_first_value = self.storage.sload(self.precompile_address, slot)?;
        let old_first_bytes = old_first_value.to_be_bytes::<32>();
        let old_len = u16::from_be_bytes([old_first_bytes[0], old_first_bytes[1]]) as usize;

        // Prepare new first slot
        let mut slot_to_store = [0u8; 32];
        let len_bytes = (new_len as u16).to_be_bytes();
        slot_to_store[0] = len_bytes[0];
        slot_to_store[1] = len_bytes[1];
        let first_chunk_len = new_len.min(30);
        slot_to_store[2..2 + first_chunk_len].copy_from_slice(&bytes[..first_chunk_len]);

        // Update first slot if changed
        if old_first_bytes != slot_to_store {
            self.storage.sstore(
                self.precompile_address,
                slot,
                U256::from_be_bytes(slot_to_store),
            )?;
        }

        // Update additional slots if needed
        if new_len > 30 {
            for (i, chunk) in bytes[30..].chunks(32).enumerate() {
                let mut new_slot_bytes = [0u8; 32];
                new_slot_bytes[..chunk.len()].copy_from_slice(chunk);

                // Only write if different from current value
                let current_value = self
                    .storage
                    .sload(self.precompile_address, slot + U256::from(i + 1))?;
                if current_value.to_be_bytes::<32>() != new_slot_bytes {
                    self.storage.sstore(
                        self.precompile_address,
                        slot + U256::from(i + 1),
                        U256::from_be_bytes(new_slot_bytes),
                    )?;
                }
            }
        }

        // Clear any extra slots if new string is shorter
        if old_len > new_len {
            // ceil division but take into account the 2-byte length header
            let old_total_slots = (old_len + 2).div_ceil(32);
            let new_total_slots = (new_len + 2).div_ceil(32);
            for i in new_total_slots..old_total_slots {
                self.storage
                    .sstore(self.precompile_address, slot + U256::from(i), U256::ZERO)?;
            }
        }

        Ok(())
    }

    fn delete_string(&mut self, slot: U256) -> Result<(), TempoPrecompileError> {
        let first_value = self.storage.sload(self.precompile_address, slot)?;
        let first_bytes = first_value.to_be_bytes::<32>();
        let len = u16::from_be_bytes([first_bytes[0], first_bytes[1]]) as usize;

        self.storage
            .sstore(self.precompile_address, slot, U256::ZERO)?;

        if len > 30 {
            let num_slots = (len - 30).div_ceil(32);
            for i in 0..num_slots {
                self.storage.sstore(
                    self.precompile_address,
                    slot + U256::from(i + 1),
                    U256::ZERO,
                )?;
            }
        }

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
        let public_key = FixedBytes::<32>::from([0x44; 32]);
        let result = validator_config.add_validator(
            &owner1,
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

        // Add first validator with long inbound address (100+ bytes)
        let validator1 = Address::from([0x11; 20]);
        let public_key1 = FixedBytes::<32>::from([0x21; 32]);
        let long_host1 = "a.".repeat(100);
        let long_inbound1 = format!("{long_host1}:8000");
        let long_outbound1 = "192.168.1.1:9000".to_string();
        validator_config
            .add_validator(
                &owner,
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
            &owner,
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
                &owner,
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
                &owner,
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
                &owner,
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
                &owner,
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
                &validator1,
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
                &validator2,
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
                &validator3,
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

        let mut validator_config = ValidatorConfig::new(PRECOMPILE_ADDRESS, &mut storage);
        validator_config.initialize(owner).unwrap();

        // Owner adds a validator
        let public_key = FixedBytes::<32>::from([0x21; 32]);
        validator_config
            .add_validator(
                &owner,
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
            &owner,
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

        let mut validator_config = ValidatorConfig::new(PRECOMPILE_ADDRESS, &mut storage);
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
                &owner,
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

        let mut validator_config = ValidatorConfig::new(PRECOMPILE_ADDRESS, &mut storage);
        validator_config.initialize(owner).unwrap();

        // Create a 254-character hostname (exceeds max DNS length)
        let too_long_host = "a".repeat(254);
        let inbound_address = format!("{too_long_host}:8000");
        let outbound_address = format!("{too_long_host}:9000");

        // Try to add validator with too-long hostname - should fail
        let public_key = FixedBytes::<32>::from([0x21; 32]);
        let result = validator_config.add_validator(
            &owner,
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

        let mut validator_config = ValidatorConfig::new(PRECOMPILE_ADDRESS, &mut storage);
        validator_config.initialize(owner).unwrap();

        // Add validator with long inbound address that uses multiple slots
        let long_host = "a.".repeat(100);
        let long_inbound = format!("{long_host}:8000");
        let long_outbound = "192.168.1.1:9000".to_string();
        let public_key = FixedBytes::<32>::from([0x21; 32]);

        validator_config
            .add_validator(
                &owner,
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
                &validator1,
                IValidatorConfig::updateValidatorCall {
                    newValidatorAddress: validator2,
                    publicKey: public_key,
                    inboundAddress: "10.0.0.1:8000".to_string(),
                    outboundAddress: "10.0.0.1:9000".to_string(),
                },
            )
            .expect("Should rotate validator");

        // Verify old slots are cleared by checking storage directly
        let old_slot = slots::validator_base_slot(&validator1);
        let old_inbound_slot = old_slot + slots::VALIDATOR_INBOUND_ADDRESS_OFFSET;

        // Check that first slot is cleared
        let cleared_value = validator_config
            .storage
            .sload(validator_config.precompile_address, old_inbound_slot)
            .unwrap();
        assert_eq!(
            cleared_value,
            U256::ZERO,
            "First slot of old inbound address should be cleared"
        );

        // Check that additional slots are also cleared
        for i in 1..9 {
            let slot_value = validator_config
                .storage
                .sload(
                    validator_config.precompile_address,
                    old_inbound_slot + U256::from(i),
                )
                .unwrap();
            assert_eq!(
                slot_value,
                U256::ZERO,
                "Additional slot {i} of old inbound address should be cleared"
            );
        }
    }

    #[test]
    fn test_update_string_various_lengths() {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::from([0x01; 20]);
        let validator = Address::from([0x11; 20]);

        let mut validator_config = ValidatorConfig::new(PRECOMPILE_ADDRESS, &mut storage);
        validator_config.initialize(owner).unwrap();

        // Start with a long address
        let long_host = "a.".repeat(100);
        let initial_inbound = format!("{long_host}:8000");
        let public_key = FixedBytes::<32>::from([0x21; 32]);

        validator_config
            .add_validator(
                &owner,
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
                &validator,
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
                &validator,
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

        // Verify extra slots are cleared
        let slot = slots::validator_base_slot(&validator);
        let inbound_slot = slot + slots::VALIDATOR_INBOUND_ADDRESS_OFFSET;
        for i in 1..9 {
            let slot_value = validator_config
                .storage
                .sload(
                    validator_config.precompile_address,
                    inbound_slot + U256::from(i),
                )
                .unwrap();
            assert_eq!(slot_value, U256::ZERO, "Extra slot {i} should be cleared");
        }

        // Update to medium-length address
        let medium_host = "b.".repeat(50);
        let medium_inbound = format!("{medium_host}:8000");
        validator_config
            .update_validator(
                &validator,
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
