use alloy::primitives::{Address, B256};
use tempo_precompiles_macros::contract;
use tracing::trace;

pub use crate::abi::{
    IValidatorConfig, IValidatorConfig::prelude::*, VALIDATOR_CONFIG_ADDRESS,
};
use IValidatorConfig::IValidatorConfig as _;
use crate::{
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping},
};

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
            return Err(IValidatorConfig::Error::unauthorized().into());
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

impl IValidatorConfig::IValidatorConfig for ValidatorConfig {
    /// Get the owner address
    fn owner(&self) -> Result<Address> {
        self.owner.read()
    }

    /// Get the current validator count
    fn validator_count(&self) -> Result<u64> {
        self.validators_array.len().map(|c| c as u64)
    }

    /// Get validator address at a specific index in the validators array
    fn validators_array(&self, index: u64) -> Result<Address> {
        match self.validators_array.at(index as usize)? {
            Some(elem) => elem.read(),
            None => Err(TempoPrecompileError::array_oob()),
        }
    }

    /// Get validator information by address
    fn validators(&self, validator: Address) -> Result<Validator> {
        let validator_info = self.validators[validator].read()?;
        Ok(Validator {
            public_key: validator_info.public_key,
            active: validator_info.active,
            index: validator_info.index,
            validator_address: validator_info.validator_address,
            inbound_address: validator_info.inbound_address,
            outbound_address: validator_info.outbound_address,
        })
    }

    fn get_validators(&self) -> Result<Vec<Validator>> {
        let count = self.validators_array.len()?;
        let mut validators = Vec::with_capacity(count);

        for i in 0..count {
            let validator_address = self.validators_array[i].read()?;

            let Validator {
                public_key,
                active,
                index,
                validator_address: _,
                inbound_address,
                outbound_address,
            } = self.validators[validator_address].read()?;

            validators.push(Validator {
                public_key,
                active,
                index,
                validator_address,
                inbound_address,
                outbound_address,
            });
        }

        Ok(validators)
    }

    /// Get the epoch at which a fresh DKG ceremony will be triggered
    fn get_next_full_dkg_ceremony(&self) -> Result<u64> {
        self.next_dkg_ceremony.read()
    }

    fn change_owner(&mut self, msg_sender: Address, new_owner: Address) -> Result<()> {
        self.check_owner(msg_sender)?;
        self.owner.write(new_owner)
    }

    fn add_validator(
        &mut self,
        msg_sender: Address,
        new_validator_address: Address,
        public_key: B256,
        active: bool,
        inbound_address: String,
        outbound_address: String,
    ) -> Result<()> {
        if public_key.is_zero() {
            return Err(IValidatorConfig::Error::invalid_public_key().into());
        }

        self.check_owner(msg_sender)?;

        if self.validator_exists(new_validator_address)? {
            return Err(IValidatorConfig::Error::validator_already_exists().into());
        }

        ensure_address_is_ip_port(&inbound_address).map_err(|err| {
            IValidatorConfig::Error::not_host_port(
                "inboundAddress".to_string(),
                inbound_address.clone(),
                format!("{err:?}"),
            )
        })?;

        ensure_address_is_ip_port(&outbound_address).map_err(|err| {
            IValidatorConfig::Error::not_ip_port(
                "outboundAddress".to_string(),
                outbound_address.clone(),
                format!("{err:?}"),
            )
        })?;

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
        self.validators_array.push(new_validator_address)
    }

    fn update_validator(
        &mut self,
        msg_sender: Address,
        new_validator_address: Address,
        public_key: B256,
        inbound_address: String,
        outbound_address: String,
    ) -> Result<()> {
        if public_key.is_zero() {
            return Err(IValidatorConfig::Error::invalid_public_key().into());
        }

        if !self.validator_exists(msg_sender)? {
            return Err(IValidatorConfig::Error::validator_not_found().into());
        }

        let old_validator = self.validators[msg_sender].read()?;

        if new_validator_address != msg_sender {
            if self.validator_exists(new_validator_address)? {
                return Err(IValidatorConfig::Error::validator_already_exists().into());
            }

            self.validators_array[old_validator.index as usize].write(new_validator_address)?;
            self.validators[msg_sender].delete()?;
        }

        ensure_address_is_ip_port(&inbound_address).map_err(|err| {
            IValidatorConfig::Error::not_host_port(
                "inboundAddress".to_string(),
                inbound_address.clone(),
                format!("{err:?}"),
            )
        })?;

        ensure_address_is_ip_port(&outbound_address).map_err(|err| {
            IValidatorConfig::Error::not_ip_port(
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

    fn change_validator_status(
        &mut self,
        msg_sender: Address,
        validator: Address,
        active: bool,
    ) -> Result<()> {
        self.check_owner(msg_sender)?;

        if !self.validator_exists(validator)? {
            return Err(IValidatorConfig::Error::validator_not_found().into());
        }

        let mut validator_data = self.validators[validator].read()?;
        validator_data.active = active;
        self.validators[validator].write(validator_data)
    }

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

            validator_config.initialize(owner1)?;

            let current_owner = validator_config.owner()?;
            assert_eq!(
                current_owner, owner1,
                "Owner should be owner1 after initialization"
            );

            validator_config.change_owner( owner1, owner2)?;

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

            validator_config.initialize(owner1)?;

            let public_key = FixedBytes::<32>::from([0x44; 32]);
            validator_config.add_validator(
                owner1,
                validator1,
                public_key,
                true,
                "192.168.1.1:8000".to_string(),
                "192.168.1.1:9000".to_string(),
            )?;

            let validators = validator_config.get_validators()?;
            assert_eq!(validators.len(), 1, "Should have 1 validator");
            assert_eq!(validators[0].validator_address, validator1);
            assert_eq!(validators[0].public_key, public_key);
            assert!(validators[0].active, "New validator should be active");

            validator_config.change_validator_status(
                owner1,
                validator1,
                false,
            )?;

            let validators = validator_config.get_validators()?;
            assert!(!validators[0].active, "Validator should be inactive");

            let res = validator_config.add_validator(
                owner2,
                validator2,
                FixedBytes::<32>::from([0x66; 32]),
                true,
                "192.168.1.2:8000".to_string(),
                "192.168.1.2:9000".to_string(),
            );
            assert_eq!(res, Err(IValidatorConfig::Error::unauthorized().into()));

            let res = validator_config.change_validator_status(
                owner2,
                validator1,
                true,
            );
            assert_eq!(res, Err(IValidatorConfig::Error::unauthorized().into()));

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
                Err(IValidatorConfig::Error::validator_already_exists().into()),
                "Should return ValidatorAlreadyExists error"
            );

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

            let mut validators = validator_config.get_validators()?;

            assert_eq!(validators.len(), 5, "Should have 5 validators");

            validators.sort_by_key(|v| v.validator_address);

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

            let validator2_new = Address::from([0x22; 20]);
            validator_config.update_validator(
                validator2,
                validator2_new,
                public_key2,
                "192.168.1.2:8000".to_string(),
                "192.168.1.2:9000".to_string(),
            )?;

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

            let mut validators = validator_config.get_validators()?;

            assert_eq!(validators.len(), 5, "Should still have 5 validators");

            validators.sort_by_key(|v| v.validator_address);

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

            assert_eq!(validators[1].validator_address, validator4);
            assert_eq!(validators[1].public_key, public_key4);
            assert_eq!(validators[1].inbound_address, "192.168.1.4:8000");
            assert!(validators[1].active);

            assert_eq!(validators[2].validator_address, validator5);
            assert_eq!(validators[2].public_key, public_key5);
            assert_eq!(validators[2].inbound_address, "192.168.1.5:8000");
            assert!(validators[2].active);

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

            let public_key = FixedBytes::<32>::from([0x21; 32]);
            validator_config.add_validator(
                owner,
                validator,
                public_key,
                true,
                "192.168.1.1:8000".to_string(),
                "192.168.1.1:9000".to_string(),
            )?;

            let result = validator_config.update_validator(
                owner,
                validator,
                FixedBytes::<32>::from([0x22; 32]),
                "10.0.0.1:8000".to_string(),
                "10.0.0.1:9000".to_string(),
            );

            assert_eq!(
                result,
                Err(IValidatorConfig::Error::validator_not_found().into()),
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

            validator_config.update_validator(
                validator1,
                validator2,
                public_key,
                "10.0.0.1:8000".to_string(),
                "10.0.0.1:9000".to_string(),
            )?;

            let validator = validator_config.validators[validator1].read()?;

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

            assert_eq!(
                validator_config.get_next_full_dkg_ceremony()?,
                0
            );

            validator_config.set_next_full_dkg_ceremony( owner, 42)?;
            assert_eq!(
                validator_config.get_next_full_dkg_ceremony()?,
                42
            );

            let result =
                validator_config.set_next_full_dkg_ceremony( non_owner, 100);
            assert_eq!(result, Err(IValidatorConfig::Error::unauthorized().into()));

            assert_eq!(
                validator_config.get_next_full_dkg_ceremony()?,
                42
            );

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
                Err(IValidatorConfig::Error::invalid_public_key().into()),
                "Should reject zero public key"
            );

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
                Err(IValidatorConfig::Error::invalid_public_key().into()),
                "Should reject zero public key in update"
            );

            let validators = validator_config.get_validators()?;
            assert_eq!(validators.len(), 1, "Should still have 1 validator");
            assert_eq!(
                validators[0].public_key, original_public_key,
                "Original public key should be preserved"
            );

            Ok(())
        })
    }
}
