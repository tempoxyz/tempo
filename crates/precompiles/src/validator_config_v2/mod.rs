pub mod dispatch;

use tempo_contracts::precompiles::VALIDATOR_CONFIG_V2_ADDRESS;
pub use tempo_contracts::precompiles::{IValidatorConfigV2, ValidatorConfigV2Error};
use tempo_precompiles_macros::{Storable, contract};

use crate::{
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping},
    validator_config::ensure_address_is_ip_port,
};
use alloy::primitives::{Address, B256};
use tracing::trace;

#[derive(Debug, Storable)]
struct ValidatorV2 {
    public_key: B256,
    validator_address: Address,
    ingress: String,
    egress: String,
    index: u64,
    added_at_height: u64,
    deactivated_at_height: u64,
}

/// Validator Config V2 precompile.
///
/// Index-canonical storage: the `validators` mapping (keyed by u64 index) is the
/// source of truth. `address_to_index` and `pubkey_to_index` are 1-indexed lookup
/// pointers (0 = not found).
#[contract(addr = VALIDATOR_CONFIG_V2_ADDRESS)]
pub struct ValidatorConfigV2 {
    owner: Address,
    validator_count: u64,
    validators: Mapping<u64, ValidatorV2>,
    address_to_index: Mapping<Address, u64>,
    pubkey_to_index: Mapping<B256, u64>,
    next_dkg_ceremony: u64,
    initialized: bool,
    initialized_at_height: u64,
}

impl ValidatorConfigV2 {
    pub fn initialize(&mut self, owner: Address, block_height: u64) -> Result<()> {
        trace!(address=%self.address, %owner, "Initializing validator config v2 precompile");
        self.__initialize()?;
        self.owner.write(owner)?;
        self.initialized.write(true)?;
        self.initialized_at_height.write(block_height)
    }

    pub fn owner(&self) -> Result<Address> {
        self.owner.read()
    }

    fn check_owner(&self, caller: Address) -> Result<()> {
        if self.owner()? != caller {
            return Err(ValidatorConfigV2Error::unauthorized())?;
        }
        Ok(())
    }

    fn check_owner_or_validator(&self, caller: Address, validator: Address) -> Result<()> {
        if caller != validator && self.owner()? != caller {
            return Err(ValidatorConfigV2Error::unauthorized())?;
        }
        Ok(())
    }

    fn check_initialized(&self) -> Result<()> {
        if !self.initialized.read()? {
            return Err(ValidatorConfigV2Error::not_initialized())?;
        }
        Ok(())
    }

    pub fn is_initialized(&self) -> Result<bool> {
        self.initialized.read()
    }

    pub fn get_initialized_at_height(&self) -> Result<u64> {
        self.initialized_at_height.read()
    }

    pub fn validator_count(&self) -> Result<u64> {
        self.validator_count.read()
    }

    /// Lookup the 1-indexed position for an address. Returns 0 if not found.
    fn address_index(&self, addr: Address) -> Result<u64> {
        self.address_to_index[addr].read()
    }

    fn read_validator_at(&self, index: u64) -> Result<IValidatorConfigV2::Validator> {
        let v = self.validators[index].read()?;
        Ok(IValidatorConfigV2::Validator {
            publicKey: v.public_key,
            validatorAddress: v.validator_address,
            ingress: v.ingress,
            egress: v.egress,
            index: v.index,
            addedAtHeight: v.added_at_height,
            deactivatedAtHeight: v.deactivated_at_height,
        })
    }

    pub fn validator_by_index(&self, index: u64) -> Result<IValidatorConfigV2::Validator> {
        if index >= self.validator_count()? {
            return Err(ValidatorConfigV2Error::validator_not_found())?;
        }
        self.read_validator_at(index)
    }

    pub fn validator_by_address(
        &self,
        addr: Address,
    ) -> Result<IValidatorConfigV2::Validator> {
        let idx1 = self.address_index(addr)?;
        if idx1 == 0 {
            return Err(ValidatorConfigV2Error::validator_not_found())?;
        }
        self.read_validator_at(idx1 - 1)
    }

    pub fn validator_by_public_key(&self, pubkey: B256) -> Result<IValidatorConfigV2::Validator> {
        let idx1 = self.pubkey_to_index[pubkey].read()?;
        if idx1 == 0 {
            return Err(ValidatorConfigV2Error::validator_not_found())?;
        }
        self.read_validator_at(idx1 - 1)
    }

    pub fn get_validators(&self) -> Result<Vec<IValidatorConfigV2::Validator>> {
        let count = self.validator_count()?;
        let mut out = Vec::with_capacity(count as usize);
        for i in 0..count {
            out.push(self.read_validator_at(i)?);
        }
        Ok(out)
    }

    pub fn get_active_validators(&self) -> Result<Vec<IValidatorConfigV2::Validator>> {
        let count = self.validator_count()?;
        let mut out = Vec::new();
        for i in 0..count {
            let v = self.read_validator_at(i)?;
            if v.deactivatedAtHeight == 0 {
                out.push(v);
            }
        }
        Ok(out)
    }

    pub fn get_next_full_dkg_ceremony(&self) -> Result<u64> {
        self.next_dkg_ceremony.read()
    }

    fn validate_ingress(ingress: &str) -> Result<()> {
        ensure_address_is_ip_port(ingress).map_err(|err| {
            TempoPrecompileError::from(ValidatorConfigV2Error::not_ip_port(
                "ingress".to_string(),
                ingress.to_string(),
                format!("{err:?}"),
            ))
        })
    }

    fn validate_egress(egress: &str) -> Result<()> {
        ensure_address_is_ip(egress).map_err(|err| {
            TempoPrecompileError::from(ValidatorConfigV2Error::not_ip_port(
                "egress".to_string(),
                egress.to_string(),
                format!("{err:?}"),
            ))
        })
    }

    /// Append a new validator entry and update lookup indices.
    fn append_validator(
        &mut self,
        addr: Address,
        pubkey: B256,
        ingress: String,
        egress: String,
        block_height: u64,
    ) -> Result<()> {
        let count = self.validator_count()?;
        let v = ValidatorV2 {
            public_key: pubkey,
            validator_address: addr,
            ingress,
            egress,
            index: count,
            added_at_height: block_height,
            deactivated_at_height: 0,
        };
        self.validators[count].write(v)?;
        self.address_to_index[addr].write(count + 1)?;
        self.pubkey_to_index[pubkey].write(count + 1)?;
        self.validator_count.write(count + 1)
    }

    fn validate_add_params(&self, addr: Address, pubkey: B256) -> Result<()> {
        if addr.is_zero() {
            return Err(ValidatorConfigV2Error::invalid_validator_address())?;
        }
        if pubkey.is_zero() {
            return Err(ValidatorConfigV2Error::invalid_public_key())?;
        }
        if self.address_to_index[addr].read()? != 0 {
            return Err(ValidatorConfigV2Error::validator_already_exists())?;
        }
        if self.pubkey_to_index[pubkey].read()? != 0 {
            return Err(ValidatorConfigV2Error::public_key_already_exists())?;
        }
        Ok(())
    }

    fn validate_rotate_params(&self, pubkey: B256) -> Result<()> {
        if pubkey.is_zero() {
            return Err(ValidatorConfigV2Error::invalid_public_key())?;
        }
        if self.pubkey_to_index[pubkey].read()? != 0 {
            return Err(ValidatorConfigV2Error::public_key_already_exists())?;
        }
        Ok(())
    }

    // =========================================================================
    // Owner-only mutating functions
    // =========================================================================

    pub fn add_validator(
        &mut self,
        sender: Address,
        call: IValidatorConfigV2::addValidatorCall,
        block_height: u64,
    ) -> Result<()> {
        self.check_initialized()?;
        self.check_owner(sender)?;
        self.validate_add_params(call.validatorAddress, call.publicKey)?;
        Self::validate_ingress(&call.ingress)?;
        Self::validate_egress(&call.egress)?;
        self.append_validator(
            call.validatorAddress,
            call.publicKey,
            call.ingress,
            call.egress,
            block_height,
        )
    }

    pub fn deactivate_validator(
        &mut self,
        sender: Address,
        call: IValidatorConfigV2::deactivateValidatorCall,
        block_height: u64,
    ) -> Result<()> {
        self.check_initialized()?;
        self.check_owner_or_validator(sender, call.validatorAddress)?;

        let idx1 = self.address_index(call.validatorAddress)?;
        if idx1 == 0 {
            return Err(ValidatorConfigV2Error::validator_not_found())?;
        }

        let mut v = self.validators[idx1 - 1].read()?;
        if v.deactivated_at_height != 0 {
            return Err(ValidatorConfigV2Error::validator_already_deleted())?;
        }
        v.deactivated_at_height = block_height;
        self.validators[idx1 - 1].write(v)
    }

    pub fn transfer_ownership(
        &mut self,
        sender: Address,
        call: IValidatorConfigV2::transferOwnershipCall,
    ) -> Result<()> {
        self.check_owner(sender)?;
        self.owner.write(call.newOwner)
    }

    pub fn set_next_full_dkg_ceremony(
        &mut self,
        sender: Address,
        call: IValidatorConfigV2::setNextFullDkgCeremonyCall,
    ) -> Result<()> {
        self.check_initialized()?;
        self.check_owner(sender)?;
        self.next_dkg_ceremony.write(call.epoch)
    }

    // =========================================================================
    // Dual-auth functions (owner or validator)
    // =========================================================================

    pub fn rotate_validator(
        &mut self,
        sender: Address,
        call: IValidatorConfigV2::rotateValidatorCall,
        block_height: u64,
    ) -> Result<()> {
        self.check_initialized()?;
        self.check_owner_or_validator(sender, call.validatorAddress)?;

        let idx1 = self.address_index(call.validatorAddress)?;
        if idx1 == 0 {
            return Err(ValidatorConfigV2Error::validator_not_found())?;
        }

        let mut old = self.validators[idx1 - 1].read()?;
        if old.deactivated_at_height != 0 {
            return Err(ValidatorConfigV2Error::validator_already_deleted())?;
        }

        self.validate_rotate_params(call.publicKey)?;
        Self::validate_ingress(&call.ingress)?;
        Self::validate_egress(&call.egress)?;

        // Deactivate old entry
        old.deactivated_at_height = block_height;
        self.validators[idx1 - 1].write(old)?;

        // Append new entry with same address
        self.append_validator(
            call.validatorAddress,
            call.publicKey,
            call.ingress,
            call.egress,
            block_height,
        )
    }

    pub fn set_ip_addresses(
        &mut self,
        sender: Address,
        call: IValidatorConfigV2::setIpAddressesCall,
    ) -> Result<()> {
        self.check_initialized()?;
        self.check_owner_or_validator(sender, call.validatorAddress)?;

        let idx1 = self.address_index(call.validatorAddress)?;
        if idx1 == 0 {
            return Err(ValidatorConfigV2Error::validator_not_found())?;
        }

        let mut v = self.validators[idx1 - 1].read()?;
        if v.deactivated_at_height != 0 {
            return Err(ValidatorConfigV2Error::validator_already_deleted())?;
        }

        Self::validate_ingress(&call.ingress)?;
        Self::validate_egress(&call.egress)?;

        v.ingress = call.ingress;
        v.egress = call.egress;
        self.validators[idx1 - 1].write(v)
    }

    pub fn transfer_validator_ownership(
        &mut self,
        sender: Address,
        call: IValidatorConfigV2::transferValidatorOwnershipCall,
    ) -> Result<()> {
        self.check_initialized()?;
        self.check_owner_or_validator(sender, call.currentAddress)?;

        if call.newAddress.is_zero() {
            return Err(ValidatorConfigV2Error::invalid_validator_address())?;
        }

        let idx1 = self.address_index(call.currentAddress)?;
        if idx1 == 0 {
            return Err(ValidatorConfigV2Error::validator_not_found())?;
        }
        if self.address_to_index[call.newAddress].read()? != 0 {
            return Err(ValidatorConfigV2Error::validator_already_exists())?;
        }

        let mut v = self.validators[idx1 - 1].read()?;
        if v.deactivated_at_height != 0 {
            return Err(ValidatorConfigV2Error::validator_already_deleted())?;
        }

        v.validator_address = call.newAddress;
        self.validators[idx1 - 1].write(v)?;
        self.address_to_index[call.newAddress].write(idx1)?;
        self.address_to_index[call.currentAddress].delete()
    }

    // =========================================================================
    // Migration
    // =========================================================================

    pub fn migrate_validator(
        &mut self,
        sender: Address,
        _call: IValidatorConfigV2::migrateValidatorCall,
    ) -> Result<()> {
        self.check_owner(sender)?;
        Ok(())
    }

    pub fn initialize_if_migrated(
        &mut self,
        sender: Address,
        _call: IValidatorConfigV2::initializeIfMigratedCall,
    ) -> Result<()> {
        self.check_owner(sender)?;
        if self.initialized.read()? {
            return Err(ValidatorConfigV2Error::already_initialized())?;
        }
        self.initialized.write(true)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("input was not a valid IP address")]
pub struct IpParseError {
    #[from]
    source: std::net::AddrParseError,
}

pub fn ensure_address_is_ip(input: &str) -> core::result::Result<(), IpParseError> {
    input.parse::<std::net::IpAddr>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};
    use alloy::primitives::Address;
    use alloy_primitives::FixedBytes;

    fn make_add_call(
        addr: Address,
        pubkey: [u8; 32],
        ingress: &str,
        egress: &str,
    ) -> IValidatorConfigV2::addValidatorCall {
        IValidatorConfigV2::addValidatorCall {
            validatorAddress: addr,
            publicKey: FixedBytes::<32>::from(pubkey),
            ingress: ingress.to_string(),
            egress: egress.to_string(),
            signature: vec![0u8; 64].into(),
        }
    }

    #[test]
    fn test_owner_initialization() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner, 100)?;

            assert_eq!(vc.owner()?, owner);
            assert!(vc.is_initialized()?);
            assert_eq!(vc.get_initialized_at_height()?, 100);
            assert_eq!(vc.validator_count()?, 0);

            Ok(())
        })
    }

    #[test]
    fn test_add_validator() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner, 100)?;

            let pubkey = FixedBytes::<32>::from([0x42; 32]);
            vc.add_validator(
                owner,
                make_add_call(validator, [0x42; 32], "192.168.1.1:8000", "192.168.1.1"),
                200,
            )?;

            assert_eq!(vc.validator_count()?, 1);

            let v = vc.validator_by_index(0)?;
            assert_eq!(v.publicKey, pubkey);
            assert_eq!(v.validatorAddress, validator);
            assert_eq!(v.addedAtHeight, 200);
            assert_eq!(v.deactivatedAtHeight, 0);
            assert_eq!(v.index, 0);

            let v2 = vc.validator_by_address(validator)?;
            assert_eq!(v2.publicKey, pubkey);

            let v3 = vc.validator_by_public_key(pubkey)?;
            assert_eq!(v3.validatorAddress, validator);

            Ok(())
        })
    }

    #[test]
    fn test_add_validator_rejects_unauthorized() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let non_owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner, 100)?;

            let result = vc.add_validator(
                non_owner,
                make_add_call(Address::random(), [0x42; 32], "192.168.1.1:8000", "192.168.1.1"),
                200,
            );
            assert_eq!(result, Err(ValidatorConfigV2Error::unauthorized().into()));

            Ok(())
        })
    }

    #[test]
    fn test_add_validator_rejects_zero_pubkey() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner, 100)?;

            let result = vc.add_validator(
                owner,
                make_add_call(Address::random(), [0; 32], "192.168.1.1:8000", "192.168.1.1"),
                200,
            );
            assert_eq!(
                result,
                Err(ValidatorConfigV2Error::invalid_public_key().into())
            );

            Ok(())
        })
    }

    #[test]
    fn test_add_validator_rejects_duplicate_address() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner, 100)?;

            vc.add_validator(
                owner,
                make_add_call(validator, [0x42; 32], "192.168.1.1:8000", "192.168.1.1"),
                200,
            )?;

            let result = vc.add_validator(
                owner,
                make_add_call(validator, [0x43; 32], "192.168.1.2:8000", "192.168.1.2"),
                201,
            );
            assert_eq!(
                result,
                Err(ValidatorConfigV2Error::validator_already_exists().into())
            );

            Ok(())
        })
    }

    #[test]
    fn test_add_validator_rejects_duplicate_pubkey() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner, 100)?;

            vc.add_validator(
                owner,
                make_add_call(Address::random(), [0x42; 32], "192.168.1.1:8000", "192.168.1.1"),
                200,
            )?;

            let result = vc.add_validator(
                owner,
                make_add_call(Address::random(), [0x42; 32], "192.168.1.2:8000", "192.168.1.2"),
                201,
            );
            assert_eq!(
                result,
                Err(ValidatorConfigV2Error::public_key_already_exists().into())
            );

            Ok(())
        })
    }

    #[test]
    fn test_deactivate_validator() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner, 100)?;

            vc.add_validator(
                owner,
                make_add_call(validator, [0x42; 32], "192.168.1.1:8000", "192.168.1.1"),
                200,
            )?;

            vc.deactivate_validator(
                owner,
                IValidatorConfigV2::deactivateValidatorCall {
                    validatorAddress: validator,
                },
                300,
            )?;

            let v = vc.validator_by_index(0)?;
            assert_eq!(v.deactivatedAtHeight, 300);

            // Double deactivation fails
            let result = vc.deactivate_validator(
                owner,
                IValidatorConfigV2::deactivateValidatorCall {
                    validatorAddress: validator,
                },
                301,
            );
            assert_eq!(
                result,
                Err(ValidatorConfigV2Error::validator_already_deleted().into())
            );

            Ok(())
        })
    }

    #[test]
    fn test_deactivate_validator_dual_auth() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let v1 = Address::random();
        let v2 = Address::random();
        let third_party = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner, 100)?;

            vc.add_validator(
                owner,
                make_add_call(v1, [0x11; 32], "192.168.1.1:8000", "192.168.1.1"),
                200,
            )?;
            vc.add_validator(
                owner,
                make_add_call(v2, [0x22; 32], "192.168.1.2:8000", "192.168.1.2"),
                200,
            )?;

            // Third party cannot deactivate
            let result = vc.deactivate_validator(
                third_party,
                IValidatorConfigV2::deactivateValidatorCall {
                    validatorAddress: v1,
                },
                300,
            );
            assert_eq!(result, Err(ValidatorConfigV2Error::unauthorized().into()));

            // Validator can deactivate itself
            vc.deactivate_validator(
                v1,
                IValidatorConfigV2::deactivateValidatorCall {
                    validatorAddress: v1,
                },
                300,
            )?;
            assert_eq!(vc.validator_by_index(0)?.deactivatedAtHeight, 300);

            // Owner can deactivate another validator
            vc.deactivate_validator(
                owner,
                IValidatorConfigV2::deactivateValidatorCall {
                    validatorAddress: v2,
                },
                301,
            )?;
            assert_eq!(vc.validator_by_index(1)?.deactivatedAtHeight, 301);

            Ok(())
        })
    }

    #[test]
    fn test_rotate_validator() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner, 100)?;

            vc.add_validator(
                owner,
                make_add_call(validator, [0x11; 32], "192.168.1.1:8000", "192.168.1.1"),
                200,
            )?;

            let new_pubkey = FixedBytes::<32>::from([0x22; 32]);
            vc.rotate_validator(
                owner,
                IValidatorConfigV2::rotateValidatorCall {
                    validatorAddress: validator,
                    publicKey: new_pubkey,
                    ingress: "10.0.0.1:8000".to_string(),
                    egress: "10.0.0.1".to_string(),
                    signature: vec![0u8; 64].into(),
                },
                300,
            )?;

            // Should now have 2 entries
            assert_eq!(vc.validator_count()?, 2);

            // Old entry deactivated
            let old = vc.validator_by_index(0)?;
            assert_eq!(old.deactivatedAtHeight, 300);
            assert_eq!(old.publicKey, FixedBytes::<32>::from([0x11; 32]));

            // New entry active with same address
            let new = vc.validator_by_index(1)?;
            assert_eq!(new.deactivatedAtHeight, 0);
            assert_eq!(new.publicKey, new_pubkey);
            assert_eq!(new.validatorAddress, validator);
            assert_eq!(new.addedAtHeight, 300);

            // address_to_index now points to the new entry
            let by_addr = vc.validator_by_address(validator)?;
            assert_eq!(by_addr.publicKey, new_pubkey);

            // Old pubkey still resolves to the old entry
            let by_old_pk = vc.validator_by_public_key(FixedBytes::<32>::from([0x11; 32]))?;
            assert_eq!(by_old_pk.deactivatedAtHeight, 300);

            Ok(())
        })
    }

    #[test]
    fn test_get_active_validators() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let v1 = Address::random();
        let v2 = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner, 100)?;

            vc.add_validator(
                owner,
                make_add_call(v1, [0x11; 32], "192.168.1.1:8000", "192.168.1.1"),
                200,
            )?;
            vc.add_validator(
                owner,
                make_add_call(v2, [0x22; 32], "192.168.1.2:8000", "192.168.1.2"),
                201,
            )?;

            assert_eq!(vc.get_active_validators()?.len(), 2);

            vc.deactivate_validator(
                owner,
                IValidatorConfigV2::deactivateValidatorCall {
                    validatorAddress: v1,
                },
                300,
            )?;

            let active = vc.get_active_validators()?;
            assert_eq!(active.len(), 1);
            assert_eq!(active[0].validatorAddress, v2);

            assert_eq!(vc.get_validators()?.len(), 2);

            Ok(())
        })
    }

    #[test]
    fn test_set_ip_addresses() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner, 100)?;

            vc.add_validator(
                owner,
                make_add_call(validator, [0x42; 32], "192.168.1.1:8000", "192.168.1.1"),
                200,
            )?;

            vc.set_ip_addresses(
                owner,
                IValidatorConfigV2::setIpAddressesCall {
                    validatorAddress: validator,
                    ingress: "10.0.0.1:8000".to_string(),
                    egress: "10.0.0.1".to_string(),
                },
            )?;

            let v = vc.validator_by_address(validator)?;
            assert_eq!(v.ingress, "10.0.0.1:8000");
            assert_eq!(v.egress, "10.0.0.1");

            // Validator can update its own
            vc.set_ip_addresses(
                validator,
                IValidatorConfigV2::setIpAddressesCall {
                    validatorAddress: validator,
                    ingress: "10.0.0.2:8000".to_string(),
                    egress: "10.0.0.2".to_string(),
                },
            )?;

            let v = vc.validator_by_address(validator)?;
            assert_eq!(v.ingress, "10.0.0.2:8000");

            Ok(())
        })
    }

    #[test]
    fn test_transfer_ownership() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let new_owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner, 100)?;

            vc.transfer_ownership(
                owner,
                IValidatorConfigV2::transferOwnershipCall {
                    newOwner: new_owner,
                },
            )?;
            assert_eq!(vc.owner()?, new_owner);

            let result = vc.transfer_ownership(
                owner,
                IValidatorConfigV2::transferOwnershipCall {
                    newOwner: Address::random(),
                },
            );
            assert_eq!(result, Err(ValidatorConfigV2Error::unauthorized().into()));

            Ok(())
        })
    }

    #[test]
    fn test_transfer_validator_ownership() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator = Address::random();
        let new_address = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner, 100)?;

            vc.add_validator(
                owner,
                make_add_call(validator, [0x42; 32], "192.168.1.1:8000", "192.168.1.1"),
                200,
            )?;

            vc.transfer_validator_ownership(
                owner,
                IValidatorConfigV2::transferValidatorOwnershipCall {
                    currentAddress: validator,
                    newAddress: new_address,
                },
            )?;

            // Old address lookup gone
            let result = vc.validator_by_address(validator);
            assert_eq!(
                result,
                Err(ValidatorConfigV2Error::validator_not_found().into())
            );

            // New address works
            let v = vc.validator_by_address(new_address)?;
            assert_eq!(v.publicKey, FixedBytes::<32>::from([0x42; 32]));
            assert_eq!(v.validatorAddress, new_address);

            Ok(())
        })
    }

    #[test]
    fn test_transfer_validator_ownership_rejects_deactivated() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner, 100)?;

            vc.add_validator(
                owner,
                make_add_call(validator, [0x42; 32], "192.168.1.1:8000", "192.168.1.1"),
                200,
            )?;

            vc.deactivate_validator(
                owner,
                IValidatorConfigV2::deactivateValidatorCall {
                    validatorAddress: validator,
                },
                300,
            )?;

            let result = vc.transfer_validator_ownership(
                owner,
                IValidatorConfigV2::transferValidatorOwnershipCall {
                    currentAddress: validator,
                    newAddress: Address::random(),
                },
            );
            assert_eq!(
                result,
                Err(ValidatorConfigV2Error::validator_already_deleted().into())
            );

            Ok(())
        })
    }

    #[test]
    fn test_set_next_full_dkg_ceremony() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner, 100)?;

            assert_eq!(vc.get_next_full_dkg_ceremony()?, 0);

            vc.set_next_full_dkg_ceremony(
                owner,
                IValidatorConfigV2::setNextFullDkgCeremonyCall { epoch: 42 },
            )?;
            assert_eq!(vc.get_next_full_dkg_ceremony()?, 42);

            let non_owner = Address::random();
            let result = vc.set_next_full_dkg_ceremony(
                non_owner,
                IValidatorConfigV2::setNextFullDkgCeremonyCall { epoch: 100 },
            );
            assert_eq!(result, Err(ValidatorConfigV2Error::unauthorized().into()));

            Ok(())
        })
    }

    #[test]
    fn test_not_initialized_errors() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.__initialize()?;
            vc.owner.write(owner)?;

            let result = vc.add_validator(
                owner,
                make_add_call(Address::random(), [0x42; 32], "192.168.1.1:8000", "192.168.1.1"),
                200,
            );
            assert_eq!(
                result,
                Err(ValidatorConfigV2Error::not_initialized().into())
            );

            Ok(())
        })
    }

    #[test]
    fn test_egress_validates_ip_without_port() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner, 100)?;

            // IP:port for egress should fail
            let result = vc.add_validator(
                owner,
                make_add_call(
                    Address::random(),
                    [0x42; 32],
                    "192.168.1.1:8000",
                    "192.168.1.1:9000",
                ),
                200,
            );
            assert!(result.is_err(), "egress with port should be rejected");

            // Plain IP for egress should succeed
            let result = vc.add_validator(
                owner,
                make_add_call(
                    Address::random(),
                    [0x42; 32],
                    "192.168.1.1:8000",
                    "192.168.1.1",
                ),
                200,
            );
            assert!(result.is_ok(), "egress with plain IP should succeed");

            Ok(())
        })
    }
}
