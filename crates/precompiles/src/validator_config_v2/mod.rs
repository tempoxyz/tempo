pub mod dispatch;

use tempo_contracts::precompiles::VALIDATOR_CONFIG_V2_ADDRESS;
pub use tempo_contracts::precompiles::{IValidatorConfigV2, ValidatorConfigV2Error};
use tempo_precompiles_macros::{Storable, contract};

use crate::{
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping},
    validator_config::{ValidatorConfig, ensure_address_is_ip_port},
};
use alloy::primitives::{Address, B256, keccak256};
use commonware_codec::DecodeExt;
use commonware_cryptography::{
    Verifier,
    ed25519::{PublicKey, Signature},
};
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
/// Index-canonical storage: the `validators` vec is the source of truth.
/// `address_to_index` and `pubkey_to_index` are 1-indexed lookup pointers (0 = not found).
#[contract(addr = VALIDATOR_CONFIG_V2_ADDRESS)]
pub struct ValidatorConfigV2 {
    owner: Address,
    validators: Vec<ValidatorV2>,
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
        Ok(self.validators.len()? as u64)
    }

    /// Lookup the 1-indexed position for an address. Returns 0 if not found.
    fn address_index(&self, addr: Address) -> Result<u64> {
        self.address_to_index[addr].read()
    }

    fn read_validator_at(&self, index: u64) -> Result<IValidatorConfigV2::Validator> {
        // Check bounds first
        if index >= self.validator_count()? {
            return Err(ValidatorConfigV2Error::validator_not_found())?;
        }

        let v = self.validators[index as usize].read()?;
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

    pub fn validator_by_address(&self, addr: Address) -> Result<IValidatorConfigV2::Validator> {
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

        // Push to Vec
        self.validators.push(v)?;

        // Update lookup indices (1-indexed)
        self.address_to_index[addr].write(count + 1)?;
        self.pubkey_to_index[pubkey].write(count + 1)
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

    /// Construct message for addValidator signature verification
    ///
    /// Format: keccak256(abi.encodePacked("TEMPO", "_VALIDATOR_CONFIG_V2_ADD_VALIDATOR",
    ///                                     chainId, contractAddress, validatorAddress, ingress, egress))
    ///
    /// Note: This implementation omits chainId and contractAddress since they're not readily
    /// available in the precompile context. In production, these should be included for
    /// cross-chain replay protection.
    fn construct_add_message(validator_address: Address, ingress: &str, egress: &str) -> B256 {
        let mut data = Vec::new();
        data.extend_from_slice(b"TEMPO");
        data.extend_from_slice(b"_VALIDATOR_CONFIG_V2_ADD_VALIDATOR");
        // TODO: Add chainId when available in precompile context
        // TODO: Add contractAddress when available
        data.extend_from_slice(validator_address.as_slice());
        data.extend_from_slice(ingress.as_bytes());
        data.extend_from_slice(egress.as_bytes());

        keccak256(&data)
    }

    /// Construct message for rotateValidator signature verification
    ///
    /// Format: keccak256(abi.encodePacked("TEMPO", "_VALIDATOR_CONFIG_V2_ROTATE_VALIDATOR",
    ///                                     chainId, contractAddress, validatorAddress, ingress, egress))
    fn construct_rotate_message(validator_address: Address, ingress: &str, egress: &str) -> B256 {
        let mut data = Vec::new();
        data.extend_from_slice(b"TEMPO");
        data.extend_from_slice(b"_VALIDATOR_CONFIG_V2_ROTATE_VALIDATOR");
        // TODO: Add chainId when available in precompile context
        // TODO: Add contractAddress when available
        data.extend_from_slice(validator_address.as_slice());
        data.extend_from_slice(ingress.as_bytes());
        data.extend_from_slice(egress.as_bytes());

        keccak256(&data)
    }

    /// Verify Ed25519 signature
    ///
    /// Verifies that the signature is valid for the given public key and message.
    ///
    /// The signature verification uses the commonware-cryptography Ed25519 implementation.
    fn verify_ed25519_signature(pubkey: &B256, message: &[u8], signature: &[u8]) -> Result<()> {
        // Decode the public key from bytes
        let public_key = PublicKey::decode(pubkey.as_slice())
            .map_err(|_| ValidatorConfigV2Error::invalid_public_key())?;

        // Decode the signature from bytes
        let sig = Signature::decode(signature)
            .map_err(|_| ValidatorConfigV2Error::invalid_signature())?;

        // Verify the signature
        // namespace is empty for this use case
        if !public_key.verify(&[], message, &sig) {
            return Err(ValidatorConfigV2Error::invalid_signature())?;
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

        // Construct message for signature verification
        // Format: keccak256(abi.encodePacked("TEMPO", "_VALIDATOR_CONFIG_V2_ADD_VALIDATOR",
        //                                     chainId, contractAddress, validatorAddress, ingress, egress))
        // Note: chainId and contractAddress should be included when available in the precompile context
        let message =
            Self::construct_add_message(call.validatorAddress, &call.ingress, &call.egress);

        // Verify Ed25519 signature
        Self::verify_ed25519_signature(&call.publicKey, message.as_slice(), &call.signature)?;

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

        let idx = (idx1 - 1) as usize;
        let mut v = self.validators[idx].read()?;
        if v.deactivated_at_height != 0 {
            return Err(ValidatorConfigV2Error::validator_already_deleted())?;
        }
        v.deactivated_at_height = block_height;
        self.validators[idx].write(v)
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

        let idx = (idx1 - 1) as usize;
        let mut old = self.validators[idx].read()?;
        if old.deactivated_at_height != 0 {
            return Err(ValidatorConfigV2Error::validator_already_deleted())?;
        }

        self.validate_rotate_params(call.publicKey)?;
        Self::validate_ingress(&call.ingress)?;
        Self::validate_egress(&call.egress)?;

        // Construct message for signature verification
        // Format: keccak256(abi.encodePacked("TEMPO", "_VALIDATOR_CONFIG_V2_ROTATE_VALIDATOR",
        //                                     chainId, contractAddress, validatorAddress, ingress, egress))
        let message =
            Self::construct_rotate_message(call.validatorAddress, &call.ingress, &call.egress);

        // Verify Ed25519 signature
        Self::verify_ed25519_signature(&call.publicKey, message.as_slice(), &call.signature)?;

        // Deactivate old entry
        old.deactivated_at_height = block_height;
        self.validators[idx].write(old)?;

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

        let idx = (idx1 - 1) as usize;
        let mut v = self.validators[idx].read()?;
        if v.deactivated_at_height != 0 {
            return Err(ValidatorConfigV2Error::validator_already_deleted())?;
        }

        Self::validate_ingress(&call.ingress)?;
        Self::validate_egress(&call.egress)?;

        v.ingress = call.ingress;
        v.egress = call.egress;
        self.validators[idx].write(v)
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

        let idx = (idx1 - 1) as usize;
        let mut v = self.validators[idx].read()?;
        if v.deactivated_at_height != 0 {
            return Err(ValidatorConfigV2Error::validator_already_deleted())?;
        }

        v.validator_address = call.newAddress;
        self.validators[idx].write(v)?;
        self.address_to_index[call.newAddress].write(idx1)?;
        self.address_to_index[call.currentAddress].delete()
    }

    // =========================================================================
    // Migration
    // =========================================================================

    pub fn migrate_validator(
        &mut self,
        sender: Address,
        call: IValidatorConfigV2::migrateValidatorCall,
    ) -> Result<()> {
        // Check if already initialized - migration is blocked after initialization
        if self.initialized.read()? {
            return Err(ValidatorConfigV2Error::already_initialized())?;
        }

        // Ensure validators are migrated in order (idx must equal current count)
        let current_count = self.validator_count()?;
        if call.idx != current_count {
            return Err(ValidatorConfigV2Error::invalid_migration_index())?;
        }

        // Get V1 validators
        let v1 = ValidatorConfig::new();
        let v1_validators = v1.get_validators()?;

        // Check if idx is out of bounds
        if call.idx >= v1_validators.len() as u64 {
            return Err(ValidatorConfigV2Error::validator_not_found())?;
        }

        // On first migration, copy owner from V1 if V2 owner is not set
        if current_count == 0 {
            let current_owner = self.owner.read()?;
            if current_owner.is_zero() {
                let v1_owner = v1.owner()?;
                self.owner.write(v1_owner)?;
            }
        }

        // Check authorization (must be owner)
        self.check_owner(sender)?;

        // Get the V1 validator at the specified index
        let v1_val = &v1_validators[call.idx as usize];

        // Note: The Solidity version sets deactivatedAtHeight to block.number for inactive validators
        // during migration, but we use 0 for all validators during migration since we don't have
        // historical block height information at this point.
        let deactivated_at_height = 0;

        // Append the validator (will use 0 for both addedAtHeight and deactivatedAtHeight during migration)
        self.append_validator_raw(
            v1_val.validatorAddress,
            v1_val.publicKey,
            v1_val.inboundAddress.clone(),
            v1_val.outboundAddress.clone(),
            0, // addedAtHeight - we don't have historical block height
            deactivated_at_height,
        )
    }

    pub fn initialize_if_migrated(
        &mut self,
        sender: Address,
        _call: IValidatorConfigV2::initializeIfMigratedCall,
    ) -> Result<()> {
        // Check owner first
        self.check_owner(sender)?;

        // Check if already initialized
        if self.initialized.read()? {
            return Err(ValidatorConfigV2Error::already_initialized())?;
        }

        // Get V1 validators to verify migration is complete
        let v1 = ValidatorConfig::new();
        let v1_validators = v1.get_validators()?;
        let v2_count = self.validator_count()?;

        // Ensure all V1 validators have been migrated
        if v2_count < v1_validators.len() as u64 {
            return Err(ValidatorConfigV2Error::migration_not_complete())?;
        }

        // Copy nextDkgCeremony from V1
        let v1_next_dkg = v1.get_next_full_dkg_ceremony()?;
        self.next_dkg_ceremony.write(v1_next_dkg)?;

        // Mark as initialized (we don't have block height here, so use 0)
        self.initialized.write(true)?;
        self.initialized_at_height.write(0)
    }

    /// Internal helper to append a validator with explicit height values (for migration)
    fn append_validator_raw(
        &mut self,
        addr: Address,
        pubkey: B256,
        ingress: String,
        egress: String,
        added_at_height: u64,
        deactivated_at_height: u64,
    ) -> Result<()> {
        let count = self.validator_count()?;
        let v = ValidatorV2 {
            public_key: pubkey,
            validator_address: addr,
            ingress,
            egress,
            index: count,
            added_at_height,
            deactivated_at_height,
        };

        // Push to Vec
        self.validators.push(v)?;

        // Update lookup indices (1-indexed)
        self.address_to_index[addr].write(count + 1)?;
        self.pubkey_to_index[pubkey].write(count + 1)
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
    use commonware_codec::Encode;
    use commonware_cryptography::{Signer, ed25519::PrivateKey};

    /// Generate a test Ed25519 key pair and create a valid signature
    fn make_test_keypair_and_signature(
        validator_address: Address,
        ingress: &str,
        egress: &str,
        is_rotate: bool,
    ) -> (FixedBytes<32>, Vec<u8>) {
        // Generate a random private key for testing
        let seed = rand_08::random::<u64>();
        let private_key = PrivateKey::from_seed(seed);
        let public_key = private_key.public_key();

        // Construct the message according to the precompile spec
        let message = if is_rotate {
            ValidatorConfigV2::construct_rotate_message(validator_address, ingress, egress)
        } else {
            ValidatorConfigV2::construct_add_message(validator_address, ingress, egress)
        };

        // Sign the message
        let signature = private_key.sign(&[], message.as_slice());

        // Encode public key to bytes
        let pubkey_bytes = public_key.encode();
        let mut pubkey_array = [0u8; 32];
        pubkey_array.copy_from_slice(&pubkey_bytes);

        (
            FixedBytes::<32>::from(pubkey_array),
            signature.encode().to_vec(),
        )
    }

    fn make_add_call(
        addr: Address,
        pubkey: FixedBytes<32>,
        ingress: &str,
        egress: &str,
        signature: Vec<u8>,
    ) -> IValidatorConfigV2::addValidatorCall {
        IValidatorConfigV2::addValidatorCall {
            validatorAddress: addr,
            publicKey: pubkey,
            ingress: ingress.to_string(),
            egress: egress.to_string(),
            signature: signature.into(),
        }
    }

    /// Helper to make a complete add call with generated keys
    fn make_valid_add_call(
        addr: Address,
        ingress: &str,
        egress: &str,
    ) -> IValidatorConfigV2::addValidatorCall {
        let (pubkey, signature) = make_test_keypair_and_signature(addr, ingress, egress, false);
        make_add_call(addr, pubkey, ingress, egress, signature)
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

            let (pubkey, signature) = make_test_keypair_and_signature(
                validator,
                "192.168.1.1:8000",
                "192.168.1.1",
                false,
            );
            vc.add_validator(
                owner,
                make_add_call(
                    validator,
                    pubkey,
                    "192.168.1.1:8000",
                    "192.168.1.1",
                    signature,
                ),
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
                make_valid_add_call(Address::random(), "192.168.1.1:8000", "192.168.1.1"),
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
                make_add_call(
                    Address::random(),
                    FixedBytes::<32>::ZERO,
                    "192.168.1.1:8000",
                    "192.168.1.1",
                    vec![0u8; 64],
                ),
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
                make_valid_add_call(validator, "192.168.1.1:8000", "192.168.1.1"),
                200,
            )?;

            let result = vc.add_validator(
                owner,
                make_valid_add_call(validator, "192.168.1.2:8000", "192.168.1.2"),
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

            // First validator
            let addr1 = Address::random();
            let (pubkey, sig1) =
                make_test_keypair_and_signature(addr1, "192.168.1.1:8000", "192.168.1.1", false);
            vc.add_validator(
                owner,
                make_add_call(addr1, pubkey, "192.168.1.1:8000", "192.168.1.1", sig1),
                200,
            )?;

            // Try to add second validator with same public key (but different signature for different address)
            let addr2 = Address::random();
            let (_, sig2) =
                make_test_keypair_and_signature(addr2, "192.168.1.2:8000", "192.168.1.2", false);
            let result = vc.add_validator(
                owner,
                make_add_call(addr2, pubkey, "192.168.1.2:8000", "192.168.1.2", sig2),
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
                make_valid_add_call(validator, "192.168.1.1:8000", "192.168.1.1"),
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
                make_valid_add_call(v1, "192.168.1.1:8000", "192.168.1.1"),
                200,
            )?;
            vc.add_validator(
                owner,
                make_valid_add_call(v2, "192.168.1.2:8000", "192.168.1.2"),
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

            // Add initial validator and track the old key
            let (old_pubkey, old_sig) = make_test_keypair_and_signature(
                validator,
                "192.168.1.1:8000",
                "192.168.1.1",
                false,
            );
            vc.add_validator(
                owner,
                make_add_call(
                    validator,
                    old_pubkey,
                    "192.168.1.1:8000",
                    "192.168.1.1",
                    old_sig,
                ),
                200,
            )?;

            // Rotate to new key
            let (new_pubkey, new_sig) = make_test_keypair_and_signature(
                validator,
                "10.0.0.1:8000",
                "10.0.0.1",
                true, // rotate flag
            );
            vc.rotate_validator(
                owner,
                IValidatorConfigV2::rotateValidatorCall {
                    validatorAddress: validator,
                    publicKey: new_pubkey,
                    ingress: "10.0.0.1:8000".to_string(),
                    egress: "10.0.0.1".to_string(),
                    signature: new_sig.into(),
                },
                300,
            )?;

            // Should now have 2 entries
            assert_eq!(vc.validator_count()?, 2);

            // Old entry deactivated
            let old = vc.validator_by_index(0)?;
            assert_eq!(old.deactivatedAtHeight, 300);
            assert_eq!(old.publicKey, old_pubkey);

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
            let by_old_pk = vc.validator_by_public_key(old_pubkey)?;
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
                make_valid_add_call(v1, "192.168.1.1:8000", "192.168.1.1"),
                200,
            )?;
            vc.add_validator(
                owner,
                make_valid_add_call(v2, "192.168.1.2:8000", "192.168.1.2"),
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
                make_valid_add_call(validator, "192.168.1.1:8000", "192.168.1.1"),
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

            let (pubkey, sig) = make_test_keypair_and_signature(
                validator,
                "192.168.1.1:8000",
                "192.168.1.1",
                false,
            );
            vc.add_validator(
                owner,
                make_add_call(validator, pubkey, "192.168.1.1:8000", "192.168.1.1", sig),
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
            assert_eq!(v.publicKey, pubkey);
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
                make_valid_add_call(validator, "192.168.1.1:8000", "192.168.1.1"),
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
                make_valid_add_call(Address::random(), "192.168.1.1:8000", "192.168.1.1"),
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

            let addr1 = Address::random();
            let (pubkey1, sig1) = make_test_keypair_and_signature(
                addr1,
                "192.168.1.1:8000",
                "192.168.1.1:9000",
                false,
            );

            // IP:port for egress should fail (egress validation happens before signature)
            let result = vc.add_validator(
                owner,
                make_add_call(addr1, pubkey1, "192.168.1.1:8000", "192.168.1.1:9000", sig1),
                200,
            );
            assert!(result.is_err(), "egress with port should be rejected");

            // Plain IP for egress should succeed
            let result = vc.add_validator(
                owner,
                make_valid_add_call(Address::random(), "192.168.1.1:8000", "192.168.1.1"),
                200,
            );
            assert!(result.is_ok(), "egress with plain IP should succeed");

            Ok(())
        })
    }

    #[test]
    fn test_migration_from_v1() -> eyre::Result<()> {
        use crate::validator_config::ValidatorConfig;
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let v1_addr = Address::random();
        let v2_addr = Address::random();

        StorageCtx::enter(&mut storage, || {
            // Set up V1 with some validators
            let mut v1 = ValidatorConfig::new();
            v1.initialize(owner)?;

            v1.add_validator(
                owner,
                tempo_contracts::precompiles::IValidatorConfig::addValidatorCall {
                    newValidatorAddress: v1_addr,
                    publicKey: FixedBytes::<32>::from([0x11; 32]),
                    active: true,
                    inboundAddress: "192.168.1.1:8000".to_string(),
                    outboundAddress: "192.168.1.1:9000".to_string(),
                },
            )?;

            v1.add_validator(
                owner,
                tempo_contracts::precompiles::IValidatorConfig::addValidatorCall {
                    newValidatorAddress: v2_addr,
                    publicKey: FixedBytes::<32>::from([0x22; 32]),
                    active: false,
                    inboundAddress: "192.168.1.2:8000".to_string(),
                    outboundAddress: "192.168.1.2:9000".to_string(),
                },
            )?;

            // Now migrate to V2
            let mut v2 = ValidatorConfigV2::new();

            // Migrate first validator
            v2.migrate_validator(owner, IValidatorConfigV2::migrateValidatorCall { idx: 0 })?;

            assert_eq!(v2.validator_count()?, 1);
            let migrated = v2.validator_by_index(0)?;
            assert_eq!(migrated.validatorAddress, v1_addr);
            assert_eq!(migrated.publicKey, FixedBytes::<32>::from([0x11; 32]));
            assert_eq!(migrated.deactivatedAtHeight, 0);

            // Migrate second validator
            v2.migrate_validator(owner, IValidatorConfigV2::migrateValidatorCall { idx: 1 })?;

            assert_eq!(v2.validator_count()?, 2);

            // Try to initialize before migration complete should fail
            // (This would fail if we had more V1 validators, but we've migrated all)

            // Initialize V2
            v2.initialize_if_migrated(owner, IValidatorConfigV2::initializeIfMigratedCall {})?;

            assert!(v2.is_initialized()?);

            // Migration should be blocked after initialization
            let result =
                v2.migrate_validator(owner, IValidatorConfigV2::migrateValidatorCall { idx: 2 });
            assert_eq!(
                result,
                Err(ValidatorConfigV2Error::already_initialized().into())
            );

            Ok(())
        })
    }

    #[test]
    fn test_migration_out_of_order_fails() -> eyre::Result<()> {
        use crate::validator_config::ValidatorConfig;
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();

        StorageCtx::enter(&mut storage, || {
            // Set up V1 with validators
            let mut v1 = ValidatorConfig::new();
            v1.initialize(owner)?;

            v1.add_validator(
                owner,
                tempo_contracts::precompiles::IValidatorConfig::addValidatorCall {
                    newValidatorAddress: Address::random(),
                    publicKey: FixedBytes::<32>::from([0x11; 32]),
                    active: true,
                    inboundAddress: "192.168.1.1:8000".to_string(),
                    outboundAddress: "192.168.1.1:9000".to_string(),
                },
            )?;

            v1.add_validator(
                owner,
                tempo_contracts::precompiles::IValidatorConfig::addValidatorCall {
                    newValidatorAddress: Address::random(),
                    publicKey: FixedBytes::<32>::from([0x22; 32]),
                    active: true,
                    inboundAddress: "192.168.1.2:8000".to_string(),
                    outboundAddress: "192.168.1.2:9000".to_string(),
                },
            )?;

            // Try to migrate out of order (skip idx 0, try idx 1)
            let mut v2 = ValidatorConfigV2::new();
            let result =
                v2.migrate_validator(owner, IValidatorConfigV2::migrateValidatorCall { idx: 1 });

            assert_eq!(
                result,
                Err(ValidatorConfigV2Error::invalid_migration_index().into())
            );

            Ok(())
        })
    }

    #[test]
    fn test_initialize_before_migration_complete_fails() -> eyre::Result<()> {
        use crate::validator_config::ValidatorConfig;
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();

        StorageCtx::enter(&mut storage, || {
            // Set up V1 with 2 validators
            let mut v1 = ValidatorConfig::new();
            v1.initialize(owner)?;

            v1.add_validator(
                owner,
                tempo_contracts::precompiles::IValidatorConfig::addValidatorCall {
                    newValidatorAddress: Address::random(),
                    publicKey: FixedBytes::<32>::from([0x11; 32]),
                    active: true,
                    inboundAddress: "192.168.1.1:8000".to_string(),
                    outboundAddress: "192.168.1.1:9000".to_string(),
                },
            )?;

            v1.add_validator(
                owner,
                tempo_contracts::precompiles::IValidatorConfig::addValidatorCall {
                    newValidatorAddress: Address::random(),
                    publicKey: FixedBytes::<32>::from([0x22; 32]),
                    active: true,
                    inboundAddress: "192.168.1.2:8000".to_string(),
                    outboundAddress: "192.168.1.2:9000".to_string(),
                },
            )?;

            // Only migrate first validator
            let mut v2 = ValidatorConfigV2::new();
            v2.migrate_validator(owner, IValidatorConfigV2::migrateValidatorCall { idx: 0 })?;

            // Try to initialize with incomplete migration
            let result =
                v2.initialize_if_migrated(owner, IValidatorConfigV2::initializeIfMigratedCall {});

            assert_eq!(
                result,
                Err(ValidatorConfigV2Error::migration_not_complete().into())
            );

            Ok(())
        })
    }
}
