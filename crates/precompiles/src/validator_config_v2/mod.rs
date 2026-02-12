pub mod dispatch;

use tempo_contracts::precompiles::VALIDATOR_CONFIG_V2_ADDRESS;
pub use tempo_contracts::precompiles::{IValidatorConfigV2, ValidatorConfigV2Error};
use tempo_precompiles_macros::{Storable, contract};

use crate::{
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping},
    validator_config::{ValidatorConfig, ensure_address_is_ip, ensure_address_is_ip_port},
};
use alloy::primitives::{Address, B256, keccak256};
use commonware_codec::DecodeExt;
use commonware_cryptography::{
    Verifier,
    ed25519::{PublicKey, Signature},
};
use tracing::trace;

/// Validator operation type for signature verification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValidatorOperation {
    /// Adding a new validator
    Add,
    /// Rotating an existing validator's keys
    Rotate,
}

impl ValidatorOperation {
    /// Get the namespace/domain separator for this operation
    fn namespace(&self) -> &'static [u8] {
        match self {
            Self::Add => b"TEMPO_VALIDATOR_CONFIG_V2_ADD_VALIDATOR",
            Self::Rotate => b"TEMPO_VALIDATOR_CONFIG_V2_ROTATE_VALIDATOR",
        }
    }
}

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

#[derive(Debug, Storable)]
struct Config {
    owner: Address,
    init_at_height: u64,
}

impl Config {
    fn is_initialized(&self) -> bool {
        self.init_at_height != 0
    }

    fn is_owner(&self, addr: Address) -> bool {
        self.owner == addr
    }
}

/// Validator Config V2 precompile.
///
/// Index-canonical storage: the `validators` vec is the source of truth.
/// `address_to_index` and `pubkey_to_index` are 1-indexed lookup pointers (0 = not found).
#[contract(addr = VALIDATOR_CONFIG_V2_ADDRESS)]
pub struct ValidatorConfigV2 {
    config: Config,
    validators: Vec<ValidatorV2>,
    address_to_index: Mapping<Address, u64>,
    pubkey_to_index: Mapping<B256, u64>,
    next_dkg_ceremony: u64,
}

impl ValidatorConfigV2 {
    pub fn initialize(&mut self, owner: Address) -> Result<()> {
        trace!(address=%self.address, %owner, "Initializing validator config v2 precompile");
        self.__initialize()?;
        let config = Config {
            owner,
            init_at_height: self.storage.block_number().max(1),
        };

        self.config.write(config)
    }

    // =========================================================================
    // Config accessors and guards — each reads config once (1 SLOAD)
    // =========================================================================

    pub fn owner(&self) -> Result<Address> {
        self.config.owner.read()
    }

    pub fn get_initialized_at_height(&self) -> Result<u64> {
        self.config.init_at_height.read()
    }

    pub fn is_initialized(&self) -> Result<bool> {
        self.config.read().map(|c| c.is_initialized())
    }

    /// Requires the contract to be initialized. Returns the config.
    fn require_initialized(&self) -> Result<Config> {
        let config = self.config.read()?;
        if !config.is_initialized() {
            return Err(ValidatorConfigV2Error::not_initialized())?;
        }
        Ok(config)
    }

    /// Requires initialized + caller is owner. Returns the config.
    fn require_initialized_owner(&self, caller: Address) -> Result<Config> {
        let config = self.require_initialized()?;
        if !config.is_owner(caller) {
            return Err(ValidatorConfigV2Error::unauthorized())?;
        }
        Ok(config)
    }

    /// Requires initialized + caller is owner or the validator itself. Returns the config.
    fn require_initialized_owner_or_validator(
        &self,
        caller: Address,
        validator: Address,
    ) -> Result<Config> {
        let config = self.require_initialized()?;
        if caller != validator && !config.is_owner(caller) {
            return Err(ValidatorConfigV2Error::unauthorized())?;
        }
        Ok(config)
    }

    pub fn validator_count(&self) -> Result<u64> {
        Ok(self.validators.len()? as u64)
    }

    /// Lookup the 1-indexed position for an address. Returns 0 if not found.
    fn address_index(&self, addr: Address) -> Result<u64> {
        self.address_to_index[addr].read()
    }

    /// Get active validator by address with index.
    ///
    /// Returns the validator's array index and data if found and active.
    /// Returns error if validator not found or already deactivated.
    fn get_active_validator(&self, addr: Address) -> Result<(usize, ValidatorV2)> {
        let idx1 = self.address_index(addr)?;
        if idx1 == 0 {
            return Err(ValidatorConfigV2Error::validator_not_found())?;
        }
        let idx = (idx1 - 1) as usize;
        let v = self.validators[idx].read()?;
        if v.deactivated_at_height != 0 {
            return Err(ValidatorConfigV2Error::validator_already_deleted())?;
        }
        Ok((idx, v))
    }

    fn read_validator_at(&self, index: u64) -> Result<IValidatorConfigV2::Validator> {
        debug_assert!(index < self.validator_count()?, "OOB index");

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

    fn validate_endpoints(ingress: &str, egress: &str) -> Result<()> {
        ensure_address_is_ip_port(ingress).map_err(|err| {
            TempoPrecompileError::from(ValidatorConfigV2Error::not_ip_port(
                ingress.to_string(),
                format!("{err:?}"),
            ))
        })?;

        ensure_address_is_ip(egress).map_err(|err| {
            TempoPrecompileError::from(ValidatorConfigV2Error::not_ip(
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
        self.append_validator_raw(addr, pubkey, ingress, egress, block_height, 0)
    }

    /// Validates that the address is non-zero and not already registered.
    fn require_new_address(&self, addr: Address) -> Result<()> {
        if addr.is_zero() {
            return Err(ValidatorConfigV2Error::invalid_validator_address())?;
        }
        if self.address_to_index[addr].read()? != 0 {
            return Err(ValidatorConfigV2Error::validator_already_exists())?;
        }
        Ok(())
    }

    /// Validates that the public key is non-zero and not already registered.
    fn require_new_pubkey(&self, pubkey: B256) -> Result<()> {
        if pubkey.is_zero() {
            return Err(ValidatorConfigV2Error::invalid_public_key())?;
        }
        if self.pubkey_to_index[pubkey].read()? != 0 {
            return Err(ValidatorConfigV2Error::public_key_already_exists())?;
        }
        Ok(())
    }

    /// Verify validator signature for add or rotate operations
    ///
    /// Constructs the message according to the validator config v2 specification
    /// and verifies the Ed25519 signature using the appropriate namespace.
    ///
    /// **FORMAT**:
    /// - Namespace: `b"TEMPO_VALIDATOR_CONFIG_V2_ADD_VALIDATOR"` or `b"TEMPO_VALIDATOR_CONFIG_V2_ROTATE_VALIDATOR"`
    /// - Message: `keccak256(abi.encodePacked(chainId, contractAddr, validatorAddr, ingress, egress))`
    fn verify_validator_signature(
        &self,
        operation: ValidatorOperation,
        pubkey: &B256,
        signature: &[u8],
        validator_address: Address,
        ingress: &str,
        egress: &str,
    ) -> Result<()> {
        // Get namespace from operation type
        let namespace = operation.namespace();

        // Construct message data WITHOUT "TEMPO" prefix
        let mut data = Vec::new();
        data.extend_from_slice(&self.storage.chain_id().to_be_bytes());
        data.extend_from_slice(VALIDATOR_CONFIG_V2_ADDRESS.as_slice());
        data.extend_from_slice(validator_address.as_slice());
        data.extend_from_slice(ingress.as_bytes());
        data.extend_from_slice(egress.as_bytes());
        let message = keccak256(&data);

        // Decode public key and signature
        let public_key = PublicKey::decode(pubkey.as_slice())
            .map_err(|_| ValidatorConfigV2Error::invalid_public_key())?;
        let sig = Signature::decode(signature)
            .map_err(|_| ValidatorConfigV2Error::invalid_signature_format())?;

        // Verify signature with namespace
        if !public_key.verify(namespace, message.as_slice(), &sig) {
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
    ) -> Result<()> {
        self.require_initialized_owner(sender)?;
        self.require_new_pubkey(call.publicKey)?;
        self.require_new_address(call.validatorAddress)?;
        Self::validate_endpoints(&call.ingress, &call.egress)?;

        // Verify Ed25519 signature
        self.verify_validator_signature(
            ValidatorOperation::Add,
            &call.publicKey,
            &call.signature,
            call.validatorAddress,
            &call.ingress,
            &call.egress,
        )?;

        let block_height = self.storage.block_number();
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
    ) -> Result<()> {
        if sender != call.validatorAddress && !self.config.read()?.is_owner(sender) {
            return Err(ValidatorConfigV2Error::unauthorized())?;
        }
        let block_height = self.storage.block_number();

        let (idx, mut v) = self.get_active_validator(call.validatorAddress)?;
        v.deactivated_at_height = block_height;
        self.validators[idx].write(v)
    }

    pub fn transfer_ownership(
        &mut self,
        sender: Address,
        call: IValidatorConfigV2::transferOwnershipCall,
    ) -> Result<()> {
        let mut config = self.require_initialized_owner(sender)?;
        config.owner = call.newOwner;
        self.config.write(config)
    }

    pub fn set_next_full_dkg_ceremony(
        &mut self,
        sender: Address,
        call: IValidatorConfigV2::setNextFullDkgCeremonyCall,
    ) -> Result<()> {
        self.require_initialized_owner(sender)?;
        self.next_dkg_ceremony.write(call.epoch)
    }

    // =========================================================================
    // Dual-auth functions (owner or validator)
    // =========================================================================

    pub fn rotate_validator(
        &mut self,
        sender: Address,
        call: IValidatorConfigV2::rotateValidatorCall,
    ) -> Result<()> {
        self.require_initialized_owner_or_validator(sender, call.validatorAddress)?;
        self.require_new_pubkey(call.publicKey)?;
        Self::validate_endpoints(&call.ingress, &call.egress)?;

        // Verify Ed25519 signature
        self.verify_validator_signature(
            ValidatorOperation::Rotate,
            &call.publicKey,
            &call.signature,
            call.validatorAddress,
            &call.ingress,
            &call.egress,
        )?;

        let block_height = self.storage.block_number();
        let (idx, mut old) = self.get_active_validator(call.validatorAddress)?;

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
        self.require_initialized_owner_or_validator(sender, call.validatorAddress)?;

        let (idx, mut v) = self.get_active_validator(call.validatorAddress)?;
        Self::validate_endpoints(&call.ingress, &call.egress)?;

        v.ingress = call.ingress;
        v.egress = call.egress;
        self.validators[idx].write(v)
    }

    pub fn transfer_validator_ownership(
        &mut self,
        sender: Address,
        call: IValidatorConfigV2::transferValidatorOwnershipCall,
    ) -> Result<()> {
        self.require_initialized_owner_or_validator(sender, call.currentAddress)?;
        self.require_new_address(call.newAddress)?;

        let (idx, mut v) = self.get_active_validator(call.currentAddress)?;
        let idx1 = (idx + 1) as u64; // Convert back to 1-indexed

        v.validator_address = call.newAddress;
        self.validators[idx].write(v)?;
        self.address_to_index[call.newAddress].write(idx1)?;
        self.address_to_index[call.currentAddress].delete()
    }

    // =========================================================================
    // Migration
    // =========================================================================

    /// Requires the contract to NOT be initialized and the caller to be owner.
    ///
    /// On the very first migration call the V2 owner is still zero, so we copy
    /// it from V1 before checking authorization.  Returns the (possibly updated)
    /// config for reuse.
    fn require_migration_owner(&mut self, caller: Address) -> Result<Config> {
        let mut config = self.config.read()?;
        if config.is_initialized() {
            return Err(ValidatorConfigV2Error::already_initialized())?;
        }

        // On first migration, copy owner from V1 if V2 owner is not set
        if config.owner.is_zero() {
            config.owner = v1().owner()?;
            self.config.write(Config {
                owner: config.owner,
                init_at_height: 0,
            })?;
        }

        if !config.is_owner(caller) {
            return Err(ValidatorConfigV2Error::unauthorized())?;
        }
        Ok(config)
    }

    pub fn migrate_validator(
        &mut self,
        sender: Address,
        call: IValidatorConfigV2::migrateValidatorCall,
    ) -> Result<()> {
        self.require_migration_owner(sender)?;
        let block_height = self.storage.block_number();

        // Ensure validators are migrated in order (idx must equal current count)
        let current_count = self.validator_count()?;
        if call.idx != current_count {
            return Err(ValidatorConfigV2Error::invalid_migration_index())?;
        }

        // Read a single V1 validator by index
        let v1 = v1();
        if call.idx >= v1.validator_count()? {
            return Err(ValidatorConfigV2Error::validator_not_found())?;
        }
        let v1_val = v1.validators(v1.validators_array(call.idx)?)?;

        // Defense-in-depth: reject corrupt V1 data rather than silently overwriting lookups
        self.require_new_address(v1_val.validatorAddress)?;
        self.require_new_pubkey(v1_val.publicKey)?;

        // V1 outboundAddress is ip:port, V2 egress is plain IP — strip the port
        let egress = v1_val
            .outboundAddress
            .parse::<std::net::SocketAddr>()
            .map(|sa| sa.ip().to_string())
            .unwrap_or(v1_val.outboundAddress);

        let deactivated_at_height = if v1_val.active { 0 } else { block_height };

        self.append_validator_raw(
            v1_val.validatorAddress,
            v1_val.publicKey,
            v1_val.inboundAddress,
            egress,
            block_height,
            deactivated_at_height,
        )
    }

    pub fn initialize_if_migrated(&mut self, sender: Address) -> Result<()> {
        let mut config = self.require_migration_owner(sender)?;
        let block_height = self.storage.block_number();
        let v1 = v1();

        // Verify migration is complete (compare counts, not full reads)
        if self.validator_count()? < v1.validator_count()? {
            return Err(ValidatorConfigV2Error::migration_not_complete())?;
        }

        // Copy nextDkgCeremony from V1
        let v1_next_dkg = v1.get_next_full_dkg_ceremony()?;
        self.next_dkg_ceremony.write(v1_next_dkg)?;

        // Mark as initialized
        config.init_at_height = block_height.max(1);
        self.config.write(config)
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

fn v1() -> ValidatorConfig {
    ValidatorConfig::new()
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
        operation: ValidatorOperation,
    ) -> (FixedBytes<32>, Vec<u8>) {
        // Generate a random private key for testing
        let seed = rand_08::random::<u64>();
        let private_key = PrivateKey::from_seed(seed);
        let public_key = private_key.public_key();

        // Get namespace from operation
        let namespace = operation.namespace();

        // Build message WITHOUT "TEMPO" prefix
        let mut data = Vec::new();
        data.extend_from_slice(&1u64.to_be_bytes());
        data.extend_from_slice(VALIDATOR_CONFIG_V2_ADDRESS.as_slice());
        data.extend_from_slice(validator_address.as_slice());
        data.extend_from_slice(ingress.as_bytes());
        data.extend_from_slice(egress.as_bytes());
        let message = keccak256(&data);

        // Sign with namespace
        let signature = private_key.sign(namespace, message.as_slice());

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
        let (pubkey, signature) =
            make_test_keypair_and_signature(addr, ingress, egress, ValidatorOperation::Add);
        make_add_call(addr, pubkey, ingress, egress, signature)
    }

    #[test]
    fn test_owner_initialization() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            assert_eq!(vc.owner()?, owner);
            assert!(vc.is_initialized()?);
            // block_number is 0 in test storage, clamped to 1 as sentinel guard
            assert_eq!(vc.get_initialized_at_height()?, 1);
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
            vc.initialize(owner)?;

            let (pubkey, signature) = make_test_keypair_and_signature(
                validator,
                "192.168.1.1:8000",
                "192.168.1.1",
                ValidatorOperation::Add,
            );
            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_add_call(
                    validator,
                    pubkey,
                    "192.168.1.1:8000",
                    "192.168.1.1",
                    signature,
                ),
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
            vc.initialize(owner)?;

            let result = vc.add_validator(
                non_owner,
                make_valid_add_call(Address::random(), "192.168.1.1:8000", "192.168.1.1"),
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
            vc.initialize(owner)?;

            let result = vc.add_validator(
                owner,
                make_add_call(
                    Address::random(),
                    FixedBytes::<32>::ZERO,
                    "192.168.1.1:8000",
                    "192.168.1.1",
                    vec![0u8; 64],
                ),
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
            vc.initialize(owner)?;

            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_valid_add_call(validator, "192.168.1.1:8000", "192.168.1.1"),
            )?;

            vc.storage.set_block_number(201);
            let result = vc.add_validator(
                owner,
                make_valid_add_call(validator, "192.168.1.2:8000", "192.168.1.2"),
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
            vc.initialize(owner)?;

            // First validator
            let addr1 = Address::random();
            let (pubkey, sig1) = make_test_keypair_and_signature(
                addr1,
                "192.168.1.1:8000",
                "192.168.1.1",
                ValidatorOperation::Add,
            );
            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_add_call(addr1, pubkey, "192.168.1.1:8000", "192.168.1.1", sig1),
            )?;

            // Try to add second validator with same public key (but different signature for different address)
            let addr2 = Address::random();
            let (_, sig2) = make_test_keypair_and_signature(
                addr2,
                "192.168.1.2:8000",
                "192.168.1.2",
                ValidatorOperation::Add,
            );
            vc.storage.set_block_number(201);
            let result = vc.add_validator(
                owner,
                make_add_call(addr2, pubkey, "192.168.1.2:8000", "192.168.1.2", sig2),
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
            vc.initialize(owner)?;

            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_valid_add_call(validator, "192.168.1.1:8000", "192.168.1.1"),
            )?;

            vc.storage.set_block_number(300);
            vc.deactivate_validator(
                owner,
                IValidatorConfigV2::deactivateValidatorCall {
                    validatorAddress: validator,
                },
            )?;

            let v = vc.validator_by_index(0)?;
            assert_eq!(v.deactivatedAtHeight, 300);

            // Double deactivation fails
            vc.storage.set_block_number(301);
            let result = vc.deactivate_validator(
                owner,
                IValidatorConfigV2::deactivateValidatorCall {
                    validatorAddress: validator,
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
    fn test_deactivate_validator_dual_auth() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let v1 = Address::random();
        let v2 = Address::random();
        let third_party = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_valid_add_call(v1, "192.168.1.1:8000", "192.168.1.1"),
            )?;
            vc.add_validator(
                owner,
                make_valid_add_call(v2, "192.168.1.2:8000", "192.168.1.2"),
            )?;

            // Third party cannot deactivate
            vc.storage.set_block_number(300);
            let result = vc.deactivate_validator(
                third_party,
                IValidatorConfigV2::deactivateValidatorCall {
                    validatorAddress: v1,
                },
            );
            assert_eq!(result, Err(ValidatorConfigV2Error::unauthorized().into()));

            // Validator can deactivate itself
            vc.deactivate_validator(
                v1,
                IValidatorConfigV2::deactivateValidatorCall {
                    validatorAddress: v1,
                },
            )?;
            assert_eq!(vc.validator_by_index(0)?.deactivatedAtHeight, 300);

            // Owner can deactivate another validator
            vc.storage.set_block_number(301);
            vc.deactivate_validator(
                owner,
                IValidatorConfigV2::deactivateValidatorCall {
                    validatorAddress: v2,
                },
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
            vc.initialize(owner)?;

            // Add initial validator and track the old key
            let (old_pubkey, old_sig) = make_test_keypair_and_signature(
                validator,
                "192.168.1.1:8000",
                "192.168.1.1",
                ValidatorOperation::Add,
            );
            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_add_call(
                    validator,
                    old_pubkey,
                    "192.168.1.1:8000",
                    "192.168.1.1",
                    old_sig,
                ),
            )?;

            // Rotate to new key
            let (new_pubkey, new_sig) = make_test_keypair_and_signature(
                validator,
                "10.0.0.1:8000",
                "10.0.0.1",
                ValidatorOperation::Rotate,
            );
            vc.storage.set_block_number(300);
            vc.rotate_validator(
                owner,
                IValidatorConfigV2::rotateValidatorCall {
                    validatorAddress: validator,
                    publicKey: new_pubkey,
                    ingress: "10.0.0.1:8000".to_string(),
                    egress: "10.0.0.1".to_string(),
                    signature: new_sig.into(),
                },
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
            vc.initialize(owner)?;

            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_valid_add_call(v1, "192.168.1.1:8000", "192.168.1.1"),
            )?;
            vc.storage.set_block_number(201);
            vc.add_validator(
                owner,
                make_valid_add_call(v2, "192.168.1.2:8000", "192.168.1.2"),
            )?;

            assert_eq!(vc.get_active_validators()?.len(), 2);

            vc.storage.set_block_number(300);
            vc.deactivate_validator(
                owner,
                IValidatorConfigV2::deactivateValidatorCall {
                    validatorAddress: v1,
                },
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
            vc.initialize(owner)?;

            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_valid_add_call(validator, "192.168.1.1:8000", "192.168.1.1"),
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
            vc.initialize(owner)?;

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
            vc.initialize(owner)?;

            let (pubkey, sig) = make_test_keypair_and_signature(
                validator,
                "192.168.1.1:8000",
                "192.168.1.1",
                ValidatorOperation::Add,
            );
            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_add_call(validator, pubkey, "192.168.1.1:8000", "192.168.1.1", sig),
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
            vc.initialize(owner)?;

            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_valid_add_call(validator, "192.168.1.1:8000", "192.168.1.1"),
            )?;

            vc.storage.set_block_number(300);
            vc.deactivate_validator(
                owner,
                IValidatorConfigV2::deactivateValidatorCall {
                    validatorAddress: validator,
                },
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
            vc.initialize(owner)?;

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
            // Write config with owner but init_at_height=0 (not initialized)
            vc.config.write(Config {
                owner,
                init_at_height: 0,
            })?;

            let result = vc.add_validator(
                owner,
                make_valid_add_call(Address::random(), "192.168.1.1:8000", "192.168.1.1"),
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
            vc.initialize(owner)?;

            let addr1 = Address::random();
            let (pubkey1, sig1) = make_test_keypair_and_signature(
                addr1,
                "192.168.1.1:8000",
                "192.168.1.1:9000",
                ValidatorOperation::Add,
            );

            // IP:port for egress should fail (egress validation happens before signature)
            let result = vc.add_validator(
                owner,
                make_add_call(addr1, pubkey1, "192.168.1.1:8000", "192.168.1.1:9000", sig1),
            );
            assert!(result.is_err(), "egress with port should be rejected");

            // Plain IP for egress should succeed
            vc.storage.set_block_number(200);
            let result = vc.add_validator(
                owner,
                make_valid_add_call(Address::random(), "192.168.1.1:8000", "192.168.1.1"),
            );
            assert!(result.is_ok(), "egress with plain IP should succeed");

            Ok(())
        })
    }

    #[test]
    fn test_migration_from_v1() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let v1_addr = Address::random();
        let v2_addr = Address::random();

        StorageCtx::enter(&mut storage, || {
            // Set up V1 with some validators
            let mut v1 = v1();
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
            v2.storage.set_block_number(100);
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
            v2.storage.set_block_number(400);
            v2.initialize_if_migrated(owner)?;

            assert!(v2.is_initialized()?);

            // Migration should be blocked after initialization
            v2.storage.set_block_number(100);
            let result =
                v2.migrate_validator(owner, IValidatorConfigV2::migrateValidatorCall { idx: 2 });
            assert_eq!(
                result,
                Err(ValidatorConfigV2Error::already_initialized().into())
            );

            Ok(())
        })
    }

    /// V1 stores outboundAddress as ip:port, but V2 egress is plain IP.
    /// Migration must strip the port so migrated data satisfies V2 validation.
    #[test]
    fn test_migration_strips_port_from_v1_outbound_address() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let v1_addr = Address::random();

        StorageCtx::enter(&mut storage, || {
            // V1 validator with outboundAddress = ip:port
            let mut v1 = v1();
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

            // Migrate to V2
            let mut v2 = ValidatorConfigV2::new();
            v2.storage.set_block_number(100);
            v2.migrate_validator(owner, IValidatorConfigV2::migrateValidatorCall { idx: 0 })?;
            v2.storage.set_block_number(400);
            v2.initialize_if_migrated(owner)?;

            // Egress should be plain IP (port stripped from V1's "192.168.1.1:9000")
            let migrated = v2.validator_by_index(0)?;
            assert_eq!(
                migrated.egress, "192.168.1.1",
                "migration should strip port from V1 outboundAddress"
            );

            // Ingress preserved as-is (both V1 and V2 use ip:port)
            assert_eq!(migrated.ingress, "192.168.1.1:8000");

            // setIpAddresses should accept the migrated egress value
            v2.set_ip_addresses(
                owner,
                IValidatorConfigV2::setIpAddressesCall {
                    validatorAddress: v1_addr,
                    ingress: "192.168.1.1:8000".to_string(),
                    egress: migrated.egress,
                },
            )?;

            Ok(())
        })
    }

    #[test]
    fn test_migration_out_of_order_fails() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();

        StorageCtx::enter(&mut storage, || {
            // Set up V1 with validators
            let mut v1 = v1();
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
            v2.storage.set_block_number(100);
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
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();

        StorageCtx::enter(&mut storage, || {
            // Set up V1 with 2 validators
            let mut v1 = v1();
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
            v2.storage.set_block_number(100);
            v2.migrate_validator(owner, IValidatorConfigV2::migrateValidatorCall { idx: 0 })?;

            // Try to initialize with incomplete migration
            v2.storage.set_block_number(400);
            let result = v2.initialize_if_migrated(owner);

            assert_eq!(
                result,
                Err(ValidatorConfigV2Error::migration_not_complete().into())
            );

            Ok(())
        })
    }
}
