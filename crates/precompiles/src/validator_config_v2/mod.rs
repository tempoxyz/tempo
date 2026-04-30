//! Validator Config V2 precompile – index-canonical, on-chain, [consensus] validator registry with
//! signature-gated operations, IP uniqueness enforcement, and migration support from V1.
//!
//! [consensus]: <https://docs.tempo.xyz/protocol/blockspace/consensus>

pub mod dispatch;

pub use tempo_contracts::precompiles::{IValidatorConfigV2, ValidatorConfigV2Error};
use tempo_contracts::precompiles::{VALIDATOR_CONFIG_V2_ADDRESS, ValidatorConfigV2Event};
use tempo_precompiles_macros::{Storable, contract};

use crate::{
    error::{Result, TempoPrecompileError},
    ip_validation::{IpWithPortParseError, ensure_address_is_ip, ensure_address_is_ip_port},
    storage::{Handler, Mapping},
    validator_config::ValidatorConfig,
};
use alloy::primitives::{Address, B256, Keccak256};
use commonware_codec::DecodeExt;
use commonware_cryptography::{
    Verifier,
    ed25519::{PublicKey, Signature},
};
use tracing::trace;

/// Signature namespace for `addValidator` operations.
pub const VALIDATOR_NS_ADD: &[u8] = b"TEMPO_VALIDATOR_CONFIG_V2_ADD_VALIDATOR";
/// Signature namespace for `rotateValidator` operations.
pub const VALIDATOR_NS_ROTATE: &[u8] = b"TEMPO_VALIDATOR_CONFIG_V2_ROTATE_VALIDATOR";

/// Distinguishes `addValidator` from `rotateValidator` signatures at the type level.
enum SignatureKind {
    Add { fee_recipient: Address },
    Rotate,
}

/// Contract-level configuration: ownership, initialization state, and migration bookkeeping.
#[derive(Debug, Storable)]
struct Config {
    /// Contract admin address.
    owner: Address,
    /// `true` once the contract is fully initialized (post-migration or direct init).
    is_init: bool,
    /// Block height at which initialization completed.
    init_at_height: u64,
    /// Number of V1 validators skipped during migration (bad pubkey, duplicate, etc).
    /// Packed alongside `is_init` and `init_at_height` since all are migration lifecycle state.
    migration_skipped_count: u8,
    /// Snapshotted V1 validator count, captured on the first `migrateValidator` call.
    /// Used for index validation so V1 mutations cannot break migration ordering.
    v1_validator_count: u8,
}

impl Config {
    fn new(owner: Address, is_init: bool, init_at_height: u64) -> Self {
        Self {
            owner,
            is_init,
            init_at_height,
            migration_skipped_count: 0,
            v1_validator_count: 0,
        }
    }

    fn is_owner(&self, addr: Address) -> bool {
        self.owner == addr
    }

    fn require_init(self) -> Result<Self> {
        if self.is_init {
            return Ok(self);
        }
        Err(ValidatorConfigV2Error::not_initialized())?
    }

    fn require_not_init(self) -> Result<Self> {
        if self.is_init {
            Err(ValidatorConfigV2Error::already_initialized())?
        }
        Ok(self)
    }

    fn require_owner(self, caller: Address) -> Result<Self> {
        if !self.is_owner(caller) {
            Err(ValidatorConfigV2Error::unauthorized())?
        }
        Ok(self)
    }

    fn require_owner_or_validator(self, caller: Address, validator: Address) -> Result<Self> {
        if caller != validator && !self.is_owner(caller) {
            Err(ValidatorConfigV2Error::unauthorized())?
        }
        Ok(self)
    }
}

/// A single entry in the `validators` vector.
///
/// ## Lifecycle
///
/// A record is created in one of three ways:
/// - `add_validator`: active entry (`deactivated_at_height = 0`, `active_idx != 0`)
/// - `migrate_validator`: active or born-deactivated, depending on V1 state
/// - `rotate_validator`: appends a born-deactivated snapshot of the old identity
///   and overwrites the original slot in-place with the new identity
///
/// A record is deactivated via `deactivate_validator`, which sets
/// `deactivated_at_height` to the current block height and clears `active_idx` to 0.
/// This transition is one-way — a deactivated record never becomes active again.
#[derive(Debug, Storable)]
struct ValidatorRecord {
    /// Ed25519 communication public key (unique across all records, reserved forever).
    public_key: B256,
    /// Ethereum-style address of the validator (unique among active validators).
    validator_address: Address,
    /// Inbound address for peer connections (`<ip>:<port>`).
    ingress: String,
    /// Outbound IP for firewall whitelisting (`<ip>`).
    egress: String,
    /// Address that receives execution-layer fees for this validator.
    fee_recipient: Address,
    /// Position in the `validators` array. Stable across rotations for the in-place slot;
    /// snapshots get the tail position at the time they were appended.
    index: u64,
    /// 1-indexed position in `active_indices` (0 = not active).
    /// Used as a backpointer for O(1) swap-and-pop removal on deactivation.
    active_idx: u64,
    /// Block height at which this record was created (or overwritten during rotation).
    added_at_height: u64,
    /// Block height at which this record was deactivated (0 = still active).
    deactivated_at_height: u64,
}

/// Validator Config V2 precompile — manages consensus validators with append-only,
/// delete-once semantics.
///
/// Replaces V1's mutable state with immutable height-based tracking (`addedAtHeight`,
/// `deactivatedAtHeight`) to enable historical validator set reconstruction without
/// requiring historical state access.
///
/// ## Storage design
///
/// The `validators` vec is the source of truth (append-only). Two auxiliary mappings
/// provide O(1) lookups:
/// - `address_to_index`: validator address -> 1-indexed position (0 = not found)
/// - `pubkey_to_index`: public key -> 1-indexed position (0 = not found)
///
/// A separate `active_indices` vec stores 1-indexed global positions of active validators,
/// enabling O(active_count) enumeration without scanning deactivated entries. Each validator
/// stores an `active_idx` backpointer into this vec for O(1) swap-and-pop removal.
///
/// The struct fields define the on-chain storage layout; the `#[contract]` macro generates the
/// storage handlers which provide an ergonomic way to interact with the EVM state.
#[contract(addr = VALIDATOR_CONFIG_V2_ADDRESS)]
pub struct ValidatorConfigV2 {
    /// Contract-level config: ownership, initialization state, and migration bookkeeping.
    config: Config,
    /// Append-only array of all validators ever registered (including deactivated snapshots).
    validators: Vec<ValidatorRecord>,
    /// Validator address → 1-indexed position in `validators` (0 = not found).
    /// After deactivation the mapping still points to the old (now-deactivated) entry.
    /// Overwritten when the address is reused by a new validator, or when ownership is transferred.
    address_to_index: Mapping<Address, u64>,
    /// Ed25519 public key -> 1-indexed position in `validators` (0 = not found).
    /// Public keys are reserved forever — even deactivated entries keep their mapping.
    pubkey_to_index: Mapping<B256, u64>,
    /// Epoch at which a DKG ceremony will run that rotates the network identity.
    next_network_identity_rotation_epoch: u64,
    /// Prevents two active validators from sharing the same ingress IP address.
    active_ingress_ips: Mapping<B256, bool>,
    /// Compact list of 1-indexed global positions of currently active validators.
    /// Order is NOT stable (swap-and-pop on deactivation).
    active_indices: Vec<u64>,
}

impl ValidatorConfigV2 {
    /// Initializes the validator config V2 precompile.
    ///
    /// The contract is fully operational immediately: `is_init` is set to `true` and all mutating
    /// functions (`add_validator`, `rotate_validator`, etc.) are unlocked.
    ///
    /// For V1 migration, the contract is NOT initialized — instead `migrate_validator` manually
    /// copies validators and `initialize_if_migrated` flips `is_init` once all have been migrated.
    pub fn initialize(&mut self, owner: Address) -> Result<()> {
        trace!(address=%self.address, %owner, "Initializing validator config v2 precompile");
        self.__initialize()?;

        let config = Config::new(owner, true, self.storage.block_number());

        self.config.write(config)
    }

    // =========================================================================
    // Config accessors and guards — each reads config once (1 SLOAD)
    // =========================================================================

    /// Returns the current owner of the contract.
    pub fn owner(&self) -> Result<Address> {
        self.config.owner.read()
    }

    /// Returns the block height at which the contract was initialized.
    ///
    /// Only meaningful when [`is_initialized`](Self::is_initialized) returns `true`.
    pub fn get_initialized_at_height(&self) -> Result<u64> {
        self.config.init_at_height.read()
    }

    /// Returns whether V2 has been initialized (either directly or via migration).
    ///
    /// When `false`, the CL reads from V1 and mutating operations (except
    /// `deactivate_validator` and migration functions) are blocked.
    pub fn is_initialized(&self) -> Result<bool> {
        self.config.is_init.read()
    }

    /// Returns the total number of validators ever added, including deactivated
    /// entries and rotation snapshots.
    pub fn validator_count(&self) -> Result<u64> {
        Ok(self.validators.len()? as u64)
    }

    /// Returns the validator at the given global index, or errors if the index
    /// is out of bounds or the validator has been deactivated.
    fn get_active_validator(&self, idx: u64) -> Result<ValidatorRecord> {
        if idx >= self.validators.len()? as u64 {
            Err(ValidatorConfigV2Error::validator_not_found())?
        }
        let v = self.validators[idx as usize].read()?;
        if v.deactivated_at_height != 0 {
            Err(ValidatorConfigV2Error::validator_already_deactivated())?
        }
        Ok(v)
    }

    fn read_validator_at(&self, index: u64) -> Result<IValidatorConfigV2::Validator> {
        debug_assert!(index < self.validator_count()?, "OOB index");

        let v = self.validators[index as usize].read()?;
        Ok(IValidatorConfigV2::Validator {
            publicKey: v.public_key,
            validatorAddress: v.validator_address,
            ingress: v.ingress,
            egress: v.egress,
            feeRecipient: v.fee_recipient,
            index: v.index,
            addedAtHeight: v.added_at_height,
            deactivatedAtHeight: v.deactivated_at_height,
        })
    }

    /// Returns the validator registry at the given global index in the `validators` array.
    ///
    /// # Errors
    /// - `ValidatorNotFound` — `index` is out of bounds
    pub fn validator_by_index(&self, index: u64) -> Result<IValidatorConfigV2::Validator> {
        if index >= self.validator_count()? {
            Err(ValidatorConfigV2Error::validator_not_found())?
        }
        self.read_validator_at(index)
    }

    /// Looks up a validator registry by its address.
    ///
    /// Returns the current entry for the address (after any rotations or transfers).
    ///
    /// # Errors
    /// - `ValidatorNotFound` — the address has never been registered
    pub fn validator_by_address(&self, addr: Address) -> Result<IValidatorConfigV2::Validator> {
        let idx1 = self.address_to_index[addr].read()?;
        if idx1 == 0 {
            Err(ValidatorConfigV2Error::validator_not_found())?
        }
        self.read_validator_at(idx1 - 1)
    }

    /// Looks up a validator by its Ed25519 public key.
    ///
    /// For rotated validators, the old public key resolves to the deactivated snapshot, while the
    /// new key resolves to the in-place active entry.
    ///
    /// # Errors
    /// - `ValidatorNotFound` — the public key has never been registered
    pub fn validator_by_public_key(&self, pubkey: B256) -> Result<IValidatorConfigV2::Validator> {
        let idx1 = self.pubkey_to_index[pubkey].read()?;
        if idx1 == 0 {
            Err(ValidatorConfigV2Error::validator_not_found())?
        }
        self.read_validator_at(idx1 - 1)
    }

    /// Returns only active validators (where `deactivatedAtHeight == 0`).
    ///
    /// NOTE: the order of returned validator records is NOT stable and should NOT be relied upon.
    pub fn get_active_validators(&self) -> Result<Vec<IValidatorConfigV2::Validator>> {
        let count = self.active_indices.len()?;
        let mut out = Vec::new();
        for i in 0..count {
            let global_idx1 = self.active_indices[i].read()?;
            out.push(self.read_validator_at(global_idx1 - 1)?);
        }
        Ok(out)
    }

    /// Returns the epoch at which a network identity rotation will be triggered.
    ///
    /// See [`set_network_identity_rotation_epoch`](Self::set_network_identity_rotation_epoch).
    pub fn get_next_network_identity_rotation_epoch(&self) -> Result<u64> {
        self.next_network_identity_rotation_epoch.read()
    }

    fn validate_endpoints(ingress: &str, egress: &str) -> Result<()> {
        ensure_address_is_ip_port(ingress).map_err(|err| {
            TempoPrecompileError::from(ValidatorConfigV2Error::not_ip_port(
                ingress.to_string(),
                err.to_string(),
            ))
        })?;

        ensure_address_is_ip(egress).map_err(|err| {
            TempoPrecompileError::from(ValidatorConfigV2Error::not_ip(
                egress.to_string(),
                err.to_string(),
            ))
        })
    }

    /// Parses `ingress` as an `<ip>:<port>` pair and returns the hash of the
    /// ingress' binary representation.
    ///
    /// For V4 addresses, that's `keccak256(octets(ip) || big_endian(port))`.
    ///
    /// For V6 addresses, that's `keccak256(octets(ip) || big_endian(scope_id) || big_endian(port))`.
    fn ingress_key(ingress: &str) -> Result<B256> {
        let ingress = ingress
            .parse::<std::net::SocketAddr>()
            .map_err(IpWithPortParseError::from)
            .map_err(|err| {
                TempoPrecompileError::from(ValidatorConfigV2Error::not_ip_port(
                    ingress.to_string(),
                    err.to_string(),
                ))
            })?;
        let mut hasher = Keccak256::new();
        match ingress {
            std::net::SocketAddr::V4(v4) => {
                hasher.update(v4.ip().octets());
                hasher.update(v4.port().to_be_bytes());
            }
            std::net::SocketAddr::V6(v6) => {
                hasher.update(v6.ip().octets());
                hasher.update(v6.scope_id().to_be_bytes());
                hasher.update(v6.port().to_be_bytes());
            }
        }
        Ok(hasher.finalize())
    }

    fn require_unique_ingress(&self, ingress: &str) -> Result<B256> {
        let ingress_hash = Self::ingress_key(ingress)?;
        if self.active_ingress_ips[ingress_hash].read()? {
            Err(ValidatorConfigV2Error::ingress_already_exists(
                ingress.to_string(),
            ))?
        }
        Ok(ingress_hash)
    }

    fn update_ingress_ip_tracking(&mut self, old_ingress: &str, new_ingress: &str) -> Result<()> {
        let old_ingress_hash = Self::ingress_key(old_ingress)?;
        let new_ingress_hash = Self::ingress_key(new_ingress)?;

        if old_ingress_hash != new_ingress_hash {
            if self.active_ingress_ips[new_ingress_hash].read()? {
                Err(ValidatorConfigV2Error::ingress_already_exists(
                    new_ingress.to_string(),
                ))?
            }
            self.active_ingress_ips[old_ingress_hash].delete()?;
            self.active_ingress_ips[new_ingress_hash].write(true)?;
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn append_validator(
        &mut self,
        addr: Address,
        pubkey: B256,
        ingress: String,
        egress: String,
        fee_recipient: Address,
        added_at_height: u64,
        deactivated_at_height: u64,
    ) -> Result<u64> {
        let count = self.validator_count()?;
        let mut active_idx = 0u64;

        if deactivated_at_height == 0 {
            self.active_indices.push(count + 1)?; // 1-indexed
            active_idx = self.active_indices.len()? as u64; // 1-indexed
        }

        let v = ValidatorRecord {
            public_key: pubkey,
            validator_address: addr,
            ingress,
            egress,
            fee_recipient,
            index: count,
            active_idx,
            added_at_height,
            deactivated_at_height,
        };

        self.validators.push(v)?;

        self.pubkey_to_index[pubkey].write(count + 1)?;
        // for any dups the prev entries must be deactivated since we check above
        self.address_to_index[addr].write(count + 1)?;

        Ok(count)
    }

    /// Allows reusing addresses of deactivated validators.
    fn require_new_address(&self, addr: Address) -> Result<()> {
        if addr.is_zero() {
            Err(ValidatorConfigV2Error::invalid_validator_address())?
        }
        let idx1 = self.address_to_index[addr].read()?;
        if idx1 != 0
            && self.validators[(idx1 - 1) as usize]
                .deactivated_at_height
                .read()?
                == 0
        {
            Err(ValidatorConfigV2Error::address_already_has_validator())?
        }
        Ok(())
    }

    fn require_new_pubkey(&self, pubkey: B256) -> Result<()> {
        if pubkey.is_zero() {
            Err(ValidatorConfigV2Error::invalid_public_key())?
        }
        if self.pubkey_to_index[pubkey].read()? != 0 {
            Err(ValidatorConfigV2Error::public_key_already_exists())?
        }
        Ok(())
    }

    /// Verifies a validator signature for add or rotate operations.
    ///
    /// Constructs the message according to the validator config v2 specification and verifies
    /// the Ed25519 signature using the appropriate namespace.
    fn verify_validator_signature(
        &self,
        kind: SignatureKind,
        pubkey: &B256,
        signature: &[u8],
        validator_address: Address,
        ingress: &str,
        egress: &str,
    ) -> Result<()> {
        let sig = Signature::decode(signature)
            .map_err(|_| ValidatorConfigV2Error::invalid_signature_format())?;

        let mut hasher = Keccak256::new();
        hasher.update(self.storage.chain_id().to_be_bytes());
        hasher.update(VALIDATOR_CONFIG_V2_ADDRESS.as_slice());
        hasher.update(validator_address.as_slice());
        hasher.update([
            u8::try_from(ingress.len()).expect("validator ingress length must fit in uint8")
        ]);
        hasher.update(ingress.as_bytes());
        hasher.update([
            u8::try_from(egress.len()).expect("validator egress length must fit in uint8")
        ]);
        hasher.update(egress.as_bytes());

        let namespace = match kind {
            SignatureKind::Add { fee_recipient } => {
                hasher.update(fee_recipient.as_slice());
                VALIDATOR_NS_ADD
            }
            SignatureKind::Rotate => VALIDATOR_NS_ROTATE,
        };
        let message = hasher.finalize();

        let public_key = PublicKey::decode(pubkey.as_slice())
            .map_err(|_| ValidatorConfigV2Error::invalid_public_key())?;
        if !public_key.verify(namespace, message.as_slice(), &sig) {
            Err(ValidatorConfigV2Error::invalid_signature())?
        }

        Ok(())
    }

    // =========================================================================
    // Owner-only mutating functions
    // =========================================================================

    /// Adds a new validator to the set (owner only).
    ///
    /// Requires a valid Ed25519 signature, using the [`VALIDATOR_NS_ADD`] namespace, over
    /// `keccak256(chainId || contractAddr || validatorAddr || len(ingress) || ingress || len(egress) || egress || feeRecipient)`
    /// which proves that the caller controls the private key corresponding to `publicKey`.
    ///
    /// # Errors
    /// - `NotInitialized` — the contract has not been initialized
    /// - `Unauthorized` — `sender` is not the owner
    /// - `InvalidPublicKey` — `publicKey` is zero or not a valid Ed25519 key
    /// - `PublicKeyAlreadyExists` — the public key is already registered
    /// - `InvalidValidatorAddress` — `validatorAddress` is zero
    /// - `AddressAlreadyHasValidator` — the address belongs to an active validator
    /// - `NotIpPort` / `NotIp` — endpoints fail validation
    /// - `IngressAlreadyExists` — the new ingress is already in use
    /// - `InvalidSignature` — signature verification fails
    pub fn add_validator(
        &mut self,
        sender: Address,
        call: IValidatorConfigV2::addValidatorCall,
    ) -> Result<u64> {
        self.config.read()?.require_init()?.require_owner(sender)?;
        self.require_new_pubkey(call.publicKey)?;
        self.require_new_address(call.validatorAddress)?;
        Self::validate_endpoints(&call.ingress, &call.egress)?;
        let ingress_hash = self.require_unique_ingress(&call.ingress)?;

        self.verify_validator_signature(
            SignatureKind::Add {
                fee_recipient: call.feeRecipient,
            },
            &call.publicKey,
            &call.signature,
            call.validatorAddress,
            &call.ingress,
            &call.egress,
        )?;

        let block_height = self.storage.block_number();

        self.active_ingress_ips[ingress_hash].write(true)?;

        let index = self.append_validator(
            call.validatorAddress,
            call.publicKey,
            call.ingress.clone(),
            call.egress.clone(),
            call.feeRecipient,
            block_height,
            0,
        )?;

        self.emit_event(ValidatorConfigV2Event::ValidatorAdded(
            IValidatorConfigV2::ValidatorAdded {
                index,
                validatorAddress: call.validatorAddress,
                publicKey: call.publicKey,
                ingress: call.ingress,
                egress: call.egress,
                feeRecipient: call.feeRecipient,
            },
        ))?;

        Ok(index)
    }

    /// Deactivates a validator by setting its `deactivatedAtHeight` to the current
    /// block height (owner or the validator itself).
    ///
    /// The validator's entry remains in storage for historical queries and its
    /// public key stays reserved forever. The ingress IP is freed for reuse.
    ///
    /// Does NOT require initialization — can be called during the migration window.
    ///
    /// Uses swap-and-pop on `active_indices` for O(1) removal.
    ///
    /// # Errors
    /// - `ValidatorNotFound` — `idx` is out of bounds
    /// - `ValidatorAlreadyDeleted` — the validator is already deactivated
    /// - `Unauthorized` — `sender` is neither the owner nor the validator
    pub fn deactivate_validator(
        &mut self,
        sender: Address,
        call: IValidatorConfigV2::deactivateValidatorCall,
    ) -> Result<()> {
        let v = self.get_active_validator(call.idx)?;
        self.config
            .read()?
            .require_owner_or_validator(sender, v.validator_address)?;

        self.active_ingress_ips[Self::ingress_key(&v.ingress)?].delete()?;

        let block_height = self.storage.block_number();
        self.validators[call.idx as usize]
            .deactivated_at_height
            .write(block_height)?;

        // Swap-and-pop for active_indices
        let active_index = (v.active_idx - 1) as usize;
        let last_pos = self.active_indices.len()? - 1;

        if active_index != last_pos {
            let moved_val = self.active_indices[last_pos].read()?;
            self.active_indices[active_index].write(moved_val)?;
            self.validators[(moved_val - 1) as usize]
                .active_idx
                .write((active_index + 1) as u64)?;
        }
        self.active_indices.pop()?;
        self.validators[call.idx as usize].active_idx.write(0)?;

        self.emit_event(ValidatorConfigV2Event::ValidatorDeactivated(
            IValidatorConfigV2::ValidatorDeactivated {
                index: call.idx,
                validatorAddress: v.validator_address,
            },
        ))
    }

    /// Transfers ownership of the contract to a new address (owner only).
    ///
    /// # Errors
    /// - `InvalidOwner` — `newOwner` is `address(0)`
    /// - `Unauthorized` — `sender` is not the owner
    /// - `NotInitialized` — the contract has not been initialized
    pub fn transfer_ownership(
        &mut self,
        sender: Address,
        call: IValidatorConfigV2::transferOwnershipCall,
    ) -> Result<()> {
        if call.newOwner.is_zero() {
            Err(ValidatorConfigV2Error::invalid_owner())?
        }
        let mut config = self.config.read()?.require_init()?.require_owner(sender)?;
        let old_owner = config.owner;
        config.owner = call.newOwner;
        self.config.write(config)?;

        self.emit_event(ValidatorConfigV2Event::OwnershipTransferred(
            IValidatorConfigV2::OwnershipTransferred {
                oldOwner: old_owner,
                newOwner: call.newOwner,
            },
        ))
    }

    /// Sets the epoch at which a rotation of the network identity will be triggered.
    ///
    /// If `E` is ahead of the network's current epoch, the network will perform a
    /// Distribute-Key-Generation (DKG) ceremony to rotate its identity at the new epoch `E`.
    /// - If the DKG ceremony is successful, then epoch `E+1` will run with a new network identity.
    /// - If `E` is not ahead of the network epoch this value is ignored.
    pub fn set_network_identity_rotation_epoch(
        &mut self,
        sender: Address,
        call: IValidatorConfigV2::setNetworkIdentityRotationEpochCall,
    ) -> Result<()> {
        self.config.read()?.require_init()?.require_owner(sender)?;
        let previous_epoch = self.next_network_identity_rotation_epoch.read()?;
        self.next_network_identity_rotation_epoch
            .write(call.epoch)?;
        self.emit_event(ValidatorConfigV2Event::NetworkIdentityRotationEpochSet(
            IValidatorConfigV2::NetworkIdentityRotationEpochSet {
                previousEpoch: previous_epoch,
                nextEpoch: call.epoch,
            },
        ))
    }

    // =========================================================================
    // Dual-auth functions (owner or validator)
    // =========================================================================

    /// Rotates a validator to a new identity (owner or the validator itself).
    ///
    /// Atomically:
    /// 1. Appends a deactivated snapshot of the old identity to the tail of `validators`
    /// 2. Overwrites the slot in-place with new pubkey, endpoints, and `addedAtHeight = now`
    ///
    /// The validator's global index, `active_idx`, `address_to_index` pointer, and
    /// position in `active_indices` are all preserved — only `pubkey_to_index` is
    /// updated (old key -> snapshot, new key -> original slot).
    ///
    /// Requires a valid Ed25519 signature, using the [`VALIDATOR_NS_ROTATE`] namespace, over
    /// `keccak256(chainId || contractAddr || validatorAddr || len(ingress) || ingress || len(egress) || egress)`
    /// which proves that the caller controls the private key corresponding to `publicKey`.
    ///
    /// # Errors
    /// - `ValidatorNotFound` / `ValidatorAlreadyDeleted` — `idx` is invalid
    /// - `NotInitialized` / `Unauthorized` — auth failure
    /// - `InvalidPublicKey` / `PublicKeyAlreadyExists` — the new key is invalid
    /// - `NotIpPort` / `NotIp` / `IngressAlreadyExists` — endpoint validation failure
    /// - `InvalidSignature` — signature verification fails
    pub fn rotate_validator(
        &mut self,
        sender: Address,
        call: IValidatorConfigV2::rotateValidatorCall,
    ) -> Result<()> {
        let v = self.get_active_validator(call.idx)?;
        self.config
            .read()?
            .require_init()?
            .require_owner_or_validator(sender, v.validator_address)?;
        self.require_new_pubkey(call.publicKey)?;
        Self::validate_endpoints(&call.ingress, &call.egress)?;

        self.require_unique_ingress(&call.ingress)?;
        self.verify_validator_signature(
            SignatureKind::Rotate,
            &call.publicKey,
            &call.signature,
            v.validator_address,
            &call.ingress,
            &call.egress,
        )?;

        let block_height = self.storage.block_number();

        self.update_ingress_ip_tracking(&v.ingress, &call.ingress)?;

        // Append deactivated snapshot of the old validator
        let appended_idx = self.validators.len()? as u64;
        let snapshot = ValidatorRecord {
            public_key: v.public_key,
            validator_address: v.validator_address,
            ingress: v.ingress,
            egress: v.egress,
            fee_recipient: v.fee_recipient,
            index: appended_idx,
            active_idx: 0,
            added_at_height: v.added_at_height,
            deactivated_at_height: block_height,
        };
        self.validators.push(snapshot)?;

        // Update pubkey_to_index: old pubkey → appended_idx + 1
        self.pubkey_to_index[v.public_key].write(appended_idx + 1)?;

        // Modify in-place at the original index
        let mut updated = self.validators[call.idx as usize].read()?;
        updated.public_key = call.publicKey;
        updated.ingress = call.ingress.clone();
        updated.egress = call.egress.clone();
        updated.added_at_height = block_height;
        self.validators[call.idx as usize].write(updated)?;

        // Set pubkey_to_index for new pubkey
        self.pubkey_to_index[call.publicKey].write(call.idx + 1)?;

        self.emit_event(ValidatorConfigV2Event::ValidatorRotated(
            IValidatorConfigV2::ValidatorRotated {
                index: call.idx,
                deactivatedIndex: appended_idx,
                validatorAddress: v.validator_address,
                oldPublicKey: v.public_key,
                newPublicKey: call.publicKey,
                ingress: call.ingress,
                egress: call.egress,
                caller: sender,
            },
        ))
    }

    /// Updates the fee recipient address for a validator (owner or the validator itself).
    ///
    /// # Errors
    /// - `NotInitialized` — the contract has not been initialized
    /// - `ValidatorNotFound` / `ValidatorAlreadyDeleted` — `idx` is invalid
    /// - `Unauthorized` — `sender` is neither the owner nor the validator
    pub fn set_fee_recipient(
        &mut self,
        sender: Address,
        call: IValidatorConfigV2::setFeeRecipientCall,
    ) -> Result<()> {
        let mut v = self.get_active_validator(call.idx)?;
        self.config
            .read()?
            .require_init()?
            .require_owner_or_validator(sender, v.validator_address)?;

        v.fee_recipient = call.feeRecipient;
        self.validators[call.idx as usize].write(v)?;

        self.emit_event(ValidatorConfigV2Event::FeeRecipientUpdated(
            IValidatorConfigV2::FeeRecipientUpdated {
                index: call.idx,
                feeRecipient: call.feeRecipient,
                caller: sender,
            },
        ))
    }

    /// Updates a validator's ingress and egress addresses (owner or the validator itself).
    ///
    /// # Errors
    /// - `NotInitialized` — the contract has not been initialized
    /// - `ValidatorNotFound` / `ValidatorAlreadyDeleted` — `idx` is invalid
    /// - `Unauthorized` — `sender` is neither the owner nor the validator
    /// - `NotIpPort` / `NotIp` — the new endpoints fail validation
    /// - `IngressAlreadyExists` — the new ingress is already in use.
    pub fn set_ip_addresses(
        &mut self,
        sender: Address,
        call: IValidatorConfigV2::setIpAddressesCall,
    ) -> Result<()> {
        let mut v = self.get_active_validator(call.idx)?;
        self.config
            .read()?
            .require_init()?
            .require_owner_or_validator(sender, v.validator_address)?;

        Self::validate_endpoints(&call.ingress, &call.egress)?;

        self.update_ingress_ip_tracking(&v.ingress, &call.ingress)?;

        v.ingress = call.ingress.clone();
        v.egress = call.egress.clone();
        self.validators[call.idx as usize].write(v)?;

        self.emit_event(ValidatorConfigV2Event::IpAddressesUpdated(
            IValidatorConfigV2::IpAddressesUpdated {
                index: call.idx,
                ingress: call.ingress,
                egress: call.egress,
                caller: sender,
            },
        ))
    }

    /// Transfers a validator entry to a new address (owner or the validator itself).
    ///
    /// Updates the validator's address in the lookup maps: deletes the old `address_to_index`
    /// entry and creates a new one pointing to the same slot.
    ///
    /// # Errors
    /// - `ValidatorNotFound` / `ValidatorAlreadyDeleted` — `idx` is invalid
    /// - `NotInitialized` / `Unauthorized` — auth failure
    /// - `InvalidValidatorAddress` — `newAddress` is zero
    /// - `AddressAlreadyHasValidator` — `newAddress` belongs to an active validator
    pub fn transfer_validator_ownership(
        &mut self,
        sender: Address,
        call: IValidatorConfigV2::transferValidatorOwnershipCall,
    ) -> Result<()> {
        let mut v = self.get_active_validator(call.idx)?;
        self.config
            .read()?
            .require_init()?
            .require_owner_or_validator(sender, v.validator_address)?;
        self.require_new_address(call.newAddress)?;

        let old_address = v.validator_address;
        v.validator_address = call.newAddress;
        self.validators[call.idx as usize].write(v)?;

        self.address_to_index[old_address].delete()?;
        self.address_to_index[call.newAddress].write(call.idx + 1)?;

        self.emit_event(ValidatorConfigV2Event::ValidatorOwnershipTransferred(
            IValidatorConfigV2::ValidatorOwnershipTransferred {
                index: call.idx,
                oldAddress: old_address,
                newAddress: call.newAddress,
                caller: sender,
            },
        ))
    }

    // =========================================================================
    // Migration
    // =========================================================================

    /// On the very first migration call the V2 owner is still zero, so we copy it from V1
    /// before checking authorization. Returns the (potentially updated) config for reuse.
    ///
    /// # Errors
    /// - `AlreadyInitialized` — V2 is already initialized
    /// - `Unauthorized` — `caller` is not the owner (after copying from V1 if needed)
    fn require_migration_owner(&mut self, caller: Address) -> Result<Config> {
        let mut config = self.config.read()?.require_not_init()?;

        if config.owner.is_zero() {
            let v1 = v1();
            config.owner = v1.owner()?;
            let v1_count = v1.validator_count()?;
            if v1_count == 0 {
                Err(ValidatorConfigV2Error::empty_v1_validator_set())?
            }
            config.v1_validator_count = v1_count as u8;
            self.config.write(Config {
                owner: config.owner,
                is_init: false,
                init_at_height: 0,
                migration_skipped_count: 0,
                v1_validator_count: config.v1_validator_count,
            })?;
        }

        config.require_owner(caller)
    }

    /// Migrates a single validator from V1 to V2 (owner only).
    ///
    /// Must be called once per V1 validator, in reverse index order.
    /// On the first call, copies the owner from V1 if V2's owner is `address(0)`.
    ///
    /// Validators are skipped (not reverted) when:
    /// - The public key is not a valid Ed25519 key
    /// - The egress address cannot be parsed as a `SocketAddr`
    /// - The public key or ingress IP is a duplicate of an already-migrated entry
    ///
    /// Active V1 validators get `deactivatedAtHeight = 0`; inactive ones get
    /// `deactivatedAtHeight = block.number`.
    ///
    /// # Errors
    /// - `Unauthorized` — `sender` is not the owner
    /// - `AlreadyInitialized` — V2 is already initialized
    /// - `InvalidMigrationIndex` — `idx` is out of order
    pub fn migrate_validator(
        &mut self,
        sender: Address,
        call: IValidatorConfigV2::migrateValidatorCall,
    ) -> Result<()> {
        let config = self.require_migration_owner(sender)?;
        let block_height = self.storage.block_number();

        let v1 = v1();
        let v1_count = u64::from(config.v1_validator_count);
        let migrated = self.validator_count()?;
        let skipped = config.migration_skipped_count;

        let total_processed = migrated + u64::from(skipped);
        if total_processed >= v1_count || call.idx != v1_count - total_processed - 1 {
            Err(ValidatorConfigV2Error::invalid_migration_index())?
        }

        let v1_val = v1.validators(v1.validators_array(call.idx)?)?;

        // Closure to skipping a validator when one of the checks fails
        let skip = |s: &mut Self| {
            s.emit_event(ValidatorConfigV2Event::SkippedValidatorMigration(
                IValidatorConfigV2::SkippedValidatorMigration {
                    index: call.idx,
                    validatorAddress: v1_val.validatorAddress,
                    publicKey: v1_val.publicKey,
                },
            ))?;
            s.config
                .migration_skipped_count
                .write(skipped.saturating_add(1))
        };

        // Skip if public key decoding fails
        if PublicKey::decode(v1_val.publicKey.as_slice()).is_err() {
            return skip(self);
        }

        // Skip if egress decoding fails
        let egress = match v1_val.outboundAddress.parse::<std::net::SocketAddr>() {
            Ok(sa) => sa.ip().to_string(),
            Err(_) => return skip(self),
        };

        // Skip if public key is a duplicate of an existing entry
        if self.pubkey_to_index[v1_val.publicKey].read()? != 0 {
            return skip(self);
        }

        // Skip if address is a duplicate of an existing entry
        let addr_idx = self.address_to_index[v1_val.validatorAddress].read()?;
        if addr_idx != 0
            && self.validators[(addr_idx - 1) as usize]
                .deactivated_at_height
                .read()?
                == 0
        {
            Err(ValidatorConfigV2Error::address_already_has_validator())?
        }

        let now_active = v1_val.active;
        let ingress_hash = Self::ingress_key(&v1_val.inboundAddress)?;

        // Skip if ingress ip hash is a duplicate of an existing entry
        if now_active && self.active_ingress_ips[ingress_hash].read()? {
            return skip(self);
        }

        let migrated_idx = self.append_validator(
            v1_val.validatorAddress,
            v1_val.publicKey,
            v1_val.inboundAddress,
            egress,
            Address::ZERO,
            block_height,
            if now_active { 0 } else { block_height },
        )?;

        if now_active {
            self.active_ingress_ips[ingress_hash].write(true)?;
        }

        self.emit_event(ValidatorConfigV2Event::ValidatorMigrated(
            IValidatorConfigV2::ValidatorMigrated {
                index: migrated_idx,
                validatorAddress: v1_val.validatorAddress,
                publicKey: v1_val.publicKey,
            },
        ))
    }

    /// Finalizes V1 -> V2 migration by setting `is_init = true`.
    ///
    /// Should only be called after all V1 validators have been migrated via
    /// [`migrate_validator`](Self::migrate_validator). Copies `nextDkgCeremony`
    /// from V1. After this call, the CL reads from V2 instead of V1 and all
    /// mutating functions are unlocked.
    ///
    /// # Errors
    /// - `Unauthorized` — `sender` is not the owner
    /// - `AlreadyInitialized` — V2 is already initialized
    /// - `MigrationNotComplete` — `validator_count + skipped < v1.validator_count`
    pub fn initialize_if_migrated(&mut self, sender: Address) -> Result<()> {
        let mut config = self.require_migration_owner(sender)?;

        // NOTE: this count comparison is sufficient because `add_validator` and
        // `rotate_validator` are blocked until the contract is initialized.
        if config.v1_validator_count == 0
            || self.validator_count()? + u64::from(config.migration_skipped_count)
                < u64::from(config.v1_validator_count)
        {
            Err(ValidatorConfigV2Error::migration_not_complete())?
        }

        let v1 = v1();
        let v1_next_dkg = v1.get_next_full_dkg_ceremony()?;
        self.next_network_identity_rotation_epoch
            .write(v1_next_dkg)?;

        trace!(address=%self.address, "Initializing validator config v2 precompile after migration");

        // Initialize the precompile config
        let height = self.storage.block_number();
        config.init_at_height = height;
        config.is_init = true;
        self.config.write(config)?;

        self.emit_event(ValidatorConfigV2Event::Initialized(
            IValidatorConfigV2::Initialized { height },
        ))
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
        kind: SignatureKind,
    ) -> (FixedBytes<32>, Vec<u8>) {
        // Generate a random private key for testing
        let seed = rand_08::random::<u64>();
        let private_key = PrivateKey::from_seed(seed);
        let public_key = private_key.public_key();

        let mut hasher = Keccak256::new();
        hasher.update(1u64.to_be_bytes());
        hasher.update(VALIDATOR_CONFIG_V2_ADDRESS.as_slice());
        hasher.update(validator_address.as_slice());
        hasher.update([
            u8::try_from(ingress.len()).expect("validator ingress length must fit in uint8")
        ]);
        hasher.update(ingress.as_bytes());
        hasher.update([
            u8::try_from(egress.len()).expect("validator egress length must fit in uint8")
        ]);
        hasher.update(egress.as_bytes());
        let namespace = match kind {
            SignatureKind::Add { fee_recipient } => {
                hasher.update(fee_recipient.as_slice());
                VALIDATOR_NS_ADD
            }
            SignatureKind::Rotate => VALIDATOR_NS_ROTATE,
        };
        let message = hasher.finalize();

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
        fee_recipient: Address,
        signature: Vec<u8>,
    ) -> IValidatorConfigV2::addValidatorCall {
        IValidatorConfigV2::addValidatorCall {
            validatorAddress: addr,
            publicKey: pubkey,
            ingress: ingress.to_string(),
            egress: egress.to_string(),
            feeRecipient: fee_recipient,
            signature: signature.into(),
        }
    }

    /// Helper to make a complete add call with generated keys
    fn make_valid_add_call(
        addr: Address,
        ingress: &str,
        egress: &str,
        fee_recipient: Address,
    ) -> IValidatorConfigV2::addValidatorCall {
        let (pubkey, signature) = make_test_keypair_and_signature(
            addr,
            ingress,
            egress,
            SignatureKind::Add { fee_recipient },
        );
        make_add_call(addr, pubkey, ingress, egress, fee_recipient, signature)
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
            assert_eq!(vc.get_initialized_at_height()?, 0);
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
                SignatureKind::Add {
                    fee_recipient: validator,
                },
            );
            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_add_call(
                    validator,
                    pubkey,
                    "192.168.1.1:8000",
                    "192.168.1.1",
                    validator,
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
                make_valid_add_call(
                    Address::random(),
                    "192.168.1.1:8000",
                    "192.168.1.1",
                    Address::random(),
                ),
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
                    Address::random(),
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
                make_valid_add_call(validator, "192.168.1.1:8000", "192.168.1.1", validator),
            )?;

            vc.storage.set_block_number(201);
            let result = vc.add_validator(
                owner,
                make_valid_add_call(validator, "192.168.1.2:8000", "192.168.1.2", validator),
            );
            assert_eq!(
                result,
                Err(ValidatorConfigV2Error::address_already_has_validator().into())
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
                SignatureKind::Add {
                    fee_recipient: addr1,
                },
            );
            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_add_call(
                    addr1,
                    pubkey,
                    "192.168.1.1:8000",
                    "192.168.1.1",
                    addr1,
                    sig1,
                ),
            )?;

            // Try to add second validator with same public key (but different signature for different address)
            let addr2 = Address::random();
            let (_, sig2) = make_test_keypair_and_signature(
                addr2,
                "192.168.1.2:8000",
                "192.168.1.2",
                SignatureKind::Add {
                    fee_recipient: addr2,
                },
            );
            vc.storage.set_block_number(201);
            let result = vc.add_validator(
                owner,
                make_add_call(
                    addr2,
                    pubkey,
                    "192.168.1.2:8000",
                    "192.168.1.2",
                    addr2,
                    sig2,
                ),
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
                make_valid_add_call(validator, "192.168.1.1:8000", "192.168.1.1", validator),
            )?;

            vc.storage.set_block_number(300);
            vc.deactivate_validator(
                owner,
                IValidatorConfigV2::deactivateValidatorCall { idx: 0 },
            )?;

            let v = vc.validator_by_index(0)?;
            assert_eq!(v.deactivatedAtHeight, 300);

            // Double deactivation fails
            vc.storage.set_block_number(301);
            let result = vc.deactivate_validator(
                owner,
                IValidatorConfigV2::deactivateValidatorCall { idx: 0 },
            );
            assert_eq!(
                result,
                Err(ValidatorConfigV2Error::validator_already_deactivated().into())
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
                make_valid_add_call(v1, "192.168.1.1:8000", "192.168.1.1", v1),
            )?;
            vc.add_validator(
                owner,
                make_valid_add_call(v2, "192.168.1.2:8000", "192.168.1.2", v2),
            )?;

            // Third party cannot deactivate
            vc.storage.set_block_number(300);
            let result = vc.deactivate_validator(
                third_party,
                IValidatorConfigV2::deactivateValidatorCall { idx: 0 },
            );
            assert_eq!(result, Err(ValidatorConfigV2Error::unauthorized().into()));

            // Validator can deactivate itself
            vc.deactivate_validator(v1, IValidatorConfigV2::deactivateValidatorCall { idx: 0 })?;
            assert_eq!(vc.validator_by_index(0)?.deactivatedAtHeight, 300);

            // Owner can deactivate another validator
            vc.storage.set_block_number(301);
            vc.deactivate_validator(
                owner,
                IValidatorConfigV2::deactivateValidatorCall { idx: 1 },
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
                SignatureKind::Add {
                    fee_recipient: validator,
                },
            );
            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_add_call(
                    validator,
                    old_pubkey,
                    "192.168.1.1:8000",
                    "192.168.1.1",
                    validator,
                    old_sig,
                ),
            )?;

            // Rotate to new key
            let (new_pubkey, new_sig) = make_test_keypair_and_signature(
                validator,
                "10.0.0.1:8000",
                "10.0.0.1",
                SignatureKind::Rotate,
            );
            vc.storage.set_block_number(300);
            vc.rotate_validator(
                owner,
                IValidatorConfigV2::rotateValidatorCall {
                    idx: 0,
                    publicKey: new_pubkey,
                    ingress: "10.0.0.1:8000".to_string(),
                    egress: "10.0.0.1".to_string(),
                    signature: new_sig.into(),
                },
            )?;

            // Should now have 2 entries
            assert_eq!(vc.validator_count()?, 2);

            // Original slot updated in-place with new key
            let updated = vc.validator_by_index(0)?;
            assert_eq!(updated.deactivatedAtHeight, 0);
            assert_eq!(updated.publicKey, new_pubkey);
            assert_eq!(updated.validatorAddress, validator);
            assert_eq!(updated.addedAtHeight, 300);

            // Appended snapshot of old validator deactivated
            let snapshot = vc.validator_by_index(1)?;
            assert_eq!(snapshot.deactivatedAtHeight, 300);
            assert_eq!(snapshot.publicKey, old_pubkey);

            // address_to_index still points to the original slot
            let by_addr = vc.validator_by_address(validator)?;
            assert_eq!(by_addr.publicKey, new_pubkey);

            // Old pubkey resolves to the appended snapshot
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
                make_valid_add_call(v1, "192.168.1.1:8000", "192.168.1.1", v1),
            )?;
            vc.storage.set_block_number(201);
            vc.add_validator(
                owner,
                make_valid_add_call(v2, "192.168.1.2:8000", "192.168.1.2", v2),
            )?;

            assert_eq!(vc.get_active_validators()?.len(), 2);

            vc.storage.set_block_number(300);
            vc.deactivate_validator(
                owner,
                IValidatorConfigV2::deactivateValidatorCall { idx: 0 },
            )?;

            let active = vc.get_active_validators()?;
            assert_eq!(active.len(), 1);
            assert_eq!(active[0].validatorAddress, v2);

            assert_eq!(vc.validator_count()?, 2);

            Ok(())
        })
    }

    #[test]
    fn test_set_fee_recipient() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_valid_add_call(validator, "192.168.1.1:8000", "192.168.1.1", validator),
            )?;

            let fee_recipient_1 = Address::random();
            vc.set_fee_recipient(
                owner,
                IValidatorConfigV2::setFeeRecipientCall {
                    idx: 0,
                    feeRecipient: fee_recipient_1,
                },
            )?;

            let v = vc.validator_by_address(validator)?;
            assert_eq!(v.feeRecipient, fee_recipient_1);

            // Validator can update its own
            let fee_recipient_2 = Address::random();
            vc.set_fee_recipient(
                validator,
                IValidatorConfigV2::setFeeRecipientCall {
                    idx: 0,
                    feeRecipient: fee_recipient_2,
                },
            )?;

            let v = vc.validator_by_address(validator)?;
            assert_eq!(v.feeRecipient, fee_recipient_2);

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
                make_valid_add_call(validator, "192.168.1.1:8000", "192.168.1.1", validator),
            )?;

            vc.set_ip_addresses(
                owner,
                IValidatorConfigV2::setIpAddressesCall {
                    idx: 0,
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
                    idx: 0,
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
        let non_owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();

            // Rejects pre-init
            let result = vc.transfer_ownership(
                owner,
                IValidatorConfigV2::transferOwnershipCall {
                    newOwner: new_owner,
                },
            );
            assert_eq!(
                result,
                Err(ValidatorConfigV2Error::not_initialized().into())
            );

            vc.initialize(owner)?;

            // Rejects zero address
            let result = vc.transfer_ownership(
                owner,
                IValidatorConfigV2::transferOwnershipCall {
                    newOwner: Address::ZERO,
                },
            );
            assert_eq!(result, Err(ValidatorConfigV2Error::invalid_owner().into()));
            assert_eq!(vc.owner()?, owner);

            // Rejects non-owner
            let result = vc.transfer_ownership(
                non_owner,
                IValidatorConfigV2::transferOwnershipCall {
                    newOwner: new_owner,
                },
            );
            assert_eq!(result, Err(ValidatorConfigV2Error::unauthorized().into()));

            // Succeeds for owner
            vc.transfer_ownership(
                owner,
                IValidatorConfigV2::transferOwnershipCall {
                    newOwner: new_owner,
                },
            )?;
            assert_eq!(vc.owner()?, new_owner);

            // Old owner can no longer transfer
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
                SignatureKind::Add {
                    fee_recipient: validator,
                },
            );
            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_add_call(
                    validator,
                    pubkey,
                    "192.168.1.1:8000",
                    "192.168.1.1",
                    validator,
                    sig,
                ),
            )?;

            vc.transfer_validator_ownership(
                owner,
                IValidatorConfigV2::transferValidatorOwnershipCall {
                    idx: 0,
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
                make_valid_add_call(validator, "192.168.1.1:8000", "192.168.1.1", validator),
            )?;

            vc.storage.set_block_number(300);
            vc.deactivate_validator(
                owner,
                IValidatorConfigV2::deactivateValidatorCall { idx: 0 },
            )?;

            let result = vc.transfer_validator_ownership(
                owner,
                IValidatorConfigV2::transferValidatorOwnershipCall {
                    idx: 0,
                    newAddress: Address::random(),
                },
            );
            assert_eq!(
                result,
                Err(ValidatorConfigV2Error::validator_already_deactivated().into())
            );

            Ok(())
        })
    }

    #[test]
    fn test_set_network_identity_rotation_epoch() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            assert_eq!(vc.get_next_network_identity_rotation_epoch()?, 0);

            vc.set_network_identity_rotation_epoch(
                owner,
                IValidatorConfigV2::setNetworkIdentityRotationEpochCall { epoch: 42 },
            )?;
            assert_eq!(vc.get_next_network_identity_rotation_epoch()?, 42);

            let non_owner = Address::random();
            let result = vc.set_network_identity_rotation_epoch(
                non_owner,
                IValidatorConfigV2::setNetworkIdentityRotationEpochCall { epoch: 100 },
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

            let result = vc.add_validator(
                owner,
                make_valid_add_call(
                    Address::random(),
                    "192.168.1.1:8000",
                    "192.168.1.1",
                    Address::random(),
                ),
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
                SignatureKind::Add {
                    fee_recipient: addr1,
                },
            );

            // IP:port for egress should fail (egress validation happens before signature)
            let result = vc.add_validator(
                owner,
                make_add_call(
                    addr1,
                    pubkey1,
                    "192.168.1.1:8000",
                    "192.168.1.1:9000",
                    addr1,
                    sig1,
                ),
            );
            assert!(result.is_err(), "egress with port should be rejected");

            // Plain IP for egress should succeed
            vc.storage.set_block_number(200);
            let result = vc.add_validator(
                owner,
                make_valid_add_call(
                    Address::random(),
                    "192.168.1.1:8000",
                    "192.168.1.1",
                    Address::random(),
                ),
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

            // Now migrate to V2 (not initialized — migration mode)
            let mut v2 = ValidatorConfigV2::new();

            // Migrate second validator first (reverse order)
            v2.storage.set_block_number(100);
            v2.migrate_validator(owner, IValidatorConfigV2::migrateValidatorCall { idx: 1 })?;

            assert_eq!(v2.validator_count()?, 1);
            let migrated = v2.validator_by_index(0)?;
            assert_eq!(migrated.validatorAddress, v2_addr);
            assert_eq!(migrated.publicKey, FixedBytes::<32>::from([0x22; 32]));
            assert_eq!(migrated.deactivatedAtHeight, 100);

            // Migrate first validator
            v2.migrate_validator(owner, IValidatorConfigV2::migrateValidatorCall { idx: 0 })?;

            assert_eq!(v2.validator_count()?, 2);

            // Initialize V2
            v2.storage.set_block_number(400);
            v2.initialize_if_migrated(owner)?;

            assert!(v2.is_initialized()?);

            // Migration should be blocked after initialization
            v2.storage.set_block_number(100);
            let result =
                v2.migrate_validator(owner, IValidatorConfigV2::migrateValidatorCall { idx: 0 });
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

            // Migrate to V2 (not initialized — migration mode)
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
                    idx: 0,
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

            // Try to migrate out of order (should start at idx 1, not idx 0)
            let mut v2 = ValidatorConfigV2::new();
            v2.storage.set_block_number(100);
            let result =
                v2.migrate_validator(owner, IValidatorConfigV2::migrateValidatorCall { idx: 0 });

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

            // Only migrate second validator (reverse order starts at idx 1)
            let mut v2 = ValidatorConfigV2::new();
            v2.storage.set_block_number(100);
            v2.migrate_validator(owner, IValidatorConfigV2::migrateValidatorCall { idx: 1 })?;

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

    #[test]
    fn test_add_validator_reuses_deactivated_address() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator_addr = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            // Add first validator
            let (pubkey1, sig1) = make_test_keypair_and_signature(
                validator_addr,
                "192.168.1.1:8000",
                "192.168.1.1",
                SignatureKind::Add {
                    fee_recipient: validator_addr,
                },
            );
            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_add_call(
                    validator_addr,
                    pubkey1,
                    "192.168.1.1:8000",
                    "192.168.1.1",
                    validator_addr,
                    sig1,
                ),
            )?;

            // Deactivate it
            vc.storage.set_block_number(300);
            vc.deactivate_validator(
                owner,
                IValidatorConfigV2::deactivateValidatorCall { idx: 0 },
            )?;

            // Now add new validator with SAME address but different pubkey - should succeed
            let (pubkey2, sig2) = make_test_keypair_and_signature(
                validator_addr,
                "192.168.1.2:8000",
                "192.168.1.2",
                SignatureKind::Add {
                    fee_recipient: validator_addr,
                },
            );
            vc.storage.set_block_number(400);
            vc.add_validator(
                owner,
                make_add_call(
                    validator_addr,
                    pubkey2,
                    "192.168.1.2:8000",
                    "192.168.1.2",
                    validator_addr,
                    sig2,
                ),
            )?;

            // Should have 2 validators
            assert_eq!(vc.validator_count()?, 2);

            // First one is deactivated
            let v1 = vc.validator_by_index(0)?;
            assert_eq!(v1.validatorAddress, validator_addr);
            assert_eq!(v1.publicKey, pubkey1);
            assert_eq!(v1.deactivatedAtHeight, 300);

            // Second one is active with same address
            let v2 = vc.validator_by_index(1)?;
            assert_eq!(v2.validatorAddress, validator_addr);
            assert_eq!(v2.publicKey, pubkey2);
            assert_eq!(v2.deactivatedAtHeight, 0);

            // Lookup by address returns the NEW active validator
            let by_addr = vc.validator_by_address(validator_addr)?;
            assert_eq!(by_addr.publicKey, pubkey2);
            assert_eq!(by_addr.deactivatedAtHeight, 0);

            // Lookup by old pubkey returns old deactivated validator
            let by_old_pk = vc.validator_by_public_key(pubkey1)?;
            assert_eq!(by_old_pk.deactivatedAtHeight, 300);

            // Lookup by new pubkey returns new active validator
            let by_new_pk = vc.validator_by_public_key(pubkey2)?;
            assert_eq!(by_new_pk.deactivatedAtHeight, 0);

            Ok(())
        })
    }

    #[test]
    fn test_add_validator_rejects_duplicate_ingress() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_valid_add_call(
                    Address::random(),
                    "192.168.1.1:8000",
                    "192.168.1.1",
                    Address::random(),
                ),
            )?;

            vc.storage.set_block_number(201);
            let result = vc.add_validator(
                owner,
                make_valid_add_call(
                    Address::random(),
                    "192.168.1.1:8000",
                    "192.168.2.1",
                    Address::random(),
                ),
            );

            assert!(result.is_err());
            Ok(())
        })
    }

    #[test]
    fn test_ingress_reuse_after_deactivation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let v1 = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_valid_add_call(v1, "192.168.1.1:8000", "192.168.1.1", v1),
            )?;

            vc.storage.set_block_number(300);
            vc.deactivate_validator(
                owner,
                IValidatorConfigV2::deactivateValidatorCall { idx: 0 },
            )?;

            // Should allow IP reuse after deactivation
            vc.storage.set_block_number(400);
            vc.add_validator(
                owner,
                make_valid_add_call(
                    Address::random(),
                    "192.168.1.1:8000",
                    "192.168.1.1",
                    Address::random(),
                ),
            )?;

            Ok(())
        })
    }

    #[test]
    fn test_ingress_reuse_after_rotation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let v1 = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_valid_add_call(v1, "[2001:db8::1]:8000", "2001:db8::1", Address::random()),
            )?;

            vc.storage.set_block_number(300);

            // Rotate to different ingress
            let (new_pubkey, new_sig) = make_test_keypair_and_signature(
                v1,
                "[2001:db8::1]:8001",
                "2001:db8::1",
                SignatureKind::Rotate,
            );
            vc.rotate_validator(
                owner,
                IValidatorConfigV2::rotateValidatorCall {
                    idx: 0,
                    publicKey: new_pubkey,
                    ingress: "[2001:db8::1]:8001".to_string(),
                    egress: "2001:db8::1".to_string(),
                    signature: new_sig.into(),
                },
            )?;
            let v = vc.validator_by_address(v1)?;
            assert_eq!(v.ingress, "[2001:db8::1]:8001");

            // Should allow ingress reuse after rotation.
            vc.storage.set_block_number(400);
            vc.set_ip_addresses(
                owner,
                IValidatorConfigV2::setIpAddressesCall {
                    idx: 0,
                    ingress: "[2001:db8::1]:8000".to_string(),
                    egress: "2001:db8::1".to_string(),
                },
            )?;
            let v = vc.validator_by_address(v1)?;
            assert_eq!(v.ingress, "[2001:db8::1]:8000");

            Ok(())
        })
    }

    #[test]
    fn test_set_ip_addresses_rejects_pre_init() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let v1_addr = Address::random();

        StorageCtx::enter(&mut storage, || {
            // Setup V1
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

            let result = v2.set_ip_addresses(
                owner,
                IValidatorConfigV2::setIpAddressesCall {
                    idx: 0,
                    ingress: "10.0.0.1:8000".to_string(),
                    egress: "10.0.0.1".to_string(),
                },
            );

            assert_eq!(
                result,
                Err(ValidatorConfigV2Error::not_initialized().into())
            );
            Ok(())
        })
    }

    #[test]
    fn test_rotate_removes_and_checks_ips() -> eyre::Result<()> {
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
                make_valid_add_call(v1, "192.168.1.1:8000", "192.168.1.1", v1),
            )?;
            vc.add_validator(
                owner,
                make_valid_add_call(v2, "192.168.2.1:8000", "192.168.2.1", v2),
            )?;

            // Rotate v1 to v2's IPs should fail
            let (new_pk, sig) = make_test_keypair_and_signature(
                v1,
                "192.168.2.1:8000",
                "192.168.2.1",
                SignatureKind::Rotate,
            );

            vc.storage.set_block_number(300);
            let result = vc.rotate_validator(
                owner,
                IValidatorConfigV2::rotateValidatorCall {
                    idx: 0,
                    publicKey: new_pk,
                    ingress: "192.168.2.1:8000".to_string(),
                    egress: "192.168.2.1".to_string(),
                    signature: sig.into(),
                },
            );

            assert!(result.is_err());
            Ok(())
        })
    }

    #[test]
    fn test_migrate_skips_duplicate_ingress() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();

        StorageCtx::enter(&mut storage, || {
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
                    inboundAddress: "192.168.1.1:8000".to_string(),
                    outboundAddress: "192.168.2.1:9000".to_string(),
                },
            )?;

            let mut v2 = ValidatorConfigV2::new();
            v2.storage.set_block_number(100);
            v2.migrate_validator(owner, IValidatorConfigV2::migrateValidatorCall { idx: 1 })?;

            v2.migrate_validator(owner, IValidatorConfigV2::migrateValidatorCall { idx: 0 })?;
            assert_eq!(v2.validator_count()?, 1);
            assert_eq!(v2.config.migration_skipped_count.read()?, 1);

            v2.storage.set_block_number(400);
            v2.initialize_if_migrated(owner)?;
            assert!(v2.is_initialized()?);

            Ok(())
        })
    }

    #[test]
    fn test_migrate_skips_invalid_ed25519_pubkey() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut v1 = v1();
            v1.initialize(owner)?;
            v1.add_validator(
                owner,
                tempo_contracts::precompiles::IValidatorConfig::addValidatorCall {
                    newValidatorAddress: Address::random(),
                    publicKey: FixedBytes::<32>::from([0xDD; 32]),
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

            let mut v2 = ValidatorConfigV2::new();
            v2.storage.set_block_number(100);

            v2.migrate_validator(owner, IValidatorConfigV2::migrateValidatorCall { idx: 1 })?;
            assert_eq!(v2.validator_count()?, 1);

            v2.migrate_validator(owner, IValidatorConfigV2::migrateValidatorCall { idx: 0 })?;
            assert_eq!(v2.validator_count()?, 1);
            assert_eq!(v2.config.migration_skipped_count.read()?, 1);

            v2.storage.set_block_number(400);
            v2.initialize_if_migrated(owner)?;
            assert!(v2.is_initialized()?);

            Ok(())
        })
    }

    #[test]
    fn test_migrate_overwrites_duplicate_pubkey() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let addr1 = Address::random();
        let addr2 = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut v1 = v1();
            v1.initialize(owner)?;
            v1.add_validator(
                owner,
                tempo_contracts::precompiles::IValidatorConfig::addValidatorCall {
                    newValidatorAddress: addr1,
                    publicKey: FixedBytes::<32>::from([0x11; 32]),
                    active: true,
                    inboundAddress: "192.168.1.1:8000".to_string(),
                    outboundAddress: "192.168.1.1:9000".to_string(),
                },
            )?;
            v1.add_validator(
                owner,
                tempo_contracts::precompiles::IValidatorConfig::addValidatorCall {
                    newValidatorAddress: addr2,
                    publicKey: FixedBytes::<32>::from([0x11; 32]),
                    active: true,
                    inboundAddress: "192.168.1.2:8000".to_string(),
                    outboundAddress: "192.168.1.2:9000".to_string(),
                },
            )?;

            let mut v2 = ValidatorConfigV2::new();
            v2.storage.set_block_number(100);

            v2.migrate_validator(owner, IValidatorConfigV2::migrateValidatorCall { idx: 1 })?;
            assert_eq!(v2.validator_count()?, 1);

            v2.migrate_validator(owner, IValidatorConfigV2::migrateValidatorCall { idx: 0 })?;
            assert_eq!(v2.validator_count()?, 1);
            assert_eq!(v2.config.migration_skipped_count.read()?, 1);

            let migrated = v2.validator_by_index(0)?;
            assert_eq!(migrated.validatorAddress, addr2);
            assert_eq!(migrated.ingress, "192.168.1.2:8000");
            assert_eq!(migrated.egress, "192.168.1.2");

            v2.storage.set_block_number(400);
            v2.initialize_if_migrated(owner)?;
            assert!(v2.is_initialized()?);

            Ok(())
        })
    }

    #[test]
    fn test_add_validator_rejects_third_party() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator = Address::random();
        let third_party = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_valid_add_call(validator, "192.168.1.1:8000", "192.168.1.1", validator),
            )?;

            // Third party is neither owner nor validator_owner — should be rejected
            let result = vc.set_ip_addresses(
                third_party,
                IValidatorConfigV2::setIpAddressesCall {
                    idx: 0,
                    ingress: "10.0.0.1:8000".to_string(),
                    egress: "10.0.0.1".to_string(),
                },
            );
            assert_eq!(result, Err(ValidatorConfigV2Error::unauthorized().into()));

            let result = vc.transfer_validator_ownership(
                third_party,
                IValidatorConfigV2::transferValidatorOwnershipCall {
                    idx: 0,
                    newAddress: Address::random(),
                },
            );
            assert_eq!(result, Err(ValidatorConfigV2Error::unauthorized().into()));

            Ok(())
        })
    }

    #[test]
    fn test_rotate_validator_to_different_ingress() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_valid_add_call(validator, "192.168.1.1:8000", "192.168.1.1", validator),
            )?;

            // Rotate keeping the same ingress/egress — should succeed
            let (new_pubkey, new_sig) = make_test_keypair_and_signature(
                validator,
                "192.168.1.1:8001",
                "192.168.1.1",
                SignatureKind::Rotate,
            );
            vc.storage.set_block_number(300);
            vc.rotate_validator(
                owner,
                IValidatorConfigV2::rotateValidatorCall {
                    idx: 0,
                    publicKey: new_pubkey,
                    ingress: "192.168.1.1:8001".to_string(),
                    egress: "192.168.1.1".to_string(),
                    signature: new_sig.into(),
                },
            )?;

            assert_eq!(vc.validator_count()?, 2);
            assert_eq!(vc.validator_by_index(0)?.deactivatedAtHeight, 0);
            assert_eq!(vc.validator_by_index(1)?.deactivatedAtHeight, 300);
            assert_eq!(vc.validator_by_address(validator)?.publicKey, new_pubkey);
            assert_eq!(
                vc.validator_by_address(validator)?.ingress,
                "192.168.1.1:8001"
            );
            assert_eq!(vc.validator_by_address(validator)?.egress, "192.168.1.1");

            Ok(())
        })
    }

    #[test]
    fn test_rotate_validator_rejects_same_ingress() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_valid_add_call(
                    validator,
                    "192.168.1.1:8000",
                    "192.168.1.1",
                    Address::random(),
                ),
            )?;

            // Rotate keeping the same ingress/egress — should succeed
            let (new_pubkey, new_sig) = make_test_keypair_and_signature(
                validator,
                "192.168.1.1:8000",
                "192.168.1.1",
                SignatureKind::Rotate,
            );
            vc.storage.set_block_number(300);
            assert!(
                vc.rotate_validator(
                    owner,
                    IValidatorConfigV2::rotateValidatorCall {
                        idx: 0,
                        publicKey: new_pubkey,
                        ingress: "192.168.1.1:8000".to_string(),
                        egress: "192.168.1.1".to_string(),
                        signature: new_sig.into(),
                    },
                )
                .is_err()
            );
            Ok(())
        })
    }

    #[test]
    fn test_set_ip_addresses_ingress_only() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_valid_add_call(validator, "192.168.1.1:8000", "192.168.1.1", validator),
            )?;

            // Change ingress only, keep egress the same
            vc.set_ip_addresses(
                owner,
                IValidatorConfigV2::setIpAddressesCall {
                    idx: 0,
                    ingress: "10.0.0.1:8000".to_string(),
                    egress: "192.168.1.1".to_string(),
                },
            )?;

            let v = vc.validator_by_address(validator)?;
            assert_eq!(v.ingress, "10.0.0.1:8000");
            assert_eq!(v.egress, "192.168.1.1");

            Ok(())
        })
    }

    #[test]
    fn test_set_ip_addresses_ingress_port_only() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_valid_add_call(validator, "192.168.1.1:8000", "192.168.1.1", validator),
            )?;

            // Change ingress only, keep egress the same
            vc.set_ip_addresses(
                owner,
                IValidatorConfigV2::setIpAddressesCall {
                    idx: 0,
                    ingress: "192.168.1.1:8001".to_string(),
                    egress: "192.168.1.1".to_string(),
                },
            )?;

            let v = vc.validator_by_address(validator)?;
            assert_eq!(v.ingress, "192.168.1.1:8001");
            assert_eq!(v.egress, "192.168.1.1");

            Ok(())
        })
    }

    #[test]
    fn test_set_ip_addresses_egress_only() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_valid_add_call(validator, "192.168.1.1:8000", "192.168.1.1", validator),
            )?;

            // Change egress only, keep ingress the same
            vc.set_ip_addresses(
                owner,
                IValidatorConfigV2::setIpAddressesCall {
                    idx: 0,
                    ingress: "192.168.1.1:8000".to_string(),
                    egress: "10.0.0.1".to_string(),
                },
            )?;

            let v = vc.validator_by_address(validator)?;
            assert_eq!(v.ingress, "192.168.1.1:8000");
            assert_eq!(v.egress, "10.0.0.1");

            Ok(())
        })
    }

    #[test]
    fn test_set_ip_addresses_rejects_duplicate_ingress() -> eyre::Result<()> {
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
                make_valid_add_call(v1, "192.168.1.1:8000", "192.168.1.1", v1),
            )?;
            vc.add_validator(
                owner,
                make_valid_add_call(v2, "192.168.2.1:8000", "192.168.2.1", v2),
            )?;

            let result = vc.set_ip_addresses(
                owner,
                IValidatorConfigV2::setIpAddressesCall {
                    idx: 1,
                    ingress: "192.168.1.1:8000".to_string(),
                    egress: "192.168.2.1".to_string(),
                },
            );

            assert!(result.is_err());
            Ok(())
        })
    }

    #[test]
    fn test_set_ip_addresses_allows_same_ip_different_port() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_valid_add_call(validator, "192.168.1.1:8000", "192.168.1.1", validator),
            )?;

            vc.set_ip_addresses(
                owner,
                IValidatorConfigV2::setIpAddressesCall {
                    idx: 0,
                    ingress: "192.168.1.1:9000".to_string(),
                    egress: "192.168.1.1".to_string(),
                },
            )?;

            let v = vc.validator_by_address(validator)?;
            assert_eq!(v.ingress, "192.168.1.1:9000");

            Ok(())
        })
    }

    #[test]
    fn test_transfer_validator_ownership_by_validator() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator = Address::random();
        let new_address = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_valid_add_call(validator, "192.168.1.1:8000", "192.168.1.1", validator),
            )?;

            // Validator transfers its own ownership (not owner)
            vc.transfer_validator_ownership(
                validator,
                IValidatorConfigV2::transferValidatorOwnershipCall {
                    idx: 0,
                    newAddress: new_address,
                },
            )?;

            let result = vc.validator_by_address(validator);
            assert_eq!(
                result,
                Err(ValidatorConfigV2Error::validator_not_found().into())
            );

            let v = vc.validator_by_address(new_address)?;
            assert_eq!(v.validatorAddress, new_address);

            Ok(())
        })
    }

    #[test]
    fn test_add_validator_rejects_deleted_pubkey() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            let addr1 = Address::random();
            let (pubkey, sig) = make_test_keypair_and_signature(
                addr1,
                "192.168.1.1:8000",
                "192.168.1.1",
                SignatureKind::Add {
                    fee_recipient: addr1,
                },
            );
            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_add_call(addr1, pubkey, "192.168.1.1:8000", "192.168.1.1", addr1, sig),
            )?;

            // Deactivate
            vc.storage.set_block_number(300);
            vc.deactivate_validator(
                owner,
                IValidatorConfigV2::deactivateValidatorCall { idx: 0 },
            )?;

            // Try to add a new validator reusing the deleted pubkey — should fail
            let addr2 = Address::random();
            let result = vc.add_validator(
                owner,
                make_add_call(
                    addr2,
                    pubkey,
                    "192.168.2.1:8000",
                    "192.168.2.1",
                    addr2,
                    vec![0u8; 64],
                ),
            );
            assert_eq!(
                result,
                Err(ValidatorConfigV2Error::public_key_already_exists().into())
            );

            Ok(())
        })
    }

    #[test]
    fn test_add_validator_with_ipv6() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            // Add validator with IPv6 ingress
            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_valid_add_call(validator, "[::1]:8000", "::1", validator),
            )?;

            assert_eq!(vc.validator_count()?, 1);
            let v = vc.validator_by_index(0)?;
            assert_eq!(v.validatorAddress, validator);
            assert_eq!(v.ingress, "[::1]:8000");
            assert_eq!(v.egress, "::1");

            Ok(())
        })
    }

    #[test]
    fn test_add_validator_rejects_duplicate_ingress_ipv6() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_valid_add_call(
                    Address::random(),
                    "[2001:db8::1]:8000",
                    "2001:db8::1",
                    Address::random(),
                ),
            )?;

            // Try to add another validator with same IPv6 IP (different port)
            vc.storage.set_block_number(201);
            let result = vc.add_validator(
                owner,
                make_valid_add_call(
                    Address::random(),
                    "[2001:db8::1]:8000",
                    "2001:db8::2",
                    Address::random(),
                ),
            );

            assert!(result.is_err());
            Ok(())
        })
    }

    #[test]
    fn test_ipv6_reuse_after_deactivation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let v1 = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_valid_add_call(v1, "[2001:db8::1]:8000", "2001:db8::1", v1),
            )?;

            vc.storage.set_block_number(300);
            vc.deactivate_validator(
                owner,
                IValidatorConfigV2::deactivateValidatorCall { idx: 0 },
            )?;

            // Should allow IPv6 reuse after deactivation
            vc.storage.set_block_number(400);
            vc.add_validator(
                owner,
                make_valid_add_call(
                    Address::random(),
                    "[2001:db8::1]:8000",
                    "2001:db8::1",
                    Address::random(),
                ),
            )?;

            Ok(())
        })
    }

    #[test]
    fn test_rotate_validator_with_ipv6() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            // Add initial validator with IPv4
            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_valid_add_call(validator, "192.168.1.1:8000", "192.168.1.1", validator),
            )?;

            // Rotate to IPv6
            let (new_pubkey, new_sig) = make_test_keypair_and_signature(
                validator,
                "[2001:db8::1]:8000",
                "2001:db8::1",
                SignatureKind::Rotate,
            );
            vc.storage.set_block_number(300);
            vc.rotate_validator(
                owner,
                IValidatorConfigV2::rotateValidatorCall {
                    idx: 0,
                    publicKey: new_pubkey,
                    ingress: "[2001:db8::1]:8000".to_string(),
                    egress: "2001:db8::1".to_string(),
                    signature: new_sig.into(),
                },
            )?;

            assert_eq!(vc.validator_count()?, 2);
            let updated = vc.validator_by_index(0)?;
            assert_eq!(updated.deactivatedAtHeight, 0);
            assert_eq!(updated.ingress, "[2001:db8::1]:8000");
            assert_eq!(updated.egress, "2001:db8::1");

            let snapshot = vc.validator_by_index(1)?;
            assert_eq!(snapshot.deactivatedAtHeight, 300);

            Ok(())
        })
    }

    #[test]
    fn test_ipv6_canonical_representation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            // Add validator with compressed IPv6 notation
            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_valid_add_call(Address::random(), "[::1]:8000", "::1", Address::random()),
            )?;

            // Try to add another validator with expanded IPv6 notation of same IP
            // This should fail because [::1] and [0:0:0:0:0:0:0:1] are the same IP
            vc.storage.set_block_number(201);
            let result = vc.add_validator(
                owner,
                make_valid_add_call(
                    Address::random(),
                    "[0:0:0:0:0:0:0:1]:8000",
                    "::1",
                    Address::random(),
                ),
            );

            assert!(
                result.is_err(),
                "Different IPv6 notations of same IP should be rejected"
            );

            // No scope and %0 are the same - should fail.
            vc.storage.set_block_number(202);
            let result = vc.add_validator(
                owner,
                make_valid_add_call(Address::random(), "[::1%0]:8000", "::1", Address::random()),
            );

            assert!(
                result.is_err(),
                "Different IPv6 notations of same IP should be rejected"
            );

            // Same IP/Port but different port should succeed.
            vc.storage.set_block_number(203);
            let result = vc.add_validator(
                owner,
                make_valid_add_call(Address::random(), "[::1%1]:8000", "::1", Address::random()),
            );
            assert!(result.is_ok());

            Ok(())
        })
    }

    #[test]
    fn test_add_validator_rejects_wrong_key_signature() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator = Address::random();
        let fee_recipient = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            // Generate a valid keypair for a different key
            let (pubkey, _) = make_test_keypair_and_signature(
                validator,
                "192.168.1.1:8000",
                "192.168.1.1",
                SignatureKind::Add { fee_recipient },
            );

            // Generate signature from a completely different key
            let (_, wrong_sig) = make_test_keypair_and_signature(
                validator,
                "192.168.1.1:8000",
                "192.168.1.1",
                SignatureKind::Add { fee_recipient },
            );

            vc.storage.set_block_number(200);
            let result = vc.add_validator(
                owner,
                make_add_call(
                    validator,
                    pubkey,
                    "192.168.1.1:8000",
                    "192.168.1.1",
                    fee_recipient,
                    wrong_sig,
                ),
            );
            assert_eq!(
                result,
                Err(ValidatorConfigV2Error::invalid_signature().into())
            );

            Ok(())
        })
    }

    #[test]
    fn test_add_validator_rejects_wrong_namespace_signature() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator = Address::random();
        let fee_recipient = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            // Sign with ROTATE namespace, but try to ADD
            let (pubkey, sig) = make_test_keypair_and_signature(
                validator,
                "192.168.1.1:8000",
                "192.168.1.1",
                SignatureKind::Rotate,
            );

            vc.storage.set_block_number(200);
            let result = vc.add_validator(
                owner,
                make_add_call(
                    validator,
                    pubkey,
                    "192.168.1.1:8000",
                    "192.168.1.1",
                    fee_recipient,
                    sig,
                ),
            );
            assert_eq!(
                result,
                Err(ValidatorConfigV2Error::invalid_signature().into())
            );

            Ok(())
        })
    }

    #[test]
    fn test_rotate_validator_rejects_wrong_key_signature() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator = Address::random();
        let fee_recipient = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            // Add a valid validator first
            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_valid_add_call(validator, "192.168.1.1:8000", "192.168.1.1", fee_recipient),
            )?;

            // Generate a new pubkey for rotation
            let (new_pubkey, _) = make_test_keypair_and_signature(
                validator,
                "10.0.0.1:8000",
                "10.0.0.1",
                SignatureKind::Rotate,
            );

            // Sign with a different key
            let (_, wrong_sig) = make_test_keypair_and_signature(
                validator,
                "10.0.0.1:8000",
                "10.0.0.1",
                SignatureKind::Rotate,
            );

            vc.storage.set_block_number(300);
            let result = vc.rotate_validator(
                owner,
                IValidatorConfigV2::rotateValidatorCall {
                    idx: 0,
                    publicKey: new_pubkey,
                    ingress: "10.0.0.1:8000".to_string(),
                    egress: "10.0.0.1".to_string(),
                    signature: wrong_sig.into(),
                },
            );
            assert_eq!(
                result,
                Err(ValidatorConfigV2Error::invalid_signature().into())
            );

            Ok(())
        })
    }

    #[test]
    fn test_add_validator_rejects_malformed_signature() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator = Address::random();
        let fee_recipient = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            let (pubkey, _) = make_test_keypair_and_signature(
                validator,
                "192.168.1.1:8000",
                "192.168.1.1",
                SignatureKind::Add { fee_recipient },
            );

            vc.storage.set_block_number(200);
            let result = vc.add_validator(
                owner,
                make_add_call(
                    validator,
                    pubkey,
                    "192.168.1.1:8000",
                    "192.168.1.1",
                    fee_recipient,
                    vec![0xde, 0xad],
                ),
            );
            assert_eq!(
                result,
                Err(ValidatorConfigV2Error::invalid_signature_format().into())
            );

            Ok(())
        })
    }

    #[test]
    fn test_ipv4_ipv6_different_ips() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            // Add IPv4 validator
            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_valid_add_call(
                    Address::random(),
                    "192.168.1.1:8000",
                    "192.168.1.1",
                    Address::random(),
                ),
            )?;

            // Add IPv6 validator - should succeed (different IP)
            vc.storage.set_block_number(201);
            vc.add_validator(
                owner,
                make_valid_add_call(
                    Address::random(),
                    "[2001:db8::1]:8000",
                    "2001:db8::1",
                    Address::random(),
                ),
            )?;

            assert_eq!(vc.validator_count()?, 2);
            Ok(())
        })
    }

    #[test]
    fn test_event_emission_owner_and_validator_actions() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator = Address::random();
        let new_validator_address = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            let (pubkey, signature) = make_test_keypair_and_signature(
                validator,
                "192.168.1.1:8000",
                "192.168.1.1",
                SignatureKind::Add {
                    fee_recipient: validator,
                },
            );

            vc.storage.set_block_number(100);
            vc.add_validator(
                owner,
                make_add_call(
                    validator,
                    pubkey,
                    "192.168.1.1:8000",
                    "192.168.1.1",
                    validator,
                    signature,
                ),
            )?;
            vc.assert_emitted_events(vec![ValidatorConfigV2Event::ValidatorAdded(
                IValidatorConfigV2::ValidatorAdded {
                    index: 0,
                    validatorAddress: validator,
                    publicKey: pubkey,
                    ingress: "192.168.1.1:8000".to_string(),
                    egress: "192.168.1.1".to_string(),
                    feeRecipient: validator,
                },
            )]);

            vc.clear_emitted_events();
            vc.set_ip_addresses(
                validator,
                IValidatorConfigV2::setIpAddressesCall {
                    idx: 0,
                    ingress: "10.0.0.1:8000".to_string(),
                    egress: "10.0.0.1".to_string(),
                },
            )?;
            vc.assert_emitted_events(vec![ValidatorConfigV2Event::IpAddressesUpdated(
                IValidatorConfigV2::IpAddressesUpdated {
                    index: 0,
                    ingress: "10.0.0.1:8000".to_string(),
                    egress: "10.0.0.1".to_string(),
                    caller: validator,
                },
            )]);

            vc.clear_emitted_events();
            vc.transfer_validator_ownership(
                owner,
                IValidatorConfigV2::transferValidatorOwnershipCall {
                    idx: 0,
                    newAddress: new_validator_address,
                },
            )?;
            vc.assert_emitted_events(vec![ValidatorConfigV2Event::ValidatorOwnershipTransferred(
                IValidatorConfigV2::ValidatorOwnershipTransferred {
                    index: 0,
                    oldAddress: validator,
                    newAddress: new_validator_address,
                    caller: owner,
                },
            )]);

            vc.clear_emitted_events();
            vc.deactivate_validator(
                new_validator_address,
                IValidatorConfigV2::deactivateValidatorCall { idx: 0 },
            )?;
            vc.assert_emitted_events(vec![ValidatorConfigV2Event::ValidatorDeactivated(
                IValidatorConfigV2::ValidatorDeactivated {
                    index: 0,
                    validatorAddress: new_validator_address,
                },
            )]);

            vc.clear_emitted_events();
            let new_owner = Address::random();
            vc.transfer_ownership(
                owner,
                IValidatorConfigV2::transferOwnershipCall {
                    newOwner: new_owner,
                },
            )?;
            vc.assert_emitted_events(vec![ValidatorConfigV2Event::OwnershipTransferred(
                IValidatorConfigV2::OwnershipTransferred {
                    oldOwner: owner,
                    newOwner: new_owner,
                },
            )]);

            Ok(())
        })
    }

    #[test]
    fn test_event_emission_rotate_and_next_dkg() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let validator = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut vc = ValidatorConfigV2::new();
            vc.initialize(owner)?;

            let (old_pubkey, old_sig) = make_test_keypair_and_signature(
                validator,
                "192.168.1.1:8000",
                "192.168.1.1",
                SignatureKind::Add {
                    fee_recipient: validator,
                },
            );

            vc.storage.set_block_number(200);
            vc.add_validator(
                owner,
                make_add_call(
                    validator,
                    old_pubkey,
                    "192.168.1.1:8000",
                    "192.168.1.1",
                    validator,
                    old_sig,
                ),
            )?;

            vc.clear_emitted_events();
            let (new_pubkey, new_sig) = make_test_keypair_and_signature(
                validator,
                "10.0.0.2:8000",
                "10.0.0.2",
                SignatureKind::Rotate,
            );
            vc.storage.set_block_number(300);
            vc.rotate_validator(
                owner,
                IValidatorConfigV2::rotateValidatorCall {
                    idx: 0,
                    publicKey: new_pubkey,
                    ingress: "10.0.0.2:8000".to_string(),
                    egress: "10.0.0.2".to_string(),
                    signature: new_sig.into(),
                },
            )?;
            vc.assert_emitted_events(vec![ValidatorConfigV2Event::ValidatorRotated(
                IValidatorConfigV2::ValidatorRotated {
                    index: 0,
                    deactivatedIndex: 1,
                    validatorAddress: validator,
                    oldPublicKey: old_pubkey,
                    newPublicKey: new_pubkey,
                    ingress: "10.0.0.2:8000".to_string(),
                    egress: "10.0.0.2".to_string(),
                    caller: owner,
                },
            )]);

            vc.clear_emitted_events();
            vc.set_network_identity_rotation_epoch(
                owner,
                IValidatorConfigV2::setNetworkIdentityRotationEpochCall { epoch: 42 },
            )?;
            vc.assert_emitted_events(vec![
                ValidatorConfigV2Event::NetworkIdentityRotationEpochSet(
                    IValidatorConfigV2::NetworkIdentityRotationEpochSet {
                        previousEpoch: 0,
                        nextEpoch: 42,
                    },
                ),
            ]);

            Ok(())
        })
    }

    #[test]
    fn test_event_emission_migration_and_initialize() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let v1_addr = Address::random();
        let v1_pk = FixedBytes::<32>::from([0x11; 32]);

        StorageCtx::enter(&mut storage, || {
            let mut v1 = v1();
            v1.initialize(owner)?;
            v1.add_validator(
                owner,
                tempo_contracts::precompiles::IValidatorConfig::addValidatorCall {
                    newValidatorAddress: v1_addr,
                    publicKey: v1_pk,
                    active: true,
                    inboundAddress: "192.168.1.1:8000".to_string(),
                    outboundAddress: "192.168.1.1:9000".to_string(),
                },
            )?;

            let mut v2 = ValidatorConfigV2::new();
            v2.storage.set_block_number(500);
            v2.migrate_validator(owner, IValidatorConfigV2::migrateValidatorCall { idx: 0 })?;
            v2.assert_emitted_events(vec![ValidatorConfigV2Event::ValidatorMigrated(
                IValidatorConfigV2::ValidatorMigrated {
                    index: 0,
                    validatorAddress: v1_addr,
                    publicKey: v1_pk,
                },
            )]);

            v2.clear_emitted_events();
            v2.storage.set_block_number(700);
            v2.initialize_if_migrated(owner)?;
            v2.assert_emitted_events(vec![ValidatorConfigV2Event::Initialized(
                IValidatorConfigV2::Initialized { height: 700 },
            )]);

            Ok(())
        })
    }
}
