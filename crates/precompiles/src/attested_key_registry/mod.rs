//! Attested Key Registry (attested signers PoC).
//!
//! Policies list the measurements of approved signer programs. Anyone registers a program key into
//! one of a policy's [`ATTESTED_KEY_SLOTS`] slots with an attestation document whose measurement is
//! active in the policy, for at most the policy's `maxKeyLifetime`. A registration overwrites the
//! slot, which ends the key it held. Attested signatures (type `0x06`) are valid only while
//! [`AttestedKeyRegistry::program_key_current`] holds for their slot and key.

pub mod dispatch;

use crate::{
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping},
    zone_verifier::attestation::verify_attestation_with_root,
};
use alloy::{
    primitives::{Address, B128, B256, U256, keccak256},
    sol_types::SolValue,
};
use tempo_contracts::precompiles::{
    ATTESTED_KEY_REGISTRY_ADDRESS, AttestedKeyRegistryError, AttestedKeyRegistryEvent,
    IAttestedKeyRegistry,
};
use tempo_nitro_attestation::{AWS_NITRO_ROOT_DER, NITRO_DEV_ROOT_DER};
use tempo_precompiles_macros::{Storable, contract};
use tempo_primitives::transaction::{ATTESTED_KEY_SLOTS, is_valid_p256_public_key};

/// Largest `maxKeyLifetime`, in seconds, a policy can choose (7 days).
pub const MAX_KEY_LIFETIME: u64 = 604_800;
/// Allowance, in seconds, for attestation service clocks running ahead.
pub const MAX_FUTURE_SKEW: u64 = 60;
/// Oldest document accepted, in seconds after its issue time.
pub const MAX_ATTESTATION_AGE: u64 = 300;
/// Longest delay, in seconds, a policy can choose (30 days).
pub const MAX_DELAY: u64 = 2_592_000;
/// Most active and pending measurements per policy.
pub const MAX_MEASUREMENTS: u8 = 16;

/// AWS Nitro Enclaves scheme, verified against [`AWS_NITRO_ROOT_DER`].
pub const SCHEME_NITRO: u8 = 0x01;
/// Development Nitro scheme, verified against [`NITRO_DEV_ROOT_DER`] on [`DEV_CHAIN_ID`] only.
pub const SCHEME_NITRO_DEV: u8 = 0xFE;
/// The only chain that accepts [`SCHEME_NITRO_DEV`].
pub const DEV_CHAIN_ID: u64 = 1337;

/// Domain prefix of the binding an attestation document commits to.
pub const BINDING_DOMAIN: &[u8] = b"tempo:attested-key";

/// Slot 0 of a policy, packed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Storable)]
pub struct Policy {
    /// Owner. Zero if the policy does not exist.
    pub owner: Address,
    /// Attestation scheme.
    pub scheme: u8,
    /// Whether registrations and attested signatures are rejected.
    pub paused: bool,
    /// Revocation epoch. A key record is current only at the policy's epoch.
    pub epoch: u64,
}

/// Delay settings and entry counts of a policy, packed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Storable)]
pub struct PolicySettings {
    /// Seconds before a proposal becomes active.
    pub delay: u64,
    /// Decreased delay that applies from `pending_delay_at`.
    pub pending_delay: u64,
    /// When `pending_delay` applies. Zero if no decrease is pending.
    pub pending_delay_at: u64,
    /// Active and pending measurements.
    pub measurement_count: u8,
    /// Active and pending anchors. Always zero: the Nitro schemes accept no anchors.
    pub anchor_count: u8,
}

impl PolicySettings {
    /// Returns the delay in effect at `now`.
    fn delay_at(&self, now: u64) -> u64 {
        if self.pending_delay_at != 0 && now >= self.pending_delay_at {
            self.pending_delay
        } else {
            self.delay
        }
    }
}

/// Key lifetime cap of a policy, packed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Storable)]
pub struct KeyLifetime {
    /// Longest registration, in seconds.
    pub max: u64,
    /// Increased cap that applies from `pending_max_at`.
    pub pending_max: u64,
    /// When `pending_max` applies. Zero if no increase is pending.
    pub pending_max_at: u64,
}

impl KeyLifetime {
    /// Returns the cap in effect at `now`.
    fn max_at(&self, now: u64) -> u64 {
        if self.pending_max_at != 0 && now >= self.pending_max_at {
            self.pending_max
        } else {
            self.max
        }
    }
}

/// A program key slot of a policy, packed into one storage slot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Storable)]
pub struct KeySlot {
    /// [`key_hash`] of the program key the slot holds.
    pub key_hash: B128,
    /// Last block timestamp at which the key is current.
    pub valid_until: u64,
    /// Policy epoch at registration.
    pub epoch: u64,
}

#[contract(addr = ATTESTED_KEY_REGISTRY_ADDRESS)]
pub struct AttestedKeyRegistry {
    policies: Mapping<B256, Policy>,
    guardians: Mapping<B256, Address>,
    settings: Mapping<B256, PolicySettings>,
    measurement_active_at: Mapping<B256, Mapping<B256, u64>>,
    anchor_active_at: Mapping<B256, Mapping<B256, u64>>,
    key_slots: Mapping<B256, Mapping<u8, KeySlot>>,
    key_lifetimes: Mapping<B256, KeyLifetime>,
}

impl AttestedKeyRegistry {
    /// Returns whether `slot` of `policy_id` holds `(x, y)` as current at the block timestamp:
    /// the policy exists and is not paused, and the slot holds the key, unexpired and at the
    /// policy's epoch. `false` for a slot from [`ATTESTED_KEY_SLOTS`] up.
    ///
    /// Called by the EVM handler for every attested signature, at the transaction's position.
    /// Reads two storage slots: the policy and the key slot.
    pub fn program_key_current(&self, policy_id: B256, slot: u8, x: B256, y: B256) -> Result<bool> {
        let policy = self.policies[policy_id].read()?;
        if policy.owner.is_zero() || policy.paused || slot >= ATTESTED_KEY_SLOTS {
            return Ok(false);
        }
        let key = self.key_slots[policy_id][slot].read()?;
        Ok(key.key_hash == key_hash(x, y)
            && key.valid_until >= self.now()
            && key.epoch == policy.epoch)
    }

    fn create_policy(
        &mut self,
        sender: Address,
        call: IAttestedKeyRegistry::createPolicyCall,
    ) -> Result<B256> {
        let policy_id = self.compute_policy_id(sender, call.salt)?;
        if !self.policies[policy_id].read()?.owner.is_zero() {
            return Err(AttestedKeyRegistryError::policy_exists().into());
        }
        if call.owner.is_zero() {
            return Err(AttestedKeyRegistryError::zero_address().into());
        }
        self.root_for(call.scheme)?;
        if call.delay > MAX_DELAY {
            return Err(AttestedKeyRegistryError::delay_too_long().into());
        }
        ensure_key_lifetime_in_range(call.maxKeyLifetime)?;
        let measurement_count = u8::try_from(call.measurements.len())
            .ok()
            .filter(|count| *count <= MAX_MEASUREMENTS)
            .ok_or_else(AttestedKeyRegistryError::too_many_entries)?;
        if call.anchors.len() > usize::from(MAX_MEASUREMENTS) {
            return Err(AttestedKeyRegistryError::too_many_entries().into());
        }
        if !call.anchors.is_empty() {
            return Err(AttestedKeyRegistryError::invalid_anchor().into());
        }

        self.policies[policy_id].write(Policy {
            owner: call.owner,
            scheme: call.scheme,
            paused: false,
            epoch: 0,
        })?;
        self.guardians[policy_id].write(call.guardian)?;
        self.settings[policy_id].write(PolicySettings {
            delay: call.delay,
            measurement_count,
            ..Default::default()
        })?;
        self.key_lifetimes[policy_id].write(KeyLifetime {
            max: call.maxKeyLifetime,
            ..Default::default()
        })?;
        self.emit_event(AttestedKeyRegistryEvent::policy_created(
            policy_id,
            sender,
            call.scheme,
            call.owner,
            call.guardian,
            call.delay,
            call.maxKeyLifetime,
        ))?;

        // Initial measurements are active at once. Zero marks an absent entry, so a block at
        // timestamp zero lists them at one.
        let active_at = self.now().max(1);
        for measurement in call.measurements {
            if self.measurement_active_at[policy_id][measurement].read()? != 0 {
                return Err(AttestedKeyRegistryError::already_listed().into());
            }
            self.measurement_active_at[policy_id][measurement].write(active_at)?;
            self.emit_event(AttestedKeyRegistryEvent::measurement_proposed(
                policy_id,
                measurement,
                active_at,
            ))?;
        }
        Ok(policy_id)
    }

    fn compute_policy_id(&self, creator: Address, salt: B256) -> Result<B256> {
        self.storage.keccak256(&(creator, salt).abi_encode())
    }

    fn propose_measurement(
        &mut self,
        sender: Address,
        policy_id: B256,
        measurement: B256,
    ) -> Result<()> {
        self.ensure_owner(sender, policy_id)?;
        if self.measurement_active_at[policy_id][measurement].read()? != 0 {
            return Err(AttestedKeyRegistryError::already_listed().into());
        }
        let mut settings = self.settings[policy_id].read()?;
        if settings.measurement_count >= MAX_MEASUREMENTS {
            return Err(AttestedKeyRegistryError::too_many_entries().into());
        }
        let now = self.now();
        let active_at = now
            .checked_add(settings.delay_at(now))
            .ok_or_else(TempoPrecompileError::under_overflow)?
            .max(1);
        settings.measurement_count += 1;
        self.settings[policy_id].write(settings)?;
        self.measurement_active_at[policy_id][measurement].write(active_at)?;
        self.emit_event(AttestedKeyRegistryEvent::measurement_proposed(
            policy_id,
            measurement,
            active_at,
        ))
    }

    fn propose_anchor(&mut self, sender: Address, policy_id: B256) -> Result<()> {
        self.ensure_owner(sender, policy_id)?;
        // Both Nitro schemes pin their root and accept no anchors.
        Err(AttestedKeyRegistryError::invalid_anchor().into())
    }

    fn cancel_proposal(
        &mut self,
        sender: Address,
        policy_id: B256,
        entry: B256,
        is_anchor: bool,
    ) -> Result<()> {
        self.ensure_owner_or_guardian(sender, policy_id)?;
        let active_at = if is_anchor {
            self.anchor_active_at[policy_id][entry].read()?
        } else {
            self.measurement_active_at[policy_id][entry].read()?
        };
        if active_at == 0 || active_at <= self.now() {
            return Err(AttestedKeyRegistryError::not_pending().into());
        }
        // Anchors are never listed, so only a measurement reaches this point.
        self.remove_measurement_entry(policy_id, entry)?;
        self.emit_event(AttestedKeyRegistryEvent::proposal_cancelled(
            policy_id, entry, is_anchor,
        ))
    }

    fn remove_measurement(
        &mut self,
        sender: Address,
        policy_id: B256,
        measurement: B256,
    ) -> Result<()> {
        self.ensure_owner_or_guardian(sender, policy_id)?;
        if self.measurement_active_at[policy_id][measurement].read()? == 0 {
            return Err(AttestedKeyRegistryError::not_listed().into());
        }
        self.remove_measurement_entry(policy_id, measurement)?;
        let epoch = self.increment_epoch(policy_id)?;
        self.emit_event(AttestedKeyRegistryEvent::measurement_removed(
            policy_id,
            measurement,
            epoch,
        ))
    }

    fn remove_anchor(&mut self, sender: Address, policy_id: B256) -> Result<()> {
        self.ensure_owner_or_guardian(sender, policy_id)?;
        Err(AttestedKeyRegistryError::not_listed().into())
    }

    pub(crate) fn revoke_keys(&mut self, sender: Address, policy_id: B256) -> Result<()> {
        self.ensure_owner_or_guardian(sender, policy_id)?;
        let epoch = self.increment_epoch(policy_id)?;
        self.emit_event(AttestedKeyRegistryEvent::keys_revoked(policy_id, epoch))
    }

    pub(crate) fn set_paused(
        &mut self,
        sender: Address,
        policy_id: B256,
        paused: bool,
    ) -> Result<()> {
        if paused {
            self.ensure_owner_or_guardian(sender, policy_id)?;
        } else {
            self.ensure_owner(sender, policy_id)?;
        }
        let mut policy = self.policies[policy_id].read()?;
        policy.paused = paused;
        self.policies[policy_id].write(policy)?;
        self.emit_event(AttestedKeyRegistryEvent::policy_paused(policy_id, paused))
    }

    fn set_delay(&mut self, sender: Address, policy_id: B256, new_delay: u64) -> Result<()> {
        self.ensure_owner(sender, policy_id)?;
        if new_delay > MAX_DELAY {
            return Err(AttestedKeyRegistryError::delay_too_long().into());
        }
        let now = self.now();
        let mut settings = self.settings[policy_id].read()?;
        let current = settings.delay_at(now);
        // An increase applies at once and cancels a pending decrease. A decrease waits for the
        // current delay.
        let effective_at = if new_delay >= current {
            settings.delay = new_delay;
            settings.pending_delay = 0;
            settings.pending_delay_at = 0;
            now
        } else {
            let effective_at = now
                .checked_add(current)
                .ok_or_else(TempoPrecompileError::under_overflow)?;
            settings.delay = current;
            settings.pending_delay = new_delay;
            settings.pending_delay_at = effective_at;
            effective_at
        };
        self.settings[policy_id].write(settings)?;
        self.emit_event(AttestedKeyRegistryEvent::delay_changed(
            policy_id,
            new_delay,
            effective_at,
        ))
    }

    fn set_max_key_lifetime(
        &mut self,
        sender: Address,
        policy_id: B256,
        new_max: u64,
    ) -> Result<()> {
        self.ensure_owner(sender, policy_id)?;
        ensure_key_lifetime_in_range(new_max)?;
        let now = self.now();
        let mut lifetime = self.key_lifetimes[policy_id].read()?;
        let current = lifetime.max_at(now);
        // A longer lifetime widens what a leaked program key can do, so, unlike the delay, a
        // decrease applies at once and cancels a pending increase, and an increase waits for the
        // policy's delay.
        let effective_at = if new_max <= current {
            lifetime = KeyLifetime {
                max: new_max,
                ..Default::default()
            };
            now
        } else {
            let effective_at = now
                .checked_add(self.settings[policy_id].read()?.delay_at(now))
                .ok_or_else(TempoPrecompileError::under_overflow)?;
            lifetime = KeyLifetime {
                max: current,
                pending_max: new_max,
                pending_max_at: effective_at,
            };
            effective_at
        };
        self.key_lifetimes[policy_id].write(lifetime)?;
        self.emit_event(AttestedKeyRegistryEvent::max_key_lifetime_changed(
            policy_id,
            new_max,
            effective_at,
        ))
    }

    fn set_guardian(&mut self, sender: Address, policy_id: B256, guardian: Address) -> Result<()> {
        self.ensure_owner(sender, policy_id)?;
        let previous = self.guardians[policy_id].read()?;
        self.guardians[policy_id].write(guardian)?;
        self.emit_event(AttestedKeyRegistryEvent::guardian_changed(
            policy_id, previous, guardian,
        ))
    }

    fn transfer_ownership(
        &mut self,
        sender: Address,
        policy_id: B256,
        owner: Address,
    ) -> Result<()> {
        self.ensure_owner(sender, policy_id)?;
        if owner.is_zero() {
            return Err(AttestedKeyRegistryError::zero_address().into());
        }
        let mut policy = self.policies[policy_id].read()?;
        policy.owner = owner;
        self.policies[policy_id].write(policy)?;
        self.emit_event(AttestedKeyRegistryEvent::ownership_transferred(
            policy_id, sender, owner,
        ))
    }

    /// Registers a program key into a slot from an attestation document, running the checks in
    /// the order the registry specifies. Overwrites the slot, which ends the key it held. Returns
    /// the registration's `valid_until`.
    fn register_key(&mut self, call: IAttestedKeyRegistry::registerKeyCall) -> Result<u64> {
        let policy_id = call.policyId;
        let policy = self.policies[policy_id].read()?;
        if policy.owner.is_zero() {
            return Err(AttestedKeyRegistryError::policy_not_found().into());
        }
        if policy.paused {
            return Err(AttestedKeyRegistryError::policy_is_paused().into());
        }
        let root = self.root_for(policy.scheme)?;
        let slot = call.slot;
        if slot >= ATTESTED_KEY_SLOTS {
            return Err(AttestedKeyRegistryError::invalid_slot().into());
        }
        let (x, y) = (call.programKeyX, call.programKeyY);
        if !is_valid_p256_public_key(&x, &y) {
            return Err(AttestedKeyRegistryError::invalid_program_key().into());
        }

        let now = self.now();
        let binding = self.binding(policy_id, slot, x, y, call.lifetime)?;
        let attestation = verify_attestation_with_root(&call.document, now, root)?
            .ok_or_else(AttestedKeyRegistryError::invalid_attestation)?;
        // TIP-XXX4 steps 5 and 6: PCR0-2 present, 48 bytes, not all zero, and `user_data`
        // equal to the binding.
        let mut pcrs = [0u8; 3 * 48];
        for (index, chunk) in (0..).zip(pcrs.as_chunks_mut::<48>().0) {
            let pcr = attestation
                .pcrs
                .iter()
                .find(|pcr| pcr.index == index)
                .filter(|pcr| pcr.value.len() == 48 && pcr.value.iter().any(|byte| *byte != 0))
                .ok_or_else(AttestedKeyRegistryError::invalid_attestation)?;
            chunk.copy_from_slice(&pcr.value);
        }
        if attestation.user_data.as_slice() != binding.as_slice() {
            return Err(AttestedKeyRegistryError::invalid_attestation().into());
        }
        let measurement = self.storage.keccak256(&pcrs)?;

        let active_at = self.measurement_active_at[policy_id][measurement].read()?;
        if active_at == 0 || active_at > now {
            return Err(AttestedKeyRegistryError::measurement_not_active().into());
        }
        let issued_at = attestation.timestamp / 1_000;
        if issued_at > now.saturating_add(MAX_FUTURE_SKEW)
            || now > issued_at.saturating_add(MAX_ATTESTATION_AGE)
        {
            return Err(AttestedKeyRegistryError::stale_attestation().into());
        }
        // Nitro documents have no expiry, so `valid_until` is `now + min(lifetime, max)`, where a
        // zero `lifetime` asks for the maximum.
        let max = self.key_lifetimes[policy_id].read()?.max_at(now);
        let lifetime = if call.lifetime == 0 {
            max
        } else {
            call.lifetime.min(max)
        };
        let valid_until = now
            .checked_add(lifetime)
            .ok_or_else(TempoPrecompileError::under_overflow)?;

        self.key_slots[policy_id][slot].write(KeySlot {
            key_hash: key_hash(x, y),
            valid_until,
            epoch: policy.epoch,
        })?;
        self.emit_event(AttestedKeyRegistryEvent::key_registered(
            policy_id,
            key_id(policy_id, x, y),
            measurement,
            slot,
            valid_until,
        ))?;
        Ok(valid_until)
    }

    fn policy(&self, policy_id: B256) -> Result<IAttestedKeyRegistry::policyReturn> {
        let policy = self.policies[policy_id].read()?;
        let settings = self.settings[policy_id].read()?;
        let lifetime = self.key_lifetimes[policy_id].read()?;
        Ok(IAttestedKeyRegistry::policyReturn {
            owner: policy.owner,
            guardian: self.guardians[policy_id].read()?,
            scheme: policy.scheme,
            paused: policy.paused,
            epoch: policy.epoch,
            delay: settings.delay,
            pendingDelay: settings.pending_delay,
            pendingDelayAt: settings.pending_delay_at,
            maxKeyLifetime: lifetime.max,
            pendingMaxKeyLifetime: lifetime.pending_max,
            pendingMaxKeyLifetimeAt: lifetime.pending_max_at,
        })
    }

    /// Returns the `valid_until` of the slot that holds `(x, y)` as current, or zero if none
    /// does. Reads every slot, for callers that do not know which one holds the key.
    fn key_valid_until(&self, policy_id: B256, x: B256, y: B256) -> Result<u64> {
        for slot in 0..ATTESTED_KEY_SLOTS {
            if self.program_key_current(policy_id, slot, x, y)? {
                return Ok(self.key_slots[policy_id][slot].read()?.valid_until);
            }
        }
        Ok(0)
    }

    /// Returns the pinned root of `scheme` if it is active on this chain.
    fn root_for(&self, scheme: u8) -> Result<&'static [u8]> {
        match scheme {
            SCHEME_NITRO => Ok(AWS_NITRO_ROOT_DER),
            SCHEME_NITRO_DEV if self.storage.chain_id() == DEV_CHAIN_ID => Ok(NITRO_DEV_ROOT_DER),
            _ => Err(AttestedKeyRegistryError::unknown_scheme().into()),
        }
    }

    /// `keccak256("tempo:attested-key" || chainid || registry || policy_id || slot || x || y ||
    /// lifetime)`, with a 1-byte `slot` and an 8-byte big-endian `lifetime`.
    ///
    /// The document commits to the requested `lifetime`, so a copy of a registration cannot
    /// shorten the key's lifetime.
    fn binding(&self, policy_id: B256, slot: u8, x: B256, y: B256, lifetime: u64) -> Result<B256> {
        let chain_id = U256::from(self.storage.chain_id()).to_be_bytes::<32>();
        let preimage = [
            BINDING_DOMAIN,
            &chain_id,
            ATTESTED_KEY_REGISTRY_ADDRESS.as_slice(),
            policy_id.as_slice(),
            &[slot],
            x.as_slice(),
            y.as_slice(),
            &lifetime.to_be_bytes(),
        ]
        .concat();
        self.storage.keccak256(&preimage)
    }

    fn now(&self) -> u64 {
        self.storage.timestamp().saturating_to()
    }

    /// Reverts with `PolicyNotFound` for a missing policy, then `Unauthorized` unless `sender`
    /// owns it.
    fn ensure_owner(&self, sender: Address, policy_id: B256) -> Result<()> {
        let owner = self.policies[policy_id].read()?.owner;
        if owner.is_zero() {
            return Err(AttestedKeyRegistryError::policy_not_found().into());
        }
        if owner != sender {
            return Err(AttestedKeyRegistryError::unauthorized().into());
        }
        Ok(())
    }

    /// As [`Self::ensure_owner`], also admitting the policy's non-zero guardian.
    fn ensure_owner_or_guardian(&self, sender: Address, policy_id: B256) -> Result<()> {
        let owner = self.policies[policy_id].read()?.owner;
        if owner.is_zero() {
            return Err(AttestedKeyRegistryError::policy_not_found().into());
        }
        if owner != sender && self.guardians[policy_id].read()? != sender {
            return Err(AttestedKeyRegistryError::unauthorized().into());
        }
        Ok(())
    }

    fn remove_measurement_entry(&mut self, policy_id: B256, measurement: B256) -> Result<()> {
        self.measurement_active_at[policy_id][measurement].delete()?;
        let mut settings = self.settings[policy_id].read()?;
        settings.measurement_count = settings
            .measurement_count
            .checked_sub(1)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.settings[policy_id].write(settings)
    }

    /// Increments the policy's epoch, which revokes every registered key, and returns it.
    fn increment_epoch(&mut self, policy_id: B256) -> Result<u64> {
        let mut policy = self.policies[policy_id].read()?;
        policy.epoch = policy
            .epoch
            .checked_add(1)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        let epoch = policy.epoch;
        self.policies[policy_id].write(policy)?;
        Ok(epoch)
    }
}

/// `keccak256(policy_id || x || y)`, the program key's ID in `KeyRegistered`.
pub fn key_id(policy_id: B256, x: B256, y: B256) -> B256 {
    keccak256([policy_id.as_slice(), x.as_slice(), y.as_slice()].concat())
}

/// The first 16 bytes of `keccak256(x || y)`, which a key slot stores. A key with the same hash
/// would take a 2^128 second-preimage search, the security level of P256 itself.
pub fn key_hash(x: B256, y: B256) -> B128 {
    B128::from_slice(&keccak256([x.as_slice(), y.as_slice()].concat())[..16])
}

/// Reverts with `InvalidKeyLifetime` unless `lifetime` is in `[1, MAX_KEY_LIFETIME]`.
fn ensure_key_lifetime_in_range(lifetime: u64) -> Result<()> {
    if lifetime == 0 || lifetime > MAX_KEY_LIFETIME {
        return Err(AttestedKeyRegistryError::invalid_key_lifetime().into());
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};
    use p256::ecdsa::SigningKey;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_nitro_attestation::testing::{DEV_PCRS, DevAttestation};

    pub(crate) const NOW: u64 = 1_800_000_000;
    pub(crate) const OWNER: Address = Address::repeat_byte(0x01);
    const GUARDIAN: Address = Address::repeat_byte(0x02);
    const OTHER: Address = Address::repeat_byte(0x03);
    /// `maxKeyLifetime` of the test policies.
    const LIFETIME: u64 = 3_600;

    fn dev_measurement() -> B256 {
        keccak256(DEV_PCRS.concat())
    }

    pub(crate) fn program_key(seed: u8) -> (B256, B256) {
        let key = SigningKey::from_slice(&[seed; 32]).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        (
            B256::from_slice(point.x().unwrap()),
            B256::from_slice(point.y().unwrap()),
        )
    }

    pub(crate) fn with_registry<R>(
        chain_id: u64,
        f: impl FnOnce(&mut AttestedKeyRegistry) -> R,
    ) -> R {
        let mut storage = HashMapStorageProvider::new_with_spec(chain_id, TempoHardfork::T14);
        storage.set_timestamp(U256::from(NOW));
        StorageCtx::enter(&mut storage, || f(&mut AttestedKeyRegistry::new()))
    }

    fn create_call(scheme: u8, measurements: Vec<B256>) -> IAttestedKeyRegistry::createPolicyCall {
        IAttestedKeyRegistry::createPolicyCall {
            salt: B256::repeat_byte(0x55),
            scheme,
            owner: OWNER,
            guardian: GUARDIAN,
            delay: 0,
            maxKeyLifetime: LIFETIME,
            measurements,
            anchors: vec![],
        }
    }

    /// Creates the dev policy and registers the program key `SigningKey::from_slice(&[seed; 32])`
    /// into slot 0 at [`NOW`]. Returns the policy ID.
    pub(crate) fn register_dev_key(registry: &mut AttestedKeyRegistry, seed: u8) -> B256 {
        let policy_id = create_dev_policy(registry);
        let key = program_key(seed);
        let attestation = attestation_for(registry, policy_id, 0, key);
        register(registry, policy_id, 0, key, attestation).unwrap();
        policy_id
    }

    fn create_dev_policy(registry: &mut AttestedKeyRegistry) -> B256 {
        registry
            .create_policy(
                OWNER,
                create_call(SCHEME_NITRO_DEV, vec![dev_measurement()]),
            )
            .unwrap()
    }

    /// Registers `(x, y)` into `slot` for the policy's maximum lifetime.
    fn register(
        registry: &mut AttestedKeyRegistry,
        policy_id: B256,
        slot: u8,
        key: (B256, B256),
        attestation: DevAttestation,
    ) -> Result<u64> {
        register_for(registry, policy_id, slot, key, attestation, 0)
    }

    /// Returns a document issued at the block timestamp, bound to `(x, y)` in `slot` for the
    /// policy's maximum lifetime.
    fn attestation_for(
        registry: &AttestedKeyRegistry,
        policy_id: B256,
        slot: u8,
        key: (B256, B256),
    ) -> DevAttestation {
        attestation_for_lifetime(registry, policy_id, slot, key, 0)
    }

    fn register_for(
        registry: &mut AttestedKeyRegistry,
        policy_id: B256,
        slot: u8,
        (x, y): (B256, B256),
        attestation: DevAttestation,
        lifetime: u64,
    ) -> Result<u64> {
        registry.register_key(IAttestedKeyRegistry::registerKeyCall {
            policyId: policy_id,
            slot,
            document: attestation.build().into(),
            programKeyX: x,
            programKeyY: y,
            lifetime,
        })
    }

    fn attestation_for_lifetime(
        registry: &AttestedKeyRegistry,
        policy_id: B256,
        slot: u8,
        (x, y): (B256, B256),
        lifetime: u64,
    ) -> DevAttestation {
        let binding = registry.binding(policy_id, slot, x, y, lifetime).unwrap();
        DevAttestation::new(binding.as_slice(), registry.now() * 1_000)
    }

    fn current(
        registry: &AttestedKeyRegistry,
        policy_id: B256,
        slot: u8,
        key: (B256, B256),
    ) -> bool {
        registry
            .program_key_current(policy_id, slot, key.0, key.1)
            .unwrap()
    }

    fn err(error: AttestedKeyRegistryError) -> TempoPrecompileError {
        error.into()
    }

    #[test]
    fn registers_dev_key_and_reports_it_current() {
        with_registry(DEV_CHAIN_ID, |registry| {
            let policy_id = create_dev_policy(registry);
            assert_eq!(
                policy_id,
                keccak256((OWNER, B256::repeat_byte(0x55)).abi_encode())
            );
            assert_eq!(
                registry
                    .compute_policy_id(OWNER, B256::repeat_byte(0x55))
                    .unwrap(),
                policy_id
            );
            let key = program_key(7);
            assert!(!current(registry, policy_id, 3, key));

            let attestation = attestation_for(registry, policy_id, 3, key);
            assert_eq!(
                register(registry, policy_id, 3, key, attestation).unwrap(),
                NOW + LIFETIME
            );
            assert!(current(registry, policy_id, 3, key));
            assert_eq!(
                registry.key_valid_until(policy_id, key.0, key.1).unwrap(),
                NOW + LIFETIME
            );
            assert_eq!(
                registry.key_slots[policy_id][3].read().unwrap(),
                KeySlot {
                    key_hash: key_hash(key.0, key.1),
                    valid_until: NOW + LIFETIME,
                    epoch: 0
                }
            );
            // The key is current only in its own slot, and another key of the policy is not.
            assert!(!current(registry, policy_id, 2, key));
            assert!(!current(registry, policy_id, ATTESTED_KEY_SLOTS, key));
            let other = program_key(8);
            assert!(!current(registry, policy_id, 3, other));
            assert_eq!(
                registry
                    .key_valid_until(policy_id, other.0, other.1)
                    .unwrap(),
                0
            );

            let policy = registry.policy(policy_id).unwrap();
            assert_eq!(
                (
                    policy.owner,
                    policy.guardian,
                    policy.scheme,
                    policy.paused,
                    policy.epoch
                ),
                (OWNER, GUARDIAN, SCHEME_NITRO_DEV, false, 0)
            );
            assert_eq!(
                (
                    policy.maxKeyLifetime,
                    policy.pendingMaxKeyLifetime,
                    policy.pendingMaxKeyLifetimeAt
                ),
                (LIFETIME, 0, 0)
            );
            assert_eq!(
                registry.measurement_active_at[policy_id][dev_measurement()]
                    .read()
                    .unwrap(),
                NOW
            );
        });
    }

    #[test]
    fn registration_failures() {
        with_registry(DEV_CHAIN_ID, |registry| {
            let policy_id = create_dev_policy(registry);
            let key = program_key(7);
            let attestation = attestation_for(registry, policy_id, 0, key);

            assert_eq!(
                register(registry, B256::ZERO, 0, key, attestation.clone()),
                Err(err(AttestedKeyRegistryError::policy_not_found()))
            );

            let off_range = attestation_for(registry, policy_id, ATTESTED_KEY_SLOTS, key);
            assert_eq!(
                register(registry, policy_id, ATTESTED_KEY_SLOTS, key, off_range),
                Err(err(AttestedKeyRegistryError::invalid_slot()))
            );

            let off_curve = (key.0, B256::repeat_byte(0x01));
            assert_eq!(
                register(registry, policy_id, 0, off_curve, attestation.clone()),
                Err(err(AttestedKeyRegistryError::invalid_program_key()))
            );

            // A document bound to another key, or to the same key in another slot.
            assert_eq!(
                register(registry, policy_id, 0, program_key(8), attestation.clone()),
                Err(err(AttestedKeyRegistryError::invalid_attestation()))
            );
            assert_eq!(
                register(registry, policy_id, 1, key, attestation.clone()),
                Err(err(AttestedKeyRegistryError::invalid_attestation()))
            );

            // A debug-mode PCR.
            let mut zero_pcr = attestation.clone();
            zero_pcr.pcrs[1] = [0; 48];
            assert_eq!(
                register(registry, policy_id, 0, key, zero_pcr),
                Err(err(AttestedKeyRegistryError::invalid_attestation()))
            );

            // A 31-byte `user_data`.
            let mut short = attestation.clone();
            short.user_data.pop();
            assert_eq!(
                register(registry, policy_id, 0, key, short),
                Err(err(AttestedKeyRegistryError::invalid_attestation()))
            );

            // Approved code only: other PCRs give another measurement.
            let mut other_code = attestation.clone();
            other_code.pcrs[2] = [0x09; 48];
            assert_eq!(
                register(registry, policy_id, 0, key, other_code),
                Err(err(AttestedKeyRegistryError::measurement_not_active()))
            );

            let mut old = attestation.clone();
            old.timestamp_ms = (NOW - MAX_ATTESTATION_AGE - 1) * 1_000;
            assert_eq!(
                register(registry, policy_id, 0, key, old.clone()),
                Err(err(AttestedKeyRegistryError::stale_attestation()))
            );
            old.timestamp_ms = (NOW - MAX_ATTESTATION_AGE) * 1_000;
            assert!(register(registry, policy_id, 0, key, old).is_ok());

            let mut future = attestation.clone();
            future.timestamp_ms = (NOW + MAX_FUTURE_SKEW + 1) * 1_000;
            assert_eq!(
                register(registry, policy_id, 0, key, future),
                Err(err(AttestedKeyRegistryError::stale_attestation()))
            );

            registry.set_paused(GUARDIAN, policy_id, true).unwrap();
            assert_eq!(
                register(registry, policy_id, 0, key, attestation),
                Err(err(AttestedKeyRegistryError::policy_is_paused()))
            );
        });
    }

    #[test]
    fn production_scheme_rejects_dev_documents() {
        with_registry(DEV_CHAIN_ID, |registry| {
            let policy_id = registry
                .create_policy(OWNER, create_call(SCHEME_NITRO, vec![dev_measurement()]))
                .unwrap();
            let key = program_key(7);
            let attestation = attestation_for(registry, policy_id, 0, key);
            assert_eq!(
                register(registry, policy_id, 0, key, attestation),
                Err(err(AttestedKeyRegistryError::invalid_attestation()))
            );
        });
    }

    #[test]
    fn dev_scheme_is_unknown_outside_dev_chain() {
        with_registry(1, |registry| {
            assert_eq!(
                registry.create_policy(OWNER, create_call(SCHEME_NITRO_DEV, vec![])),
                Err(err(AttestedKeyRegistryError::unknown_scheme()))
            );
            assert!(
                registry
                    .create_policy(OWNER, create_call(SCHEME_NITRO, vec![]))
                    .is_ok()
            );
        });
    }

    #[test]
    fn create_policy_failures() {
        with_registry(DEV_CHAIN_ID, |registry| {
            create_dev_policy(registry);
            assert_eq!(
                registry.create_policy(OWNER, create_call(SCHEME_NITRO_DEV, vec![])),
                Err(err(AttestedKeyRegistryError::policy_exists()))
            );

            let fresh = |mutate: fn(&mut IAttestedKeyRegistry::createPolicyCall)| {
                let mut call = create_call(SCHEME_NITRO_DEV, vec![]);
                call.salt = B256::repeat_byte(0x66);
                mutate(&mut call);
                call
            };
            for (call, expected) in [
                (
                    fresh(|c| c.owner = Address::ZERO),
                    AttestedKeyRegistryError::zero_address(),
                ),
                (
                    fresh(|c| c.scheme = 0x02),
                    AttestedKeyRegistryError::unknown_scheme(),
                ),
                (
                    fresh(|c| c.delay = MAX_DELAY + 1),
                    AttestedKeyRegistryError::delay_too_long(),
                ),
                (
                    fresh(|c| c.maxKeyLifetime = 0),
                    AttestedKeyRegistryError::invalid_key_lifetime(),
                ),
                (
                    fresh(|c| c.maxKeyLifetime = MAX_KEY_LIFETIME + 1),
                    AttestedKeyRegistryError::invalid_key_lifetime(),
                ),
                (
                    fresh(|c| {
                        c.measurements = (0..=MAX_MEASUREMENTS).map(B256::with_last_byte).collect()
                    }),
                    AttestedKeyRegistryError::too_many_entries(),
                ),
                (
                    fresh(|c| c.anchors = vec![B256::ZERO]),
                    AttestedKeyRegistryError::invalid_anchor(),
                ),
                (
                    fresh(|c| c.measurements = vec![B256::ZERO, B256::ZERO]),
                    AttestedKeyRegistryError::already_listed(),
                ),
            ] {
                assert_eq!(registry.create_policy(OWNER, call), Err(err(expected)));
            }
        });
    }

    #[test]
    fn revocation_removal_and_pause_end_current_keys() {
        with_registry(DEV_CHAIN_ID, |registry| {
            let policy_id = create_dev_policy(registry);
            let key = program_key(7);
            let attestation = attestation_for(registry, policy_id, 0, key);
            let current = |registry: &AttestedKeyRegistry| current(registry, policy_id, 0, key);

            register(registry, policy_id, 0, key, attestation.clone()).unwrap();
            assert_eq!(
                registry.revoke_keys(OTHER, policy_id),
                Err(err(AttestedKeyRegistryError::unauthorized()))
            );
            registry.revoke_keys(GUARDIAN, policy_id).unwrap();
            assert!(!current(registry));
            assert_eq!(
                registry.key_valid_until(policy_id, key.0, key.1).unwrap(),
                0
            );
            assert_eq!(registry.policy(policy_id).unwrap().epoch, 1);

            // Re-registration records the new epoch.
            register(registry, policy_id, 0, key, attestation.clone()).unwrap();
            assert!(current(registry));

            registry.set_paused(GUARDIAN, policy_id, true).unwrap();
            assert!(!current(registry));
            assert_eq!(
                registry.set_paused(GUARDIAN, policy_id, false),
                Err(err(AttestedKeyRegistryError::unauthorized()))
            );
            registry.set_paused(OWNER, policy_id, false).unwrap();
            assert!(current(registry));

            registry
                .remove_measurement(OWNER, policy_id, dev_measurement())
                .unwrap();
            assert!(!current(registry));
            assert_eq!(registry.policy(policy_id).unwrap().epoch, 2);
            assert_eq!(
                registry.remove_measurement(OWNER, policy_id, dev_measurement()),
                Err(err(AttestedKeyRegistryError::not_listed()))
            );
            assert_eq!(
                register(registry, policy_id, 0, key, attestation),
                Err(err(AttestedKeyRegistryError::measurement_not_active()))
            );
            assert_eq!(
                registry.revoke_keys(OWNER, B256::ZERO),
                Err(err(AttestedKeyRegistryError::policy_not_found()))
            );
        });
    }

    #[test]
    fn proposals_wait_for_the_delay() {
        with_registry(DEV_CHAIN_ID, |registry| {
            let mut call = create_call(SCHEME_NITRO_DEV, vec![]);
            call.delay = 100;
            let policy_id = registry.create_policy(OWNER, call).unwrap();
            let measurement = dev_measurement();

            assert_eq!(
                registry.propose_measurement(GUARDIAN, policy_id, measurement),
                Err(err(AttestedKeyRegistryError::unauthorized()))
            );
            registry
                .propose_measurement(OWNER, policy_id, measurement)
                .unwrap();
            assert_eq!(
                registry.measurement_active_at[policy_id][measurement]
                    .read()
                    .unwrap(),
                NOW + 100
            );
            assert_eq!(
                registry.propose_measurement(OWNER, policy_id, measurement),
                Err(err(AttestedKeyRegistryError::already_listed()))
            );

            // A pending measurement cannot register keys.
            let key = program_key(7);
            let attestation = attestation_for(registry, policy_id, 0, key);
            assert_eq!(
                register(registry, policy_id, 0, key, attestation),
                Err(err(AttestedKeyRegistryError::measurement_not_active()))
            );

            registry
                .cancel_proposal(GUARDIAN, policy_id, measurement, false)
                .unwrap();
            assert_eq!(
                registry.measurement_active_at[policy_id][measurement]
                    .read()
                    .unwrap(),
                0
            );
            assert_eq!(
                registry.cancel_proposal(OWNER, policy_id, measurement, false),
                Err(err(AttestedKeyRegistryError::not_pending()))
            );
            assert_eq!(
                registry.propose_anchor(OWNER, policy_id),
                Err(err(AttestedKeyRegistryError::invalid_anchor()))
            );

            // A decrease waits for the current delay; an increase applies at once.
            registry.set_delay(OWNER, policy_id, 10).unwrap();
            let policy = registry.policy(policy_id).unwrap();
            assert_eq!(
                (policy.delay, policy.pendingDelay, policy.pendingDelayAt),
                (100, 10, NOW + 100)
            );
            registry.set_delay(OWNER, policy_id, 200).unwrap();
            let policy = registry.policy(policy_id).unwrap();
            assert_eq!(
                (policy.delay, policy.pendingDelay, policy.pendingDelayAt),
                (200, 0, 0)
            );

            registry.set_guardian(OWNER, policy_id, OTHER).unwrap();
            registry
                .transfer_ownership(OWNER, policy_id, OTHER)
                .unwrap();
            let policy = registry.policy(policy_id).unwrap();
            assert_eq!((policy.owner, policy.guardian), (OTHER, OTHER));
            assert_eq!(
                registry.transfer_ownership(OTHER, policy_id, Address::ZERO),
                Err(err(AttestedKeyRegistryError::zero_address()))
            );
        });
    }

    #[test]
    fn overwriting_a_slot_ends_its_key_and_two_slots_overlap() {
        with_registry(DEV_CHAIN_ID, |registry| {
            let policy_id = create_dev_policy(registry);
            let (first, second, third) = (program_key(7), program_key(8), program_key(9));

            let attestation = attestation_for(registry, policy_id, 0, first);
            register(registry, policy_id, 0, first, attestation).unwrap();

            // A key in the other slot overlaps the first.
            registry.storage.set_timestamp(U256::from(NOW + 100));
            let attestation = attestation_for(registry, policy_id, 1, second);
            assert_eq!(
                register(registry, policy_id, 1, second, attestation).unwrap(),
                NOW + 100 + LIFETIME
            );
            assert!(current(registry, policy_id, 0, first));
            assert!(current(registry, policy_id, 1, second));

            // Overwriting slot 0 ends the first key at once, with time left on its registration.
            registry.storage.set_timestamp(U256::from(NOW + 200));
            let attestation = attestation_for(registry, policy_id, 0, third);
            register(registry, policy_id, 0, third, attestation).unwrap();
            assert!(!current(registry, policy_id, 0, first));
            assert_eq!(
                registry
                    .key_valid_until(policy_id, first.0, first.1)
                    .unwrap(),
                0
            );
            assert!(current(registry, policy_id, 0, third));
            assert!(current(registry, policy_id, 1, second));
            assert_eq!(
                registry
                    .key_valid_until(policy_id, second.0, second.1)
                    .unwrap(),
                NOW + 100 + LIFETIME
            );

            // The slot's key expires at `valid_until`.
            registry
                .storage
                .set_timestamp(U256::from(NOW + 200 + LIFETIME));
            assert!(current(registry, policy_id, 0, third));
            registry
                .storage
                .set_timestamp(U256::from(NOW + 201 + LIFETIME));
            assert!(!current(registry, policy_id, 0, third));
        });
    }

    #[test]
    fn registrations_are_capped_by_max_key_lifetime() {
        with_registry(DEV_CHAIN_ID, |registry| {
            let policy_id = create_dev_policy(registry);
            let key = program_key(7);
            for (lifetime, expected) in [(0, LIFETIME), (100, 100), (LIFETIME + 1, LIFETIME)] {
                let attestation = attestation_for_lifetime(registry, policy_id, 0, key, lifetime);
                assert_eq!(
                    register_for(registry, policy_id, 0, key, attestation, lifetime).unwrap(),
                    NOW + expected
                );
            }

            // The document commits to the lifetime, so a copy cannot request another one.
            let attestation = attestation_for_lifetime(registry, policy_id, 0, key, 100);
            assert_eq!(
                register_for(registry, policy_id, 0, key, attestation, 1),
                Err(err(AttestedKeyRegistryError::invalid_attestation()))
            );

            // A decrease caps the next registration at once.
            registry.set_max_key_lifetime(OWNER, policy_id, 60).unwrap();
            let attestation = attestation_for(registry, policy_id, 0, key);
            assert_eq!(
                register(registry, policy_id, 0, key, attestation).unwrap(),
                NOW + 60
            );
        });
    }

    #[test]
    fn max_key_lifetime_increases_wait_for_the_delay() {
        with_registry(DEV_CHAIN_ID, |registry| {
            let mut call = create_call(SCHEME_NITRO_DEV, vec![dev_measurement()]);
            call.delay = 100;
            let policy_id = registry.create_policy(OWNER, call).unwrap();
            let lifetime = |registry: &AttestedKeyRegistry| {
                let policy = registry.policy(policy_id).unwrap();
                (
                    policy.maxKeyLifetime,
                    policy.pendingMaxKeyLifetime,
                    policy.pendingMaxKeyLifetimeAt,
                )
            };

            for (sender, value, expected) in [
                (GUARDIAN, LIFETIME, AttestedKeyRegistryError::unauthorized()),
                (OWNER, 0, AttestedKeyRegistryError::invalid_key_lifetime()),
                (
                    OWNER,
                    MAX_KEY_LIFETIME + 1,
                    AttestedKeyRegistryError::invalid_key_lifetime(),
                ),
            ] {
                assert_eq!(
                    registry.set_max_key_lifetime(sender, policy_id, value),
                    Err(err(expected))
                );
            }

            // An increase waits for the delay. Registrations until then use the earlier cap.
            registry
                .set_max_key_lifetime(OWNER, policy_id, MAX_KEY_LIFETIME)
                .unwrap();
            assert_eq!(lifetime(registry), (LIFETIME, MAX_KEY_LIFETIME, NOW + 100));
            let key = program_key(7);
            registry.storage.set_timestamp(U256::from(NOW + 99));
            let attestation = attestation_for(registry, policy_id, 0, key);
            assert_eq!(
                register(registry, policy_id, 0, key, attestation).unwrap(),
                NOW + 99 + LIFETIME
            );
            registry.storage.set_timestamp(U256::from(NOW + 100));
            let attestation = attestation_for(registry, policy_id, 0, key);
            assert_eq!(
                register(registry, policy_id, 0, key, attestation).unwrap(),
                NOW + 100 + MAX_KEY_LIFETIME
            );

            // A decrease applies at once and cancels a pending increase.
            registry
                .set_max_key_lifetime(OWNER, policy_id, 2 * LIFETIME)
                .unwrap();
            assert_eq!(lifetime(registry), (2 * LIFETIME, 0, 0));
            registry
                .set_max_key_lifetime(OWNER, policy_id, 3 * LIFETIME)
                .unwrap();
            assert_eq!(lifetime(registry), (2 * LIFETIME, 3 * LIFETIME, NOW + 200));
            registry
                .set_max_key_lifetime(OWNER, policy_id, LIFETIME)
                .unwrap();
            assert_eq!(lifetime(registry), (LIFETIME, 0, 0));
        });
    }
}
