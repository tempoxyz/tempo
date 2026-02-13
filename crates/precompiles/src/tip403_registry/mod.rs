pub mod abi;
mod dispatch;

use crate::StorageCtx;
use abi::ITIP403Registry::PolicyType;
pub use abi::{ITIP403Registry, ITIP403Registry::Interface};
use tempo_precompiles_macros::{Storable, contract};

use crate::{
    TIP403_REGISTRY_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping},
};
use alloy::primitives::{Address, U256};

#[contract(addr = TIP403_REGISTRY_ADDRESS, abi = ITIP403Registry)]
pub struct TIP403Registry {
    policy_id_counter: u64,
    policy_records: Mapping<u64, PolicyRecord>,
    policy_set: Mapping<u64, Mapping<Address, bool>>,
}

/// Policy record containing base data and optional data for compound policies (TIP-1015)
#[derive(Debug, Clone, Storable)]
pub struct PolicyRecord {
    /// Base policy data
    pub base: PolicyData,
    /// Compound policy data. Only relevant when `base.policy_type == COMPOUND`
    pub compound: CompoundPolicyData,
}

/// Data for compound policies (TIP-1015)
#[derive(Debug, Clone, Default, Storable)]
pub struct CompoundPolicyData {
    pub sender_policy_id: u64,
    pub recipient_policy_id: u64,
    pub mint_recipient_policy_id: u64,
}

/// Authorization role for policy checks.
///
/// - `Transfer` (symmetric sender/recipient) available since `Genesis`.
/// - Directional roles (`Sender`, `Recipient`, `MintRecipient`) for compound policies available since `T2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRole {
    /// Check both sender AND recipient. Used for `isAuthorized` calls (spec: pre T2).
    Transfer,
    /// Check sender authorization only (spec: +T2).
    Sender,
    /// Check recipient authorization only (spec: +T2).
    Recipient,
    /// Check mint recipient authorization only (spec: +T2).
    MintRecipient,
}

#[derive(Debug, Clone, Storable)]
pub struct PolicyData {
    pub policy_type: PolicyType,
    pub admin: Address,
}

// NOTE(rusowsky): can be removed once revm uses precompiles rather than directly
// interacting with storage slots.
impl PolicyData {
    pub fn decode_from_slot(slot_value: U256) -> Self {
        use crate::storage::{LayoutCtx, Storable, packing::PackedSlot};

        // NOTE: fine to expect, as `StorageOps` on `PackedSlot` are infallible
        Self::load(&PackedSlot(slot_value), U256::ZERO, LayoutCtx::FULL)
            .expect("unable to decode PoliciData from slot")
    }

    pub fn encode_to_slot(&self) -> U256 {
        use crate::storage::packing::insert_into_word;
        use __packing_policy_data::{ADMIN_LOC as A_LOC, POLICY_TYPE_LOC as PT_LOC};

        let encoded = insert_into_word(
            U256::ZERO,
            &(self.policy_type as u8),
            PT_LOC.offset_bytes,
            PT_LOC.size,
        )
        .expect("unable to insert 'policy_type'");

        insert_into_word(encoded, &self.admin, A_LOC.offset_bytes, A_LOC.size)
            .expect("unable to insert 'admin'")
    }

    /// Returns `true` if the policy data indicates a compound policy
    fn is_compound(&self) -> bool {
        matches!(self.policy_type, PolicyType::COMPOUND)
    }

    /// Returns `true` if the policy data is the default (uninitialized) value.
    fn is_default(&self) -> bool {
        matches!(self.policy_type, PolicyType::WHITELIST) && self.admin == Address::ZERO
    }
}

impl PolicyType {
    /// Validates the policy type, checking for invalid values and hardfork rules.
    ///
    /// - `__Invalid`: Always returns error (out-of-range value in storage)
    /// - `COMPOUND`: Only valid on T2+; pre-T2 returns underflow error for backward compatibility
    fn validate(self) -> Result<Self> {
        let is_t2 = StorageCtx.spec().is_t2();

        match self {
            Self::WHITELIST | Self::BLACKLIST => Ok(self),
            Self::COMPOUND if is_t2 => Ok(self),
            Self::COMPOUND => Err(TempoPrecompileError::under_overflow()),
            Self::__Invalid => Err(if is_t2 {
                TIP403RegistryError::invalid_policy_type().into()
            } else {
                TempoPrecompileError::under_overflow()
            }),
        }
    }

    /// Validates and returns the policy type to store, handling backward compatibility.
    ///
    /// Pre-T2: Converts `COMPOUND`/`__Invalid` to `__Invalid` to match original ABI decoding behavior.
    /// T2+: Only allows `WHITELIST` and `BLACKLIST`.
    fn ensure_is_simple(self) -> Result<Self> {
        match self {
            Self::WHITELIST | Self::BLACKLIST => Ok(self),
            Self::COMPOUND | Self::__Invalid => {
                if StorageCtx.spec().is_t2() {
                    Err(TIP403RegistryError::incompatible_policy_type().into())
                } else {
                    Ok(Self::__Invalid)
                }
            }
        }
    }
}

impl Interface for TIP403Registry {
    fn policy_id_counter(&self) -> Result<u64> {
        // Initialize policy ID counter to 2 if it's 0 (skip special policies)
        self.policy_id_counter.read().map(|counter| counter.max(2))
    }

    fn policy_exists(&self, policy_id: u64) -> Result<bool> {
        // Built-in policies (0 and 1) always exist
        if self.builtin_authorization(policy_id).is_some() {
            return Ok(true);
        }

        // Check if policy ID is within the range of created policies
        let counter = self.policy_id_counter()?;
        Ok(policy_id < counter)
    }

    fn policy_data(&self, policy_id: u64) -> Result<(PolicyType, Address)> {
        // Check if policy exists before reading the data (spec: pre-T2)
        if !self.storage.spec().is_t2() && !self.policy_exists(policy_id)? {
            return Err(TIP403RegistryError::policy_not_found().into());
        }

        // Get policy data and verify that the policy id exists (spec: +T2)
        let data = self.get_policy_data(policy_id)?;

        Ok((data.policy_type.validate()?, data.admin))
    }

    /// Returns the compound policy data for a compound policy (TIP-1015)
    fn compound_policy_data(&self, policy_id: u64) -> Result<(u64, u64, u64)> {
        let data = self.get_policy_data(policy_id)?;

        // Only compound policies have compound data
        if !data.is_compound() {
            // Check if the policy exists for error clarity
            let err = if self.policy_exists(policy_id)? {
                TIP403RegistryError::incompatible_policy_type()
            } else {
                TIP403RegistryError::policy_not_found()
            };
            return Err(err.into());
        }

        let compound = self.policy_records[policy_id].compound.read()?;
        Ok((
            compound.sender_policy_id,
            compound.recipient_policy_id,
            compound.mint_recipient_policy_id,
        ))
    }

    fn create_policy(
        &mut self,
        msg_sender: Address,
        admin: Address,
        policy_type: PolicyType,
    ) -> Result<u64> {
        let policy_type = policy_type.ensure_is_simple()?;
        let new_policy_id = self.policy_id_counter()?;

        // Increment counter
        self.policy_id_counter.write(
            new_policy_id
                .checked_add(1)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        // Store policy data
        self.policy_records[new_policy_id]
            .base
            .write(PolicyData { policy_type, admin })?;

        self.emit_event(TIP403RegistryEvent::policy_created(
            new_policy_id,
            msg_sender,
            policy_type,
        ))?;

        self.emit_event(TIP403RegistryEvent::policy_admin_updated(
            new_policy_id,
            msg_sender,
            admin,
        ))?;

        Ok(new_policy_id)
    }

    fn create_policy_with_accounts(
        &mut self,
        msg_sender: Address,
        admin: Address,
        policy_type: PolicyType,
        accounts: Vec<Address>,
    ) -> Result<u64> {
        let policy_type = policy_type.ensure_is_simple()?;
        let new_policy_id = self.policy_id_counter()?;

        // Increment counter
        self.policy_id_counter.write(
            new_policy_id
                .checked_add(1)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        // Store policy data
        self.set_policy_data(new_policy_id, PolicyData { policy_type, admin })?;

        // Set initial accounts - only emit events for valid policy types
        // Pre-T1 with invalid types: accounts are added but no events emitted (matches original)
        for account in accounts.iter() {
            self.set_policy_set(new_policy_id, *account, true)?;

            match policy_type {
                PolicyType::WHITELIST => {
                    self.emit_event(TIP403RegistryEvent::whitelist_updated(
                        new_policy_id,
                        msg_sender,
                        *account,
                        true,
                    ))?;
                }
                PolicyType::BLACKLIST => {
                    self.emit_event(TIP403RegistryEvent::blacklist_updated(
                        new_policy_id,
                        msg_sender,
                        *account,
                        true,
                    ))?;
                }
                ITIP403Registry::PolicyType::COMPOUND | ITIP403Registry::PolicyType::__Invalid => {
                    // T2+: unreachable since `ensure_is_simple` already rejected
                    return Err(TIP403RegistryError::incompatible_policy_type().into());
                }
            }
        }

        self.emit_event(TIP403RegistryEvent::policy_created(
            new_policy_id,
            msg_sender,
            policy_type,
        ))?;

        self.emit_event(TIP403RegistryEvent::policy_admin_updated(
            new_policy_id,
            msg_sender,
            admin,
        ))?;

        Ok(new_policy_id)
    }

    fn set_policy_admin(
        &mut self,
        msg_sender: Address,
        policy_id: u64,
        admin: Address,
    ) -> Result<()> {
        let data = self.get_policy_data(policy_id)?;

        // Check authorization
        if data.admin != msg_sender {
            return Err(TIP403RegistryError::unauthorized().into());
        }

        // Update admin policy ID
        self.set_policy_data(policy_id, PolicyData { admin, ..data })?;

        self.emit_event(TIP403RegistryEvent::policy_admin_updated(
            policy_id, msg_sender, admin,
        ))
    }

    fn modify_policy_whitelist(
        &mut self,
        msg_sender: Address,
        policy_id: u64,
        account: Address,
        allowed: bool,
    ) -> Result<()> {
        let data = self.get_policy_data(policy_id)?;

        // Check authorization
        if data.admin != msg_sender {
            return Err(TIP403RegistryError::unauthorized().into());
        }

        // Check policy type
        if !matches!(data.policy_type.validate()?, PolicyType::WHITELIST) {
            return Err(TIP403RegistryError::incompatible_policy_type().into());
        }

        self.set_policy_set(policy_id, account, allowed)?;

        self.emit_event(TIP403RegistryEvent::whitelist_updated(
            policy_id, msg_sender, account, allowed,
        ))
    }

    fn modify_policy_blacklist(
        &mut self,
        msg_sender: Address,
        policy_id: u64,
        account: Address,
        restricted: bool,
    ) -> Result<()> {
        let data = self.get_policy_data(policy_id)?;

        // Check authorization
        if data.admin != msg_sender {
            return Err(TIP403RegistryError::unauthorized().into());
        }

        // Check policy type
        if !matches!(data.policy_type.validate()?, PolicyType::BLACKLIST) {
            return Err(TIP403RegistryError::incompatible_policy_type().into());
        }

        self.set_policy_set(policy_id, account, restricted)?;

        self.emit_event(TIP403RegistryEvent::blacklist_updated(
            policy_id, msg_sender, account, restricted,
        ))
    }

    /// Creates a new compound policy that references three simple policies (TIP-1015)
    fn create_compound_policy(
        &mut self,
        msg_sender: Address,
        sender_policy_id: u64,
        recipient_policy_id: u64,
        mint_recipient_policy_id: u64,
    ) -> Result<u64> {
        // Validate all referenced policies exist and are simple (not compound)
        self.validate_simple_policy(sender_policy_id)?;
        self.validate_simple_policy(recipient_policy_id)?;
        self.validate_simple_policy(mint_recipient_policy_id)?;

        let new_policy_id = self.policy_id_counter()?;

        // Increment counter
        self.policy_id_counter.write(
            new_policy_id
                .checked_add(1)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        // Store policy record with COMPOUND type and compound data
        self.policy_records[new_policy_id].write(PolicyRecord {
            base: PolicyData {
                policy_type: PolicyType::COMPOUND,
                admin: Address::ZERO,
            },
            compound: CompoundPolicyData {
                sender_policy_id,
                recipient_policy_id,
                mint_recipient_policy_id,
            },
        })?;

        // Emit event
        self.emit_event(TIP403RegistryEvent::compound_policy_created(
            new_policy_id,
            msg_sender,
            sender_policy_id,
            recipient_policy_id,
            mint_recipient_policy_id,
        ))?;

        Ok(new_policy_id)
    }

    fn is_authorized(&self, policy_id: u64, user: Address) -> Result<bool> {
        self.is_authorized_as(policy_id, user, AuthRole::Transfer)
    }

    fn is_authorized_sender(&self, policy_id: u64, user: Address) -> Result<bool> {
        self.is_authorized_as(policy_id, user, AuthRole::Sender)
    }

    fn is_authorized_recipient(&self, policy_id: u64, user: Address) -> Result<bool> {
        self.is_authorized_as(policy_id, user, AuthRole::Recipient)
    }

    fn is_authorized_mint_recipient(&self, policy_id: u64, user: Address) -> Result<bool> {
        self.is_authorized_as(policy_id, user, AuthRole::MintRecipient)
    }
}

impl TIP403Registry {
    /// Initializes the registry contract.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Core role-based authorization check (TIP-1015).
    pub fn is_authorized_as(&self, policy_id: u64, user: Address, role: AuthRole) -> Result<bool> {
        if let Some(auth) = self.builtin_authorization(policy_id) {
            return Ok(auth);
        }

        let data = self.get_policy_data(policy_id)?;

        if data.is_compound() {
            let compound = self.policy_records[policy_id].compound.read()?;
            return match role {
                AuthRole::Sender => self.is_authorized_simple(compound.sender_policy_id, user),
                AuthRole::Recipient => {
                    self.is_authorized_simple(compound.recipient_policy_id, user)
                }
                AuthRole::MintRecipient => {
                    self.is_authorized_simple(compound.mint_recipient_policy_id, user)
                }
                AuthRole::Transfer => {
                    // (spec: +T2) short-circuit and skip recipient check if sender fails
                    let sender_auth = self.is_authorized_simple(compound.sender_policy_id, user)?;
                    if self.storage.spec().is_t2() && !sender_auth {
                        return Ok(false);
                    }
                    let recipient_auth =
                        self.is_authorized_simple(compound.recipient_policy_id, user)?;
                    Ok(sender_auth && recipient_auth)
                }
            };
        }

        self.is_simple(policy_id, user, &data)
    }

    /// Returns authorization result for built-in policies (0 = reject, 1 = allow).
    /// Returns None for user-created policies.
    #[inline]
    fn builtin_authorization(&self, policy_id: u64) -> Option<bool> {
        (policy_id < 2).then_some(policy_id == 1)
    }

    /// Authorization for simple (non-compound) policies only.
    ///
    /// **WARNING:** skips compound check - caller must guarantee policy is simple.
    fn is_authorized_simple(&self, policy_id: u64, user: Address) -> Result<bool> {
        if let Some(auth) = self.builtin_authorization(policy_id) {
            return Ok(auth);
        }
        let data = self.get_policy_data(policy_id)?;
        self.is_simple(policy_id, user, &data)
    }

    /// Authorization check for simple (non-compound) policies
    fn is_simple(&self, policy_id: u64, user: Address, data: &PolicyData) -> Result<bool> {
        // NOTE: read `policy_set` BEFORE checking policy type to match original gas consumption.
        // Pre-T1: the old code read policy_set first, then failed on invalid policy types.
        // This order must be preserved for block re-execution compatibility.
        let is_in_set = self.policy_set[policy_id][user].read()?;

        match data.policy_type.validate()? {
            PolicyType::WHITELIST => Ok(is_in_set),
            PolicyType::BLACKLIST => Ok(!is_in_set),
            PolicyType::COMPOUND | PolicyType::__Invalid => {
                Err(TIP403RegistryError::incompatible_policy_type().into())
            }
        }
    }

    /// Validates that a policy ID references an existing simple policy (not compound)
    fn validate_simple_policy(&self, policy_id: u64) -> Result<()> {
        // Built-in policies (0 and 1) are always valid simple policies
        if self.builtin_authorization(policy_id).is_some() {
            return Ok(());
        }

        // Check if policy exists
        if policy_id >= Interface::policy_id_counter(self)? {
            return Err(TIP403RegistryError::policy_not_found().into());
        }

        // Check if policy is simple (not compound)
        let data = self.get_policy_data(policy_id)?;
        if data.is_compound() {
            return Err(TIP403RegistryError::policy_not_simple().into());
        }

        Ok(())
    }

    // Internal helper functions

    /// Returns policy data for the given policy ID.
    /// Errors with `PolicyNotFound` for invalid policy ids.
    fn get_policy_data(&self, policy_id: u64) -> Result<PolicyData> {
        let data = self.policy_records[policy_id].base.read()?;

        // Verify that the policy id exists (spec: +T2).
        // Skip the counter read (extra SLOAD) when policy data is non-default.
        if self.storage.spec().is_t2()
            && data.is_default()
            && policy_id >= self.policy_id_counter()?
        {
            return Err(TIP403RegistryError::policy_not_found().into());
        }

        Ok(data)
    }

    fn set_policy_data(&mut self, policy_id: u64, data: PolicyData) -> Result<()> {
        self.policy_records[policy_id].base.write(data)
    }

    fn set_policy_set(&mut self, policy_id: u64, account: Address, value: bool) -> Result<()> {
        self.policy_set[policy_id][account].write(value)
    }
}

impl AuthRole {
    #[inline]
    fn transfer_or(t2_variant: Self) -> Self {
        if StorageCtx.spec().is_t2() {
            t2_variant
        } else {
            Self::Transfer
        }
    }

    /// Hardfork-aware: always returns `Transfer`.
    pub fn transfer() -> Self {
        Self::Transfer
    }

    /// Hardfork-aware: returns `Sender` for T2+, `Transfer` for pre-T2.
    pub fn sender() -> Self {
        Self::transfer_or(Self::Sender)
    }

    /// Hardfork-aware: returns `Recipient` for T2+, `Transfer` for pre-T2.
    pub fn recipient() -> Self {
        Self::transfer_or(Self::Recipient)
    }

    /// Hardfork-aware: returns `MintRecipient` for T2+, `Transfer` for pre-T2.
    pub fn mint_recipient() -> Self {
        Self::transfer_or(Self::MintRecipient)
    }
}

#[cfg(test)]
mod tests {
    use super::{abi::ITIP403Registry::Interface, *};
    use crate::{
        error::TempoPrecompileError,
        storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
    };
    use alloy::{
        primitives::{Address, Log},
        sol_types::SolEvent,
    };
    use rand_08::Rng;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::TIP403_REGISTRY_ADDRESS;

    #[test]
    fn test_create_policy() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Initial counter should be 2 (skipping special policies)
            assert_eq!(Interface::policy_id_counter(&registry)?, 2);

            // Create a whitelist policy
            let result = registry.create_policy(admin, admin, PolicyType::WHITELIST);
            assert!(result.is_ok());
            assert_eq!(result?, 2);

            // Counter should be incremented
            assert_eq!(Interface::policy_id_counter(&registry)?, 3);

            // Check policy data
            let (policy_type, policy_admin) = Interface::policy_data(&registry, 2)?;
            assert_eq!(policy_type, PolicyType::WHITELIST);
            assert_eq!(policy_admin, admin);
            Ok(())
        })
    }

    #[test]
    fn test_is_authorized_special_policies() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let registry = TIP403Registry::new();

            // Policy 0 should always reject
            assert!(!registry.is_authorized_as(0, user, AuthRole::Transfer)?);

            // Policy 1 should always allow
            assert!(registry.is_authorized_as(1, user, AuthRole::Transfer)?);
            Ok(())
        })
    }

    #[test]
    fn test_whitelist_policy() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Create whitelist policy
            let policy_id = registry.create_policy(admin, admin, PolicyType::WHITELIST)?;

            // User should not be authorized initially
            assert!(!registry.is_authorized_as(policy_id, user, AuthRole::Transfer)?);

            // Add user to whitelist
            registry.modify_policy_whitelist(admin, policy_id, user, true)?;

            // User should now be authorized
            assert!(registry.is_authorized_as(policy_id, user, AuthRole::Transfer)?);

            Ok(())
        })
    }

    #[test]
    fn test_blacklist_policy() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Create blacklist policy
            let policy_id = registry.create_policy(admin, admin, PolicyType::BLACKLIST)?;

            // User should be authorized initially (not in blacklist)
            assert!(registry.is_authorized_as(policy_id, user, AuthRole::Transfer)?);

            // Add user to blacklist
            registry.modify_policy_blacklist(admin, policy_id, user, true)?;

            // User should no longer be authorized
            assert!(!registry.is_authorized_as(policy_id, user, AuthRole::Transfer)?);

            Ok(())
        })
    }

    #[test]
    fn test_policy_data_reverts_for_non_existent_policy() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let registry = TIP403Registry::new();

            // Test that querying a non-existent policy ID reverts
            let result = Interface::policy_data(&registry, 100);
            assert!(result.is_err());

            // Verify the error is PolicyNotFound
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::TIP403RegistryError(TIP403RegistryError::PolicyNotFound(_))
            ));

            Ok(())
        })
    }

    #[test]
    fn test_policy_exists() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Special policies 0 and 1 always exist
            assert!(Interface::policy_exists(&registry, 0)?);
            assert!(Interface::policy_exists(&registry, 1)?);

            // Test 100 random policy IDs > 1 should not exist initially
            let mut rng = rand_08::thread_rng();
            for _ in 0..100 {
                let random_policy_id = rng.gen_range(2..u64::MAX);
                assert!(!Interface::policy_exists(&registry, random_policy_id)?);
            }

            // Create 50 policies
            let mut created_policy_ids = Vec::new();
            for i in 0..50 {
                let policy_type = if i % 2 == 0 {
                    PolicyType::WHITELIST
                } else {
                    PolicyType::BLACKLIST
                };
                let policy_id = registry.create_policy(admin, admin, policy_type)?;
                created_policy_ids.push(policy_id);
            }

            // All created policies should exist
            for policy_id in &created_policy_ids {
                assert!(Interface::policy_exists(&registry, *policy_id)?);
            }

            Ok(())
        })
    }

    // =========================================================================
    //                      TIP-1015: Compound Policy Tests
    // =========================================================================

    #[test]
    fn test_create_compound_policy() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let admin = Address::random();
        let creator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Create two simple policies to reference
            let sender_policy = registry.create_policy(admin, admin, PolicyType::WHITELIST)?;
            let recipient_policy = registry.create_policy(admin, admin, PolicyType::BLACKLIST)?;
            let mint_recipient_policy =
                registry.create_policy(admin, admin, PolicyType::WHITELIST)?;

            // Create compound policy
            let compound_id = registry.create_compound_policy(
                creator,
                sender_policy,
                recipient_policy,
                mint_recipient_policy,
            )?;

            // Verify compound policy exists
            assert!(Interface::policy_exists(&registry, compound_id)?);

            // Verify policy type is COMPOUND
            let (policy_type, policy_admin) = Interface::policy_data(&registry, compound_id)?;
            assert_eq!(policy_type, PolicyType::COMPOUND);
            assert_eq!(policy_admin, Address::ZERO); // Compound policies have no admin

            // Verify compound policy data
            let (sender_id, recipient_id, mint_recipient_id) =
                Interface::compound_policy_data(&registry, compound_id)?;
            assert_eq!(sender_id, sender_policy);
            assert_eq!(recipient_id, recipient_policy);
            assert_eq!(mint_recipient_id, mint_recipient_policy);

            Ok(())
        })
    }

    #[test]
    fn test_compound_policy_rejects_non_existent_refs() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1);
        let creator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Try to create compound policy with non-existent policy IDs
            let result = registry.create_compound_policy(creator, 999, 1, 1);
            assert!(result.is_err());

            Ok(())
        })
    }

    #[test]
    fn test_compound_policy_rejects_compound_refs() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1);
        let admin = Address::random();
        let creator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Create a simple policy
            let simple_policy = registry.create_policy(admin, admin, PolicyType::WHITELIST)?;

            // Create a compound policy
            let compound_id = registry.create_compound_policy(creator, 1, simple_policy, 1)?;

            // Try to create another compound policy referencing the first compound
            let result = registry.create_compound_policy(
                creator,
                compound_id, // This should fail - can't reference compound
                1,
                1,
            );
            assert!(result.is_err());

            Ok(())
        })
    }

    #[test]
    fn test_compound_policy_sender_recipient_differentiation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1);
        let admin = Address::random();
        let creator = Address::random();
        let alice = Address::random();
        let bob = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Create sender whitelist (only Alice can send)
            let sender_policy = registry.create_policy(admin, admin, PolicyType::WHITELIST)?;
            registry.modify_policy_whitelist(admin, sender_policy, alice, true)?;

            // Create recipient whitelist (only Bob can receive)
            let recipient_policy = registry.create_policy(admin, admin, PolicyType::WHITELIST)?;
            registry.modify_policy_whitelist(admin, recipient_policy, bob, true)?;

            // Create compound policy
            let compound_id = registry.create_compound_policy(
                creator,
                sender_policy,
                recipient_policy,
                1, // anyone can receive mints
            )?;

            // Alice can send (is in sender whitelist)
            assert!(registry.is_authorized_as(compound_id, alice, AuthRole::Sender)?);

            // Bob cannot send (not in sender whitelist)
            assert!(!registry.is_authorized_as(compound_id, bob, AuthRole::Sender)?);

            // Bob can receive (is in recipient whitelist)
            assert!(registry.is_authorized_as(compound_id, bob, AuthRole::Recipient)?);

            // Alice cannot receive (not in recipient whitelist)
            assert!(!registry.is_authorized_as(compound_id, alice, AuthRole::Recipient)?);

            // Anyone can receive mints (mintRecipientPolicyId = 1 = always-allow)
            assert!(registry.is_authorized_as(compound_id, alice, AuthRole::MintRecipient)?);
            assert!(registry.is_authorized_as(compound_id, bob, AuthRole::MintRecipient)?);

            Ok(())
        })
    }

    #[test]
    fn test_compound_policy_is_authorized_behavior() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1);
        let admin = Address::random();
        let creator = Address::random();
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Create sender whitelist with user
            let sender_policy = registry.create_policy(admin, admin, PolicyType::WHITELIST)?;
            registry.modify_policy_whitelist(admin, sender_policy, user, true)?;

            // Create recipient whitelist WITHOUT user
            let recipient_policy = registry.create_policy(admin, admin, PolicyType::WHITELIST)?;

            // Create compound policy
            let compound_id =
                registry.create_compound_policy(creator, sender_policy, recipient_policy, 1)?;

            // isAuthorized should be sender && recipient
            // User is sender-authorized but NOT recipient-authorized
            assert!(registry.is_authorized_as(compound_id, user, AuthRole::Sender)?);
            assert!(!registry.is_authorized_as(compound_id, user, AuthRole::Recipient)?);

            // isAuthorized = sender && recipient = true && false = false
            assert!(!registry.is_authorized_as(compound_id, user, AuthRole::Transfer)?);

            // Now add user to recipient whitelist
            registry.modify_policy_whitelist(admin, recipient_policy, user, true)?;

            // Now isAuthorized = sender && recipient = true && true = true
            assert!(registry.is_authorized_as(compound_id, user, AuthRole::Transfer)?);

            Ok(())
        })
    }

    #[test]
    fn test_compound_policy_is_authorized_transfer() -> eyre::Result<()> {
        let admin = Address::random();
        let creator = Address::random();
        let user = Address::random();

        for hardfork in [TempoHardfork::T0, TempoHardfork::T1] {
            let mut storage = HashMapStorageProvider::new_with_spec(1, hardfork);

            StorageCtx::enter(&mut storage, || {
                let mut registry = TIP403Registry::new();

                // Create sender and recipient whitelists
                let sender_policy = registry.create_policy(admin, admin, PolicyType::WHITELIST)?;
                let recipient_policy =
                    registry.create_policy(admin, admin, PolicyType::WHITELIST)?;

                // Create compound policy
                let compound_id =
                    registry.create_compound_policy(creator, sender_policy, recipient_policy, 1)?;

                // User not in sender whitelist, but in recipient whitelist
                registry.modify_policy_whitelist(admin, recipient_policy, user, true)?;
                assert!(!registry.is_authorized_as(compound_id, user, AuthRole::Transfer)?);

                // User in sender whitelist, not in recipient whitelist
                registry.modify_policy_whitelist(admin, sender_policy, user, true)?;
                registry.modify_policy_whitelist(admin, recipient_policy, user, false)?;
                assert!(!registry.is_authorized_as(compound_id, user, AuthRole::Transfer)?);

                // User in both whitelists
                registry.modify_policy_whitelist(admin, recipient_policy, user, true)?;
                assert!(registry.is_authorized_as(compound_id, user, AuthRole::Transfer)?);

                Ok::<_, TempoPrecompileError>(())
            })?;
        }

        Ok(())
    }

    #[test]
    fn test_simple_policy_equivalence() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1);
        let admin = Address::random();
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Create a simple whitelist policy with user
            let policy_id = registry.create_policy(admin, admin, PolicyType::WHITELIST)?;
            registry.modify_policy_whitelist(admin, policy_id, user, true)?;

            // For simple policies, all four authorization functions should return the same result
            let is_authorized = registry.is_authorized_as(policy_id, user, AuthRole::Transfer)?;
            let is_sender = registry.is_authorized_as(policy_id, user, AuthRole::Sender)?;
            let is_recipient = registry.is_authorized_as(policy_id, user, AuthRole::Recipient)?;
            let is_mint_recipient =
                registry.is_authorized_as(policy_id, user, AuthRole::MintRecipient)?;

            assert!(is_authorized);
            assert_eq!(is_authorized, is_sender);
            assert_eq!(is_sender, is_recipient);
            assert_eq!(is_recipient, is_mint_recipient);

            Ok(())
        })
    }

    #[test]
    fn test_compound_policy_with_builtin_policies() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1);
        let creator = Address::random();
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Create compound policy using built-in policies
            // senderPolicyId = 1 (always-allow)
            // recipientPolicyId = 0 (always-reject)
            // mintRecipientPolicyId = 1 (always-allow)
            let compound_id = registry.create_compound_policy(creator, 1, 0, 1)?;

            // Anyone can send (policy 1 = always-allow)
            assert!(registry.is_authorized_as(compound_id, user, AuthRole::Sender)?);

            // No one can receive transfers (policy 0 = always-reject)
            assert!(!registry.is_authorized_as(compound_id, user, AuthRole::Recipient)?);

            // Anyone can receive mints (policy 1 = always-allow)
            assert!(registry.is_authorized_as(compound_id, user, AuthRole::MintRecipient)?);

            // isAuthorized = sender && recipient = true && false = false
            assert!(!registry.is_authorized_as(compound_id, user, AuthRole::Transfer)?);

            Ok(())
        })
    }

    #[test]
    fn test_vendor_credits_use_case() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1);
        let admin = Address::random();
        let creator = Address::random();
        let vendor = Address::random();
        let customer = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Create vendor whitelist (only vendor can receive transfers)
            let vendor_whitelist = registry.create_policy(admin, admin, PolicyType::WHITELIST)?;
            registry.modify_policy_whitelist(admin, vendor_whitelist, vendor, true)?;

            // Create compound policy for vendor credits:
            // - Anyone can send (senderPolicyId = 1)
            // - Only vendor can receive transfers (recipientPolicyId = vendor_whitelist)
            // - Anyone can receive mints (mintRecipientPolicyId = 1)
            let compound_id = registry.create_compound_policy(creator, 1, vendor_whitelist, 1)?;

            // Minting: anyone can receive mints (customer gets credits)
            assert!(registry.is_authorized_as(compound_id, customer, AuthRole::MintRecipient)?);

            // Transfer: customer can send
            assert!(registry.is_authorized_as(compound_id, customer, AuthRole::Sender)?);

            // Transfer: only vendor can receive
            assert!(registry.is_authorized_as(compound_id, vendor, AuthRole::Recipient)?);
            // customer cannot receive transfers (no P2P)
            assert!(!registry.is_authorized_as(compound_id, customer, AuthRole::Recipient)?);

            Ok(())
        })
    }

    #[test]
    fn test_policy_data_rejects_compound_policy_on_pre_t1() -> eyre::Result<()> {
        let creator = Address::random();

        // First, create a compound policy on T1
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1);
        let compound_id = StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();
            registry.create_compound_policy(creator, 1, 1, 1)
        })?;

        // Now downgrade to T0 and try to read the compound policy data
        let mut storage = storage.with_spec(TempoHardfork::T0);
        StorageCtx::enter(&mut storage, || {
            let registry = TIP403Registry::new();

            let result = registry.policy_data(compound_id);
            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), TempoPrecompileError::under_overflow());

            Ok(())
        })
    }

    #[test]
    fn test_create_policy_rejects_non_simple_policy_types() -> eyre::Result<()> {
        let admin = Address::random();

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            let result = registry.create_policy(admin, admin, PolicyType::COMPOUND);
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::TIP403RegistryError(
                    TIP403RegistryError::IncompatiblePolicyType(_)
                )
            ));

            Ok(())
        })
    }

    #[test]
    fn test_create_policy_with_accounts_rejects_non_simple_policy_types() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1);
        let admin = Address::random();
        let account = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            let result = registry.create_policy_with_accounts(
                admin,
                admin,
                PolicyType::COMPOUND,
                vec![account],
            );
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::TIP403RegistryError(
                    TIP403RegistryError::IncompatiblePolicyType(_)
                )
            ));

            Ok(())
        })
    }

    // =========================================================================
    //                Pre-T1 Backward Compatibility Tests
    // =========================================================================

    #[test]
    fn test_pre_t1_create_policy_with_compound_type_stores_255() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T0);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Pre-T1: COMPOUND should succeed but store as 255
            let policy_id = registry.create_policy(admin, admin, PolicyType::COMPOUND)?;

            // Verify policy was created
            assert!(registry.policy_exists(policy_id)?);

            // Verify the stored policy_type is 255
            let data = registry.get_policy_data(policy_id)?;
            assert_eq!(data.policy_type, PolicyType::__Invalid);

            Ok(())
        })
    }

    #[test]
    fn test_pre_t1_create_policy_with_valid_types_stores_correct_value() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T0);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // WHITELIST should store as 0
            let whitelist_id = registry.create_policy(admin, admin, PolicyType::WHITELIST)?;
            let data = registry.get_policy_data(whitelist_id)?;
            assert_eq!(data.policy_type, PolicyType::WHITELIST);

            // BLACKLIST should store as 1
            let blacklist_id = registry.create_policy(admin, admin, PolicyType::BLACKLIST)?;
            let data = registry.get_policy_data(blacklist_id)?;
            assert_eq!(data.policy_type, PolicyType::BLACKLIST);

            Ok(())
        })
    }

    #[test]
    fn test_pre_t1_create_policy_with_accounts_compound_type_behavior() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T0);
        let (admin, account) = (Address::random(), Address::random());

        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // With non-empty accounts: reverts with IncompatiblePolicyType
            let result = registry.create_policy_with_accounts(
                admin,
                admin,
                PolicyType::COMPOUND,
                vec![account],
            );
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::TIP403RegistryError(
                    TIP403RegistryError::IncompatiblePolicyType(_)
                )
            ));

            // With empty accounts: succeeds (loop never enters revert path)
            let policy_id =
                registry.create_policy_with_accounts(admin, admin, PolicyType::COMPOUND, vec![])?;
            let data = registry.get_policy_data(policy_id)?;
            assert_eq!(data.policy_type, PolicyType::__Invalid);

            Ok(())
        })
    }

    #[test]
    fn test_pre_t1_policy_data_reverts_for_any_policy_type_gte_2() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T0);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Create a policy with COMPOUND type (will be stored as 255)
            let policy_id = registry.create_policy(admin, admin, PolicyType::COMPOUND)?;

            // policy_data should revert for policy_type >= 2 on pre-T1
            let result = registry.policy_data(policy_id);
            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), TempoPrecompileError::under_overflow());

            Ok(())
        })
    }

    #[test]
    fn test_pre_t1_is_authorized_reverts_for_compound_policy_type() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T0);
        let admin = Address::random();
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Create a policy with COMPOUND type (stored as 255)
            let policy_id = registry.create_policy(admin, admin, PolicyType::COMPOUND)?;

            // is_authorized should revert for policy_type >= 2 on pre-T1
            let result = registry.is_authorized_as(policy_id, user, AuthRole::Transfer);
            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), TempoPrecompileError::under_overflow());

            Ok(())
        })
    }

    #[test]
    fn test_pre_t2_to_t2_migration_compound_policy_still_fails() -> eyre::Result<()> {
        // Create a policy with COMPOUND type on pre-T2 (stored as 255)
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T0);
        let admin = Address::random();
        let user = Address::random();

        let policy_id = StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();
            registry.create_policy(admin, admin, PolicyType::COMPOUND)
        })?;

        // Upgrade to T2 and try to use the policy
        let mut storage = storage.with_spec(TempoHardfork::T2);
        StorageCtx::enter(&mut storage, || {
            let registry = TIP403Registry::new();

            // policy_data should fail with InvalidPolicyType on T2
            let result = registry.policy_data(policy_id);
            assert!(result.is_err());
            assert_eq!(
                result.unwrap_err(),
                TIP403RegistryError::invalid_policy_type().into()
            );

            // is_authorized should also fail with InvalidPolicyType on T2
            let result = registry.is_authorized_as(policy_id, user, AuthRole::Transfer);
            assert!(result.is_err());
            assert_eq!(
                result.unwrap_err(),
                TIP403RegistryError::invalid_policy_type().into()
            );

            Ok(())
        })
    }

    #[test]
    fn test_t2_validate_policy_type_returns_correct_u8() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // WHITELIST should store as 0
            let whitelist_id = registry.create_policy(admin, admin, PolicyType::WHITELIST)?;
            let data = registry.get_policy_data(whitelist_id)?;
            assert_eq!(data.policy_type, PolicyType::WHITELIST);

            // BLACKLIST should store as 1
            let blacklist_id = registry.create_policy(admin, admin, PolicyType::BLACKLIST)?;
            let data = registry.get_policy_data(blacklist_id)?;
            assert_eq!(data.policy_type, PolicyType::BLACKLIST);

            Ok(())
        })
    }

    #[test]
    fn test_is_simple_errors_on_compound_policy_type_t2() -> eyre::Result<()> {
        // This test verifies that is_simple explicitly errors for COMPOUND
        // (stored as 255 on pre-T2) rather than returning false.
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T0);
        let admin = Address::random();
        let user = Address::random();

        // Create policy with COMPOUND on pre-T2 (stores as 255)
        let policy_id = StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();
            registry.create_policy(admin, admin, PolicyType::COMPOUND)
        })?;

        // Now on T2, is_authorized should error with InvalidPolicyType
        let mut storage = storage.with_spec(TempoHardfork::T2);
        StorageCtx::enter(&mut storage, || {
            let registry = TIP403Registry::new();

            let result = registry.is_authorized_as(policy_id, user, AuthRole::Transfer);
            assert_eq!(
                result.unwrap_err(),
                TIP403RegistryError::invalid_policy_type().into()
            );

            Ok(())
        })
    }

    #[test]
    fn test_pre_t1_whitelist_and_blacklist_work_normally() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T0);
        let admin = Address::random();
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Create and test whitelist on pre-T1
            let whitelist_id = registry.create_policy(admin, admin, PolicyType::WHITELIST)?;

            // User not authorized initially
            assert!(!registry.is_authorized_as(whitelist_id, user, AuthRole::Transfer)?);

            // Add to whitelist
            registry.modify_policy_whitelist(admin, whitelist_id, user, true)?;

            // Now authorized
            assert!(registry.is_authorized_as(whitelist_id, user, AuthRole::Transfer)?);

            // Create and test blacklist on pre-T1
            let blacklist_id = registry.create_policy(admin, admin, PolicyType::BLACKLIST)?;

            // User authorized initially (not in blacklist)
            assert!(registry.is_authorized_as(blacklist_id, user, AuthRole::Transfer)?);

            // Add to blacklist
            registry.modify_policy_blacklist(admin, blacklist_id, user, true)?;

            // Now not authorized
            assert!(!registry.is_authorized_as(blacklist_id, user, AuthRole::Transfer)?);

            Ok(())
        })
    }

    #[test]
    fn test_pre_t1_create_policy_event_emits_compound_stored_as_255() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T0);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            let policy_id = registry.create_policy(admin, admin, PolicyType::COMPOUND)?;

            let data = registry.get_policy_data(policy_id)?;
            assert_eq!(data.policy_type, PolicyType::__Invalid);

            Ok::<_, TempoPrecompileError>(())
        })?;

        let events = storage.events.get(&TIP403_REGISTRY_ADDRESS).unwrap();
        let policy_created_event = &events[0];

        // The raw event data contains the policy type as a u8
        // On pre-T1, COMPOUND (value >= 2) maps to __Invalid (255) in storage
        // The event now correctly emits __Invalid since we store and emit PolicyType directly
        let decoded = ITIP403Registry::PolicyCreated::decode_log(&Log::new_unchecked(
            TIP403_REGISTRY_ADDRESS,
            policy_created_event.topics().to_vec(),
            policy_created_event.data.clone(),
        ))?;

        // The emitted policyType is __Invalid (255) matching what's stored
        assert_eq!(decoded.policy_type, PolicyType::__Invalid);

        Ok(())
    }

    #[test]
    fn test_t2_create_policy_rejects_compound_type() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            let result = registry.create_policy(admin, admin, PolicyType::COMPOUND);
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::TIP403RegistryError(
                    TIP403RegistryError::IncompatiblePolicyType(_)
                )
            ));

            Ok(())
        })
    }

    #[test]
    fn test_t2_create_policy_emits_correct_type() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            registry.create_policy(admin, admin, PolicyType::WHITELIST)?;
            registry.create_policy(admin, admin, PolicyType::BLACKLIST)?;

            Ok::<_, TempoPrecompileError>(())
        })?;

        let events = storage.events.get(&TIP403_REGISTRY_ADDRESS).unwrap();

        // events[0] = PolicyCreated, events[1] = PolicyAdminUpdated, events[2] = PolicyCreated
        let whitelist_log = Log::new_unchecked(
            TIP403_REGISTRY_ADDRESS,
            events[0].topics().to_vec(),
            events[0].data.clone(),
        );
        let whitelist_decoded = ITIP403Registry::PolicyCreated::decode_log(&whitelist_log)?;
        assert_eq!(
            whitelist_decoded.policy_type,
            ITIP403Registry::PolicyType::WHITELIST
        );

        let blacklist_log = Log::new_unchecked(
            TIP403_REGISTRY_ADDRESS,
            events[2].topics().to_vec(),
            events[2].data.clone(),
        );
        let blacklist_decoded = ITIP403Registry::PolicyCreated::decode_log(&blacklist_log)?;
        assert_eq!(
            blacklist_decoded.policy_type,
            ITIP403Registry::PolicyType::BLACKLIST
        );

        Ok(())
    }

    #[test]
    fn test_compound_policy_data_error_cases() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Non-existent policy should return PolicyNotFound
            let result = registry.compound_policy_data(999);
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::TIP403RegistryError(TIP403RegistryError::PolicyNotFound(_))
            ));

            // Simple policy should return IncompatiblePolicyType
            let simple_policy_id = registry.create_policy(admin, admin, PolicyType::WHITELIST)?;
            let result = registry.compound_policy_data(simple_policy_id);
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::TIP403RegistryError(
                    TIP403RegistryError::IncompatiblePolicyType(_)
                )
            ));

            Ok(())
        })
    }

    #[test]
    fn test_compound_policy_type_behavior() -> eyre::Result<()> {
        // Create a policy with COMPOUND type on pre-T2 (stored as 255)
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T0);
        let admin = Address::random();
        let user = Address::random();

        let policy_id = StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();
            registry.create_policy(admin, admin, PolicyType::COMPOUND)
        })?;

        // Pre-T2: should return under_overflow error
        StorageCtx::enter(&mut storage, || {
            let registry = TIP403Registry::new();

            let result = registry.policy_data(policy_id);
            assert_eq!(result.unwrap_err(), TempoPrecompileError::under_overflow());

            let result = registry.is_authorized_as(policy_id, user, AuthRole::Transfer);
            assert_eq!(result.unwrap_err(), TempoPrecompileError::under_overflow());

            Ok::<_, TempoPrecompileError>(())
        })?;

        // T2+: should return InvalidPolicyType error
        let mut storage = storage.with_spec(TempoHardfork::T2);
        StorageCtx::enter(&mut storage, || {
            let registry = TIP403Registry::new();

            let result = registry.policy_data(policy_id);
            assert_eq!(
                result.unwrap_err(),
                TIP403RegistryError::invalid_policy_type().into()
            );

            let result = registry.is_authorized_as(policy_id, user, AuthRole::Transfer);
            assert_eq!(
                result.unwrap_err(),
                TIP403RegistryError::invalid_policy_type().into()
            );

            Ok(())
        })
    }

    #[test]
    fn test_policy_data_encode_to_slot_returns_correct_value() -> eyre::Result<()> {
        let admin = Address::random();
        let policy_data = PolicyData {
            policy_type: PolicyType::WHITELIST,
            admin,
        };

        let encoded = policy_data.encode_to_slot();

        // Decode it back and verify
        let decoded = PolicyData::decode_from_slot(encoded);
        assert_eq!(decoded.policy_type, policy_data.policy_type);
        assert_eq!(decoded.admin, policy_data.admin);

        // Verify encoded is NOT default (all zeros)
        assert_ne!(
            encoded,
            U256::ZERO,
            "encode_to_slot should return non-default value for valid policy data"
        );

        Ok(())
    }

    #[test]
    fn test_initialize_sets_storage_state() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Before init, should not be initialized
            assert!(!registry.is_initialized()?);

            // Initialize
            registry.initialize()?;

            // After init, should be initialized
            assert!(registry.is_initialized()?);

            // New handle should still see initialized state
            let registry2 = TIP403Registry::new();
            assert!(registry2.is_initialized()?);

            Ok(())
        })
    }

    #[test]
    fn test_policy_exists_boundary_at_counter() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Create a policy to get policy_id = 2 (counter starts at 2)
            let policy_id = registry.create_policy(admin, admin, PolicyType::WHITELIST)?;

            // The counter should now be 3
            let counter = registry.policy_id_counter()?;
            assert_eq!(counter, 3);

            // Policy at counter - 1 should exist
            assert!(registry.policy_exists(policy_id)?);

            // Policy at exactly counter should NOT exist (tests < vs <=)
            assert!(!registry.policy_exists(counter)?);

            // Policy at counter + 1 should NOT exist
            assert!(!registry.policy_exists(counter + 1)?);

            Ok(())
        })
    }

    #[test]
    fn test_nonexistent_policy_behavior() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1);
        let user = Address::random();
        let nonexistent_id = 999;

        // Pre-T2: silently returns default data / false
        StorageCtx::enter(&mut storage, || -> Result<()> {
            let registry = TIP403Registry::new();
            let data = registry.get_policy_data(nonexistent_id)?;
            assert!(data.is_default());
            assert!(!registry.is_authorized_as(nonexistent_id, user, AuthRole::Transfer)?);
            Ok(())
        })?;

        // T2: reverts with `PolicyNotFound`
        let mut storage = storage.with_spec(TempoHardfork::T2);
        StorageCtx::enter(&mut storage, || {
            let registry = TIP403Registry::new();
            assert_eq!(
                registry.get_policy_data(nonexistent_id).unwrap_err(),
                TIP403RegistryError::policy_not_found().into()
            );
            assert_eq!(
                registry
                    .is_authorized_as(nonexistent_id, user, AuthRole::Transfer)
                    .unwrap_err(),
                TIP403RegistryError::policy_not_found().into()
            );
            Ok(())
        })
    }
}
