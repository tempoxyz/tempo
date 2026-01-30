pub mod dispatch;

pub use tempo_contracts::precompiles::{ITIP403Registry, TIP403RegistryError, TIP403RegistryEvent};
use tempo_precompiles_macros::{Storable, contract};

use crate::{
    TIP403_REGISTRY_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping},
};
use alloy::primitives::{Address, U256};

#[contract(addr = TIP403_REGISTRY_ADDRESS)]
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
/// - Directional roles (`Sender`, `Recipient`, `MintRecipient`) for compound policies available since `T1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRole {
    /// Check both sender AND recipient. Used for `isAuthorized` calls (spec: pre T1).
    Transfer,
    /// Check sender authorization only (spec: +T1).
    Sender,
    /// Check recipient authorization only (spec: +T1).
    Recipient,
    /// Check mint recipient authorization only (spec: +T1).
    MintRecipient,
}

#[derive(Debug, Clone, Storable)]
pub struct PolicyData {
    // NOTE: enums are defined as u8, and leverage the sol! macro's `TryInto<u8>` impl
    pub policy_type: u8,
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
            &self.policy_type,
            PT_LOC.offset_bytes,
            PT_LOC.size,
        )
        .expect("unable to insert 'policy_type'");

        insert_into_word(encoded, &self.admin, A_LOC.offset_bytes, A_LOC.size)
            .expect("unable to insert 'admin'")
    }

    /// Returns `true` if the policy data indicates a compound policy
    fn is_compound(&self) -> bool {
        self.policy_type == ITIP403Registry::PolicyType::COMPOUND as u8
    }
}

impl TIP403Registry {
    /// Initializes the registry contract.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    // View functions
    pub fn policy_id_counter(&self) -> Result<u64> {
        // Initialize policy ID counter to 2 if it's 0 (skip special policies)
        self.policy_id_counter.read().map(|counter| counter.max(2))
    }

    pub fn policy_exists(&self, call: ITIP403Registry::policyExistsCall) -> Result<bool> {
        // Built-in policies (0 and 1) always exist
        if self.builtin_authorization(call.policyId).is_some() {
            return Ok(true);
        }

        // Check if policy ID is within the range of created policies
        let counter = self.policy_id_counter()?;
        Ok(call.policyId < counter)
    }

    pub fn policy_data(
        &self,
        call: ITIP403Registry::policyDataCall,
    ) -> Result<ITIP403Registry::policyDataReturn> {
        // Check if policy exists before returning data
        if !self.policy_exists(ITIP403Registry::policyExistsCall {
            policyId: call.policyId,
        })? {
            return Err(TIP403RegistryError::policy_not_found().into());
        }

        let data = self.get_policy_data(call.policyId)?;

        if data.is_compound() && !self.storage.spec().is_t1() {
            return Err(TempoPrecompileError::under_overflow());
        }

        Ok(ITIP403Registry::policyDataReturn {
            policyType: data
                .policy_type
                .try_into()
                .map_err(|_| TempoPrecompileError::under_overflow())?,
            admin: data.admin,
        })
    }

    /// Returns the compound policy data for a compound policy (TIP-1015)
    pub fn compound_policy_data(
        &self,
        call: ITIP403Registry::compoundPolicyDataCall,
    ) -> Result<ITIP403Registry::compoundPolicyDataReturn> {
        let data = self.get_policy_data(call.policyId)?;

        // Only compound policies have compound data
        if !data.is_compound() {
            return Err(TIP403RegistryError::incompatible_policy_type().into());
        }

        let compound = self.policy_records[call.policyId].compound.read()?;
        Ok(ITIP403Registry::compoundPolicyDataReturn {
            senderPolicyId: compound.sender_policy_id,
            recipientPolicyId: compound.recipient_policy_id,
            mintRecipientPolicyId: compound.mint_recipient_policy_id,
        })
    }

    // State-changing functions
    pub fn create_policy(
        &mut self,
        msg_sender: Address,
        call: ITIP403Registry::createPolicyCall,
    ) -> Result<u64> {
        if self.storage.spec().is_t1()
            && matches!(
                call.policyType,
                ITIP403Registry::PolicyType::COMPOUND | ITIP403Registry::PolicyType::__Invalid
            )
        {
            // COMPOUND policies are created via createCompoundPolicy
            return Err(TIP403RegistryError::incompatible_policy_type().into());
        }

        let new_policy_id = self.policy_id_counter()?;

        // Increment counter
        self.policy_id_counter.write(
            new_policy_id
                .checked_add(1)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        // Store policy data
        self.policy_records[new_policy_id].base.write(PolicyData {
            policy_type: call.policyType as u8,
            admin: call.admin,
        })?;

        // Emit events
        self.emit_event(TIP403RegistryEvent::PolicyCreated(
            ITIP403Registry::PolicyCreated {
                policyId: new_policy_id,
                updater: msg_sender,
                policyType: call.policyType,
            },
        ))?;

        self.emit_event(TIP403RegistryEvent::PolicyAdminUpdated(
            ITIP403Registry::PolicyAdminUpdated {
                policyId: new_policy_id,
                updater: msg_sender,
                admin: call.admin,
            },
        ))?;

        Ok(new_policy_id)
    }

    pub fn create_policy_with_accounts(
        &mut self,
        msg_sender: Address,
        call: ITIP403Registry::createPolicyWithAccountsCall,
    ) -> Result<u64> {
        let (admin, policy_type) = (call.admin, call.policyType);
        let new_policy_id = self.policy_id_counter()?;

        // Increment counter
        self.policy_id_counter.write(
            new_policy_id
                .checked_add(1)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        // Store policy data
        self.set_policy_data(
            new_policy_id,
            PolicyData {
                policy_type: policy_type as u8,
                admin,
            },
        )?;

        // Set initial accounts
        for account in call.accounts.iter() {
            self.set_policy_set(new_policy_id, *account, true)?;

            match policy_type {
                ITIP403Registry::PolicyType::WHITELIST => {
                    self.emit_event(TIP403RegistryEvent::WhitelistUpdated(
                        ITIP403Registry::WhitelistUpdated {
                            policyId: new_policy_id,
                            updater: msg_sender,
                            account: *account,
                            allowed: true,
                        },
                    ))?;
                }
                ITIP403Registry::PolicyType::BLACKLIST => {
                    self.emit_event(TIP403RegistryEvent::BlacklistUpdated(
                        ITIP403Registry::BlacklistUpdated {
                            policyId: new_policy_id,
                            updater: msg_sender,
                            account: *account,
                            restricted: true,
                        },
                    ))?;
                }
                ITIP403Registry::PolicyType::COMPOUND | ITIP403Registry::PolicyType::__Invalid => {
                    // COMPOUND policies are created via createCompoundPolicy
                    return Err(TIP403RegistryError::incompatible_policy_type().into());
                }
            }
        }

        // Emit policy creation events
        self.emit_event(TIP403RegistryEvent::PolicyCreated(
            ITIP403Registry::PolicyCreated {
                policyId: new_policy_id,
                updater: msg_sender,
                policyType: call.policyType,
            },
        ))?;

        self.emit_event(TIP403RegistryEvent::PolicyAdminUpdated(
            ITIP403Registry::PolicyAdminUpdated {
                policyId: new_policy_id,
                updater: msg_sender,
                admin,
            },
        ))?;

        Ok(new_policy_id)
    }

    pub fn set_policy_admin(
        &mut self,
        msg_sender: Address,
        call: ITIP403Registry::setPolicyAdminCall,
    ) -> Result<()> {
        let data = self.get_policy_data(call.policyId)?;

        // Check authorization
        if data.admin != msg_sender {
            return Err(TIP403RegistryError::unauthorized().into());
        }

        // Update admin policy ID
        self.set_policy_data(
            call.policyId,
            PolicyData {
                admin: call.admin,
                ..data
            },
        )?;

        self.emit_event(TIP403RegistryEvent::PolicyAdminUpdated(
            ITIP403Registry::PolicyAdminUpdated {
                policyId: call.policyId,
                updater: msg_sender,
                admin: call.admin,
            },
        ))
    }

    pub fn modify_policy_whitelist(
        &mut self,
        msg_sender: Address,
        call: ITIP403Registry::modifyPolicyWhitelistCall,
    ) -> Result<()> {
        let data = self.get_policy_data(call.policyId)?;

        // Check authorization
        if data.admin != msg_sender {
            return Err(TIP403RegistryError::unauthorized().into());
        }

        // Check policy type
        if data.policy_type != ITIP403Registry::PolicyType::WHITELIST as u8 {
            return Err(TIP403RegistryError::incompatible_policy_type().into());
        }

        self.set_policy_set(call.policyId, call.account, call.allowed)?;

        self.emit_event(TIP403RegistryEvent::WhitelistUpdated(
            ITIP403Registry::WhitelistUpdated {
                policyId: call.policyId,
                updater: msg_sender,
                account: call.account,
                allowed: call.allowed,
            },
        ))
    }

    pub fn modify_policy_blacklist(
        &mut self,
        msg_sender: Address,
        call: ITIP403Registry::modifyPolicyBlacklistCall,
    ) -> Result<()> {
        let data = self.get_policy_data(call.policyId)?;

        // Check authorization
        if data.admin != msg_sender {
            return Err(TIP403RegistryError::unauthorized().into());
        }

        // Check policy type
        if data.policy_type != ITIP403Registry::PolicyType::BLACKLIST as u8 {
            return Err(TIP403RegistryError::incompatible_policy_type().into());
        }

        self.set_policy_set(call.policyId, call.account, call.restricted)?;

        self.emit_event(TIP403RegistryEvent::BlacklistUpdated(
            ITIP403Registry::BlacklistUpdated {
                policyId: call.policyId,
                updater: msg_sender,
                account: call.account,
                restricted: call.restricted,
            },
        ))
    }

    /// Creates a new compound policy that references three simple policies (TIP-1015)
    pub fn create_compound_policy(
        &mut self,
        msg_sender: Address,
        call: ITIP403Registry::createCompoundPolicyCall,
    ) -> Result<u64> {
        // Validate all referenced policies exist and are simple (not compound)
        self.validate_simple_policy(call.senderPolicyId)?;
        self.validate_simple_policy(call.recipientPolicyId)?;
        self.validate_simple_policy(call.mintRecipientPolicyId)?;

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
                policy_type: ITIP403Registry::PolicyType::COMPOUND as u8,
                admin: Address::ZERO,
            },
            compound: CompoundPolicyData {
                sender_policy_id: call.senderPolicyId,
                recipient_policy_id: call.recipientPolicyId,
                mint_recipient_policy_id: call.mintRecipientPolicyId,
            },
        })?;

        // Emit event
        self.emit_event(TIP403RegistryEvent::CompoundPolicyCreated(
            ITIP403Registry::CompoundPolicyCreated {
                policyId: new_policy_id,
                creator: msg_sender,
                senderPolicyId: call.senderPolicyId,
                recipientPolicyId: call.recipientPolicyId,
                mintRecipientPolicyId: call.mintRecipientPolicyId,
            },
        ))?;

        Ok(new_policy_id)
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
                AuthRole::Sender => {
                    self.is_authorized_simple_policy(compound.sender_policy_id, user)
                }
                AuthRole::Recipient => {
                    self.is_authorized_simple_policy(compound.recipient_policy_id, user)
                }
                AuthRole::MintRecipient => {
                    self.is_authorized_simple_policy(compound.mint_recipient_policy_id, user)
                }
                AuthRole::Transfer => {
                    if !self.is_authorized_simple_policy(compound.sender_policy_id, user)? {
                        // Short-circuit: if sender fails, skip recipient check
                        return Ok(false);
                    }
                    self.is_authorized_simple_policy(compound.recipient_policy_id, user)
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
    fn is_authorized_simple_policy(&self, policy_id: u64, user: Address) -> Result<bool> {
        if let Some(auth) = self.builtin_authorization(policy_id) {
            return Ok(auth);
        }
        let data = self.get_policy_data(policy_id)?;
        self.is_simple(policy_id, user, &data)
    }

    /// Authorization check for simple (non-compound) policies
    fn is_simple(&self, policy_id: u64, user: Address, data: &PolicyData) -> Result<bool> {
        let is_in_set = self.policy_set[policy_id][user].read()?;

        let auth = match data
            .policy_type
            .try_into()
            .map_err(|_| TempoPrecompileError::under_overflow())?
        {
            ITIP403Registry::PolicyType::WHITELIST => is_in_set,
            ITIP403Registry::PolicyType::BLACKLIST => !is_in_set,
            ITIP403Registry::PolicyType::COMPOUND | ITIP403Registry::PolicyType::__Invalid => false,
        };

        Ok(auth)
    }

    /// Validates that a policy ID references an existing simple policy (not compound)
    fn validate_simple_policy(&self, policy_id: u64) -> Result<()> {
        // Built-in policies (0 and 1) are always valid simple policies
        if self.builtin_authorization(policy_id).is_some() {
            return Ok(());
        }

        // Check if policy exists
        if policy_id >= self.policy_id_counter()? {
            return Err(TIP403RegistryError::policy_does_not_exist().into());
        }

        // Check if policy is simple (not compound)
        let data = self.get_policy_data(policy_id)?;
        if data.is_compound() {
            return Err(TIP403RegistryError::policy_not_simple().into());
        }

        Ok(())
    }

    // Internal helper functions
    fn get_policy_data(&self, policy_id: u64) -> Result<PolicyData> {
        self.policy_records[policy_id].base.read()
    }

    fn set_policy_data(&mut self, policy_id: u64, data: PolicyData) -> Result<()> {
        self.policy_records[policy_id].base.write(data)
    }

    fn set_policy_set(&mut self, policy_id: u64, account: Address, value: bool) -> Result<()> {
        self.policy_set[policy_id][account].write(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::TempoPrecompileError,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
    };
    use alloy::primitives::Address;
    use rand::Rng;
    use tempo_chainspec::hardfork::TempoHardfork;

    #[test]
    fn test_create_policy() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Initial counter should be 2 (skipping special policies)
            assert_eq!(registry.policy_id_counter()?, 2);

            // Create a whitelist policy
            let result = registry.create_policy(
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                },
            );
            assert!(result.is_ok());
            assert_eq!(result?, 2);

            // Counter should be incremented
            assert_eq!(registry.policy_id_counter()?, 3);

            // Check policy data
            let data = registry.policy_data(ITIP403Registry::policyDataCall { policyId: 2 })?;
            assert_eq!(data.policyType, ITIP403Registry::PolicyType::WHITELIST);
            assert_eq!(data.admin, admin);
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
            let policy_id = registry.create_policy(
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                },
            )?;

            // User should not be authorized initially
            assert!(!registry.is_authorized_as(policy_id, user, AuthRole::Transfer)?);

            // Add user to whitelist
            registry.modify_policy_whitelist(
                admin,
                ITIP403Registry::modifyPolicyWhitelistCall {
                    policyId: policy_id,
                    account: user,
                    allowed: true,
                },
            )?;

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
            let policy_id = registry.create_policy(
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::BLACKLIST,
                },
            )?;

            // User should be authorized initially (not in blacklist)
            assert!(registry.is_authorized_as(policy_id, user, AuthRole::Transfer)?);

            // Add user to blacklist
            registry.modify_policy_blacklist(
                admin,
                ITIP403Registry::modifyPolicyBlacklistCall {
                    policyId: policy_id,
                    account: user,
                    restricted: true,
                },
            )?;

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
            let result = registry.policy_data(ITIP403Registry::policyDataCall { policyId: 100 });
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
            assert!(registry.policy_exists(ITIP403Registry::policyExistsCall { policyId: 0 })?);
            assert!(registry.policy_exists(ITIP403Registry::policyExistsCall { policyId: 1 })?);

            // Test 100 random policy IDs > 1 should not exist initially
            let mut rng = rand::thread_rng();
            for _ in 0..100 {
                let random_policy_id = rng.gen_range(2..u64::MAX);
                assert!(!registry.policy_exists(ITIP403Registry::policyExistsCall {
                    policyId: random_policy_id
                })?);
            }

            // Create 50 policies
            let mut created_policy_ids = Vec::new();
            for i in 0..50 {
                let policy_id = registry.create_policy(
                    admin,
                    ITIP403Registry::createPolicyCall {
                        admin,
                        policyType: if i % 2 == 0 {
                            ITIP403Registry::PolicyType::WHITELIST
                        } else {
                            ITIP403Registry::PolicyType::BLACKLIST
                        },
                    },
                )?;
                created_policy_ids.push(policy_id);
            }

            // All created policies should exist
            for policy_id in &created_policy_ids {
                assert!(registry.policy_exists(ITIP403Registry::policyExistsCall {
                    policyId: *policy_id
                })?);
            }

            Ok(())
        })
    }

    // =========================================================================
    //                      TIP-1015: Compound Policy Tests
    // =========================================================================

    #[test]
    fn test_create_compound_policy() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1);
        let admin = Address::random();
        let creator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Create two simple policies to reference
            let sender_policy = registry.create_policy(
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                },
            )?;
            let recipient_policy = registry.create_policy(
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::BLACKLIST,
                },
            )?;
            let mint_recipient_policy = registry.create_policy(
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                },
            )?;

            // Create compound policy
            let compound_id = registry.create_compound_policy(
                creator,
                ITIP403Registry::createCompoundPolicyCall {
                    senderPolicyId: sender_policy,
                    recipientPolicyId: recipient_policy,
                    mintRecipientPolicyId: mint_recipient_policy,
                },
            )?;

            // Verify compound policy exists
            assert!(registry.policy_exists(ITIP403Registry::policyExistsCall {
                policyId: compound_id
            })?);

            // Verify policy type is COMPOUND
            let data = registry.policy_data(ITIP403Registry::policyDataCall {
                policyId: compound_id,
            })?;
            assert_eq!(data.policyType, ITIP403Registry::PolicyType::COMPOUND);
            assert_eq!(data.admin, Address::ZERO); // Compound policies have no admin

            // Verify compound policy data
            let compound_data =
                registry.compound_policy_data(ITIP403Registry::compoundPolicyDataCall {
                    policyId: compound_id,
                })?;
            assert_eq!(compound_data.senderPolicyId, sender_policy);
            assert_eq!(compound_data.recipientPolicyId, recipient_policy);
            assert_eq!(compound_data.mintRecipientPolicyId, mint_recipient_policy);

            Ok(())
        })
    }

    #[test]
    fn test_compound_policy_rejects_non_existent_refs() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let creator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Try to create compound policy with non-existent policy IDs
            let result = registry.create_compound_policy(
                creator,
                ITIP403Registry::createCompoundPolicyCall {
                    senderPolicyId: 999,
                    recipientPolicyId: 1,
                    mintRecipientPolicyId: 1,
                },
            );
            assert!(result.is_err());

            Ok(())
        })
    }

    #[test]
    fn test_compound_policy_rejects_compound_refs() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let creator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Create a simple policy
            let simple_policy = registry.create_policy(
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                },
            )?;

            // Create a compound policy
            let compound_id = registry.create_compound_policy(
                creator,
                ITIP403Registry::createCompoundPolicyCall {
                    senderPolicyId: 1,
                    recipientPolicyId: simple_policy,
                    mintRecipientPolicyId: 1,
                },
            )?;

            // Try to create another compound policy referencing the first compound
            let result = registry.create_compound_policy(
                creator,
                ITIP403Registry::createCompoundPolicyCall {
                    senderPolicyId: compound_id, // This should fail - can't reference compound
                    recipientPolicyId: 1,
                    mintRecipientPolicyId: 1,
                },
            );
            assert!(result.is_err());

            Ok(())
        })
    }

    #[test]
    fn test_compound_policy_sender_recipient_differentiation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let creator = Address::random();
        let alice = Address::random();
        let bob = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Create sender whitelist (only Alice can send)
            let sender_policy = registry.create_policy(
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                },
            )?;
            registry.modify_policy_whitelist(
                admin,
                ITIP403Registry::modifyPolicyWhitelistCall {
                    policyId: sender_policy,
                    account: alice,
                    allowed: true,
                },
            )?;

            // Create recipient whitelist (only Bob can receive)
            let recipient_policy = registry.create_policy(
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                },
            )?;
            registry.modify_policy_whitelist(
                admin,
                ITIP403Registry::modifyPolicyWhitelistCall {
                    policyId: recipient_policy,
                    account: bob,
                    allowed: true,
                },
            )?;

            // Create compound policy
            let compound_id = registry.create_compound_policy(
                creator,
                ITIP403Registry::createCompoundPolicyCall {
                    senderPolicyId: sender_policy,
                    recipientPolicyId: recipient_policy,
                    mintRecipientPolicyId: 1, // anyone can receive mints
                },
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
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let creator = Address::random();
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Create sender whitelist with user
            let sender_policy = registry.create_policy(
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                },
            )?;
            registry.modify_policy_whitelist(
                admin,
                ITIP403Registry::modifyPolicyWhitelistCall {
                    policyId: sender_policy,
                    account: user,
                    allowed: true,
                },
            )?;

            // Create recipient whitelist WITHOUT user
            let recipient_policy = registry.create_policy(
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                },
            )?;

            // Create compound policy
            let compound_id = registry.create_compound_policy(
                creator,
                ITIP403Registry::createCompoundPolicyCall {
                    senderPolicyId: sender_policy,
                    recipientPolicyId: recipient_policy,
                    mintRecipientPolicyId: 1,
                },
            )?;

            // isAuthorized should be sender && recipient
            // User is sender-authorized but NOT recipient-authorized
            assert!(registry.is_authorized_as(compound_id, user, AuthRole::Sender)?);
            assert!(!registry.is_authorized_as(compound_id, user, AuthRole::Recipient)?);

            // isAuthorized = sender && recipient = true && false = false
            assert!(!registry.is_authorized_as(compound_id, user, AuthRole::Transfer)?);

            // Now add user to recipient whitelist
            registry.modify_policy_whitelist(
                admin,
                ITIP403Registry::modifyPolicyWhitelistCall {
                    policyId: recipient_policy,
                    account: user,
                    allowed: true,
                },
            )?;

            // Now isAuthorized = sender && recipient = true && true = true
            assert!(registry.is_authorized_as(compound_id, user, AuthRole::Transfer)?);

            Ok(())
        })
    }

    #[test]
    fn test_simple_policy_equivalence() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Create a simple whitelist policy with user
            let policy_id = registry.create_policy(
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                },
            )?;
            registry.modify_policy_whitelist(
                admin,
                ITIP403Registry::modifyPolicyWhitelistCall {
                    policyId: policy_id,
                    account: user,
                    allowed: true,
                },
            )?;

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
        let mut storage = HashMapStorageProvider::new(1);
        let creator = Address::random();
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Create compound policy using built-in policies
            // senderPolicyId = 1 (always-allow)
            // recipientPolicyId = 0 (always-reject)
            // mintRecipientPolicyId = 1 (always-allow)
            let compound_id = registry.create_compound_policy(
                creator,
                ITIP403Registry::createCompoundPolicyCall {
                    senderPolicyId: 1,
                    recipientPolicyId: 0,
                    mintRecipientPolicyId: 1,
                },
            )?;

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
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let creator = Address::random();
        let vendor = Address::random();
        let customer = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Create vendor whitelist (only vendor can receive transfers)
            let vendor_whitelist = registry.create_policy(
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                },
            )?;
            registry.modify_policy_whitelist(
                admin,
                ITIP403Registry::modifyPolicyWhitelistCall {
                    policyId: vendor_whitelist,
                    account: vendor,
                    allowed: true,
                },
            )?;

            // Create compound policy for vendor credits:
            // - Anyone can send (senderPolicyId = 1)
            // - Only vendor can receive transfers (recipientPolicyId = vendor_whitelist)
            // - Anyone can receive mints (mintRecipientPolicyId = 1)
            let compound_id = registry.create_compound_policy(
                creator,
                ITIP403Registry::createCompoundPolicyCall {
                    senderPolicyId: 1,                   // anyone can send
                    recipientPolicyId: vendor_whitelist, // only vendor receives
                    mintRecipientPolicyId: 1,            // anyone can receive mints
                },
            )?;

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
            registry.create_compound_policy(
                creator,
                ITIP403Registry::createCompoundPolicyCall {
                    senderPolicyId: 1,
                    recipientPolicyId: 1,
                    mintRecipientPolicyId: 1,
                },
            )
        })?;

        // Now downgrade to T0 and try to read the compound policy data
        let mut storage = storage.with_spec(TempoHardfork::T0);
        StorageCtx::enter(&mut storage, || {
            let registry = TIP403Registry::new();

            let result = registry.policy_data(ITIP403Registry::policyDataCall {
                policyId: compound_id,
            });
            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), TempoPrecompileError::under_overflow());

            Ok(())
        })
    }

    #[test]
    fn test_create_policy_rejects_non_simple_policy_types() -> eyre::Result<()> {
        let admin = Address::random();

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            for policy_type in [
                ITIP403Registry::PolicyType::COMPOUND,
                ITIP403Registry::PolicyType::__Invalid,
            ] {
                let result = registry.create_policy(
                    admin,
                    ITIP403Registry::createPolicyCall {
                        admin,
                        policyType: policy_type,
                    },
                );
                assert!(matches!(
                    result.unwrap_err(),
                    TempoPrecompileError::TIP403RegistryError(
                        TIP403RegistryError::IncompatiblePolicyType(_)
                    )
                ));
            }

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

            for policy_type in [
                ITIP403Registry::PolicyType::COMPOUND,
                ITIP403Registry::PolicyType::__Invalid,
            ] {
                let result = registry.create_policy_with_accounts(
                    admin,
                    ITIP403Registry::createPolicyWithAccountsCall {
                        admin,
                        policyType: policy_type,
                        accounts: vec![account],
                    },
                );
                assert!(matches!(
                    result.unwrap_err(),
                    TempoPrecompileError::TIP403RegistryError(
                        TIP403RegistryError::IncompatiblePolicyType(_)
                    )
                ));
            }

            Ok(())
        })
    }
}
