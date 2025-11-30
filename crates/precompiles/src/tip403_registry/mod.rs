pub mod dispatch;

pub use tempo_contracts::precompiles::{ITIP403Registry, TIP403RegistryError, TIP403RegistryEvent};
use tempo_precompiles_macros::{Storable, contract};

use crate::{
    TIP403_REGISTRY_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::{Mapping, PrecompileStorageProvider},
};
use alloy::primitives::{Address, Bytes, IntoLogData};
use revm::state::Bytecode;

#[contract]
pub struct TIP403Registry {
    policy_id_counter: u64,
    policy_data: Mapping<u64, PolicyData>,
    policy_set: Mapping<u64, Mapping<Address, bool>>,
}

#[derive(Debug, Clone, Storable)]
pub struct PolicyData {
    // NOTE: enums are defined as u8, and leverage the sol! macro's `TryInto<u8>` impl
    pub policy_type: u8,
    pub admin: Address,
}

impl<'a, S: PrecompileStorageProvider> TIP403Registry<'a, S> {
    /// Creates an instance of the precompile.
    ///
    /// Caution: This does not initialize the account, see [`Self::initialize`].
    pub fn new(storage: &'a mut S) -> Self {
        Self::_new(TIP403_REGISTRY_ADDRESS, storage)
    }

    /// Initializes the registry contract.
    pub fn initialize(&mut self) -> Result<()> {
        self.storage.set_code(
            TIP403_REGISTRY_ADDRESS,
            Bytecode::new_legacy(Bytes::from_static(&[0xef])),
        )?;

        Ok(())
    }

    // View functions
    pub fn policy_id_counter(&mut self) -> Result<u64> {
        let counter_val = self.sload_policy_id_counter()?;
        // Initialize policy ID counter to 2 if it's 0 (skip special policies)
        Ok(counter_val.max(2))
    }

    pub fn policy_data(
        &mut self,
        call: ITIP403Registry::policyDataCall,
    ) -> Result<ITIP403Registry::policyDataReturn> {
        let data = self.get_policy_data(call.policyId)?;
        Ok(ITIP403Registry::policyDataReturn {
            policyType: data
                .policy_type
                .try_into()
                .map_err(|_| TempoPrecompileError::under_overflow())?,
            admin: data.admin,
        })
    }

    pub fn is_authorized(&mut self, call: ITIP403Registry::isAuthorizedCall) -> Result<bool> {
        self.is_authorized_internal(call.policyId, call.user)
    }

    // State-changing functions
    pub fn create_policy(
        &mut self,
        msg_sender: Address,
        call: ITIP403Registry::createPolicyCall,
    ) -> Result<u64> {
        let new_policy_id = self.policy_id_counter()?;

        // Increment counter
        self.sstore_policy_id_counter(
            new_policy_id
                .checked_add(1)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        // Store policy data
        self.sstore_policy_data(
            new_policy_id,
            PolicyData {
                policy_type: call.policyType as u8,
                admin: call.admin,
            },
        )?;

        // Emit events
        self.storage.emit_event(
            TIP403_REGISTRY_ADDRESS,
            TIP403RegistryEvent::PolicyCreated(ITIP403Registry::PolicyCreated {
                policyId: new_policy_id,
                updater: msg_sender,
                policyType: call.policyType,
            })
            .into_log_data(),
        )?;

        self.storage.emit_event(
            TIP403_REGISTRY_ADDRESS,
            TIP403RegistryEvent::PolicyAdminUpdated(ITIP403Registry::PolicyAdminUpdated {
                policyId: new_policy_id,
                updater: msg_sender,
                admin: call.admin,
            })
            .into_log_data(),
        )?;

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
        self.sstore_policy_id_counter(
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
                    self.storage.emit_event(
                        TIP403_REGISTRY_ADDRESS,
                        TIP403RegistryEvent::WhitelistUpdated(ITIP403Registry::WhitelistUpdated {
                            policyId: new_policy_id,
                            updater: msg_sender,
                            account: *account,
                            allowed: true,
                        })
                        .into_log_data(),
                    )?;
                }
                ITIP403Registry::PolicyType::BLACKLIST => {
                    self.storage.emit_event(
                        TIP403_REGISTRY_ADDRESS,
                        TIP403RegistryEvent::BlacklistUpdated(ITIP403Registry::BlacklistUpdated {
                            policyId: new_policy_id,
                            updater: msg_sender,
                            account: *account,
                            restricted: true,
                        })
                        .into_log_data(),
                    )?;
                }
                ITIP403Registry::PolicyType::__Invalid => {
                    return Err(TIP403RegistryError::incompatible_policy_type().into());
                }
            }
        }

        // Emit policy creation events
        self.storage.emit_event(
            TIP403_REGISTRY_ADDRESS,
            TIP403RegistryEvent::PolicyCreated(ITIP403Registry::PolicyCreated {
                policyId: new_policy_id,
                updater: msg_sender,
                policyType: call.policyType,
            })
            .into_log_data(),
        )?;

        self.storage.emit_event(
            TIP403_REGISTRY_ADDRESS,
            TIP403RegistryEvent::PolicyAdminUpdated(ITIP403Registry::PolicyAdminUpdated {
                policyId: new_policy_id,
                updater: msg_sender,
                admin,
            })
            .into_log_data(),
        )?;

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

        self.storage.emit_event(
            TIP403_REGISTRY_ADDRESS,
            TIP403RegistryEvent::PolicyAdminUpdated(ITIP403Registry::PolicyAdminUpdated {
                policyId: call.policyId,
                updater: msg_sender,
                admin: call.admin,
            })
            .into_log_data(),
        )
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

        self.storage.emit_event(
            TIP403_REGISTRY_ADDRESS,
            TIP403RegistryEvent::WhitelistUpdated(ITIP403Registry::WhitelistUpdated {
                policyId: call.policyId,
                updater: msg_sender,
                account: call.account,
                allowed: call.allowed,
            })
            .into_log_data(),
        )
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

        self.storage.emit_event(
            TIP403_REGISTRY_ADDRESS,
            TIP403RegistryEvent::BlacklistUpdated(ITIP403Registry::BlacklistUpdated {
                policyId: call.policyId,
                updater: msg_sender,
                account: call.account,
                restricted: call.restricted,
            })
            .into_log_data(),
        )
    }

    // Internal helper functions
    fn get_policy_data(&mut self, policy_id: u64) -> Result<PolicyData> {
        self.sload_policy_data(policy_id)
    }

    fn set_policy_data(&mut self, policy_id: u64, data: PolicyData) -> Result<()> {
        self.sstore_policy_data(policy_id, data)
    }

    fn set_policy_set(&mut self, policy_id: u64, account: Address, value: bool) -> Result<()> {
        self.sstore_policy_set(policy_id, account, value)
    }

    fn is_authorized_internal(&mut self, policy_id: u64, user: Address) -> Result<bool> {
        // Special case for always-allow and always-reject policies
        if policy_id < 2 {
            // policyId == 0 is the "always-reject" policy
            // policyId == 1 is the "always-allow" policy
            return Ok(policy_id == 1);
        }

        let data = self.get_policy_data(policy_id)?;
        let is_in_set = self.sload_policy_set(policy_id, user)?;

        let auth = match data
            .policy_type
            .try_into()
            .map_err(|_| TempoPrecompileError::under_overflow())?
        {
            ITIP403Registry::PolicyType::WHITELIST => is_in_set,
            ITIP403Registry::PolicyType::BLACKLIST => !is_in_set,
            ITIP403Registry::PolicyType::__Invalid => false,
        };

        Ok(auth)
    }
}

#[cfg(test)]
mod tests {
    use crate::storage::hashmap::HashMapStorageProvider;

    use super::*;

    #[test]
    fn test_create_policy() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut registry = TIP403Registry::new(&mut storage);
        let admin = Address::from([1u8; 20]);

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
    }

    #[test]
    fn test_is_authorized_special_policies() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut registry = TIP403Registry::new(&mut storage);
        let user = Address::from([1u8; 20]);

        // Policy 0 should always reject
        assert!(!registry.is_authorized(ITIP403Registry::isAuthorizedCall { policyId: 0, user })?);

        // Policy 1 should always allow
        assert!(registry.is_authorized(ITIP403Registry::isAuthorizedCall { policyId: 1, user })?);
        Ok(())
    }

    #[test]
    fn test_whitelist_policy() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut registry = TIP403Registry::new(&mut storage);
        let admin = Address::from([1u8; 20]);
        let user = Address::from([2u8; 20]);

        // Create whitelist policy
        let policy_id = registry.create_policy(
            admin,
            ITIP403Registry::createPolicyCall {
                admin,
                policyType: ITIP403Registry::PolicyType::WHITELIST,
            },
        )?;

        // User should not be authorized initially
        assert!(!registry.is_authorized(ITIP403Registry::isAuthorizedCall {
            policyId: policy_id,
            user,
        })?);

        // Add user to whitelist
        registry.modify_policy_whitelist(
            admin, // Anyone is authorized with policy 1
            ITIP403Registry::modifyPolicyWhitelistCall {
                policyId: policy_id,
                account: user,
                allowed: true,
            },
        )?;

        // User should now be authorized
        assert!(registry.is_authorized(ITIP403Registry::isAuthorizedCall {
            policyId: policy_id,
            user,
        })?);

        Ok(())
    }

    #[test]
    fn test_blacklist_policy() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut registry = TIP403Registry::new(&mut storage);
        let admin = Address::from([1u8; 20]);
        let user = Address::from([2u8; 20]);

        // Create blacklist policy
        let policy_id = registry.create_policy(
            admin,
            ITIP403Registry::createPolicyCall {
                admin,
                policyType: ITIP403Registry::PolicyType::BLACKLIST,
            },
        )?;

        // User should be authorized initially (not in blacklist)
        assert!(registry.is_authorized(ITIP403Registry::isAuthorizedCall {
            policyId: policy_id,
            user,
        })?);

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
        assert!(!registry.is_authorized(ITIP403Registry::isAuthorizedCall {
            policyId: policy_id,
            user,
        })?);

        Ok(())
    }
}
