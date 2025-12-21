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
    policy_data: Mapping<u64, PolicyData>,
    policy_set: Mapping<u64, Mapping<Address, bool>>,
}

#[derive(Debug, Clone, Storable)]
pub struct PolicyData {
    pub policy_type: u8,
    pub admin: Address,
}

impl PolicyData {
    pub fn decode_from_slot(slot_value: U256) -> Self {
        use crate::storage::{LayoutCtx, Storable, packing::PackedSlot};
        Self::load(&PackedSlot(slot_value), U256::ZERO, LayoutCtx::FULL)
            .expect("unable to decode PoliciData from slot")
    }

    pub fn encode_to_slot(&self) -> U256 {
        use crate::storage::packing::insert_packed_value;
        use __packing_policy_data::{ADMIN_LOC as A_LOC, POLICY_TYPE_LOC as PT_LOC};

        let encoded = insert_packed_value(
            U256::ZERO,
            &self.policy_type,
            PT_LOC.offset_bytes,
            PT_LOC.size,
        )
        .expect("unable to insert 'policy_type'");

        insert_packed_value(encoded, &self.admin, A_LOC.offset_bytes, A_LOC.size)
            .expect("unable to insert 'admin'")
    }
}

impl TIP403Registry {
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    pub fn policy_id_counter(&self) -> Result<u64> {
        self.policy_id_counter.read().map(|counter| counter.max(2))
    }

    pub fn policy_exists(&self, call: ITIP403Registry::policyExistsCall) -> Result<bool> {
        if call.policyId < 2 {
            return Ok(true);
        }
        let counter = self.policy_id_counter()?;
        Ok(call.policyId < counter)
    }

    pub fn policy_data(
        &self,
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

    pub fn is_authorized(&self, call: ITIP403Registry::isAuthorizedCall) -> Result<bool> {
        self.is_authorized_internal(call.policyId, call.user)
    }

    pub fn create_policy(
        &mut self,
        msg_sender: Address,
        call: ITIP403Registry::createPolicyCall,
    ) -> Result<u64> {
        if matches!(call.policyType, ITIP403Registry::PolicyType::__Invalid) {
            return Err(TIP403RegistryError::incompatible_policy_type().into());
        }

        let new_policy_id = self.policy_id_counter()?;

        self.policy_id_counter.write(
            new_policy_id
                .checked_add(1)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        self.policy_data.at(new_policy_id).write(PolicyData {
            policy_type: call.policyType as u8,
            admin: call.admin,
        })?;

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
        if matches!(call.policyType, ITIP403Registry::PolicyType::__Invalid) {
            return Err(TIP403RegistryError::incompatible_policy_type().into());
        }

        let (admin, policy_type) = (call.admin, call.policyType);
        let new_policy_id = self.policy_id_counter()?;

        self.policy_id_counter.write(
            new_policy_id
                .checked_add(1)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        self.set_policy_data(
            new_policy_id,
            PolicyData {
                policy_type: policy_type as u8,
                admin,
            },
        )?;

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
                _ => {}
            }
        }

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
        if call.admin == Address::ZERO {
            return Err(TIP403RegistryError::unauthorized().into());
        }

        let data = self.get_policy_data(call.policyId)?;

        if data.admin != msg_sender {
            return Err(TIP403RegistryError::unauthorized().into());
        }

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
        if data.admin != msg_sender {
            return Err(TIP403RegistryError::unauthorized().into());
        }
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
        if data.admin != msg_sender {
            return Err(TIP403RegistryError::unauthorized().into());
        }
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

    fn get_policy_data(&self, policy_id: u64) -> Result<PolicyData> {
        self.policy_data.at(policy_id).read()
    }

    fn set_policy_data(&mut self, policy_id: u64, data: PolicyData) -> Result<()> {
        self.policy_data.at(policy_id).write(data)
    }

    fn set_policy_set(&mut self, policy_id: u64, account: Address, value: bool) -> Result<()> {
        self.policy_set.at(policy_id).at(account).write(value)
    }

    fn is_authorized_internal(&self, policy_id: u64, user: Address) -> Result<bool> {
        if policy_id < 2 {
            return Ok(policy_id == 1);
        }
        let data = self.get_policy_data(policy_id)?;
        let is_in_set = self.policy_set.at(policy_id).at(user).read()?;

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
    use super::*;
    use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};
    use alloy::primitives::Address;

    #[test]
    fn test_orphaned_policy_prevention() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();
            let policy_id = registry.create_policy(
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::BLACKLIST,
                },
            )?;

            let result = registry.set_policy_admin(
                admin,
                ITIP403Registry::setPolicyAdminCall {
                    policyId: policy_id,
                    admin: Address::ZERO,
                },
            );

            assert!(result.is_err(), "Registry should prevent setting admin to Address::ZERO");
            
            let data = registry.get_policy_data(policy_id)?;
            assert_eq!(data.admin, admin, "Admin should remain the original address");
            Ok(())
        })
    }

    #[test]
    fn test_create_policy() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();
            assert_eq!(registry.policy_id_counter()?, 2);

            let result = registry.create_policy(
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                },
            );
            assert!(result.is_ok());
            assert_eq!(result?, 2);
            assert_eq!(registry.policy_id_counter()?, 3);

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
            assert!(!registry.is_authorized(ITIP403Registry::isAuthorizedCall { policyId: 0, user })?);
            assert!(registry.is_authorized(ITIP403Registry::isAuthorizedCall { policyId: 1, user })?);
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
            let policy_id = registry.create_policy(
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                },
            )?;
            assert!(!registry.is_authorized(ITIP403Registry::isAuthorizedCall { policyId: policy_id, user })?);
            registry.modify_policy_whitelist(admin, ITIP403Registry::modifyPolicyWhitelistCall { policyId: policy_id, account: user, allowed: true })?;
            assert!(registry.is_authorized(ITIP403Registry::isAuthorizedCall { policyId: policy_id, user })?);
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
            let policy_id = registry.create_policy(
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::BLACKLIST,
                },
            )?;
            assert!(registry.is_authorized(ITIP403Registry::isAuthorizedCall { policyId: policy_id, user })?);
            registry.modify_policy_blacklist(admin, ITIP403Registry::modifyPolicyBlacklistCall { policyId: policy_id, account: user, restricted: true })?;
            assert!(!registry.is_authorized(ITIP403Registry::isAuthorizedCall { policyId: policy_id, user })?);
            Ok(())
        })
    }

    #[test]
    fn test_policy_exists() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let registry = TIP403Registry::new();
            assert!(registry.policy_exists(ITIP403Registry::policyExistsCall { policyId: 0 })?);
            assert!(registry.policy_exists(ITIP403Registry::policyExistsCall { policyId: 1 })?);
            Ok(())
        })
    }
}