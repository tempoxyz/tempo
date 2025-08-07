use alloy::primitives::{Address, IntoLogData, U256};

use crate::{
    contracts::{
        ITIP403Registry, StorageProvider, TIP403_REGISTRY_ADDRESS,
        storage::slots::{double_mapping_slot, mapping_slot},
        types::{TIP403RegistryError, TIP403RegistryEvent},
    },
    tip403_err,
};

mod slots {
    use crate::contracts::storage::slots::to_u256;
    use alloy::primitives::U256;

    pub const POLICY_ID_COUNTER: U256 = to_u256(0);
    pub const POLICY_DATA: U256 = to_u256(1);
    pub const POLICY_SET: U256 = to_u256(2);
}

#[derive(Debug)]
pub struct TIP403Registry<'a, S: StorageProvider> {
    storage: &'a mut S,
}

#[derive(Debug, Clone)]
pub struct PolicyData {
    pub policy_type: ITIP403Registry::PolicyType,
    pub admin_policy_id: u64,
}

impl<'a, S: StorageProvider> TIP403Registry<'a, S> {
    pub fn new(storage: &'a mut S) -> Self {
        Self { storage }
    }

    // View functions
    pub fn policy_id_counter(&mut self) -> u64 {
        let counter_val = self
            .storage
            .sload(TIP403_REGISTRY_ADDRESS, slots::POLICY_ID_COUNTER);
        // Initialize policy ID counter to 2 if it's 0 (skip special policies)
        if counter_val == U256::ZERO {
            self.storage.sstore(
                TIP403_REGISTRY_ADDRESS,
                slots::POLICY_ID_COUNTER,
                U256::from(2),
            );
            return 2;
        }
        counter_val.to::<u64>()
    }

    pub fn policy_data(
        &mut self,
        call: ITIP403Registry::policyDataCall,
    ) -> ITIP403Registry::policyDataReturn {
        let data = self.get_policy_data(call.policyId);
        ITIP403Registry::policyDataReturn {
            policyType: data.policy_type,
            adminPolicyId: data.admin_policy_id,
        }
    }

    pub fn is_authorized(&mut self, call: ITIP403Registry::isAuthorizedCall) -> bool {
        self.is_authorized_internal(call.policyId, &call.user)
    }

    // State-changing functions
    pub fn create_policy(
        &mut self,
        msg_sender: &Address,
        call: ITIP403Registry::createPolicyCall,
    ) -> Result<u64, TIP403RegistryError> {
        let new_policy_id = self.policy_id_counter();

        // Increment counter
        self.storage.sstore(
            TIP403_REGISTRY_ADDRESS,
            slots::POLICY_ID_COUNTER,
            U256::from(new_policy_id + 1),
        );

        // Store policy data
        self.set_policy_data(
            new_policy_id,
            &PolicyData {
                policy_type: call.policyType,
                admin_policy_id: call.adminPolicyId,
            },
        );

        // Emit events
        self.storage.emit_event(
            TIP403_REGISTRY_ADDRESS,
            TIP403RegistryEvent::PolicyCreated(ITIP403Registry::PolicyCreated {
                policyId: new_policy_id,
                updater: *msg_sender,
                policyType: call.policyType,
            })
            .into_log_data(),
        );

        self.storage.emit_event(
            TIP403_REGISTRY_ADDRESS,
            TIP403RegistryEvent::PolicyAdminUpdated(ITIP403Registry::PolicyAdminUpdated {
                policyId: new_policy_id,
                updater: *msg_sender,
                adminPolicyId: call.adminPolicyId,
            })
            .into_log_data(),
        );

        Ok(new_policy_id)
    }

    pub fn create_policy_with_accounts(
        &mut self,
        msg_sender: &Address,
        call: ITIP403Registry::createPolicyWithAccountsCall,
    ) -> Result<u64, TIP403RegistryError> {
        let mut admin_policy_id = call.adminPolicyId;
        let policy_type = call.policyType;
        let new_policy_id = self.policy_id_counter();

        // Handle special case for self-owned policy (type(uint64).max)
        if admin_policy_id == u64::MAX {
            if policy_type != ITIP403Registry::PolicyType::WHITELIST {
                return Err(tip403_err!(SelfOwnedPolicyMustBeWhitelist));
            }
            admin_policy_id = new_policy_id;
        }

        // Increment counter
        self.storage.sstore(
            TIP403_REGISTRY_ADDRESS,
            slots::POLICY_ID_COUNTER,
            U256::from(new_policy_id + 1),
        );

        // Store policy data

        self.set_policy_data(
            new_policy_id,
            &PolicyData {
                policy_type,
                admin_policy_id,
            },
        );

        // Set initial accounts
        for account in call.accounts.iter() {
            self.set_policy_set(new_policy_id, account, true);

            match policy_type {
                ITIP403Registry::PolicyType::WHITELIST => {
                    self.storage.emit_event(
                        TIP403_REGISTRY_ADDRESS,
                        TIP403RegistryEvent::WhitelistUpdated(ITIP403Registry::WhitelistUpdated {
                            policyId: new_policy_id,
                            updater: *msg_sender,
                            account: *account,
                            allowed: true,
                        })
                        .into_log_data(),
                    );
                }
                ITIP403Registry::PolicyType::BLACKLIST => {
                    self.storage.emit_event(
                        TIP403_REGISTRY_ADDRESS,
                        TIP403RegistryEvent::BlacklistUpdated(ITIP403Registry::BlacklistUpdated {
                            policyId: new_policy_id,
                            updater: *msg_sender,
                            account: *account,
                            restricted: true,
                        })
                        .into_log_data(),
                    );
                }
                ITIP403Registry::PolicyType::__Invalid => {
                    return Err(tip403_err!(IncompatiblePolicyType));
                }
            }
        }

        // Emit policy creation events
        self.storage.emit_event(
            TIP403_REGISTRY_ADDRESS,
            TIP403RegistryEvent::PolicyCreated(ITIP403Registry::PolicyCreated {
                policyId: new_policy_id,
                updater: *msg_sender,
                policyType: call.policyType,
            })
            .into_log_data(),
        );

        self.storage.emit_event(
            TIP403_REGISTRY_ADDRESS,
            TIP403RegistryEvent::PolicyAdminUpdated(ITIP403Registry::PolicyAdminUpdated {
                policyId: new_policy_id,
                updater: *msg_sender,
                adminPolicyId: admin_policy_id,
            })
            .into_log_data(),
        );

        Ok(new_policy_id)
    }

    pub fn set_policy_admin(
        &mut self,
        msg_sender: &Address,
        call: ITIP403Registry::setPolicyAdminCall,
    ) -> Result<(), TIP403RegistryError> {
        let data = self.get_policy_data(call.policyId);

        // Check authorization
        if !self.is_authorized_internal(data.admin_policy_id, msg_sender) {
            return Err(tip403_err!(Unauthorized));
        }

        // Update admin policy ID
        self.set_policy_data(
            call.policyId,
            &PolicyData {
                admin_policy_id: call.adminPolicyId,
                ..data
            },
        );

        self.storage.emit_event(
            TIP403_REGISTRY_ADDRESS,
            TIP403RegistryEvent::PolicyAdminUpdated(ITIP403Registry::PolicyAdminUpdated {
                policyId: call.policyId,
                updater: *msg_sender,
                adminPolicyId: call.adminPolicyId,
            })
            .into_log_data(),
        );

        Ok(())
    }

    pub fn modify_policy_whitelist(
        &mut self,
        msg_sender: &Address,
        call: ITIP403Registry::modifyPolicyWhitelistCall,
    ) -> Result<(), TIP403RegistryError> {
        let data = self.get_policy_data(call.policyId);

        // Check authorization
        if !self.is_authorized_internal(data.admin_policy_id, msg_sender) {
            return Err(tip403_err!(Unauthorized));
        }

        // Check policy type
        if data.policy_type != ITIP403Registry::PolicyType::WHITELIST {
            return Err(tip403_err!(IncompatiblePolicyType));
        }

        self.set_policy_set(call.policyId, &call.account, call.allowed);

        self.storage.emit_event(
            TIP403_REGISTRY_ADDRESS,
            TIP403RegistryEvent::WhitelistUpdated(ITIP403Registry::WhitelistUpdated {
                policyId: call.policyId,
                updater: *msg_sender,
                account: call.account,
                allowed: call.allowed,
            })
            .into_log_data(),
        );

        Ok(())
    }

    pub fn modify_policy_blacklist(
        &mut self,
        msg_sender: &Address,
        call: ITIP403Registry::modifyPolicyBlacklistCall,
    ) -> Result<(), TIP403RegistryError> {
        let data = self.get_policy_data(call.policyId);

        // Check authorization
        if !self.is_authorized_internal(data.admin_policy_id, msg_sender) {
            return Err(tip403_err!(Unauthorized));
        }

        // Check policy type
        if data.policy_type != ITIP403Registry::PolicyType::BLACKLIST {
            return Err(tip403_err!(IncompatiblePolicyType));
        }

        self.set_policy_set(call.policyId, &call.account, call.restricted);

        self.storage.emit_event(
            TIP403_REGISTRY_ADDRESS,
            TIP403RegistryEvent::BlacklistUpdated(ITIP403Registry::BlacklistUpdated {
                policyId: call.policyId,
                updater: *msg_sender,
                account: call.account,
                restricted: call.restricted,
            })
            .into_log_data(),
        );

        Ok(())
    }

    // Internal helper functions
    fn get_policy_data(&mut self, policy_id: u64) -> PolicyData {
        let slot = mapping_slot(policy_id.to_be_bytes(), slots::POLICY_DATA);
        let value = self.storage.sload(TIP403_REGISTRY_ADDRESS, slot);

        // Extract policy type (low 128 bits) and admin policy ID (high 128 bits)
        let policy_type = (value.to::<u128>() & 0xFF) as u8;
        let admin_policy_id = (value.to::<u128>() >> 64) as u64;

        PolicyData {
            policy_type: policy_type.try_into().unwrap(),
            admin_policy_id,
        }
    }

    fn set_policy_data(&mut self, policy_id: u64, data: &PolicyData) {
        let slot = mapping_slot(policy_id.to_be_bytes(), slots::POLICY_DATA);

        // Pack policy type and admin policy ID into single U256
        let value = U256::from(data.policy_type as u128) | (U256::from(data.admin_policy_id) << 64);

        self.storage.sstore(TIP403_REGISTRY_ADDRESS, slot, value);
    }

    fn set_policy_set(&mut self, policy_id: u64, account: &Address, value: bool) {
        let slot = double_mapping_slot(policy_id.to_be_bytes(), account, slots::POLICY_SET);
        self.storage.sstore(
            TIP403_REGISTRY_ADDRESS,
            slot,
            if value { U256::from(1) } else { U256::ZERO },
        );
    }

    fn is_authorized_internal(&mut self, policy_id: u64, user: &Address) -> bool {
        // Special case for always-allow and always-reject policies
        if policy_id < 2 {
            // policyId == 0 is the "always-reject" policy
            // policyId == 1 is the "always-allow" policy
            return policy_id == 1;
        }

        let data = self.get_policy_data(policy_id);
        let is_in_set = self.storage.sload(
            TIP403_REGISTRY_ADDRESS,
            double_mapping_slot(policy_id.to_be_bytes(), user, slots::POLICY_SET),
        ) != U256::ZERO;

        match data.policy_type {
            ITIP403Registry::PolicyType::WHITELIST => is_in_set,
            ITIP403Registry::PolicyType::BLACKLIST => !is_in_set,
            ITIP403Registry::PolicyType::__Invalid => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::storage::hashmap::HashMapStorageProvider;

    #[test]
    fn test_create_policy() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut registry = TIP403Registry::new(&mut storage);
        let admin = Address::from([1u8; 20]);

        // Initial counter should be 2 (skipping special policies)
        assert_eq!(registry.policy_id_counter(), 2);

        // Create a whitelist policy
        let result = registry.create_policy(
            &admin,
            ITIP403Registry::createPolicyCall {
                adminPolicyId: 1, // Always-allow admin
                policyType: ITIP403Registry::PolicyType::WHITELIST,
            },
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 2);

        // Counter should be incremented
        assert_eq!(registry.policy_id_counter(), 3);

        // Check policy data
        let data = registry.policy_data(ITIP403Registry::policyDataCall { policyId: 2 });
        assert_eq!(data.policyType, ITIP403Registry::PolicyType::WHITELIST);
        assert_eq!(data.adminPolicyId, 1);
    }

    #[test]
    fn test_is_authorized_special_policies() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut registry = TIP403Registry::new(&mut storage);
        let user = Address::from([1u8; 20]);

        // Policy 0 should always reject
        assert!(!registry.is_authorized(ITIP403Registry::isAuthorizedCall { policyId: 0, user }));

        // Policy 1 should always allow
        assert!(registry.is_authorized(ITIP403Registry::isAuthorizedCall { policyId: 1, user }));
    }

    #[test]
    fn test_whitelist_policy() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut registry = TIP403Registry::new(&mut storage);
        let admin = Address::from([1u8; 20]);
        let user = Address::from([2u8; 20]);

        // Create whitelist policy
        let policy_id = registry
            .create_policy(
                &admin,
                ITIP403Registry::createPolicyCall {
                    adminPolicyId: 1,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                },
            )
            .unwrap();

        // User should not be authorized initially
        assert!(!registry.is_authorized(ITIP403Registry::isAuthorizedCall {
            policyId: policy_id,
            user,
        }));

        // Add user to whitelist
        registry
            .modify_policy_whitelist(
                &admin, // Anyone is authorized with policy 1
                ITIP403Registry::modifyPolicyWhitelistCall {
                    policyId: policy_id,
                    account: user,
                    allowed: true,
                },
            )
            .unwrap();

        // User should now be authorized
        assert!(registry.is_authorized(ITIP403Registry::isAuthorizedCall {
            policyId: policy_id,
            user,
        }));
    }

    #[test]
    fn test_blacklist_policy() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut registry = TIP403Registry::new(&mut storage);
        let admin = Address::from([1u8; 20]);
        let user = Address::from([2u8; 20]);

        // Create blacklist policy
        let policy_id = registry
            .create_policy(
                &admin,
                ITIP403Registry::createPolicyCall {
                    adminPolicyId: 1,
                    policyType: ITIP403Registry::PolicyType::BLACKLIST,
                },
            )
            .unwrap();

        // User should be authorized initially (not in blacklist)
        assert!(registry.is_authorized(ITIP403Registry::isAuthorizedCall {
            policyId: policy_id,
            user,
        }));

        // Add user to blacklist
        registry
            .modify_policy_blacklist(
                &admin,
                ITIP403Registry::modifyPolicyBlacklistCall {
                    policyId: policy_id,
                    account: user,
                    restricted: true,
                },
            )
            .unwrap();

        // User should no longer be authorized
        assert!(!registry.is_authorized(ITIP403Registry::isAuthorizedCall {
            policyId: policy_id,
            user,
        }));
    }
}
