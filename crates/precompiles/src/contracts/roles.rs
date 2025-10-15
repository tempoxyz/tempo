use alloy::primitives::{Address, B256, IntoLogData, U256};

use crate::contracts::{
    storage::{
        StorageProvider,
        slots::{double_mapping_slot, mapping_slot},
    },
    types::{IRolesAuth, RolesAuthError, RolesAuthEvent},
};

pub const DEFAULT_ADMIN_ROLE: B256 = B256::ZERO;
pub const UNGRANTABLE_ROLE: B256 = B256::new([0xff; 32]);

pub struct RolesAuthContract<'a, S: StorageProvider> {
    storage: &'a mut S,
    parent_contract_address: Address,
    roles_slot: U256,
    role_admin_slot: U256,
}

impl<'a, S: StorageProvider> RolesAuthContract<'a, S> {
    pub fn new(
        storage: &'a mut S,
        parent_contract_address: Address,
        roles_slot: U256,
        role_admin_slot: U256,
    ) -> Self {
        Self {
            storage,
            parent_contract_address,
            roles_slot,
            role_admin_slot,
        }
    }

    /// Initialize the UNGRANTABLE_ROLE to be self-administered
    pub fn initialize(&mut self) {
        self.set_role_admin_internal(UNGRANTABLE_ROLE, UNGRANTABLE_ROLE);
    }

    /// Grant the default admin role to an account
    pub fn grant_default_admin(&mut self, admin: &Address) {
        self.grant_role_internal(admin, DEFAULT_ADMIN_ROLE);
    }

    // Public functions that handle calldata and emit events

    pub fn has_role(&mut self, call: IRolesAuth::hasRoleCall) -> bool {
        self.has_role_internal(&call.account, call.role)
    }

    pub fn get_role_admin(&mut self, call: IRolesAuth::getRoleAdminCall) -> B256 {
        self.get_role_admin_internal(call.role)
    }

    pub fn grant_role(
        &mut self,
        msg_sender: &Address,
        call: IRolesAuth::grantRoleCall,
    ) -> Result<(), RolesAuthError> {
        let admin_role = self.get_role_admin_internal(call.role);
        self.check_role_internal(msg_sender, admin_role)?;

        self.grant_role_internal(&call.account, call.role);

        self.storage
            .emit_event(
                self.parent_contract_address,
                RolesAuthEvent::RoleMembershipUpdated(IRolesAuth::RoleMembershipUpdated {
                    role: call.role,
                    account: call.account,
                    sender: *msg_sender,
                    hasRole: true,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");

        Ok(())
    }

    pub fn revoke_role(
        &mut self,
        msg_sender: &Address,
        call: IRolesAuth::revokeRoleCall,
    ) -> Result<(), RolesAuthError> {
        let admin_role = self.get_role_admin_internal(call.role);
        self.check_role_internal(msg_sender, admin_role)?;

        self.revoke_role_internal(&call.account, call.role);

        self.storage
            .emit_event(
                self.parent_contract_address,
                RolesAuthEvent::RoleMembershipUpdated(IRolesAuth::RoleMembershipUpdated {
                    role: call.role,
                    account: call.account,
                    sender: *msg_sender,
                    hasRole: false,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");

        Ok(())
    }

    pub fn renounce_role(
        &mut self,
        msg_sender: &Address,
        call: IRolesAuth::renounceRoleCall,
    ) -> Result<(), RolesAuthError> {
        self.check_role_internal(msg_sender, call.role)?;

        self.revoke_role_internal(msg_sender, call.role);

        self.storage
            .emit_event(
                self.parent_contract_address,
                RolesAuthEvent::RoleMembershipUpdated(IRolesAuth::RoleMembershipUpdated {
                    role: call.role,
                    account: *msg_sender,
                    sender: *msg_sender,
                    hasRole: false,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");

        Ok(())
    }

    pub fn set_role_admin(
        &mut self,
        msg_sender: &Address,
        call: IRolesAuth::setRoleAdminCall,
    ) -> Result<(), RolesAuthError> {
        let current_admin_role = self.get_role_admin_internal(call.role);
        self.check_role_internal(msg_sender, current_admin_role)?;

        self.set_role_admin_internal(call.role, call.adminRole);

        self.storage
            .emit_event(
                self.parent_contract_address,
                RolesAuthEvent::RoleAdminUpdated(IRolesAuth::RoleAdminUpdated {
                    role: call.role,
                    newAdminRole: call.adminRole,
                    sender: *msg_sender,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");

        Ok(())
    }

    // Utility functions for checking roles without calldata
    pub fn check_role(&mut self, account: &Address, role: B256) -> Result<(), RolesAuthError> {
        self.check_role_internal(account, role)
    }

    // Internal implementation functions
    pub fn has_role_internal(&mut self, account: &Address, role: B256) -> bool {
        let slot = double_mapping_slot(account, role, self.roles_slot);
        self.storage
            .sload(self.parent_contract_address, slot)
            .expect("TODO: handle error")
            != U256::ZERO
    }

    pub fn grant_role_internal(&mut self, account: &Address, role: B256) {
        let slot = double_mapping_slot(account, role, self.roles_slot);
        self.storage
            .sstore(self.parent_contract_address, slot, U256::ONE)
            .expect("TODO: handle error");
    }

    fn revoke_role_internal(&mut self, account: &Address, role: B256) {
        let slot = double_mapping_slot(account, role, self.roles_slot);
        self.storage
            .sstore(self.parent_contract_address, slot, U256::ZERO)
            .expect("TODO: handle error");
    }

    fn get_role_admin_internal(&mut self, role: B256) -> B256 {
        let slot = mapping_slot(role, self.role_admin_slot);
        let admin = self
            .storage
            .sload(self.parent_contract_address, slot)
            .expect("TODO: handle error");
        B256::from(admin) // If sloads 0, will be equal to DEFAULT_ADMIN_ROLE
    }

    fn set_role_admin_internal(&mut self, role: B256, admin_role: B256) {
        let slot = mapping_slot(role, self.role_admin_slot);
        self.storage
            .sstore(
                self.parent_contract_address,
                slot,
                U256::from_be_bytes(admin_role.0),
            )
            .expect("TODO: handle error");
    }

    fn check_role_internal(&mut self, account: &Address, role: B256) -> Result<(), RolesAuthError> {
        if !self.has_role_internal(account, role) {
            return Err(RolesAuthError::Unauthorized(IRolesAuth::Unauthorized {}));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{address, keccak256};

    use super::*;
    use crate::contracts::storage::hashmap::HashMapStorageProvider;

    #[test]
    fn test_role_contract_grant_and_check() {
        let mut storage = HashMapStorageProvider::new(1);
        let test_address = Address::from([
            0x20, 0xC0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]);
        let mut roles = RolesAuthContract::new(&mut storage, test_address, U256::ZERO, U256::ONE);

        let admin = Address::from([1u8; 20]);
        let user = Address::from([2u8; 20]);
        let custom_role = keccak256(b"CUSTOM_ROLE");

        // Initialize and grant admin
        roles.initialize();
        roles.grant_default_admin(&admin);

        // Test hasRole
        let has_admin = roles.has_role(IRolesAuth::hasRoleCall {
            account: admin,
            role: DEFAULT_ADMIN_ROLE,
        });
        assert!(has_admin);

        // Grant custom role
        roles
            .grant_role(
                &admin,
                IRolesAuth::grantRoleCall {
                    role: custom_role,
                    account: user,
                },
            )
            .unwrap();

        // Check custom role
        let has_custom = roles.has_role(IRolesAuth::hasRoleCall {
            account: user,
            role: custom_role,
        });
        assert!(has_custom);

        // Verify events were emitted
        assert_eq!(storage.events[&test_address].len(), 1); // One grant event
    }

    #[test]
    fn test_role_admin_functions() {
        let mut storage = HashMapStorageProvider::new(1);
        let test_address = address!("0x20C0000000000000000000000000000000000001");
        let mut roles = RolesAuthContract::new(&mut storage, test_address, U256::ZERO, U256::ONE);

        let admin = Address::from([1u8; 20]);
        let custom_role = keccak256(b"CUSTOM_ROLE");
        let admin_role = keccak256(b"ADMIN_ROLE");

        roles.initialize();
        roles.grant_default_admin(&admin);

        // Set custom admin for role
        roles
            .set_role_admin(
                &admin,
                IRolesAuth::setRoleAdminCall {
                    role: custom_role,
                    adminRole: admin_role,
                },
            )
            .unwrap();

        // Check role admin
        let retrieved_admin =
            roles.get_role_admin(IRolesAuth::getRoleAdminCall { role: custom_role });
        assert_eq!(retrieved_admin, admin_role);
    }

    #[test]
    fn test_renounce_role() {
        let mut storage = HashMapStorageProvider::new(1);
        let test_address = address!("0x20C0000000000000000000000000000000000001");
        let mut roles = RolesAuthContract::new(&mut storage, test_address, U256::ZERO, U256::ONE);

        let user = Address::from([1u8; 20]);
        let custom_role = keccak256(b"CUSTOM_ROLE");

        roles.initialize();
        roles.grant_role_internal(&user, custom_role);

        // Renounce role
        roles
            .renounce_role(&user, IRolesAuth::renounceRoleCall { role: custom_role })
            .unwrap();

        // Check role is removed
        assert!(!roles.has_role_internal(&user, custom_role));
    }

    #[test]
    fn test_unauthorized_access() {
        let mut storage = HashMapStorageProvider::new(1);
        let test_address = address!("0x20C0000000000000000000000000000000000001");
        let mut roles = RolesAuthContract::new(&mut storage, test_address, U256::ZERO, U256::ONE);

        let user = Address::from([1u8; 20]);
        let other = Address::from([2u8; 20]);
        let custom_role = keccak256(b"CUSTOM_ROLE");

        roles.initialize();

        // Try to grant role without permission
        let result = roles.grant_role(
            &user,
            IRolesAuth::grantRoleCall {
                role: custom_role,
                account: other,
            },
        );

        assert!(matches!(
            result,
            Err(RolesAuthError::Unauthorized(IRolesAuth::Unauthorized {}))
        ));
    }
}
