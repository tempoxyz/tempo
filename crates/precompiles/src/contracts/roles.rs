use std::sync::LazyLock;

use alloy::{
    primitives::{Address, B256, IntoLogData, U256},
    sol,
};

use crate::contracts::storage::{
    StorageProvider,
    slots::{double_mapping_slot, mapping_slot},
};

// Constants
pub static DEFAULT_ADMIN_ROLE: LazyLock<B256> = LazyLock::new(|| B256::ZERO);
pub static UNGRANTABLE_ROLE: LazyLock<B256> = LazyLock::new(|| B256::from(U256::MAX));

// Storage layout constants for roles
pub mod slots {
    pub const ROLES: u64 = 0;
    pub const ROLE_ADMIN: u64 = 1;
}

sol! {
    #[derive(Debug, PartialEq, Eq)]
    interface RolesAuth {
        // Role Management Functions
        function grantRole(bytes32 role, address account) external;
        function revokeRole(bytes32 role, address account) external;
        function renounceRole(bytes32 role) external;
        function setRoleAdmin(bytes32 role, bytes32 adminRole) external;
        function hasRole(address account, bytes32 role) external view returns (bool);
        function getRoleAdmin(bytes32 role) external view returns (bytes32);

        // Events
        event RoleMembershipUpdated(bytes32 indexed role, address indexed account, address indexed sender, bool hasRole);
        event RoleAdminUpdated(bytes32 indexed role, bytes32 indexed newAdminRole, address indexed sender);

        // Errors
        error Unauthorized();
    }
}

// Re-export for convenience
pub use RolesAuth::{RolesAuthErrors as RolesError, RolesAuthEvents as RolesEvent};

/// Error type that can be converted to contract-specific errors
#[derive(Debug)]
pub enum RolesAuthError {
    Unauthorized,
}

/// Complete roles system that handles calldata parsing and event emission
pub struct RolesAuthContract<'a, S: StorageProvider> {
    storage: &'a mut S,
    contract_id: u64,
    roles_base_slot: u64,
    role_admin_base_slot: u64,
}

impl<'a, S: StorageProvider> RolesAuthContract<'a, S> {
    pub fn new(
        storage: &'a mut S,
        contract_id: u64,
        roles_base_slot: u64,
        role_admin_base_slot: u64,
    ) -> Self {
        Self {
            storage,
            contract_id,
            roles_base_slot,
            role_admin_base_slot,
        }
    }

    /// Initialize the UNGRANTABLE_ROLE to be self-administered
    pub fn initialize(&mut self) {
        self.set_role_admin_internal(*UNGRANTABLE_ROLE, *UNGRANTABLE_ROLE);
    }

    /// Grant the default admin role to an account
    pub fn grant_default_admin(&mut self, admin: &Address) {
        self.grant_role_internal(admin, *DEFAULT_ADMIN_ROLE);
    }

    // Public functions that handle calldata and emit events

    pub fn has_role(&mut self, call: RolesAuth::hasRoleCall) -> bool {
        self.has_role_internal(&call.account, call.role)
    }

    pub fn get_role_admin(&mut self, call: RolesAuth::getRoleAdminCall) -> B256 {
        self.get_role_admin_internal(call.role)
    }

    pub fn grant_role(
        &mut self,
        msg_sender: &Address,
        call: RolesAuth::grantRoleCall,
    ) -> Result<(), RolesAuthError> {
        let admin_role = self.get_role_admin_internal(call.role);
        self.check_role_internal(msg_sender, admin_role)?;

        self.grant_role_internal(&call.account, call.role);

        self.storage.emit_event(
            self.contract_id,
            RolesEvent::RoleMembershipUpdated(RolesAuth::RoleMembershipUpdated {
                role: call.role,
                account: call.account,
                sender: *msg_sender,
                hasRole: true,
            })
            .into_log_data(),
        );

        Ok(())
    }

    pub fn revoke_role(
        &mut self,
        msg_sender: &Address,
        call: RolesAuth::revokeRoleCall,
    ) -> Result<(), RolesAuthError> {
        let admin_role = self.get_role_admin_internal(call.role);
        self.check_role_internal(msg_sender, admin_role)?;

        self.revoke_role_internal(&call.account, call.role);

        self.storage.emit_event(
            self.contract_id,
            RolesEvent::RoleMembershipUpdated(RolesAuth::RoleMembershipUpdated {
                role: call.role,
                account: call.account,
                sender: *msg_sender,
                hasRole: false,
            })
            .into_log_data(),
        );

        Ok(())
    }

    pub fn renounce_role(
        &mut self,
        msg_sender: &Address,
        call: RolesAuth::renounceRoleCall,
    ) -> Result<(), RolesAuthError> {
        self.check_role_internal(msg_sender, call.role)?;

        self.revoke_role_internal(msg_sender, call.role);

        self.storage.emit_event(
            self.contract_id,
            RolesEvent::RoleMembershipUpdated(RolesAuth::RoleMembershipUpdated {
                role: call.role,
                account: *msg_sender,
                sender: *msg_sender,
                hasRole: false,
            })
            .into_log_data(),
        );

        Ok(())
    }

    pub fn set_role_admin(
        &mut self,
        msg_sender: &Address,
        call: RolesAuth::setRoleAdminCall,
    ) -> Result<(), RolesAuthError> {
        let current_admin_role = self.get_role_admin_internal(call.role);
        self.check_role_internal(msg_sender, current_admin_role)?;

        self.set_role_admin_internal(call.role, call.adminRole);

        self.storage.emit_event(
            self.contract_id,
            RolesEvent::RoleAdminUpdated(RolesAuth::RoleAdminUpdated {
                role: call.role,
                newAdminRole: call.adminRole,
                sender: *msg_sender,
            })
            .into_log_data(),
        );

        Ok(())
    }

    // Utility functions for checking roles without calldata
    pub fn check_role(&mut self, account: &Address, role: B256) -> Result<(), RolesAuthError> {
        self.check_role_internal(account, role)
    }

    // Internal implementation functions

    fn has_role_internal(&mut self, account: &Address, role: B256) -> bool {
        let slot = double_mapping_slot(account, role, self.roles_base_slot);
        self.storage.sload(self.contract_id, slot) != U256::ZERO
    }

    pub fn grant_role_internal(&mut self, account: &Address, role: B256) {
        let slot = double_mapping_slot(account, role, self.roles_base_slot);
        self.storage.sstore(self.contract_id, slot, U256::ONE);
    }

    fn revoke_role_internal(&mut self, account: &Address, role: B256) {
        let slot = double_mapping_slot(account, role, self.roles_base_slot);
        self.storage.sstore(self.contract_id, slot, U256::ZERO);
    }

    fn get_role_admin_internal(&mut self, role: B256) -> B256 {
        let slot = mapping_slot(role, self.role_admin_base_slot);
        let admin = self.storage.sload(self.contract_id, slot);
        B256::from(admin) // If sloads 0, will be equal to DEFAULT_ADMIN_ROLE
    }

    fn set_role_admin_internal(&mut self, role: B256, admin_role: B256) {
        let slot = mapping_slot(role, self.role_admin_base_slot);
        self.storage
            .sstore(self.contract_id, slot, U256::from_be_bytes(admin_role.0));
    }

    fn check_role_internal(&mut self, account: &Address, role: B256) -> Result<(), RolesAuthError> {
        if !self.has_role_internal(account, role) {
            return Err(RolesAuthError::Unauthorized);
        }
        Ok(())
    }
}

/// Trait for contracts that implement role-based access control
/// This is the low-level trait, most contracts should use RolesAuthContract instead
pub trait RolesAuthTrait {
    fn has_role(&mut self, account: &Address, role: B256) -> bool;
    fn get_role_admin(&mut self, role: B256) -> B256;
    fn grant_role(&mut self, account: &Address, role: B256);
    fn revoke_role(&mut self, account: &Address, role: B256);
    fn set_role_admin(&mut self, role: B256, admin_role: B256);
    fn check_role(&mut self, account: &Address, role: B256) -> Result<(), RolesError>;
}

/// Generic implementation of role-based access control
/// Most contracts should use RolesAuthContract instead of this directly
pub struct RolesAuthProvider<'a, S: StorageProvider> {
    storage: &'a mut S,
    contract_id: u64,
    roles_base_slot: u64,
    role_admin_base_slot: u64,
}

impl<'a, S: StorageProvider> RolesAuthProvider<'a, S> {
    pub fn new(
        storage: &'a mut S,
        contract_id: u64,
        roles_base_slot: u64,
        role_admin_base_slot: u64,
    ) -> Self {
        Self {
            storage,
            contract_id,
            roles_base_slot,
            role_admin_base_slot,
        }
    }

    /// Initialize the UNGRANTABLE_ROLE to be self-administered
    pub fn initialize(&mut self) {
        self.set_role_admin(*UNGRANTABLE_ROLE, *UNGRANTABLE_ROLE);
    }

    /// Grant the default admin role to an account
    pub fn grant_default_admin(&mut self, admin: &Address) {
        self.grant_role(admin, *DEFAULT_ADMIN_ROLE);
    }
}

impl<'a, S: StorageProvider> RolesAuthTrait for RolesAuthProvider<'a, S> {
    fn has_role(&mut self, account: &Address, role: B256) -> bool {
        let slot = double_mapping_slot(account, role, self.roles_base_slot);
        self.storage.sload(self.contract_id, slot) != U256::ZERO
    }

    fn grant_role(&mut self, account: &Address, role: B256) {
        let slot = double_mapping_slot(account, role, self.roles_base_slot);
        self.storage.sstore(self.contract_id, slot, U256::ONE);
    }

    fn revoke_role(&mut self, account: &Address, role: B256) {
        let slot = double_mapping_slot(account, role, self.roles_base_slot);
        self.storage.sstore(self.contract_id, slot, U256::ZERO);
    }

    fn get_role_admin(&mut self, role: B256) -> B256 {
        let slot = mapping_slot(role, self.role_admin_base_slot);
        let admin = self.storage.sload(self.contract_id, slot);
        B256::from(admin) // If sloads 0, will be equal to DEFAULT_ADMIN_ROLE
    }

    fn set_role_admin(&mut self, role: B256, admin_role: B256) {
        let slot = mapping_slot(role, self.role_admin_base_slot);
        self.storage
            .sstore(self.contract_id, slot, U256::from_be_bytes(admin_role.0));
    }

    fn check_role(&mut self, account: &Address, role: B256) -> Result<(), RolesError> {
        if !self.has_role(account, role) {
            return Err(RolesError::Unauthorized(RolesAuth::Unauthorized {}));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::keccak256;

    use super::*;
    use crate::contracts::storage::hashmap::HashMapStorageProvider;

    #[test]
    fn test_role_contract_grant_and_check() {
        let mut storage = HashMapStorageProvider::new();
        let mut roles = RolesAuthContract::new(&mut storage, 1, 0, 1);

        let admin = Address::from([1u8; 20]);
        let user = Address::from([2u8; 20]);
        let custom_role = B256::from(keccak256(b"CUSTOM_ROLE"));

        // Initialize and grant admin
        roles.initialize();
        roles.grant_default_admin(&admin);

        // Test hasRole
        let has_admin = roles.has_role(RolesAuth::hasRoleCall {
            account: admin,
            role: *DEFAULT_ADMIN_ROLE,
        });
        assert!(has_admin);

        // Grant custom role
        roles
            .grant_role(
                &admin,
                RolesAuth::grantRoleCall {
                    role: custom_role,
                    account: user,
                },
            )
            .unwrap();

        // Check custom role
        let has_custom = roles.has_role(RolesAuth::hasRoleCall {
            account: user,
            role: custom_role,
        });
        assert!(has_custom);

        // Verify events were emitted
        assert_eq!(storage.events[&1].len(), 1); // One grant event
    }

    #[test]
    fn test_role_admin_functions() {
        let mut storage = HashMapStorageProvider::new();
        let mut roles = RolesAuthContract::new(&mut storage, 1, 0, 1);

        let admin = Address::from([1u8; 20]);
        let custom_role = B256::from(keccak256(b"CUSTOM_ROLE"));
        let admin_role = B256::from(keccak256(b"ADMIN_ROLE"));

        roles.initialize();
        roles.grant_default_admin(&admin);

        // Set custom admin for role
        roles
            .set_role_admin(
                &admin,
                RolesAuth::setRoleAdminCall {
                    role: custom_role,
                    adminRole: admin_role,
                },
            )
            .unwrap();

        // Check role admin
        let retrieved_admin =
            roles.get_role_admin(RolesAuth::getRoleAdminCall { role: custom_role });
        assert_eq!(retrieved_admin, admin_role);
    }

    #[test]
    fn test_renounce_role() {
        let mut storage = HashMapStorageProvider::new();
        let mut roles = RolesAuthContract::new(&mut storage, 1, 0, 1);

        let user = Address::from([1u8; 20]);
        let custom_role = B256::from(keccak256(b"CUSTOM_ROLE"));

        roles.initialize();
        roles.grant_role_internal(&user, custom_role);

        // Renounce role
        roles
            .renounce_role(&user, RolesAuth::renounceRoleCall { role: custom_role })
            .unwrap();

        // Check role is removed
        assert!(!roles.has_role_internal(&user, custom_role));
    }

    #[test]
    fn test_unauthorized_access() {
        let mut storage = HashMapStorageProvider::new();
        let mut roles = RolesAuthContract::new(&mut storage, 1, 0, 1);

        let user = Address::from([1u8; 20]);
        let other = Address::from([2u8; 20]);
        let custom_role = B256::from(keccak256(b"CUSTOM_ROLE"));

        roles.initialize();

        // Try to grant role without permission
        let result = roles.grant_role(
            &user,
            RolesAuth::grantRoleCall {
                role: custom_role,
                account: other,
            },
        );

        assert!(matches!(result, Err(RolesAuthError::Unauthorized)));
    }
}
