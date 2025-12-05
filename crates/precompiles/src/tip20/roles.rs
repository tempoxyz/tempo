use alloy::primitives::{Address, B256, IntoLogData};

use crate::{
    error::Result,
    storage::PrecompileStorageProvider,
    tip20::{IRolesAuth, RolesAuthError, RolesAuthEvent, TIP20Token},
};

pub const DEFAULT_ADMIN_ROLE: B256 = B256::ZERO;
pub const UNGRANTABLE_ROLE: B256 = B256::new([0xff; 32]);

impl<'a, S: PrecompileStorageProvider> TIP20Token<'a, S> {
    /// Initialize the UNGRANTABLE_ROLE to be self-administered
    pub fn initialize_roles(&mut self) -> Result<()> {
        self.set_role_admin_internal(UNGRANTABLE_ROLE, UNGRANTABLE_ROLE)
    }

    /// Grant the default admin role to an account
    pub fn grant_default_admin(&mut self, admin: Address) -> Result<()> {
        self.grant_role_internal(admin, DEFAULT_ADMIN_ROLE)
    }

    // Public functions that handle calldata and emit events
    pub fn has_role(&mut self, call: IRolesAuth::hasRoleCall) -> Result<bool> {
        self.has_role_internal(call.account, call.role)
    }

    pub fn get_role_admin(&mut self, call: IRolesAuth::getRoleAdminCall) -> Result<B256> {
        self.get_role_admin_internal(call.role)
    }

    pub fn grant_role(
        &mut self,
        msg_sender: Address,
        call: IRolesAuth::grantRoleCall,
    ) -> Result<()> {
        let admin_role = self.get_role_admin_internal(call.role)?;
        self.check_role_internal(msg_sender, admin_role)?;
        self.grant_role_internal(call.account, call.role)?;

        self.storage.emit_event(
            self.address,
            RolesAuthEvent::RoleMembershipUpdated(IRolesAuth::RoleMembershipUpdated {
                role: call.role,
                account: call.account,
                sender: msg_sender,
                hasRole: true,
            })
            .into_log_data(),
        )
    }

    pub fn revoke_role(
        &mut self,
        msg_sender: Address,
        call: IRolesAuth::revokeRoleCall,
    ) -> Result<()> {
        let admin_role = self.get_role_admin_internal(call.role)?;
        self.check_role_internal(msg_sender, admin_role)?;
        self.revoke_role_internal(call.account, call.role)?;

        self.storage.emit_event(
            self.address,
            RolesAuthEvent::RoleMembershipUpdated(IRolesAuth::RoleMembershipUpdated {
                role: call.role,
                account: call.account,
                sender: msg_sender,
                hasRole: false,
            })
            .into_log_data(),
        )
    }

    pub fn renounce_role(
        &mut self,
        msg_sender: Address,
        call: IRolesAuth::renounceRoleCall,
    ) -> Result<()> {
        self.check_role_internal(msg_sender, call.role)?;
        self.revoke_role_internal(msg_sender, call.role)?;

        self.storage.emit_event(
            self.address,
            RolesAuthEvent::RoleMembershipUpdated(IRolesAuth::RoleMembershipUpdated {
                role: call.role,
                account: msg_sender,
                sender: msg_sender,
                hasRole: false,
            })
            .into_log_data(),
        )
    }

    pub fn set_role_admin(
        &mut self,
        msg_sender: Address,
        call: IRolesAuth::setRoleAdminCall,
    ) -> Result<()> {
        let current_admin_role = self.get_role_admin_internal(call.role)?;
        self.check_role_internal(msg_sender, current_admin_role)?;

        self.set_role_admin_internal(call.role, call.adminRole)?;

        self.storage.emit_event(
            self.address,
            RolesAuthEvent::RoleAdminUpdated(IRolesAuth::RoleAdminUpdated {
                role: call.role,
                newAdminRole: call.adminRole,
                sender: msg_sender,
            })
            .into_log_data(),
        )
    }

    // Utility functions for checking roles without calldata
    pub fn check_role(&mut self, account: Address, role: B256) -> Result<()> {
        self.check_role_internal(account, role)
    }

    // Internal implementation functions
    pub fn has_role_internal(&mut self, account: Address, role: B256) -> Result<bool> {
        self.sload_roles(account, role)
    }

    pub fn grant_role_internal(&mut self, account: Address, role: B256) -> Result<()> {
        self.sstore_roles(account, role, true)
    }

    fn revoke_role_internal(&mut self, account: Address, role: B256) -> Result<()> {
        self.sstore_roles(account, role, false)
    }

    /// If sloads 0, will be equal to DEFAULT_ADMIN_ROLE
    fn get_role_admin_internal(&mut self, role: B256) -> Result<B256> {
        self.sload_role_admins(role)
    }

    fn set_role_admin_internal(&mut self, role: B256, admin_role: B256) -> Result<()> {
        self.sstore_role_admins(role, admin_role)
    }

    fn check_role_internal(&mut self, account: Address, role: B256) -> Result<()> {
        if !self.has_role_internal(account, role)? {
            return Err(RolesAuthError::unauthorized().into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{address, keccak256};

    use super::*;
    use crate::{error::TempoPrecompileError, storage::hashmap::HashMapStorageProvider};

    #[test]
    fn test_role_contract_grant_and_check() {
        let mut storage = HashMapStorageProvider::new(1);
        let test_address =
            Address::from([0x20, 0xC0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let mut token = TIP20Token::from_address(test_address, &mut storage);

        let admin = Address::from([1u8; 20]);
        let user = Address::from([2u8; 20]);
        let custom_role = keccak256(b"CUSTOM_ROLE");

        // Initialize and grant admin
        token
            .initialize("name", "symbol", "currency", Address::ZERO, admin, Address::ZERO)
            .unwrap();

        // Test hasRole
        let has_admin = token
            .has_role(IRolesAuth::hasRoleCall { account: admin, role: DEFAULT_ADMIN_ROLE })
            .expect("Should have admin");
        assert!(has_admin);

        // Grant custom role
        token
            .grant_role(admin, IRolesAuth::grantRoleCall { role: custom_role, account: user })
            .unwrap();

        // Check custom role
        let has_custom = token
            .has_role(IRolesAuth::hasRoleCall { account: user, role: custom_role })
            .expect("Should have role");
        assert!(has_custom);

        // Verify events were emitted
        assert_eq!(storage.events[&test_address].len(), 1); // One grant event
    }

    #[test]
    fn test_role_admin_functions() {
        let mut storage = HashMapStorageProvider::new(1);
        let test_address = address!("0x20C0000000000000000000000000000000000001");
        let mut token = TIP20Token::from_address(test_address, &mut storage);

        let admin = Address::from([1u8; 20]);
        let custom_role = keccak256(b"CUSTOM_ROLE");
        let admin_role = keccak256(b"ADMIN_ROLE");

        // Initialize and grant admin
        token
            .initialize("name", "symbol", "currency", Address::ZERO, admin, Address::ZERO)
            .unwrap();

        // Set custom admin for role
        token
            .set_role_admin(
                admin,
                IRolesAuth::setRoleAdminCall { role: custom_role, adminRole: admin_role },
            )
            .unwrap();

        // Check role admin
        let retrieved_admin = token
            .get_role_admin(IRolesAuth::getRoleAdminCall { role: custom_role })
            .expect("Should have admin");
        assert_eq!(retrieved_admin, admin_role);
    }

    #[test]
    fn test_renounce_role() {
        let mut storage = HashMapStorageProvider::new(1);
        let test_address = address!("0x20C0000000000000000000000000000000000001");
        let mut token = TIP20Token::from_address(test_address, &mut storage);

        let user = Address::from([1u8; 20]);
        let custom_role = keccak256(b"CUSTOM_ROLE");

        token
            .initialize("name", "symbol", "currency", Address::ZERO, Address::ZERO, Address::ZERO)
            .unwrap();
        token.grant_role_internal(user, custom_role).unwrap();

        // Renounce role
        token.renounce_role(user, IRolesAuth::renounceRoleCall { role: custom_role }).unwrap();

        // Check role is removed
        assert!(!token.has_role_internal(user, custom_role).expect("Could not get role"));
    }

    #[test]
    fn test_unauthorized_access() {
        let mut storage = HashMapStorageProvider::new(1);
        let test_address = address!("0x20C0000000000000000000000000000000000001");
        let mut token = TIP20Token::from_address(test_address, &mut storage);

        let user = Address::from([1u8; 20]);
        let other = Address::from([2u8; 20]);
        let custom_role = keccak256(b"CUSTOM_ROLE");

        token
            .initialize("name", "symbol", "currency", Address::ZERO, Address::ZERO, Address::ZERO)
            .unwrap();

        // Try to grant role without permission
        let result =
            token.grant_role(user, IRolesAuth::grantRoleCall { role: custom_role, account: other });

        assert!(matches!(
            result,
            Err(TempoPrecompileError::RolesAuthError(RolesAuthError::Unauthorized(
                IRolesAuth::Unauthorized {}
            )))
        ));
    }
}
