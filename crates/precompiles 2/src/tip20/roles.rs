use alloy::primitives::{Address, B256};

use crate::{
    error::Result,
    storage::Handler,
    tip20::{IRolesAuth, RolesAuthError, RolesAuthEvent, TIP20Token},
};

pub const DEFAULT_ADMIN_ROLE: B256 = B256::ZERO;
pub const UNGRANTABLE_ROLE: B256 = B256::new([0xff; 32]);

impl TIP20Token {
    /// Initialize the UNGRANTABLE_ROLE to be self-administered
    pub fn initialize_roles(&mut self) -> Result<()> {
        self.set_role_admin_internal(UNGRANTABLE_ROLE, UNGRANTABLE_ROLE)
    }

    /// Grant the default admin role to an account
    pub fn grant_default_admin(&mut self, msg_sender: Address, admin: Address) -> Result<()> {
        self.grant_role_internal(admin, DEFAULT_ADMIN_ROLE)?;

        self.emit_event(RolesAuthEvent::RoleMembershipUpdated(
            IRolesAuth::RoleMembershipUpdated {
                role: DEFAULT_ADMIN_ROLE,
                account: admin,
                sender: msg_sender,
                hasRole: true,
            },
        ))
    }

    // Public functions that handle calldata and emit events
    pub fn has_role(&self, call: IRolesAuth::hasRoleCall) -> Result<bool> {
        self.has_role_internal(call.account, call.role)
    }

    pub fn get_role_admin(&self, call: IRolesAuth::getRoleAdminCall) -> Result<B256> {
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

        self.emit_event(RolesAuthEvent::RoleMembershipUpdated(
            IRolesAuth::RoleMembershipUpdated {
                role: call.role,
                account: call.account,
                sender: msg_sender,
                hasRole: true,
            },
        ))
    }

    pub fn revoke_role(
        &mut self,
        msg_sender: Address,
        call: IRolesAuth::revokeRoleCall,
    ) -> Result<()> {
        let admin_role = self.get_role_admin_internal(call.role)?;
        self.check_role_internal(msg_sender, admin_role)?;
        self.revoke_role_internal(call.account, call.role)?;

        self.emit_event(RolesAuthEvent::RoleMembershipUpdated(
            IRolesAuth::RoleMembershipUpdated {
                role: call.role,
                account: call.account,
                sender: msg_sender,
                hasRole: false,
            },
        ))
    }

    pub fn renounce_role(
        &mut self,
        msg_sender: Address,
        call: IRolesAuth::renounceRoleCall,
    ) -> Result<()> {
        self.check_role_internal(msg_sender, call.role)?;
        self.revoke_role_internal(msg_sender, call.role)?;

        self.emit_event(RolesAuthEvent::RoleMembershipUpdated(
            IRolesAuth::RoleMembershipUpdated {
                role: call.role,
                account: msg_sender,
                sender: msg_sender,
                hasRole: false,
            },
        ))
    }

    pub fn set_role_admin(
        &mut self,
        msg_sender: Address,
        call: IRolesAuth::setRoleAdminCall,
    ) -> Result<()> {
        let current_admin_role = self.get_role_admin_internal(call.role)?;
        self.check_role_internal(msg_sender, current_admin_role)?;

        self.set_role_admin_internal(call.role, call.adminRole)?;

        self.emit_event(RolesAuthEvent::RoleAdminUpdated(
            IRolesAuth::RoleAdminUpdated {
                role: call.role,
                newAdminRole: call.adminRole,
                sender: msg_sender,
            },
        ))
    }

    // Utility functions for checking roles without calldata
    pub fn check_role(&self, account: Address, role: B256) -> Result<()> {
        self.check_role_internal(account, role)
    }

    // Internal implementation functions
    pub fn has_role_internal(&self, account: Address, role: B256) -> Result<bool> {
        self.roles[account][role].read()
    }

    pub fn grant_role_internal(&mut self, account: Address, role: B256) -> Result<()> {
        self.roles[account][role].write(true)
    }

    fn revoke_role_internal(&mut self, account: Address, role: B256) -> Result<()> {
        self.roles[account][role].write(false)
    }

    /// If sloads 0, will be equal to DEFAULT_ADMIN_ROLE
    fn get_role_admin_internal(&self, role: B256) -> Result<B256> {
        self.role_admins[role].read()
    }

    fn set_role_admin_internal(&mut self, role: B256, admin_role: B256) -> Result<()> {
        self.role_admins[role].write(admin_role)
    }

    fn check_role_internal(&self, account: Address, role: B256) -> Result<()> {
        if !self.has_role_internal(account, role)? {
            return Err(RolesAuthError::unauthorized().into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::keccak256;

    use super::*;
    use crate::{error::TempoPrecompileError, storage::StorageCtx, test_util::TIP20Setup};

    #[test]
    fn test_role_contract_grant_and_check() -> eyre::Result<()> {
        let mut storage = crate::storage::hashmap::HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let custom_role = keccak256(b"CUSTOM_ROLE");

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;

            // Test hasRole
            let has_admin = token.has_role(IRolesAuth::hasRoleCall {
                account: admin,
                role: DEFAULT_ADMIN_ROLE,
            })?;
            assert!(has_admin);

            // Grant custom role
            token.grant_role(
                admin,
                IRolesAuth::grantRoleCall {
                    role: custom_role,
                    account: user,
                },
            )?;

            // Check custom role
            let has_custom = token.has_role(IRolesAuth::hasRoleCall {
                account: user,
                role: custom_role,
            })?;
            assert!(has_custom);

            // Verify events were emitted
            token.assert_emitted_events(vec![
                // Event from grant_default_admin during token initialization
                RolesAuthEvent::RoleMembershipUpdated(IRolesAuth::RoleMembershipUpdated {
                    role: DEFAULT_ADMIN_ROLE,
                    account: admin,
                    sender: admin,
                    hasRole: true,
                }),
                // Event from grant_role call above
                RolesAuthEvent::RoleMembershipUpdated(IRolesAuth::RoleMembershipUpdated {
                    role: custom_role,
                    account: user,
                    sender: admin,
                    hasRole: true,
                }),
            ]);

            Ok(())
        })
    }

    #[test]
    fn test_role_admin_functions() -> eyre::Result<()> {
        let mut storage = crate::storage::hashmap::HashMapStorageProvider::new(1);
        let admin = Address::random();
        let custom_role = keccak256(b"CUSTOM_ROLE");
        let admin_role = keccak256(b"ADMIN_ROLE");

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;

            // Set custom admin for role
            token.set_role_admin(
                admin,
                IRolesAuth::setRoleAdminCall {
                    role: custom_role,
                    adminRole: admin_role,
                },
            )?;

            // Check role admin
            let retrieved_admin =
                token.get_role_admin(IRolesAuth::getRoleAdminCall { role: custom_role })?;
            assert_eq!(retrieved_admin, admin_role);

            Ok(())
        })
    }

    #[test]
    fn test_renounce_role() -> eyre::Result<()> {
        let mut storage = crate::storage::hashmap::HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let custom_role = keccak256(b"CUSTOM_ROLE");

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;
            token.grant_role_internal(user, custom_role).unwrap();

            // Renounce role
            token.renounce_role(user, IRolesAuth::renounceRoleCall { role: custom_role })?;

            // Check role is removed
            assert!(!token.has_role_internal(user, custom_role)?);

            Ok(())
        })
    }

    #[test]
    fn test_unauthorized_access() -> eyre::Result<()> {
        let mut storage = crate::storage::hashmap::HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let other = Address::random();
        let custom_role = keccak256(b"CUSTOM_ROLE");

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;

            // Try to grant role without permission
            let result = token.grant_role(
                user,
                IRolesAuth::grantRoleCall {
                    role: custom_role,
                    account: other,
                },
            );

            assert!(matches!(
                result,
                Err(TempoPrecompileError::RolesAuthError(
                    RolesAuthError::Unauthorized(IRolesAuth::Unauthorized {})
                ))
            ));

            Ok(())
        })
    }
}
